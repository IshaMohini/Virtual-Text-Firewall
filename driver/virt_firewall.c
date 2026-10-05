/*
 * virt_firewall.c - Linux Character Device Driver for Virtual Text Firewall
 *
 * Implements a character device (/dev/virt_firewall) that filters text messages
 * in kernel space, maintains statistics counters, and allows rule management via ioctl.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/version.h>
#include <linux/errno.h>

#include "virt_firewall_ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Virtual Text Firewall Project Team");
MODULE_DESCRIPTION("Virtual Text Firewall & Content Filter Character Device Driver");
MODULE_VERSION("1.0");

/* Inspection verdict */
enum fw_verdict {
    FW_VERDICT_NONE = 0,
    FW_VERDICT_PASS = 1,
    FW_VERDICT_BLOCKED = 2
};

/* Device registration numbers and structures */
static dev_t fw_dev_num;
static struct cdev fw_cdev;
static struct class *fw_class = NULL;
static struct device *fw_device = NULL;

/* In-memory rule table */
static char fw_rules[MAX_RULES][MAX_KEYWORD_LENGTH];
static unsigned int fw_rule_count = 0;

/* Mutex protecting rule table and last verdict */
static DEFINE_MUTEX(fw_mutex);

/* Last inspection result cache */
static enum fw_verdict last_verdict = FW_VERDICT_NONE;
static char last_matched_rule[MAX_KEYWORD_LENGTH] = "";

/* Telemetry counters */
static atomic64_t total_inspected = ATOMIC64_INIT(0);
static atomic64_t total_passed    = ATOMIC64_INIT(0);
static atomic64_t total_blocked   = ATOMIC64_INIT(0);

/* Called on open() */
static int fw_open(struct inode *inode, struct file *filp)
{
    pr_info("virt_firewall: device opened by PID %d (%s)\n",
            current->pid, current->comm);
    return 0;
}

/* Called on close() */
static int fw_release(struct inode *inode, struct file *filp)
{
    pr_info("virt_firewall: device closed by PID %d (%s)\n",
            current->pid, current->comm);
    return 0;
}

/* Write handler: receives user text and filters against blocked keywords */
static ssize_t fw_write(struct file *filp, const char __user *user_buf,
                        size_t count, loff_t *offset)
{
    char kbuf[MAX_MESSAGE_LENGTH + 1];
    size_t payload_len;
    unsigned int i;
    bool blocked = false;

    if (count == 0)
        return 0;

    if (count > MAX_MESSAGE_LENGTH) {
        pr_warn("virt_firewall: message length %zu exceeds limit of %d bytes\n",
                count, MAX_MESSAGE_LENGTH);
        return -EINVAL;
    }

    /* Copy payload safely from user space */
    if (copy_from_user(kbuf, user_buf, count)) {
        pr_err("virt_firewall: copy_from_user failed in write()\n");
        return -EFAULT;
    }

    kbuf[count] = '\0';
    payload_len = count;

    /* Strip trailing newline for clean display/matching */
    while (payload_len > 0 &&
          (kbuf[payload_len - 1] == '\n' || kbuf[payload_len - 1] == '\r')) {
        kbuf[--payload_len] = '\0';
    }

    mutex_lock(&fw_mutex);

    atomic64_inc(&total_inspected);
    last_matched_rule[0] = '\0';

    /* Scan message for blocked keywords */
    for (i = 0; i < fw_rule_count; i++) {
        if (fw_rules[i][0] != '\0' && strstr(kbuf, fw_rules[i])) {
            blocked = true;
            strscpy(last_matched_rule, fw_rules[i], sizeof(last_matched_rule));
            break;
        }
    }

    if (blocked) {
        atomic64_inc(&total_blocked);
        last_verdict = FW_VERDICT_BLOCKED;
        pr_info("virt_firewall: [BLOCKED] Threat detected! Rule='%s' PID=%d Payload=\"%s\"\n",
                last_matched_rule, current->pid, kbuf);
    } else {
        atomic64_inc(&total_passed);
        last_verdict = FW_VERDICT_PASS;
        pr_info("virt_firewall: [PASS] Message passed checks. PID=%d Payload=\"%s\"\n",
                current->pid, kbuf);
    }

    mutex_unlock(&fw_mutex);

    return count;
}

/* Read handler: returns status and statistics in KEY=VALUE format */
static ssize_t fw_read(struct file *filp, char __user *user_buf,
                       size_t count, loff_t *offset)
{
    char out_buf[256];
    int out_len;
    const char *status_str;

    mutex_lock(&fw_mutex);
    switch (last_verdict) {
    case FW_VERDICT_PASS:
        status_str = "PASS";
        break;
    case FW_VERDICT_BLOCKED:
        status_str = "BLOCKED";
        break;
    default:
        status_str = "NONE";
        break;
    }

    out_len = scnprintf(out_buf, sizeof(out_buf),
                        "STATUS=%s\n"
                        "TOTAL_INSPECTED=%lld\n"
                        "TOTAL_PASSED=%lld\n"
                        "TOTAL_BLOCKED=%lld\n"
                        "RULE_COUNT=%u\n",
                        status_str,
                        (long long)atomic64_read(&total_inspected),
                        (long long)atomic64_read(&total_passed),
                        (long long)atomic64_read(&total_blocked),
                        fw_rule_count);
    mutex_unlock(&fw_mutex);

    /* Return EOF if offset reached end of formatted data */
    if (*offset >= out_len)
        return 0;

    if (count > (size_t)(out_len - *offset))
        count = out_len - *offset;

    if (copy_to_user(user_buf, out_buf + *offset, count)) {
        pr_err("virt_firewall: copy_to_user failed in read()\n");
        return -EFAULT;
    }

    *offset += count;
    return count;
}

/* IOCTL handler: supports adding rules, resetting stats, and clearing rules */
static long fw_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    char kw_buf[MAX_KEYWORD_LENGTH];
    size_t kw_len;
    unsigned int i;

    switch (cmd) {
    case VIRT_FW_IOC_ADD_RULE:
        if (copy_from_user(kw_buf, (void __user *)arg, sizeof(kw_buf))) {
            pr_err("virt_firewall: copy_from_user failed in ADD_RULE ioctl\n");
            return -EFAULT;
        }

        kw_buf[sizeof(kw_buf) - 1] = '\0';
        kw_len = strlen(kw_buf);

        while (kw_len > 0 && (kw_buf[kw_len - 1] == '\n' ||
                              kw_buf[kw_len - 1] == '\r' ||
                              kw_buf[kw_len - 1] == ' ')) {
            kw_buf[--kw_len] = '\0';
        }

        if (kw_len == 0) {
            pr_warn("virt_firewall: rejected empty keyword\n");
            return -EINVAL;
        }

        mutex_lock(&fw_mutex);

        if (fw_rule_count >= MAX_RULES) {
            mutex_unlock(&fw_mutex);
            pr_warn("virt_firewall: rule table full (MAX_RULES=%d)\n", MAX_RULES);
            return -ENOSPC;
        }

        /* Check for duplicate */
        for (i = 0; i < fw_rule_count; i++) {
            if (strcmp(fw_rules[i], kw_buf) == 0) {
                mutex_unlock(&fw_mutex);
                pr_info("virt_firewall: rule '%s' already exists\n", kw_buf);
                return -EEXIST;
            }
        }

        strscpy(fw_rules[fw_rule_count], kw_buf, MAX_KEYWORD_LENGTH);
        fw_rule_count++;

        pr_info("virt_firewall: rule added '%s' (active: %u)\n",
                kw_buf, fw_rule_count);

        mutex_unlock(&fw_mutex);
        return 0;

    case VIRT_FW_IOC_CLEAR_STATS:
        atomic64_set(&total_inspected, 0);
        atomic64_set(&total_passed, 0);
        atomic64_set(&total_blocked, 0);

        mutex_lock(&fw_mutex);
        last_verdict = FW_VERDICT_NONE;
        last_matched_rule[0] = '\0';
        mutex_unlock(&fw_mutex);

        pr_info("virt_firewall: statistics counters cleared\n");
        return 0;

    case VIRT_FW_IOC_CLEAR_RULES:
        mutex_lock(&fw_mutex);
        fw_rule_count = 0;
        memset(fw_rules, 0, sizeof(fw_rules));
        mutex_unlock(&fw_mutex);

        pr_info("virt_firewall: all rules cleared\n");
        return 0;

    default:
        pr_warn("virt_firewall: invalid ioctl command 0x%x\n", cmd);
        return -ENOTTY;
    }
}

/* File operations table */
static const struct file_operations fw_fops = {
    .owner          = THIS_MODULE,
    .open           = fw_open,
    .release        = fw_release,
    .read           = fw_read,
    .write          = fw_write,
    .unlocked_ioctl = fw_ioctl,
};

/* Module initialization */
static int __init virt_firewall_init(void)
{
    int ret;

    pr_info("virt_firewall: initializing module\n");

    /* 1. Allocate device numbers */
    ret = alloc_chrdev_region(&fw_dev_num, 0, 1, VIRT_FW_DEVICE_NAME);
    if (ret < 0) {
        pr_err("virt_firewall: alloc_chrdev_region failed (%d)\n", ret);
        return ret;
    }

    /* 2. Initialize and register cdev */
    cdev_init(&fw_cdev, &fw_fops);
    fw_cdev.owner = THIS_MODULE;

    ret = cdev_add(&fw_cdev, fw_dev_num, 1);
    if (ret < 0) {
        pr_err("virt_firewall: cdev_add failed (%d)\n", ret);
        goto err_unregister;
    }

    /* 3. Create sysfs device class (handles API change in Linux 6.4+) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    fw_class = class_create(VIRT_FW_CLASS_NAME);
#else
    fw_class = class_create(THIS_MODULE, VIRT_FW_CLASS_NAME);
#endif
    if (IS_ERR(fw_class)) {
        ret = PTR_ERR(fw_class);
        pr_err("virt_firewall: class_create failed (%d)\n", ret);
        goto err_cdev_del;
    }

    /* 4. Create /dev/virt_firewall device node */
    fw_device = device_create(fw_class, NULL, fw_dev_num, NULL, VIRT_FW_DEVICE_NAME);
    if (IS_ERR(fw_device)) {
        ret = PTR_ERR(fw_device);
        pr_err("virt_firewall: device_create failed (%d)\n", ret);
        goto err_class_destroy;
    }

    /* 5. Initialize default firewall rules */
    mutex_lock(&fw_mutex);
    strscpy(fw_rules[0], "MALWARE", MAX_KEYWORD_LENGTH);
    strscpy(fw_rules[1], "UNAUTHORIZED", MAX_KEYWORD_LENGTH);
    strscpy(fw_rules[2], "DROP", MAX_KEYWORD_LENGTH);
    fw_rule_count = 3;
    mutex_unlock(&fw_mutex);

    pr_info("virt_firewall: loaded (Major=%d, Minor=%d)\n",
            MAJOR(fw_dev_num), MINOR(fw_dev_num));
    pr_info("virt_firewall: /dev/%s ready with %u default rules\n",
            VIRT_FW_DEVICE_NAME, fw_rule_count);

    return 0;

err_class_destroy:
    class_destroy(fw_class);
err_cdev_del:
    cdev_del(&fw_cdev);
err_unregister:
    unregister_chrdev_region(fw_dev_num, 1);
    return ret;
}

/* Module cleanup */
static void __exit virt_firewall_exit(void)
{
    pr_info("virt_firewall: cleaning up module\n");

    if (fw_device)
        device_destroy(fw_class, fw_dev_num);

    if (fw_class)
        class_destroy(fw_class);

    cdev_del(&fw_cdev);
    unregister_chrdev_region(fw_dev_num, 1);

    pr_info("virt_firewall: unloaded cleanly\n");
}

module_init(virt_firewall_init);
module_exit(virt_firewall_exit);
