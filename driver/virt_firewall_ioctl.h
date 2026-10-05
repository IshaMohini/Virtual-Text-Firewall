#ifndef VIRT_FIREWALL_IOCTL_H
#define VIRT_FIREWALL_IOCTL_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <sys/ioctl.h>
#include <stdint.h>
#include <stddef.h>
#endif

/* Device node configuration */
#define VIRT_FW_DEVICE_NAME     "virt_firewall"
#define VIRT_FW_CLASS_NAME      "virt_firewall_class"
#define VIRT_FW_DEVICE_PATH     "/dev/virt_firewall"

#define DEVICE_NAME             VIRT_FW_DEVICE_NAME
#define DEVICE_PATH             VIRT_FW_DEVICE_PATH

/* Buffer and capacity limits */
#define MAX_RULES               32
#define MAX_KEYWORD_LENGTH      64
#define MAX_MESSAGE_LENGTH      512

/* IOCTL magic number and command definitions */
#define VIRT_FW_IOC_MAGIC       'v'

/* Pass a string to add a new blocked keyword rule */
#define VIRT_FW_IOC_ADD_RULE    _IOW(VIRT_FW_IOC_MAGIC, 1, char[MAX_KEYWORD_LENGTH])

/* Reset inspected, passed, and blocked counters */
#define VIRT_FW_IOC_CLEAR_STATS _IO(VIRT_FW_IOC_MAGIC, 2)

/* Clear all active firewall rules */
#define VIRT_FW_IOC_CLEAR_RULES _IO(VIRT_FW_IOC_MAGIC, 3)

#endif /* VIRT_FIREWALL_IOCTL_H */
