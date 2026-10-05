// main.cpp - Interactive User-Space Application for Virtual Text Firewall

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <cerrno>
#include <memory>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "../driver/virt_firewall_ioctl.h"

// ANSI color escape codes for terminal output
namespace Color {
    const std::string RESET       = "\033[0m";
    const std::string BOLD        = "\033[1m";
    const std::string RED         = "\033[1;31m";
    const std::string GREEN       = "\033[1;32m";
    const std::string YELLOW      = "\033[1;33m";
    const std::string BLUE        = "\033[1;34m";
    const std::string CYAN        = "\033[1;36m";
    const std::string WHITE       = "\033[1;37m";
}

// Holds statistics and status read from /dev/virt_firewall
struct FirewallStats {
    std::string status = "NONE";
    long long totalInspected = 0;
    long long totalPassed = 0;
    long long totalBlocked = 0;
    unsigned int activeRules = 0;

    double blockRate() const {
        if (totalInspected <= 0)
            return 0.0;
        return (static_cast<double>(totalBlocked) / totalInspected) * 100.0;
    }
};

// Manages device communication using RAII (opens on init, closes on destruction)
class FirewallManager {
private:
    int fd;
    std::string devicePath;

    // Reads driver state. Opens a dedicated read descriptor so read offset starts at 0.
    bool fetchDriverState(FirewallStats& stats) {
        int readFd = open(devicePath.c_str(), O_RDONLY);
        if (readFd < 0) {
            std::cerr << Color::RED << "[!] Failed to open " << devicePath
                      << " for reading: " << std::strerror(errno) << Color::RESET << "\n";
            return false;
        }

        char buffer[512];
        std::memset(buffer, 0, sizeof(buffer));

        ssize_t bytesRead = read(readFd, buffer, sizeof(buffer) - 1);
        int readErr = errno;
        close(readFd);

        if (bytesRead < 0) {
            std::cerr << Color::RED << "[!] Failed to read from " << devicePath
                      << ": " << std::strerror(readErr) << Color::RESET << "\n";
            return false;
        }

        buffer[bytesRead] = '\0';
        std::istringstream stream(buffer);
        std::string line;

        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            size_t eqPos = line.find('=');
            if (eqPos == std::string::npos)
                continue;

            std::string key = line.substr(0, eqPos);
            std::string val = line.substr(eqPos + 1);

            try {
                if (key == "STATUS") {
                    stats.status = val;
                } else if (key == "TOTAL_INSPECTED") {
                    stats.totalInspected = std::stoll(val);
                } else if (key == "TOTAL_PASSED") {
                    stats.totalPassed = std::stoll(val);
                } else if (key == "TOTAL_BLOCKED") {
                    stats.totalBlocked = std::stoll(val);
                } else if (key == "RULE_COUNT") {
                    stats.activeRules = static_cast<unsigned int>(std::stoul(val));
                }
            } catch (...) {
                // Ignore parse errors on individual fields
            }
        }

        return true;
    }

public:
    // Constructor: opens character device
    explicit FirewallManager(const std::string& path = DEVICE_PATH)
        : fd(-1), devicePath(path)
    {
        fd = open(devicePath.c_str(), O_RDWR);
        if (fd < 0) {
            int err = errno;
            std::string hint = "";
            if (err == ENOENT) {
                hint = "\n  -> Kernel module might not be loaded. Run: sudo insmod ../driver/virt_firewall.ko";
            } else if (err == EACCES) {
                hint = "\n  -> Permission denied. Run with sudo, or run: sudo chmod 666 " + devicePath;
            }
            throw std::runtime_error("Could not open device '" + devicePath +
                                     "': " + std::strerror(err) + hint);
        }
    }

    // Destructor: closes file descriptor
    ~FirewallManager() {
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
    }

    // Disable copy to prevent double closing of the file descriptor
    FirewallManager(const FirewallManager&) = delete;
    FirewallManager& operator=(const FirewallManager&) = delete;

    // Enable move semantics
    FirewallManager(FirewallManager&& other) noexcept
        : fd(other.fd), devicePath(std::move(other.devicePath))
    {
        other.fd = -1;
    }

    FirewallManager& operator=(FirewallManager&& other) noexcept {
        if (this != &other) {
            if (fd >= 0) close(fd);
            fd = other.fd;
            devicePath = std::move(other.devicePath);
            other.fd = -1;
        }
        return *this;
    }

    // Sends text message to kernel module via write()
    bool sendMessage(const std::string& message, FirewallStats& outStats) {
        if (fd < 0) return false;

        ssize_t bytesWritten = write(fd, message.c_str(), message.length());
        if (bytesWritten < 0) {
            std::cerr << Color::RED << "[!] Error writing message to firewall: "
                      << std::strerror(errno) << Color::RESET << "\n";
            return false;
        }

        return fetchDriverState(outStats);
    }

    // Adds a blocked keyword via ioctl()
    bool addBlockedWord(const std::string& keyword, std::string& errMessage) {
        if (fd < 0) {
            errMessage = "Device not open";
            return false;
        }

        if (keyword.empty()) {
            errMessage = "Keyword cannot be empty";
            return false;
        }

        if (keyword.length() >= MAX_KEYWORD_LENGTH) {
            errMessage = "Keyword length exceeds maximum allowed (" +
                         std::to_string(MAX_KEYWORD_LENGTH - 1) + " chars)";
            return false;
        }

        char buffer[MAX_KEYWORD_LENGTH];
        std::memset(buffer, 0, sizeof(buffer));
        std::strncpy(buffer, keyword.c_str(), sizeof(buffer) - 1);

        int res = ioctl(fd, VIRT_FW_IOC_ADD_RULE, buffer);
        if (res < 0) {
            int err = errno;
            if (err == EEXIST) {
                errMessage = "Keyword '" + keyword + "' is already in the rule list";
            } else if (err == ENOSPC) {
                errMessage = "Firewall rule table is full (max: " +
                             std::to_string(MAX_RULES) + " rules)";
            } else if (err == EINVAL) {
                errMessage = "Invalid keyword string submitted";
            } else {
                errMessage = std::strerror(err);
            }
            return false;
        }

        return true;
    }

    // Gets latest statistics from driver
    bool getStatistics(FirewallStats& stats) {
        return fetchDriverState(stats);
    }

    // Clears statistics counters via ioctl()
    bool clearStatistics() {
        if (fd < 0) return false;

        int res = ioctl(fd, VIRT_FW_IOC_CLEAR_STATS);
        if (res < 0) {
            std::cerr << Color::RED << "[!] ioctl CLEAR_STATS failed: "
                      << std::strerror(errno) << Color::RESET << "\n";
            return false;
        }
        return true;
    }
};

void displayBanner() {
    std::cout << Color::CYAN << Color::BOLD
              << "========================================================\n"
              << "       VIRTUAL TEXT FIREWALL & CONTENT FILTER          \n"
              << "          In-Kernel Character Device Inspector          \n"
              << "========================================================"
              << Color::RESET << "\n";
}

void displayMenu() {
    std::cout << "\n" << Color::YELLOW << Color::BOLD
              << "FIREWALL CONTROL MENU:" << Color::RESET << "\n"
              << "  1. Send Message Through Firewall\n"
              << "  2. Add Blocked Keyword\n"
              << "  3. View Firewall Statistics\n"
              << "  4. Clear Statistics\n"
              << "  5. Exit\n"
              << "--------------------------------------------------------\n"
              << "Enter choice [1-5]: ";
}

int main() {
    displayBanner();

    std::unique_ptr<FirewallManager> fw;
    try {
        fw = std::make_unique<FirewallManager>();
        std::cout << Color::GREEN << "[+] Connected to character device: "
                  << DEVICE_PATH << Color::RESET << "\n";
    } catch (const std::exception& ex) {
        std::cerr << Color::RED << "\n[-] Initialization Error:\n"
                  << "    " << ex.what() << Color::RESET << "\n\n";
        return 1;
    }

    bool running = true;
    while (running) {
        displayMenu();

        std::string inputChoice;
        if (!std::getline(std::cin, inputChoice)) {
            std::cout << "\nInput stream closed. Exiting.\n";
            break;
        }

        // Trim whitespace
        while (!inputChoice.empty() && (inputChoice.front() == ' ' || inputChoice.front() == '\t'))
            inputChoice.erase(inputChoice.begin());
        while (!inputChoice.empty() && (inputChoice.back() == ' ' || inputChoice.back() == '\t'))
            inputChoice.pop_back();

        if (inputChoice.empty()) {
            std::cout << Color::YELLOW << "[!] Please enter a selection between 1 and 5.\n" << Color::RESET;
            continue;
        }

        if (inputChoice == "1") {
            // Option 1: Send message through firewall
            std::cout << "\n" << Color::WHITE << Color::BOLD
                      << ">> Enter message payload to transmit: " << Color::RESET;
            std::string message;
            if (!std::getline(std::cin, message)) break;

            if (message.empty()) {
                std::cout << Color::YELLOW << "[!] Message is empty. Nothing transmitted.\n" << Color::RESET;
                continue;
            }

            FirewallStats stats;
            std::cout << Color::CYAN << "[*] Transmitting " << message.length()
                      << " bytes to /dev/virt_firewall via write()...\n" << Color::RESET;

            if (fw->sendMessage(message, stats)) {
                std::cout << "--------------------------------------------------------\n";
                if (stats.status == "PASS") {
                    std::cout << Color::GREEN << Color::BOLD
                              << "[PASS] Message Delivered" << Color::RESET << "\n";
                    std::cout << "  Payload       : \"" << message << "\"\n";
                    std::cout << "  Kernel Verdict: PASSED (No blacklisted terms found)\n";
                } else if (stats.status == "BLOCKED") {
                    std::cout << Color::RED << Color::BOLD
                              << "[BLOCKED] Threat Dropped" << Color::RESET << "\n";
                    std::cout << "  Payload       : \"" << message << "\"\n";
                    std::cout << "  Kernel Verdict: BLOCKED by Active Firewall Rule\n";
                } else {
                    std::cout << Color::YELLOW << "[?] Unknown Status: "
                              << stats.status << Color::RESET << "\n";
                }
                std::cout << "--------------------------------------------------------\n";
            }

        } else if (inputChoice == "2") {
            // Option 2: Add blocked keyword
            std::cout << "\n" << Color::WHITE << Color::BOLD
                      << ">> Enter new blocked keyword: " << Color::RESET;
            std::string keyword;
            if (!std::getline(std::cin, keyword)) break;

            while (!keyword.empty() && (keyword.front() == ' ' || keyword.front() == '\t'))
                keyword.erase(keyword.begin());
            while (!keyword.empty() && (keyword.back() == ' ' || keyword.back() == '\t'))
                keyword.pop_back();

            if (keyword.empty()) {
                std::cout << Color::YELLOW << "[!] Keyword cannot be blank.\n" << Color::RESET;
                continue;
            }

            std::string errMsg;
            if (fw->addBlockedWord(keyword, errMsg)) {
                std::cout << Color::GREEN << Color::BOLD
                          << "[+] Rule added successfully: " << keyword << Color::RESET << "\n";
            } else {
                std::cout << Color::RED << Color::BOLD
                          << "[-] Failed to add rule: " << errMsg << Color::RESET << "\n";
            }

        } else if (inputChoice == "3") {
            // Option 3: View firewall statistics
            FirewallStats stats;
            if (fw->getStatistics(stats)) {
                std::cout << "\n" << Color::CYAN << Color::BOLD
                          << "========================================\n"
                          << "          FIREWALL STATISTICS           \n"
                          << "========================================" << Color::RESET << "\n"
                          << std::left
                          << std::setw(20) << "Total Inspected"  << ": " << stats.totalInspected << "\n"
                          << std::setw(20) << "Passed"           << ": " << Color::GREEN << stats.totalPassed << Color::RESET << "\n"
                          << std::setw(20) << "Blocked"          << ": " << Color::RED << stats.totalBlocked << Color::RESET << "\n"
                          << std::setw(20) << "Active Rules"     << ": " << stats.activeRules << "\n"
                          << "----------------------------------------\n"
                          << std::fixed << std::setprecision(2)
                          << std::setw(20) << "Block Rate"       << ": " << stats.blockRate() << "%\n"
                          << Color::CYAN << Color::BOLD
                          << "========================================" << Color::RESET << "\n";
            }

        } else if (inputChoice == "4") {
            // Option 4: Clear statistics
            if (fw->clearStatistics()) {
                std::cout << Color::GREEN << Color::BOLD
                          << "[+] Firewall statistics cleared successfully."
                          << Color::RESET << "\n";
            }

        } else if (inputChoice == "5") {
            // Option 5: Exit
            std::cout << "\n" << Color::CYAN
                      << "[*] Closing firewall connection and exiting...\n"
                      << "    (RAII destructor automatically invoking close())\n"
                      << "Goodbye!" << Color::RESET << "\n\n";
            running = false;

        } else {
            std::cout << Color::YELLOW << "[!] Invalid choice: '" << inputChoice
                      << "'. Please enter a number from 1 to 5.\n" << Color::RESET;
        }
    }

    return 0;
}
