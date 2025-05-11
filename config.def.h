/* pseudo device that points to foreground console */
#define CONSOLE_DEVICE  "/dev/tty0"

/* common basename of all virtual console devices */
#define TTY_DEVICE_BASE "/dev/tty"

/* full path to kernel sysrq control file */
#define SYSRQ_PATH "/proc/sys/kernel/sysrq"

/* full path to kernel printk file */
#define PRINTK_PATH "/proc/sys/kernel/printk"

/* partial path to battery information */
#define BATTERY_PATH "/sys/class/power_supply/BAT0/"

/* shutdown and reboot commands */
#define REBOOT_CMD    "/usr/bin/sudo /sbin/reboot"
#define SHUTDOWN_CMD  "/usr/bin/sudo /sbin/shutdown"

