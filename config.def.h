/* pseudo device that points to foreground console:    */
static const char * const CONSOLE_DEVICE  = "/dev/tty0";

/* common basename of all virtual console devices:     */
static const char * const TTY_DEVICE_BASE = "/dev/tty";

/* full path to kernel sysrq control file:             */
static const char * const SYSRQ_PATH = "/proc/sys/kernel/sysrq";

/* full path to kernel printk file:			*/
static const char * const PRINTK_PATH = "/proc/sys/kernel/printk";

/* full path to battery capacity */
static const char * const BATTERY_PATH = "/sys/class/power_supply/BAT0/capacity";

/* shutdown and reboot commands */
static const char * const REBOOT_CMD = "/bin/systemctl reboot";
static const char * const SHUTDOWN_CMD = "/bin/systemctl poweroff";

