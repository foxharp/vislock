vislock will lock physical access to a linux computer by disabling
all of its virtual terminals.

vislock allows any active user of the local machine, as well as
others mentioned on the command line (e.g., root) to unlock the
computer.  vislock uses PAM for authentication.

vislock uses two mechanisms to find the local active users.  Which
mechanism to use is determined at compile time (see the Makefile).

- Querying systemd-logind(1) or elogind(8) for non-remote, active,
    users (if compiled with either `HAVE_SYSTEMD=1` or
    `HAVE_ELOGIND=1`).

- Searching the utmp file for entries whose `ut_line` field 
    represents a VC (ttyN).

Without options, the lock screen consists of just a simple "password:"
prompt.  It can also show the time, a laptop's battery level, and can
even allow shutdown/reboot directly from the lock screen.  (I've
always been frustrated by lock screens that don't have these basic
features.)

Note that ssh, or other network access, is unaffected by vislock.

![ screenshot ]( screenshot.png )


Installation
------------
vislock is built and installed using:

    $ make
    # make install

By default, vislock is installed to `/usr/local`, so the full path of
the executable will be `/usr/local/bin/vislock`.  Modify this using:

    # make PREFIX="/your/dir" install

vislock will be installed as setuid-to-root.

All build-time specific settings are in the file `config.def.h`. 
Check and change them as needed.

You also have to make sure that vislock works with your PAM
configuration.  If you have a restrictive PAM fallback config file
`/etc/pam.d/other`, then you need to create a suitable PAM config file
for vislock named `/etc/pam.d/vislock`.  The sample `vislock.pam`
should work for most users.

Usage
-----
The behavior of vislock is completely controlled by command-line
arguments.  vislock uses either logind or utmp to identify the active
local users on the machine.  Any of their passwords will unlock the
computer.

Display options:
  -p MSG    display MSG at top of lock screen
  -t        display time-of-day on lock screen
  -b        display battery level on lock screen
  -n        display names of unlocking users on lock screen
  -c        allow shutdown/reboot commands on lock screen
  -f FONT   specify file containing lock screen font (full path)
  -m        mute kernel messages while running

Configuration:
  -u USER   add USER to the "allowed to unlock" list (can be repeated)
  -s        disable sysrq while running
  -d        fork and detach process, useful in scripts when suspending

Debug:
  -l        disable console switching and exit
  -L        enable console switching and exit (useful after crash)

Misc:
  -v        version
  -h        help


