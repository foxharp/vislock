Control physical access to a linux computer by locking all of its virtual
terminals.

vislock only allows the user of the active session (the user logged in on the
foreground virtual terminal) and the root user to unlock the computer and uses
PAM for authentication.

vislock uses 3 mechanisms to detect the user of the active session:

1. Querying systemd-logind(1) or elogind(8) if compiled with either
   `HAVE_SYSTEMD=1` or `HAVE_ELOGIND=1`
2. Searching the utmp file for an entry whose `ut_line` field is the base name
   of the active tty device file
3. Using the owner of the active tty device file typically set by login(1)

Installation
------------
vislock is build using the commands:

    $ make
    # make install

Please note, that the latter one requires root privileges.
By default, vislock is installed using the prefix `/usr/local`, so the full
path of the executable will be `/usr/local/bin/vislock`.

You can install it into a directory of your choice by overwriting the `PREFIX`
macro in the second command:

    # make PREFIX="/your/dir" install

Please also note, that the vislock executable will have root ownership and the
setuid bit set.

All build-time specific settings are set in the file `config.h`. Please check
and change them, so that they fit your needs. If the file `config.h` does not
already exist, then you have to create it with the following command:

    $ make config.h

You also have to make sure that vislock works with your PAM configuration. If
you have a restrictive PAM fallback config file `/etc/pam.d/other`, then you
need to create a suitable PAM config file for vislock named
`/etc/pam.d/vislock`. The sample `vislock.pam` should work for most users.

Usage
-----
The behaviour of vislock is completely controlled via command-line arguments,
it does not rely on environment variables.
vislock uses the utmp file to identify the owner of the current session (i.e.
active tty) and prompts for her password to unlock the computer.

The following command-line arguments are supported:

    -b       display the battery capacity on the lock screen
    -c       allow "reboot" and "suspend" responses, in lieu of password,
             with obvious result
    -d       fork and detach, parent returns after everything is set up
             (useful for suspend/hibernate scripts)
    -h       print short usage help and exit
    -l       only lock console switching
    -L       only enable console switching
    -m       mute kernel messages on console while vislock is running
    -p MSG   Display MSG before the password prompt
    -s       disable sysrq key while vislock is running
    -r       ask for root's password, rather than the user's, every 4th try
    -t       display the time of day on the lock screen
    -v       print version information and exit
