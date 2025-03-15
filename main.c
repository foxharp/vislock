/* Copyright 2013 Bert Muennich
 * Copyright 2024 Paul Fox
 *
 * This file is part of vislock.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "vislock.h"
#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <security/pam_misc.h>
#include <linux/tiocl.h>
#include <sys/ioctl.h>

#define PASSBUFLEN 30
#define NUSERS 10

static int oldvt;
static vt_t vt;
static int oldsysrq;
static int oldprintk;
static pid_t chpid;
static int locked;
static userinfo_t users[NUSERS];

struct pam_response *reply;

/* scheme to allow access to password before authenticating:
 *  https://stackoverflow.com/questions/5913865/pam-authentication-for-a-legacy-application/5970078#5970078
 */

int function_conversation(int num_msg, const struct pam_message **msg,
		struct pam_response **resp, void *appdata_ptr)
{
	*resp = reply;
	return PAM_SUCCESS;
}

static struct pam_conv conv = {
	function_conversation,
	NULL
};

static void get_pam(userinfo_t *uinfo) {

	/* pam would tell us this much later, let's catch it early */
	if (!getpwnam(uinfo->name))
		error(EXIT_FAILURE, 0, "No such user '%s'", uinfo->name);

	if (pam_start("vislock", uinfo->name, &conv, &uinfo->pamh) != PAM_SUCCESS)
		error(EXIT_FAILURE, 0, "pam_start failure");
}

void get_user_by_name(userinfo_t *uinfo, const char *name) {
	uinfo->name = estrdup(name);
	get_pam(uinfo);
}

CLEANUP void free_user(userinfo_t *uinfo) {
	if (uinfo->pamh != NULL)
		pam_end(uinfo->pamh, uinfo->pam_status);
}



int nusers;
const char *usernames[NUSERS];

void add_username(const char *name) {
	int i;

	// check for duplicates
	for(i = 0; i < nusers; i++) {
		if (strcmp(usernames[i], name) == 0)
			return;
	}

	if (nusers < NUSERS) {
		usernames[nusers++] = estrdup(name);
	} else {
		fprintf(stderr, "Warning:  Too many users, max %d\n", NUSERS);
	}
}

void cleanup() {
	if (options->detach && chpid > 0)
		/* No cleanup in parent after successful fork */
		return;
	int i;
	for (i = 0; i < nusers; i++)
		free_user(&users[i]);
	close(0);
	close(1);
	close(2);
	if (oldprintk > 1)
		write_int_to_file(PRINTK_PATH, oldprintk);
	if (locked)
		return;
	if (oldsysrq > 0)
		write_int_to_file(SYSRQ_PATH, oldsysrq);
	if (vt.fd >= 0)
		vt_reset(&vt);
	vt_lock_switch(0);
	vt_release(&vt, oldvt);
	vt_destroy();
}

void sa_handler_exit(int signum) {
	exit(0);
}

int refresh_requested;
void sa_handler_refresh(int signum) {
	refresh_requested = 3;
	return;
}

void setup_signal(int signum, void (*handler)(int)) {
	struct sigaction sigact;

	sigact.sa_flags = 0;
	sigact.sa_handler = handler;
	sigemptyset(&sigact.sa_mask);

	if (sigaction(signum, &sigact, NULL) < 0)
		error(0, errno, "signal %d", signum);
}

int avail_c(int secs)
{
	fd_set readfds;
	struct timeval timeout;
	int fd = 0;

	// Set up the file descriptor set
	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);

	timeout.tv_sec = secs;
	timeout.tv_usec = 0;

	// Use select to check if data is available
	int result = select(fd + 1, &readfds, NULL, NULL, &timeout);

	// was it a signal?
	if (result == -1 && errno == EINTR)
		return -1;

	// a failure?
	if (result < 0)
		error(EXIT_FAILURE, errno, "select");

	// characters?
	if (result > 0)
		return 1;

	// result == 0, it's a timeout
	return 0;
}

void get_password(char *buffer, size_t size)
{
	struct termios oldt, newt;

	// Disable echo
	tcgetattr(0, &oldt);
	newt = oldt;
	newt.c_lflag &= ~ECHO;
	tcsetattr(0, TCSANOW, &newt);

	// Read password
	// After a suspend, the first character is sometimes NUL, leading
	// to a guaranteed incorrect password attempt.  Remove NUL characters
	// from the password as we read it.  Messy.
	int i = 0;
	while (i < size-1) {
		int c;
		c = getchar();
		if (c == '\0')  // skip it
			continue;
		if (c == EOF || c == '\n')  // kill it
			c = '\0';
		buffer[i++] = c;
		if (c == '\0')
			break;
	}
	buffer[size-1] = '\0';

	// Re-enable echo
	tcsetattr(0, TCSANOW, &oldt);
}

int
do_pam_auth(userinfo_t *u, char *pass) {

	/* Set PAM_TTY for PAM modules that might want it, e.g.
	 * pam_securetty.so.  From xxc3nsoredxx on github, for
	 * physlock issue #110.
	 */
	u->pam_status = pam_set_item(u->pamh, PAM_TTY, vt.vt_name);
	if (u->pam_status != PAM_SUCCESS) {
		error(EXIT_FAILURE, 0, "Unable to set PAM_TTY: %s",
				pam_strerror(u->pamh, u->pam_status));
	}

	reply = (struct pam_response *) malloc(sizeof(struct pam_response));
	reply[0].resp = estrdup(pass);
	reply[0].resp_retcode = 0;

	u->pam_status = pam_authenticate(u->pamh, 0);
	switch (u->pam_status) {
	case PAM_SUCCESS:
		pam_setcred(u->pamh, PAM_REFRESH_CRED);
		return 0;

	case PAM_AUTH_ERR:
		return -1;

	case PAM_MAXTRIES:
		return -2;

	case PAM_ABORT:
	case PAM_CRED_INSUFFICIENT:
	case PAM_AUTHINFO_UNAVAIL:
	case PAM_USER_UNKNOWN:
		printf("\n%s\n", pam_strerror(u->pamh, u->pam_status));
		return EXIT_FAILURE;

	default:
		/* intermittent error?
		 * see https://github.com/xyb3rt/vislock/commit/15744f5a2bf05178c1eafc7c4f8a46ffabb29184
		 * and https://github.com/xyb3rt/vislock/issues/68
		 */
		sleep(5);
		return -3;
	}
}

char *
timestring()
{
	static char outstr[200];

	time_t t;
	struct tm *tmp;

	t = time(NULL);
	tmp = localtime(&t);
					// e.g., Wednesday Dec 11     9:22 am
	(void)strftime(outstr, sizeof(outstr), "%A %b %-e    %l:%M %P", tmp);

	return outstr;
}

void set_font()
{
	struct stat sb;

	if (stat(options->fontfile, &sb) != 0 || ! S_ISREG(sb.st_mode))
		error(EXIT_FAILURE, 0, "Font file is not a regular file");

	pid_t pid = fork();

	if (pid < 0) {
		error(EXIT_FAILURE, errno, "fork");
	} else if (pid > 0) {
		int status;
		waitpid(pid, &status, 0);
	} else {
		char *args[] = {"/usr/bin/setfont",
				(char *)options->fontfile, NULL};
		char *envp[] = {NULL};

		if (execve("/usr/bin/setfont", args, envp) == -1) {
			error(EXIT_FAILURE, errno, "execve");
		}
		// not reached
	}
}

#define CLEARSCREEN "\x1b[H\x1b[J"
#define CLEARLINE "\x1b[2K"
#define CHOOSELINE "\x1b[%dH"	    // parameter is line no.
#define BLANKAFTER "\x1b[9;%d]"	    // parameter in minutes
#define CYANFG "\x1b[36m"
#define REDFG "\x1b[31m"
#define REDBG "\x1b[41m"
#define NORMAL "\x1b[39m\x1b[49m"

/* returns no. of lines printed */
int display_message(void) {

	const char *msg = options->message;

	printf(CLEARSCREEN);

	if (msg[0]) {
		int wasnl = 0;

		/* figure out how long (in lines) the message is, so
		 * we don't have to repaint it over and over again.
		 * it would probably work okay, but if it were a
		 * really long message, it might cause screen flashing
		 * on some displays?
		 * also note whether string ended with a newline -- we
		 * want to add one if not.
		 */

		printf("%s", msg);

		int lines = 0;
		const char *p;

		for (p = msg; *p; p++) {
			if (*p == '\n') {
				wasnl = 1;
				lines++;;
			} else {
				wasnl = 0;
			}
		}
		if (!wasnl) {
			putchar('\n');
			lines++;
		}

		return lines;
	}

	return 0;
}

void display_refresh(int fails, int startline) {
	int i;

	printf(CHOOSELINE, startline);

	/* line 1:  time of day */
	if (options->timeofday) {
		printf(CLEARLINE);
		printf("%s\n", timestring());
	}

	/* line 2:  battery capacity */
	if (options->batterycap) {

		char *color, *normal;

		int capacity =
		    read_int_from_file(BATTERY_PATH "/capacity", '\n');
		char *status =
		    read_string_from_file(BATTERY_PATH "/status", '\n');

		if (strcmp(status, "Charging") == 0) {
			color = CYANFG; normal = NORMAL;
		} else if (capacity <= 5) {
			color = REDBG; normal = NORMAL;
		} else if (capacity <= 10) {
			color = REDFG; normal = NORMAL;
		} else {
			color = ""; normal = "";
		}
		printf(CLEARLINE);
		printf("Battery: %s%d%%%s\n", color, capacity, normal);
	}

	/* line 3:  user names */
	if (options->names) {
		printf(CLEARLINE);
		for (i = 0; i < nusers; i++)
			printf("%s ", usernames[i]);
		printf("\n");
	}

	/* line 4:  failure indicators */
	printf(CLEARLINE);
	if (fails > 10) fails = 1;
	for (i = 0; i < fails; i++) printf(":-( ");
	printf("\n");
	/* we're only called more than once if there was a password
	 * mismatch.  so, get ready for the next call */

	/* line 5: the prompt */
	printf(CLEARLINE);
	if (options->commands)
		printf("\"reboot\", \"shutdown\", or a ");
	printf("password: ");
	fflush(stdout);

}

int main(int argc, char **argv) {
	int i;
	int fails = 0;
	char *passbuff;

	oldvt = oldsysrq = oldprintk = vt.nr = vt.fd = -1;

	error_init(2);

	parse_options(argc, argv);

	if (options->batterycap && access(BATTERY_PATH, R_OK|X_OK) < 0) {
		error(0, 0, "Warning: battery information inaccessible, "
				"-b ignored\n");
		options->batterycap = 0;
	}

	/* Users from -u options are already in usernames[].  Now
	 * add users from either logind or utmp.
	 */
	if (!get_users_logind())    // only fails if unavailable
		get_users_utmp();

	/* this can occur if no one is logged in to the machine, in
	 * which case it's proper that the locker not activate.
	 */
	if (nusers == 0)
		error(EXIT_FAILURE, 0, "No users found or specified");

	if (geteuid() != 0)
		error(EXIT_FAILURE, 0, "Must be root!");

	setup_signal(SIGTERM, sa_handler_exit);
	setup_signal(SIGQUIT, sa_handler_exit);
	setup_signal(SIGHUP, SIG_IGN);
	setup_signal(SIGINT, SIG_IGN);
	setup_signal(SIGUSR1, sa_handler_refresh);
	setup_signal(SIGUSR2, SIG_IGN);

	vt_init();
	vt_get_current(&oldvt);

	if (options->lock_switch != -1) {
		if (vt_lock_switch(options->lock_switch) == -1)
			exit(EXIT_FAILURE);
		vt_destroy();
		return 0;
	}

	for (i = 0; i < nusers; i++)
		get_user_by_name(&users[i], usernames[i]);

	atexit(cleanup);

	if (options->disable_sysrq) {
		oldsysrq = read_int_from_file(SYSRQ_PATH, '\n');
		if (oldsysrq > 0)
			if (write_int_to_file(SYSRQ_PATH, 0) == -1)
				exit(EXIT_FAILURE);
	}

	if (options->mute_kernel_messages) {
		oldprintk = read_int_from_file(PRINTK_PATH, '\t');
		if (oldprintk > 1)
			if (write_int_to_file(PRINTK_PATH, 1) == -1)
				exit(EXIT_FAILURE);
	}

	vt_lock_switch(0);
	vt_acquire(&vt);
	vt_lock_switch(1);

	if (options->fontfile)
		set_font();

	if (options->detach) {
		chpid = fork();
		if (chpid < 0) {
			error(EXIT_FAILURE, errno, "fork");
		} else if (chpid > 0) {
			return 0;
		} else {
			setsid();
			sleep(1); /* w/o this, accessing the vt might fail */
			vt_reopen(&vt);
		}
	}
	vt_secure(&vt);

	dup2(vt.fd, 0);
	dup2(vt.fd, 1);
	dup2(vt.fd, 2);

	/* enable or disable display blanking:  an interval of 0 (the
	 * default) disables */
	printf(BLANKAFTER, options->screenoff);

	int msglines = display_message();

	locked = 1;

	while (locked) {
		static int refresh_delay;

		display_refresh(fails, msglines + 1);

		/* if we got SIGUSR1, do a couple of extra refreshes.  it's
		 * likely because battery status has changed, and that can
		 * take a while to settle. */
		if (refresh_requested) {
			refresh_delay = 4 * refresh_requested;
			refresh_requested--;
		} else {
			refresh_delay = 45;
		}

		/* while waiting for a character, a timeout should
		 * just refresh the screen (to keep the clock reasonably
		 * up to date), but characters and signals should also
		 * unblank it. */
		int r = avail_c(refresh_delay);

		if (r == 0) // timeout
			continue;

		/* unblank.  this is how "setterm --blank=poke" does it */
		char ioctlarg = TIOCL_UNBLANKSCREEN;
		(void)ioctl(vt.fd, TIOCLINUX, &ioctlarg);

		if (r < 0) // signal
			continue;

		/* r > 0, characters are available */

		passbuff = malloc(PASSBUFLEN);

		get_password(passbuff, PASSBUFLEN);

		if (options->commands) {
			if (strcmp(passbuff, "reboot") == 0) {
				printf("\nRebooting...\n");
				system(REBOOT_CMD);
				sleep(10);
				continue;
			}
			if (strcmp(passbuff, "shutdown") == 0) {
				printf("\nShutting down...\n");
				system(SHUTDOWN_CMD);
				sleep(10);
				continue;
			}
		}

		for (i = 0; i < nusers; i++) {
			if (do_pam_auth(&users[i], passbuff) == 0) {
				locked = 0;
				break;
			}
		}

		/* scrub our copy of the password.  pam scrubbed theirs */
		explicit_bzero(passbuff, sizeof(passbuff));
		free(passbuff);

		if (locked == 0)
			break;
		fails++;
	}

	return 0;
}

