/* Copyright 2013 Bert Muennich
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

#define PASSBUFLEN 30

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

void cleanup() {
	if (options->detach && chpid > 0)
		/* No cleanup in parent after successful fork */
		return;
	int i;
	for (i = 0; i < options->nusers; i++)
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

void sa_handler_refresh(int signum) {
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
	if (result == -1 && errno == EINTR)
		return 0;
	if (result < 0)
		error(EXIT_FAILURE, errno, "select");

	return (result > 0 && FD_ISSET(fd, &readfds));
}

void get_password(char *prompt, char *buffer, size_t size)
{
	struct termios oldt, newt;
	printf("%s", prompt);
	fflush(stdout);

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

	if (prompt[0])
		printf("\n");
}

int
do_pam_auth(userinfo_t *u, char *pass) {

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
		fprintf(vt.ios, "\n%s\n", pam_strerror(u->pamh, u->pam_status));
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

#define CLEARLINE "\x1b[2K"
#define CLEARSCREEN "\x1b[2J"
#define CHOOSELINE "\x1b[14H"
#define FIRSTLINE "\x1b[1H"
#define HIDECURSOR "\x1b[?25l"
#define RED "\x1b[31m"
#define NORMAL "\x1b[39m"

int main(int argc, char **argv) {
	int tries = 0;
	uid_t owner;
	int i;

	char *passbuff;

	oldvt = oldsysrq = oldprintk = vt.nr = vt.fd = -1;
	vt.ios = NULL;

	error_init(2);

	parse_options(argc, argv);
	if (options->nusers == 0)
		error(EXIT_FAILURE, 0, "No users specified");

	if (geteuid() != 0)
		error(EXIT_FAILURE, 0, "Must be root!");

	setup_signal(SIGTERM, sa_handler_exit);
	setup_signal(SIGQUIT, sa_handler_exit);
	setup_signal(SIGHUP, SIG_IGN);
	setup_signal(SIGINT, SIG_IGN);
	setup_signal(SIGUSR1, sa_handler_refresh);
	setup_signal(SIGUSR2, SIG_IGN);

	vt_init();
	vt_get_current(&oldvt, &owner);

	if (options->lock_switch != -1) {
		if (vt_lock_switch(options->lock_switch) == -1)
			exit(EXIT_FAILURE);
		vt_destroy();
		return 0;
	}

	for (i = 0; i < options->nusers; i++)
		get_user_by_name(&users[i], options->usernames[i]);

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

	fprintf(vt.ios, CLEARSCREEN);
	if (options->prompt != NULL && options->prompt[0] != '\0') {
		fprintf(vt.ios, "%s\n\n", options->prompt);
	}

	locked = 1;


	while (locked) {

		if (options->timeofday) {
			fprintf(vt.ios, CHOOSELINE CLEARLINE "%s\n",
				timestring());
		}

		if (options->batterycap) {
			int capacity = read_int_from_file(BATTERY_PATH, '\n');
			char *red, *normal;
			if (capacity < 15) {
				red = RED; normal = NORMAL;
			} else {
				red = ""; normal = "";
			}
			fprintf(vt.ios, CLEARLINE "Battery: %s%d%%%s\n",
				red, capacity, normal);
		}

		fprintf(vt.ios, CLEARLINE);
		if (tries > 10) tries = 1;
		for (i = 0; i < tries; i++) fprintf(vt.ios, ":-( ");

		// Build the "prompt" line
		fprintf(vt.ios, "\n" CLEARLINE);
		if (options->commands)
			fprintf(vt.ios, "\"reboot\", \"shutdown\", or ");
		fprintf(vt.ios, "password: ");
		fflush(vt.ios);

		// SIGUSR1, or a timeout, will cause a screen refresh
		if (!avail_c(30))
			continue;

		passbuff = malloc(PASSBUFLEN);

		get_password("", passbuff, PASSBUFLEN);

		if (options->commands) {
			if (strcmp(passbuff, "reboot") == 0) {
				fprintf(vt.ios, "Rebooting...\n");
				system("systemctl reboot");
				for(;;);
			}
			if (strcmp(passbuff, "shutdown") == 0) {
				fprintf(vt.ios, "Shutting down...\n");
				system("systemctl shutdown");
				for(;;);
			}
		}

		for (i = 0; i < options->nusers; i++) {
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

		tries++;

	}

	return 0;
}

