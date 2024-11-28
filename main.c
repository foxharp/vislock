/* Copyright 2013 Bert Muennich
 *
 * This file is part of physlock.
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

#include "physlock.h"
#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
static userinfo_t root, user;

struct pam_response *reply;

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
	if (pam_start("physlock", uinfo->name, &conv, &uinfo->pamh) != PAM_SUCCESS)
		error(EXIT_FAILURE, 0, "No pam for user %s", uinfo->name);
}

void get_user_by_id(userinfo_t *uinfo, uid_t uid) {
	struct passwd *pw;

	while (errno = 0, (pw = getpwuid(uid)) == NULL && errno == EINTR);
	if (pw == NULL)
		error(EXIT_FAILURE, 0, "No password file entry for uid %u found", uid);

	get_user_by_name(uinfo, pw->pw_name);
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
	free_user(&user);
	free_user(&root);
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

void setup_signal(int signum, void (*handler)(int)) {
	struct sigaction sigact;

	sigact.sa_flags = 0;
	sigact.sa_handler = handler;
	sigemptyset(&sigact.sa_mask);
	
	if (sigaction(signum, &sigact, NULL) < 0)
		error(0, errno, "signal %d", signum);
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
	    if (c == 0) continue;
	    if (c == EOF || c == '\n') c = '\0';
	    buffer[i++] = c;
	    if (c == '\0')
		break;
	}
	buffer[size-1] = '\0';

	// Re-enable echo
	tcsetattr(0, TCSANOW, &oldt);
	printf("\n");
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

int main(int argc, char **argv) {
	int try = 0, root_user = 1;
	uid_t owner;
	userinfo_t *u = &user;

	char *passbuff;

	oldvt = oldsysrq = oldprintk = vt.nr = vt.fd = -1;
	vt.ios = NULL;

	error_init(2);
	parse_options(argc, argv);

	if (geteuid() != 0)
		error(EXIT_FAILURE, 0, "Must be root!");

	setup_signal(SIGTERM, sa_handler_exit);
	setup_signal(SIGQUIT, sa_handler_exit);
	setup_signal(SIGHUP, SIG_IGN);
	setup_signal(SIGINT, SIG_IGN);
	setup_signal(SIGUSR1, SIG_IGN);
	setup_signal(SIGUSR2, SIG_IGN);

	vt_init();
	vt_get_current(&oldvt, &owner);

	if (options->lock_switch != -1) {
		if (vt_lock_switch(options->lock_switch) == -1)
			exit(EXIT_FAILURE);
		vt_destroy();
		return 0;
	}

	if (get_user_logind(&user, oldvt) == -1 && get_user_utmp(&user, oldvt) == -1)
		get_user_by_id(&user, owner);

	if (options->rootunlock) {
	    get_user_by_id(&root, 0);
	    if (strcmp(user.name, root.name) != 0)
		    root_user = 0;
	    else
		    u = &root;
	}

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

	if (options->prompt != NULL && options->prompt[0] != '\0') {
		fprintf(vt.ios, "%s\n\n", options->prompt);
	}

	locked = 1;


	while (locked) {
		if (!root_user && try >= (u == &root ? 1 : 3)) {
			u = (u == &root ? &user : &root);
			try = 0;
		}
		if (u == &root) {
			fprintf(vt.ios, "%s: ", root.name);
			fflush(vt.ios);
		}

		/* password shenanigans taken from:
		 *  https://stackoverflow.com/questions/5913865/pam-authentication-for-a-legacy-application/5970078#5970078
		 */

		reply = (struct pam_response *)malloc(sizeof(struct pam_response));
		passbuff = malloc(PASSBUFLEN);

		if (!options->commands) {
		    get_password("password: ", passbuff, PASSBUFLEN);
		} else {
		    get_password("\"reboot\", \"shutdown\", or password: ",
		    	passbuff, PASSBUFLEN);
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

		reply[0].resp = passbuff;
		reply[0].resp_retcode = 0;

		u->pam_status = pam_authenticate(u->pamh, 0);
		switch (u->pam_status) {
		case PAM_SUCCESS:
			pam_setcred(u->pamh, PAM_REFRESH_CRED);
			locked = 0;
			break;
		case PAM_AUTH_ERR:
		case PAM_MAXTRIES:
			if (options->batterycap) {
				/* do this here, so that the data is
				 * accurate.  if we did it first time
				 * through, it would likely be stale after
				 * a system suspend.  */
				int capacity = read_int_from_file(BATTERY_PATH, '\n');
				fprintf(vt.ios, "Battery: %d%%\n", capacity);
			}
			fprintf(vt.ios, "\n");
			try++;
			break;
		case PAM_ABORT:
		case PAM_CRED_INSUFFICIENT:
		case PAM_USER_UNKNOWN:
			fprintf(vt.ios, "%s\n", pam_strerror(u->pamh, u->pam_status));
			return EXIT_FAILURE;
		default:
			/* intermittent error? */
			sleep(5);
			break;
		}
	}

	return 0;
}

