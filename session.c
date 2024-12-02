#include "vislock.h"

#include <paths.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <errno.h>
#include <utmp.h>
#include <ctype.h>

#if HAVE_SYSTEMD
#include <systemd/sd-login.h>
#elif HAVE_ELOGIND
#include <elogind/sd-login.h>
#endif

#if HAVE_SYSTEMD || HAVE_ELOGIND

int get_users_logind(void) {
	int  i, n;
	char **sessions = NULL;
	uid_t sess_uid;

	n = sd_get_sessions(&sessions);

	for (i = 0; i < n; i++) {

		if (sd_session_is_remote(sessions[i]))
			continue;

		if (sd_session_get_uid(sessions[i], &sess_uid) < 0)
			continue;

		struct passwd *pwd = getpwuid(sess_uid);
		if (pwd)
			add_username(pwd->pw_name);

	}

	for (i = 0; i < n; i++)
		free(sessions[i]);
	free(sessions);

	return 1;
}

void get_users_utmp(void) {
	// stub
}

#else

int get_users_logind(void) {
	// stub
	return 0;
}

void get_users_utmp(void) {

	FILE *uf;
	struct utmp r;
	char name[UT_NAMESIZE+1];

	while ((uf = fopen(_PATH_UTMP, "r")) == NULL && errno == EINTR);
	if (uf == NULL)
		error(EXIT_FAILURE, 0, "Couldn't open utmp file");

	while (!feof(uf) && !ferror(uf)) {
		if (fread(&r, sizeof(r), 1, uf) != 1)
			continue;
		if (r.ut_type != USER_PROCESS || r.ut_user[0] == '\0')
			continue;

		// ut_line must be ttyN or ttyNN
		if (strncmp(r.ut_line, "tty", 3) != 0)
			continue;
		if (!isdigit(r.ut_line[3]))
			continue;
		if ( (r.ut_line[4] == '\0') ||
		    ((r.ut_line[5] == '\0') && isdigit(r.ut_line[4]))
		   ) {
			strncpy(name, r.ut_user, UT_NAMESIZE);
			name[UT_NAMESIZE] = '\0';
			add_username(name);
		}
	}
	fclose(uf);

}

#endif


