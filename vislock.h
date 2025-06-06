/* Copyright 2018 Bert Muennich
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

#ifndef PHYSLOCK_H
#define PHYSLOCK_H

#include <stdarg.h>
#include <stdio.h>
#include <termios.h>
#include <sys/types.h>
#include <security/pam_appl.h>

/*
 * Annotation for functions called in cleanup().
 * These functions are not allowed to call error(!0, ...) or exit().
 */
#define CLEANUP


/* main.c */

typedef struct userinfo_s {
	const char *name;
	int pam_status;
	pam_handle_t *pamh;
} userinfo_t;

void get_user_by_name(userinfo_t*, const char*);
CLEANUP void free_user(userinfo_t*);

void add_username(const char *);

/* options.c */

typedef struct options_s {
	int detach;
	int disable_sysrq;
	int lock_switch;
	int mute_kernel_messages;
	int batterycap;
	int timeofday;
	int names;
	int commands;
	int screenoff;
	const char *message;
	const char *fontfile;
} options_t;

extern options_t *options;

void parse_options(int, char**);


/* session.c */

int get_users_logind(void);
void get_users_utmp(void);


/* util.h */

extern const char *progname;

void error_init(int);
void error(int, int, const char*, ...);
char *estrdup(const char*);
int read_int_from_file(const char*, char);
char *read_string_from_file(const char *path, char ending_char);
CLEANUP ssize_t write_int_to_file(const char*, int);


/* vt.h */

typedef struct vt_s {
	int nr;
	FILE *ios;
	int fd;
	char *vt_name;
	struct termios term;
	struct termios term_orig;
} vt_t;

void vt_init();
CLEANUP void vt_destroy();
void vt_get_current(int*);
CLEANUP int vt_lock_switch(int);
void vt_acquire(vt_t*);
void vt_reopen(vt_t*);
CLEANUP int vt_release(vt_t*, int);
void vt_secure(vt_t*);
CLEANUP void vt_reset(vt_t*);

#endif /* PHYSLOCK_H */

