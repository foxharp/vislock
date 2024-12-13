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
#include "version.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static options_t _options;
options_t *options = &_options;

void print_usage() {
	fprintf(stderr, 
"usage: vislock [options]\n\
  -p MSG    display MSG at top of lock screen\n\
  -t        display time-of-day on lock screen\n\
  -b        display battery level on lock screen\n\
  -n        display names of unlocking users on lock screen\n\
  -c        allow shutdown/reboot commands on lock screen\n\
  -o MIN    turn the lock screen off after MIN minutes\n\
  -f FONT   specify file containing lock screen font\n\
  -u USER   add USER's password to unlock list (can be repeated)\n\
  -d        fork and detach process, useful when suspending immediately\n\
  -l        disable console switching and exit\n\
  -L        enable console switching and exit (useful after crash)\n\
  -m        mute kernel messages while running\n\
  -s        disable sysrq while running\n\
  -v        version\n\
  -h        help\n\
");
}

void print_version() {
	puts("vislock " VERSION);
}

void parse_options(int argc, char **argv) {
	int opt, n;
	char *endp;
	
	progname = strrchr(argv[0], '/');
	progname = progname != NULL ? progname + 1 : argv[0];

	_options.detach = 0;
	_options.disable_sysrq = 0;
	_options.lock_switch = -1;
	_options.mute_kernel_messages = 0;
	_options.message = "";

	while ((opt = getopt(argc, argv, "bcdf:hLlmno:p:stu:v")) != -1) {
		switch (opt) {
			case '?':
				print_usage();
				exit(1);
			case 'b':
				_options.batterycap = 1;
				break;
			case 'c':
				_options.commands = 1;
				break;
			case 'd':
				_options.detach = 1;
				break;
			case 'f':
				_options.fontfile = optarg;
				break;
			case 'h':
				print_usage();
				exit(0);
			case 'L':
				_options.lock_switch = 0;
				break;
			case 'l':
				_options.lock_switch = 1;
				break;
			case 'm':
				_options.mute_kernel_messages = 1;
				break;
			case 'n':
				_options.names = 1;
				break;
			case 'o':
				n = strtol(optarg, &endp, 10);
				if (*endp != '\0') {
				    error(EXIT_FAILURE, 0,
					"bad or missing argument for -o\n");
				}
				_options.screenoff = n;
				break;
			case 'p':
				_options.message = optarg;
				break;
			case 's':
				_options.disable_sysrq = 1;
				break;
			case 't':
				_options.timeofday = 1;
				break;
			case 'u':
				add_username(optarg);
				break;
			case 'v':
				print_version();
				exit(0);
		}
	}
}

