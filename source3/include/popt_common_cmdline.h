/*
   Unix SMB/CIFS implementation.
   Common popt arguments
   Copyright (C) Jelmer Vernooij	2003
   Copyright (C) Christof Schmitt	2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef _POPT_COMMON_CREDENTIALS_H
#define _POPT_COMMON_CREDENTIALS_H

#include "popt_common.h"

extern struct poptOption popt_common_credentials[];
#define POPT_COMMON_CREDENTIALS \
	{ \
		NULL,						\
		0,						\
		POPT_ARG_INCLUDE_TABLE,			\
		popt_common_credentials,			\
		0,						\
		"Authentication options:",			\
		NULL						\
	},

struct user_auth_info *popt_get_cmdline_auth_info(void);
void popt_free_cmdline_auth_info(void);

void popt_common_credentials_set_ignore_missing_conf(void);
void popt_common_credentials_set_delay_post(void);
void popt_common_credentials_post(void);
void popt_burn_cmdline_password(int argc, char *argv[]);

#endif
