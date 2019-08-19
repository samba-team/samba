/*
   Unix SMB/CIFS implementation.
   xattr renaming
   Copyright (C) Ralph Boehme 2017

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

#include "includes.h"
#include "system/filesys.h"
#include "popt_common.h"
#include <ftw.h>

static struct rename_xattr_state {
	int follow_symlink;
	int print;
	int force;
	int verbose;
	char *xattr_from;
	char *xattr_to;
} state;

static int rename_xattr(const char *path,
			const struct stat *sb,
			int typeflag,
			struct FTW *ftwbuf)
{
	ssize_t len;
	int ret;

	if (typeflag == FTW_SL) {
		d_printf("Ignoring symlink %s\n", path);
		return 0;
	}

	if (state.verbose) {
		d_printf("%s\n", path);
	}

	len = getxattr(path, state.xattr_from, NULL, 0);
	if (len < 0) {
		if (errno == ENOATTR) {
			return 0;
		}
		d_printf("getxattr [%s] failed [%s]\n",
			 path, strerror(errno));
		return -1;
	}

	{
		uint8_t buf[len];

		len = getxattr(path, state.xattr_from, &buf[0], len);
		if (len == -1) {
			d_printf("getxattr [%s] failed [%s]\n",
				 path, strerror(errno));
			return -1;
		}

		ret = setxattr(path, state.xattr_to, &buf[0], len, XATTR_CREATE);
		if (ret != 0) {
			if (errno != EEXIST) {
				d_printf("setxattr [%s] failed [%s]\n",
					 path, strerror(errno));
				return -1;
			}
			if (!state.force) {
				d_printf("destination [%s:%s] exists, use -f to force\n",
					 path, state.xattr_to);
				return -1;
			}
			ret = setxattr(path, state.xattr_to, &buf[0], len, XATTR_REPLACE);
			if (ret != 0) {
				d_printf("setxattr [%s:%s] failed [%s]\n",
					 path, state.xattr_to, strerror(errno));
				return -1;
			}
		}

		ret = removexattr(path, state.xattr_from);
		if (ret != 0) {
			d_printf("removexattr [%s:%s] failed [%s]\n",
				 path, state.xattr_from, strerror(errno));
			return -1;
		}

		if (state.print) {
			d_printf("Renamed %s to %s on %s\n",
				 state.xattr_from, state.xattr_to, path);
		}
	}

	return 0;
}

int main(int argc, const char *argv[])
{
	int c;
	const char *path = NULL;
	poptContext pc = NULL;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "from",
			.shortName  = 's',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &state.xattr_from,
			.val        = 's',
			.descrip    = "xattr source name",
		},
		{
			.longName   = "to",
			.shortName  = 'd',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &state.xattr_to,
			.val        = 'd',
			.descrip    = "xattr destination name",
		},
		{
			.longName   = "follow-symlinks",
			.shortName  = 'l',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &state.follow_symlink,
			.val        = 'l',
			.descrip    = "follow symlinks, the default is to "
				      "ignore them",
		},
		{
			.longName   = "print",
			.shortName  = 'p',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &state.print,
			.val        = 'p',
			.descrip    = "print files where the xattr got "
				      "renamed",
		},
		{
			.longName   = "verbose",
			.shortName  = 'v',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &state.verbose,
			.val        = 'v',
			.descrip    = "print files as they are checked",
		},
		{
			.longName   = "force",
			.shortName  = 'f',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &state.force,
			.val        = 'f',
			.descrip    = "force overwriting of destination xattr",
		},
		POPT_TABLEEND
	};
	TALLOC_CTX *frame = talloc_stackframe();
	const char *s = NULL;
	int ret = 0;

	if (getuid() != 0) {
		d_printf("%s only works as root!\n", argv[0]);
		ret = 1;
		goto done;
	}

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptSetOtherOptionHelp(pc, "-s STRING -d STRING PATH [PATH ...]");

	while ((c = poptGetNextOpt(pc)) != -1) {
		switch (c) {
		case 's':
			s = poptGetOptArg(pc);
			state.xattr_from = talloc_strdup(frame, s);
			if (state.xattr_from == NULL) {
				ret = 1;
				goto done;
			}
			break;
		case 'd':
			s = poptGetOptArg(pc);
			state.xattr_to = talloc_strdup(frame, s);
			if (state.xattr_to == NULL) {
				ret = 1;
				goto done;
			}
			break;
		}
	}

	if (state.xattr_from == NULL || state.xattr_to == NULL) {
		poptPrintUsage(pc, stderr, 0);
		ret = 1;
		goto done;
	}

	if (poptPeekArg(pc) == NULL) {
		poptPrintUsage(pc, stderr, 0);
		ret = 1;
		goto done;
	}

	while ((path = poptGetArg(pc)) != NULL) {
		ret = nftw(path, rename_xattr, 256,
			   state.follow_symlink ? 0 : FTW_PHYS);
	}

done:
	poptFreeContext(pc);

	TALLOC_FREE(frame);
	return ret;
}
