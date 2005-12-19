/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 

   Copyright (C) Jeremy Allison (jra@samba.org) 2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include "includes.h"
#include "utils/net.h"

/* The help subsystem for the USERSHARE subcommand */

static int net_usershare_add_usage(int argc, const char **argv)
{
	char c = *lp_winbind_separator();
	d_printf(
		"net usershare add [-Uusername%%password|-k] <sharename> <path> [<comment>] [<acl>]\n"
		"\tAdds the specified share name for this user.\n"
		"\tusername and password are credentials to use to query a server in looking up names\n"
		"\t-k specifies use kerberos authentication\n"
		"\t<sharename> is the new share name.\n"
		"\t<path> is the path on the filesystem to export.\n"
		"\t<comment> is the optional comment for the new share.\n"
		"\t<acl> is an optional share acl in the format \"DOMAIN%cname:X,DOMAIN%cname:X,....\"\n"
		"\t\t\"X\" represents a permission and can be any one of the characters f, r or d\n"
		"\t\twhere \"f\" means full control, \"r\" means read-only, \"d\" means deny access.\n"
		"\t\tname may be a domain user or group. For local users use the local server name "
		"instead of \"DOMAIN\"\n"
		"\t\tThe default acl is \"Everyone:r\" which allows everyone read-only access.\n",
		c, c );
	return -1;
}

static int net_usershare_delete_usage(int argc, const char **argv)
{
	d_printf(
		"net usershare delete <sharename>\n"\
		"\tdeletes the specified share name for this user.\n");
	return -1;
}

static int net_usershare_info_usage(int argc, const char **argv)
{
	d_printf(
		"net usershare info [-l|--long] [-Uusername%%password|-k] [wildcard sharename]\n"\
		"\tPrints out the path, comment and acl elements of shares that match the wildcard.\n"
		"\tBy default only gives info on shares owned by the current user\n"
		"\tAdd -l or --long to apply this to all shares\n"
		"\tusername and password are credentials to use to query a server in looking up names\n"
		"\t-k specifies use kerberos authentication\n"
		"\tOmit the sharename or use a wildcard of '*' to see all shares\n");
	return -1;
}

static int net_usershare_list_usage(int argc, const char **argv)
{
	d_printf(
		"net usershare list [-l|--long] [wildcard sharename]\n"\
		"\tLists the names of all shares that match the wildcard.\n"
		"\tBy default only lists shares owned by the current user\n"
		"\tAdd -l or --long to apply this to all shares\n"
		"\tOmit the sharename or use a wildcard of '*' to see all shares\n");
	return -1;
}

int net_usershare_usage(int argc, const char **argv)
{
	d_printf("net usershare add [-Uusername%%password|-k] <sharename> <path> [<comment>] [<acl>] to add or change a user defined share.\n"
		"net usershare delete <sharename> to delete a user defined share.\n"
		"net usershare info [-l|--long] [-Uusername%%pasword|-k] [wildcard sharename] to print info about a user defined share.\n"
		"net usershare list [-l|--long] [wildcard sharename] to list user defined shares.\n"
		"net usershare help\n"\
		"\nType \"net usershare help <option>\" to get more information on that option\n\n");

	net_common_flags_usage(argc, argv);
	return -1;
}

/***************************************************************************
 Add a single userlevel share.
***************************************************************************/

static int net_usershare_add(int argc, const char **argv)
{
	return -1;
}

/***************************************************************************
 Delete a single userlevel share.
***************************************************************************/

static int net_usershare_delete(int argc, const char **argv)
{
	pstring us_path;

	if (argc != 1) {
		return net_usershare_delete_usage(argc, argv);
	}

	if (!validate_net_name(argv[0], INVALID_SHARENAME_CHARS, strlen(argv[0]))) {
		d_printf("net usershare delete: share name %s contains "
                        "invalid characters (any of %s)\n",
                        argv[0], INVALID_SHARENAME_CHARS);
		return -1;
	}

	pstrcpy(us_path, lp_usershare_path());
	pstrcat(us_path, "/");
	pstrcat(us_path, argv[0]);

	if (unlink(us_path) != 0) {
		d_printf("net usershare delete: unable to remove usershare %s. "
			"Error was %s\n",
                        us_path, strerror(errno));
		return -1;
	}
	return 0;
}

/***************************************************************************
 Data structures to handle a list of usershare files.
***************************************************************************/

struct file_list {
	struct file_list *next, *prev;
	const char *pathname;
};

static struct file_list *flist;

/***************************************************************************
***************************************************************************/

static void get_basepath(pstring basepath)
{
	pstrcpy(basepath, lp_usershare_path());
	if (basepath[strlen(basepath)-1] == '/') {
		basepath[strlen(basepath)-1] = '\0';
	}
}

/***************************************************************************
***************************************************************************/

static int get_share_list(TALLOC_CTX *ctx, const char *wcard, BOOL only_ours)
{
	SMB_STRUCT_DIR *dp;
	SMB_STRUCT_DIRENT *de;
	uid_t myuid = geteuid();
	struct file_list *fl = NULL;
	pstring basepath;

	get_basepath(basepath);
	dp = sys_opendir(basepath);
	if (!dp) {
		d_printf("get_share_list: cannot open usershare directory %s. Error %s\n",
			basepath, strerror(errno) );
		return -1;
	}

	while((de = sys_readdir(dp)) != 0) {
		SMB_STRUCT_STAT sbuf;
		pstring path;
		const char *n = de->d_name;

		/* Ignore . and .. */
		if (*n == '.') {
			if ((n[1] == '\0') || (n[1] == '.' && n[2] == '\0')) {
				continue;
			}
		}

		if (!validate_net_name(n, INVALID_SHARENAME_CHARS, strlen(n))) {
			d_printf("get_share_list: ignoring bad share name %s\n",n);
			continue;
		}
		pstrcpy(path, basepath);
		pstrcat(path, "/");
		pstrcat(path, n);

		if (sys_lstat(path, &sbuf) != 0) {
			d_printf("get_share_list: can't lstat file %s. Error was %s\n",
				path, strerror(errno) );
			continue;
		}

		if (!S_ISREG(sbuf.st_mode)) {
			d_printf("get_share_list: file %s is not a regular file. Ignoring.\n",
				path );
			continue;
		}

		if (only_ours && sbuf.st_uid != myuid) {
			continue;
		}

		if (!unix_wild_match(wcard, n)) {
			continue;
		}

		/* (Finally) - add to list. */ 
		fl = TALLOC_P(ctx, struct file_list);
		if (!fl) {
			return -1;
		}
		fl->pathname = talloc_strdup(ctx, n);
		if (!fl->pathname) {
			return -1;
		}

		DLIST_ADD(flist, fl);
	}

	sys_closedir(dp);
	return 0;
}

/***************************************************************************
 Call a function for every share on the list.
***************************************************************************/

static int process_share_list(int (*fn)(struct file_list *, void *), void *private)
{
	struct file_list *fl;
	int ret = 0;

	for (fl = flist; fl; fl = fl->next) {
		ret = (*fn)(fl, private);
	}

	return ret;
}

/***************************************************************************
 Info function.
***************************************************************************/

static int info_fn(struct file_list *fl, void *private)
{
	SMB_STRUCT_STAT sbuf;
	char **lines = NULL;
	TALLOC_CTX *ctx = (TALLOC_CTX *)private;
	int fd = -1;
	int numlines = 0;
	SEC_DESC *psd = NULL;
	pstring basepath;
	pstring sharepath;
	pstring comment;
	pstring acl_str;
	int num_aces;
	char sep_str[2];

	sep_str[0] = *lp_winbind_separator();
	sep_str[1] = '\0';

	get_basepath(basepath);
	pstrcat(basepath, "/");
	pstrcat(basepath, fl->pathname);

#ifdef O_NOFOLLOW
	fd = sys_open(basepath, O_RDONLY|O_NOFOLLOW, 0);
#else
	fd = sys_open(basepath, O_RDONLY, 0);
#endif

	if (fd == -1) {
		d_printf("info_fn: unable to open %s. %s\n",
                        basepath, strerror(errno) );
                return -1;
        }

	/* Paranoia... */
	if (sys_fstat(fd, &sbuf) != 0) {
		d_printf("info_fn: can't fstat file %s. Error was %s\n",
			basepath, strerror(errno) );
		close(fd);
		return -1;
	}

	if (!S_ISREG(sbuf.st_mode)) {
		d_printf("info_fn: file %s is not a regular file. Ignoring.\n",
			basepath );
		close(fd);
		return -1;
	}

	lines = fd_lines_load(fd, &numlines);
	close(fd);

	if (lines == NULL) {
		return -1;
	}

	/* Ensure it's well formed. */
	if (!parse_usershare_file(ctx, &sbuf, -1, lines, numlines,
				sharepath,
				comment,
				&psd)) {
		d_printf("info_fn: file %s is not a well formed usershare file.\n",
			basepath );
		return -1;
	}

	pstrcpy(acl_str, "usershare_acl=");

	for (num_aces = 0; num_aces < psd->dacl->num_aces; num_aces++) {
		char access_str[2];
		const char *domain;
		const char *name;

		access_str[1] = '\0';

		if (net_lookup_name_from_sid(ctx, &psd->dacl->ace[num_aces].trustee, &domain, &name)) {
			if (*domain) {
				pstrcat(acl_str, domain);
				pstrcat(acl_str, sep_str);
			}
			pstrcat(acl_str,name);
		} else {
			fstring sidstr;
			sid_to_string(sidstr, &psd->dacl->ace[num_aces].trustee);
			pstrcat(acl_str,sidstr);
		}
		pstrcat(acl_str, ":");

		if (psd->dacl->ace[num_aces].type == SEC_ACE_TYPE_ACCESS_DENIED) {
			pstrcat(acl_str, "D,");
		} else {
			if (psd->dacl->ace[num_aces].info.mask & GENERIC_ALL_ACCESS) {
				pstrcat(acl_str, "F,");
			} else {
				pstrcat(acl_str, "R,");
			}
		}
	}

	acl_str[strlen(acl_str)-1] = '\0';

	d_printf("[%s]\n", fl->pathname );
	d_printf("path=%s\n", sharepath );
	d_printf("comment=%s\n", comment);
	d_printf("%s\n\n", acl_str);

	return 0;
}

/***************************************************************************
 Print out info (internal detail) on userlevel shares.
***************************************************************************/

static int net_usershare_info(int argc, const char **argv)
{
	fstring wcard;
	BOOL only_ours = True;
	int ret = -1;
	TALLOC_CTX *ctx;

	fstrcpy(wcard, "*");

	if (opt_long_list_entries) {
		only_ours = False;
	}

	switch (argc) {
		case 0:
			break;
		case 1:
			fstrcpy(wcard, argv[0]);
			break;
		default:
			return net_usershare_info_usage(argc, argv);
	}

	ctx = talloc_init("share_info");
	ret = get_share_list(ctx, wcard, only_ours);
	if (ret) {
		return ret;
	}
	ret = process_share_list(info_fn, ctx);
	talloc_destroy(ctx);
	return ret;
}

/***************************************************************************
 List function.
***************************************************************************/

static int list_fn(struct file_list *fl, void *private)
{
	d_printf("%s\n", fl->pathname);
	return 0;
}

/***************************************************************************
 List userlevel shares.
***************************************************************************/

static int net_usershare_list(int argc, const char **argv)
{
	fstring wcard;
	BOOL only_ours = True;
	int ret = -1;
	TALLOC_CTX *ctx;

	fstrcpy(wcard, "*");

	if (opt_long_list_entries) {
		only_ours = False;
	}

	switch (argc) {
		case 0:
			break;
		case 1:
			fstrcpy(wcard, argv[0]);
			break;
		default:
			return net_usershare_list_usage(argc, argv);
	}

	ctx = talloc_init("share_list");
	ret = get_share_list(ctx, wcard, only_ours);
	if (ret) {
		return ret;
	}
	ret = process_share_list(list_fn, NULL);
	talloc_destroy(ctx);
	return ret;
}

/***************************************************************************
 Handle "net usershare help *" subcommands.
***************************************************************************/

int net_usershare_help(int argc, const char **argv)
{
	struct functable func[] = {
		{"ADD", net_usershare_add_usage},
		{"DELETE", net_usershare_delete_usage},
		{"INFO", net_usershare_info_usage},
		{"LIST", net_usershare_list_usage},
		{NULL, NULL}};

	return net_run_function(argc, argv, func, net_usershare_usage);
}

/***************************************************************************
 Entry-point for all the USERSHARE functions.
***************************************************************************/

int net_usershare(int argc, const char **argv)
{
	SMB_STRUCT_DIR *dp;

	struct functable func[] = {
		{"ADD", net_usershare_add},
		{"DELETE", net_usershare_delete},
		{"INFO", net_usershare_info},
		{"LIST", net_usershare_list},
		{"HELP", net_usershare_help},
		{NULL, NULL}
	};
	
	if (lp_usershare_max_shares() == 0) {
		d_printf("net usershare: usershares are currently disabled\n");
		return -1;
	}

	dp = sys_opendir(lp_usershare_path());
	if (!dp) {
		d_printf("net usershare: cannot open usershare directory %s. Error %s\n",
			lp_usershare_path(), strerror(errno) );
		return -1;
	}
	sys_closedir(dp);

	return net_run_function(argc, argv, func, net_usershare_usage);
}
