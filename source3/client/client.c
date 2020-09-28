/*
   Unix SMB/CIFS implementation.
   SMB client
   Copyright (C) Andrew Tridgell          1994-1998
   Copyright (C) Simo Sorce               2001-2002
   Copyright (C) Jelmer Vernooij          2003
   Copyright (C) Gerald (Jerry) Carter    2004
   Copyright (C) Jeremy Allison           1994-2007

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
#include "popt_common_cmdline.h"
#include "rpc_client/cli_pipe.h"
#include "client/client_proto.h"
#include "client/clitar_proto.h"
#include "../librpc/gen_ndr/ndr_srvsvc_c.h"
#include "../lib/util/select.h"
#include "system/readline.h"
#include "../libcli/smbreadline/smbreadline.h"
#include "../libcli/security/security.h"
#include "system/select.h"
#include "libsmb/libsmb.h"
#include "libsmb/clirap.h"
#include "trans2.h"
#include "libsmb/nmblib.h"
#include "include/ntioctl.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lib/util/time_basic.h"

#ifndef REGISTER
#define REGISTER 0
#endif

extern int do_smb_browse(void); /* mDNS browsing */

extern bool override_logfile;

static int port = 0;
static char *service;
static char *desthost;
static bool grepable = false;
static bool quiet = false;
static char *cmdstr = NULL;
const char *cmd_ptr = NULL;

static int io_bufsize = 0; /* we use the default size */
static int io_timeout = (CLIENT_TIMEOUT/1000); /* Per operation timeout (in seconds). */

static int name_type = 0x20;
static int max_protocol = -1;

static int process_tok(char *tok);
static int cmd_help(void);

/* value for unused fid field in trans2 secondary request */
#define FID_UNUSED (0xFFFF)

time_t newer_than = 0;
static int archive_level = 0;

static bool translation = false;
static bool have_ip;

static bool prompt = true;

static bool recurse = false;
static bool showacls = false;
bool lowercase = false;
static bool backup_intent = false;

static struct sockaddr_storage dest_ss;
static char dest_ss_str[INET6_ADDRSTRLEN];

#define SEPARATORS " \t\n\r"

/* timing globals */
uint64_t get_total_size = 0;
unsigned int get_total_time_ms = 0;
static uint64_t put_total_size = 0;
static unsigned int put_total_time_ms = 0;

/* totals globals */
static double dir_total;

/* encrypted state. */
static bool smb_encrypt;

/* root cli_state connection */

struct cli_state *cli;

static char CLI_DIRSEP_CHAR = '\\';
static char CLI_DIRSEP_STR[] = { '\\', '\0' };

/* Accessor functions for directory paths. */
static char *fileselection;
static const char *client_get_fileselection(void)
{
	if (fileselection) {
		return fileselection;
	}
	return "";
}

static const char *client_set_fileselection(const char *new_fs)
{
	SAFE_FREE(fileselection);
	if (new_fs) {
		fileselection = SMB_STRDUP(new_fs);
	}
	return client_get_fileselection();
}

static char *cwd;
static const char *client_get_cwd(void)
{
	if (cwd) {
		return cwd;
	}
	return CLI_DIRSEP_STR;
}

static const char *client_set_cwd(const char *new_cwd)
{
	SAFE_FREE(cwd);
	if (new_cwd) {
		cwd = SMB_STRDUP(new_cwd);
	}
	return client_get_cwd();
}

static char *cur_dir;
const char *client_get_cur_dir(void)
{
	if (cur_dir) {
		return cur_dir;
	}
	return CLI_DIRSEP_STR;
}

const char *client_set_cur_dir(const char *newdir)
{
	SAFE_FREE(cur_dir);
	if (newdir) {
		cur_dir = SMB_STRDUP(newdir);
	}
	return client_get_cur_dir();
}

/****************************************************************************
 Put up a yes/no prompt.
****************************************************************************/

static bool yesno(const char *p)
{
	char ans[20];
	printf("%s",p);

	if (!fgets(ans,sizeof(ans)-1,stdin))
		return(False);

	if (*ans == 'y' || *ans == 'Y')
		return(True);

	return(False);
}

/****************************************************************************
 Write to a local file with CR/LF->LF translation if appropriate. Return the
 number taken from the buffer. This may not equal the number written.
****************************************************************************/

static ssize_t writefile(int f, char *b, size_t n)
{
	size_t i = 0;

	if (n == 0) {
		errno = EINVAL;
		return -1;
	}

	if (!translation) {
		return write(f,b,n);
	}

	do {
		if (*b == '\r' && (i<(n-1)) && *(b+1) == '\n') {
			b++;i++;
		}
		if (write(f, b, 1) != 1) {
			break;
		}
		b++;
		i++;
	} while (i < n);

	return (ssize_t)i;
}

/****************************************************************************
 Read from a file with LF->CR/LF translation if appropriate. Return the
 number read. read approx n bytes.
****************************************************************************/

static int readfile(uint8_t *b, int n, FILE *f)
{
	int i;
	int c;

	if (!translation)
		return fread(b,1,n,f);

	i = 0;
	while (i < (n - 1)) {
		if ((c = getc(f)) == EOF) {
			break;
		}

		if (c == '\n') { /* change all LFs to CR/LF */
			b[i++] = '\r';
		}

		b[i++] = c;
	}

	return(i);
}

struct push_state {
	FILE *f;
	off_t nread;
};

static size_t push_source(uint8_t *buf, size_t n, void *priv)
{
	struct push_state *state = (struct push_state *)priv;
	int result;

	if (feof(state->f)) {
		return 0;
	}

	result = readfile(buf, n, state->f);
	state->nread += result;
	return result;
}

/****************************************************************************
 Send a message.
****************************************************************************/

static void send_message(const char *username)
{
	char buf[1600];
	NTSTATUS status;
	size_t i;

	d_printf("Type your message, ending it with a Control-D\n");

	i = 0;
	while (i<sizeof(buf)-2) {
		int c = fgetc(stdin);
		if (c == EOF) {
			break;
		}
		if (c == '\n') {
			buf[i++] = '\r';
		}
		buf[i++] = c;
	}
	buf[i] = '\0';

	status = cli_message(cli, desthost, username, buf);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_message returned %s\n",
			  nt_errstr(status));
	}
}

/****************************************************************************
 Check the space on a device.
****************************************************************************/

static int do_dskattr(void)
{
	uint64_t total, bsize, avail;
	struct cli_state *targetcli = NULL;
	char *targetpath = NULL;
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status;

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(), cli,
				  client_get_cur_dir(), &targetcli,
				  &targetpath);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Error in dskattr: %s\n", nt_errstr(status));
		return 1;
	}

	status = cli_disk_size(targetcli, targetpath, &bsize, &total, &avail);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Error in dskattr: %s\n", nt_errstr(status));
		return 1;
	}

	d_printf("\n\t\t%" PRIu64
		" blocks of size %" PRIu64
		". %" PRIu64 " blocks available\n",
		total, bsize, avail);

	return 0;
}

/****************************************************************************
 Show cd/pwd.
****************************************************************************/

static int cmd_pwd(void)
{
	d_printf("Current directory is %s",service);
	d_printf("%s\n",client_get_cur_dir());
	return 0;
}

/****************************************************************************
 Ensure name has correct directory separators.
****************************************************************************/

static void normalize_name(char *newdir)
{
	if (!(cli->requested_posix_capabilities & CIFS_UNIX_POSIX_PATHNAMES_CAP)) {
		string_replace(newdir,'/','\\');
	}
}

/****************************************************************************
 Local name cleanup before sending to server. SMB1 allows relative pathnames,
 but SMB2 does not, so we need to resolve them locally.
****************************************************************************/

char *client_clean_name(TALLOC_CTX *ctx, const char *name)
{
	char *newname = NULL;
	if (name == NULL) {
		return NULL;
	}

	/* First ensure any path separators are correct. */
	newname = talloc_strdup(ctx, name);
	if (newname == NULL) {
		return NULL;
	}
	normalize_name(newname);

	/* Now remove any relative (..) path components. */
	if (cli->requested_posix_capabilities & CIFS_UNIX_POSIX_PATHNAMES_CAP) {
		newname = unix_clean_name(ctx, newname);
	} else {
		newname = clean_name(ctx, newname);
	}
	if (newname == NULL) {
		return NULL;
	}
	return newname;
}

/****************************************************************************
 Change directory - inner section.
****************************************************************************/

static int do_cd(const char *new_dir)
{
	char *newdir = NULL;
	char *saved_dir = NULL;
	char *new_cd = NULL;
	char *targetpath = NULL;
	struct cli_state *targetcli = NULL;
	SMB_STRUCT_STAT sbuf;
	uint32_t attributes;
	int ret = 1;
	TALLOC_CTX *ctx = talloc_stackframe();
	NTSTATUS status;

	newdir = talloc_strdup(ctx, new_dir);
	if (!newdir) {
		TALLOC_FREE(ctx);
		return 1;
	}

	normalize_name(newdir);

	/* Save the current directory in case the new directory is invalid */

	saved_dir = talloc_strdup(ctx, client_get_cur_dir());
	if (!saved_dir) {
		TALLOC_FREE(ctx);
		return 1;
	}

	if (*newdir == CLI_DIRSEP_CHAR) {
		client_set_cur_dir(newdir);
		new_cd = newdir;
	} else {
		new_cd = talloc_asprintf(ctx, "%s%s",
				client_get_cur_dir(),
				newdir);
		if (!new_cd) {
			goto out;
		}
	}

	/* Ensure cur_dir ends in a DIRSEP */
	if ((new_cd[0] != '\0') && (*(new_cd+strlen(new_cd)-1) != CLI_DIRSEP_CHAR)) {
		new_cd = talloc_asprintf_append(new_cd, "%s", CLI_DIRSEP_STR);
		if (!new_cd) {
			goto out;
		}
	}
	client_set_cur_dir(new_cd);

	new_cd = client_clean_name(ctx, new_cd);
	client_set_cur_dir(new_cd);

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
				cli, new_cd, &targetcli, &targetpath);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cd %s: %s\n", new_cd, nt_errstr(status));
		client_set_cur_dir(saved_dir);
		goto out;
	}

	if (strequal(targetpath,CLI_DIRSEP_STR )) {
		TALLOC_FREE(ctx);
		return 0;
	}

	/* Use a trans2_qpathinfo to test directories for modern servers.
	   Except Win9x doesn't support the qpathinfo_basic() call..... */

	if (smbXcli_conn_protocol(targetcli->conn) > PROTOCOL_LANMAN2 && !targetcli->win95) {

		status = cli_qpathinfo_basic(targetcli, targetpath, &sbuf,
					     &attributes);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("cd %s: %s\n", new_cd, nt_errstr(status));
			client_set_cur_dir(saved_dir);
			goto out;
		}

		if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
			d_printf("cd %s: not a directory\n", new_cd);
			client_set_cur_dir(saved_dir);
			goto out;
		}
	} else {

		targetpath = talloc_asprintf(ctx,
				"%s%s",
				targetpath,
				CLI_DIRSEP_STR );
		if (!targetpath) {
			client_set_cur_dir(saved_dir);
			goto out;
		}
		targetpath = client_clean_name(ctx, targetpath);
		if (!targetpath) {
			client_set_cur_dir(saved_dir);
			goto out;
		}

		status = cli_chkpath(targetcli, targetpath);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("cd %s: %s\n", new_cd, nt_errstr(status));
			client_set_cur_dir(saved_dir);
			goto out;
		}
	}

	ret = 0;

out:

	TALLOC_FREE(ctx);
	return ret;
}

/****************************************************************************
 Change directory.
****************************************************************************/

static int cmd_cd(void)
{
	char *buf = NULL;
	int rc = 0;

	if (next_token_talloc(talloc_tos(), &cmd_ptr, &buf,NULL)) {
		rc = do_cd(buf);
	} else {
		d_printf("Current directory is %s\n",client_get_cur_dir());
	}

	return rc;
}

/****************************************************************************
 Change directory.
****************************************************************************/

static int cmd_cd_oneup(void)
{
	return do_cd("..");
}

/*******************************************************************
 Decide if a file should be operated on.
********************************************************************/

static bool do_this_one(struct file_info *finfo)
{
	if (!finfo->name) {
		return false;
	}

	if (finfo->attr & FILE_ATTRIBUTE_DIRECTORY) {
		return true;
	}

	if (*client_get_fileselection() &&
	    !mask_match(finfo->name,client_get_fileselection(),false)) {
		DEBUG(3,("mask_match %s failed\n", finfo->name));
		return false;
	}

	if (newer_than && finfo->mtime_ts.tv_sec < newer_than) {
		DEBUG(3,("newer_than %s failed\n", finfo->name));
		return false;
	}

	if ((archive_level==1 || archive_level==2) && !(finfo->attr & FILE_ATTRIBUTE_ARCHIVE)) {
		DEBUG(3,("archive %s failed\n", finfo->name));
		return false;
	}

	return true;
}

/****************************************************************************
 Display info about a file.
****************************************************************************/

static NTSTATUS display_finfo(struct cli_state *cli_state, struct file_info *finfo,
			  const char *dir)
{
	time_t t;
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status = NT_STATUS_OK;

	if (!do_this_one(finfo)) {
		return NT_STATUS_OK;
	}

	t = finfo->mtime_ts.tv_sec; /* the time is assumed to be passed as GMT */
	if (!showacls) {
		d_printf("  %-30s%7.7s %8.0f  %s",
			 finfo->name,
			 attrib_string(talloc_tos(), finfo->attr),
		 	(double)finfo->size,
			time_to_asc(t));
		dir_total += finfo->size;
	} else {
		char *afname = NULL;
		uint16_t fnum;

		/* skip if this is . or .. */
		if ( strequal(finfo->name,"..") || strequal(finfo->name,".") )
			return NT_STATUS_OK;
		/* create absolute filename for cli_ntcreate() FIXME */
		afname = talloc_asprintf(ctx,
					"%s%s%s",
					dir,
					CLI_DIRSEP_STR,
					finfo->name);
		if (!afname) {
			return NT_STATUS_NO_MEMORY;
		}
		/* print file meta date header */
		d_printf( "FILENAME:%s\n", finfo->name);
		d_printf( "MODE:%s\n", attrib_string(talloc_tos(), finfo->attr));
		d_printf( "SIZE:%.0f\n", (double)finfo->size);
		d_printf( "MTIME:%s", time_to_asc(t));
		status = cli_ntcreate(
			cli_state,	      /* cli */
			afname,		      /* fname */
			0,		      /* CreatFlags */
			READ_CONTROL_ACCESS,  /* DesiredAccess */
			0,		      /* FileAttributes */
			FILE_SHARE_READ|
			FILE_SHARE_WRITE,     /* ShareAccess */
			FILE_OPEN,	      /* CreateDisposition */
			0x0,		      /* CreateOptions */
			0x0,		      /* SecurityFlags */
			&fnum,		      /* pfid */
			NULL);		      /* cr */
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG( 0, ("display_finfo() Failed to open %s: %s\n",
				   afname, nt_errstr(status)));
		} else {
			struct security_descriptor *sd = NULL;
			status = cli_query_secdesc(cli_state, fnum,
						   ctx, &sd);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG( 0, ("display_finfo() failed to "
					   "get security descriptor: %s",
					   nt_errstr(status)));
			} else {
				display_sec_desc(sd);
			}
			TALLOC_FREE(sd);
		}
		TALLOC_FREE(afname);
	}
	return status;
}

/****************************************************************************
 Accumulate size of a file.
****************************************************************************/

static NTSTATUS do_du(struct cli_state *cli_state, struct file_info *finfo,
		  const char *dir)
{
	if (do_this_one(finfo)) {
		dir_total += finfo->size;
	}
	return NT_STATUS_OK;
}

struct do_list_queue_entry {
	struct do_list_queue_entry *prev, *next;
	char name[];
};

struct do_list_queue {
	struct do_list_queue_entry *list;
};

static bool do_list_recurse;
static bool do_list_dirs;
static struct do_list_queue *queue = NULL;
static NTSTATUS (*do_list_fn)(struct cli_state *cli_state, struct file_info *,
			  const char *dir);

/****************************************************************************
 Functions for do_list_queue.
****************************************************************************/

static void reset_do_list_queue(void)
{
	TALLOC_FREE(queue);
}

static void init_do_list_queue(void)
{
	TALLOC_FREE(queue);
	queue = talloc_zero(NULL, struct do_list_queue);
}

static void add_to_do_list_queue(const char *entry)
{
	struct do_list_queue_entry *e = NULL;
	size_t entry_str_len = strlen(entry)+1;
	size_t entry_len = offsetof(struct do_list_queue_entry, name);

	entry_len += entry_str_len;
	SMB_ASSERT(entry_len >= entry_str_len);

	e = talloc_size(queue, entry_len);
	if (e == NULL) {
		d_printf("talloc failed for entry %s\n", entry);
		return;
	}
	talloc_set_name_const(e, "struct do_list_queue_entry");

	memcpy(e->name, entry, entry_str_len);
	DLIST_ADD_END(queue->list, e);
}

static char *do_list_queue_head(void)
{
	return queue->list->name;
}

static void remove_do_list_queue_head(void)
{
	struct do_list_queue_entry *e = queue->list;
	DLIST_REMOVE(queue->list, e);
	TALLOC_FREE(e);
}

static int do_list_queue_empty(void)
{
	return (queue == NULL) || (queue->list == NULL);
}

/****************************************************************************
 A helper for do_list.
****************************************************************************/

static NTSTATUS do_list_helper(const char *mntpoint, struct file_info *f,
			   const char *mask, void *state)
{
	struct cli_state *cli_state = (struct cli_state *)state;
	TALLOC_CTX *ctx = talloc_tos();
	char *dir = NULL;
	char *dir_end = NULL;
	NTSTATUS status = NT_STATUS_OK;
	char *mask2 = NULL;
	char *p = NULL;

	/* Work out the directory. */
	dir = talloc_strdup(ctx, mask);
	if (!dir) {
		return NT_STATUS_NO_MEMORY;
	}
	if ((dir_end = strrchr(dir, CLI_DIRSEP_CHAR)) != NULL) {
		*dir_end = '\0';
	}

	if (!(f->attr & FILE_ATTRIBUTE_DIRECTORY)) {
		if (do_this_one(f)) {
			status = do_list_fn(cli_state, f, dir);
		}
		TALLOC_FREE(dir);
		return status;
	}

	if (do_list_dirs && do_this_one(f)) {
		status = do_list_fn(cli_state, f, dir);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (!do_list_recurse ||
	    (f->name == NULL) ||
	    ISDOT(f->name) ||
	    ISDOTDOT(f->name)) {
		return NT_STATUS_OK;
	}

	if (!f->name[0]) {
		d_printf("Empty dir name returned. Possible server misconfiguration.\n");
		TALLOC_FREE(dir);
		return NT_STATUS_UNSUCCESSFUL;
	}

	mask2 = talloc_asprintf(ctx,
				"%s%s",
				mntpoint,
				mask);
	if (!mask2) {
		TALLOC_FREE(dir);
		return NT_STATUS_NO_MEMORY;
	}
	p = strrchr_m(mask2,CLI_DIRSEP_CHAR);
	if (p) {
		p[1] = 0;
	} else {
		mask2[0] = '\0';
	}
	mask2 = talloc_asprintf_append(mask2,
				       "%s%s*",
				       f->name,
				       CLI_DIRSEP_STR);
	if (!mask2) {
		TALLOC_FREE(dir);
		return NT_STATUS_NO_MEMORY;
	}
	add_to_do_list_queue(mask2);
	TALLOC_FREE(mask2);

	TALLOC_FREE(dir);
	return NT_STATUS_OK;
}

/****************************************************************************
 A wrapper around cli_list that adds recursion.
****************************************************************************/

NTSTATUS do_list(const char *mask,
			uint32_t attribute,
			NTSTATUS (*fn)(struct cli_state *cli_state, struct file_info *,
				   const char *dir),
			bool rec,
			bool dirs)
{
	static int in_do_list = 0;
	TALLOC_CTX *ctx = talloc_tos();
	struct cli_state *targetcli = NULL;
	char *targetpath = NULL;
	NTSTATUS ret_status = NT_STATUS_OK;
	NTSTATUS status = NT_STATUS_OK;

	if (in_do_list && rec) {
		fprintf(stderr, "INTERNAL ERROR: do_list called recursively when the recursive flag is true\n");
		exit(1);
	}

	in_do_list = 1;

	do_list_recurse = rec;
	do_list_dirs = dirs;
	do_list_fn = fn;

	init_do_list_queue();
	add_to_do_list_queue(mask);

	while (!do_list_queue_empty()) {
		const char *head = do_list_queue_head();

		/* check for dfs */

		status = cli_resolve_path(ctx, "",
					  popt_get_cmdline_auth_info(),
					  cli, head, &targetcli, &targetpath);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("do_list: [%s] %s\n", head,
				 nt_errstr(status));
			remove_do_list_queue_head();
			continue;
		}

		status = cli_list(targetcli, targetpath, attribute,
				  do_list_helper, targetcli);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("%s listing %s\n",
				 nt_errstr(status), targetpath);
			ret_status = status;
		}
		remove_do_list_queue_head();
		if ((! do_list_queue_empty()) && (fn == display_finfo)) {
			char *next_file = do_list_queue_head();
			char *save_ch = 0;
			if ((strlen(next_file) >= 2) &&
			    (next_file[strlen(next_file) - 1] == '*') &&
			    (next_file[strlen(next_file) - 2] == CLI_DIRSEP_CHAR)) {
				save_ch = next_file +
					strlen(next_file) - 2;
				*save_ch = '\0';
				if (showacls) {
					/* cwd is only used if showacls is on */
					client_set_cwd(next_file);
				}
			}
			if (!showacls) /* don't disturbe the showacls output */
				d_printf("\n%s\n",next_file);
			if (save_ch) {
				*save_ch = CLI_DIRSEP_CHAR;
			}
		}
		TALLOC_FREE(targetpath);
	}

	in_do_list = 0;
	reset_do_list_queue();
	return ret_status;
}

/****************************************************************************
 Get a directory listing.
****************************************************************************/

static int cmd_dir(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	uint32_t attribute = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN;
	char *mask = NULL;
	char *buf = NULL;
	int rc = 1;
	NTSTATUS status;

	dir_total = 0;
	mask = talloc_strdup(ctx, client_get_cur_dir());
	if (!mask) {
		return 1;
	}

	if (next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		normalize_name(buf);
		if (*buf == CLI_DIRSEP_CHAR) {
			mask = talloc_strdup(ctx, buf);
		} else {
			mask = talloc_asprintf_append(mask, "%s", buf);
		}
	} else {
		mask = talloc_asprintf_append(mask, "*");
	}
	if (!mask) {
		return 1;
	}

	mask = client_clean_name(ctx, mask);
	if (mask == NULL) {
		return 1;
	}

	if (showacls) {
		/* cwd is only used if showacls is on */
		client_set_cwd(client_get_cur_dir());
	}

	status = do_list(mask, attribute, display_finfo, recurse, true);
	if (!NT_STATUS_IS_OK(status)) {
		return 1;
	}

	rc = do_dskattr();

	DEBUG(3, ("Total bytes listed: %.0f\n", dir_total));

	return rc;
}

/****************************************************************************
 Get a directory listing.
****************************************************************************/

static int cmd_du(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	uint32_t attribute = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN;
	char *mask = NULL;
	char *buf = NULL;
	NTSTATUS status;
	int rc = 1;

	dir_total = 0;
	mask = talloc_strdup(ctx, client_get_cur_dir());
	if (!mask) {
		return 1;
	}
	if ((mask[0] != '\0') && (mask[strlen(mask)-1]!=CLI_DIRSEP_CHAR)) {
		mask = talloc_asprintf_append(mask, "%s", CLI_DIRSEP_STR);
		if (!mask) {
			return 1;
		}
	}

	if (next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		normalize_name(buf);
		if (*buf == CLI_DIRSEP_CHAR) {
			mask = talloc_strdup(ctx, buf);
		} else {
			mask = talloc_asprintf_append(mask, "%s", buf);
		}
	} else {
		mask = talloc_strdup(ctx, "*");
	}
	if (!mask) {
		return 1;
	}

	mask = client_clean_name(ctx, mask);
	if (mask == NULL) {
		return 1;
	}

	status = do_list(mask, attribute, do_du, recurse, true);
	if (!NT_STATUS_IS_OK(status)) {
		return 1;
	}

	rc = do_dskattr();

	d_printf("Total number of bytes: %.0f\n", dir_total);

	return rc;
}

static int cmd_echo(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *num;
	char *data;
	NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr, &num, NULL)
	    || !next_token_talloc(ctx, &cmd_ptr, &data, NULL)) {
		d_printf("echo <num> <data>\n");
		return 1;
	}

	status = cli_echo(cli, atoi(num), data_blob_const(data, strlen(data)));

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("echo failed: %s\n", nt_errstr(status));
		return 1;
	}

	return 0;
}

/****************************************************************************
 Get a file from rname to lname
****************************************************************************/

static NTSTATUS writefile_sink(char *buf, size_t n, void *priv)
{
	int *pfd = (int *)priv;
	ssize_t rc;

	rc = writefile(*pfd, buf, n);
	if (rc == -1) {
		return map_nt_error_from_unix(errno);
	}
	return NT_STATUS_OK;
}

static int do_get(const char *rname, const char *lname_in, bool reget)
{
	TALLOC_CTX *ctx = talloc_tos();
	int handle = 0;
	uint16_t fnum;
	bool newhandle = false;
	struct timespec tp_start;
	uint32_t attr;
	off_t size;
	off_t start = 0;
	off_t nread = 0;
	int rc = 0;
	struct cli_state *targetcli = NULL;
	char *targetname = NULL;
	char *lname = NULL;
	NTSTATUS status;

	lname = talloc_strdup(ctx, lname_in);
	if (!lname) {
		return 1;
	}

	if (lowercase) {
		if (!strlower_m(lname)) {
			d_printf("strlower_m %s failed\n", lname);
			return 1;
		}
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
				cli, rname, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Failed to open %s: %s\n", rname, nt_errstr(status));
		return 1;
	}

	clock_gettime_mono(&tp_start);

	status = cli_open(targetcli, targetname, O_RDONLY, DENY_NONE, &fnum);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s opening remote file %s\n", nt_errstr(status),
			 rname);
		return 1;
	}

	if(!strcmp(lname,"-")) {
		handle = fileno(stdout);
	} else {
		if (reget) {
			handle = open(lname, O_WRONLY|O_CREAT, 0644);
			if (handle >= 0) {
				start = lseek(handle, 0, SEEK_END);
				if (start == -1) {
					d_printf("Error seeking local file\n");
					close(handle);
					return 1;
				}
			}
		} else {
			handle = open(lname, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		}
		newhandle = true;
	}
	if (handle < 0) {
		d_printf("Error opening local file %s\n",lname);
		return 1;
	}


	status = cli_qfileinfo_basic(targetcli, fnum, &attr, &size, NULL, NULL,
				     NULL, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("getattrib: %s\n", nt_errstr(status));
		if (newhandle) {
			close(handle);
		}
		return 1;
	}

	DEBUG(1,("getting file %s of size %.0f as %s ",
		 rname, (double)size, lname));

	status = cli_pull(targetcli, fnum, start, size, io_bufsize,
			  writefile_sink, (void *)&handle, &nread);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "parallel_read returned %s\n",
			  nt_errstr(status));
		if (newhandle) {
			close(handle);
		}
		cli_close(targetcli, fnum);
		return 1;
	}

	status = cli_close(targetcli, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Error %s closing remote file\n", nt_errstr(status));
		rc = 1;
	}

	if (newhandle) {
		close(handle);
	}

	if (archive_level >= 2 && (attr & FILE_ATTRIBUTE_ARCHIVE)) {
		cli_setatr(cli, rname, attr & ~(uint32_t)FILE_ATTRIBUTE_ARCHIVE, 0);
	}

	{
		struct timespec tp_end;
		int this_time;

		clock_gettime_mono(&tp_end);
		this_time = nsec_time_diff(&tp_end,&tp_start)/1000000;
		get_total_time_ms += this_time;
		get_total_size += nread;

		DEBUG(1,("(%3.1f KiloBytes/sec) (average %3.1f KiloBytes/sec)\n",
			 nread / (1.024*this_time + 1.0e-4),
			 get_total_size / (1.024*get_total_time_ms)));
	}

	TALLOC_FREE(targetname);
	return rc;
}

/****************************************************************************
 Get a file.
****************************************************************************/

static int cmd_get(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *lname = NULL;
	char *rname = NULL;
	char *fname = NULL;

	rname = talloc_strdup(ctx, client_get_cur_dir());
	if (!rname) {
		return 1;
	}

	if (!next_token_talloc(ctx, &cmd_ptr,&fname,NULL)) {
		d_printf("get <filename> [localname]\n");
		return 1;
	}
	rname = talloc_asprintf_append(rname, "%s", fname);
	if (!rname) {
		return 1;
	}
	rname = client_clean_name(ctx, rname);
	if (!rname) {
		return 1;
	}

	next_token_talloc(ctx, &cmd_ptr,&lname,NULL);
	if (!lname) {
		lname = fname;
	}

	return do_get(rname, lname, false);
}

/****************************************************************************
 Do an mget operation on one file.
****************************************************************************/

static NTSTATUS do_mget(struct cli_state *cli_state, struct file_info *finfo,
		    const char *dir)
{
	TALLOC_CTX *ctx = talloc_tos();
	const char *client_cwd = NULL;
	size_t client_cwd_len;
	char *path = NULL;
	char *local_path = NULL;

	if (!finfo->name) {
		return NT_STATUS_OK;
	}

	if (strequal(finfo->name,".") || strequal(finfo->name,".."))
		return NT_STATUS_OK;

	if ((finfo->attr & FILE_ATTRIBUTE_DIRECTORY) && !recurse) {
		return NT_STATUS_OK;
	}

	if (prompt) {
		const char *object = (finfo->attr & FILE_ATTRIBUTE_DIRECTORY) ?
			"directory" : "file";
		char *quest = NULL;
		bool ok;

		quest = talloc_asprintf(
			ctx, "Get %s %s? ", object, finfo->name);
		if (quest == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		ok = yesno(quest);
		TALLOC_FREE(quest);
		if (!ok) {
			return NT_STATUS_OK;
		}
	}

	path = talloc_asprintf(
		ctx, "%s%c%s", dir, CLI_DIRSEP_CHAR, finfo->name);
	if (path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	path = client_clean_name(ctx, path);
	if (path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Skip the path prefix if we've done a remote "cd" when
	 * creating the local path
	 */
	client_cwd = client_get_cur_dir();
	client_cwd_len = strlen(client_cwd);

	local_path = talloc_strdup(ctx, path + client_cwd_len);
	if (local_path == NULL) {
		TALLOC_FREE(path);
		return NT_STATUS_NO_MEMORY;
	}
	string_replace(local_path, CLI_DIRSEP_CHAR, '/');

	if (finfo->attr & FILE_ATTRIBUTE_DIRECTORY) {
		int ret = mkdir(local_path, 0777);

		if ((ret == -1) && (errno != EEXIST)) {
			return map_nt_error_from_unix(errno);
		}
	} else {
		do_get(path, local_path, false);
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 View the file using the pager.
****************************************************************************/

static int cmd_more(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *rname = NULL;
	char *fname = NULL;
	char *lname = NULL;
	char *pager_cmd = NULL;
	const char *pager;
	int fd;
	int rc = 0;
	mode_t mask;

	rname = talloc_strdup(ctx, client_get_cur_dir());
	if (!rname) {
		return 1;
	}

	lname = talloc_asprintf(ctx, "%s/smbmore.XXXXXX",tmpdir());
	if (!lname) {
		return 1;
	}
	mask = umask(S_IRWXO | S_IRWXG);
	fd = mkstemp(lname);
	umask(mask);
	if (fd == -1) {
		d_printf("failed to create temporary file for more\n");
		return 1;
	}
	close(fd);

	if (!next_token_talloc(ctx, &cmd_ptr,&fname,NULL)) {
		d_printf("more <filename>\n");
		unlink(lname);
		return 1;
	}
	rname = talloc_asprintf_append(rname, "%s", fname);
	if (!rname) {
		return 1;
	}
	rname = client_clean_name(ctx,rname);
	if (!rname) {
		return 1;
	}

	rc = do_get(rname, lname, false);

	pager=getenv("PAGER");

	pager_cmd = talloc_asprintf(ctx,
				"%s %s",
				(pager? pager:PAGER),
				lname);
	if (!pager_cmd) {
		return 1;
	}
	if (system(pager_cmd) == -1) {
		d_printf("system command '%s' returned -1\n",
			pager_cmd);
	}
	unlink(lname);

	return rc;
}

/****************************************************************************
 Do a mget command.
****************************************************************************/

static int cmd_mget(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	uint32_t attribute = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN;
	char *mget_mask = NULL;
	char *buf = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (recurse) {
		attribute |= FILE_ATTRIBUTE_DIRECTORY;
	}

	while (next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {

		mget_mask = talloc_strdup(ctx, client_get_cur_dir());
		if (!mget_mask) {
			return 1;
		}
		if (*buf == CLI_DIRSEP_CHAR) {
			mget_mask = talloc_strdup(ctx, buf);
		} else {
			mget_mask = talloc_asprintf_append(mget_mask,
							"%s", buf);
		}
		if (!mget_mask) {
			return 1;
		}
		mget_mask = client_clean_name(ctx, mget_mask);
		if (mget_mask == NULL) {
			return 1;
		}
		status = do_list(mget_mask, attribute, do_mget, recurse, true);
		if (!NT_STATUS_IS_OK(status)) {
			return 1;
		}
	}

	if (mget_mask == NULL) {
		d_printf("nothing to mget\n");
		return 0;
	}

	if (!*mget_mask) {
		mget_mask = talloc_asprintf(ctx,
					"%s*",
					client_get_cur_dir());
		if (!mget_mask) {
			return 1;
		}
		mget_mask = client_clean_name(ctx, mget_mask);
		if (mget_mask == NULL) {
			return 1;
		}
		status = do_list(mget_mask, attribute, do_mget, recurse, true);
		if (!NT_STATUS_IS_OK(status)) {
			return 1;
		}
	}

	return 0;
}

/****************************************************************************
 Make a directory of name "name".
****************************************************************************/

static bool do_mkdir(const char *name)
{
	TALLOC_CTX *ctx = talloc_tos();
	struct cli_state *targetcli;
	char *targetname = NULL;
	NTSTATUS status;

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
				cli, name, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("mkdir %s: %s\n", name, nt_errstr(status));
		return false;
	}

	status = cli_mkdir(targetcli, targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s making remote directory %s\n",
			 nt_errstr(status),name);
		return false;
	}

	return true;
}

/****************************************************************************
 Show 8.3 name of a file.
****************************************************************************/

static bool do_altname(const char *name)
{
	fstring altname;
	NTSTATUS status;

	status = cli_qpathinfo_alt_name(cli, name, altname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s getting alt name for %s\n",
			 nt_errstr(status),name);
		return false;
	}
	d_printf("%s\n", altname);

	return true;
}

/****************************************************************************
 Exit client.
****************************************************************************/

static int cmd_quit(void)
{
	cli_shutdown(cli);
	popt_free_cmdline_auth_info();
	exit(0);
	/* NOTREACHED */
	return 0;
}

/****************************************************************************
 Make a directory.
****************************************************************************/

static int cmd_mkdir(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *mask = NULL;
	char *buf = NULL;
        NTSTATUS status;

	mask = talloc_strdup(ctx, client_get_cur_dir());
	if (!mask) {
		return 1;
	}

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		if (!recurse) {
			d_printf("mkdir <dirname>\n");
		}
		return 1;
	}
	mask = talloc_asprintf_append(mask, "%s", buf);
	if (!mask) {
		return 1;
	}
	mask = client_clean_name(ctx, mask);
	if (mask == NULL) {
		return 1;
	}

	if (recurse) {
		char *ddir = NULL;
		char *ddir2 = NULL;
		struct cli_state *targetcli;
		char *targetname = NULL;
		char *p = NULL;
		char *saveptr;

		ddir2 = talloc_strdup(ctx, "");
		if (!ddir2) {
			return 1;
		}

		status = cli_resolve_path(ctx, "",
				popt_get_cmdline_auth_info(), cli, mask,
				&targetcli, &targetname);
		if (!NT_STATUS_IS_OK(status)) {
			return 1;
		}

		ddir = talloc_strdup(ctx, targetname);
		if (!ddir) {
			return 1;
		}
		trim_char(ddir,'.','\0');
		p = strtok_r(ddir, "/\\", &saveptr);
		while (p) {
			ddir2 = talloc_asprintf_append(ddir2, "%s", p);
			if (!ddir2) {
				return 1;
			}
			if (!NT_STATUS_IS_OK(cli_chkpath(targetcli, ddir2))) {
				do_mkdir(ddir2);
			}
			ddir2 = talloc_asprintf_append(ddir2, "%s", CLI_DIRSEP_STR);
			if (!ddir2) {
				return 1;
			}
			p = strtok_r(NULL, "/\\", &saveptr);
		}
	} else {
		do_mkdir(mask);
	}

	return 0;
}

/****************************************************************************
 Show alt name.
****************************************************************************/

static int cmd_altname(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *name;
	char *buf;

	name = talloc_strdup(ctx, client_get_cur_dir());
	if (!name) {
		return 1;
	}

	if (!next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
		d_printf("altname <file>\n");
		return 1;
	}
	name = talloc_asprintf_append(name, "%s", buf);
	if (!name) {
		return 1;
	}
	name = client_clean_name(ctx, name);
	if (name == NULL) {
		return 1;
	}
	do_altname(name);
	return 0;
}

static char *attr_str(TALLOC_CTX *mem_ctx, uint32_t attr)
{
	char *attrs = talloc_zero_array(mem_ctx, char, 17);
	int i = 0;

	if (!(attr & FILE_ATTRIBUTE_NORMAL)) {
		if (attr & FILE_ATTRIBUTE_ENCRYPTED) {
			attrs[i++] = 'E';
		}
		if (attr & FILE_ATTRIBUTE_NONINDEXED) {
			attrs[i++] = 'N';
		}
		if (attr & FILE_ATTRIBUTE_OFFLINE) {
			attrs[i++] = 'O';
		}
		if (attr & FILE_ATTRIBUTE_COMPRESSED) {
			attrs[i++] = 'C';
		}
		if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
			attrs[i++] = 'r';
		}
		if (attr & FILE_ATTRIBUTE_SPARSE) {
			attrs[i++] = 's';
		}
		if (attr & FILE_ATTRIBUTE_TEMPORARY) {
			attrs[i++] = 'T';
		}
		if (attr & FILE_ATTRIBUTE_NORMAL) {
			attrs[i++] = 'N';
		}
		if (attr & FILE_ATTRIBUTE_READONLY) {
			attrs[i++] = 'R';
		}
		if (attr & FILE_ATTRIBUTE_HIDDEN) {
			attrs[i++] = 'H';
		}
		if (attr & FILE_ATTRIBUTE_SYSTEM) {
			attrs[i++] = 'S';
		}
		if (attr & FILE_ATTRIBUTE_DIRECTORY) {
			attrs[i++] = 'D';
		}
		if (attr & FILE_ATTRIBUTE_ARCHIVE) {
			attrs[i++] = 'A';
		}
	}
	return attrs;
}

/****************************************************************************
 Show all info we can get
****************************************************************************/

static int do_allinfo(const char *name)
{
	fstring altname;
	struct timespec b_time, a_time, m_time, c_time;
	off_t size;
	uint32_t attr;
	NTTIME tmp;
	uint16_t fnum;
	unsigned int num_streams;
	struct stream_struct *streams;
	int j, num_snapshots;
	char **snapshots = NULL;
	unsigned int i;
	NTSTATUS status;

	status = cli_qpathinfo_alt_name(cli, name, altname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s getting alt name for %s\n", nt_errstr(status),
			 name);
		/*
		 * Ignore not supported or not implemented, it does not
		 * hurt if we can't list alternate names.
		 */
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)) {
			altname[0] = '\0';
		} else {
			return false;
		}
	}
	d_printf("altname: %s\n", altname);

	status = cli_qpathinfo3(cli, name, &b_time, &a_time, &m_time, &c_time,
				&size, &attr, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s getting pathinfo for %s\n", nt_errstr(status),
			 name);
		return false;
	}

	tmp = full_timespec_to_nt_time(&b_time);
	d_printf("create_time:    %s\n", nt_time_string(talloc_tos(), tmp));

	tmp = full_timespec_to_nt_time(&a_time);
	d_printf("access_time:    %s\n", nt_time_string(talloc_tos(), tmp));

	tmp = full_timespec_to_nt_time(&m_time);
	d_printf("write_time:     %s\n", nt_time_string(talloc_tos(), tmp));

	tmp = full_timespec_to_nt_time(&c_time);
	d_printf("change_time:    %s\n", nt_time_string(talloc_tos(), tmp));

	d_printf("attributes: %s (%x)\n", attr_str(talloc_tos(), attr), attr);

	status = cli_qpathinfo_streams(cli, name, talloc_tos(), &num_streams,
				       &streams);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s getting streams for %s\n", nt_errstr(status),
			 name);
		return false;
	}

	for (i=0; i<num_streams; i++) {
		d_printf("stream: [%s], %lld bytes\n", streams[i].name,
			 (unsigned long long)streams[i].size);
	}

	if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
		char *subst, *print;
		uint32_t flags;

		status = cli_readlink(cli, name, talloc_tos(), &subst, &print,
				      &flags);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, "cli_readlink returned %s\n",
				  nt_errstr(status));
		} else {
			d_printf("symlink: subst=[%s], print=[%s], flags=%x\n",
				 subst, print, flags);
			TALLOC_FREE(subst);
			TALLOC_FREE(print);
		}
	}

	status = cli_ntcreate(cli, name, 0,
			      SEC_FILE_READ_DATA | SEC_FILE_READ_ATTRIBUTE |
			      SEC_STD_SYNCHRONIZE, 0,
			      FILE_SHARE_READ|FILE_SHARE_WRITE
			      |FILE_SHARE_DELETE,
			      FILE_OPEN, 0x0, 0x0, &fnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * Ignore failure, it does not hurt if we can't list
		 * snapshots
		 */
		return 0;
	}
	/*
	 * In order to get shadow copy data over SMB1 we
	 * must call twice, once with 'get_names = false'
	 * to get the size, then again with 'get_names = true'
	 * to get the data or a Windows server fails to return
	 * valid info. Samba doesn't have this bug. JRA.
	 */

	status = cli_shadow_copy_data(talloc_tos(), cli, fnum,
				      false, &snapshots, &num_snapshots);
	if (!NT_STATUS_IS_OK(status)) {
		cli_close(cli, fnum);
		return 0;
	}
	status = cli_shadow_copy_data(talloc_tos(), cli, fnum,
				      true, &snapshots, &num_snapshots);
	if (!NT_STATUS_IS_OK(status)) {
		cli_close(cli, fnum);
		return 0;
	}

	for (j=0; j<num_snapshots; j++) {
		char *snap_name;

		d_printf("%s\n", snapshots[j]);
		snap_name = talloc_asprintf(talloc_tos(), "%s%s",
					    snapshots[j], name);
		status = cli_qpathinfo3(cli, snap_name, &b_time, &a_time,
					&m_time, &c_time, &size,
					NULL, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, "pathinfo(%s) failed: %s\n",
				  snap_name, nt_errstr(status));
			TALLOC_FREE(snap_name);
			continue;
		}
		tmp = unix_timespec_to_nt_time(b_time);
		d_printf("create_time:    %s\n", nt_time_string(talloc_tos(), tmp));
		tmp = unix_timespec_to_nt_time(a_time);
		d_printf("access_time:    %s\n", nt_time_string(talloc_tos(), tmp));
		tmp =unix_timespec_to_nt_time(m_time);
		d_printf("write_time:     %s\n", nt_time_string(talloc_tos(), tmp));
		tmp = unix_timespec_to_nt_time(c_time);
		d_printf("change_time:    %s\n", nt_time_string(talloc_tos(), tmp));
		d_printf("size: %d\n", (int)size);
	}

	TALLOC_FREE(snapshots);
	cli_close(cli, fnum);

	return 0;
}

/****************************************************************************
 Show all info we can get
****************************************************************************/

static int cmd_allinfo(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *name;
	char *buf;

	name = talloc_strdup(ctx, client_get_cur_dir());
	if (!name) {
		return 1;
	}

	if (!next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
		d_printf("allinfo <file>\n");
		return 1;
	}
	name = talloc_asprintf_append(name, "%s", buf);
	if (!name) {
		return 1;
	}
	name = client_clean_name(ctx, name);
	if (name == NULL) {
		return 1;
	}
	do_allinfo(name);

	return 0;
}

/****************************************************************************
 Put a single file.
****************************************************************************/

static int do_put(const char *rname, const char *lname, bool reput)
{
	TALLOC_CTX *ctx = talloc_tos();
	uint16_t fnum;
	FILE *f;
	off_t start = 0;
	int rc = 0;
	struct timespec tp_start;
	struct cli_state *targetcli;
	char *targetname = NULL;
	struct push_state state;
	NTSTATUS status;

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
				cli, rname, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Failed to open %s: %s\n", rname, nt_errstr(status));
		return 1;
	}

	clock_gettime_mono(&tp_start);

	if (reput) {
		status = cli_open(targetcli, targetname, O_RDWR|O_CREAT, DENY_NONE, &fnum);
		if (NT_STATUS_IS_OK(status)) {
			if (!NT_STATUS_IS_OK(status = cli_qfileinfo_basic(
						     targetcli, fnum, NULL,
						     &start, NULL, NULL,
						     NULL, NULL, NULL))) {
				d_printf("getattrib: %s\n", nt_errstr(status));
				return 1;
			}
		}
	} else {
		status = cli_open(targetcli, targetname, O_RDWR|O_CREAT|O_TRUNC, DENY_NONE, &fnum);
	}

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s opening remote file %s\n", nt_errstr(status),
			 rname);
		return 1;
	}

	/* allow files to be piped into smbclient
	   jdblair 24.jun.98

	   Note that in this case this function will exit(0) rather
	   than returning. */
	if (!strcmp(lname, "-")) {
		f = stdin;
		/* size of file is not known */
	} else {
		f = fopen(lname, "r");
		if (f && reput) {
			if (fseek(f, start, SEEK_SET) == -1) {
				d_printf("Error seeking local file\n");
				fclose(f);
				return 1;
			}
		}
	}

	if (!f) {
		d_printf("Error opening local file %s\n",lname);
		return 1;
	}

	DEBUG(1,("putting file %s as %s ",lname,
		 rname));

	setvbuf(f, NULL, _IOFBF, io_bufsize);

	state.f = f;
	state.nread = 0;

	status = cli_push(targetcli, fnum, 0, 0, io_bufsize, push_source,
			  &state);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "cli_push returned %s\n", nt_errstr(status));
		rc = 1;
	}

	status = cli_close(targetcli, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s closing remote file %s\n", nt_errstr(status),
			 rname);
		if (f != stdin) {
			fclose(f);
		}
		return 1;
	}

	if (f != stdin) {
		fclose(f);
	}

	{
		struct timespec tp_end;
		int this_time;

		clock_gettime_mono(&tp_end);
		this_time = nsec_time_diff(&tp_end,&tp_start)/1000000;
		put_total_time_ms += this_time;
		put_total_size += state.nread;

		DEBUG(1,("(%3.1f kb/s) (average %3.1f kb/s)\n",
			 state.nread / (1.024*this_time + 1.0e-4),
			 put_total_size / (1.024*put_total_time_ms)));
	}

	if (f == stdin) {
		cli_shutdown(cli);
		popt_free_cmdline_auth_info();
		exit(rc);
	}

	return rc;
}

/****************************************************************************
 Put a file.
****************************************************************************/

static int cmd_put(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *lname;
	char *rname;
	char *buf;

	rname = talloc_strdup(ctx, client_get_cur_dir());
	if (!rname) {
		return 1;
	}

	if (!next_token_talloc(ctx, &cmd_ptr,&lname,NULL)) {
		d_printf("put <filename>\n");
		return 1;
	}

	if (next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		rname = talloc_asprintf_append(rname, "%s", buf);
	} else {
		rname = talloc_asprintf_append(rname, "%s", lname);
	}
	if (!rname) {
		return 1;
	}

	rname = client_clean_name(ctx, rname);
	if (!rname) {
		return 1;
	}

	{
		SMB_STRUCT_STAT st;
		/* allow '-' to represent stdin
		   jdblair, 24.jun.98 */
		if (!file_exist_stat(lname, &st, false) &&
		    (strcmp(lname,"-"))) {
			d_printf("%s does not exist\n",lname);
			return 1;
		}
	}

	return do_put(rname, lname, false);
}

/*************************************
 File list structure.
*************************************/

static struct file_list {
	struct file_list *prev, *next;
	char *file_path;
	bool isdir;
} *file_list;

/****************************************************************************
 Free a file_list structure.
****************************************************************************/

static void free_file_list (struct file_list *l_head)
{
	struct file_list *list, *next;

	for (list = l_head; list; list = next) {
		next = list->next;
		DLIST_REMOVE(l_head, list);
		TALLOC_FREE(list);
	}
}

/****************************************************************************
 Seek in a directory/file list until you get something that doesn't start with
 the specified name.
****************************************************************************/

static bool seek_list(struct file_list *list, char *name)
{
	while (list) {
		trim_string(list->file_path,"./","\n");
		if (strncmp(list->file_path, name, strlen(name)) != 0) {
			return true;
		}
		list = list->next;
	}

	return false;
}

/****************************************************************************
 Set the file selection mask.
****************************************************************************/

static int cmd_select(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *new_fs = NULL;
	next_token_talloc(ctx, &cmd_ptr,&new_fs,NULL)
		;
	if (new_fs) {
		client_set_fileselection(new_fs);
	} else {
		client_set_fileselection("");
	}
	return 0;
}

/****************************************************************************
  Recursive file matching function act as find
  match must be always set to true when calling this function
****************************************************************************/

static int file_find(TALLOC_CTX *ctx,
			struct file_list **list,
			const char *directory,
			const char *expression,
			bool match)
{
	DIR *dir;
	struct file_list *entry;
        struct stat statbuf;
        int ret;
        char *path;
	bool isdir;
	const char *dname;

        dir = opendir(directory);
	if (!dir)
		return -1;

        while ((dname = readdirname(dir))) {
		if (!strcmp("..", dname))
			continue;
		if (!strcmp(".", dname))
			continue;

		path = talloc_asprintf(ctx, "%s/%s", directory, dname);
		if (path == NULL) {
			continue;
		}

		isdir = false;
		if (!match || !gen_fnmatch(expression, dname)) {
			if (recurse) {
				ret = stat(path, &statbuf);
				if (ret == 0) {
					if (S_ISDIR(statbuf.st_mode)) {
						isdir = true;
						ret = file_find(ctx,
								list,
								path,
								expression,
								false);
					}
				} else {
					d_printf("file_find: cannot stat file %s\n", path);
				}

				if (ret == -1) {
					TALLOC_FREE(path);
					closedir(dir);
					return -1;
				}
			}
			entry = talloc_zero(ctx, struct file_list);
			if (!entry) {
				d_printf("Out of memory in file_find\n");
				closedir(dir);
				return -1;
			}
			entry->file_path = talloc_move(entry, &path);
			entry->isdir = isdir;
                        DLIST_ADD(*list, entry);
		} else {
			TALLOC_FREE(path);
		}
        }

	closedir(dir);
	return 0;
}

/****************************************************************************
 mput some files.
****************************************************************************/

static int cmd_mput(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *p = NULL;

	while (next_token_talloc(ctx, &cmd_ptr,&p,NULL)) {
		int ret;
		struct file_list *temp_list;
		char *quest, *lname, *rname;

		file_list = NULL;

		ret = file_find(ctx, &file_list, ".", p, true);
		if (ret) {
			free_file_list(file_list);
			continue;
		}

		quest = NULL;
		lname = NULL;
		rname = NULL;

		for (temp_list = file_list; temp_list;
		     temp_list = temp_list->next) {

			SAFE_FREE(lname);
			if (asprintf(&lname, "%s/", temp_list->file_path) <= 0) {
				continue;
			}
			trim_string(lname, "./", "/");

			/* check if it's a directory */
			if (temp_list->isdir) {
				/* if (!recurse) continue; */

				SAFE_FREE(quest);
				if (asprintf(&quest, "Put directory %s? ", lname) < 0) {
					break;
				}
				if (prompt && !yesno(quest)) { /* No */
					/* Skip the directory */
					lname[strlen(lname)-1] = '/';
					if (!seek_list(temp_list, lname))
						break;
				} else { /* Yes */
	      				SAFE_FREE(rname);
					if(asprintf(&rname, "%s%s", client_get_cur_dir(), lname) < 0) {
						break;
					}
					normalize_name(rname);
					{
						char *tmp_rname =
							client_clean_name(ctx, rname);
						if (tmp_rname == NULL) {
							break;
						}
						SAFE_FREE(rname);
						rname = smb_xstrdup(tmp_rname);
						TALLOC_FREE(tmp_rname);
						if (rname == NULL) {
							break;
						}
					}
					if (!NT_STATUS_IS_OK(cli_chkpath(cli, rname)) &&
					    !do_mkdir(rname)) {
						DEBUG (0, ("Unable to make dir, skipping..."));
						/* Skip the directory */
						lname[strlen(lname)-1] = '/';
						if (!seek_list(temp_list, lname)) {
							break;
						}
					}
				}
				continue;
			} else {
				SAFE_FREE(quest);
				if (asprintf(&quest,"Put file %s? ", lname) < 0) {
					break;
				}
				if (prompt && !yesno(quest)) {
					/* No */
					continue;
				}

				/* Yes */
				SAFE_FREE(rname);
				if (asprintf(&rname, "%s%s", client_get_cur_dir(), lname) < 0) {
					break;
				}
			}

			normalize_name(rname);

			{
				char *tmp_rname = client_clean_name(ctx, rname);
				if (tmp_rname == NULL) {
					break;
				}
				SAFE_FREE(rname);
				rname = smb_xstrdup(tmp_rname);
				TALLOC_FREE(tmp_rname);
				if (rname == NULL) {
					break;
				}
			}
			do_put(rname, lname, false);
		}
		free_file_list(file_list);
		SAFE_FREE(quest);
		SAFE_FREE(lname);
		SAFE_FREE(rname);
	}

	return 0;
}

/****************************************************************************
 Cancel a print job.
****************************************************************************/

static int do_cancel(int job)
{
	if (cli_printjob_del(cli, job)) {
		d_printf("Job %d cancelled\n",job);
		return 0;
	} else {
		NTSTATUS status = cli_nt_error(cli);
		d_printf("Error cancelling job %d : %s\n",
			 job, nt_errstr(status));
		return 1;
	}
}

/****************************************************************************
 Cancel a print job.
****************************************************************************/

static int cmd_cancel(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *buf = NULL;
	int job;

	if (!next_token_talloc(ctx, &cmd_ptr, &buf,NULL)) {
		d_printf("cancel <jobid> ...\n");
		return 1;
	}
	do {
		job = atoi(buf);
		do_cancel(job);
	} while (next_token_talloc(ctx, &cmd_ptr,&buf,NULL));

	return 0;
}

/****************************************************************************
 Print a file.
****************************************************************************/

static int cmd_print(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *lname = NULL;
	char *rname = NULL;
	char *p = NULL;

	if (!next_token_talloc(ctx, &cmd_ptr, &lname,NULL)) {
		d_printf("print <filename>\n");
		return 1;
	}

	rname = talloc_strdup(ctx, lname);
	if (!rname) {
		return 1;
	}
	p = strrchr_m(rname,'/');
	if (p) {
		rname = talloc_asprintf(ctx,
					"%s-%d",
					p+1,
					(int)getpid());
	}
	if (strequal(lname,"-")) {
		rname = talloc_asprintf(ctx,
				"stdin-%d",
				(int)getpid());
	}
	if (!rname) {
		return 1;
	}

	return do_put(rname, lname, false);
}

/****************************************************************************
 Show a print queue entry.
****************************************************************************/

static void queue_fn(struct print_job_info *p)
{
	d_printf("%-6d   %-9d    %s\n", (int)p->id, (int)p->size, p->name);
}

/****************************************************************************
 Show a print queue.
****************************************************************************/

static int cmd_queue(void)
{
	cli_print_queue(cli, queue_fn);
	return 0;
}

/****************************************************************************
 Delete some files.
****************************************************************************/

static NTSTATUS do_del(struct cli_state *cli_state, struct file_info *finfo,
		   const char *dir)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *mask = NULL;
	NTSTATUS status;

	mask = talloc_asprintf(ctx,
				"%s%c%s",
				dir,
				CLI_DIRSEP_CHAR,
				finfo->name);
	if (!mask) {
		return NT_STATUS_NO_MEMORY;
	}

	if (finfo->attr & FILE_ATTRIBUTE_DIRECTORY) {
		TALLOC_FREE(mask);
		return NT_STATUS_OK;
	}

	status = cli_unlink(cli_state, mask, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s deleting remote file %s\n",
			 nt_errstr(status), mask);
	}
	TALLOC_FREE(mask);
	return status;
}

/****************************************************************************
 Delete some files.
****************************************************************************/

static int cmd_del(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *mask = NULL;
	char *buf = NULL;
	NTSTATUS status = NT_STATUS_OK;
	uint32_t attribute = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN;

	if (recurse) {
		attribute |= FILE_ATTRIBUTE_DIRECTORY;
	}

	mask = talloc_strdup(ctx, client_get_cur_dir());
	if (!mask) {
		return 1;
	}
	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("del <filename>\n");
		return 1;
	}
	mask = talloc_asprintf_append(mask, "%s", buf);
	if (!mask) {
		return 1;
	}
	mask = client_clean_name(ctx, mask);
	if (mask == NULL) {
		return 1;
	}

	status = do_list(mask,attribute,do_del,false,false);
	if (!NT_STATUS_IS_OK(status)) {
		return 1;
	}
	return 0;
}

/****************************************************************************
 Delete some files.
****************************************************************************/

static NTSTATUS delete_remote_files_list(struct cli_state *cli_state,
					 struct file_list *flist)
{
	NTSTATUS status = NT_STATUS_OK;
	struct file_list *deltree_list_iter = NULL;

	for (deltree_list_iter = flist;
			deltree_list_iter != NULL;
			deltree_list_iter = deltree_list_iter->next) {
		if (CLI_DIRSEP_CHAR == '/') {
			/* POSIX. */
			status = cli_posix_unlink(cli_state,
					deltree_list_iter->file_path);
		} else if (deltree_list_iter->isdir) {
			status = cli_rmdir(cli_state,
					deltree_list_iter->file_path);
		} else {
			status = cli_unlink(cli_state,
					deltree_list_iter->file_path,
					FILE_ATTRIBUTE_SYSTEM |
					FILE_ATTRIBUTE_HIDDEN);
		}
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("%s deleting remote %s %s\n",
				nt_errstr(status),
				deltree_list_iter->isdir ?
				"directory" : "file",
				deltree_list_iter->file_path);
			return status;
		}
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Save a list of files to delete.
****************************************************************************/

static struct file_list *deltree_list_head;

static NTSTATUS do_deltree_list(struct cli_state *cli_state,
				struct file_info *finfo,
				const char *dir)
{
	struct file_list **file_list_head_pp = &deltree_list_head;
	struct file_list *dt = NULL;

	if (!do_this_one(finfo)) {
		return NT_STATUS_OK;
	}

	/* skip if this is . or .. */
	if (ISDOT(finfo->name) || ISDOTDOT(finfo->name)) {
		return NT_STATUS_OK;
	}

	dt = talloc_zero(NULL, struct file_list);
	if (dt == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* create absolute filename for cli_ntcreate() */
	dt->file_path = talloc_asprintf(dt,
					"%s%s%s",
					dir,
					CLI_DIRSEP_STR,
					finfo->name);
	if (dt->file_path == NULL) {
		TALLOC_FREE(dt);
		return NT_STATUS_NO_MEMORY;
	}

	if (finfo->attr & FILE_ATTRIBUTE_DIRECTORY) {
		dt->isdir = true;
	}

	DLIST_ADD(*file_list_head_pp, dt);
	return NT_STATUS_OK;
}

static int cmd_deltree(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *buf = NULL;
	NTSTATUS status = NT_STATUS_OK;
	struct file_list *deltree_list_norecurse = NULL;
	struct file_list *deltree_list_iter = NULL;
	uint32_t attribute = FILE_ATTRIBUTE_SYSTEM |
			     FILE_ATTRIBUTE_HIDDEN |
			     FILE_ATTRIBUTE_DIRECTORY;
	bool ok;
	char *mask = talloc_strdup(ctx, client_get_cur_dir());
	if (mask == NULL) {
		return 1;
	}
	ok = next_token_talloc(ctx, &cmd_ptr, &buf, NULL);
	if (!ok) {
		d_printf("deltree <filename>\n");
		return 1;
	}
	mask = talloc_asprintf_append(mask, "%s", buf);
	if (mask == NULL) {
		return 1;
	}
	mask = client_clean_name(ctx, mask);
	if (mask == NULL) {
		return 1;
	}

	deltree_list_head = NULL;

	/*
	 * Get the list of directories to
	 * delete (in case mask has a wildcard).
	 */
	status = do_list(mask, attribute, do_deltree_list, false, true);
	if (!NT_STATUS_IS_OK(status)) {
		goto err;
	}
	deltree_list_norecurse = deltree_list_head;
	deltree_list_head = NULL;

	for (deltree_list_iter = deltree_list_norecurse;
	     deltree_list_iter != NULL;
	     deltree_list_iter = deltree_list_iter->next) {

		if (deltree_list_iter->isdir == false) {
			/* Just a regular file. */
			if (CLI_DIRSEP_CHAR == '/') {
				/* POSIX. */
				status = cli_posix_unlink(cli,
					deltree_list_iter->file_path);
			} else {
				status = cli_unlink(cli,
					deltree_list_iter->file_path,
					FILE_ATTRIBUTE_SYSTEM |
					FILE_ATTRIBUTE_HIDDEN);
			}
			if (!NT_STATUS_IS_OK(status)) {
				goto err;
			}
			continue;
		}

		/*
		 * Get the list of files or directories to
		 * delete in depth order.
		 */
		status = do_list(deltree_list_iter->file_path,
				 attribute,
				 do_deltree_list,
				 true,
				 true);
		if (!NT_STATUS_IS_OK(status)) {
			goto err;
		}
		status = delete_remote_files_list(cli, deltree_list_head);
		free_file_list(deltree_list_head);
		deltree_list_head = NULL;
		if (!NT_STATUS_IS_OK(status)) {
			goto err;
		}
	}

	free_file_list(deltree_list_norecurse);
	free_file_list(deltree_list_head);
	return 0;

  err:

	free_file_list(deltree_list_norecurse);
	free_file_list(deltree_list_head);
	deltree_list_head = NULL;
	return 1;
}


/****************************************************************************
 Wildcard delete some files.
****************************************************************************/

static int cmd_wdel(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *mask = NULL;
	char *buf = NULL;
	uint32_t attribute;
	struct cli_state *targetcli;
	char *targetname = NULL;
	NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("wdel 0x<attrib> <wcard>\n");
		return 1;
	}

	attribute = (uint32_t)strtol(buf, (char **)NULL, 16);

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("wdel 0x<attrib> <wcard>\n");
		return 1;
	}

	mask = talloc_asprintf(ctx, "%s%s",
			client_get_cur_dir(),
			buf);
	if (!mask) {
		return 1;
	}
	mask = client_clean_name(ctx, mask);
	if (mask == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
				cli, mask, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cmd_wdel %s: %s\n", mask, nt_errstr(status));
		return 1;
	}

	status = cli_unlink(targetcli, targetname, attribute);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s deleting remote files %s\n", nt_errstr(status),
			 targetname);
	}
	return 0;
}

/****************************************************************************
****************************************************************************/

static int cmd_open(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *mask = NULL;
	char *buf = NULL;
	char *targetname = NULL;
	struct cli_state *targetcli;
	uint16_t fnum = (uint16_t)-1;
        NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("open <filename>\n");
		return 1;
	}
	mask = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf);
	if (!mask) {
		return 1;
	}

	mask = client_clean_name(ctx, mask);
	if (mask == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, mask, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("open %s: %s\n", mask, nt_errstr(status));
		return 1;
	}

	status = cli_ntcreate(targetcli, targetname, 0,
			FILE_READ_DATA|FILE_WRITE_DATA, 0,
			FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN,
			0x0, 0x0, &fnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		status = cli_ntcreate(targetcli, targetname, 0,
				FILE_READ_DATA, 0,
				FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN,
				0x0, 0x0, &fnum, NULL);
		if (NT_STATUS_IS_OK(status)) {
			d_printf("open file %s: for read/write fnum %d\n", targetname, fnum);
		} else {
			d_printf("Failed to open file %s. %s\n",
				 targetname, nt_errstr(status));
		}
	} else {
		d_printf("open file %s: for read/write fnum %d\n", targetname, fnum);
	}
	return 0;
}

static int cmd_posix_encrypt(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *domain = NULL;
	char *user = NULL;
	char *password = NULL;
	struct cli_credentials *creds = NULL;
	struct cli_credentials *lcreds = NULL;

	if (next_token_talloc(ctx, &cmd_ptr, &domain, NULL)) {

		if (!next_token_talloc(ctx, &cmd_ptr, &user, NULL)) {
			d_printf("posix_encrypt domain user password\n");
			return 1;
		}

		if (!next_token_talloc(ctx, &cmd_ptr, &password, NULL)) {
			d_printf("posix_encrypt domain user password\n");
			return 1;
		}

		lcreds = cli_session_creds_init(ctx,
						user,
						domain,
						NULL, /* realm */
						password,
						false, /* use_kerberos */
						false, /* fallback_after_kerberos */
						false, /* use_ccache */
						false); /* password_is_nt_hash */
		if (lcreds == NULL) {
			d_printf("cli_session_creds_init() failed.\n");
			return -1;
		}
		creds = lcreds;
	} else {
		bool auth_requested = false;

		creds = get_cmdline_auth_info_creds(
				popt_get_cmdline_auth_info());

		auth_requested = cli_credentials_authentication_requested(creds);
		if (!auth_requested) {
			d_printf("posix_encrypt domain user password\n");
			return 1;
		}
	}

	status = cli_smb1_setup_encryption(cli, creds);
	/* gensec currently references the creds so we can't free them here */
	talloc_unlink(ctx, lcreds);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("posix_encrypt failed with error %s\n", nt_errstr(status));
	} else {
		d_printf("encryption on\n");
		smb_encrypt = true;
	}

	return 0;
}

/****************************************************************************
****************************************************************************/

static int cmd_posix_open(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *mask = NULL;
	char *buf = NULL;
	char *targetname = NULL;
	struct cli_state *targetcli;
	mode_t mode;
	uint16_t fnum;
        NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("posix_open <filename> 0<mode>\n");
		return 1;
	}
	mask = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf);
	if (!mask) {
		return 1;
	}
	mask = client_clean_name(ctx, mask);
	if (mask == NULL) {
		return 1;
	}

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("posix_open <filename> 0<mode>\n");
		return 1;
	}
	mode = (mode_t)strtol(buf, (char **)NULL, 8);

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
				cli, mask, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("posix_open %s: %s\n", mask, nt_errstr(status));
		return 1;
	}

	status = cli_posix_open(targetcli, targetname, O_CREAT|O_RDWR, mode,
				&fnum);
	if (!NT_STATUS_IS_OK(status)) {
		status = cli_posix_open(targetcli, targetname,
					O_CREAT|O_RDONLY, mode, &fnum);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("Failed to open file %s. %s\n", targetname,
				 nt_errstr(status));
		} else {
			d_printf("posix_open file %s: for readonly fnum %d\n",
				 targetname, fnum);
		}
	} else {
		d_printf("posix_open file %s: for read/write fnum %d\n",
			 targetname, fnum);
	}

	return 0;
}

static int cmd_posix_mkdir(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *mask = NULL;
	char *buf = NULL;
	char *targetname = NULL;
	struct cli_state *targetcli;
	mode_t mode;
        NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("posix_mkdir <filename> 0<mode>\n");
		return 1;
	}
	mask = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf);
	if (!mask) {
		return 1;
	}
	mask = client_clean_name(ctx, mask);
	if (mask == NULL) {
		return 1;
	}

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("posix_mkdir <filename> 0<mode>\n");
		return 1;
	}
	mode = (mode_t)strtol(buf, (char **)NULL, 8);

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
				cli, mask, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("posix_mkdir %s: %s\n", mask, nt_errstr(status));
		return 1;
	}

	status = cli_posix_mkdir(targetcli, targetname, mode);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Failed to open file %s. %s\n",
			 targetname, nt_errstr(status));
	} else {
		d_printf("posix_mkdir created directory %s\n", targetname);
	}
	return 0;
}

static int cmd_posix_unlink(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *mask = NULL;
	char *buf = NULL;
	char *targetname = NULL;
	struct cli_state *targetcli;
        NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("posix_unlink <filename>\n");
		return 1;
	}
	mask = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf);
	if (!mask) {
		return 1;
	}
	mask = client_clean_name(ctx, mask);
	if (mask == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
				cli, mask, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("posix_unlink %s: %s\n", mask, nt_errstr(status));
		return 1;
	}

	status = cli_posix_unlink(targetcli, targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Failed to unlink file %s. %s\n",
			 targetname, nt_errstr(status));
	} else {
		d_printf("posix_unlink deleted file %s\n", targetname);
	}

	return 0;
}

static int cmd_posix_rmdir(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *mask = NULL;
	char *buf = NULL;
	char *targetname = NULL;
	struct cli_state *targetcli;
        NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("posix_rmdir <filename>\n");
		return 1;
	}
	mask = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf);
	if (!mask) {
		return 1;
	}
	mask = client_clean_name(ctx, mask);
	if (mask == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, mask, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("posix_rmdir %s: %s\n", mask, nt_errstr(status));
		return 1;
	}

	status = cli_posix_rmdir(targetcli, targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Failed to unlink directory %s. %s\n",
			 targetname, nt_errstr(status));
	} else {
		d_printf("posix_rmdir deleted directory %s\n", targetname);
	}

	return 0;
}

static int cmd_close(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *buf = NULL;
	int fnum;
	NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("close <fnum>\n");
		return 1;
	}

	fnum = atoi(buf);
	/* We really should use the targetcli here.... */
	status = cli_close(cli, fnum);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("close %d: %s\n", fnum, nt_errstr(status));
		return 1;
	}
	return 0;
}

static int cmd_posix(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	uint16_t major, minor;
	uint32_t caplow, caphigh;
	char *caps;
	NTSTATUS status;

	if (!SERVER_HAS_UNIX_CIFS(cli)) {
		d_printf("Server doesn't support UNIX CIFS extensions.\n");
		return 1;
	}

	status = cli_unix_extensions_version(cli, &major, &minor, &caplow,
					     &caphigh);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Can't get UNIX CIFS extensions version from "
			 "server: %s\n", nt_errstr(status));
		return 1;
	}

	d_printf("Server supports CIFS extensions %u.%u\n", (unsigned int)major, (unsigned int)minor);

	caps = talloc_strdup(ctx, "");
	if (!caps) {
		return 1;
	}
        if (caplow & CIFS_UNIX_FCNTL_LOCKS_CAP) {
		caps = talloc_asprintf_append(caps, "locks ");
		if (!caps) {
			return 1;
		}
	}
        if (caplow & CIFS_UNIX_POSIX_ACLS_CAP) {
		caps = talloc_asprintf_append(caps, "acls ");
		if (!caps) {
			return 1;
		}
	}
        if (caplow & CIFS_UNIX_XATTTR_CAP) {
		caps = talloc_asprintf_append(caps, "eas ");
		if (!caps) {
			return 1;
		}
	}
        if (caplow & CIFS_UNIX_POSIX_PATHNAMES_CAP) {
		caps = talloc_asprintf_append(caps, "pathnames ");
		if (!caps) {
			return 1;
		}
	}
        if (caplow & CIFS_UNIX_POSIX_PATH_OPERATIONS_CAP) {
		caps = talloc_asprintf_append(caps, "posix_path_operations ");
		if (!caps) {
			return 1;
		}
	}
        if (caplow & CIFS_UNIX_LARGE_READ_CAP) {
		caps = talloc_asprintf_append(caps, "large_read ");
		if (!caps) {
			return 1;
		}
	}
        if (caplow & CIFS_UNIX_LARGE_WRITE_CAP) {
		caps = talloc_asprintf_append(caps, "large_write ");
		if (!caps) {
			return 1;
		}
	}
	if (caplow & CIFS_UNIX_TRANSPORT_ENCRYPTION_CAP) {
		caps = talloc_asprintf_append(caps, "posix_encrypt ");
		if (!caps) {
			return 1;
		}
	}
	if (caplow & CIFS_UNIX_TRANSPORT_ENCRYPTION_MANDATORY_CAP) {
		caps = talloc_asprintf_append(caps, "mandatory_posix_encrypt ");
		if (!caps) {
			return 1;
		}
	}

	if (*caps && caps[strlen(caps)-1] == ' ') {
		caps[strlen(caps)-1] = '\0';
	}

	d_printf("Server supports CIFS capabilities %s\n", caps);

	status = cli_set_unix_extensions_capabilities(cli, major, minor,
						      caplow, caphigh);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Can't set UNIX CIFS extensions capabilities. %s.\n",
			 nt_errstr(status));
		return 1;
	}

	if (caplow & CIFS_UNIX_POSIX_PATHNAMES_CAP) {
		CLI_DIRSEP_CHAR = '/';
		*CLI_DIRSEP_STR = '/';
		client_set_cur_dir(CLI_DIRSEP_STR);
	}

	return 0;
}

static int cmd_lock(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *buf = NULL;
	uint64_t start, len;
	enum brl_type lock_type;
	int fnum;
	NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("lock <fnum> [r|w] <hex-start> <hex-len>\n");
		return 1;
	}
	fnum = atoi(buf);

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("lock <fnum> [r|w] <hex-start> <hex-len>\n");
		return 1;
	}

	if (*buf == 'r' || *buf == 'R') {
		lock_type = READ_LOCK;
	} else if (*buf == 'w' || *buf == 'W') {
		lock_type = WRITE_LOCK;
	} else {
		d_printf("lock <fnum> [r|w] <hex-start> <hex-len>\n");
		return 1;
	}

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("lock <fnum> [r|w] <hex-start> <hex-len>\n");
		return 1;
	}

	start = (uint64_t)strtol(buf, (char **)NULL, 16);

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("lock <fnum> [r|w] <hex-start> <hex-len>\n");
		return 1;
	}

	len = (uint64_t)strtol(buf, (char **)NULL, 16);

	status = cli_posix_lock(cli, fnum, start, len, true, lock_type);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("lock failed %d: %s\n", fnum, nt_errstr(status));
	}

	return 0;
}

static int cmd_unlock(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *buf = NULL;
	uint64_t start, len;
	int fnum;
	NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("unlock <fnum> <hex-start> <hex-len>\n");
		return 1;
	}
	fnum = atoi(buf);

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("unlock <fnum> <hex-start> <hex-len>\n");
		return 1;
	}

	start = (uint64_t)strtol(buf, (char **)NULL, 16);

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("unlock <fnum> <hex-start> <hex-len>\n");
		return 1;
	}

	len = (uint64_t)strtol(buf, (char **)NULL, 16);

	status = cli_posix_unlock(cli, fnum, start, len);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("unlock failed %d: %s\n", fnum, nt_errstr(status));
	}

	return 0;
}

static int cmd_posix_whoami(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	uint64_t uid = 0;
	uint64_t gid = 0;
	uint32_t num_gids = 0;
	uint32_t num_sids = 0;
	uint64_t *gids = NULL;
	struct dom_sid *sids = NULL;
	bool guest = false;
	uint32_t i;

	status = cli_posix_whoami(cli,
			ctx,
			&uid,
			&gid,
			&num_gids,
			&gids,
			&num_sids,
			&sids,
			&guest);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("posix_whoami failed with error %s\n", nt_errstr(status));
		return 1;
	}

	d_printf("GUEST:%s\n", guest ? "True" : "False");
	d_printf("UID:%" PRIu64 "\n", uid);
	d_printf("GID:%" PRIu64 "\n", gid);
	d_printf("NUM_GIDS:%" PRIu32 "\n", num_gids);
	for (i = 0; i < num_gids; i++) {
		d_printf("GIDS[%" PRIu32 "]:%" PRIu64 "\n", i, gids[i]);
	}
	d_printf("NUM_SIDS:%" PRIu32 "\n", num_sids);
	for (i = 0; i < num_sids; i++) {
		struct dom_sid_buf buf;
		d_printf("SIDS[%" PRIu32 "]:%s\n",
			 i,
			 dom_sid_str_buf(&sids[i], &buf));
	}
	return 0;
}


/****************************************************************************
 Remove a directory.
****************************************************************************/

static int cmd_rmdir(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *mask = NULL;
	char *buf = NULL;
	char *targetname = NULL;
	struct cli_state *targetcli;
        NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("rmdir <dirname>\n");
		return 1;
	}
	mask = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf);
	if (!mask) {
		return 1;
	}
	mask = client_clean_name(ctx, mask);
	if (mask == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, mask, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("rmdir %s: %s\n", mask, nt_errstr(status));
		return 1;
	}

	status = cli_rmdir(targetcli, targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s removing remote directory file %s\n",
			 nt_errstr(status), mask);
	}

	return 0;
}

/****************************************************************************
 UNIX hardlink.
****************************************************************************/

static int cmd_link(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *oldname = NULL;
	char *newname = NULL;
	char *buf = NULL;
	char *buf2 = NULL;
	char *targetname = NULL;
	struct cli_state *targetcli;
        NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL) ||
	    !next_token_talloc(ctx, &cmd_ptr,&buf2,NULL)) {
		d_printf("link <oldname> <newname>\n");
		return 1;
	}
	oldname = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf);
	if (!oldname) {
		return 1;
	}
	oldname = client_clean_name(ctx, oldname);
	if (oldname == NULL) {
		return 1;
	}
	newname = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf2);
	if (!newname) {
		return 1;
	}
	newname = client_clean_name(ctx, newname);
	if (newname == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, oldname, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("link %s: %s\n", oldname, nt_errstr(status));
		return 1;
	}

	if (!SERVER_HAS_UNIX_CIFS(targetcli)) {
		d_printf("Server doesn't support UNIX CIFS calls.\n");
		return 1;
	}

	status = cli_posix_hardlink(targetcli, targetname, newname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s linking files (%s -> %s)\n",
			 nt_errstr(status), newname, oldname);
		return 1;
	}
	return 0;
}

/****************************************************************************
 UNIX readlink.
****************************************************************************/

static int cmd_readlink(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *name= NULL;
	char *buf = NULL;
	char *targetname = NULL;
	char *linkname = NULL;
	struct cli_state *targetcli;
        NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("readlink <name>\n");
		return 1;
	}
	name = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf);
	if (!name) {
		return 1;
	}
	name = client_clean_name(ctx, name);
	if (name == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, name, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("readlink %s: %s\n", name, nt_errstr(status));
		return 1;
	}

	if (!SERVER_HAS_UNIX_CIFS(targetcli)) {
		d_printf("Server doesn't support UNIX CIFS calls.\n");
		return 1;
	}

	status = cli_posix_readlink(targetcli, name, talloc_tos(), &linkname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s readlink on file %s\n",
			 nt_errstr(status), name);
		return 1;
	}

	d_printf("%s -> %s\n", name, linkname);

	TALLOC_FREE(linkname);

	return 0;
}


/****************************************************************************
 UNIX symlink.
****************************************************************************/

static int cmd_symlink(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *link_target = NULL;
	char *newname = NULL;
	char *buf = NULL;
	char *buf2 = NULL;
	struct cli_state *newcli;
	NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL) ||
	    !next_token_talloc(ctx, &cmd_ptr,&buf2,NULL)) {
		d_printf("symlink <link_target> <newname>\n");
		return 1;
	}
	/* Oldname (link target) must be an untouched blob. */
	link_target = buf;

	if (SERVER_HAS_UNIX_CIFS(cli)) {
		newname = talloc_asprintf(ctx, "%s%s", client_get_cur_dir(),
					  buf2);
		if (!newname) {
			return 1;
		}
		newname = client_clean_name(ctx, newname);
		if (newname == NULL) {
			return 1;
		}
		/* New name must be present in share namespace. */
		status = cli_resolve_path(ctx, "",
				popt_get_cmdline_auth_info(), cli, newname,
				&newcli, &newname);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("link %s: %s\n", newname,
				nt_errstr(status));
			return 1;
		}
		status = cli_posix_symlink(newcli, link_target, newname);
	} else {
		status = cli_symlink(
			cli, link_target, buf2,
			buf2[0] == '\\' ? 0 : SYMLINK_FLAG_RELATIVE);
	}

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s symlinking files (%s -> %s)\n",
			 nt_errstr(status), newname, link_target);
		return 1;
	}

	return 0;
}

/****************************************************************************
 UNIX chmod.
****************************************************************************/

static int cmd_chmod(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *src = NULL;
	char *buf = NULL;
	char *buf2 = NULL;
	char *targetname = NULL;
	struct cli_state *targetcli;
	mode_t mode;
        NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL) ||
	    !next_token_talloc(ctx, &cmd_ptr,&buf2,NULL)) {
		d_printf("chmod mode file\n");
		return 1;
	}
	src = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf2);
	if (!src) {
		return 1;
	}
	src = client_clean_name(ctx, src);
	if (src == NULL) {
		return 1;
	}

	mode = (mode_t)strtol(buf, NULL, 8);

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, src, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("chmod %s: %s\n", src, nt_errstr(status));
		return 1;
	}

	if (!SERVER_HAS_UNIX_CIFS(targetcli)) {
		d_printf("Server doesn't support UNIX CIFS calls.\n");
		return 1;
	}

	status = cli_posix_chmod(targetcli, targetname, mode);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s chmod file %s 0%o\n",
			 nt_errstr(status), src, (unsigned int)mode);
		return 1;
	}

	return 0;
}

static const char *filetype_to_str(mode_t mode)
{
	if (S_ISREG(mode)) {
		return "regular file";
	} else if (S_ISDIR(mode)) {
		return "directory";
	} else
#ifdef S_ISCHR
	if (S_ISCHR(mode)) {
		return "character device";
	} else
#endif
#ifdef S_ISBLK
	if (S_ISBLK(mode)) {
		return "block device";
	} else
#endif
#ifdef S_ISFIFO
	if (S_ISFIFO(mode)) {
		return "fifo";
	} else
#endif
#ifdef S_ISLNK
	if (S_ISLNK(mode)) {
		return "symbolic link";
	} else
#endif
#ifdef S_ISSOCK
	if (S_ISSOCK(mode)) {
		return "socket";
	} else
#endif
	return "";
}

static char rwx_to_str(mode_t m, mode_t bt, char ret)
{
	if (m & bt) {
		return ret;
	} else {
		return '-';
	}
}

static char *unix_mode_to_str(char *s, mode_t m)
{
	char *p = s;
	const char *str = filetype_to_str(m);

	switch(str[0]) {
		case 'd':
			*p++ = 'd';
			break;
		case 'c':
			*p++ = 'c';
			break;
		case 'b':
			*p++ = 'b';
			break;
		case 'f':
			*p++ = 'p';
			break;
		case 's':
			*p++ = str[1] == 'y' ? 'l' : 's';
			break;
		case 'r':
		default:
			*p++ = '-';
			break;
	}
	*p++ = rwx_to_str(m, S_IRUSR, 'r');
	*p++ = rwx_to_str(m, S_IWUSR, 'w');
	*p++ = rwx_to_str(m, S_IXUSR, 'x');
	*p++ = rwx_to_str(m, S_IRGRP, 'r');
	*p++ = rwx_to_str(m, S_IWGRP, 'w');
	*p++ = rwx_to_str(m, S_IXGRP, 'x');
	*p++ = rwx_to_str(m, S_IROTH, 'r');
	*p++ = rwx_to_str(m, S_IWOTH, 'w');
	*p++ = rwx_to_str(m, S_IXOTH, 'x');
	*p++ = '\0';
	return s;
}

/****************************************************************************
 Utility function for UNIX getfacl.
****************************************************************************/

static char *perms_to_string(fstring permstr, unsigned char perms)
{
	fstrcpy(permstr, "---");
	if (perms & SMB_POSIX_ACL_READ) {
		permstr[0] = 'r';
	}
	if (perms & SMB_POSIX_ACL_WRITE) {
		permstr[1] = 'w';
	}
	if (perms & SMB_POSIX_ACL_EXECUTE) {
		permstr[2] = 'x';
	}
	return permstr;
}

/****************************************************************************
 UNIX getfacl.
****************************************************************************/

static int cmd_getfacl(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *src = NULL;
	char *name = NULL;
	char *targetname = NULL;
	struct cli_state *targetcli;
	uint16_t major, minor;
	uint32_t caplow, caphigh;
	char *retbuf = NULL;
	size_t rb_size = 0;
	SMB_STRUCT_STAT sbuf;
	size_t num_file_acls = 0;
	size_t num_dir_acls = 0;
	size_t expected_buflen;
	uint16_t i;
	NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&name,NULL)) {
		d_printf("getfacl filename\n");
		return 1;
	}
	src = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			name);
	if (!src) {
		return 1;
	}
	src = client_clean_name(ctx, src);
	if (src == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, src, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("stat %s: %s\n", src, nt_errstr(status));
		return 1;
	}

	if (!SERVER_HAS_UNIX_CIFS(targetcli)) {
		d_printf("Server doesn't support UNIX CIFS calls.\n");
		return 1;
	}

	status = cli_unix_extensions_version(targetcli, &major, &minor,
					     &caplow, &caphigh);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Can't get UNIX CIFS version from server: %s.\n",
			 nt_errstr(status));
		return 1;
	}

	if (!(caplow & CIFS_UNIX_POSIX_ACLS_CAP)) {
		d_printf("This server supports UNIX extensions "
			"but doesn't support POSIX ACLs.\n");
		return 1;
	}

	status = cli_posix_stat(targetcli, targetname, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s getfacl doing a stat on file %s\n",
			 nt_errstr(status), src);
		return 1;
	}

	status = cli_posix_getacl(targetcli, targetname, ctx, &rb_size, &retbuf);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s getfacl file %s\n",
			 nt_errstr(status), src);
		return 1;
	}

	/* ToDo : Print out the ACL values. */
	if (rb_size < 6 || SVAL(retbuf,0) != SMB_POSIX_ACL_VERSION) {
		d_printf("getfacl file %s, unknown POSIX acl version %u.\n",
			src, (unsigned int)CVAL(retbuf,0) );
		return 1;
	}

	num_file_acls = SVAL(retbuf,2);
	num_dir_acls = SVAL(retbuf,4);

	/*
	 * No overflow check, num_*_acls comes from a 16-bit value,
	 * and we expect expected_buflen (size_t) to be of at least 32
	 * bit.
	 */
	expected_buflen = SMB_POSIX_ACL_HEADER_SIZE +
		SMB_POSIX_ACL_ENTRY_SIZE*(num_file_acls+num_dir_acls);

	if (rb_size != expected_buflen) {
		d_printf("getfacl file %s, incorrect POSIX acl buffer size "
			 "(should be %zu, was %zu).\n",
			 src,
			 expected_buflen,
			 rb_size);
		return 1;
	}

	d_printf("# file: %s\n", src);
	d_printf("# owner: %u\n# group: %u\n", (unsigned int)sbuf.st_ex_uid, (unsigned int)sbuf.st_ex_gid);

	if (num_file_acls == 0 && num_dir_acls == 0) {
		d_printf("No acls found.\n");
	}

	for (i = 0; i < num_file_acls; i++) {
		uint32_t uorg;
		fstring permstring;
		unsigned char tagtype = CVAL(retbuf, SMB_POSIX_ACL_HEADER_SIZE+(i*SMB_POSIX_ACL_ENTRY_SIZE));
		unsigned char perms = CVAL(retbuf, SMB_POSIX_ACL_HEADER_SIZE+(i*SMB_POSIX_ACL_ENTRY_SIZE)+1);

		switch(tagtype) {
			case SMB_POSIX_ACL_USER_OBJ:
				d_printf("user::");
				break;
			case SMB_POSIX_ACL_USER:
				uorg = IVAL(retbuf,SMB_POSIX_ACL_HEADER_SIZE+(i*SMB_POSIX_ACL_ENTRY_SIZE)+2);
				d_printf("user:%u:", uorg);
				break;
			case SMB_POSIX_ACL_GROUP_OBJ:
				d_printf("group::");
				break;
			case SMB_POSIX_ACL_GROUP:
				uorg = IVAL(retbuf,SMB_POSIX_ACL_HEADER_SIZE+(i*SMB_POSIX_ACL_ENTRY_SIZE)+2);
				d_printf("group:%u:", uorg);
				break;
			case SMB_POSIX_ACL_MASK:
				d_printf("mask::");
				break;
			case SMB_POSIX_ACL_OTHER:
				d_printf("other::");
				break;
			default:
				d_printf("getfacl file %s, incorrect POSIX acl tagtype (%u).\n",
					src, (unsigned int)tagtype );
				SAFE_FREE(retbuf);
				return 1;
		}

		d_printf("%s\n", perms_to_string(permstring, perms));
	}

	for (i = 0; i < num_dir_acls; i++) {
		uint32_t uorg;
		fstring permstring;
		unsigned char tagtype = CVAL(retbuf, SMB_POSIX_ACL_HEADER_SIZE+((i+num_file_acls)*SMB_POSIX_ACL_ENTRY_SIZE));
		unsigned char perms = CVAL(retbuf, SMB_POSIX_ACL_HEADER_SIZE+((i+num_file_acls)*SMB_POSIX_ACL_ENTRY_SIZE)+1);

		switch(tagtype) {
			case SMB_POSIX_ACL_USER_OBJ:
				d_printf("default:user::");
				break;
			case SMB_POSIX_ACL_USER:
				uorg = IVAL(retbuf,SMB_POSIX_ACL_HEADER_SIZE+((i+num_file_acls)*SMB_POSIX_ACL_ENTRY_SIZE)+2);
				d_printf("default:user:%u:", uorg);
				break;
			case SMB_POSIX_ACL_GROUP_OBJ:
				d_printf("default:group::");
				break;
			case SMB_POSIX_ACL_GROUP:
				uorg = IVAL(retbuf,SMB_POSIX_ACL_HEADER_SIZE+((i+num_file_acls)*SMB_POSIX_ACL_ENTRY_SIZE)+2);
				d_printf("default:group:%u:", uorg);
				break;
			case SMB_POSIX_ACL_MASK:
				d_printf("default:mask::");
				break;
			case SMB_POSIX_ACL_OTHER:
				d_printf("default:other::");
				break;
			default:
				d_printf("getfacl file %s, incorrect POSIX acl tagtype (%u).\n",
					src, (unsigned int)tagtype );
				SAFE_FREE(retbuf);
				return 1;
		}

		d_printf("%s\n", perms_to_string(permstring, perms));
	}

	return 0;
}

/****************************************************************************
 Get the EA list of a file
****************************************************************************/

static int cmd_geteas(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *src = NULL;
	char *name = NULL;
	char *targetname = NULL;
	struct cli_state *targetcli;
	NTSTATUS status;
	size_t i, num_eas;
	struct ea_struct *eas;

	if (!next_token_talloc(ctx, &cmd_ptr,&name,NULL)) {
		d_printf("geteas filename\n");
		return 1;
	}
	src = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			name);
	if (!src) {
		return 1;
	}
	src = client_clean_name(ctx, src);
	if (src == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, src, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("stat %s: %s\n", src, nt_errstr(status));
		return 1;
	}

	status = cli_get_ea_list_path(targetcli, targetname, talloc_tos(),
				      &num_eas, &eas);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_get_ea_list_path: %s\n", nt_errstr(status));
		return 1;
	}

	for (i=0; i<num_eas; i++) {
		d_printf("%s (%d) =\n", eas[i].name, (int)eas[i].flags);
		dump_data_file(eas[i].value.data, eas[i].value.length, false,
			       stdout);
		d_printf("\n");
	}

	TALLOC_FREE(eas);

	return 0;
}

/****************************************************************************
 Set an EA of a file
****************************************************************************/

static int cmd_setea(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *src = NULL;
	char *name = NULL;
	char *eaname = NULL;
	char *eavalue = NULL;
	char *targetname = NULL;
	struct cli_state *targetcli;
	NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr, &name, NULL)
	    || !next_token_talloc(ctx, &cmd_ptr, &eaname, NULL)) {
		d_printf("setea filename eaname value\n");
		return 1;
	}
	if (!next_token_talloc(ctx, &cmd_ptr, &eavalue, NULL)) {
		eavalue = talloc_strdup(ctx, "");
	}
	src = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			name);
	if (!src) {
		return 1;
	}
	src = client_clean_name(ctx, src);
	if (src == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, src, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("stat %s: %s\n", src, nt_errstr(status));
		return 1;
	}

	status =  cli_set_ea_path(targetcli, targetname, eaname, eavalue,
				  strlen(eavalue));
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("set_ea %s: %s\n", src, nt_errstr(status));
		return 1;
	}

	return 0;
}

/****************************************************************************
 UNIX stat.
****************************************************************************/

static int cmd_stat(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *src = NULL;
	char *name = NULL;
	char *targetname = NULL;
	struct cli_state *targetcli;
	fstring mode_str;
	SMB_STRUCT_STAT sbuf;
	struct tm *lt;
	time_t tmp_time;
        NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&name,NULL)) {
		d_printf("stat file\n");
		return 1;
	}
	src = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			name);
	if (!src) {
		return 1;
	}
	src = client_clean_name(ctx, src);
	if (src == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, src, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("stat %s: %s\n", src, nt_errstr(status));
		return 1;
	}

	if (!SERVER_HAS_UNIX_CIFS(targetcli)) {
		d_printf("Server doesn't support UNIX CIFS calls.\n");
		return 1;
	}

	status = cli_posix_stat(targetcli, targetname, &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s stat file %s\n",
			 nt_errstr(status), src);
		return 1;
	}

	/* Print out the stat values. */
	d_printf("File: %s\n", src);
	d_printf("Size: %-12.0f\tBlocks: %u\t%s\n",
		(double)sbuf.st_ex_size,
		(unsigned int)sbuf.st_ex_blocks,
		filetype_to_str(sbuf.st_ex_mode));

#if defined(S_ISCHR) && defined(S_ISBLK)
	if (S_ISCHR(sbuf.st_ex_mode) || S_ISBLK(sbuf.st_ex_mode)) {
		d_printf("Inode: %.0f\tLinks: %u\tDevice type: %u,%u\n",
			(double)sbuf.st_ex_ino,
			(unsigned int)sbuf.st_ex_nlink,
			unix_dev_major(sbuf.st_ex_rdev),
			unix_dev_minor(sbuf.st_ex_rdev));
	} else
#endif
		d_printf("Inode: %.0f\tLinks: %u\n",
			(double)sbuf.st_ex_ino,
			(unsigned int)sbuf.st_ex_nlink);

	d_printf("Access: (0%03o/%s)\tUid: %u\tGid: %u\n",
		((int)sbuf.st_ex_mode & 0777),
		unix_mode_to_str(mode_str, sbuf.st_ex_mode),
		(unsigned int)sbuf.st_ex_uid,
		(unsigned int)sbuf.st_ex_gid);

	tmp_time = convert_timespec_to_time_t(sbuf.st_ex_atime);
	lt = localtime(&tmp_time);
	if (lt) {
		strftime(mode_str, sizeof(mode_str), "%Y-%m-%d %T %z", lt);
	} else {
		fstrcpy(mode_str, "unknown");
	}
	d_printf("Access: %s\n", mode_str);

	tmp_time = convert_timespec_to_time_t(sbuf.st_ex_mtime);
	lt = localtime(&tmp_time);
	if (lt) {
		strftime(mode_str, sizeof(mode_str), "%Y-%m-%d %T %z", lt);
	} else {
		fstrcpy(mode_str, "unknown");
	}
	d_printf("Modify: %s\n", mode_str);

	tmp_time = convert_timespec_to_time_t(sbuf.st_ex_ctime);
	lt = localtime(&tmp_time);
	if (lt) {
		strftime(mode_str, sizeof(mode_str), "%Y-%m-%d %T %z", lt);
	} else {
		fstrcpy(mode_str, "unknown");
	}
	d_printf("Change: %s\n", mode_str);

	return 0;
}


/****************************************************************************
 UNIX chown.
****************************************************************************/

static int cmd_chown(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *src = NULL;
	uid_t uid;
	gid_t gid;
	char *buf, *buf2, *buf3;
	struct cli_state *targetcli;
	char *targetname = NULL;
        NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL) ||
	    !next_token_talloc(ctx, &cmd_ptr,&buf2,NULL) ||
	    !next_token_talloc(ctx, &cmd_ptr,&buf3,NULL)) {
		d_printf("chown uid gid file\n");
		return 1;
	}

	uid = (uid_t)atoi(buf);
	gid = (gid_t)atoi(buf2);

	src = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf3);
	if (!src) {
		return 1;
	}
	src = client_clean_name(ctx, src);
	if (src == NULL) {
		return 1;
	}
	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, src, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("chown %s: %s\n", src, nt_errstr(status));
		return 1;
	}

	if (!SERVER_HAS_UNIX_CIFS(targetcli)) {
		d_printf("Server doesn't support UNIX CIFS calls.\n");
		return 1;
	}

	status = cli_posix_chown(targetcli, targetname, uid, gid);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s chown file %s uid=%d, gid=%d\n",
			 nt_errstr(status), src, (int)uid, (int)gid);
		return 1;
	}

	return 0;
}

/****************************************************************************
 Rename some file.
****************************************************************************/

static int cmd_rename(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *src, *dest;
	char *buf, *buf2;
	struct cli_state *targetcli;
	char *targetsrc;
	char *targetdest;
        NTSTATUS status;
	bool replace = false;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL) ||
	    !next_token_talloc(ctx, &cmd_ptr,&buf2,NULL)) {
		d_printf("rename <src> <dest> [-f]\n");
		return 1;
	}

	src = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf);
	if (!src) {
		return 1;
	}
	src = client_clean_name(ctx, src);
	if (src == NULL) {
		return 1;
	}

	dest = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf2);
	if (!dest) {
		return 1;
	}
	dest = client_clean_name(ctx, dest);
	if (dest == NULL) {
		return 1;
	}

	if (next_token_talloc(ctx, &cmd_ptr, &buf, NULL) &&
	    strcsequal(buf, "-f")) {
		replace = true;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, src, &targetcli, &targetsrc);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("rename %s: %s\n", src, nt_errstr(status));
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, dest, &targetcli, &targetdest);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("rename %s: %s\n", dest, nt_errstr(status));
		return 1;
	}

	status = cli_rename(targetcli, targetsrc, targetdest, replace);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s renaming files %s -> %s \n",
			nt_errstr(status),
			targetsrc,
			targetdest);
		return 1;
	}

	return 0;
}

struct scopy_timing {
	struct timespec tp_start;
};

static int scopy_status(off_t written, void *priv)
{
	struct timespec tp_end;
	unsigned int scopy_total_time_ms;
	struct scopy_timing *st = priv;

	clock_gettime_mono(&tp_end);
	scopy_total_time_ms = nsec_time_diff(&tp_end,&st->tp_start)/1000000;

	DEBUG(5,("Copied %jd bytes at an average %3.1f kb/s\n",
		 (intmax_t)written, written / (1.024*scopy_total_time_ms)));

	return true;
}

/****************************************************************************
 Server-Side copy some file.
****************************************************************************/

static int cmd_scopy(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *src, *dest;
	char *buf, *buf2;
	struct cli_state *targetcli;
	char *targetsrc;
	char *targetdest;
	uint32_t DesiredAccess, ShareAccess, CreateDisposition, CreateOptions;
	struct smb_create_returns cr;
	uint16_t destfnum = (uint16_t)-1;
	uint16_t srcfnum = (uint16_t)-1;
	off_t written = 0;
	struct scopy_timing st;
	int rc = 0;
	NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL) ||
			!next_token_talloc(ctx, &cmd_ptr,&buf2,NULL)) {
		d_printf("scopy <src> <dest>\n");
		return 1;
	}

	src = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf);
	if (!src) {
		return 1;
	}
	src = client_clean_name(ctx, src);
	if (src == NULL) {
		return 1;
	}

	dest = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf2);
	if (!dest) {
		return 1;
	}
	dest = client_clean_name(ctx, dest);
	if (dest == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, src, &targetcli, &targetsrc);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("scopy %s: %s\n", src, nt_errstr(status));
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
			cli, dest, &targetcli, &targetdest);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("scopy %s: %s\n", dest, nt_errstr(status));
		return 1;
	}


	DesiredAccess = (FILE_READ_DATA|FILE_READ_EA|FILE_READ_ATTRIBUTES|
			READ_CONTROL_ACCESS|SYNCHRONIZE_ACCESS);
	ShareAccess = FILE_SHARE_READ|FILE_SHARE_DELETE;
	CreateDisposition = FILE_OPEN;
	CreateOptions = (FILE_SEQUENTIAL_ONLY|FILE_NON_DIRECTORY_FILE|
			FILE_OPEN_REPARSE_POINT);
	status = cli_ntcreate(targetcli, targetsrc, 0, DesiredAccess, 0,
			ShareAccess, CreateDisposition, CreateOptions, 0x0,
			&srcfnum, &cr);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Failed to open file %s. %s\n",
				targetsrc, nt_errstr(status));
		return 1;
	}

	DesiredAccess = (FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_READ_EA|
			FILE_WRITE_EA|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|
			DELETE_ACCESS|READ_CONTROL_ACCESS|WRITE_DAC_ACCESS|SYNCHRONIZE_ACCESS);
	ShareAccess = FILE_SHARE_NONE;
	CreateDisposition = FILE_CREATE;
	CreateOptions = FILE_SEQUENTIAL_ONLY|FILE_NON_DIRECTORY_FILE;
	status = cli_ntcreate(targetcli, targetdest, 0, DesiredAccess,
			FILE_ATTRIBUTE_ARCHIVE, ShareAccess, CreateDisposition,
			CreateOptions, 0x0, &destfnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Failed to create file %s. %s\n",
				targetdest, nt_errstr(status));
		cli_close(targetcli, srcfnum);
		return 1;
	}

	clock_gettime_mono(&st.tp_start);
	status = cli_splice(targetcli, targetcli, srcfnum, destfnum,
			cr.end_of_file, 0, 0, &written, scopy_status, &st);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s copying file %s -> %s \n",
				nt_errstr(status),
				targetsrc,
				targetdest);
		rc = 1;
	}

	status = cli_close(targetcli, srcfnum);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Error %s closing remote source file\n", nt_errstr(status));
		rc = 1;
	}
	status = cli_close(targetcli, destfnum);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Error %s closing remote dest file\n", nt_errstr(status));
		rc = 1;
	}

	return rc;
}

/****************************************************************************
 Print the volume name.
****************************************************************************/

static int cmd_volume(void)
{
	char *volname;
	uint32_t serial_num;
	time_t create_date;
	NTSTATUS status;

	status = cli_get_fs_volume_info(cli, talloc_tos(),
					&volname, &serial_num,
					&create_date);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Error %s getting volume info\n", nt_errstr(status));
		return 1;
	}

	d_printf("Volume: |%s| serial number 0x%x\n",
			volname, (unsigned int)serial_num);
	return 0;
}

/****************************************************************************
 Hard link files using the NT call.
****************************************************************************/

static int cmd_hardlink(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *src, *dest;
	char *buf, *buf2;
	struct cli_state *targetcli;
	char *targetname;
        NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL) ||
	    !next_token_talloc(ctx, &cmd_ptr,&buf2,NULL)) {
		d_printf("hardlink <src> <dest>\n");
		return 1;
	}

	src = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf);
	if (!src) {
		return 1;
	}
	src = client_clean_name(ctx, src);
	if (src == NULL) {
		return 1;
	}

	dest = talloc_asprintf(ctx,
			"%s%s",
			client_get_cur_dir(),
			buf2);
	if (!dest) {
		return 1;
	}
	dest = client_clean_name(ctx, dest);
	if (dest == NULL) {
		return 1;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
				cli, src, &targetcli, &targetname);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("hardlink %s: %s\n", src, nt_errstr(status));
		return 1;
	}

	status = cli_hardlink(targetcli, targetname, dest);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("%s doing an NT hard link of files\n",
			 nt_errstr(status));
		return 1;
	}

	return 0;
}

/****************************************************************************
 Toggle the prompt flag.
****************************************************************************/

static int cmd_prompt(void)
{
	prompt = !prompt;
	DEBUG(2,("prompting is now %s\n",prompt?"on":"off"));
	return 1;
}

/****************************************************************************
 Set the newer than time.
****************************************************************************/

static int cmd_newer(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *buf;
	bool ok;
	SMB_STRUCT_STAT sbuf;

	ok = next_token_talloc(ctx, &cmd_ptr,&buf,NULL);
	if (ok && (sys_stat(buf, &sbuf, false) == 0)) {
		newer_than = convert_timespec_to_time_t(sbuf.st_ex_mtime);
		DEBUG(1,("Getting files newer than %s",
			 time_to_asc(newer_than)));
	} else {
		newer_than = 0;
	}

	if (ok && newer_than == 0) {
		d_printf("Error setting newer-than time\n");
		return 1;
	}

	return 0;
}

/****************************************************************************
 Watch directory changes
****************************************************************************/

static int cmd_notify(void)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *name, *buf;
	NTSTATUS status;
	uint16_t fnum;

	name = talloc_strdup(talloc_tos(), client_get_cur_dir());
	if (name == NULL) {
		goto fail;
	}
	if (!next_token_talloc(talloc_tos(), &cmd_ptr, &buf, NULL)) {
		goto usage;
	}
	name = talloc_asprintf_append(name, "%s", buf);
	if (name == NULL) {
		goto fail;
	}
	name = client_clean_name(talloc_tos(), name);
	if (name == NULL) {
		return 1;
	}
	status = cli_ntcreate(
		cli, name, 0, FILE_READ_DATA, 0,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN, 0, 0, &fnum, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Could not open file: %s\n", nt_errstr(status));
		goto fail;
	}

	while (1) {
		uint32_t i;
		uint32_t num_changes = 0;
		struct notify_change *changes = NULL;

		status = cli_notify(cli, fnum, 1000, FILE_NOTIFY_CHANGE_ALL,
				    true,
				    talloc_tos(), &num_changes, &changes);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOTIFY_ENUM_DIR)) {
			printf("NOTIFY_ENUM_DIR\n");
			status = NT_STATUS_OK;
		}
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("notify returned %s\n",
				 nt_errstr(status));
			goto fail;
		}
		for (i=0; i<num_changes; i++) {
			printf("%4.4x %s\n", changes[i].action,
			       changes[i].name);
		}
		TALLOC_FREE(changes);
	}
usage:
	d_printf("notify <dir name>\n");
fail:
	TALLOC_FREE(frame);
	return 1;
}

/****************************************************************************
 Set the archive level.
****************************************************************************/

static int cmd_archive(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *buf;

	if (next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		archive_level = atoi(buf);
	} else {
		d_printf("Archive level is %d\n",archive_level);
	}

	return 0;
}

/****************************************************************************
 Toggle the backup_intent state.
****************************************************************************/

static int cmd_backup(void)
{
	backup_intent = !backup_intent;
	cli_set_backup_intent(cli, backup_intent);
	DEBUG(2,("backup intent is now %s\n",backup_intent?"on":"off"));
	return 1;
}

/****************************************************************************
 Toggle the lowercaseflag.
****************************************************************************/

static int cmd_lowercase(void)
{
	lowercase = !lowercase;
	DEBUG(2,("filename lowercasing is now %s\n",lowercase?"on":"off"));
	return 0;
}

/****************************************************************************
 Toggle the case sensitive flag.
****************************************************************************/

static int cmd_setcase(void)
{
	bool orig_case_sensitive = cli_set_case_sensitive(cli, false);

	cli_set_case_sensitive(cli, !orig_case_sensitive);
	DEBUG(2,("filename case sensitivity is now %s\n",!orig_case_sensitive ?
		"on":"off"));
	return 0;
}

/****************************************************************************
 Toggle the showacls flag.
****************************************************************************/

static int cmd_showacls(void)
{
	showacls = !showacls;
	DEBUG(2,("showacls is now %s\n",showacls?"on":"off"));
	return 0;
}


/****************************************************************************
 Toggle the recurse flag.
****************************************************************************/

static int cmd_recurse(void)
{
	recurse = !recurse;
	DEBUG(2,("directory recursion is now %s\n",recurse?"on":"off"));
	return 0;
}

/****************************************************************************
 Toggle the translate flag.
****************************************************************************/

static int cmd_translate(void)
{
	translation = !translation;
	DEBUG(2,("CR/LF<->LF and print text translation now %s\n",
		 translation?"on":"off"));
	return 0;
}

/****************************************************************************
 Do the lcd command.
 ****************************************************************************/

static int cmd_lcd(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *buf;
	char *d;

	if (next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		if (chdir(buf) == -1) {
			d_printf("chdir to %s failed (%s)\n",
				buf, strerror(errno));
		}
	}
	d = sys_getwd();
	if (!d) {
		return 1;
	}
	DEBUG(2,("the local directory is now %s\n",d));
	SAFE_FREE(d);
	return 0;
}

/****************************************************************************
 Get a file restarting at end of local file.
 ****************************************************************************/

static int cmd_reget(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *local_name = NULL;
	char *remote_name = NULL;
	char *fname = NULL;
	char *p = NULL;

	remote_name = talloc_strdup(ctx, client_get_cur_dir());
	if (!remote_name) {
		return 1;
	}

	if (!next_token_talloc(ctx, &cmd_ptr, &fname, NULL)) {
		d_printf("reget <filename>\n");
		return 1;
	}
	remote_name = talloc_asprintf_append(remote_name, "%s", fname);
	if (!remote_name) {
		return 1;
	}
	remote_name = client_clean_name(ctx,remote_name);
	if (!remote_name) {
		return 1;
	}

	local_name = fname;
	next_token_talloc(ctx, &cmd_ptr, &p, NULL);
	if (p) {
		local_name = p;
	}

	return do_get(remote_name, local_name, true);
}

/****************************************************************************
 Put a file restarting at end of local file.
 ****************************************************************************/

static int cmd_reput(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *local_name = NULL;
	char *remote_name = NULL;
	char *buf;
	SMB_STRUCT_STAT st;

	remote_name = talloc_strdup(ctx, client_get_cur_dir());
	if (!remote_name) {
		return 1;
	}

	if (!next_token_talloc(ctx, &cmd_ptr, &local_name, NULL)) {
		d_printf("reput <filename>\n");
		return 1;
	}

	if (!file_exist_stat(local_name, &st, false)) {
		d_printf("%s does not exist\n", local_name);
		return 1;
	}

	if (next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
		remote_name = talloc_asprintf_append(remote_name,
						"%s", buf);
	} else {
		remote_name = talloc_asprintf_append(remote_name,
						"%s", local_name);
	}
	if (!remote_name) {
		return 1;
	}

	remote_name = client_clean_name(ctx, remote_name);
	if (!remote_name) {
		return 1;
	}

	return do_put(remote_name, local_name, true);
}

/****************************************************************************
 List a share name.
 ****************************************************************************/

static void browse_fn(const char *name, uint32_t m,
                      const char *comment, void *state)
{
	const char *typestr = "";

        switch (m & 7) {
	case STYPE_DISKTREE:
		typestr = "Disk";
		break;
	case STYPE_PRINTQ:
		typestr = "Printer";
		break;
	case STYPE_DEVICE:
		typestr = "Device";
		break;
	case STYPE_IPC:
		typestr = "IPC";
		break;
        }
	/* FIXME: If the remote machine returns non-ascii characters
	   in any of these fields, they can corrupt the output.  We
	   should remove them. */
	if (!grepable) {
		d_printf("\t%-15s %-10.10s%s\n",
               		name,typestr,comment);
	} else {
		d_printf ("%s|%s|%s\n",typestr,name,comment);
	}
}

static bool browse_host_rpc(bool sort)
{
	NTSTATUS status;
	struct rpc_pipe_client *pipe_hnd = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	WERROR werr;
	struct srvsvc_NetShareInfoCtr info_ctr;
	struct srvsvc_NetShareCtr1 ctr1;
	uint32_t resume_handle = 0;
	uint32_t total_entries = 0;
	uint32_t i;
	struct dcerpc_binding_handle *b;

	status = cli_rpc_pipe_open_noauth(cli, &ndr_table_srvsvc,
					  &pipe_hnd);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Could not connect to srvsvc pipe: %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(frame);
		return false;
	}

	b = pipe_hnd->binding_handle;

	ZERO_STRUCT(info_ctr);
	ZERO_STRUCT(ctr1);

	info_ctr.level = 1;
	info_ctr.ctr.ctr1 = &ctr1;

	status = dcerpc_srvsvc_NetShareEnumAll(b, frame,
					      pipe_hnd->desthost,
					      &info_ctr,
					      0xffffffff,
					      &total_entries,
					      &resume_handle,
					      &werr);

	if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(werr)) {
		TALLOC_FREE(pipe_hnd);
		TALLOC_FREE(frame);
		return false;
	}

	for (i=0; i < info_ctr.ctr.ctr1->count; i++) {
		struct srvsvc_NetShareInfo1 info = info_ctr.ctr.ctr1->array[i];
		browse_fn(info.name, info.type, info.comment, NULL);
	}

	TALLOC_FREE(pipe_hnd);
	TALLOC_FREE(frame);
	return true;
}

/****************************************************************************
 Try and browse available connections on a host.
****************************************************************************/

static bool browse_host(bool sort)
{
	int ret;

	if (!grepable) {
	        d_printf("\n\tSharename       Type      Comment\n");
	        d_printf("\t---------       ----      -------\n");
	}

	if (browse_host_rpc(sort)) {
		return true;
	}

	if (smbXcli_conn_protocol(cli->conn) > PROTOCOL_NT1) {
		return false;
	}

	ret = cli_RNetShareEnum(cli, browse_fn, NULL);
	if (ret == -1) {
		NTSTATUS status = cli_nt_error(cli);
		d_printf("Error returning browse list: %s\n",
			 nt_errstr(status));
	}

	return (ret != -1);
}

/****************************************************************************
 List a server name.
****************************************************************************/

static void server_fn(const char *name, uint32_t m,
                      const char *comment, void *state)
{

	if (!grepable){
		d_printf("\t%-16s     %s\n", name, comment);
	} else {
		d_printf("%s|%s|%s\n",(char *)state, name, comment);
	}
}

/****************************************************************************
 Try and browse available connections on a host.
****************************************************************************/

static bool list_servers(const char *wk_grp)
{
	fstring state;

	if (!cli->server_domain)
		return false;

	if (!grepable) {
        	d_printf("\n\tServer               Comment\n");
        	d_printf("\t---------            -------\n");
	};
	fstrcpy( state, "Server" );
	cli_NetServerEnum(cli, cli->server_domain, SV_TYPE_ALL, server_fn,
			  state);

	if (!grepable) {
	        d_printf("\n\tWorkgroup            Master\n");
	        d_printf("\t---------            -------\n");
	};

	fstrcpy( state, "Workgroup" );
	cli_NetServerEnum(cli, cli->server_domain, SV_TYPE_DOMAIN_ENUM,
			  server_fn, state);
	return true;
}

/****************************************************************************
 Print or set current VUID
****************************************************************************/

static int cmd_vuid(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *buf;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		d_printf("Current VUID is %d\n",
			 cli_state_get_uid(cli));
		return 0;
	}

	cli_state_set_uid(cli, atoi(buf));
	return 0;
}

/****************************************************************************
 Setup a new VUID, by issuing a session setup
****************************************************************************/

static int cmd_logon(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *l_username, *l_password;
	struct cli_credentials *creds = NULL;
	NTSTATUS nt_status;

	if (!next_token_talloc(ctx, &cmd_ptr,&l_username,NULL)) {
		d_printf("logon <username> [<password>]\n");
		return 0;
	}

	if (!next_token_talloc(ctx, &cmd_ptr,&l_password,NULL)) {
		char pwd[256] = {0};
		int rc;

		rc = samba_getpass("Password: ", pwd, sizeof(pwd), false, false);
		if (rc == 0) {
			l_password = talloc_strdup(ctx, pwd);
		}
	}
	if (!l_password) {
		return 1;
	}

	creds = cli_session_creds_init(ctx,
				       l_username,
				       lp_workgroup(),
				       NULL, /* realm */
				       l_password,
				       false, /* use_kerberos */
				       false, /* fallback_after_kerberos */
				       false, /* use_ccache */
				       false); /* password_is_nt_hash */
	if (creds == NULL) {
		d_printf("cli_session_creds_init() failed.\n");
		return -1;
	}
	nt_status = cli_session_setup_creds(cli, creds);
	TALLOC_FREE(creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		d_printf("session setup failed: %s\n", nt_errstr(nt_status));
		return -1;
	}

	d_printf("Current VUID is %d\n", cli_state_get_uid(cli));
	return 0;
}

/**
 * close the session
 */

static int cmd_logoff(void)
{
	NTSTATUS status;

	status = cli_ulogoff(cli);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("logoff failed: %s\n", nt_errstr(status));
		return -1;
	}

	d_printf("logoff successful\n");
	return 0;
}


/**
 * tree connect (connect to a share)
 */

static int cmd_tcon(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *sharename;
	NTSTATUS status;

	if (!next_token_talloc(ctx, &cmd_ptr, &sharename, NULL)) {
		d_printf("tcon <sharename>\n");
		return 0;
	}

	if (!sharename) {
		return 1;
	}

	status = cli_tree_connect(cli, sharename, "?????", NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("tcon failed: %s\n", nt_errstr(status));
		return -1;
	}

	talloc_free(sharename);

	d_printf("tcon to %s successful, tid: %u\n", sharename,
		 cli_state_get_tid(cli));
	return 0;
}

/**
 * tree disconnect (disconnect from a share)
 */

static int cmd_tdis(void)
{
	NTSTATUS status;

	status = cli_tdis(cli);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("tdis failed: %s\n", nt_errstr(status));
		return -1;
	}

	d_printf("tdis successful\n");
	return 0;
}


/**
 * get or set tid
 */

static int cmd_tid(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *tid_str;

	if (!next_token_talloc(ctx, &cmd_ptr, &tid_str, NULL)) {
		if (cli_state_has_tcon(cli)) {
			d_printf("current tid is %d\n", cli_state_get_tid(cli));
		} else {
			d_printf("no tcon currently\n");
		}
	} else {
		uint32_t tid = atoi(tid_str);
		if (!cli_state_has_tcon(cli)) {
			d_printf("no tcon currently\n");
		}
		cli_state_set_tid(cli, tid);
	}

	return 0;
}


/****************************************************************************
 list active connections
****************************************************************************/

static int cmd_list_connect(void)
{
	cli_cm_display(cli);
	return 0;
}

/****************************************************************************
 display the current active client connection
****************************************************************************/

static int cmd_show_connect( void )
{
	TALLOC_CTX *ctx = talloc_tos();
	struct cli_state *targetcli;
	char *targetpath;
	NTSTATUS status;

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(), cli,
				  client_get_cur_dir(), &targetcli,
				  &targetpath);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("showconnect %s: %s\n", cur_dir, nt_errstr(status));
		return 1;
	}

	d_printf("//%s/%s\n", smbXcli_conn_remote_name(targetcli->conn), targetcli->share);
	return 0;
}

/**
 * cmd_utimes - interactive command to set the four times
 *
 * Read a filename and four times from the client command line and update
 * the file times. A value of -1 for a time means don't change.
 */
static int cmd_utimes(void)
{
	char *buf;
	char *fname = NULL;
	struct timespec times[4] = {{0}};
	struct timeval_buf tbuf[4];
	int time_count = 0;
	int err = 0;
	bool ok;
	TALLOC_CTX *ctx = talloc_new(NULL);
	NTSTATUS status;

	if (ctx == NULL) {
		return 1;
	}

	ok = next_token_talloc(ctx, &cmd_ptr, &buf, NULL);
	if (!ok) {
		d_printf("utimes <filename> <create-time> <access-time> "
			 "<write-time> <change-time>\n");
		d_printf("Dates should be in YY:MM:DD-HH:MM:SS format "
			"or -1 for no change\n");
		err = 1;
		goto out;
	}

	fname = talloc_asprintf(ctx,
				"%s%s",
				client_get_cur_dir(),
				buf);
	if (fname == NULL) {
		err = 1;
		goto out;
	}
	fname = client_clean_name(ctx, fname);
	if (fname == NULL) {
		err = 1;
		goto out;
	}

	while (next_token_talloc(ctx, &cmd_ptr, &buf, NULL) &&
		time_count < 4) {
		const char *s = buf;
		struct tm tm = {0,};
		time_t t;
		char *ret;

		if (strlen(s) == 2 && strcmp(s, "-1") == 0) {
			times[time_count] = make_omit_timespec();
			time_count++;
			continue;
		}

		ret = strptime(s, "%y:%m:%d-%H:%M:%S", &tm);

		if (ret == NULL) {
			ret = strptime(s, "%Y:%m:%d-%H:%M:%S", &tm);
		}

		/* We could not match all the chars, so print error */
		if (ret == NULL || *ret != 0) {
			d_printf("Invalid date format: %s\n", s);
			d_printf("utimes <filename> <create-time> "
				"<access-time> <write-time> <change-time>\n");
			d_printf("Dates should be in [YY]YY:MM:DD-HH:MM:SS "
				 "format or -1 for no change\n");
			err = 1;
			goto out;
		}

		/* Convert tm to a time_t */
		t = mktime(&tm);
		times[time_count] = (struct timespec){.tv_sec = t};
		time_count++;
	}

	if (time_count < 4) {
		d_printf("Insufficient dates: %d\n", time_count);
		d_printf("utimes <filename> <create-time> <access-time> "
			"<write-time> <change-time>\n");
		d_printf("Dates should be in YY:MM:DD-HH:MM:SS format "
			"or -1 for no change\n");
		err = 1;
		goto out;
	}

	DEBUG(10, ("times\nCreate: %sAccess: %s Write: %sChange: %s\n",
		   timespec_string_buf(&times[0], false, &tbuf[0]),
		   timespec_string_buf(&times[1], false, &tbuf[1]),
		   timespec_string_buf(&times[2], false, &tbuf[2]),
		   timespec_string_buf(&times[3], false, &tbuf[3])));

	status = cli_setpathinfo_ext(
		cli, fname, times[0], times[1], times[2], times[3],
		(uint32_t)-1);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_setpathinfo_ext failed: %s\n",
			 nt_errstr(status));
		err = 1;
		goto out;
	}
out:
	talloc_free(ctx);
	return err;
}

/**
 * set_remote_attr - set DOS attributes of a remote file
 * @filename: path to the file name
 * @new_attr: attribute bit mask to use
 * @mode: one of ATTR_SET or ATTR_UNSET
 *
 * Update the file attributes with the one provided.
 */
int set_remote_attr(const char *filename, uint32_t new_attr, int mode)
{
	extern struct cli_state *cli;
	uint32_t old_attr;
	NTSTATUS status;

	status = cli_getatr(cli, filename, &old_attr, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_getatr failed: %s\n", nt_errstr(status));
		return 1;
	}

	if (mode == ATTR_SET) {
		new_attr |= old_attr;
	} else {
		new_attr = old_attr & ~new_attr;
	}

	status = cli_setatr(cli, filename, new_attr, 0);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("cli_setatr failed: %s\n", nt_errstr(status));
		return 1;
	}

	return 0;
}

/**
 * cmd_setmode - interactive command to set DOS attributes
 *
 * Read a filename and mode from the client command line and update
 * the file DOS attributes.
 */
int cmd_setmode(void)
{
	char *buf;
	char *fname = NULL;
	uint32_t attr[2] = {0};
	int mode = ATTR_SET;
	int err = 0;
	bool ok;
	TALLOC_CTX *ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return 1;
	}

	ok = next_token_talloc(ctx, &cmd_ptr, &buf, NULL);
	if (!ok) {
		d_printf("setmode <filename> <[+|-]rsha>\n");
		err = 1;
		goto out;
	}

	fname = talloc_asprintf(ctx,
				"%s%s",
				client_get_cur_dir(),
				buf);
	if (fname == NULL) {
		err = 1;
		goto out;
	}
	fname = client_clean_name(ctx, fname);
	if (fname == NULL) {
		err = 1;
		goto out;
	}

	while (next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
		const char *s = buf;

		while (*s) {
			switch (*s++) {
			case '+':
				mode = ATTR_SET;
				break;
			case '-':
				mode = ATTR_UNSET;
				break;
			case 'r':
				attr[mode] |= FILE_ATTRIBUTE_READONLY;
				break;
			case 'h':
				attr[mode] |= FILE_ATTRIBUTE_HIDDEN;
				break;
			case 's':
				attr[mode] |= FILE_ATTRIBUTE_SYSTEM;
				break;
			case 'a':
				attr[mode] |= FILE_ATTRIBUTE_ARCHIVE;
				break;
			default:
				d_printf("setmode <filename> <perm=[+|-]rsha>\n");
				err = 1;
				goto out;
			}
		}
	}

	if (attr[ATTR_SET] == 0 && attr[ATTR_UNSET] == 0) {
		d_printf("setmode <filename> <[+|-]rsha>\n");
		err = 1;
		goto out;
	}

	DEBUG(2, ("perm set %d %d\n", attr[ATTR_SET], attr[ATTR_UNSET]));

	/* ignore return value: server might not store DOS attributes */
	set_remote_attr(fname, attr[ATTR_SET], ATTR_SET);
	set_remote_attr(fname, attr[ATTR_UNSET], ATTR_UNSET);
out:
	talloc_free(ctx);
	return err;
}

/****************************************************************************
 iosize command
***************************************************************************/

int cmd_iosize(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *buf;
	int iosize;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
			if (!smb_encrypt) {
				d_printf("iosize <n> or iosize 0x<n>. "
					"Minimum is 0 (default), "
					"max is 16776960 (0xFFFF00)\n");
			} else {
				d_printf("iosize <n> or iosize 0x<n>. "
					"(Encrypted connection) ,"
					"Minimum is 0 (default), "
					"max is 130048 (0x1FC00)\n");
			}
		} else {
			d_printf("iosize <n> or iosize 0x<n>.\n");
		}
		return 1;
	}

	iosize = strtol(buf,NULL,0);
	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		if (smb_encrypt && (iosize < 0 || iosize > 0xFC00)) {
			d_printf("iosize out of range for encrypted "
				"connection (min = 0 (default), "
				"max = 130048 (0x1FC00)\n");
			return 1;
		} else if (!smb_encrypt && (iosize < 0 || iosize > 0xFFFF00)) {
			d_printf("iosize out of range (min = 0 (default), "
				"max = 16776960 (0xFFFF00)\n");
			return 1;
		}
	}

	io_bufsize = iosize;
	d_printf("iosize is now %d\n", io_bufsize);
	return 0;
}

/****************************************************************************
 timeout command
***************************************************************************/

static int cmd_timeout(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *buf;

	if (!next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		unsigned int old_timeout = cli_set_timeout(cli, 0);
		cli_set_timeout(cli, old_timeout);
		d_printf("timeout <n> (per-operation timeout "
			"in seconds - currently %u).\n",
			old_timeout/1000);
		return 1;
	}

	io_timeout = strtol(buf,NULL,0);
	cli_set_timeout(cli, io_timeout*1000);
	d_printf("io_timeout per operation is now %d\n", io_timeout);
	return 0;
}


/****************************************************************************
history
****************************************************************************/
static int cmd_history(void)
{
#if defined(HAVE_LIBREADLINE) && defined(HAVE_HISTORY_LIST)
	HIST_ENTRY **hlist;
	int i;

	hlist = history_list();

	for (i = 0; hlist && hlist[i]; i++) {
		DEBUG(0, ("%d: %s\n", i, hlist[i]->line));
	}
#else
	DEBUG(0,("no history without readline support\n"));
#endif

	return 0;
}

/* Some constants for completing filename arguments */

#define COMPL_NONE        0          /* No completions */
#define COMPL_REMOTE      1          /* Complete remote filename */
#define COMPL_LOCAL       2          /* Complete local filename */

/* This defines the commands supported by this client.
 * NOTE: The "!" must be the last one in the list because it's fn pointer
 *       field is NULL, and NULL in that field is used in process_tok()
 *       (below) to indicate the end of the list.  crh
 */
static struct {
	const char *name;
	int (*fn)(void);
	const char *description;
	char compl_args[2];      /* Completion argument info */
} commands[] = {
  {"?",cmd_help,"[command] give help on a command",{COMPL_NONE,COMPL_NONE}},
  {"allinfo",cmd_allinfo,"<file> show all available info",
   {COMPL_REMOTE,COMPL_NONE}},
  {"altname",cmd_altname,"<file> show alt name",{COMPL_REMOTE,COMPL_NONE}},
  {"archive",cmd_archive,"<level>\n0=ignore archive bit\n1=only get archive files\n2=only get archive files and reset archive bit\n3=get all files and reset archive bit",{COMPL_NONE,COMPL_NONE}},
  {"backup",cmd_backup,"toggle backup intent state",{COMPL_NONE,COMPL_NONE}},
  {"blocksize",cmd_block,"blocksize <number> (default 20)",{COMPL_NONE,COMPL_NONE}},
  {"cancel",cmd_cancel,"<jobid> cancel a print queue entry",{COMPL_NONE,COMPL_NONE}},
  {"case_sensitive",cmd_setcase,"toggle the case sensitive flag to server",{COMPL_NONE,COMPL_NONE}},
  {"cd",cmd_cd,"[directory] change/report the remote directory",{COMPL_REMOTE,COMPL_NONE}},
  {"chmod",cmd_chmod,"<src> <mode> chmod a file using UNIX permission",{COMPL_REMOTE,COMPL_NONE}},
  {"chown",cmd_chown,"<src> <uid> <gid> chown a file using UNIX uids and gids",{COMPL_REMOTE,COMPL_NONE}},
  {"close",cmd_close,"<fid> close a file given a fid",{COMPL_REMOTE,COMPL_NONE}},
  {"del",cmd_del,"<mask> delete all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"deltree",cmd_deltree,"<mask> recursively delete all matching files and directories",{COMPL_REMOTE,COMPL_NONE}},
  {"dir",cmd_dir,"<mask> list the contents of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"du",cmd_du,"<mask> computes the total size of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"echo",cmd_echo,"ping the server",{COMPL_NONE,COMPL_NONE}},
  {"exit",cmd_quit,"logoff the server",{COMPL_NONE,COMPL_NONE}},
  {"get",cmd_get,"<remote name> [local name] get a file",{COMPL_REMOTE,COMPL_LOCAL}},
  {"getfacl",cmd_getfacl,"<file name> get the POSIX ACL on a file (UNIX extensions only)",{COMPL_REMOTE,COMPL_NONE}},
  {"geteas", cmd_geteas, "<file name> get the EA list of a file",
   {COMPL_REMOTE, COMPL_NONE}},
  {"hardlink",cmd_hardlink,"<src> <dest> create a Windows hard link",{COMPL_REMOTE,COMPL_REMOTE}},
  {"help",cmd_help,"[command] give help on a command",{COMPL_NONE,COMPL_NONE}},
  {"history",cmd_history,"displays the command history",{COMPL_NONE,COMPL_NONE}},
  {"iosize",cmd_iosize,"iosize <number> (default 64512)",{COMPL_NONE,COMPL_NONE}},
  {"lcd",cmd_lcd,"[directory] change/report the local current working directory",{COMPL_LOCAL,COMPL_NONE}},
  {"link",cmd_link,"<oldname> <newname> create a UNIX hard link",{COMPL_REMOTE,COMPL_REMOTE}},
  {"lock",cmd_lock,"lock <fnum> [r|w] <hex-start> <hex-len> : set a POSIX lock",{COMPL_REMOTE,COMPL_REMOTE}},
  {"lowercase",cmd_lowercase,"toggle lowercasing of filenames for get",{COMPL_NONE,COMPL_NONE}},
  {"ls",cmd_dir,"<mask> list the contents of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"l",cmd_dir,"<mask> list the contents of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"mask",cmd_select,"<mask> mask all filenames against this",{COMPL_REMOTE,COMPL_NONE}},
  {"md",cmd_mkdir,"<directory> make a directory",{COMPL_NONE,COMPL_NONE}},
  {"mget",cmd_mget,"<mask> get all the matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"mkdir",cmd_mkdir,"<directory> make a directory",{COMPL_NONE,COMPL_NONE}},
  {"more",cmd_more,"<remote name> view a remote file with your pager",{COMPL_REMOTE,COMPL_NONE}},
  {"mput",cmd_mput,"<mask> put all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"newer",cmd_newer,"<file> only mget files newer than the specified local file",{COMPL_LOCAL,COMPL_NONE}},
  {"notify",cmd_notify,"<file>Get notified of dir changes",{COMPL_REMOTE,COMPL_NONE}},
  {"open",cmd_open,"<mask> open a file",{COMPL_REMOTE,COMPL_NONE}},
  {"posix", cmd_posix, "turn on all POSIX capabilities", {COMPL_REMOTE,COMPL_NONE}},
  {"posix_encrypt",cmd_posix_encrypt,"<domain> <user> <password> start up transport encryption",{COMPL_REMOTE,COMPL_NONE}},
  {"posix_open",cmd_posix_open,"<name> 0<mode> open_flags mode open a file using POSIX interface",{COMPL_REMOTE,COMPL_NONE}},
  {"posix_mkdir",cmd_posix_mkdir,"<name> 0<mode> creates a directory using POSIX interface",{COMPL_REMOTE,COMPL_NONE}},
  {"posix_rmdir",cmd_posix_rmdir,"<name> removes a directory using POSIX interface",{COMPL_REMOTE,COMPL_NONE}},
  {"posix_unlink",cmd_posix_unlink,"<name> removes a file using POSIX interface",{COMPL_REMOTE,COMPL_NONE}},
  {"posix_whoami",cmd_posix_whoami,"return logged on user information "
			"using POSIX interface",{COMPL_REMOTE,COMPL_NONE}},
  {"print",cmd_print,"<file name> print a file",{COMPL_NONE,COMPL_NONE}},
  {"prompt",cmd_prompt,"toggle prompting for filenames for mget and mput",{COMPL_NONE,COMPL_NONE}},
  {"put",cmd_put,"<local name> [remote name] put a file",{COMPL_LOCAL,COMPL_REMOTE}},
  {"pwd",cmd_pwd,"show current remote directory (same as 'cd' with no args)",{COMPL_NONE,COMPL_NONE}},
  {"q",cmd_quit,"logoff the server",{COMPL_NONE,COMPL_NONE}},
  {"queue",cmd_queue,"show the print queue",{COMPL_NONE,COMPL_NONE}},
  {"quit",cmd_quit,"logoff the server",{COMPL_NONE,COMPL_NONE}},
  {"readlink",cmd_readlink,"filename Do a UNIX extensions readlink call on a symlink",{COMPL_REMOTE,COMPL_REMOTE}},
  {"rd",cmd_rmdir,"<directory> remove a directory",{COMPL_NONE,COMPL_NONE}},
  {"recurse",cmd_recurse,"toggle directory recursion for mget and mput",{COMPL_NONE,COMPL_NONE}},
  {"reget",cmd_reget,"<remote name> [local name] get a file restarting at end of local file",{COMPL_REMOTE,COMPL_LOCAL}},
  {"rename",cmd_rename,"<src> <dest> rename some files",{COMPL_REMOTE,COMPL_REMOTE}},
  {"reput",cmd_reput,"<local name> [remote name] put a file restarting at end of remote file",{COMPL_LOCAL,COMPL_REMOTE}},
  {"rm",cmd_del,"<mask> delete all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"rmdir",cmd_rmdir,"<directory> remove a directory",{COMPL_REMOTE,COMPL_NONE}},
  {"showacls",cmd_showacls,"toggle if ACLs are shown or not",{COMPL_NONE,COMPL_NONE}},
  {"setea", cmd_setea, "<file name> <eaname> <eaval> Set an EA of a file",
   {COMPL_REMOTE, COMPL_LOCAL}},
  {"setmode",cmd_setmode,"<file name> <setmode string> change modes of file",{COMPL_REMOTE,COMPL_NONE}},
  {"scopy",cmd_scopy,"<src> <dest> server-side copy file",{COMPL_REMOTE,COMPL_REMOTE}},
  {"stat",cmd_stat,"<file name> Do a UNIX extensions stat call on a file",{COMPL_REMOTE,COMPL_NONE}},
  {"symlink",cmd_symlink,"<oldname> <newname> create a UNIX symlink",{COMPL_REMOTE,COMPL_REMOTE}},
  {"tar",cmd_tar,"tar <c|x>[IXFvbgNan] current directory to/from <file name>",{COMPL_NONE,COMPL_NONE}},
  {"tarmode",cmd_tarmode,"<full|inc|reset|noreset> tar's behaviour towards archive bits",{COMPL_NONE,COMPL_NONE}},
  {"timeout",cmd_timeout,"timeout <number> - set the per-operation timeout in seconds (default 20)",{COMPL_NONE,COMPL_NONE}},
  {"translate",cmd_translate,"toggle text translation for printing",{COMPL_NONE,COMPL_NONE}},
  {"unlock",cmd_unlock,"unlock <fnum> <hex-start> <hex-len> : remove a POSIX lock",{COMPL_REMOTE,COMPL_REMOTE}},
  {"volume",cmd_volume,"print the volume name",{COMPL_NONE,COMPL_NONE}},
  {"vuid",cmd_vuid,"change current vuid",{COMPL_NONE,COMPL_NONE}},
  {"wdel",cmd_wdel,"<attrib> <mask> wildcard delete all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"logon",cmd_logon,"establish new logon",{COMPL_NONE,COMPL_NONE}},
  {"listconnect",cmd_list_connect,"list open connections",{COMPL_NONE,COMPL_NONE}},
  {"showconnect",cmd_show_connect,"display the current active connection",{COMPL_NONE,COMPL_NONE}},
  {"tcon",cmd_tcon,"connect to a share" ,{COMPL_NONE,COMPL_NONE}},
  {"tdis",cmd_tdis,"disconnect from a share",{COMPL_NONE,COMPL_NONE}},
  {"tid",cmd_tid,"show or set the current tid (tree-id)",{COMPL_NONE,COMPL_NONE}},
  {"utimes", cmd_utimes,"<file name> <create_time> <access_time> <mod_time> "
	"<ctime> set times", {COMPL_REMOTE,COMPL_NONE}},
  {"logoff",cmd_logoff,"log off (close the session)",{COMPL_NONE,COMPL_NONE}},
  {"..",cmd_cd_oneup,"change the remote directory (up one level)",{COMPL_REMOTE,COMPL_NONE}},

  /* Yes, this must be here, see crh's comment above. */
  {"!",NULL,"run a shell command on the local system",{COMPL_NONE,COMPL_NONE}},
  {NULL,NULL,NULL,{COMPL_NONE,COMPL_NONE}}
};

/*******************************************************************
 Lookup a command string in the list of commands, including
 abbreviations.
******************************************************************/

static int process_tok(char *tok)
{
	size_t i = 0, matches = 0;
	size_t cmd=0;
	size_t tok_len = strlen(tok);

	while (commands[i].fn != NULL) {
		if (strequal(commands[i].name,tok)) {
			matches = 1;
			cmd = i;
			break;
		} else if (strnequal(commands[i].name, tok, tok_len)) {
			matches++;
			cmd = i;
		}
		i++;
	}

	if (matches == 0)
		return(-1);
	else if (matches == 1)
		return(cmd);
	else
		return(-2);
}

/****************************************************************************
 Help.
****************************************************************************/

static int cmd_help(void)
{
	TALLOC_CTX *ctx = talloc_tos();
	int i=0,j;
	char *buf;

	if (next_token_talloc(ctx, &cmd_ptr,&buf,NULL)) {
		if ((i = process_tok(buf)) >= 0)
			d_printf("HELP %s:\n\t%s\n\n",
				commands[i].name,commands[i].description);
	} else {
		while (commands[i].description) {
			for (j=0; commands[i].description && (j<5); j++) {
				d_printf("%-15s",commands[i].name);
				i++;
			}
			d_printf("\n");
		}
	}
	return 0;
}

/****************************************************************************
 Process a -c command string.
****************************************************************************/

static int process_command_string(const char *cmd_in)
{
	TALLOC_CTX *ctx = talloc_tos();
	char *cmd = talloc_strdup(ctx, cmd_in);
	int rc = 0;

	if (!cmd) {
		return 1;
	}
	/* establish the connection if not already */

	if (!cli) {
		NTSTATUS status;

		status = cli_cm_open(talloc_tos(), NULL,
				     desthost,
				     service, popt_get_cmdline_auth_info(),
				     smb_encrypt,
				     max_protocol,
				     have_ip ? &dest_ss : NULL, port,
				     name_type,
				     &cli);
		if (!NT_STATUS_IS_OK(status)) {
			return 1;
		}
		cli_set_timeout(cli, io_timeout*1000);
	}

	while (cmd[0] != '\0')    {
		char *line;
		char *p;
		char *tok;
		int i;

		if ((p = strchr_m(cmd, ';')) == 0) {
			line = cmd;
			cmd += strlen(cmd);
		} else {
			*p = '\0';
			line = cmd;
			cmd = p + 1;
		}

		/* and get the first part of the command */
		cmd_ptr = line;
		if (!next_token_talloc(ctx, &cmd_ptr,&tok,NULL)) {
			continue;
		}

		if ((i = process_tok(tok)) >= 0) {
			rc = commands[i].fn();
		} else if (i == -2) {
			d_printf("%s: command abbreviation ambiguous\n",tok);
		} else {
			d_printf("%s: command not found\n",tok);
		}
	}

	return rc;
}

#define MAX_COMPLETIONS 100

struct completion_remote {
	char *dirmask;
	char **matches;
	int count, samelen;
	const char *text;
	int len;
};

static NTSTATUS completion_remote_filter(const char *mnt,
				struct file_info *f,
				const char *mask,
				void *state)
{
	struct completion_remote *info = (struct completion_remote *)state;

	if (info->count >= MAX_COMPLETIONS - 1) {
		return NT_STATUS_OK;
	}
	if (strncmp(info->text, f->name, info->len) != 0) {
		return NT_STATUS_OK;
	}
	if (ISDOT(f->name) || ISDOTDOT(f->name)) {
		return NT_STATUS_OK;
	}

	if ((info->dirmask[0] == 0) && !(f->attr & FILE_ATTRIBUTE_DIRECTORY))
		info->matches[info->count] = SMB_STRDUP(f->name);
	else {
		TALLOC_CTX *ctx = talloc_stackframe();
		char *tmp;

		tmp = talloc_strdup(ctx,info->dirmask);
		if (!tmp) {
			TALLOC_FREE(ctx);
			return NT_STATUS_NO_MEMORY;
		}
		tmp = talloc_asprintf_append(tmp, "%s", f->name);
		if (!tmp) {
			TALLOC_FREE(ctx);
			return NT_STATUS_NO_MEMORY;
		}
		if (f->attr & FILE_ATTRIBUTE_DIRECTORY) {
			tmp = talloc_asprintf_append(tmp, "%s",
						     CLI_DIRSEP_STR);
		}
		if (!tmp) {
			TALLOC_FREE(ctx);
			return NT_STATUS_NO_MEMORY;
		}
		info->matches[info->count] = SMB_STRDUP(tmp);
		TALLOC_FREE(ctx);
	}
	if (info->matches[info->count] == NULL) {
		return NT_STATUS_OK;
	}
	if (f->attr & FILE_ATTRIBUTE_DIRECTORY) {
		smb_readline_ca_char(0);
	}
	if (info->count == 1) {
		info->samelen = strlen(info->matches[info->count]);
	} else {
		while (strncmp(info->matches[info->count],
			       info->matches[info->count-1],
			       info->samelen) != 0) {
			info->samelen--;
		}
	}
	info->count++;
	return NT_STATUS_OK;
}

static char **remote_completion(const char *text, int len)
{
	TALLOC_CTX *ctx = talloc_stackframe();
	char *dirmask = NULL;
	char *targetpath = NULL;
	struct cli_state *targetcli = NULL;
	int i;
	struct completion_remote info = { NULL, NULL, 1, 0, NULL, 0 };
	NTSTATUS status;

	/* can't have non-static initialisation on Sun CC, so do it
	   at run time here */
	info.samelen = len;
	info.text = text;
	info.len = len;

	info.matches = SMB_MALLOC_ARRAY(char *,MAX_COMPLETIONS);
	if (!info.matches) {
		TALLOC_FREE(ctx);
		return NULL;
	}

	/*
	 * We're leaving matches[0] free to fill it later with the text to
	 * display: Either the one single match or the longest common subset
	 * of the matches.
	 */
	info.matches[0] = NULL;
	info.count = 1;

	for (i = len-1; i >= 0; i--) {
		if ((text[i] == '/') || (text[i] == CLI_DIRSEP_CHAR)) {
			break;
		}
	}

	info.text = text+i+1;
	info.samelen = info.len = len-i-1;

	if (i > 0) {
		info.dirmask = SMB_MALLOC_ARRAY(char, i+2);
		if (!info.dirmask) {
			goto cleanup;
		}
		strncpy(info.dirmask, text, i+1);
		info.dirmask[i+1] = 0;
		dirmask = talloc_asprintf(ctx,
					"%s%*s*",
					client_get_cur_dir(),
					i-1,
					text);
	} else {
		info.dirmask = SMB_STRDUP("");
		if (!info.dirmask) {
			goto cleanup;
		}
		dirmask = talloc_asprintf(ctx,
					"%s*",
					client_get_cur_dir());
	}
	if (!dirmask) {
		goto cleanup;
	}
	dirmask = client_clean_name(ctx, dirmask);
	if (dirmask == NULL) {
		goto cleanup;
	}

	status = cli_resolve_path(ctx, "", popt_get_cmdline_auth_info(),
				cli, dirmask, &targetcli, &targetpath);
	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup;
	}
	status = cli_list(targetcli, targetpath, FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN,
			  completion_remote_filter, (void *)&info);
	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup;
	}

	if (info.count == 1) {
		/*
		 * No matches at all, NULL indicates there is nothing
		 */
		SAFE_FREE(info.matches[0]);
		SAFE_FREE(info.matches);
		TALLOC_FREE(ctx);
		return NULL;
	}

	if (info.count == 2) {
		/*
		 * Exactly one match in matches[1], indicate this is the one
		 * in matches[0].
		 */
		info.matches[0] = info.matches[1];
		info.matches[1] = NULL;
		info.count -= 1;
		TALLOC_FREE(ctx);
		return info.matches;
	}

	/*
	 * We got more than one possible match, set the result to the maximum
	 * common subset
	 */

	info.matches[0] = SMB_STRNDUP(info.matches[1], info.samelen);
	info.matches[info.count] = NULL;
	TALLOC_FREE(ctx);
	return info.matches;

cleanup:
	for (i = 0; i < info.count; i++) {
		SAFE_FREE(info.matches[i]);
	}
	SAFE_FREE(info.matches);
	SAFE_FREE(info.dirmask);
	TALLOC_FREE(ctx);
	return NULL;
}

static char **completion_fn(const char *text, int start, int end)
{
	smb_readline_ca_char(' ');

	if (start) {
		const char *buf, *sp;
		int i;
		char compl_type;

		buf = smb_readline_get_line_buffer();
		if (buf == NULL)
			return NULL;

		sp = strchr(buf, ' ');
		if (sp == NULL)
			return NULL;

		for (i = 0; commands[i].name; i++) {
			if ((strncmp(commands[i].name, buf, sp - buf) == 0) &&
			    (commands[i].name[sp - buf] == 0)) {
				break;
			}
		}
		if (commands[i].name == NULL)
			return NULL;

		while (*sp == ' ')
			sp++;

		if (sp == (buf + start))
			compl_type = commands[i].compl_args[0];
		else
			compl_type = commands[i].compl_args[1];

		if (compl_type == COMPL_REMOTE)
			return remote_completion(text, end - start);
		else /* fall back to local filename completion */
			return NULL;
	} else {
		char **matches;
		size_t i, len, samelen = 0, count=1;

		matches = SMB_MALLOC_ARRAY(char *, MAX_COMPLETIONS);
		if (!matches) {
			return NULL;
		}
		matches[0] = NULL;

		len = strlen(text);
		for (i=0;commands[i].fn && count < MAX_COMPLETIONS-1;i++) {
			if (strncmp(text, commands[i].name, len) == 0) {
				matches[count] = SMB_STRDUP(commands[i].name);
				if (!matches[count])
					goto cleanup;
				if (count == 1)
					samelen = strlen(matches[count]);
				else
					while (strncmp(matches[count], matches[count-1], samelen) != 0)
						samelen--;
				count++;
			}
		}

		switch (count) {
		case 0:	/* should never happen */
		case 1:
			goto cleanup;
		case 2:
			matches[0] = SMB_STRDUP(matches[1]);
			break;
		default:
			matches[0] = (char *)SMB_MALLOC(samelen+1);
			if (!matches[0])
				goto cleanup;
			strncpy(matches[0], matches[1], samelen);
			matches[0][samelen] = 0;
		}
		matches[count] = NULL;
		return matches;

cleanup:
		for (i = 0; i < count; i++)
			free(matches[i]);

		free(matches);
		return NULL;
	}
}

static bool finished;

/****************************************************************************
 Make sure we swallow keepalives during idle time.
****************************************************************************/

static void readline_callback(void)
{
	static time_t last_t;
	struct timespec now;
	time_t t;
	NTSTATUS status;
	unsigned char garbage[16];

	clock_gettime_mono(&now);
	t = now.tv_sec;

	if (t - last_t < 5)
		return;

	last_t = t;

	/* Ping the server to keep the connection alive using SMBecho. */
	memset(garbage, 0xf0, sizeof(garbage));
	status = cli_echo(cli, 1, data_blob_const(garbage, sizeof(garbage)));
	if (NT_STATUS_IS_OK(status) ||
			NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		/*
		 * Even if server returns NT_STATUS_INVALID_PARAMETER
		 * it still responded.
		 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=13007
		 */
		return;
	}

	if (!cli_state_is_connected(cli)) {
		DEBUG(0,("SMBecho failed (%s). The connection is "
			 "disconnected now\n", nt_errstr(status)));
		finished = true;
		smb_readline_done();
	}
}

/****************************************************************************
 Process commands on stdin.
****************************************************************************/

static int process_stdin(void)
{
	int rc = 0;

	if (!quiet) {
		d_printf("Try \"help\" to get a list of possible commands.\n");
	}

	while (!finished) {
		TALLOC_CTX *frame = talloc_stackframe();
		char *tok = NULL;
		char *the_prompt = NULL;
		char *line = NULL;
		int i;

		/* display a prompt */
		if (asprintf(&the_prompt, "smb: %s> ", client_get_cur_dir()) < 0) {
			TALLOC_FREE(frame);
			break;
		}
		line = smb_readline(the_prompt, readline_callback, completion_fn);
		SAFE_FREE(the_prompt);
		if (!line) {
			TALLOC_FREE(frame);
			break;
		}

		/* special case - first char is ! */
		if (*line == '!') {
			if (system(line + 1) == -1) {
				d_printf("system() command %s failed.\n",
					line+1);
			}
			SAFE_FREE(line);
			TALLOC_FREE(frame);
			continue;
		}

		/* and get the first part of the command */
		cmd_ptr = line;
		if (!next_token_talloc(frame, &cmd_ptr,&tok,NULL)) {
			TALLOC_FREE(frame);
			SAFE_FREE(line);
			continue;
		}

		if ((i = process_tok(tok)) >= 0) {
			rc = commands[i].fn();
		} else if (i == -2) {
			d_printf("%s: command abbreviation ambiguous\n",tok);
		} else {
			d_printf("%s: command not found\n",tok);
		}
		SAFE_FREE(line);
		TALLOC_FREE(frame);
	}
	return rc;
}

/****************************************************************************
 Process commands from the client.
****************************************************************************/

static int process(const char *base_directory)
{
	int rc = 0;
	NTSTATUS status;

	status = cli_cm_open(talloc_tos(), NULL,
			     desthost,
			     service, popt_get_cmdline_auth_info(),
			     smb_encrypt, max_protocol,
			     have_ip ? &dest_ss : NULL, port,
			     name_type, &cli);
	if (!NT_STATUS_IS_OK(status)) {
		return 1;
	}

	cli_set_timeout(cli, io_timeout*1000);

	if (base_directory && *base_directory) {
		rc = do_cd(base_directory);
		if (rc) {
			cli_shutdown(cli);
			return rc;
		}
	}

	if (cmdstr) {
		rc = process_command_string(cmdstr);
	} else {
		process_stdin();
	}

	cli_shutdown(cli);
	return rc;
}

/****************************************************************************
 Handle a -L query.
****************************************************************************/

static int do_host_query(const char *query_host)
{
	NTSTATUS status;

	status = cli_cm_open(talloc_tos(), NULL,
			     query_host,
			     "IPC$", popt_get_cmdline_auth_info(),
			     smb_encrypt, max_protocol,
			     have_ip ? &dest_ss : NULL, port,
			     name_type, &cli);
	if (!NT_STATUS_IS_OK(status)) {
		return 1;
	}

	cli_set_timeout(cli, io_timeout*1000);
	browse_host(true);

	/* Ensure that the host can do IPv4 */

	if (!interpret_addr(query_host)) {
		struct sockaddr_storage ss;
		if (interpret_string_addr(&ss, query_host, 0) &&
				(ss.ss_family != AF_INET)) {
			d_printf("%s is an IPv6 address -- no workgroup available\n",
				query_host);
			return 1;
		}
	}

	if (lp_client_min_protocol() > PROTOCOL_NT1) {
		d_printf("SMB1 disabled -- no workgroup available\n");
		goto out;
	}

	if (lp_disable_netbios()) {
		d_printf("NetBIOS over TCP disabled -- no workgroup available\n");
		goto out;
	}

	if (port != NBT_SMB_PORT ||
	    smbXcli_conn_protocol(cli->conn) > PROTOCOL_NT1)
	{
		int max_proto = MIN(max_protocol, PROTOCOL_NT1);

		/*
		 * Workgroups simply don't make sense over anything
		 * else but port 139 and SMB1.
		 */

		cli_shutdown(cli);
		d_printf("Reconnecting with SMB1 for workgroup listing.\n");
		status = cli_cm_open(talloc_tos(), NULL,
				     query_host,
				     "IPC$", popt_get_cmdline_auth_info(),
				     smb_encrypt, max_proto,
				     have_ip ? &dest_ss : NULL, NBT_SMB_PORT,
				     name_type, &cli);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("Unable to connect with SMB1 "
				 "-- no workgroup available\n");
			return 0;
		}
	}

	cli_set_timeout(cli, io_timeout*1000);
	list_servers(lp_workgroup());
out:
	cli_shutdown(cli);

	return(0);
}

/****************************************************************************
 Handle a tar operation.
****************************************************************************/

static int do_tar_op(const char *base_directory)
{
	struct tar *tar_ctx = tar_get_ctx();
	int ret = 0;

	/* do we already have a connection? */
	if (!cli) {
		NTSTATUS status;

		status = cli_cm_open(talloc_tos(), NULL,
				     desthost,
				     service, popt_get_cmdline_auth_info(),
				     smb_encrypt, max_protocol,
				     have_ip ? &dest_ss : NULL, port,
				     name_type, &cli);
		if (!NT_STATUS_IS_OK(status)) {
            ret = 1;
            goto out;
		}
		cli_set_timeout(cli, io_timeout*1000);
	}

	recurse = true;

	if (base_directory && *base_directory)  {
		ret = do_cd(base_directory);
		if (ret) {
            goto out_cli;
		}
	}

	ret = tar_process(tar_ctx);

 out_cli:
	cli_shutdown(cli);
 out:
	return ret;
}

/****************************************************************************
 Handle a message operation.
****************************************************************************/

static int do_message_op(struct user_auth_info *a_info)
{
	NTSTATUS status;

	if (lp_disable_netbios()) {
		d_printf("NetBIOS over TCP disabled.\n");
		return 1;
	}

	status = cli_connect_nb(desthost, have_ip ? &dest_ss : NULL,
				port ? port : NBT_SMB_PORT, name_type,
				lp_netbios_name(), SMB_SIGNING_DEFAULT, 0, &cli);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Connection to %s failed. Error %s\n", desthost, nt_errstr(status));
		return 1;
	}

	cli_set_timeout(cli, io_timeout*1000);
	send_message(get_cmdline_auth_info_username(a_info));
	cli_shutdown(cli);

	return 0;
}

/****************************************************************************
  main program
****************************************************************************/

int main(int argc,char *argv[])
{
	const char **const_argv = discard_const_p(const char *, argv);
	char *base_directory = NULL;
	int opt;
	char *query_host = NULL;
	bool message = false;
	static const char *new_name_resolve_order = NULL;
	poptContext pc;
	char *p;
	int rc = 0;
	bool tar_opt = false;
	bool service_opt = false;
	struct tar *tar_ctx = tar_get_ctx();

	struct poptOption long_options[] = {
		POPT_AUTOHELP

		{
			.longName   = "name-resolve",
			.shortName  = 'R',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &new_name_resolve_order,
			.val        = 'R',
			.descrip    = "Use these name resolution services only",
			.argDescrip = "NAME-RESOLVE-ORDER",
		},
		{
			.longName   = "message",
			.shortName  = 'M',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'M',
			.descrip    = "Send message",
			.argDescrip = "HOST",
		},
		{
			.longName   = "ip-address",
			.shortName  = 'I',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'I',
			.descrip    = "Use this IP to connect to",
			.argDescrip = "IP",
		},
		{
			.longName   = "stderr",
			.shortName  = 'E',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'E',
			.descrip    = "Write messages to stderr instead of stdout",
		},
		{
			.longName   = "list",
			.shortName  = 'L',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'L',
			.descrip    = "Get a list of shares available on a host",
			.argDescrip = "HOST",
		},
		{
			.longName   = "max-protocol",
			.shortName  = 'm',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'm',
			.descrip    = "Set the max protocol level",
			.argDescrip = "LEVEL",
		},
		{
			.longName   = "tar",
			.shortName  = 'T',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'T',
			.descrip    = "Command line tar",
			.argDescrip = "<c|x>IXFvgbNan",
		},
		{
			.longName   = "directory",
			.shortName  = 'D',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'D',
			.descrip    = "Start from directory",
			.argDescrip = "DIR",
		},
		{
			.longName   = "command",
			.shortName  = 'c',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &cmdstr,
			.val        = 'c',
			.descrip    = "Execute semicolon separated commands",
		},
		{
			.longName   = "send-buffer",
			.shortName  = 'b',
			.argInfo    = POPT_ARG_INT,
			.arg        = &io_bufsize,
			.val        = 'b',
			.descrip    = "Changes the transmit/send buffer",
			.argDescrip = "BYTES",
		},
		{
			.longName   = "timeout",
			.shortName  = 't',
			.argInfo    = POPT_ARG_INT,
			.arg        = &io_timeout,
			.val        = 'b',
			.descrip    = "Changes the per-operation timeout",
			.argDescrip = "SECONDS",
		},
		{
			.longName   = "port",
			.shortName  = 'p',
			.argInfo    = POPT_ARG_INT,
			.arg        = &port,
			.val        = 'p',
			.descrip    = "Port to connect to",
			.argDescrip = "PORT",
		},
		{
			.longName   = "grepable",
			.shortName  = 'g',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'g',
			.descrip    = "Produce grepable output",
		},
		{
			.longName   = "quiet",
			.shortName  = 'q',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'q',
			.descrip    = "Suppress help message",
		},
		{
			.longName   = "browse",
			.shortName  = 'B',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'B',
			.descrip    = "Browse SMB servers using DNS",
		},
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_TABLEEND
	};
	TALLOC_CTX *frame = talloc_stackframe();

	if (!client_set_cur_dir("\\")) {
		exit(ENOMEM);
	}

        /* set default debug level to 1 regardless of what smb.conf sets */
	setup_logging( "smbclient", DEBUG_DEFAULT_STDERR );
	smb_init_locale();

	lp_set_cmdline("log level", "1");

	popt_common_credentials_set_ignore_missing_conf();
	popt_common_credentials_set_delay_post();

	/* skip argv(0) */
	pc = poptGetContext("smbclient", argc, const_argv, long_options, 0);
	poptSetOtherOptionHelp(pc, "service <password>");

	while ((opt = poptGetNextOpt(pc)) != -1) {

		/*
		 * if the tar option has been called previously, now
		 * we need to eat out the leftovers
		 */
		/* I see no other way to keep things sane --SSS */
		if (tar_opt == true) {
			while (poptPeekArg(pc)) {
				poptGetArg(pc);
			}
			tar_opt = false;
		}

		/* if the service has not yet been specified lets see if it is available in the popt stack */
		if (!service_opt && poptPeekArg(pc)) {
			service = talloc_strdup(frame, poptGetArg(pc));
			if (!service) {
				exit(ENOMEM);
			}
			service_opt = true;
		}

		/* if the service has already been retrieved then check if we have also a password */
		if (service_opt
		    && (!get_cmdline_auth_info_got_pass(
				popt_get_cmdline_auth_info()))
		    && poptPeekArg(pc)) {
			set_cmdline_auth_info_password(
				popt_get_cmdline_auth_info(), poptGetArg(pc));
		}


		switch (opt) {
		case 'M':
			/* Messages are sent to NetBIOS name type 0x3
			 * (Messenger Service).  Make sure we default
			 * to port 139 instead of port 445. srl,crh
			 */
			name_type = 0x03;
			desthost = talloc_strdup(frame,poptGetOptArg(pc));
			if (!desthost) {
				exit(ENOMEM);
			}
			if( !port )
				port = NBT_SMB_PORT;
 			message = true;
 			break;
		case 'I':
			{
				if (!interpret_string_addr(&dest_ss, poptGetOptArg(pc), 0)) {
					exit(1);
				}
				have_ip = true;
				print_sockaddr(dest_ss_str, sizeof(dest_ss_str), &dest_ss);
			}
			break;
		case 'E':
			setup_logging("smbclient", DEBUG_STDERR );
			display_set_stderr();
			break;

		case 'L':
			query_host = talloc_strdup(frame, poptGetOptArg(pc));
			if (!query_host) {
				exit(ENOMEM);
			}
			break;
		case 'm':
			lp_set_cmdline("client max protocol", poptGetOptArg(pc));
			break;
		case 'T':
			/* We must use old option processing for this. Find the
			 * position of the -T option in the raw argv[]. */
			{
				int i;

				for (i = 1; i < argc; i++) {
					if (strncmp("-T", argv[i],2)==0)
						break;
				}
				i++;
				if (tar_parse_args(tar_ctx, poptGetOptArg(pc),
						   const_argv + i, argc - i)) {
					poptPrintUsage(pc, stderr, 0);
					exit(1);
				}
			}
			/* this must be the last option, mark we have parsed it so that we know we have */
			tar_opt = true;
			break;
		case 'D':
			base_directory = talloc_strdup(frame, poptGetOptArg(pc));
			if (!base_directory) {
				exit(ENOMEM);
			}
			break;
		case 'g':
			grepable=true;
			break;
		case 'q':
			quiet=true;
			break;
		case 'e':
			smb_encrypt=true;
			break;
		case 'B':
			return(do_smb_browse());

		}
	}

	/* We may still have some leftovers after the last popt option has been called */
	if (tar_opt == true) {
		while (poptPeekArg(pc)) {
			poptGetArg(pc);
		}
		tar_opt = false;
	}

	/* if the service has not yet been specified lets see if it is available in the popt stack */
	if (!service_opt && poptPeekArg(pc)) {
		service = talloc_strdup(frame,poptGetArg(pc));
		if (!service) {
			exit(ENOMEM);
		}
		service_opt = true;
	}

	/* if the service has already been retrieved then check if we have also a password */
	if (service_opt
	    && !get_cmdline_auth_info_got_pass(popt_get_cmdline_auth_info())
	    && poptPeekArg(pc)) {
		set_cmdline_auth_info_password(popt_get_cmdline_auth_info(),
					       poptGetArg(pc));
	}

	if (service_opt && service) {
		size_t len;

		/* Convert any '/' characters in the service name to '\' characters */
		string_replace(service, '/','\\');
		if (count_chars(service,'\\') < 3) {
			d_printf("\n%s: Not enough '\\' characters in service\n",service);
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
		/* Remove trailing slashes */
		len = strlen(service);
		while(len > 0 && service[len - 1] == '\\') {
			--len;
			service[len] = '\0';
		}
	}

	if (!init_names()) {
		fprintf(stderr, "init_names() failed\n");
		exit(1);
	}

	if(new_name_resolve_order)
		lp_set_cmdline("name resolve order", new_name_resolve_order);

	if (!tar_to_process(tar_ctx) && !query_host && !service && !message) {
		poptPrintUsage(pc, stderr, 0);
		exit(1);
	}

	poptFreeContext(pc);
	popt_burn_cmdline_password(argc, argv);

	DEBUG(3,("Client started (version %s).\n", samba_version_string()));

	/* Ensure we have a password (or equivalent). */
	popt_common_credentials_post();
	smb_encrypt = get_cmdline_auth_info_smb_encrypt(
			popt_get_cmdline_auth_info());

	max_protocol = lp_client_max_protocol();

	if (tar_to_process(tar_ctx)) {
		if (cmdstr)
			process_command_string(cmdstr);
		rc = do_tar_op(base_directory);
	} else if (query_host && *query_host) {
		char *qhost = query_host;
		char *slash;

		while (*qhost == '\\' || *qhost == '/')
			qhost++;

		if ((slash = strchr_m(qhost, '/'))
		    || (slash = strchr_m(qhost, '\\'))) {
			*slash = 0;
		}

		if ((p=strchr_m(qhost, '#'))) {
			*p = 0;
			p++;
			sscanf(p, "%x", &name_type);
		}

		rc = do_host_query(qhost);
	} else if (message) {
		rc = do_message_op(popt_get_cmdline_auth_info());
	} else if (process(base_directory)) {
		rc = 1;
	}

	popt_free_cmdline_auth_info();
	TALLOC_FREE(frame);
	return rc;
}
