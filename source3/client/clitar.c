/*
   Unix SMB/CIFS implementation.
   Tar backup command extension
   Copyright (C) Aurélien Aptel 2013

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

/**
 * # General overview of the tar extension
 *
 * All tar_xxx() functions work on a `struct tar` which store most of
 * the context of the backup process.
 *
 * The current tar context can be accessed via the global variable
 * `tar_ctx`. It's publicly exported as an opaque handle via
 * tar_get_ctx().
 *
 * A tar context is first configured through tar_parse_args() which
 * can be called from either the CLI (in client.c) or the interactive
 * session (via the cmd_tar() callback).
 *
 * Once the configuration is done (successfully), the context is ready
 * for processing and tar_to_process() returns true.
 *
 * The next step is to call tar_process() which dispatch the
 * processing to either tar_create() or tar_extract(), depending on
 * the context.
 *
 * ## Archive creation
 *
 * tar_create() creates an archive using the libarchive API then
 *
 * - iterates on the requested paths if the context is in inclusion
 *   mode with tar_create_from_list()
 *
 * - or iterates on the whole share (starting from the current dir) if
 *   in exclusion mode or if no specific path were requested
 *
 * The do_list() function from client.c is used to list recursively
 * the share. In particular it takes a DOS path mask (eg. \mydir\*)
 * and a callback function which will be called with each file name
 * and attributes. The tar callback function is get_file_callback().
 *
 * The callback function checks whether the file should be skipped
 * according the the configuration via tar_create_skip_path(). If it's
 * not skipped it's downloaded and written to the archive in
 * tar_get_file().
 *
 * ## Archive extraction
 *
 * tar_extract() opens the archive and iterates on each file in
 * it. For each file tar_extract_skip_path() checks whether it should
 * be skipped according to the config. If it's not skipped it's
 * uploaded on the server in tar_send_file().
 */

#include "includes.h"
#include "system/filesys.h"
#include "client/client_proto.h"
#include "client/clitar_proto.h"
#include "libsmb/libsmb.h"

#ifdef HAVE_LIBARCHIVE

#include <archive.h>
#include <archive_entry.h>

/* prepend module name and line number to debug messages */
#define DBG(a, b) (DEBUG(a, ("tar:%-4d ", __LINE__)), DEBUG(a, b))

/* preprocessor magic to stringify __LINE__ (int) */
#define STR1(x) #x
#define STR2(x) STR1(x)

/**
 * Number of byte in a block unit.
 */
#define TAR_BLOCK_UNIT 512

/**
 * Default tar block size in TAR_BLOCK_UNIT.
 */
#define TAR_DEFAULT_BLOCK_SIZE 20

/**
 * Maximum value for the blocksize field
 */
#define TAR_MAX_BLOCK_SIZE 0xffff

/**
 * Size of the buffer used when downloading a file
 */
#define TAR_CLI_READ_SIZE 0xff00

#define TAR_DO_LIST_ATTR (FILE_ATTRIBUTE_DIRECTORY \
			  | FILE_ATTRIBUTE_SYSTEM  \
			  | FILE_ATTRIBUTE_HIDDEN)


enum tar_operation {
	TAR_NO_OPERATION,
	TAR_CREATE,    /* c flag */
	TAR_EXTRACT,   /* x flag */
};

enum tar_selection {
	TAR_NO_SELECTION,
	TAR_INCLUDE,       /* I and F flag, default */
	TAR_EXCLUDE,       /* X flag */
};

enum {
	ATTR_UNSET,
	ATTR_SET,
};

struct tar {
	TALLOC_CTX *talloc_ctx;

	/* in state that needs/can be processed? */
	bool to_process;

	/* flags */
	struct tar_mode {
		enum tar_operation operation; /* create, extract */
		enum tar_selection selection; /* include, exclude */
		int blocksize;    /* size in TAR_BLOCK_UNIT of a tar file block */
		bool hidden;      /* backup hidden file? */
		bool system;      /* backup system file? */
		bool incremental; /* backup _only_ archived file? */
		bool reset;       /* unset archive bit? */
		bool dry;         /* don't write tar file? */
		bool regex;       /* XXX: never actually using regex... */
		bool verbose;     /* XXX: ignored */
	} mode;

	/* nb of bytes received */
	uint64_t total_size;

	/* path to tar archive name */
	char *tar_path;

	/* list of path to include or exclude */
	char **path_list;
	int path_list_size;

	/* archive handle */
	struct archive *archive;
};

/**
 * Global context imported in client.c when needed.
 *
 * Default options.
 */
struct tar tar_ctx = {
	.mode.selection   = TAR_INCLUDE,
	.mode.blocksize   = TAR_DEFAULT_BLOCK_SIZE,
	.mode.hidden      = true,
	.mode.system      = true,
	.mode.incremental = false,
	.mode.reset       = false,
	.mode.dry         = false,
	.mode.regex       = false,
	.mode.verbose     = false,
};

/* tar, local function */
static int tar_create(struct tar* t);
static int tar_create_from_list(struct tar *t);
static int tar_extract(struct tar *t);
static int tar_read_inclusion_file(struct tar *t, const char* filename);
static int tar_send_file(struct tar *t, struct archive_entry *entry);
static int tar_set_blocksize(struct tar *t, int size);
static int tar_set_newer_than(struct tar *t, const char *filename);
static NTSTATUS tar_add_selection_path(struct tar *t, const char *path);
static void tar_dump(struct tar *t);
static NTSTATUS tar_extract_skip_path(struct tar *t,
				      struct archive_entry *entry,
				      bool *_skip);
static TALLOC_CTX *tar_reset_mem_context(struct tar *t);
static void tar_free_mem_context(struct tar *t);
static NTSTATUS tar_create_skip_path(struct tar *t,
				     const char *fullpath,
				     const struct file_info *finfo,
				     bool *_skip);

static NTSTATUS tar_path_in_list(struct tar *t, const char *path,
				 bool reverse, bool *_is_in_list);

static int tar_get_file(struct tar *t,
			const char *full_dos_path,
			struct file_info *finfo);

static NTSTATUS get_file_callback(struct cli_state *cli,
				  struct file_info *finfo,
				  const char *dir);

/* utilities */
static char *fix_unix_path(char *path, bool removeprefix);
static NTSTATUS path_base_name(TALLOC_CTX *ctx, const char *path, char **_base);
static const char* skip_useless_char_in_path(const char *p);
static int make_remote_path(const char *full_path);
static int max_token (const char *str);
static NTSTATUS is_subpath(const char *sub, const char *full,
			   bool *_subpath_match);
static int set_remote_attr(const char *filename, uint16 new_attr, int mode);

/**
 * tar_get_ctx - retrieve global tar context handle
 */
struct tar *tar_get_ctx()
{
	return &tar_ctx;
}

/**
 * cmd_block - interactive command to change tar blocksize
 *
 * Read a size from the client command line and update the current
 * blocksize.
 */
int cmd_block(void)
{
	/* XXX: from client.c */
	const extern char *cmd_ptr;
	char *buf;
	int err = 0;
	bool ok;
	TALLOC_CTX *ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return 1;
	}

	ok = next_token_talloc(ctx, &cmd_ptr, &buf, NULL);
	if (!ok) {
		DBG(0, ("blocksize <n>\n"));
		err = 1;
		goto out;
	}

	ok = tar_set_blocksize(&tar_ctx, atoi(buf));
	if (ok) {
		DBG(0, ("invalid blocksize\n"));
		err = 1;
		goto out;
	}

	DBG(2, ("blocksize is now %d\n", tar_ctx.mode.blocksize));

out:
	talloc_free(ctx);
	return err;
}

/**
 * cmd_tarmode - interactive command to change tar behaviour
 *
 * Read one or more modes from the client command line and update the
 * current tar mode.
 */
int cmd_tarmode(void)
{
	const extern char *cmd_ptr;
	char *buf;
	int i;
	TALLOC_CTX *ctx;

	struct {
		const char *cmd;
		bool *p;
		bool value;
	} table[] = {
		{"full",      &tar_ctx.mode.incremental, false},
		{"inc",       &tar_ctx.mode.incremental, true },
		{"reset",     &tar_ctx.mode.reset,       true },
		{"noreset",   &tar_ctx.mode.reset,       false},
		{"system",    &tar_ctx.mode.system,      true },
		{"nosystem",  &tar_ctx.mode.system,      false},
		{"hidden",    &tar_ctx.mode.hidden,      true },
		{"nohidden",  &tar_ctx.mode.hidden,      false},
		{"verbose",   &tar_ctx.mode.verbose,     true },
		{"noquiet",   &tar_ctx.mode.verbose,     true },
		{"quiet",     &tar_ctx.mode.verbose,     false},
		{"noverbose", &tar_ctx.mode.verbose,     false},
	};

	ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return 1;
	}

	while (next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
		for (i = 0; i < ARRAY_SIZE(table); i++) {
			if (strequal(table[i].cmd, buf)) {
				*table[i].p = table[i].value;
				break;
			}
		}

		if (i == ARRAY_SIZE(table))
			DBG(0, ("tarmode: unrecognised option %s\n", buf));
	}

	DBG(0, ("tarmode is now %s, %s, %s, %s, %s\n",
				tar_ctx.mode.incremental ? "incremental" : "full",
				tar_ctx.mode.system      ? "system"      : "nosystem",
				tar_ctx.mode.hidden      ? "hidden"      : "nohidden",
				tar_ctx.mode.reset       ? "reset"       : "noreset",
				tar_ctx.mode.verbose     ? "verbose"     : "quiet"));

	talloc_free(ctx);
	return 0;
}

/**
 * cmd_tar - interactive command to start a tar backup/restoration
 *
 * Check presence of argument, parse them and handle the request.
 */
int cmd_tar(void)
{
	const extern char *cmd_ptr;
	const char *flag;
	const char **val;
	char *buf;
	int maxtok = max_token(cmd_ptr);
	int i = 0;
	int err = 0;
	bool ok;
	int rc;
	TALLOC_CTX *ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return 1;
	}

	ok = next_token_talloc(ctx, &cmd_ptr, &buf, NULL);
	if (!ok) {
		DBG(0, ("tar <c|x>[IXFbganN] [options] <tar file> [path list]\n"));
		err = 1;
		goto out;
	}

	flag = buf;
	val = talloc_array(ctx, const char *, maxtok);
	if (val == NULL) {
		err = 1;
		goto out;
	}

	while (next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
		val[i++] = buf;
	}

	rc = tar_parse_args(&tar_ctx, flag, val, i);
	if (rc != 0) {
		DBG(0, ("parse_args failed\n"));
		err = 1;
		goto out;
	}

	rc = tar_process(&tar_ctx);
	if (rc != 0) {
		DBG(0, ("tar_process failed\n"));
		err = 1;
		goto out;
	}

out:
	talloc_free(ctx);
	return err;
}

/**
 * cmd_setmode - interactive command to set DOS attributes
 *
 * Read a filename and mode from the client command line and update
 * the file DOS attributes.
 */
int cmd_setmode(void)
{
	const extern char *cmd_ptr;
	char *buf;
	char *fname = NULL;
	uint16 attr[2] = {0};
	int mode = ATTR_SET;
	int err = 0;
	bool ok;
	TALLOC_CTX *ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return 1;
	}

	ok = next_token_talloc(ctx, &cmd_ptr, &buf, NULL);
	if (!ok) {
		DBG(0, ("setmode <filename> <[+|-]rsha>\n"));
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
				DBG(0, ("setmode <filename> <perm=[+|-]rsha>\n"));
				err = 1;
				goto out;
			}
		}
	}

	if (attr[ATTR_SET] == 0 && attr[ATTR_UNSET] == 0) {
		DBG(0, ("setmode <filename> <[+|-]rsha>\n"));
		err = 1;
		goto out;
	}

	DBG(2, ("perm set %d %d\n", attr[ATTR_SET], attr[ATTR_UNSET]));

	/* ignore return value: server might not store DOS attributes */
	set_remote_attr(fname, attr[ATTR_SET], ATTR_SET);
	set_remote_attr(fname, attr[ATTR_UNSET], ATTR_UNSET);
out:
	talloc_free(ctx);
	return err;
}

/**
 * tar_parse_args - parse and set tar command line arguments
 * @flag: string pointing to tar options
 * @val: number of tar arguments
 * @valsize: table of arguments after the flags (number of element in val)
 *
 * tar arguments work in a weird way. For each flag f that takes a
 * value v, the user is supposed to type:
 *
 * on the CLI:
 *   -Tf1f2f3 v1 v2 v3 TARFILE PATHS...
 *
 * in the interactive session:
 *   tar f1f2f3 v1 v2 v3 TARFILE PATHS...
 *
 * @flag has only flags (eg. "f1f2f3") and @val has the arguments
 * (values) following them (eg. ["v1", "v2", "v3", "TARFILE", "PATH1",
 * "PATH2"]).
 *
 * There are only 2 flags that take an arg: b and N. The other flags
 * just change the semantic of PATH or TARFILE.
 *
 * PATH can be a list of included/excluded paths, the path to a file
 * containing a list of included/excluded paths to use (F flag). If no
 * PATH is provided, the whole share is used (/).
 */
int tar_parse_args(struct tar* t,
		   const char *flag,
		   const char **val,
		   int valsize)
{
	TALLOC_CTX *ctx;
	bool do_read_list = false;
	/* index of next value to use */
	int ival = 0;
	int rc;

	if (t == NULL) {
		DBG(0, ("Invalid tar context\n"));
		return 1;
	}

	ctx = tar_reset_mem_context(t);
	if (ctx == NULL) {
		return 1;
	}
	/*
	 * Reset back some options - could be from interactive version
	 * all other modes are left as they are
	 */
	t->mode.operation = TAR_NO_OPERATION;
	t->mode.selection = TAR_NO_SELECTION;
	t->mode.dry = false;
	t->to_process = false;
	t->total_size = 0;

	while (flag[0] != '\0') {
		switch(flag[0]) {
		/* operation */
		case 'c':
			if (t->mode.operation != TAR_NO_OPERATION) {
				printf("Tar must be followed by only one of c or x.\n");
				return 1;
			}
			t->mode.operation = TAR_CREATE;
			break;
		case 'x':
			if (t->mode.operation != TAR_NO_OPERATION) {
				printf("Tar must be followed by only one of c or x.\n");
				return 1;
			}
			t->mode.operation = TAR_EXTRACT;
			break;

			/* selection  */
		case 'I':
			if (t->mode.selection != TAR_NO_SELECTION) {
				DBG(0,("Only one of I,X,F must be specified\n"));
				return 1;
			}
			t->mode.selection = TAR_INCLUDE;
			break;
		case 'X':
			if (t->mode.selection != TAR_NO_SELECTION) {
				DBG(0,("Only one of I,X,F must be specified\n"));
				return 1;
			}
			t->mode.selection = TAR_EXCLUDE;
			break;
		case 'F':
			if (t->mode.selection != TAR_NO_SELECTION) {
				DBG(0,("Only one of I,X,F must be specified\n"));
				return 1;
			}
			t->mode.selection = TAR_INCLUDE;
			do_read_list = true;
			break;

			/* blocksize */
		case 'b':
			if (ival >= valsize) {
				DBG(0, ("Option b must be followed by a blocksize\n"));
				return 1;
			}

			if (tar_set_blocksize(t, atoi(val[ival]))) {
				DBG(0, ("Option b must be followed by a valid blocksize\n"));
				return 1;
			}

			ival++;
			break;

			/* incremental mode */
		case 'g':
			t->mode.incremental = true;
			break;

			/* newer than */
		case 'N':
			if (ival >= valsize) {
				DBG(0, ("Option N must be followed by valid file name\n"));
				return 1;
			}

			if (tar_set_newer_than(t, val[ival])) {
				DBG(0,("Error setting newer-than time\n"));
				return 1;
			}

			ival++;
			break;

			/* reset mode */
		case 'a':
			t->mode.reset = true;
			break;

			/* verbose */
		case 'q':
			t->mode.verbose = true;
			break;

			/* regex match  */
		case 'r':
			t->mode.regex = true;
			break;

			/* dry run mode */
		case 'n':
			if (t->mode.operation != TAR_CREATE) {
				DBG(0, ("n is only meaningful when creating a tar-file\n"));
				return 1;
			}

			t->mode.dry = true;
			DBG(0, ("dry_run set\n"));
			break;

		default:
			DBG(0,("Unknown tar option\n"));
			return 1;
		}

		flag++;
	}

	/* no selection given? default selection is include */
	if (t->mode.selection == TAR_NO_SELECTION) {
		t->mode.selection = TAR_INCLUDE;
	}

	if (valsize - ival < 1) {
		DBG(0, ("No tar file given.\n"));
		return 1;
	}

	/* handle TARFILE */
	t->tar_path = talloc_strdup(ctx, val[ival]);
	if (t->tar_path == NULL) {
		return 1;
	}
	ival++;

	/*
	 * Make sure that dbf points to stderr if we are using stdout for
	 * tar output
	 */
	if (t->mode.operation == TAR_CREATE && strequal(t->tar_path, "-")) {
		setup_logging("smbclient", DEBUG_STDERR);
	}

	/* handle PATHs... */

	/* flag F -> read file list */
	if (do_read_list) {
		if (valsize - ival != 1) {
			DBG(0,("Option F must be followed by exactly one filename.\n"));
			return 1;
		}

		rc = tar_read_inclusion_file(t, val[ival]);
		if (rc != 0) {
			return 1;
		}
		ival++;
	/* otherwise store all the PATHs on the command line */
	} else {
		int i;
		for (i = ival; i < valsize; i++) {
			NTSTATUS status;
			status = tar_add_selection_path(t, val[i]);
			if (!NT_STATUS_IS_OK(status)) {
				return 1;
			}
		}
	}

	t->to_process = true;
	tar_dump(t);
	return 0;
}

/**
 * tar_process - start processing archive
 *
 * The talloc context of the fields is freed at the end of the call.
 */
int tar_process(struct tar *t)
{
	int rc = 0;

	if (t == NULL) {
		DBG(0, ("Invalid tar context\n"));
		return 1;
	}

	switch(t->mode.operation) {
	case TAR_EXTRACT:
		rc = tar_extract(t);
		break;
	case TAR_CREATE:
		rc = tar_create(t);
		break;
	default:
		DBG(0, ("Invalid tar state\n"));
		rc = 1;
	}

	t->to_process = false;
	tar_free_mem_context(t);
	DBG(5, ("tar_process done, err = %d\n", rc));
	return rc;
}

/**
 * tar_create - create archive and fetch files
 */
static int tar_create(struct tar* t)
{
	int r;
	int err = 0;
	NTSTATUS status;
	const char *mask;
	TALLOC_CTX *ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return 1;
	}

	t->archive = archive_write_new();

	if (!t->mode.dry) {
		const int bsize = t->mode.blocksize * TAR_BLOCK_UNIT;
		r = archive_write_set_bytes_per_block(t->archive, bsize);
		if (r != ARCHIVE_OK) {
			DBG(0, ("Can't use a block size of %d bytes", bsize));
			err = 1;
			goto out;
		}

		/*
		 * Use PAX restricted format which is not the most
		 * conservative choice but has useful extensions and is widely
		 * supported
		 */
		r = archive_write_set_format_pax_restricted(t->archive);
		if (r != ARCHIVE_OK) {
			DBG(0, ("Can't use pax restricted format: %s\n",
						archive_error_string(t->archive)));
			err = 1;
			goto out;
		}

		if (strequal(t->tar_path, "-")) {
			r = archive_write_open_fd(t->archive, STDOUT_FILENO);
		} else {
			r = archive_write_open_filename(t->archive, t->tar_path);
		}

		if (r != ARCHIVE_OK) {
			DBG(0, ("Can't open %s: %s\n", t->tar_path,
						archive_error_string(t->archive)));
			err = 1;
			goto out_close;
		}
	}

	/*
	 * In inclusion mode, iterate on the inclusion list
	 */
	if (t->mode.selection == TAR_INCLUDE && t->path_list_size > 0) {
		if (tar_create_from_list(t)) {
			err = 1;
			goto out_close;
		}
	} else {
		mask = talloc_asprintf(ctx, "%s\\*", client_get_cur_dir());
		if (mask == NULL) {
			err = 1;
			goto out_close;
		}
		DBG(5, ("tar_process do_list with mask: %s\n", mask));
		status = do_list(mask, TAR_DO_LIST_ATTR, get_file_callback, false, true);
		if (!NT_STATUS_IS_OK(status)) {
			DBG(0, ("do_list fail %s\n", nt_errstr(status)));
			err = 1;
			goto out_close;
		}
	}

out_close:
	DBG(0, ("Total bytes received: %" PRIu64 "\n", t->total_size));

	if (!t->mode.dry) {
		r = archive_write_close(t->archive);
		if (r != ARCHIVE_OK) {
			DBG(0, ("Fatal: %s\n", archive_error_string(t->archive)));
			err = 1;
			goto out;
		}
	}
out:
	archive_write_free(t->archive);
	talloc_free(ctx);
	return err;
}

/**
 * tar_create_from_list - fetch from path list in include mode
 */
static int tar_create_from_list(struct tar *t)
{
	int err = 0;
	NTSTATUS status;
	char *base;
	const char *path, *mask, *start_dir;
	int i;
	TALLOC_CTX *ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return 1;
	}

	start_dir = talloc_strdup(ctx, client_get_cur_dir());
	if (start_dir == NULL) {
		err = 1;
		goto out;
	}

	for (i = 0; i < t->path_list_size; i++) {
		path = t->path_list[i];
		base = NULL;
		status = path_base_name(ctx, path, &base);
		if (!NT_STATUS_IS_OK(status)) {
			err = 1;
			goto out;
		}
		mask = talloc_asprintf(ctx, "%s\\%s",
				       client_get_cur_dir(), path);
		if (mask == NULL) {
			err = 1;
			goto out;
		}

		DBG(5, ("incl. path='%s', base='%s', mask='%s'\n",
					path, base ? base : "NULL", mask));

		if (base != NULL) {
			base = talloc_asprintf(ctx, "%s%s\\",
					       client_get_cur_dir(), base);
			if (base == NULL) {
				err = 1;
				goto out;
			}
			DBG(5, ("cd '%s' before do_list\n", base));
			client_set_cur_dir(base);
		}
		status = do_list(mask, TAR_DO_LIST_ATTR, get_file_callback, false, true);
		if (base != NULL) {
			client_set_cur_dir(start_dir);
		}
		if (!NT_STATUS_IS_OK(status)) {
			DBG(0, ("do_list failed on %s (%s)\n", path, nt_errstr(status)));
			err = 1;
			goto out;
		}
	}

out:
	talloc_free(ctx);
	return err;
}

/**
 * get_file_callback - do_list callback
 *
 * Callback for client.c do_list(). Called for each file found on the
 * share matching do_list mask. Recursively call do_list() with itself
 * as callback when the current file is a directory.
 */
static NTSTATUS get_file_callback(struct cli_state *cli,
				  struct file_info *finfo,
				  const char *dir)
{
	NTSTATUS status = NT_STATUS_OK;
	char *remote_name;
	const char *initial_dir = client_get_cur_dir();
	bool skip = false;
	int rc;
	TALLOC_CTX *ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	remote_name = talloc_asprintf(ctx, "%s%s", initial_dir, finfo->name);
	if (remote_name == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	if (strequal(finfo->name, "..") || strequal(finfo->name, ".")) {
		goto out;
	}

	status = tar_create_skip_path(&tar_ctx, remote_name, finfo, &skip);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (skip) {
		DBG(5, ("--- %s\n", remote_name));
		status = NT_STATUS_OK;
		goto out;
	}

	if (finfo->mode & FILE_ATTRIBUTE_DIRECTORY) {
		char *old_dir;
		char *new_dir;
		char *mask;

		old_dir = talloc_strdup(ctx, initial_dir);
		new_dir = talloc_asprintf(ctx, "%s%s\\",
					  initial_dir, finfo->name);
		if ((old_dir == NULL) || (new_dir == NULL)) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
		mask = talloc_asprintf(ctx, "%s*", new_dir);
		if (mask == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		rc = tar_get_file(&tar_ctx, remote_name, finfo);
		if (rc != 0) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}

		client_set_cur_dir(new_dir);
		do_list(mask, TAR_DO_LIST_ATTR, get_file_callback, false, true);
		client_set_cur_dir(old_dir);
	} else {
		rc = tar_get_file(&tar_ctx, remote_name, finfo);
		if (rc != 0) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	}

out:
	talloc_free(ctx);
	return status;
}

/**
 * tar_get_file - fetch a remote file to the local archive
 * @full_dos_path: path to the file to fetch
 * @finfo: attributes of the file to fetch
 */
static int tar_get_file(struct tar *t,
			const char *full_dos_path,
			struct file_info *finfo)
{
	extern struct cli_state *cli;
	NTSTATUS status;
	struct archive_entry *entry;
	char *full_unix_path;
	char buf[TAR_CLI_READ_SIZE];
	size_t len;
	uint64_t off = 0;
	uint16_t remote_fd = (uint16_t)-1;
	int err = 0, r;
	const bool isdir = finfo->mode & FILE_ATTRIBUTE_DIRECTORY;
	TALLOC_CTX *ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return 1;
	}

	DBG(5, ("+++ %s\n", full_dos_path));

	t->total_size += finfo->size;

	if (t->mode.dry) {
		goto out;
	}

	if (t->mode.reset) {
		/* ignore return value: server might not store DOS attributes */
		set_remote_attr(full_dos_path, FILE_ATTRIBUTE_ARCHIVE, ATTR_UNSET);
	}

	full_unix_path = talloc_asprintf(ctx, ".%s", full_dos_path);
	if (full_unix_path == NULL) {
		err = 1;
		goto out;
	}
	string_replace(full_unix_path, '\\', '/');
	entry = archive_entry_new();
	archive_entry_copy_pathname(entry, full_unix_path);
	archive_entry_set_filetype(entry, isdir ? AE_IFDIR : AE_IFREG);
	archive_entry_set_atime(entry,
			finfo->atime_ts.tv_sec,
			finfo->atime_ts.tv_nsec);
	archive_entry_set_mtime(entry,
			finfo->mtime_ts.tv_sec,
			finfo->mtime_ts.tv_nsec);
	archive_entry_set_ctime(entry,
			finfo->ctime_ts.tv_sec,
			finfo->ctime_ts.tv_nsec);
	archive_entry_set_perm(entry, isdir ? 0755 : 0644);
	/*
	 * check if we can safely cast unsigned file size to libarchive
	 * signed size. Very unlikely problem (>9 exabyte file)
	 */
	if (finfo->size > INT64_MAX) {
		DBG(0, ("Remote file %s too big\n", full_dos_path));
		goto out_entry;
	}

	archive_entry_set_size(entry, (int64_t)finfo->size);

	r = archive_write_header(t->archive, entry);
	if (r != ARCHIVE_OK) {
		DBG(0, ("Fatal: %s\n", archive_error_string(t->archive)));
		err = 1;
		goto out_entry;
	}

	if (isdir) {
		DBG(5, ("get_file skip dir %s\n", full_dos_path));
		goto out_entry;
	}

	status = cli_open(cli, full_dos_path, O_RDONLY, DENY_NONE, &remote_fd);
	if (!NT_STATUS_IS_OK(status)) {
		DBG(0,("%s opening remote file %s\n",
					nt_errstr(status), full_dos_path));
		goto out_entry;
	}

	do {
		status = cli_read(cli, remote_fd, buf, off, sizeof(buf), &len);
		if (!NT_STATUS_IS_OK(status)) {
			DBG(0,("Error reading file %s : %s\n",
						full_dos_path, nt_errstr(status)));
			err = 1;
			goto out_close;
		}

		off += len;

		r = archive_write_data(t->archive, buf, len);
		if (r < 0) {
			DBG(0, ("Fatal: %s\n", archive_error_string(t->archive)));
			err = 1;
			goto out_close;
		}

	} while (off < finfo->size);

out_close:
	cli_close(cli, remote_fd);

out_entry:
	archive_entry_free(entry);

out:
	talloc_free(ctx);
	return err;
}

/**
 * tar_extract - open archive and send files.
 */
static int tar_extract(struct tar *t)
{
	int err = 0;
	int r;
	struct archive_entry *entry;
	const size_t bsize = t->mode.blocksize * TAR_BLOCK_UNIT;
	int rc;

	t->archive = archive_read_new();
	archive_read_support_format_all(t->archive);
	archive_read_support_filter_all(t->archive);

	if (strequal(t->tar_path, "-")) {
		r = archive_read_open_fd(t->archive, STDIN_FILENO, bsize);
	} else {
		r = archive_read_open_filename(t->archive, t->tar_path, bsize);
	}

	if (r != ARCHIVE_OK) {
		DBG(0, ("Can't open %s : %s\n", t->tar_path,
					archive_error_string(t->archive)));
		err = 1;
		goto out;
	}

	for (;;) {
		NTSTATUS status;
		bool skip;
		r = archive_read_next_header(t->archive, &entry);
		if (r == ARCHIVE_EOF) {
			break;
		}
		if (r == ARCHIVE_WARN) {
			DBG(0, ("Warning: %s\n", archive_error_string(t->archive)));
		}
		if (r == ARCHIVE_FATAL) {
			DBG(0, ("Fatal: %s\n", archive_error_string(t->archive)));
			err = 1;
			goto out;
		}

		status = tar_extract_skip_path(t, entry, &skip);
		if (!NT_STATUS_IS_OK(status)) {
			err = 1;
			goto out;
		}
		if (skip) {
			DBG(5, ("--- %s\n", archive_entry_pathname(entry)));
			continue;
		}

		DBG(5, ("+++ %s\n", archive_entry_pathname(entry)));

		rc = tar_send_file(t, entry);
		if (rc != 0) {
			err = 1;
			goto out;
		}
	}

out:
	r = archive_read_free(t->archive);
	if (r != ARCHIVE_OK) {
		DBG(0, ("Can't close %s : %s\n", t->tar_path,
					archive_error_string(t->archive)));
		err = 1;
	}
	return err;
}

/**
 * tar_send_file - send @entry to the remote server
 * @entry: current archive entry
 *
 * Handle the creation of the parent directories and transfer the
 * entry to a new remote file.
 */
static int tar_send_file(struct tar *t, struct archive_entry *entry)
{
	extern struct cli_state *cli;
	char *dos_path;
	char *full_path;
	NTSTATUS status;
	uint16_t remote_fd = (uint16_t) -1;
	int err = 0;
	int flags = O_RDWR | O_CREAT | O_TRUNC;
	mode_t mode = archive_entry_filetype(entry);
	int rc;
	TALLOC_CTX *ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return 1;
	}

	dos_path = talloc_strdup(ctx, archive_entry_pathname(entry));
	if (dos_path == NULL) {
		err = 1;
		goto out;
	}
	fix_unix_path(dos_path, true);

	full_path = talloc_strdup(ctx, client_get_cur_dir());
	if (full_path == NULL) {
		err = 1;
		goto out;
	}
	full_path = talloc_strdup_append(full_path, dos_path);
	if (full_path == NULL) {
		err = 1;
		goto out;
	}

	if (mode != AE_IFREG && mode != AE_IFDIR) {
		DBG(0, ("Skipping non-dir & non-regular file %s\n", full_path));
		goto out;
	}

	rc = make_remote_path(full_path);
	if (rc != 0) {
		err = 1;
		goto out;
	}

	if (mode == AE_IFDIR) {
		goto out;
	}

	status = cli_open(cli, full_path, flags, DENY_NONE, &remote_fd);
	if (!NT_STATUS_IS_OK(status)) {
		DBG(0, ("Error opening remote file %s: %s\n",
					full_path, nt_errstr(status)));
		err = 1;
		goto out;
	}

	for (;;) {
		const void *buf;
		size_t len;
		off_t off;
		int r;

		r = archive_read_data_block(t->archive, &buf, &len, &off);
		if (r == ARCHIVE_EOF) {
			break;
		}
		if (r == ARCHIVE_WARN) {
			DBG(0, ("Warning: %s\n", archive_error_string(t->archive)));
		}
		if (r == ARCHIVE_FATAL) {
			DBG(0, ("Fatal: %s\n", archive_error_string(t->archive)));
			err = 1;
			goto close_out;
		}

		status = cli_writeall(cli, remote_fd, 0, buf, off, len, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			DBG(0, ("Error writing remote file %s: %s\n",
						full_path, nt_errstr(status)));
			err = 1;
			goto close_out;
		}
	}

close_out:
	status = cli_close(cli, remote_fd);
	if (!NT_STATUS_IS_OK(status)) {
		DBG(0, ("Error losing remote file %s: %s\n",
					full_path, nt_errstr(status)));
		err = 1;
	}

out:
	talloc_free(ctx);
	return err;
}

/**
 * tar_add_selection_path - add a path to the path list
 * @path: path to add
 */
static NTSTATUS tar_add_selection_path(struct tar *t, const char *path)
{
	const char **list;
	TALLOC_CTX *ctx = t->talloc_ctx;
	if (!t->path_list) {
		t->path_list = str_list_make_empty(ctx);
		if (t->path_list == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		t->path_list_size = 0;
	}

	/* cast to silence gcc const-qual warning */
	list = str_list_add((void *)t->path_list, path);
	if (list == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	t->path_list = discard_const_p(char *, list);
	t->path_list_size++;
	fix_unix_path(t->path_list[t->path_list_size - 1], true);

	return NT_STATUS_OK;
}

/**
 * tar_set_blocksize - set block size in TAR_BLOCK_UNIT
 */
static int tar_set_blocksize(struct tar *t, int size)
{
	if (size <= 0 || size > TAR_MAX_BLOCK_SIZE) {
		return 1;
	}

	t->mode.blocksize = size;

	return 0;
}

/**
 * tar_set_newer_than - set date threshold of saved files
 * @filename: local path to a file
 *
 * Only files newer than the modification time of @filename will be
 * saved.
 *
 * Note: this function set the global variable newer_than from
 * client.c. Thus the time is not a field of the tar structure. See
 * cmd_newer() to change its value from an interactive session.
 */
static int tar_set_newer_than(struct tar *t, const char *filename)
{
	extern time_t newer_than;
	SMB_STRUCT_STAT stbuf;
	int rc;

	rc = sys_stat(filename, &stbuf, false);
	if (rc != 0) {
		DBG(0, ("Error setting newer-than time\n"));
		return 1;
	}

	newer_than = convert_timespec_to_time_t(stbuf.st_ex_mtime);
	DBG(1, ("Getting files newer than %s\n", time_to_asc(newer_than)));
	return 0;
}

/**
 * tar_read_inclusion_file - set path list from file
 * @filename: path to the list file
 *
 * Read and add each line of @filename to the path list.
 */
static int tar_read_inclusion_file(struct tar *t, const char* filename)
{
	char *line;
	int err = 0;
	int fd;
	TALLOC_CTX *ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return 1;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		DBG(0, ("Can't open inclusion file '%s': %s\n", filename, strerror(errno)));
		err = 1;
		goto out;
	}

	for (line = afdgets(fd, ctx, 0);
			line != NULL;
			line = afdgets(fd, ctx, 0)) {
		NTSTATUS status;
		status = tar_add_selection_path(t, line);
		if (!NT_STATUS_IS_OK(status)) {
			err = 1;
			goto out;
		}
	}

	close(fd);

out:
	talloc_free(ctx);
	return err;
}

/**
 * tar_path_in_list - check whether @path is in the path list
 * @path: path to find
 * @reverse: when true also try to find path list element in @path
 * @_is_in_list: set if @path is in the path list
 *
 * Look at each path of the path list and set @_is_in_list if @path is a
 * subpath of one of them.
 *
 * If you want /path to be in the path list (path/a/, path/b/) set
 * @reverse to true to try to match the other way around.
 */
static NTSTATUS tar_path_in_list(struct tar *t, const char *path,
				 bool reverse, bool *_is_in_list)
{
	int i;
	const char *p;
	const char *pattern;

	if (path == NULL || path[0] == '\0') {
		*_is_in_list = false;
		return NT_STATUS_OK;
	}

	p = skip_useless_char_in_path(path);

	for (i = 0; i < t->path_list_size; i++) {
		bool is_in_list;
		NTSTATUS status;

		pattern = skip_useless_char_in_path(t->path_list[i]);
		status = is_subpath(p, pattern, &is_in_list);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		if (reverse && !is_in_list) {
			status = is_subpath(pattern, p, &is_in_list);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
		if (is_in_list) {
			*_is_in_list = true;
			return NT_STATUS_OK;
		}
	}

	*_is_in_list = false;
	return NT_STATUS_OK;
}

/**
 * tar_extract_skip_path - check if @entry should be skipped
 * @entry: current tar entry
 * @_skip: set true if path should be skipped, otherwise false
 *
 * Skip predicate for tar extraction (archive to server) only.
 */
static NTSTATUS tar_extract_skip_path(struct tar *t,
				      struct archive_entry *entry,
				      bool *_skip)
{
	const char *fullpath = archive_entry_pathname(entry);
	bool in = true;

	if (t->path_list_size <= 0) {
		*_skip = false;
		return NT_STATUS_OK;
	}

	if (t->mode.regex) {
		in = mask_match_list(fullpath, t->path_list, t->path_list_size, true);
	} else {
		NTSTATUS status = tar_path_in_list(t, fullpath, false, &in);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (t->mode.selection == TAR_EXCLUDE) {
		*_skip = in;
	} else {
		*_skip = !in;
	}

	return NT_STATUS_OK;
}

/**
 * tar_create_skip_path - check if @fullpath shoud be skipped
 * @fullpath: full remote path of the current file
 * @finfo: remote file attributes
 * @_skip: returned skip not
 *
 * Skip predicate for tar creation (server to archive) only.
 */
static NTSTATUS tar_create_skip_path(struct tar *t,
				     const char *fullpath,
				     const struct file_info *finfo,
				     bool *_skip)
{
	/* syntaxic sugar */
	const mode_t mode = finfo->mode;
	const bool isdir = mode & FILE_ATTRIBUTE_DIRECTORY;
	const bool exclude = t->mode.selection == TAR_EXCLUDE;
	bool in = true;

	if (!isdir) {

		/* 1. if we dont want X and we have X, skip */
		if (!t->mode.system && (mode & FILE_ATTRIBUTE_SYSTEM)) {
			*_skip = true;
			return NT_STATUS_OK;
		}

		if (!t->mode.hidden && (mode & FILE_ATTRIBUTE_HIDDEN)) {
			*_skip = true;
			return NT_STATUS_OK;
		}

		/* 2. if we only want archive and it's not, skip */

		if (t->mode.incremental && !(mode & FILE_ATTRIBUTE_ARCHIVE)) {
			*_skip = true;
			return NT_STATUS_OK;
		}
	}

	/* 3. is it in the selection list? */

	/*
	 * tar_create_from_list() use the include list as a starting
	 * point, no need to check
	 */
	if (!exclude) {
		*_skip = false;
		return NT_STATUS_OK;
	}

	/* we are now in exclude mode */

	/* no matter the selection, no list => include everything */
	if (t->path_list_size <= 0) {
		*_skip = false;
		return NT_STATUS_OK;
	}

	if (t->mode.regex) {
		in = mask_match_list(fullpath, t->path_list, t->path_list_size, true);
	} else {
		bool reverse = isdir && !exclude;
		NTSTATUS status = tar_path_in_list(t, fullpath, reverse, &in);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	*_skip = in;

	return NT_STATUS_OK;
}

/**
 * tar_to_process - return true if @t is ready to be processed
 *
 * @t is ready if it properly parsed command line arguments.
 */
bool tar_to_process(struct tar *t)
{
	if (t == NULL) {
		DBG(0, ("Invalid tar context\n"));
		return false;
	}
	return t->to_process;
}

/**
 * skip_useless_char_in_path - skip leading slashes/dots
 *
 * Skip leading slashes, backslashes and dot-slashes.
 */
static const char* skip_useless_char_in_path(const char *p)
{
	while (p) {
		if (*p == '/' || *p == '\\') {
			p++;
		}
		else if (p[0] == '.' && (p[1] == '/' || p[1] == '\\')) {
			p += 2;
		}
		else
			return p;
	}
	return p;
}

/**
 * is_subpath - check if the path @sub is a subpath of @full.
 * @sub: path to test
 * @full: container path
 * @_subpath_match: set true if @sub is a subpath of @full, otherwise false
 *
 * String comparaison is case-insensitive.
 */
static NTSTATUS is_subpath(const char *sub, const char *full,
			   bool *_subpath_match)
{
	NTSTATUS status = NT_STATUS_OK;
	int len = 0;
	char *f, *s;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	f = strlower_talloc(tmp_ctx, full);
	if (f == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out_ctx_free;
	}
	string_replace(f, '\\', '/');
	s = strlower_talloc(tmp_ctx, sub);
	if (f == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out_ctx_free;
	}
	string_replace(s, '\\', '/');

	/* find the point where sub and full diverge */
	while ((*f != '\0') && (*s != '\0') && (*f == *s)) {
		f++;
		s++;
		len++;
	}

	if ((*f == '\0') && (*s == '\0')) {
		*_subpath_match = true;	/* sub and full match */
		goto out_ctx_free;
	}

	if ((*f == '\0') && (len > 0) && (*(f - 1) == '/')) {
		/* sub diverges from full at path separator */
		*_subpath_match = true;
		goto out_ctx_free;
	}

	if ((*s == '\0') && (strcmp(f, "/") == 0)) {
		/* full diverges from sub with trailing slash only */
		*_subpath_match = true;
		goto out_ctx_free;
	}

	if ((*s == '/') && (*f == '\0')) {
		/* sub diverges from full with extra path component */
		*_subpath_match = true;
		goto out_ctx_free;
	}
	*_subpath_match = false;

out_ctx_free:
	talloc_free(tmp_ctx);
out:
	return status;
}

/**
 * set_remote_attr - set DOS attributes of a remote file
 * @filename: path to the file name
 * @new_attr: attribute bit mask to use
 * @mode: one of ATTR_SET or ATTR_UNSET
 *
 * Update the file attributes with the one provided.
 */
static int set_remote_attr(const char *filename, uint16 new_attr, int mode)
{
	extern struct cli_state *cli;
	uint16 old_attr;
	NTSTATUS status;

	status = cli_getatr(cli, filename, &old_attr, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DBG(0, ("cli_getatr failed: %s\n", nt_errstr(status)));
		return 1;
	}

	if (mode == ATTR_SET) {
		new_attr |= old_attr;
	} else {
		new_attr = old_attr & ~new_attr;
	}

	status = cli_setatr(cli, filename, new_attr, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG(1, ("cli_setatr failed: %s\n", nt_errstr(status)));
		return 1;
	}

	return 0;
}


/**
 * make_remote_path - recursively make remote dirs
 * @full_path: full hierarchy to create
 *
 * Create @full_path and each parent directories as needed.
 */
static int make_remote_path(const char *full_path)
{
	extern struct cli_state *cli;
	char *path;
	char *subpath;
	char *state;
	char *last_backslash;
	char *p;
	int len;
	NTSTATUS status;
	int err = 0;
	TALLOC_CTX *ctx = talloc_new(NULL);
	if (ctx == NULL) {
		return 1;
	}

	subpath = talloc_strdup(ctx, full_path);
	if (subpath == NULL) {
		err = 1;
		goto out;
	}
	path = talloc_strdup(ctx, full_path);
	if (path == NULL) {
		err = 1;
		goto out;
	}
	len = talloc_get_size(path) - 1;

	last_backslash = strrchr_m(path, '\\');
	if (last_backslash == NULL) {
		goto out;
	}

	*last_backslash = 0;

	subpath[0] = 0;
	p = strtok_r(path, "\\", &state);

	while (p != NULL) {
		strlcat(subpath, p, len);
		status = cli_chkpath(cli, subpath);
		if (!NT_STATUS_IS_OK(status)) {
			status = cli_mkdir(cli, subpath);
			if (!NT_STATUS_IS_OK(status)) {
				DBG(0, ("Can't mkdir %s: %s\n", subpath, nt_errstr(status)));
				err = 1;
				goto out;
			}
			DBG(3, ("mkdir %s\n", subpath));
		}

		strlcat(subpath, "\\", len);
		p = strtok_r(NULL, "/\\", &state);

	}

out:
	talloc_free(ctx);
	return err;
}

/**
 * tar_reset_mem_context - reset talloc context associated with @t
 *
 * At the start of the program the context is NULL so a new one is
 * allocated. On the following runs (interactive session only), simply
 * free the children.
 */
static TALLOC_CTX *tar_reset_mem_context(struct tar *t)
{
	tar_free_mem_context(t);
	t->talloc_ctx = talloc_new(NULL);
	return t->talloc_ctx;
}

/**
 * tar_free_mem_context - free talloc context associated with @t
 */
static void tar_free_mem_context(struct tar *t)
{
	if (t->talloc_ctx) {
		talloc_free(t->talloc_ctx);
		t->talloc_ctx = NULL;
		t->path_list_size = 0;
		t->path_list = NULL;
		t->tar_path = NULL;
	}
}

#define XSET(v)      [v] = #v
#define XTABLE(v, t) DBG(2, ("DUMP:%-20.20s = %s\n", #v, t[v]))
#define XBOOL(v)     DBG(2, ("DUMP:%-20.20s = %d\n", #v, v ? 1 : 0))
#define XSTR(v)      DBG(2, ("DUMP:%-20.20s = %s\n", #v, v ? v : "NULL"))
#define XINT(v)      DBG(2, ("DUMP:%-20.20s = %d\n", #v, v))
#define XUINT64(v)   DBG(2, ("DUMP:%-20.20s = %" PRIu64  "\n", #v, v))

/**
 * tar_dump - dump tar structure on stdout
 */
static void tar_dump(struct tar *t)
{
	int i;
	const char* op[] = {
		XSET(TAR_NO_OPERATION),
		XSET(TAR_CREATE),
		XSET(TAR_EXTRACT),
	};

	const char* sel[] = {
		XSET(TAR_NO_SELECTION),
		XSET(TAR_INCLUDE),
		XSET(TAR_EXCLUDE),
	};

	XBOOL(t->to_process);
	XTABLE(t->mode.operation, op);
	XTABLE(t->mode.selection, sel);
	XINT(t->mode.blocksize);
	XBOOL(t->mode.hidden);
	XBOOL(t->mode.system);
	XBOOL(t->mode.incremental);
	XBOOL(t->mode.reset);
	XBOOL(t->mode.dry);
	XBOOL(t->mode.verbose);
	XUINT64(t->total_size);
	XSTR(t->tar_path);
	XINT(t->path_list_size);

	for (i = 0; t->path_list && t->path_list[i]; i++) {
		DBG(2, ("DUMP: t->path_list[%2d] = %s\n", i, t->path_list[i]));
	}

	DBG(2, ("DUMP:t->path_list @ %p (%d elem)\n", t->path_list, i));
}
#undef XSET
#undef XTABLE
#undef XBOOL
#undef XSTR
#undef XINT

/**
 * max_token - return upper limit for the number of token in @str
 *
 * The result is not exact, the actual number of token might be less
 * than what is returned.
 */
static int max_token(const char *str)
{
	const char *s;
	int nb = 0;

	if (str == NULL) {
		return 0;
	}

	s = str;
	while (s[0] != '\0') {
		if (isspace((int)s[0])) {
			nb++;
		}
		s++;
	}

	nb++;

	return nb;
}

/**
 * fix_unix_path - convert @path to a DOS path
 * @path: path to convert
 * @removeprefix: if true, remove leading ./ or /.
 */
static char *fix_unix_path(char *path, bool do_remove_prefix)
{
	char *from = path, *to = path;

	if (path == NULL || path[0] == '\0') {
		return path;
	}

	/* remove prefix:
	 * ./path => path
	 *  /path => path
	 */
	if (do_remove_prefix) {
		/* /path */
		if (path[0] == '/' || path[0] == '\\') {
			from += 1;
		}

		/* ./path */
		if (path[1] != '\0' && path[0] == '.' && (path[1] == '/' || path[1] == '\\')) {
			from += 2;
		}
	}

	/* replace / with \ */
	while (from[0] != '\0') {
		if (from[0] == '/') {
			to[0] = '\\';
		} else {
			to[0] = from[0];
		}

		from++;
		to++;
	}
	to[0] = '\0';

	return path;
}

/**
 * path_base_name - return @path basename
 *
 * If @path doesn't contain any directory separator return NULL.
 */
static NTSTATUS path_base_name(TALLOC_CTX *ctx, const char *path, char **_base)
{
	char *base = NULL;
	int last = -1;
	int i;

	for (i = 0; path[i]; i++) {
		if (path[i] == '\\' || path[i] == '/') {
			last = i;
		}
	}

	if (last >= 0) {
		base = talloc_strdup(ctx, path);
		if (base == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		base[last] = 0;
	}

	*_base = base;
	return NT_STATUS_OK;
}

#else

#define NOT_IMPLEMENTED DEBUG(0, ("tar mode not compiled. build with --with-libarchive\n"))

int cmd_block(void)
{
	NOT_IMPLEMENTED;
	return 1;
}

int cmd_tarmode(void)
{
	NOT_IMPLEMENTED;
	return 1;
}

int cmd_setmode(void)
{
	NOT_IMPLEMENTED;
	return 1;
}

int cmd_tar(void)
{
	NOT_IMPLEMENTED;
	return 1;
}

int tar_process(struct tar* tar)
{
	NOT_IMPLEMENTED;
	return 1;
}

int tar_parse_args(struct tar *tar, const char *flag, const char **val, int valsize)
{
	NOT_IMPLEMENTED;
	return 1;
}

bool tar_to_process(struct tar *tar)
{
	return false;
}

struct tar *tar_get_ctx()
{
	return NULL;
}

#endif
