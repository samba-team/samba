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
 * `tar_ctx`. It's not static but you should avoid accessing it
 * directly.
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
#include <archive.h>
#include <archive_entry.h>

#define LEN(x) (sizeof(x)/sizeof((x)[0]))
#define DBG(a, b) (DEBUG(a, ("tar:%-4d ", __LINE__)), DEBUG(a, b))

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

/* interactive commands, exported functions */
int cmd_block(void);
int cmd_setmode(void);
int cmd_tar(void);
int cmd_tarmode(void);

/* tar, exported functions */
int tar_process(struct tar *t);
bool tar_to_process(struct tar *t);
int tar_parse_args(struct tar *t,
                   const char *flag,
                   const char **val, int valsize);


/* tar, local function */
static int tar_create(struct tar* t);
static int tar_create_from_list(struct tar *t);
static int tar_extract(struct tar *t);
static int tar_read_inclusion_file (struct tar *t, const char* filename);
static int tar_send_file(struct tar *t, struct archive_entry *entry);
static int tar_set_blocksize(struct tar *t, int size);
static int tar_set_newer_than(struct tar *t, const char *filename);
static void tar_add_selection_path(struct tar *t, const char *path);
static void tar_dump(struct tar *t);
static bool tar_extract_skip_path(struct tar *t, struct archive_entry *entry);
static bool tar_create_skip_path(struct tar *t,
                                 const char *fullpath,
                                 const struct file_info *finfo);

static bool tar_path_in_list(struct tar *t,
                             const char *path,
                             bool reverse);

static int tar_get_file(struct tar *t,
                        const char *full_dos_path,
                        struct file_info *finfo);

static NTSTATUS get_file_callback(struct cli_state *cli,
                                  struct file_info *finfo,
                                  const char *dir);

/* utilities */
static char *fix_unix_path (char *path, bool removeprefix);
static char *path_base_name (const char *path);
static const char* skip_useless_char_in_path(const char *p);
static int make_remote_path(const char *full_path);
static int max_token (const char *str);
static bool is_subpath(const char *sub, const char *full);
static int set_remote_attr(const char *filename, uint16 new_attr, int mode);


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
    TALLOC_CTX *ctx = talloc_tos();

    if (!next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
        DBG(0, ("blocksize <n>\n"));
        return 1;
    }

    if (tar_set_blocksize(&tar_ctx, atoi(buf))) {
        DBG(0, ("invalid blocksize\n"));
    }

    DBG(2, ("blocksize is now %d\n", tar_ctx.mode.blocksize));

    return 0;
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
    TALLOC_CTX *ctx = talloc_tos();

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

    while (next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
        for (i = 0; i < LEN(table); i++) {
            if (strequal(table[i].cmd, buf)) {
                *table[i].p = table[i].value;
                break;
            }
        }

        if (i == LEN(table))
            DBG(0, ("tarmode: unrecognised option %s\n", buf));

        TALLOC_FREE(buf);
    }

    DBG(0, ("tarmode is now %s, %s, %s, %s, %s\n",
              tar_ctx.mode.incremental ? "incremental" : "full",
              tar_ctx.mode.system      ? "system"      : "nosystem",
              tar_ctx.mode.hidden      ? "hidden"      : "nohidden",
              tar_ctx.mode.reset       ? "reset"       : "noreset",
              tar_ctx.mode.verbose     ? "verbose"     : "quiet"));
    return 0;
}

/**
 * cmd_tar - interactive command to start a tar backup/restoration
 *
 * Check presence of argument, parse them and handle the request.
 */
int cmd_tar(void)
{
    TALLOC_CTX *ctx = talloc_tos();
    const extern char *cmd_ptr;
    const char *flag;
    const char **val;
    char *buf;
    int maxtok = max_token(cmd_ptr);
    int i = 0;
    int err = 0;

    if (!next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
        DBG(0, ("tar <c|x>[IXFbganN] [options] <tar file> [path list]\n"));
        return 1;
    }

    flag = buf;
    val = talloc_array(ctx, const char*, maxtok);

    while (next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
        val[i++] = buf;
    }

    if (tar_parse_args(&tar_ctx, flag, val, i)) {
        DBG(0, ("parse_args failed\n"));
        err = 1;
        goto out;
    }

    if (tar_process(&tar_ctx)) {
        DBG(0, ("tar_process failed\n"));
        err = 1;
        goto out;
    }

 out:
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
    TALLOC_CTX *ctx = talloc_tos();


    if (!next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
        DBG(0, ("setmode <filename> <[+|-]rsha>\n"));
        return 1;
    }

    fname = talloc_asprintf(ctx,
                            "%s%s",
                            client_get_cur_dir(),
                            buf);
    if (!fname) {
        return 1;
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
                return 1;
            }
        }
    }

    if (attr[ATTR_SET] == 0 && attr[ATTR_UNSET] == 0) {
        DBG(0, ("setmode <filename> <[+|-]rsha>\n"));
        return 1;
    }

    DBG(2, ("perm set %d %d\n", attr[ATTR_SET], attr[ATTR_UNSET]));

    /* ignore return value: server might not store DOS attributes */
    set_remote_attr(fname, attr[ATTR_SET], ATTR_SET);
    set_remote_attr(fname, attr[ATTR_UNSET], ATTR_UNSET);
    return 0;
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
int tar_parse_args(struct tar* t, const char *flag,
                   const char **val, int valsize)
{
    TALLOC_CTX *ctx = talloc_tos();
    bool list = false;

    /* index of next value to use */
    int ival = 0;

    /*
     * Reset back some options - could be from interactive version
     * all other modes are left as they are
     */
    t->mode.operation = TAR_NO_OPERATION;
    t->mode.selection = TAR_NO_SELECTION;
    t->mode.dry = false;
    t->to_process = false;
    t->total_size = 0;

    while (*flag) {
        switch(*flag++) {
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
            list = true;
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
    if (list) {
        if (valsize - ival != 1) {
            DBG(0,("Option F must be followed by exactly one filename.\n"));
            return 1;
        }

        if (tar_read_inclusion_file(t, val[ival])) {
            return 1;
        }
        ival++;
    }

    /* otherwise store all the PATHs on the command line */
    else {
        int i;
        for (i = ival; i < valsize; i++) {
            tar_add_selection_path(t, val[i]);
        }
    }

    t->to_process = true;
    tar_dump(t);
    return 0;
}

/**
 * tar_process - start processing archive
 */
int tar_process(struct tar *t)
{
    int rc = 0;

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

    DBG(5, ("tar_process done, err = %d\n", rc));
    return rc;
}

/**
 * tar_create - create archive and fetch files
 */
static int tar_create(struct tar* t)
{
    TALLOC_CTX *ctx = talloc_tos();
    int r;
    int err = 0;
    NTSTATUS status;
    const char *mask;

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
    return err;
}

/**
 * tar_create_from_list - fetch from path list in include mode
 */
static int tar_create_from_list(struct tar *t)
{
    TALLOC_CTX *ctx = talloc_tos();
    int err = 0;
    NTSTATUS status;
    const char *path, *mask, *base, *start_dir;
    int i;

    start_dir = talloc_strdup(ctx, client_get_cur_dir());

    for (i = 0; i < t->path_list_size; i++) {
        path = t->path_list[i];
        base = path_base_name(path);
        mask = talloc_asprintf(ctx, "%s\\%s", client_get_cur_dir(), path);

        DBG(5, ("incl. path='%s', base='%s', mask='%s'\n",
                path, base ? base : "NULL", mask));

        if (base) {
            base = talloc_asprintf(ctx, "%s%s\\",
                                   client_get_cur_dir(), path_base_name(path));
            DBG(5, ("cd '%s' before do_list\n", base));
            client_set_cur_dir(base);
        }
        status = do_list(mask, TAR_DO_LIST_ATTR, get_file_callback, false, true);
        if (base) {
            client_set_cur_dir(start_dir);
        }
        if (!NT_STATUS_IS_OK(status)) {
            DBG(0, ("do_list failed on %s (%s)\n", path, nt_errstr(status)));
            err = 1;
            goto out;
        }
    }

 out:
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
    TALLOC_CTX *ctx = talloc_tos();
    NTSTATUS err = NT_STATUS_OK;
    char *remote_name;
    const char *initial_dir = client_get_cur_dir();

    remote_name = talloc_asprintf(ctx, "%s%s", initial_dir, finfo->name);

    if (strequal(finfo->name, "..") || strequal(finfo->name, ".")) {
        goto out;
    }

    if (tar_create_skip_path(&tar_ctx, remote_name, finfo)) {
        DBG(5, ("--- %s\n", remote_name));
        goto out;
    }

    if (finfo->mode & FILE_ATTRIBUTE_DIRECTORY) {
        char *old_dir;
        char *new_dir;
        char *mask;

        old_dir = talloc_strdup(ctx, initial_dir);
        new_dir = talloc_asprintf(ctx, "%s%s\\", initial_dir, finfo->name);
        mask = talloc_asprintf(ctx, "%s*", new_dir);

        if (tar_get_file(&tar_ctx, remote_name, finfo)) {
            err = NT_STATUS_UNSUCCESSFUL;
            goto out;
        }

        client_set_cur_dir(new_dir);
        do_list(mask, TAR_DO_LIST_ATTR, get_file_callback, false, true);
        client_set_cur_dir(old_dir);
    }

    else {
        if (tar_get_file(&tar_ctx, remote_name, finfo)) {
            err = NT_STATUS_UNSUCCESSFUL;
            goto out;
        }
    }

 out:
    return err;
}

/**
 * tar_get_file - fetch a remote file to the local archive
 * @full_dos_path: path to the file to fetch
 * @finfo: attributes of the file to fetch
 */
static int tar_get_file(struct tar *t, const char *full_dos_path,
                        struct file_info *finfo)
{
    extern struct cli_state *cli;
    TALLOC_CTX *ctx = talloc_tos();
    NTSTATUS status;
    struct archive_entry *entry;
    char *full_unix_path;
    char buf[TAR_CLI_READ_SIZE];
    size_t len;
    uint64_t off = 0;
    uint16_t remote_fd = (uint16_t)-1;
    int err = 0, r;
    const bool isdir = finfo->mode & FILE_ATTRIBUTE_DIRECTORY;

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

        if (tar_extract_skip_path(t, entry)) {
            DBG(5, ("--- %s\n", archive_entry_pathname(entry)));
            continue;
        }

        DBG(5, ("+++ %s\n", archive_entry_pathname(entry)));

        if (tar_send_file(t, entry)) {
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
    TALLOC_CTX *ctx = talloc_tos();
    char *dos_path;
    char *full_path;
    NTSTATUS status;
    uint16_t remote_fd = (uint16_t) -1;
    int err = 0;
    int flags = O_RDWR | O_CREAT | O_TRUNC;
    mode_t mode = archive_entry_filetype(entry);

    dos_path = talloc_strdup(ctx, archive_entry_pathname(entry));
    fix_unix_path(dos_path, true);

    full_path = talloc_strdup(ctx, client_get_cur_dir());
    full_path = talloc_strdup_append(full_path, dos_path);

    if (mode != AE_IFREG && mode != AE_IFDIR) {
        DBG(0, ("Skipping non-dir & non-regular file %s\n", full_path));
        goto out;
    }

    if (make_remote_path(full_path)) {
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
    return err;
}

/**
 * tar_add_selection_path - add a path to the path list
 * @path: path to add
 */
static void tar_add_selection_path(struct tar *t, const char *path)
{
    TALLOC_CTX *ctx = talloc_tos();
    if (!t->path_list) {
        t->path_list = str_list_make_empty(ctx);
        t->path_list_size = 0;
    }

    t->path_list = str_list_add((const char**)t->path_list, path);
    t->path_list_size++;
    fix_unix_path(t->path_list[t->path_list_size - 1], true);
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

    if (sys_stat(filename, &stbuf, false) != 0) {
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
static int tar_read_inclusion_file (struct tar *t, const char* filename)
{
    char *line;
    TALLOC_CTX *ctx = talloc_tos();
    int fd = open(filename, O_RDONLY);

    if (fd < 0) {
        DBG(0, ("Can't open inclusion file '%s': %s\n", filename, strerror(errno)));
        return 1;
    }

    while ((line = afdgets(fd, ctx, 0))) {
        tar_add_selection_path(t, line);
    }

    close(fd);
    return 0;
}

/**
 * tar_path_in_list - return true if @path is in the path list
 * @path: path to find
 * @reverse: when true also try to find path list element in @path
 *
 * Look at each path of the path list and return true if @path is a
 * subpath of one of them.
 *
 * If you want /path to be in the path list (path/a/, path/b/) set
 * @reverse to true to try to match the other way around.
 */
static bool tar_path_in_list(struct tar *t, const char *path, bool reverse)
{
    int i;
    const char *p = path;
    const char *pattern;
    bool res;

    if (!p || !p[0])
        return false;

    p = skip_useless_char_in_path(p);

    for (i = 0; i < t->path_list_size; i++) {
        pattern = skip_useless_char_in_path(t->path_list[i]);
        res = is_subpath(p, pattern);
        if (reverse) {
            res = res || is_subpath(pattern, p);
        }
        if (res) {
            return true;
        }
    }

    return false;
}

/**
 * tar_extract_skip_path - return true if @entry should be skipped
 * @entry: current tar entry
 *
 * Skip predicate for tar extraction (archive to server) only.
 */
static bool tar_extract_skip_path(struct tar *t,
                                  struct archive_entry *entry)
{
    const bool skip = true;
    const char *fullpath = archive_entry_pathname(entry);
    bool in = true;

    if (t->path_list_size <= 0) {
        return !skip;
    }

    if (t->mode.regex) {
        in = mask_match_list(fullpath, t->path_list, t->path_list_size, true);
    } else {
        in = tar_path_in_list(t, fullpath, false);
    }

    if (t->mode.selection == TAR_EXCLUDE) {
        in = !in;
    }

    return in ? !skip : skip;
}

/**
 * tar_create_skip_path - return true if @fullpath shoud be skipped
 * @fullpath: full remote path of the current file
 * @finfo: remote file attributes
 *
 * Skip predicate for tar creation (server to archive) only.
 */
static bool tar_create_skip_path(struct tar *t,
                                 const char *fullpath,
                                 const struct file_info *finfo)
{
    /* syntaxic sugar */
    const bool skip = true;
    const mode_t mode = finfo->mode;
    const bool isdir = mode & FILE_ATTRIBUTE_DIRECTORY;
    const bool exclude = t->mode.selection == TAR_EXCLUDE;
    bool in = true;

    if (!isdir) {

        /* 1. if we dont want X and we have X, skip */
        if (!t->mode.system && (mode & FILE_ATTRIBUTE_SYSTEM)) {
            return skip;
        }

        if (!t->mode.hidden && (mode & FILE_ATTRIBUTE_HIDDEN)) {
            return skip;
        }

        /* 2. if we only want archive and it's not, skip */

        if (t->mode.incremental && !(mode & FILE_ATTRIBUTE_ARCHIVE)) {
            return skip;
        }
    }

    /* 3. is it in the selection list? */

    /*
     * tar_create_from_list() use the include list as a starting
     * point, no need to check
     */
    if (!exclude) {
        return !skip;
    }

    /* we are now in exclude mode */

    /* no matter the selection, no list => include everything */
    if (t->path_list_size <= 0) {
        return !skip;
    }

    if (t->mode.regex) {
        in = mask_match_list(fullpath, t->path_list, t->path_list_size, true);
    } else {
        in = tar_path_in_list(t, fullpath, isdir && !exclude);
    }

    return in ? skip : !skip;
}

/**
 * tar_to_process - return true if @t is ready to be processed
 *
 * @t is ready if it properly parsed command line arguments.
 */
bool tar_to_process (struct tar *t)
{
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
 * is_subpath - return true if the path @sub is a subpath of @full.
 * @sub: path to test
 * @full: container path
 *
 * String comparaison is case-insensitive.
 *
 * Return true if @sub = @full
 */
static bool is_subpath(const char *sub, const char *full)
{
    const char *full_copy = full;

    while (*full && *sub &&
           (*full == *sub || tolower_m(*full) == tolower_m(*sub) ||
            (*full == '\\' && *sub=='/') || (*full == '/' && *sub=='\\'))) {
        full++; sub++;
    }

    /* if full has a trailing slash, it compared equal, so full is an "initial"
       string of sub.
    */
    if (!*full && full != full_copy && (*(full-1) == '/' || *(full-1) == '\\'))
        return true;

    /* ignore trailing slash on full */
    if (!*sub && (*full == '/' || *full == '\\') && !*(full+1))
        return true;

    /* check for full is an "initial" string of sub */
    if ((*sub == '/' || *sub == '\\') && !*full)
        return true;

    return *full == *sub;
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
    TALLOC_CTX *ctx = talloc_tos();
    char *path;
    char *subpath;
    char *state;
    char *last_backslash;
    char *p;
    int len;
    NTSTATUS status;
    int err = 0;

    subpath = talloc_strdup(ctx, full_path);
    path = talloc_strdup(ctx, full_path);
    len = talloc_get_size(path) - 1;

    last_backslash = strrchr_m(path, '\\');

    if (!last_backslash) {
        goto out;
    }

    *last_backslash = 0;

    subpath[0] = 0;
    p = strtok_r(path, "\\", &state);

    while (p) {
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
    return err;
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
static int max_token (const char *str)
{
    const char *s = str;
    int nb = 0;

    if (!str) {
        return 0;
    }

    while (*s) {
        if (isspace(*s)) {
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
static char *fix_unix_path (char *path, bool removeprefix)
{
    char *from = path, *to = path;

    if (!path || !*path)
        return path;

    /* remove prefix:
     * ./path => path
     *  /path => path
     */
    if (removeprefix) {
        /* /path */
        if (path[0] == '/' || path[0] == '\\') {
            from += 1;
        }

        /* ./path */
        if (path[1] && path[0] == '.' && (path[1] == '/' || path[1] == '\\')) {
            from += 2;
        }
    }

    /* replace / with \ */
    while (*from) {
        if (*from == '/') {
            *to = '\\';
        } else {
            *to = *from;
        }
        from++; to++;
    }
    *to = 0;

    return path;
}

/**
 * path_base_name - return @path basename
 *
 * If @path doesn't contain any directory separator return NULL.
 */
static char *path_base_name (const char *path)
{
    TALLOC_CTX *ctx = talloc_tos();
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
        base[last] = 0;
    }

    return base;
}
