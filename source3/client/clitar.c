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

#include "includes.h"
#include "system/filesys.h"
#include "client/client_proto.h"
#include "client/clitar_proto.h"
#include "libsmb/libsmb.h"
#include <archive.h>

#define LEN(x) (sizeof(x)/sizeof((x)[0]))
#define TAR_MAX_BLOCK_SIZE 65535

enum tar_operation {
    TAR_NO_OPERATION,
    TAR_CREATE,    /* c flag */
    TAR_EXTRACT,   /* x flag */
};

enum tar_selection {
    TAR_NO_SELECTION,
    TAR_INCLUDE,       /* I flag, default */
    TAR_INCLUDE_LIST,  /* F flag */
    TAR_EXCLUDE,       /* X flag */
};

enum {
    ATTR_UNSET,
    ATTR_SET,
};

struct tar {
    bool to_process;

    /* flags */
    struct tar_mode {
        enum tar_operation operation; /* create, extract */
        enum tar_selection selection; /* inc, inc from file, exclude */
        int blocksize;    /* size in bytes of a block in the tar file */
        bool hidden;      /* backup hidden file? */
        bool system;      /* backup system file? */
        bool incremental; /* backup _only_ archived file? */
        bool reset;       /* unset archive bit? */
        bool dry;         /* don't write tar file? */
        bool regex;       /* XXX: never actually using regex... */
        bool verbose;
    } mode;

    /* path to tar archive name */
    char *tar_path;

    /* file descriptor of tar file */
    int tar_fd;

    /* list of path to include or exclude */
    char **path_list;

    /* archive handle */
    struct archive *archive;
};

struct tar tar_ctx = {
    .mode.selection   = TAR_INCLUDE,
    .mode.blocksize   = 20,
    .mode.hidden      = true,
    .mode.system      = true,
    .mode.incremental = false,
    .mode.dry         = false,
};

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

    /* replace \ with / */
    while (*from) {
        if (*from == '\\') {
            *to = '/';
        } else {
            *to = *from;
        }
        from++; to++;
    }
    *to = 0;

    return path;
}

#define XSET(v)      [v] = #v
#define XTABLE(v, t) DEBUG(2, ("DUMP:%-20.20s = %s\n", #v, t[v]))
#define XBOOL(v)     DEBUG(2, ("DUMP:%-20.20s = %d\n", #v, v ? 1 : 0))
#define XSTR(v)      DEBUG(2, ("DUMP:%-20.20s = %s\n", #v, v ? v : "NULL"))
#define XINT(v)      DEBUG(2, ("DUMP:%-20.20s = %d\n", #v, v))
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
        XSET(TAR_INCLUDE_LIST),
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
    XSTR(t->tar_path);
    XINT(t->tar_fd);

    for(i = 0; t->path_list && t->path_list[i]; i++) {
        DEBUG(2, ("DUMP: t->path_list[%2d] = %s\n", i, t->path_list[i]));
    }

    DEBUG(2, ("DUMP:t->path_list @ %p (%d elem)\n", t->path_list, i));
}
#undef XSET
#undef XTABLE
#undef XBOOL
#undef XSTR
#undef XINT

static int tar_set_blocksize(struct tar *t, int size)
{
    if (size <= 0 || size > TAR_MAX_BLOCK_SIZE) {
        return 0;
    }

    t->mode.blocksize = size;

    return 1;
}

static bool tar_set_newer_than(struct tar *t, const char *filename)
{
    extern time_t newer_than;
    SMB_STRUCT_STAT stbuf;

    if (sys_stat(filename, &stbuf, false) != 0) {
        DEBUG(0, ("Error setting newer-than time\n"));
        return 0;
    }

    newer_than = convert_timespec_to_time_t(stbuf.st_ex_mtime);
    DEBUG(1, ("Getting files newer than %s\n", time_to_asc(newer_than)));
    return 1;
}

static bool tar_read_inclusion_file (struct tar *t, const char* filename)
{
    char *line;
    char **list;
    TALLOC_CTX *ctx = talloc_tos();
    int fd = open(filename, O_RDONLY);

    if (fd < 0) {
        DEBUG(0, ("Can't open inclusion file '%s': %s\n", filename, strerror(errno)));
        return 0;
    }

    list = str_list_make_empty(ctx);

    while ((line = afdgets(fd, ctx, 0))) {
        list = str_list_add((const char **)list, fix_unix_path(line, true));
    }

    close(fd);
    t->path_list = list;
    return 1;
}

bool tar_to_process (struct tar *t)
{
    return t->to_process;
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
    TALLOC_CTX *ctx = talloc_tos();

    if (!next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
        DEBUG(0, ("blocksize <n>\n"));
        return 1;
    }

    if(!tar_set_blocksize(&tar_ctx, atoi(buf))) {
        DEBUG(0, ("invalid blocksize\n"));
    }

    DEBUG(2, ("blocksize is now %d\n", tar_ctx.mode.blocksize));

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
            DEBUG(0, ("tarmode: unrecognised option %s\n", buf));

        TALLOC_FREE(buf);
    }

    DEBUG(0, ("tarmode is now %s, %s, %s, %s, %s\n",
              tar_ctx.mode.incremental ? "incremental" : "full",
              tar_ctx.mode.system      ? "system"      : "nosystem",
              tar_ctx.mode.hidden      ? "hidden"      : "nohidden",
              tar_ctx.mode.reset       ? "reset"       : "noreset",
              tar_ctx.mode.verbose     ? "verbose"     : "quiet"));
    return 0;
}

/**
 * set_remote_attr - set DOS attributes of a remote file
 * @filename: path to the file name
 * @new_attr: attribute bit mask to use
 * @mode: one of ATTR_SET or ATTR_UNSET
 *
 * Update the file attributes with the one provided.
 */
static void set_remote_attr(char *filename, uint16 new_attr, int mode)
{
    extern struct cli_state *cli;
    uint16 old_attr;
    NTSTATUS status;

    if (!NT_STATUS_IS_OK(cli_getatr(cli, filename, &old_attr, NULL, NULL))) {
        /* XXX: debug message */
        return;
    }

    if (mode == ATTR_SET) {
        new_attr |= old_attr;
    } else {
        new_attr = old_attr & ~new_attr;
    }

    status = cli_setatr(cli, filename, new_attr, 0);
    if (!NT_STATUS_IS_OK(status)) {
        DEBUG(1, ("setatr failed: %s\n", nt_errstr(status)));
    }
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
        DEBUG(0, ("setmode <filename> <[+|-]rsha>\n"));
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

        while(*s) {
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
                DEBUG(0, ("setmode <filename> <perm=[+|-]rsha>\n"));
                return 1;
            }
        }
    }

    if (attr[ATTR_SET] == 0 && attr[ATTR_UNSET] == 0) {
        DEBUG(0, ("setmode <filename> <[+|-]rsha>\n"));
        return 1;
    }

    DEBUG(2, ("\nperm set %d %d\n", attr[ATTR_SET], attr[ATTR_UNSET]));
    set_remote_attr(fname, attr[ATTR_SET], ATTR_SET);
    set_remote_attr(fname, attr[ATTR_UNSET], ATTR_UNSET);
    return 0;
}


/**
 * cmd_tar - interactive command to start a tar backup/restoration
 *
 * Check presence of argument, parse them and handle the request.
 */
int cmd_tar(void)
{
    return 0;
}

/****************************************************************************
Command line (option) version
***************************************************************************/

int process_tar(void)
{
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
 * opt has only flags (eg. "f1f2f3") and val has the arguments
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
int tar_parse_args(struct tar* t, const char *flag, const char **val, int valsize)
{
    TALLOC_CTX *ctx = talloc_tos();

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

    while (*flag) {
        switch(*flag++) {
        /* operation */
        case 'c':
            if (t->mode.operation != TAR_NO_OPERATION) {
                printf("Tar must be followed by only one of c or x.\n");
                return 0;
            }
            t->mode.operation = TAR_CREATE;
            break;
        case 'x':
            if (t->mode.operation != TAR_NO_OPERATION) {
                printf("Tar must be followed by only one of c or x.\n");
                return 0;
            }
            t->mode.operation = TAR_EXTRACT;
            break;

        /* selection  */
        case 'I':
            if (t->mode.selection != TAR_NO_SELECTION) {
                DEBUG(0,("Only one of I,X,F must be specified\n"));
                return 0;
            }
            t->mode.selection = TAR_INCLUDE;
            break;
        case 'X':
            if (t->mode.selection != TAR_NO_SELECTION) {
                DEBUG(0,("Only one of I,X,F must be specified\n"));
                return 0;
            }
            t->mode.selection = TAR_EXCLUDE;
            break;
        case 'F':
            if (t->mode.selection != TAR_NO_SELECTION) {
                DEBUG(0,("Only one of I,X,F must be specified\n"));
                return 0;
            }
            t->mode.selection = TAR_INCLUDE_LIST;
            break;

        /* blocksize */
        case 'b':
            if (ival >= valsize) {
                DEBUG(0, ("Option b must be followed by a blocksize\n"));
                return 0;
            }

            if (!tar_set_blocksize(t, atoi(val[ival]))) {
                DEBUG(0, ("Option b must be followed by a valid blocksize\n"));
                return 0;
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
                DEBUG(0, ("Option N must be followed by valid file name\n"));
                return 0;
            }

            if (!tar_set_newer_than(t, val[ival])) {
                DEBUG(0,("Error setting newer-than time\n"));
                return 0;
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
                DEBUG(0, ("n is only meaningful when creating a tar-file\n"));
                return 0;
            }

            t->mode.dry = true;
            DEBUG(0, ("dry_run set\n"));
            break;

        default:
            DEBUG(0,("Unknown tar option\n"));
            return 0;
        }
    }

    /* no selection given? default selection is include */
    if (t->mode.selection == TAR_NO_SELECTION) {
        t->mode.selection = TAR_INCLUDE;
    }

    if (valsize - ival < 1) {
        DEBUG(0, ("No tar file given.\n"));
        return 0;
    }

    /* handle TARFILE */
    t->tar_path = talloc_strdup(ctx, val[ival]);
    ival++;

    /* handle PATHs... */
    tar_ctx.path_list = str_list_make_empty(ctx);

    /* flag F -> read file list */
    if (t->mode.selection == TAR_INCLUDE_LIST) {
        if (valsize - ival != 1) {
            DEBUG(0,("Option F must be followed by exactly one filename.\n"));
            return 0;
        }

        if (!tar_read_inclusion_file(t, val[ival])) {
            return 0;
        }
        ival++;
    }

    /* otherwise store all the PATHs on the command line */
    else {
        int i;
        for (i = ival; i < valsize; i++) {
            t->path_list = str_list_add((const char**)t->path_list, val[i]);
            fix_unix_path(t->path_list[i-ival], true);
        }
    }

    t->to_process = true;
    tar_dump(t);
    return 1;
}
