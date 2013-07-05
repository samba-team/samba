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
#include "libsmb/libsmb.h"
#include <archive.h>

#define LEN(x) (sizeof(x)/sizeof((x)[0]))
#define TAR_MAX_BLOCK_SIZE 65535
/*
 * XXX: used in client.c, we have to export it for now.
 * corresponds to the transfer operation. Can be '\0', 'c' or 'x'
 */
char tar_type = 0;

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

    /* path to file list (F flag) */
    char *list_path;

    /* archive handle */
    struct archive *archive;
};

static struct tar tar_ctx = {
    .mode.selection   = TAR_INCLUDE,
    .mode.blocksize   = 20,
    .mode.hidden      = True,
    .mode.system      = True,
    .mode.incremental = False,
    .mode.dry         = False,
};

static int tar_set_blocksize(struct tar *t, int size)
{
    if (size <= 0 || size > TAR_MAX_BLOCK_SIZE) {
        return 0;
    }

    t->mode.blocksize = size;

    return 1;
}

static bool tar_set_newer_than(struct tar *t, char *filename)
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
        {"full",      &tar_ctx.mode.incremental, False},
        {"inc",       &tar_ctx.mode.incremental, True },
        {"reset",     &tar_ctx.mode.reset,       True },
        {"noreset",   &tar_ctx.mode.reset,       False},
        {"system",    &tar_ctx.mode.system,      True },
        {"nosystem",  &tar_ctx.mode.system,      False},
        {"hidden",    &tar_ctx.mode.hidden,      True },
        {"nohidden",  &tar_ctx.mode.hidden,      False},
        {"verbose",   &tar_ctx.mode.verbose,     True },
        {"noquiet",   &tar_ctx.mode.verbose,     True },
        {"quiet",     &tar_ctx.mode.verbose,     False},
        {"noverbose", &tar_ctx.mode.verbose,     False},
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


/****************************************************************************
Principal command for creating / extracting
***************************************************************************/

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

/****************************************************************************
Parse tar arguments. Sets tar_type, tar_excl, etc.
***************************************************************************/

int tar_parseargs(int argc, char *argv[], const char *Optarg, int Optind)
{
	int newOptind = Optind;

    /*
     * Reset back some options - could be from interactive version
	 * all other modes are left as they are
	 */
    tar_ctx.mode.operation = TAR_NO_OPERATION;
    tar_ctx.mode.selection = TAR_NO_SELECTION;
    tar_ctx.mode.dry = False;

    while (*Optarg) {
        switch(*Optarg++) {
        /* operation */
        case 'c':
            if (tar_ctx.mode.operation != TAR_NO_OPERATION) {
                printf("Tar must be followed by only one of c or x.\n");
                return 0;
            }
            tar_ctx.mode.operation = TAR_CREATE;
            break;
        case 'x':
            if (tar_ctx.mode.operation != TAR_NO_OPERATION) {
                printf("Tar must be followed by only one of c or x.\n");
                return 0;
            }
            tar_ctx.mode.operation = TAR_CREATE;
            break;

        /* selection  */
        case 'I':
            if (tar_ctx.mode.selection != TAR_NO_SELECTION) {
                DEBUG(0,("Only one of I,X,F must be specified\n"));
                return 0;
            }
            tar_ctx.mode.selection = TAR_INCLUDE;
            break;
        case 'X':
            if (tar_ctx.mode.selection != TAR_NO_SELECTION) {
                DEBUG(0,("Only one of I,X,F must be specified\n"));
                return 0;
            }
            tar_ctx.mode.selection = TAR_EXCLUDE;
            break;
        case 'F':
            if (tar_ctx.mode.selection != TAR_NO_SELECTION) {
                DEBUG(0,("Only one of I,X,F must be specified\n"));
                return 0;
            }
            tar_ctx.mode.selection = TAR_INCLUDE_LIST;
            break;

        /* blocksize */
        case 'b':
            if (Optind >= argc) {
                DEBUG(0, ("Option b must be followed by a blocksize\n"));
                return 0;
            }

            if (!tar_set_blocksize(&tar_ctx, atoi(argv[Optind]))) {
                DEBUG(0, ("Option b must be followed by a valid blocksize\n"));
                return 0;
            }

            Optind++;
            newOptind++;
            break;

         /* incremental mode */
        case 'g':
            tar_ctx.mode.incremental = True;
            break;

        /* newer than */
        case 'N':
            if (Optind >= argc) {
                DEBUG(0, ("Option N must be followed by valid file name\n"));
                return 0;
            }

            if (!tar_set_newer_than(&tar_ctx, argv[Optind])) {
                DEBUG(0,("Error setting newer-than time\n"));
                return 0;
            }

            newOptind++;
            Optind++;
            break;

        /* reset mode */
        case 'a':
            tar_ctx.mode.reset = True;
            break;

        /* verbose */
        case 'q':
            tar_ctx.mode.verbose = True;
            break;

        /* regex match  */
        case 'r':
            tar_ctx.mode.regex = True;
            break;

        /* dry run mode */
        case 'n':
            if (tar_ctx.mode.operation != TAR_CREATE) {
                DEBUG(0, ("n is only meaningful when creating a tar-file\n"));
                return 0;
            }

            tar_ctx.mode.dry = True;
            DEBUG(0, ("dry_run set\n"));
            break;

        default:
            DEBUG(0,("Unknown tar option\n"));
            return 0;
        }
    }

    /* default operation is include */
    if (tar_ctx.mode.operation == TAR_NO_OPERATION) {
        tar_ctx.mode.operation = TAR_INCLUDE;
    }

    if (tar_ctx.mode.selection == TAR_INCLUDE_LIST) {
        if (argc - Optind - 1 != 1) {
            DEBUG(0,("Option F must be followed by exactly one filename.\n"));
            return 0;
        }
        newOptind++;
        /* Optind points at the tar output file, Optind+1 at the inclusion file. */
        printf("tar: %s list: %s\n", argv[Optind], argv[Optind+1]);
    }

    return newOptind;

}
