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

/* XXX: used in client.c, we have to export it for now */
char tar_type = 0;

enum tar_type_t {
    TAR_INCLUDE,       /* I flag, default */
    TAR_INCLUDE_FILE,  /* F flag */
    TAR_EXLUDE,        /* X flag */
};

enum {
    ATTR_UNSET,
    ATTR_SET,
};

struct tar {
    /* include, include from file, exclude */
    enum tar_type_t type;

    /* size in bytes of a block in the tar file */
    int blocksize;

    /* flags */
    struct {
        bool hidden;      /* backup hidden file? */
        bool system;      /* backup system file? */
        bool incremental; /* backup _only_ archived file? */
        bool reset;       /* unset archive bit? */
        bool dry;         /* don't write tar file? */
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
    .type             = TAR_INCLUDE,
    .blocksize        = 20,
    .mode.hidden      = True,
    .mode.system      = True,
    .mode.incremental = False,
    .mode.dry         = False,
};


/****************************************************************************
Blocksize command
***************************************************************************/

int cmd_block(void)
{
    /* XXX: from client.c */
    const extern char *cmd_ptr;
    char *buf;
    int size;
    TALLOC_CTX *ctx = talloc_tos();

    if (!next_token_talloc(ctx, &cmd_ptr, &buf, NULL)) {
        DEBUG(0, ("blocksize <n>\n"));
        return 1;
    }

    size = atoi(buf);
    if (size < 0 || size > 65535) {
        DEBUG(0, ("blocksize out of range"));
        return 1;
    }

    tar_ctx.blocksize = size;
    DEBUG(2,("blocksize is now %d\n", size));

    return 0;
}

/****************************************************************************
command to set incremental / reset mode
***************************************************************************/

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


/****************************************************************************
Feeble attrib command
***************************************************************************/

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
    return 0;
}
