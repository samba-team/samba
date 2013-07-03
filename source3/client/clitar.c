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

/* XXX: used in client.c, we have to export it for now */
char tar_type = 0;

enum tar_type_t {
    TAR_INCLUDE,       /* I flag, default */
    TAR_INCLUDE_FILE,  /* F flag */
    TAR_EXLUDE,        /* X flag */
};

typedef struct {
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
    } mode;

    /* path to tar archive name */
    char *tar_path;

    /* path to file list (F flag) */
    char *list_path
} tar_ctx_t;

static tar_ctx_t tar_ctx;

static void tar_set_default (tar_ctx_t* t)
{
    memset(t, 0, sizeof(*t));

    t->type             = TAR_INCLUDE;
    t->blocksize        = 20;
    t->mode.hidden      = True;
    t->mode.system      = True;
    t->mode.incremental = False;
    t->mode.dry         = False;
}


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
    return 0;
}

/****************************************************************************
Feeble attrib command
***************************************************************************/

int cmd_setmode(void)
{
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
