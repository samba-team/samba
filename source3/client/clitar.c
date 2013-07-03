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

char tar_type = 0;

typedef struct {
    /*
      size in bytes of a block in the tar file
      XXX: obsolete
    */
    size_t blocksize;
} tar_ctx_t;

/*
 * samba interactive commands
 */

/****************************************************************************
Blocksize command
***************************************************************************/

int cmd_block(void)
{

}

/****************************************************************************
command to set incremental / reset mode
***************************************************************************/

int cmd_tarmode(void)
{

}

/****************************************************************************
Feeble attrib command
***************************************************************************/

int cmd_setmode(void)
{

}


/****************************************************************************
Principal command for creating / extracting
***************************************************************************/

int cmd_tar(void)
{

}

/****************************************************************************
Command line (option) version
***************************************************************************/

int process_tar(void)
{

}

/****************************************************************************
Parse tar arguments. Sets tar_type, tar_excl, etc.
***************************************************************************/

int tar_parseargs(int argc, char *argv[], const char *Optarg, int Optind)
{

}
