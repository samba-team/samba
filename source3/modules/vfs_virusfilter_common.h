/*
   Samba-VirusFilter VFS modules
   Copyright (C) 2010-2016 SATOH Fumiyasu @ OSS Technology Corp., Japan

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

#ifndef _VIRUSFILTER_COMMON_H
#define _VIRUSFILTER_COMMON_H

#include <stdint.h>
#include <time.h>

/* Samba common include file */
#include "includes.h"

#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "system/filesys.h"
#include "transfer_file.h"
#include "auth.h"
#include "passdb.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "../lib/tsocket/tsocket.h"

/* Samba debug class for VIRUSFILTER */
#undef DBGC_CLASS
#define DBGC_CLASS virusfilter_debug_level
extern int virusfilter_debug_level;

/* Samba's global variable */
extern userdom_struct current_user_info;

#define VIRUSFILTER_VERSION "0.1.5"

/* ====================================================================== */

typedef enum {
	VIRUSFILTER_ACTION_DO_NOTHING,
	VIRUSFILTER_ACTION_QUARANTINE,
	VIRUSFILTER_ACTION_RENAME,
	VIRUSFILTER_ACTION_DELETE,
} virusfilter_action;

typedef enum {
	VIRUSFILTER_RESULT_OK,
	VIRUSFILTER_RESULT_CLEAN,
	VIRUSFILTER_RESULT_ERROR,
	VIRUSFILTER_RESULT_INFECTED,
#ifdef VIRUSFILTER_DEFAULT_BLOCK_SUSPECTED_FILE
	VIRUSFILTER_RESULT_SUSPECTED,
#endif
	/* FIXME: VIRUSFILTER_RESULT_RISKWARE, */
} virusfilter_result;

#endif /* _VIRUSFILTER_COMMON_H */

