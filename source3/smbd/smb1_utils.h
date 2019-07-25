/*
 * Unix SMB/CIFS implementation.
 * Util functions valid in the SMB1 server
 *
 * Copyright (C) Volker Lendecke 2019
 * Copyright by the authors of the functions moved here eventually
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SMBD_SMB1_UTILS_H__
#define __SMBD_SMB1_UTILS_H__

#include "includes.h"
#include "vfs.h"
#include "proto.h"

struct files_struct *fcb_or_dos_open(
	struct smb_request *req,
	const struct smb_filename *smb_fname,
	uint32_t access_mask,
	uint32_t create_options,
	uint32_t private_flags);

#endif
