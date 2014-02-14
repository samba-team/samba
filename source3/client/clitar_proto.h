/*
 * Unix SMB/CIFS implementation.
 * Tar backup command extension
 * Copyright (C) Aurélien Aptel 2013
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CLITAR_PROTO_H_
#define _CLITAR_PROTO_H_

struct tar;

int cmd_block(void);
int cmd_tarmode(void);
int cmd_setmode(void);
int cmd_tar(void);
int tar_process(struct tar* tar);
int tar_parse_args(struct tar *tar, const char *flag, const char **val, int valsize);
bool tar_to_process(struct tar *tar);
struct tar *tar_get_ctx(void);

#endif /* _CLITAR_PROTO_H_ */
