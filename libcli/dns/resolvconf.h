/*
 *  Unix SMB/CIFS implementation.
 *  Internal DNS query structures
 *  Copyright (C) Volker Lendecke 2018
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIBCLI_DNS_RESOLVCONF_H__
#define __LIBCLI_DNS_RESOLVCONF_H__

#include <talloc.h>
#include <stdio.h>

int parse_resolvconf_fp(
	FILE *fp,
	TALLOC_CTX *mem_ctx,
	char ***pnameservers,
	size_t *pnum_nameservers);
int parse_resolvconf(
	const char *resolvconf,
	TALLOC_CTX *mem_ctx,
	char ***pnameservers,
	size_t *pnum_nameservers);

#endif
