/*
   Samba Unix/Linux SMB client utility libeditreg.c 
   Copyright (C) 2004 Jelmer Vernooij, jelmer@samba.org

   Backend for Windows '95 registry files. Explanation of file format 
   comes from http://www.cs.mun.ca/~michael/regutils/.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include "includes.h"
#include "lib/registry/common/registry.h"

/**
 * The registry starts with a header that contains pointers to 
 * the rgdb.
 *
 * After the main header follows the RGKN header (key index table) */

typedef unsigned int DWORD;
typedef unsigned short WORD;

typedef struct regc_block {
	DWORD REGC_ID;		/* REGC */
	DWORD uk1;
	DWORD rgdb_offset;
	DWORD chksum;
	WORD  num_rgdb;
	WORD  flags;
	DWORD  uk2;
	DWORD  uk3;
	DWORD  uk4;
	DWORD  uk5;
} REGC_HDR;

typedef struct rgkn_block {
	DWORD RGKN_ID; 		/* RGKN */
	DWORD size;
	DWORD root_offset;
	DWORD free_offset;
	DWORD flags;
	DWORD chksum;
	DWORD uk1;
	DWORD uk2;
} RGKN_HDR;

typedef struct rgkn_key {
	DWORD inuse;
	DWORD hash;
	DWORD next_free;
	DWORD parent;
	DWORD child;
	DWORD next;
	WORD id;
	WORD rgdb;
} RGKN_KEY;

typedef struct rgdb_block {
	DWORD RGDB_ID;		/* RGDB */
	DWORD size;
	DWORD unused_size;
	WORD flags;
	WORD section;
	DWORD free_offset;	/* -1 if there is no free space */
	WORD max_id;
	WORD first_free_id;
	DWORD uk1;
	DWORD chksum;
} RGDB_HDR;

typedef struct rgdb_key {
	DWORD inuse;
	DWORD hash;
	DWORD next_free;
	DWORD parent;
	DWORD child;
	DWORD next;
	WORD id;
	WORD rgdb;
} RGDB_KEY;

typedef struct rgdb_value {
	DWORD type;
	DWORD uk1;
	DWORD name_len;
	DWORD data_len;
} RGDB_VALUE;

typedef struct regc_struct_s {
	int fd;
	struct stat sbuf;
	BOOL modified;
	char *base;
} REGC;

static WERROR w95_open_reg (REG_HANDLE *h, const char *location, const char *credentials)
{
	REGC *regc = talloc_p(h->mem_ctx, REGC);
	REGC_HDR *regc_hdr;
	RGKN_HDR *rgkn_hdr;
	DWORD regc_id, rgkn_id;
	memset(regc, 0, sizeof(REGC));
	h->backend_data = regc;

	if((regc->fd = open(location, O_RDONLY, 0000)) < 0) {
		return WERR_FOOBAR;
	}

	if(fstat(regc->fd, &regc->sbuf) < 0) {
		return WERR_FOOBAR;
	}

	regc->base = mmap(0, regc->sbuf.st_size, PROT_READ, MAP_SHARED, regc->fd, 0);
	regc_hdr = (REGC_HDR *)regc->base;

	if ((int)regc->base == 1) {
		return WERR_FOOBAR;
	}
	
	if ((regc_id = IVAL(&regc_hdr->REGC_ID,0)) != str_to_dword("REGC")) {
		DEBUG(0, ("Unrecognized Windows 95 registry header id: %0X, %s\n", 
				  regc_id, location));
		return WERR_FOOBAR;
	}

	rgkn_hdr = (RGKN_HDR *)regc->base + sizeof(REGC_HDR);

	if ((rgkn_id = IVAL(&rgkn_hdr->RGKN_ID,0)) != str_to_dword("RGKN")) {
		DEBUG(0, ("Unrecognized Windows 95 registry key index id: %0X, %s\n", 
				  rgkn_id, location));
		return WERR_FOOBAR;
	}

	//rgkn = (RGKN_KEY *)regc->base + sizeof(REGC_HDR) + sizeof(RGKN_HDR);

	/* FIXME */

	return WERR_OK;
}

static WERROR w95_close_reg(REG_HANDLE *h)
{
	REGC *regc = h->backend_data;
    if (regc->base) munmap(regc->base, regc->sbuf.st_size);
    regc->base = NULL;
    close(regc->fd);
	return WERR_OK;
}

static struct registry_ops reg_backend_w95 = {
	.name = "w95",
	.open_registry = w95_open_reg,
	.close_registry = w95_close_reg,
};

NTSTATUS reg_w95_init(void)
{
	return register_backend("registry", &reg_backend_w95);
}
