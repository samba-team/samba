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

typedef struct creg_block {
	DWORD CREG_ID;		/* CREG */
	DWORD uk1;
	DWORD rgdb_offset;
	DWORD chksum;
	WORD  num_rgdb;
	WORD  flags;
	DWORD uk2;
	DWORD uk3;
	DWORD uk4;
} CREG_HDR;

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
	DWORD type;
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
	DWORD type;
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

typedef struct creg_struct_s {
	int fd;
	BOOL modified;
	char *base;
	struct stat sbuf;
	CREG_HDR *creg_hdr;
	RGKN_HDR *rgkn_hdr;
	char *rgkn;
} CREG;

static DWORD str_to_dword(const char *a) {
    int i;
    unsigned long ret = 0;
    for(i = strlen(a)-1; i >= 0; i--) {
        ret = ret * 0x100 + a[i];
    }
    return ret;
}

#define LOCN(creg, o) (((creg)->base + sizeof(CREG_HDR) + o))

static WERROR w95_open_reg (REG_HANDLE *h, const char *location, const char *credentials)
{
	CREG *creg = talloc_p(h->mem_ctx, CREG);
	DWORD creg_id, rgkn_id;
	memset(creg, 0, sizeof(CREG));
	h->backend_data = creg;
	DWORD i, nfree = 0;
	DWORD offset;

	if((creg->fd = open(location, O_RDONLY, 0000)) < 0) {
		return WERR_FOOBAR;
	}

    if (fstat(creg->fd, &creg->sbuf) < 0) {
		return WERR_FOOBAR;
    }

    creg->base = mmap(0, creg->sbuf.st_size, PROT_READ, MAP_SHARED, creg->fd, 0);
                                                                                                                                              
    if ((int)creg->base == 1) {
		DEBUG(0,("Could not mmap file: %s, %s\n", location, strerror(errno)));
        return WERR_FOOBAR;
    }

	creg->creg_hdr = (CREG_HDR *)creg->base;

	if ((creg_id = IVAL(&creg->creg_hdr->CREG_ID,0)) != str_to_dword("CREG")) {
		DEBUG(0, ("Unrecognized Windows 95 registry header id: 0x%0X, %s\n", 
				  creg_id, location));
		return WERR_FOOBAR;
	}

	creg->rgkn_hdr = (RGKN_HDR *)LOCN(creg, 0);

	if ((rgkn_id = IVAL(&creg->rgkn_hdr->RGKN_ID,0)) != str_to_dword("RGKN")) {
		DEBUG(0, ("Unrecognized Windows 95 registry key index id: 0x%0X, %s\n", 
				  rgkn_id, location));
		return WERR_FOOBAR;
	}

#if 0 
	for(i = 0; i < creg->rgkn_hdr->size; i+=sizeof(RGKN_KEY)) {
		RGKN_KEY *key = (RGKN_KEY *)LOCN(creg, sizeof(RGKN_HDR) + i);
		if(nfree > 0) {
			nfree--;
		} else if(key->type == 0) {
			DEBUG(0,("Not used\n"));
			/* Not used */
		} else if(key->type == 0x80000000) {
			DEBUG(0,("Regular key\n"));
			/* Regular key */
		} else {
			DEBUG(0,("Invalid key type in RGKN: %0X\n", key->type));
		}
	}

	curpos += creg->rgkn_hdr->size + sizeof(RGKN_HDR);
#endif
	offset = creg->rgkn_hdr->size;

	DEBUG(0, ("Reading %d rgdb entries\n", creg->creg_hdr->num_rgdb));
	for(i = 0; i < creg->creg_hdr->num_rgdb; i++) {
		RGDB_HDR *rgdb_hdr = (RGDB_HDR *)LOCN(creg, offset);
		
		if(strncmp((char *)&(rgdb_hdr->RGDB_ID), "RGDB", 4)) {
			DEBUG(0, ("unrecognized rgdb entry: %4s, %s\n", 
					  &rgdb_hdr->RGDB_ID, location));
			return WERR_FOOBAR;
		} else {
			DEBUG(0, ("Valid rgdb entry\n"));
		}

		offset+=rgdb_hdr->size;
	}
	

	return WERR_OK;
}

static WERROR w95_close_reg(REG_HANDLE *h)
{
	CREG *creg = h->backend_data;
	if (creg->base) munmap(creg->base, creg->sbuf.st_size);
	creg->base = NULL;
    close(creg->fd);
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
