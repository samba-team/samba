/*
   Samba Unix/Linux SMB client utility libeditreg.c 
   Copyright (C) 2002 Richard Sharpe, rsharpe@richardsharpe.com
   Copyright (C) 2003-2004 Jelmer Vernooij, jelmer@samba.org

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
 
/*************************************************************************
                                                       
 A utility to edit a Windows NT/2K etc registry file.
                                     
 Many of the ideas in here come from other people and software. 
 I first looked in Wine in misc/registry.c and was also influenced by
 http://www.wednesday.demon.co.uk/dosreg.html

 Which seems to contain comments from someone else. I reproduce them here
 incase the site above disappears. It actually comes from 
 http://home.eunet.no/~pnordahl/ntpasswd/WinReg.txt. 

 The goal here is to read the registry into memory, manipulate it, and then
 write it out if it was changed by any actions of the user.

The windows NT registry has 2 different blocks, where one can occur many
times...

the "regf"-Block
================
 
"regf" is obviously the abbreviation for "Registry file". "regf" is the
signature of the header-block which is always 4kb in size, although only
the first 64 bytes seem to be used and a checksum is calculated over
the first 0x200 bytes only!

Offset            Size      Contents
0x00000000      D-Word      ID: ASCII-"regf" = 0x66676572
0x00000004      D-Word      ???? //see struct REG_HANDLE
0x00000008      D-Word      ???? Always the same value as at 0x00000004
0x0000000C      Q-Word      last modify date in WinNT date-format
0x00000014      D-Word      1
0x00000018      D-Word      3
0x0000001C      D-Word      0
0x00000020      D-Word      1
0x00000024      D-Word      Offset of 1st key record
0x00000028      D-Word      Size of the data-blocks (Filesize-4kb)
0x0000002C      D-Word      1
0x000001FC      D-Word      Sum of all D-Words from 0x00000000 to
0x000001FB  //XOR of all words. Nigel

I have analyzed more registry files (from multiple machines running
NT 4.0 german version) and could not find an explanation for the values
marked with ???? the rest of the first 4kb page is not important...

the "hbin"-Block
================
I don't know what "hbin" stands for, but this block is always a multiple
of 4kb in size.

Inside these hbin-blocks the different records are placed. The memory-
management looks like a C-compiler heap management to me...

hbin-Header
===========
Offset      Size      Contents
0x0000      D-Word      ID: ASCII-"hbin" = 0x6E696268
0x0004      D-Word      Offset from the 1st hbin-Block
0x0008      D-Word      Offset to the next hbin-Block
0x001C      D-Word      Block-size

The values in 0x0008 and 0x001C should be the same, so I don't know
if they are correct or swapped...

From offset 0x0020 inside a hbin-block data is stored with the following
format:

Offset      Size      Contents
0x0000      D-Word      Data-block size    //this size must be a
multiple of 8. Nigel
0x0004      ????      Data
 
If the size field is negative (bit 31 set), the corresponding block
is free and has a size of -blocksize!

That does not seem to be true. All block lengths seem to be negative! 
(Richard Sharpe) 

The data is stored as one record per block. Block size is a multiple
of 4 and the last block reaches the next hbin-block, leaving no room.

(That also seems incorrect, in that the block size if a multiple of 8.
That is, the block, including the 4 byte header, is always a multiple of
8 bytes. Richard Sharpe.)

Records in the hbin-blocks
==========================

nk-Record

      The nk-record can be treated as a combination of tree-record and
      key-record of the win 95 registry.

lf-Record

      The lf-record is the counterpart to the RGKN-record (the
      hash-function)

vk-Record

      The vk-record consists information to a single value (value key).

sk-Record

      sk (? Security Key ?) is the ACL of the registry.

Value-Lists

      The value-lists contain information about which values are inside a
      sub-key and don't have a header.

Datas

      The datas of the registry are (like the value-list) stored without a
      header.

All offset-values are relative to the first hbin-block and point to the
block-size field of the record-entry. to get the file offset, you have to add
the header size (4kb) and the size field (4 bytes)...

the nk-Record
=============
Offset      Size      Contents
0x0000      Word      ID: ASCII-"nk" = 0x6B6E
0x0002      Word      for the root-key: 0x2C, otherwise 0x20  //key symbolic links 0x10. Nigel
0x0004      Q-Word      write-date/time in windows nt notation
0x0010      D-Word      Offset of Owner/Parent key
0x0014      D-Word      number of sub-Keys
0x001C      D-Word      Offset of the sub-key lf-Records
0x0024      D-Word      number of values
0x0028      D-Word      Offset of the Value-List
0x002C      D-Word      Offset of the sk-Record

0x0030      D-Word      Offset of the Class-Name //see NK structure for the use of these fields. Nigel
0x0044      D-Word      Unused (data-trash)  //some kind of run time index. Does not appear to be important. Nigel
0x0048      Word      name-length
0x004A      Word      class-name length
0x004C      ????      key-name

the Value-List
==============
Offset      Size      Contents
0x0000      D-Word      Offset 1st Value
0x0004      D-Word      Offset 2nd Value
0x????      D-Word      Offset nth Value

To determine the number of values, you have to look at the owner-nk-record!

The vk-Record
=============
Offset      Size      Contents
0x0000      Word      ID: ASCII-"vk" = 0x6B76
0x0002      Word      name length
0x0004      D-Word      length of the data   //if top bit is set when offset contains data. Nigel
0x0008      D-Word      Offset of Data
0x000C      D-Word      Type of value
0x0010      Word      Flag
0x0012      Word      Unused (data-trash)
0x0014      ????      Name

If bit 0 of the flag-word is set, a name is present, otherwise the value has no name (=default)

If the data-size is lower 5, the data-offset value is used to store the data itself!

The data-types
==============
Wert      Beteutung
0x0001      RegSZ:             character string (in UNICODE!)
0x0002      ExpandSZ:   string with "%var%" expanding (UNICODE!)
0x0003      RegBin:           raw-binary value
0x0004      RegDWord:   Dword
0x0007      RegMultiSZ:      multiple strings, seperated with 0
                  (UNICODE!)

The "lf"-record
===============
Offset      Size      Contents
0x0000      Word      ID: ASCII-"lf" = 0x666C
0x0002      Word      number of keys
0x0004      ????      Hash-Records

Hash-Record
===========
Offset      Size      Contents
0x0000      D-Word      Offset of corresponding "nk"-Record
0x0004      D-Word      ASCII: the first 4 characters of the key-name, padded with 0's. Case sensitiv!

Keep in mind, that the value at 0x0004 is used for checking the data-consistency! If you change the 
key-name you have to change the hash-value too!

//These hashrecords must be sorted low to high within the lf record. Nigel.

The "sk"-block
==============
(due to the complexity of the SAM-info, not clear jet)
(This is just a self-relative security descriptor in the data. R Sharpe.) 


Offset      Size      Contents
0x0000      Word      ID: ASCII-"sk" = 0x6B73
0x0002      Word      Unused
0x0004      D-Word      Offset of previous "sk"-Record
0x0008      D-Word      Offset of next "sk"-Record
0x000C      D-Word      usage-counter
0x0010      D-Word      Size of "sk"-record in bytes
????                                             //standard self
relative security desciptor. Nigel
????  ????      Security and auditing settings...
????

The usage counter counts the number of references to this
"sk"-record. You can use one "sk"-record for the entire registry!

Windows nt date/time format
===========================
The time-format is a 64-bit integer which is incremented every
0,0000001 seconds by 1 (I don't know how accurate it realy is!)
It starts with 0 at the 1st of january 1601 0:00! All values are
stored in GMT time! The time-zone is important to get the real
time!

Common values for win95 and win-nt
==================================
Offset values marking an "end of list", are either 0 or -1 (0xFFFFFFFF).
If a value has no name (length=0, flag(bit 0)=0), it is treated as the
"Default" entry...
If a value has no data (length=0), it is displayed as empty.

simplyfied win-3.?? registry:
=============================

+-----------+
| next rec. |---+                      +----->+------------+
| first sub |   |                      |      | Usage cnt. |
| name      |   |  +-->+------------+  |      | length     |
| value     |   |  |   | next rec.  |  |      | text       |------->+-------+
+-----------+   |  |   | name rec.  |--+      +------------+        | xxxxx |
   +------------+  |   | value rec. |-------->+------------+        +-------+
   v               |   +------------+         | Usage cnt. |
+-----------+      |                          | length     |
| next rec. |      |                          | text       |------->+-------+
| first sub |------+                          +------------+        | xxxxx |
| name      |                                                       +-------+
| value     |
+-----------+    

Greatly simplyfied structure of the nt-registry:
================================================
   
+---------------------------------------------------------------+
|                                                               |
v                                                               |
+---------+     +---------->+-----------+  +----->+---------+   |
| "nk"    |     |           | lf-rec.   |  |      | nk-rec. |   |
| ID      |     |           | # of keys |  |      | parent  |---+
| Date    |     |           | 1st key   |--+      | ....    |
| parent  |     |           +-----------+         +---------+
| suk-keys|-----+
| values  |--------------------->+----------+
| SK-rec. |---------------+      | 1. value |--> +----------+
| class   |--+            |      +----------+    | vk-rec.  |
+---------+  |            |                      | ....     |
             v            |                      | data     |--> +-------+
      +------------+      |                      +----------+    | xxxxx |
      | Class name |      |                                      +-------+
      +------------+      |
                          v
          +---------+    +---------+
   +----->| next sk |--->| Next sk |--+
   |  +---| prev sk |<---| prev sk |  |
   |  |   | ....    |    | ...     |  |
   |  |   +---------+    +---------+  |
   |  |                    ^          |
   |  |                    |          |
   |  +--------------------+          |
   +----------------------------------+

---------------------------------------------------------------------------

Hope this helps....  (Although it was "fun" for me to uncover this things,
                  it took me several sleepless nights ;)

            B.D.

*************************************************************************/

#include "includes.h"
#include "lib/registry/common/registry.h"

#define REG_KEY_LIST_SIZE 10
/*FIXME*/

/*
 * Structures for dealing with the on-disk format of the registry
 */

const char *def_owner_sid_str = NULL;

/* 
 * These definitions are for the in-memory registry structure.
 * It is a tree structure that mimics what you see with tools like regedit
 */


/*
 * Definition of a Key. It has a name, classname, date/time last modified,
 * sub-keys, values, and a security descriptor
 */

#define REG_ROOT_KEY 1
#define REG_SUB_KEY  2
#define REG_SYM_LINK 3

/* 
 * All of the structures below actually have a four-byte length before them
 * which always seems to be negative. The following macro retrieves that
 * size as an integer
 */

#define BLK_SIZE(b) ((int)*(int *)(((int *)b)-1))

typedef unsigned int DWORD;
typedef unsigned short WORD;

typedef struct sk_struct SK_HDR;
/*
 * This structure keeps track of the output format of the registry
 */
#define REG_OUTBLK_HDR 1
#define REG_OUTBLK_HBIN 2

typedef struct regf_block {
	DWORD REGF_ID;     /* regf */
	DWORD uk1;
	DWORD uk2;
	DWORD tim1, tim2;
	DWORD uk3;             /* 1 */
	DWORD uk4;             /* 3 */
	DWORD uk5;             /* 0 */
	DWORD uk6;             /* 1 */
	DWORD first_key;       /* offset */
	unsigned int dblk_size;
    DWORD uk7[116];        /* 1 */
    DWORD chksum;
} REGF_HDR;

typedef struct hbin_sub_struct {
	DWORD dblocksize;
	char data[1];
} HBIN_SUB_HDR;

typedef struct hbin_struct {
	DWORD HBIN_ID; /* hbin */
	DWORD off_from_first;
	DWORD off_to_next;
	DWORD uk1;
	DWORD uk2;
	DWORD uk3;
	DWORD uk4;
	DWORD blk_size;
	HBIN_SUB_HDR hbin_sub_hdr;
} HBIN_HDR;

typedef struct nk_struct {
	WORD NK_ID;
	WORD type;
	DWORD t1, t2;
	DWORD uk1;
	DWORD own_off;
	DWORD subk_num;
	DWORD uk2;
	DWORD lf_off;
	DWORD uk3;
	DWORD val_cnt;
	DWORD val_off;
	DWORD sk_off;
	DWORD clsnam_off;
	DWORD unk4[4];
	DWORD unk5;
	WORD nam_len;
	WORD clsnam_len;
	char key_nam[1];  /* Actual length determined by nam_len */
} NK_HDR;

struct sk_struct {
	WORD SK_ID;
	WORD uk1;
	DWORD prev_off;
	DWORD next_off;
	DWORD ref_cnt;
	DWORD rec_size;
	char sec_desc[1];
};

typedef struct key_sec_desc_s {
	struct key_sec_desc_s *prev, *next;
	int ref_cnt;
	int state;
	int offset;
	SK_HDR *sk_hdr;     /* This means we must keep the registry in memory */
	SEC_DESC *sec_desc;
} KEY_SEC_DESC; 

/* A map of sk offsets in the regf to KEY_SEC_DESCs for quick lookup etc */
typedef struct sk_map_s {
  int sk_off;
  KEY_SEC_DESC *key_sec_desc;
} SK_MAP;

typedef struct vk_struct {
  WORD VK_ID;
  WORD nam_len;
  DWORD dat_len;    /* If top-bit set, offset contains the data */
  DWORD dat_off;
  DWORD dat_type;
  WORD flag;        /* =1, has name, else no name (=Default). */
  WORD unk1;
  char dat_name[1]; /* Name starts here ... */
} VK_HDR;

typedef DWORD VL_TYPE[1];  /* Value list is an array of vk rec offsets */
                                                                                
typedef struct hash_struct {
  DWORD nk_off;
  char hash[4];
} HASH_REC;


typedef struct lf_struct {
  WORD LF_ID;
  WORD key_count;
  struct hash_struct hr[1];  /* Array of hash records, depending on key_count */} LF_HDR;



/*
 * This structure keeps track of the output format of the registry
 */
#define REG_OUTBLK_HDR 1
#define REG_OUTBLK_HBIN 2

typedef struct hbin_blk_s {
  int type, size;
  struct hbin_blk_s *next;
  char *data;                /* The data block                */
  unsigned int file_offset;  /* Offset in file                */
  unsigned int free_space;   /* Amount of free space in block */
  unsigned int fsp_off;      /* Start of free space in block  */
  int complete, stored;
} HBIN_BLK;

typedef struct regf_struct_s {
	int reg_type;
	int fd;
	struct stat sbuf;
	char *base;
	BOOL modified;
	NTTIME last_mod_time;
	NK_HDR *first_key;
	int sk_count, sk_map_size;
	SK_MAP *sk_map;
	const char *owner_sid_str;
	SEC_DESC *def_sec_desc;
	/*
	 * These next pointers point to the blocks used to contain the 
	 * keys when we are preparing to write them to a file
	 */
	HBIN_BLK *blk_head, *blk_tail, *free_space;
} REGF;

static DWORD str_to_dword(const char *a) {
	int i;
	unsigned long ret = 0;
	for(i = strlen(a)-1; i >= 0; i--) {
		ret = ret * 0x100 + a[i];
	}
	return ret;
}

#if 0

/*
 * Create an ACE
 */
static BOOL nt_create_ace(SEC_ACE *ace, int type, int flags, uint32 perms, const char *sid)
{
  DOM_SID s;
  SEC_ACCESS access;
  access.mask = perms;
  if(!string_to_sid(&s, sid))return False;
  init_sec_ace(ace, &s, type, access, flags);
  return True;
}

/*
 * Create a default ACL
 */
static SEC_ACL *nt_create_default_acl(REG_HANDLE *regf)
{
  SEC_ACE aces[8];

  if(!nt_create_ace(&aces[0], 0x00, 0x0, 0xF003F, regf->owner_sid_str)) return NULL;
  if(!nt_create_ace(&aces[1], 0x00, 0x0, 0xF003F, "S-1-5-18")) return NULL;
  if(!nt_create_ace(&aces[2], 0x00, 0x0, 0xF003F, "S-1-5-32-544")) return NULL;
  if(!nt_create_ace(&aces[3], 0x00, 0x0, 0x20019, "S-1-5-12")) return NULL;
  if(!nt_create_ace(&aces[4], 0x00, 0x0B, GENERIC_RIGHT_ALL_ACCESS, regf->owner_sid_str)) return NULL;
  if(!nt_create_ace(&aces[5], 0x00, 0x0B, 0x10000000, "S-1-5-18")) return NULL;
  if(!nt_create_ace(&aces[6], 0x00, 0x0B, 0x10000000, "S-1-5-32-544")) return NULL;
  if(!nt_create_ace(&aces[7], 0x00, 0x0B, 0x80000000, "S-1-5-12")) return NULL;

  return make_sec_acl(regf->mem_ctx, 2, 8, aces);
}

/*
 * Create a default security descriptor. We pull in things from env
 * if need be 
 */
static SEC_DESC *nt_create_def_sec_desc(REG_HANDLE *regf)
{
  SEC_DESC *tmp;

  tmp = (SEC_DESC *)malloc(sizeof(SEC_DESC));

  tmp->revision = 1;
  tmp->type = SEC_DESC_SELF_RELATIVE | SEC_DESC_DACL_PRESENT;
  if (!string_to_sid(tmp->owner_sid, "S-1-5-32-544")) goto error;
  if (!string_to_sid(tmp->grp_sid, "S-1-5-18")) goto error;
  tmp->sacl = NULL;
  tmp->dacl = nt_create_default_acl(regf);

  return tmp;

 error:
  if (tmp) nt_delete_sec_desc(tmp);
  return NULL;
}

/*
 * We will implement inheritence that is based on what the parent's SEC_DESC
 * says, but the Owner and Group SIDs can be overwridden from the command line
 * and additional ACEs can be applied from the command line etc.
 */
static KEY_SEC_DESC *nt_inherit_security(REG_KEY *key)
{

  if (!key) return NULL;
  return key->security;
}

/*
 * Create an initial security descriptor and init other structures, if needed
 * We assume that the initial security stuff is empty ...
 */
static KEY_SEC_DESC *nt_create_init_sec(REG_HANDLE *h)
{
	REGF *regf = h->backend_data;
	KEY_SEC_DESC *tsec = NULL;

	tsec = (KEY_SEC_DESC *)malloc(sizeof(KEY_SEC_DESC));

	tsec->ref_cnt = 1;
	tsec->state = SEC_DESC_NBK;
	tsec->offset = 0;

	tsec->sec_desc = regf->def_sec_desc;

	return tsec;
}
#endif

/*
 * Get the starting record for NT Registry file 
 */

/* 
 * Where we keep all the regf stuff for one registry.
 * This is the structure that we use to tie the in memory tree etc 
 * together. By keeping separate structs, we can operate on different
 * registries at the same time.
 * Currently, the SK_MAP is an array of mapping structure.
 * Since we only need this on input and output, we fill in the structure
 * as we go on input. On output, we know how many SK items we have, so
 * we can allocate the structure as we need to.
 * If you add stuff here that is dynamically allocated, add the 
 * appropriate free statements below.
 */

#define REG_HANDLE_REGTYPE_NONE 0
#define REG_HANDLE_REGTYPE_NT   1
#define REG_HANDLE_REGTYPE_W9X  2

#define TTTONTTIME(r, t1, t2) (r)->last_mod_time.low = (t1); \
                              (r)->last_mod_time.high = (t2);

#define REGF_HDR_BLKSIZ 0x1000 

#define OFF(f) ((f) + REGF_HDR_BLKSIZ + 4) 
#define LOCN(base, f) ((base) + OFF(f))

/* Get the header of the registry. Return a pointer to the structure 
 * If the mmap'd area has not been allocated, then mmap the input file
 */
static REGF_HDR *nt_get_regf_hdr(REG_HANDLE *h)
{
	REGF *regf = h->backend_data;
	SMB_REG_ASSERT(regf);

	if (!regf->base) { /* Try to mmap etc the file */

		if ((regf->fd = open(h->location, O_RDONLY, 0000)) <0) {
			return NULL; /* What about errors? */
		}

		if (fstat(regf->fd, &regf->sbuf) < 0) {
			return NULL;
		}

		regf->base = mmap(0, regf->sbuf.st_size, PROT_READ, MAP_SHARED, regf->fd, 0);

		if ((int)regf->base == 1) {
			DEBUG(0,("Could not mmap file: %s, %s\n", h->location,
					 strerror(errno)));
			return NULL;
		}
	}

	/* 
	 * At this point, regf->base != NULL, and we should be able to read the 
	 * header 
	 */

	SMB_REG_ASSERT(regf->base != NULL);

	return (REGF_HDR *)regf->base;
}

/*
 * Validate a regf header
 * For now, do nothing, but we should check the checksum
 */
static int valid_regf_hdr(REGF_HDR *regf_hdr)
{
	if (!regf_hdr) return 0;

	return 1;
}

#if 0

/*
 * Process an SK header ...
 * Every time we see a new one, add it to the map. Otherwise, just look it up.
 * We will do a simple linear search for the moment, since many KEYs have the 
 * same security descriptor. 
 * We allocate the map in increments of 10 entries.
 */

/*
 * Create a new entry in the map, and increase the size of the map if needed
 */
static SK_MAP *alloc_sk_map_entry(REG_HANDLE *h, KEY_SEC_DESC *tmp, int sk_off)
{
	REGF *regf = h->backend_data;
	if (!regf->sk_map) { /* Allocate a block of 10 */
		regf->sk_map = (SK_MAP *)malloc(sizeof(SK_MAP) * 10);
		regf->sk_map_size = 10;
		regf->sk_count = 1;
		(regf->sk_map)[0].sk_off = sk_off;
		(regf->sk_map)[0].key_sec_desc = tmp;
	}
	else { /* Simply allocate a new slot, unless we have to expand the list */ 
		int ndx = regf->sk_count;
		if (regf->sk_count >= regf->sk_map_size) {
			regf->sk_map = (SK_MAP *)realloc(regf->sk_map, 
											 (regf->sk_map_size + 10)*sizeof(SK_MAP));
			if (!regf->sk_map) {
				free(tmp);
				return NULL;
			}
			/*
			 * ndx already points at the first entry of the new block
			 */
			regf->sk_map_size += 10;
		}
		(regf->sk_map)[ndx].sk_off = sk_off;
		(regf->sk_map)[ndx].key_sec_desc = tmp;
		regf->sk_count++;
	}
	return regf->sk_map;
}

/*
 * Search for a KEY_SEC_DESC in the sk_map, but don't create one if not
 * found
 */
KEY_SEC_DESC *lookup_sec_key(SK_MAP *sk_map, int count, int sk_off)
{
	int i;

	if (!sk_map) return NULL;

	for (i = 0; i < count; i++) {

		if (sk_map[i].sk_off == sk_off)
			return sk_map[i].key_sec_desc;

	}

	return NULL;

}

/*
 * Allocate a KEY_SEC_DESC if we can't find one in the map
 */
static KEY_SEC_DESC *lookup_create_sec_key(REG_HANDLE *h, SK_MAP *sk_map, int sk_off)
{
	REGF *regf = h->backend_data;
	KEY_SEC_DESC *tmp = lookup_sec_key(regf->sk_map, regf->sk_count, sk_off);

	if (tmp) {
		return tmp;
	}
	else { /* Allocate a new one */
		tmp = (KEY_SEC_DESC *)malloc(sizeof(KEY_SEC_DESC));
		memset(tmp, 0, sizeof(KEY_SEC_DESC)); /* Neatly sets offset to 0 */
		tmp->state = SEC_DESC_RES;
		if (!alloc_sk_map_entry(h, tmp, sk_off)) {
			return NULL;
		}
		return tmp;
	}
}

static SEC_DESC *process_sec_desc(REG_HANDLE *regf, SEC_DESC *sec_desc)
{
	SEC_DESC *tmp = NULL;

	tmp = (SEC_DESC *)malloc(sizeof(SEC_DESC));

	tmp->revision = SVAL(&sec_desc->revision,0);
	tmp->type = SVAL(&sec_desc->type,0);
	DEBUG(2, ("SEC_DESC Rev: %0X, Type: %0X\n", tmp->revision, tmp->type));
	DEBUGADD(2, ("SEC_DESC Owner Off: %0X\n", IVAL(&sec_desc->off_owner_sid,0)));
	DEBUGADD(2, ("SEC_DESC Group Off: %0X\n", IVAL(&sec_desc->off_grp_sid,0)));
	DEBUGADD(2, ("SEC_DESC DACL Off: %0X\n", IVAL(&sec_desc->off_dacl,0)));
	tmp->owner_sid = sid_dup_talloc(regf->mem_ctx, (DOM_SID *)((char *)sec_desc + IVAL(&sec_desc->off_owner_sid,0)));
	if (!tmp->owner_sid) {
		free(tmp);
		return NULL;
	}
	tmp->grp_sid = sid_dup_talloc(regf->mem_ctx, (DOM_SID *)((char *)sec_desc + IVAL(&sec_desc->off_grp_sid,0)));
	if (!tmp->grp_sid) {
		free(tmp);
		return NULL;
	}

	/* Now pick up the SACL and DACL */

	DEBUG(0, ("%d, %d\n", IVAL(&sec_desc->off_sacl,0), IVAL(&sec_desc->off_dacl,0)));

	if (sec_desc->off_sacl)
		tmp->sacl = dup_sec_acl(regf->mem_ctx, (SEC_ACL *)((char *)sec_desc + IVAL(&sec_desc->off_sacl,0)));
	else
		tmp->sacl = NULL;

	if (sec_desc->off_dacl)
		tmp->dacl = dup_sec_acl(regf->mem_ctx, (SEC_ACL *)((char *)sec_desc + IVAL(&sec_desc->off_dacl,0)));
	else
		tmp->dacl = NULL;

	return tmp;
}

static KEY_SEC_DESC *process_sk(REG_HANDLE *regf, SK_HDR *sk_hdr, int sk_off, int size)
{
	KEY_SEC_DESC *tmp = NULL;
	int sk_next_off, sk_prev_off, sk_size;
	SEC_DESC *sec_desc;

	if (!sk_hdr) return NULL;

	if (SVAL(&sk_hdr->SK_ID,0) != str_to_dword("sk")) {
		DEBUG(0, ("Unrecognized SK Header ID: %08X, %s\n", (int)sk_hdr,
				  regf->regfile_name));
		return NULL;
	}

	if (-size < (sk_size = IVAL(&sk_hdr->rec_size,0))) {
		DEBUG(0, ("Incorrect SK record size: %d vs %d. %s\n",
				  -size, sk_size, regf->regfile_name));
		return NULL;
	}

	/* 
	 * Now, we need to look up the SK Record in the map, and return it
	 * Since the map contains the SK_OFF mapped to KEY_SEC_DESC, we can
	 * use that
	 */

	if (regf->sk_map &&
		((tmp = lookup_sec_key(regf->sk_map, regf->sk_count, sk_off)) != NULL)
		&& (tmp->state == SEC_DESC_OCU)) {
		tmp->ref_cnt++;
		return tmp;
	}

	/* Here, we have an item in the map that has been reserved, or tmp==NULL. */

	SMB_REG_ASSERT(tmp == NULL || (tmp && tmp->state != SEC_DESC_NON));

	/*
	 * Now, allocate a KEY_SEC_DESC, and parse the structure here, and add the
	 * new KEY_SEC_DESC to the mapping structure, since the offset supplied is 
	 * the actual offset of structure. The same offset will be used by
	 * all future references to this structure
	 * We could put all this unpleasantness in a function.
	 */

	if (!tmp) {
		tmp = (KEY_SEC_DESC *)malloc(sizeof(KEY_SEC_DESC));
		memset(tmp, 0, sizeof(KEY_SEC_DESC));

		/*
		 * Allocate an entry in the SK_MAP ...
		 * We don't need to free tmp, because that is done for us if the
		 * sm_map entry can't be expanded when we need more space in the map.
		 */

		if (!alloc_sk_map_entry(regf, tmp, sk_off)) {
			return NULL;
		}
	}

	tmp->ref_cnt++;
	tmp->state = SEC_DESC_OCU;

	/*
	 * Now, process the actual sec desc and plug the values in
	 */

	sec_desc = (SEC_DESC *)&sk_hdr->sec_desc[0];
	tmp->sec_desc = process_sec_desc(regf, sec_desc);

	/*
	 * Now forward and back links. Here we allocate an entry in the sk_map
	 * if it does not exist, and mark it reserved
	 */

	sk_prev_off = IVAL(&sk_hdr->prev_off,0);
	tmp->prev = lookup_create_sec_key(regf, regf->sk_map, sk_prev_off);
	SMB_REG_ASSERT(tmp->prev != NULL);
	sk_next_off = IVAL(&sk_hdr->next_off,0);
	tmp->next = lookup_create_sec_key(regf, regf->sk_map, sk_next_off);
	SMB_REG_ASSERT(tmp->next != NULL);

	return tmp;
}
#endif

/*
 * Process a VK header and return a value
 */
static WERROR vk_to_val(REG_KEY *parent, VK_HDR *vk_hdr, int size, REG_VAL **value)
{
	char val_name[1024];
	REGF *regf = parent->handle->backend_data;
	int nam_len, dat_len, flag, dat_type, dat_off, vk_id;
	REG_VAL *tmp = NULL; 

	if (!vk_hdr) return WERR_INVALID_PARAM;

	if ((vk_id = SVAL(&vk_hdr->VK_ID,0)) != str_to_dword("vk")) {
		DEBUG(0, ("Unrecognized VK header ID: %0X, block: %0X, %s\n",
				  vk_id, (int)vk_hdr, parent->handle->location));
		return WERR_GENERAL_FAILURE;
	}

	nam_len = SVAL(&vk_hdr->nam_len,0);
	val_name[nam_len] = '\0';
	flag = SVAL(&vk_hdr->flag,0);
	dat_type = IVAL(&vk_hdr->dat_type,0);
	dat_len = IVAL(&vk_hdr->dat_len,0);  /* If top bit, offset contains data */
	dat_off = IVAL(&vk_hdr->dat_off,0);

	tmp = reg_val_new(parent, NULL);
	tmp->has_name = flag;
	tmp->data_type = dat_type;

	if (flag & 0x01) {
		strncpy(val_name, vk_hdr->dat_name, nam_len);
		tmp->name = strdup(val_name);
	}
	else
		strncpy(val_name, "<No Name>", 10);

	/*
	 * Allocate space and copy the data as a BLOB
	 */

	if (dat_len&0x7FFFFFFF) {

		char *dtmp = (char *)malloc(dat_len&0x7FFFFFFF);

		tmp->data_blk = dtmp;

		if ((dat_len&0x80000000) == 0) { /* The data is pointed to by the offset */
			char *dat_ptr = LOCN(regf->base, dat_off);
			memcpy(dtmp, dat_ptr, dat_len);
		}
		else { /* The data is in the offset or type */
			/*
			 * FIXME.
			 * Some registry files seem to have weird fields. If top bit is set,
			 * but len is 0, the type seems to be the value ...
			 * Not sure how to handle this last type for the moment ...
			 */
			dat_len = dat_len & 0x7FFFFFFF;
			memcpy(dtmp, &dat_off, dat_len);
		}

		tmp->data_len = dat_len;
	}

	*value = tmp;
	return WERR_OK;
}

#if 0 /* unused */

static BOOL vl_verify(VL_TYPE vl, int count, int size)
{
	if(!vl) return False;
	if (-size < (count+1)*sizeof(int)){
		DEBUG(0, ("Error in VL header format. Size less than space required. %d\n", -size));
		return False;
	}
	return True;
}

#endif

static WERROR lf_verify(REG_HANDLE *h, LF_HDR *lf_hdr, int size)
{
	int lf_id;
	if ((lf_id = SVAL(&lf_hdr->LF_ID,0)) != str_to_dword("lf")) {
		DEBUG(0, ("Unrecognized LF Header format: %0X, Block: %0X, %s.\n",
				  lf_id, (int)lf_hdr, h->location));
		return WERR_INVALID_PARAM;
	}
	return WERR_OK;
}

static WERROR lf_num_entries(REG_HANDLE *h, LF_HDR *lf_hdr, int size, int *count)
{
	WERROR error;

	error = lf_verify(h, lf_hdr, size);
	if(!W_ERROR_IS_OK(error)) return error;

	SMB_REG_ASSERT(size < 0);

	*count = SVAL(&lf_hdr->key_count,0);
	DEBUG(2, ("Key Count: %u\n", *count));
	if (*count <= 0) return WERR_INVALID_PARAM;

	return WERR_OK;
}


static WERROR nk_to_key(REG_HANDLE *regf, NK_HDR *nk_hdr, int size, REG_KEY *parent, REG_KEY **);



/*
 * Process an LF Header and return a list of sub-keys
 */
static WERROR lf_get_entry(REG_KEY *parent, LF_HDR *lf_hdr, int size, int n, REG_KEY **key)
{
	REGF *regf = parent->handle->backend_data;
	int count, nk_off;
	NK_HDR *nk_hdr;
	WERROR error;

	if (!lf_hdr) return WERR_INVALID_PARAM;

	error = lf_verify(parent->handle, lf_hdr, size);
	if(!W_ERROR_IS_OK(error)) return error;

	SMB_REG_ASSERT(size < 0);

	count = SVAL(&lf_hdr->key_count,0);
	DEBUG(2, ("Key Count: %u\n", count));
	if (count <= 0) return WERR_GENERAL_FAILURE;
	if (n >= count) return WERR_NO_MORE_ITEMS;

	nk_off = IVAL(&lf_hdr->hr[n].nk_off,0);
	DEBUG(2, ("NK Offset: %0X\n", nk_off));
	nk_hdr = (NK_HDR *)LOCN(regf->base, nk_off);
	return nk_to_key(parent->handle, nk_hdr, BLK_SIZE(nk_hdr), parent, key);
}

static WERROR nk_to_key(REG_HANDLE *h, NK_HDR *nk_hdr, int size, REG_KEY *parent, REG_KEY **key)
{
	REGF *regf = h->backend_data;
	REG_KEY *tmp = NULL, *own;
	int namlen, clsname_len, sk_off, own_off;
	unsigned int nk_id;
	SK_HDR *sk_hdr;
	int type;
	char key_name[1024], cls_name[1024];

	if (!nk_hdr) return WERR_INVALID_PARAM;

	if ((nk_id = SVAL(&nk_hdr->NK_ID,0)) != str_to_dword("nk")) {
		DEBUG(0, ("Unrecognized NK Header format: %08X, Block: %0X. %s\n", 
				  nk_id, (int)nk_hdr, parent->handle->location));
		return WERR_INVALID_PARAM;
	}

	SMB_REG_ASSERT(size < 0);

	namlen = SVAL(&nk_hdr->nam_len,0);
	clsname_len = SVAL(&nk_hdr->clsnam_len,0);

	/*
	 * The value of -size should be ge 
	 * (sizeof(NK_HDR) - 1 + namlen)
	 * The -1 accounts for the fact that we included the first byte of 
	 * the name in the structure. clsname_len is the length of the thing 
	 * pointed to by clsnam_off
	 */

	if (-size < (sizeof(NK_HDR) - 1 + namlen)) {
		DEBUG(0, ("Incorrect NK_HDR size: %d, %0X\n", -size, (int)nk_hdr));
		DEBUG(0, ("Sizeof NK_HDR: %d, name_len %d, clsname_len %d\n",
				  sizeof(NK_HDR), namlen, clsname_len));
		return WERR_GENERAL_FAILURE;
	}

	DEBUG(2, ("NK HDR: Name len: %d, class name len: %d\n", namlen, clsname_len));

	/* Fish out the key name and process the LF list */

	SMB_REG_ASSERT(namlen < sizeof(key_name));

	strncpy(key_name, nk_hdr->key_nam, namlen);
	key_name[namlen] = '\0';

	type = (SVAL(&nk_hdr->type,0)==0x2C?REG_ROOT_KEY:REG_SUB_KEY);
	if(type == REG_ROOT_KEY && parent) {
		DEBUG(0,("Root key encountered below root level!\n"));
		return WERR_GENERAL_FAILURE;
	}

	if(type == REG_ROOT_KEY) tmp = reg_key_new_abs(key_name, h, nk_hdr);
	else tmp = reg_key_new_rel(key_name, parent, nk_hdr);

	DEBUG(2, ("Key name: %s\n", key_name));

	/*
	 * Fish out the class name, it is in UNICODE, while the key name is 
	 * ASCII :-)
	 */

	if (clsname_len) { /* Just print in Ascii for now */
		smb_ucs2_t *clsnamep;
		int clsnam_off;
		char *clsnameu;

		clsnam_off = IVAL(&nk_hdr->clsnam_off,0);
		clsnamep = (smb_ucs2_t *)LOCN(regf->base, clsnam_off);
		DEBUG(2, ("Class Name Offset: %0X\n", clsnam_off));

		clsnameu = acnv_u2ux(clsnamep);
		tmp->class_name = talloc_strdup(tmp->mem_ctx, clsnameu);
		SAFE_FREE(clsnameu);

		DEBUGADD(2,("  Class Name: %s\n", cls_name));

	}

	/*
	 * Process the owner offset ...
	 */

	own_off = IVAL(&nk_hdr->own_off,0);
	own = (REG_KEY *)LOCN(regf->base, own_off);
	DEBUG(2, ("Owner Offset: %0X\n", own_off));

	DEBUGADD(2, ("  Owner locn: %0X, Our locn: %0X\n", 
				 (unsigned int)own, (unsigned int)nk_hdr));

	/* 
	 * We should verify that the owner field is correct ...
	 * for now, we don't worry ...
	 */

	/* 
	 * Also handle the SK header ...
	 */

	sk_off = IVAL(&nk_hdr->sk_off,0);
	sk_hdr = (SK_HDR *)LOCN(regf->base, sk_off);
	DEBUG(2, ("SK Offset: %0X\n", sk_off));

	if (sk_off != -1) {

#if 0
		tmp->security = process_sk(regf, sk_hdr, sk_off, BLK_SIZE(sk_hdr));
#endif

	} 

	*key = tmp;
	return WERR_OK;
}

#if 0 /* unused */

/*
 * Allocate a new hbin block, set up the header for the block etc 
 */
static HBIN_BLK *nt_create_hbin_blk(REG_HANDLE *h, int size)
{
	REGF *regf = h->backend_data;
	HBIN_BLK *tmp;
	HBIN_HDR *hdr;

	if (!regf || !size) return NULL;

	/* Round size up to multiple of REGF_HDR_BLKSIZ */

	size = (size + (REGF_HDR_BLKSIZ - 1)) & ~(REGF_HDR_BLKSIZ - 1);

	tmp = (HBIN_BLK *)malloc(sizeof(HBIN_BLK));
	memset(tmp, 0, sizeof(HBIN_BLK));

	tmp->data = malloc(size);

	memset(tmp->data, 0, size);  /* Make it pristine */

	tmp->size = size;
	/*FIXMEtmp->file_offset = regf->blk_tail->file_offset + regf->blk_tail->size;*/

	tmp->free_space = size - (sizeof(HBIN_HDR) - sizeof(HBIN_SUB_HDR));
	tmp->fsp_off = size - tmp->free_space;

	/* 
	 * Now, build the header in the data block 
	 */
	hdr = (HBIN_HDR *)tmp->data;
	hdr->HBIN_ID = str_to_dword("hbin");
	hdr->off_from_first = tmp->file_offset - REGF_HDR_BLKSIZ;
	hdr->off_to_next = tmp->size;
	hdr->blk_size = tmp->size;

	/*
	 * Now link it in
	 */

	regf->blk_tail->next = tmp;
	regf->blk_tail = tmp;
	if (!regf->free_space) regf->free_space = tmp;

	return tmp;
}

/*
 * Allocate a unit of space ... and return a pointer as function param
 * and the block's offset as a side effect
 */
static void *nt_alloc_regf_space(REG_HANDLE *h, int size, unsigned int *off)
{
	REGF *regf = h->backend_data;
	int tmp = 0;
	void *ret = NULL;
	HBIN_BLK *blk;

	if (!regf || !size || !off) return NULL;

	SMB_REG_ASSERT(regf->blk_head != NULL);

	/*
	 * round up size to include header and then to 8-byte boundary
	 */
	size = (size + 4 + 7) & ~7;

	/*
	 * Check if there is space, if none, grab a block
	 */
	if (!regf->free_space) {
		if (!nt_create_hbin_blk(h, REGF_HDR_BLKSIZ))
			return NULL;
	}

	/*
	 * Now, chain down the list of blocks looking for free space
	 */

	for (blk = regf->free_space; blk != NULL; blk = blk->next) {
		if (blk->free_space <= size) {
			tmp = blk->file_offset + blk->fsp_off - REGF_HDR_BLKSIZ;
			ret = blk->data + blk->fsp_off;
			blk->free_space -= size;
			blk->fsp_off += size;

			/* Insert the header */
			((HBIN_SUB_HDR *)ret)->dblocksize = -size;

			/*
			 * Fix up the free space ptr
			 * If it is NULL, we fix it up next time
			 */

			if (!blk->free_space) 
				regf->free_space = blk->next;

			*off = tmp;
			return (((char *)ret)+4);/* The pointer needs to be to the data struct */
		}
	}

	/*
	 * If we got here, we need to add another block, which might be 
	 * larger than one block -- deal with that later
	 */
	if (nt_create_hbin_blk(h, REGF_HDR_BLKSIZ)) {
		blk = regf->free_space;
		tmp = blk->file_offset + blk->fsp_off - REGF_HDR_BLKSIZ;
		ret = blk->data + blk->fsp_off;
		blk->free_space -= size;
		blk->fsp_off += size;

		/* Insert the header */
		((HBIN_SUB_HDR *)ret)->dblocksize = -size;

		/*
		 * Fix up the free space ptr
		 * If it is NULL, we fix it up next time
		 */

		if (!blk->free_space) 
			regf->free_space = blk->next;

		*off = tmp;
		return (((char *)ret) + 4);/* The pointer needs to be to the data struct */
	}

	return NULL;
}

/*
 * Store a SID at the location provided
 */
static int nt_store_SID(REG_HANDLE *regf, DOM_SID *sid, unsigned char *locn)
{
	int i;
	unsigned char *p = locn;

	if (!regf || !sid || !locn) return 0;

	*p = sid->sid_rev_num; p++;
	*p = sid->num_auths; p++;

	for (i=0; i < 6; i++) {
		*p = sid->id_auth[i]; p++;
	}

	for (i=0; i < sid->num_auths; i++) {
		SIVAL(p, 0, sid->sub_auths[i]); p+=4;
	}

	return p - locn;

}

static int nt_store_ace(REG_HANDLE *regf, SEC_ACE *ace, unsigned char *locn)
{
	int size = 0;
	SEC_ACE *reg_ace = (SEC_ACE *)locn;
	unsigned char *p;

	if (!regf || !ace || !locn) return 0;

	reg_ace->type = ace->type;
	reg_ace->flags = ace->flags;

	/* Deal with the length when we have stored the SID */

	p = (unsigned char *)&reg_ace->info.mask;

	SIVAL(p, 0, ace->info.mask); p += 4;

	size = nt_store_SID(regf, &ace->trustee, p);

	size += 8; /* Size of the fixed header */

	p = (unsigned char *)&reg_ace->size;

	SSVAL(p, 0, size);

	return size;
}

/*
 * Store an ACL at the location provided
 */
static int nt_store_acl(REG_HANDLE *regf, SEC_ACL *acl, unsigned char *locn) {
	int size = 0, i;
	unsigned char *p = locn, *s;

	if (!regf || !acl || !locn) return 0;

	/*
	 * Now store the header and then the ACEs ...
	 */

	SSVAL(p, 0, acl->revision);

	p += 2; s = p; /* Save this for the size field */

	p += 2;

	SIVAL(p, 0, acl->num_aces);

	p += 4;

	for (i = 0; i < acl->num_aces; i++) {
		size = nt_store_ace(regf, &acl->ace[i], p);
		p += size;
	}

	size = s - locn;
	SSVAL(s, 0, size);
	return size;
}

/*
 * Flatten and store the Sec Desc 
 * Windows lays out the DACL first, but since there is no SACL, it might be
 * that first, then the owner, then the group SID. So, we do it that way
 * too.
 */
static unsigned int nt_store_sec_desc(REG_HANDLE *regf, SEC_DESC *sd, char *locn)
{
	SEC_DESC *rsd = (SEC_DESC *)locn;
	unsigned int size = 0, off = 0;

	if (!regf || !sd || !locn) return 0;

	/* 
	 * Now, fill in the first two fields, then lay out the various fields
	 * as needed
	 */

	rsd->revision = SEC_DESC_REVISION;
	rsd->type = SEC_DESC_DACL_PRESENT | SEC_DESC_SELF_RELATIVE;  

	off = 4 * sizeof(DWORD) + 4;

	if (sd->sacl){
		size = nt_store_acl(regf, sd->sacl, (char *)(locn + off));
		rsd->off_sacl = off;
	}
	else
		rsd->off_sacl = 0;

	off += size;

	if (sd->dacl) {
		rsd->off_dacl = off;
		size = nt_store_acl(regf, sd->dacl, (char *)(locn + off));
	}
	else {
		rsd->off_dacl = 0;
	}

	off += size;

	/* Now the owner and group SIDs */

	if (sd->owner_sid) {
		rsd->off_owner_sid = off;
		size = nt_store_SID(regf, sd->owner_sid, (char *)(locn + off));
	}
	else {
		rsd->off_owner_sid = 0;
	}

	off += size;

	if (sd->grp_sid) {
		rsd->off_grp_sid = off;
		size = nt_store_SID(regf, sd->grp_sid, (char *)(locn + off));
	}
	else {
		rsd->off_grp_sid = 0;
	}

	off += size;

	return size;
}

/*
 * Store the security information
 *
 * If it has already been stored, just get its offset from record
 * otherwise, store it and record its offset
 */
static unsigned int nt_store_security(REG_HANDLE *regf, KEY_SEC_DESC *sec)
{
	int size = 0;
	unsigned int sk_off;
	SK_HDR *sk_hdr;

	if (sec->offset) return sec->offset;

	/*
	 * OK, we don't have this one in the file yet. We must compute the 
	 * size taken by the security descriptor as a self-relative SD, which
	 * means making one pass over each structure and figuring it out
	 */

//FIXME	size = sec_desc_size(sec->sec_desc);

	/* Allocate that much space */

	sk_hdr = nt_alloc_regf_space(regf, size, &sk_off);
	sec->sk_hdr = sk_hdr;

	if (!sk_hdr) return 0;

	/* Now, lay out the sec_desc in the space provided */

	sk_hdr->SK_ID = str_to_dword("sk");

	/* 
	 * We can't deal with the next and prev offset in the SK_HDRs until the
	 * whole tree has been stored, then we can go and deal with them
	 */

	sk_hdr->ref_cnt = sec->ref_cnt;
	sk_hdr->rec_size = size;       /* Is this correct */

	/* Now, lay out the sec_desc */

	if (!nt_store_sec_desc(regf, sec->sec_desc, (char *)&sk_hdr->sec_desc))
		return 0;

	return sk_off;

}

/*
 * Store a KEY in the file ...
 *
 * We store this depth first, and defer storing the lf struct until
 * all the sub-keys have been stored.
 * 
 * We store the NK hdr, any SK header, class name, and VK structure, then
 * recurse down the LF structures ... 
 * 
 * We return the offset of the NK struct
 * FIXME, FIXME, FIXME: Convert to using SIVAL and SSVAL ...
 */
static int nt_store_reg_key(REG_HANDLE *regf, REG_KEY *key)
{
	NK_HDR *nk_hdr; 
	unsigned int nk_off, sk_off, size;

	if (!regf || !key) return 0;

	size = sizeof(NK_HDR) + strlen(key->name) - 1;
	nk_hdr = nt_alloc_regf_space(regf, size, &nk_off);
	if (!nk_hdr) goto error;

	key->offset = nk_off;  /* We will need this later */

	/*
	 * Now fill in each field etc ...
	 */

	nk_hdr->NK_ID = str_to_dword("nk"); 
	if (key->type == REG_ROOT_KEY)
		nk_hdr->type = 0x2C;
	else
		nk_hdr->type = 0x20;

	/* FIXME: Fill in the time of last update */

	if (key->type != REG_ROOT_KEY)
		nk_hdr->own_off = key->owner->offset;

	if (key->sub_keys)
		nk_hdr->subk_num = key->sub_keys->key_count;

	/*
	 * Now, process the Sec Desc and then store its offset
	 */

	sk_off = nt_store_security(regf, key->security);
	nk_hdr->sk_off = sk_off;

	/*
	 * Then, store the val list and store its offset
	 */
	if (key->values) {
		nk_hdr->val_cnt = key->values->val_count;
		nk_hdr->val_off = nt_store_val_list(regf, key->values);
	}
	else {
		nk_hdr->val_off = -1;
		nk_hdr->val_cnt = 0;
	}

	/*
	 * Finally, store the subkeys, and their offsets
	 */

error:
	return 0;
}

/*
 * Store the registry header ...
 * We actually create the registry header block and link it to the chain
 * of output blocks.
 */
static REGF_HDR *nt_get_reg_header(REG_HANDLE *h) {
	REGF *regf = h->backend_data;
	HBIN_BLK *tmp = NULL;

	tmp = (HBIN_BLK *)malloc(sizeof(HBIN_BLK));

	memset(tmp, 0, sizeof(HBIN_BLK));
	tmp->type = REG_OUTBLK_HDR;
	tmp->size = REGF_HDR_BLKSIZ;
	tmp->data = malloc(REGF_HDR_BLKSIZ);
	if (!tmp->data) goto error;

	memset(tmp->data, 0, REGF_HDR_BLKSIZ);  /* Make it pristine, unlike Windows */
	regf->blk_head = regf->blk_tail = tmp;

	return (REGF_HDR *)tmp->data;

error:
	if (tmp) free(tmp);
	return NULL;
}

#endif

static WERROR nt_close_registry (REG_HANDLE *h) 
{
	REGF *regf = h->backend_data;
	if (regf->base) munmap(regf->base, regf->sbuf.st_size);
	regf->base = NULL;
	close(regf->fd);    /* Ignore the error :-) */

	return WERR_OK;
}

static WERROR nt_open_registry (REG_HANDLE *h, const char *location, const char *credentials) 
{
	REGF *regf;
	REGF_HDR *regf_hdr;
	unsigned int regf_id, hbin_id;
	HBIN_HDR *hbin_hdr;

	regf = (REGF *)talloc_p(h->mem_ctx, REGF);
	memset(regf, 0, sizeof(REGF));
	regf->owner_sid_str = credentials;
	h->backend_data = regf;

	DEBUG(5, ("Attempting to load registry file\n"));

	/* Get the header */

	if ((regf_hdr = nt_get_regf_hdr(h)) == NULL) {
		DEBUG(0, ("Unable to get header\n"));
		return WERR_GENERAL_FAILURE;
	}

	/* Now process that header and start to read the rest in */

	if ((regf_id = IVAL(&regf_hdr->REGF_ID,0)) != str_to_dword("regf")) {
		DEBUG(0, ("Unrecognized NT registry header id: %0X, %s\n",
				  regf_id, h->location));
		return WERR_GENERAL_FAILURE;
	}

	/*
	 * Validate the header ...
	 */
	if (!valid_regf_hdr(regf_hdr)) {
		DEBUG(0, ("Registry file header does not validate: %s\n",
				  h->location));
		return WERR_GENERAL_FAILURE;
	}

	/* Update the last mod date, and then go get the first NK record and on */

	TTTONTTIME(regf, IVAL(&regf_hdr->tim1,0), IVAL(&regf_hdr->tim2,0));

	/* 
	 * The hbin hdr seems to be just uninteresting garbage. Check that
	 * it is there, but that is all.
	 */

	hbin_hdr = (HBIN_HDR *)(regf->base + REGF_HDR_BLKSIZ);

	if ((hbin_id = IVAL(&hbin_hdr->HBIN_ID,0)) != str_to_dword("hbin")) {
		DEBUG(0, ("Unrecognized registry hbin hdr ID: %0X, %s\n", 
				  hbin_id, h->location));
		return WERR_GENERAL_FAILURE;
	} 

	/*
	 * Get a pointer to the first key from the hreg_hdr
	 */

	DEBUG(2, ("First Key: %0X\n",
			  IVAL(&regf_hdr->first_key, 0)));

	regf->first_key = (NK_HDR *)LOCN(regf->base, IVAL(&regf_hdr->first_key,0));
	DEBUGADD(2, ("First Key Offset: %0X\n", 
				 IVAL(&regf_hdr->first_key, 0)));

	DEBUGADD(2, ("Data Block Size: %d\n",
				 IVAL(&regf_hdr->dblk_size, 0)));

	DEBUGADD(2, ("Offset to next hbin block: %0X\n",
				 IVAL(&hbin_hdr->off_to_next, 0)));

	DEBUGADD(2, ("HBIN block size: %0X\n",
				 IVAL(&hbin_hdr->blk_size, 0)));

	/*
	 * Unmap the registry file, as we might want to read in another
	 * tree etc.
	 */

	h->backend_data = regf;

	return WERR_OK;
}

static WERROR nt_get_root_key(REG_HANDLE *h, int hive, REG_KEY **key) 
{ 
	if(hive != 0) return WERR_NO_MORE_ITEMS;
	return nk_to_key(h, ((REGF *)h->backend_data)->first_key, BLK_SIZE(((REGF *)h->backend_data)->first_key), NULL, key);
}

static WERROR nt_num_subkeys(REG_KEY *k, int *num) 
{
	REGF *regf = k->handle->backend_data;
	LF_HDR *lf_hdr;
	int lf_off;
	NK_HDR *nk_hdr = k->backend_data;
	lf_off = IVAL(&nk_hdr->lf_off,0);
	DEBUG(2, ("SubKey list offset: %0X\n", lf_off));
	if(lf_off == -1) {
		*num = 0;
		return WERR_OK;
	}
	lf_hdr = (LF_HDR *)LOCN(regf->base, lf_off);

	return lf_num_entries(k->handle, lf_hdr, BLK_SIZE(lf_hdr), num);
}

static WERROR nt_num_values(REG_KEY *k, int *count)
{
	NK_HDR *nk_hdr = k->backend_data;
	*count = IVAL(&nk_hdr->val_cnt,0);
	return WERR_OK;
}

static WERROR nt_value_by_index(REG_KEY *k, int n, REG_VAL **value)
{
	VL_TYPE *vl;
	int val_off, vk_off;
	int val_count;
	VK_HDR *vk_hdr;
	REGF *regf = k->handle->backend_data;
	NK_HDR *nk_hdr = k->backend_data;
	val_count = IVAL(&nk_hdr->val_cnt,0);
	val_off = IVAL(&nk_hdr->val_off,0);
	vl = (VL_TYPE *)LOCN(regf->base, val_off);
	DEBUG(2, ("Val List Offset: %0X\n", val_off));
	if(n < 0) return WERR_INVALID_PARAM;
	if(n >= val_count) return WERR_NO_MORE_ITEMS;

	vk_off = IVAL(&vl[n],0);
	vk_hdr = (VK_HDR *)LOCN(regf->base, vk_off);
	return vk_to_val(k, vk_hdr, BLK_SIZE(vk_hdr), value);
}

static WERROR nt_key_by_index(REG_KEY *k, int n, REG_KEY **subkey)
{
	REGF *regf = k->handle->backend_data;
	int lf_off;
	NK_HDR *nk_hdr = k->backend_data;
	LF_HDR *lf_hdr;
	lf_off = IVAL(&nk_hdr->lf_off,0);
	DEBUG(2, ("SubKey list offset: %0X\n", lf_off));

	/*
	 * No more subkeys if lf_off == -1
	 */

	if (lf_off != -1) {
		lf_hdr = (LF_HDR *)LOCN(regf->base, lf_off);
		return lf_get_entry(k, lf_hdr, BLK_SIZE(lf_hdr), n, subkey);
	}

	return WERR_NO_MORE_ITEMS;
}

static struct registry_ops reg_backend_nt4 = {
	.name = "nt4",
	.open_registry = nt_open_registry,
	.close_registry = nt_close_registry,
	.get_hive = nt_get_root_key,
	.num_subkeys = nt_num_subkeys,
	.num_values = nt_num_values,
	.get_subkey_by_index = nt_key_by_index,
	.get_value_by_index = nt_value_by_index,

	/* TODO: 
	.add_key
	.add_value
	.del_key
	.del_value
	.update_value
	*/
};

NTSTATUS registry_nt4_init(void)
{
	return register_backend("registry", &reg_backend_nt4);
}
