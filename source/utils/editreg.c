/* 
   Samba Unix/Linux SMB client utility editreg.c 
   Copyright (C) 2002 Richard Sharpe, rsharpe@richardsharpe.com

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
 
"regf" is obviosly the abbreviation for "Registry file". "regf" is the
signature of the header-block which is always 4kb in size, although only
the first 64 bytes seem to be used and a checksum is calculated over
the first 0x200 bytes only!

Offset            Size      Contents
0x00000000      D-Word      ID: ASCII-"regf" = 0x66676572
0x00000004      D-Word      ???? //see struct REGF
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

That does not seem to be true. All block lengths seem to be negative! (Richard Sharpe) 

The data is stored as one record per block. Block size is a multiple
of 4 and the last block reaches the next hbin-block, leaving no room.

Records in the hbin-blocks
==========================

nk-Record

      The nk-record can be treated as a kombination of tree-record and
      key-record of the win 95 registry.

lf-Record

      The lf-record is the counterpart to the RGKN-record (the
      hash-function)

vk-Record

      The vk-record consists information to a single value.

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

Der vk-Record
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
(This is just a security descriptor in the data. R Sharpe.) 


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

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
/* 
 * These definitions are for the in-memory registry structure.
 * It is a tree structure that mimics what you see with tools like regedit
 */

/*
 * DateTime struct for Windows
 */

typedef struct date_time_s {
  unsigned int low, high;
} NTTIME;

/*
 * Definition of a Key. It has a name, classname, date/time last modified,
 * sub-keys, values, and a security descriptor
 */

#define REG_ROOT_KEY 1
#define REG_SUB_KEY 2

typedef struct reg_key_s {
  char *name;         /* Name of the key                    */
  char *class_name;
  int type;           /* One of REG_ROOT_KEY or REG_SUB_KEY */
  NTTIME last_mod; /* Time last modified                 */
  struct reg_key_s *owner;
  struct key_list_s *sub_keys;
  struct val_list_s *values;
  struct key_sec_desc_s *security;
} REG_KEY;

/*
 * The KEY_LIST struct lists sub-keys.
 */

typedef struct key_list_s {
  int key_count;
  REG_KEY *keys[1];
} KEY_LIST;

typedef struct val_key_s {
  char *name;
  int has_name;
  int data_type;
  int data_len;
  void *data_blk;    /* Might want a separate block */
} VAL_KEY;

typedef struct val_list_s {
  int val_count;
  VAL_KEY vals[1];
} VAL_LIST;

#ifndef MAXSUBAUTHS
#define MAXSUBAUTHS 15
#endif

typedef struct dom_sid_s {
  unsigned char ver, auths;
  unsigned char auth[6];
  unsigned int sub_auths[MAXSUBAUTHS];
} DOM_SID;

typedef struct ace_struct_s {
  unsigned char type, flags;
  unsigned int perms;   /* Perhaps a better def is in order */
  DOM_SID trustee;
} ACE; 

typedef struct acl_struct_s {
  unsigned short rev, refcnt;
  unsigned short num_aces;
  ACE *aces[1];
} ACL;

typedef struct sec_desc_s {
  unsigned int rev, type;
  DOM_SID *owner, *group;
  ACL *sacl, *dacl;
} SEC_DESC;

typedef struct key_sec_desc_s {
  struct key_sec_desc_s *prev, *next;
  int ref_cnt;
  SEC_DESC *sec_desc;
} KEY_SEC_DESC; 


/*
 * An API for accessing/creating/destroying items above
 */

/* Make, delete keys */

int nt_delete_reg_key(REG_KEY *key)
{

  return 1;
}

/* 
 * Create/delete key lists and add delete keys to/from a list, count the keys 
 */


/*
 * Create/delete value lists, add/delete values, count them
 */


/*
 * Create/delete security descriptors, add/delete SIDS, count SIDS, etc.
 * We reference count the security descriptors. Any new reference increments 
 * the ref count. If we modify an SD, we copy the old one, dec the ref count
 * and make the change. We also want to be able to check for equality so
 * we can reduce the number of SDs in use.
 */


/*
 * Load and unload a registry file.
 *
 * Load, loads it into memory as a tree, while unload sealizes/flattens it
 */

/*
 * Get the starting record for NT Registry file 
 */

/* A map of sk offsets in the regf to KEY_SEC_DESCs for quick lookup etc */
typedef struct sk_map_s {
  int sk_off;
  KEY_SEC_DESC *key_sec_desc;
} SK_MAP;

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

#define REGF_REGTYPE_NONE 0
#define REGF_REGTYPE_NT   1
#define REGF_REGTYPE_W9X  2

#define TTTONTTIME(r, t1, t2) (r)->last_mod_time.low = (t1); \
                              (r)->last_mod_time.high = (t2);

#define REGF_HDR_BLKSIZ 0x1000 

typedef struct regf_struct_s {
  int reg_type;
  char *regfile_name, *outfile_name;
  int fd;
  struct stat sbuf;
  char *base;
  int modified;
  NTTIME last_mod_time;
  REG_KEY *root;  /* Root of the tree for this file */
  int sk_count, sk_map_size;
  SK_MAP **sk_map;
} REGF;

/*
 * Structures for dealing with the on-disk format of the registry
 */

#define IVAL(buf) ((unsigned int) \
                   (unsigned int)*((unsigned char *)(buf)+3)<<24| \
                   (unsigned int)*((unsigned char *)(buf)+2)<<16| \
                   (unsigned int)*((unsigned char *)(buf)+1)<<8| \
                   (unsigned int)*((unsigned char *)(buf)+0)) 

#define SVAL(buf) ((unsigned short) \
                   (unsigned short)*((unsigned char *)(buf)+1)<<8| \
                   (unsigned short)*((unsigned char *)(buf)+0)) 

#define OFF(f) ((f) + REGF_HDR_BLKSIZ + 4) 
#define LOCN(base, f) ((base) + OFF(f))

/* 
 * All of the structures below actually have a four-byte lenght before them
 * which always seems to be negative. The following macro retrieves that
 * size as an integer
 */

#define BLK_SIZE(b) ((int)*(int *)(((int *)b)-1))

typedef unsigned int DWORD;
typedef unsigned short WORD;

#define REG_REGF_ID 0x66676572

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

#define REG_HBIN_ID 0x6E696268

typedef struct hbin_struct {
  DWORD HBIN_ID; /* hbin */
  DWORD next_off;
  DWORD prev_off;
  DWORD uk1;
  DWORD uk2;
  DWORD uk3;
  DWORD uk4;
  DWORD blk_size;
  HBIN_SUB_HDR hbin_sub_hdr;
} HBIN_HDR;

#define REG_NK_ID 0x6B6E

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

#define REG_SK_ID 0x6B73

typedef struct sk_struct {
  WORD SK_ID;
  WORD uk1;
  DWORD prev_off;
  DWORD next_off;
  DWORD ref_cnt;
  DWORD rec_size;
  char sec_desc[1];
} SK_HDR;

#define OFF(f) ((f) + 0x1000 + 4) 
#define LOCN(base, f) ((base) + OFF(f))

typedef struct hash_struct {
  DWORD nk_off;
  char hash[4];
} HASH_REC;

#define REG_LF_ID 0x666C

typedef struct lf_struct {
  WORD LF_ID;
  WORD key_count;
  struct hash_struct hr[1];  /* Array of hash records, depending on key_count */
} LF_HDR;

typedef DWORD VL_TYPE[1];  /* Value list is an array of vk rec offsets */

#define REG_VK_ID 0x6B76

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

#define REG_TYPE_REGSZ     1
#define REG_TYPE_EXPANDSZ  2
#define REG_TYPE_BIN       3  
#define REG_TYPE_DWORD     4
#define REG_TYPE_MULTISZ   7

typedef struct _val_str { 
  unsigned int val;
  char * str;
} VAL_STR;

VAL_STR reg_type_names[] = {
   { 1, "REG_SZ" },
   { 2, "REG_EXPAND_SZ" },
   { 3, "REG_BIN" },
   { 4, "REG_DWORD" },
   { 7, "REG_MULTI_SZ" },
   { 0, NULL },
};

char *val_to_str(unsigned int val, VAL_STR *val_array)
{
  int i = 0;

  if (!val_array) return NULL;

  while (val_array[i].val && val_array[i].str) {

    if (val_array[i].val == val) return val_array[i].str;
    i++;

  }

  return NULL;

}

REG_KEY *nt_get_key_tree(REGF *regf, NK_HDR *nk_hdr, int size);

int nt_set_regf_input_file(REGF *regf, char *filename)
{
  return ((regf->regfile_name = strdup(filename)) != NULL); 
}

int nt_set_regf_output_file(REGF *regf, char *filename)
{
  return ((regf->outfile_name = strdup(filename)) != NULL); 
}

/* Create a regf structure and init it */

REGF *nt_create_regf()
{
  REGF *tmp = (REGF *)malloc(sizeof(REGF));
  if (!tmp) return tmp;
  bzero(tmp, sizeof(REGF));
  return tmp;
} 

/* Free all the bits and pieces ... Assumes regf was malloc'd */
/* If you add stuff to REGF, add the relevant free bits here  */
int nt_free_regf(REGF *regf)
{
  if (!regf) return;

  if (regf->regfile_name) free(regf->regfile_name);
  if (regf->outfile_name) free(regf->outfile_name);

  /* Free the mmap'd area */

  if (regf->base) munmap(regf->base, regf->sbuf.st_size);
  regf->base = NULL;
  close(regf->fd);    /* Ignore the error :-) */

  nt_delete_reg_key(regf->root); /* Free the tree */
  free(regf->sk_map);
  regf->sk_count = regf->sk_map_size = 0;

  free(regf);

}

/*
 * Convert from UniCode to Ascii ... Does not take into account other lang
 * Restrict by ascii_max if > 0
 */
int uni_to_ascii(unsigned char *uni, unsigned char *ascii, int ascii_max, 
		 int uni_max)
{
  int i = 0; 

  while (i < ascii_max && !(!uni[i*2] && !uni[i*2+1])) {
    if (uni_max > 0 && (i*2) >= uni_max) break;
    ascii[i] = uni[i*2];
    i++;

  }

  ascii[i] = '\0';

  return i;
}

/* Get the header of the registry. Return a pointer to the structure 
 * If the mmap'd area has not been allocated, then mmap the input file
 */
REGF_HDR *nt_get_regf_hdr(REGF *regf)
{
  if (!regf)
    return NULL; /* What about errors */

  if (!regf->regfile_name)
    return NULL; /* What about errors */

  if (!regf->base) { /* Try to mmap etc the file */

    if ((regf->fd = open(regf->regfile_name, O_RDONLY, 0000)) <0) {
      return NULL; /* What about errors? */
    }

    if (fstat(regf->fd, &regf->sbuf) < 0) {
      return NULL;
    }

    regf->base = mmap(0, regf->sbuf.st_size, PROT_READ, MAP_SHARED, regf->fd, 0);

    if ((int)regf->base == 1) {
      fprintf(stderr, "Could not mmap file: %s, %s\n", regf->regfile_name,
	      strerror(errno));
      return NULL;
    }
  }

  /* 
   * At this point, regf->base != NULL, and we should be able to read the 
   * header 
   */

  assert(regf->base != NULL);

  return (REGF_HDR *)regf->base;
}

/*
 * Validate a regf header
 * For now, do nothing, but we should check the checksum
 */
int valid_regf_hdr(REGF_HDR *regf_hdr)
{
  if (!regf_hdr) return 0;

  return 1;
}

/*
 * Process a VK header and return a value
 */
VAL_KEY *process_vk(REGF *regf, VK_HDR *vk_hdr, int size)
{
  char val_name[1024], data_value[1024];
  int nam_len, dat_len, flag, dat_type, dat_off, vk_id;
  char *val_type;

  if (!vk_hdr) return NULL;

  if ((vk_id = SVAL(&vk_hdr->VK_ID)) != REG_VK_ID) {
    fprintf(stderr, "Unrecognized VK header ID: %0X, block: %0X, %s\n",
	    vk_id, vk_hdr, regf->regfile_name);
    return NULL;
  }

  nam_len = SVAL(&vk_hdr->nam_len);
  val_name[nam_len] = '\0';
  flag = SVAL(&vk_hdr->flag);
  dat_type = IVAL(&vk_hdr->dat_type);

  if (flag & 0x01)
    strncpy(val_name, vk_hdr->dat_name, nam_len);
  else
    strncpy(val_name, "<No Name>", 10);

  val_type = val_to_str(dat_type, reg_type_names);

  /*
   * We need to save the data area as well
   */

  fprintf(stdout, "  %s : %s : \n", val_name, val_type);

  return NULL;

}

/*
 * Process a VL Header and return a list of values
 */
VAL_LIST *process_vl(REGF *regf, VL_TYPE vl, int count, int size)
{
  int i, vk_off;
  VK_HDR *vk_hdr;

  if (-size < (count+1)*sizeof(int)){
    fprintf(stderr, "Error in VL header format. Size less than space required. %d\n", -size);
    return NULL;
  }

  for (i=0; i<count; i++) {
    vk_off = IVAL(&vl[i]);
    vk_hdr = (VK_HDR *)LOCN(regf->base, vk_off);
    process_vk(regf, vk_hdr, BLK_SIZE(vk_hdr));
  }
} 

/*
 * Process an LF Header and return a list of sub-keys
 */
KEY_LIST *process_lf(REGF *regf, LF_HDR *lf_hdr, int size)
{
  int count, i, nk_off;
  unsigned int lf_id;
  KEY_LIST *tmp;

  if (!lf_hdr) return NULL;

  if ((lf_id = SVAL(&lf_hdr->LF_ID)) != REG_LF_ID) {
    fprintf(stderr, "Unrecognized LF Header format: %0X, Block: %0X, %s.\n",
	    lf_id, lf_hdr, regf->regfile_name);
    return NULL;
  }

  assert(size < 0);

  count = SVAL(&lf_hdr->key_count);

  if (count <= 0) return NULL;

  /* Now, we should allocate a KEY_LIST struct and fill it in ... */

  tmp = (KEY_LIST *)malloc(sizeof(KEY_LIST) + (count - 1) * sizeof(REG_KEY *));
  if (!tmp) {
    goto error;
  }

  tmp->key_count = count;

  for (i=0; i<count; i++) {
    NK_HDR *nk_hdr;
    int nk_off;

    nk_off = IVAL(&lf_hdr->hr[i].nk_off);
    nk_hdr = (NK_HDR *)LOCN(regf->base, nk_off);
    tmp->keys[i] = nt_get_key_tree(regf, nk_hdr, BLK_SIZE(nk_hdr));
    if (!tmp->keys[i]) {
      goto error;
    }
  }

  return tmp;

 error:
  return NULL;
}

/*
 * This routine is passed a NK_HDR pointer and retrieves the entire tree
 * from there down. It return a REG_KEY *.
 */
REG_KEY *nt_get_key_tree(REGF *regf, NK_HDR *nk_hdr, int size)
{
  REG_KEY *tmp = NULL;
  KEY_LIST *key_list;
  int rec_size, name_len, clsname_len, lf_off, val_off, val_count, sk_off;
  unsigned int nk_id;
  LF_HDR *lf_hdr;
  VL_TYPE *vl;
  SK_HDR *sk_hdr;
  char key_name[1024], cls_name[1024];

  if (!nk_hdr) return NULL;

  if ((nk_id = SVAL(&nk_hdr->NK_ID)) != REG_NK_ID) {
    fprintf(stderr, "Unrecognized NK Header format: %08X, Block: %0X. %s\n", 
	    nk_id, nk_hdr, regf->regfile_name);
    return NULL;
  }

  assert(size < 0);

  name_len = SVAL(&nk_hdr->nam_len);
  clsname_len = SVAL(&nk_hdr->clsnam_len);

  /*
   * The value of -size should be ge 
   * (sizeof(NK_HDR) - 1 + name_len)
   * The -1 accounts for the fact that we included the first byte of 
   * the name in the structure. clsname_len is the length of the thing 
   * pointed to by clsnam_off
   */

  if (-size < (sizeof(NK_HDR) - 1 + name_len)) {
    fprintf(stderr, "Incorrect NK_HDR size: %d, %0X\n", -size, nk_hdr);
    fprintf(stderr, "Sizeof NK_HDR: %d, name_len %d, clsname_len %d\n",
	    sizeof(NK_HDR), name_len, clsname_len);
    /*return NULL;*/
  }

  fprintf(stdout, "NK HDR: Name len: %d, class name len: %d\n", name_len,
	  clsname_len);

  /* Fish out the key name and process the LF list */

  assert(name_len < sizeof(key_name));

  /* Allocate the key struct now */
  tmp = (REG_KEY *)malloc(sizeof(REG_KEY));
  if (!tmp) return tmp;
  bzero(tmp, sizeof(REG_KEY));

  strncpy(key_name, nk_hdr->key_nam, name_len);
  key_name[name_len] = '\0';

  fprintf(stdout, "Key name: %s\n", key_name);

  tmp->name = strdup(key_name);
  if (!tmp->name) {
    goto error;
  }

  /*
   * Fish out the class name, it is in UNICODE, while the key name is 
   * ASCII :-)
   */

  if (clsname_len) { /* Just print in Ascii for now */
    char *clsnamep;
    int clsnam_off;

    clsnam_off = IVAL(&nk_hdr->clsnam_off);
    clsnamep = LOCN(regf->base, clsnam_off);
 
    bzero(cls_name, clsname_len);
    uni_to_ascii(clsnamep, cls_name, sizeof(cls_name), clsname_len);
    
    /*
     * I am keeping class name as an ascii string for the moment.
     * That means it needs to be converted on output.
     * XXX: FIXME
     */

    tmp->class_name = strdup(cls_name);
    if (!tmp->class_name) {
      goto error;
    }

    fprintf(stdout, "  Class Name: %s\n", cls_name);

  }

  /*
   * If there are any values, process them here
   */

  val_count = IVAL(&nk_hdr->val_cnt);

  if (val_count) {
    int val_off;

    val_off = IVAL(&nk_hdr->val_off);
    vl = (VL_TYPE *)LOCN(regf->base, val_off);

    tmp->values = process_vl(regf, *vl, val_count, BLK_SIZE(vl));
    if (!tmp->values) {
      goto error;
    }

  }

  /* 
   * Also handle the SK header ...
   */

  sk_off = IVAL(&nk_hdr->sk_off);
  sk_hdr = (SK_HDR *)LOCN(regf->base, sk_off);

  if (sk_off != -1) {

    /* To be coded */  

  } 

  lf_off = IVAL(&nk_hdr->lf_off);

  /*
   * No more subkeys if lf_off == -1
   */

  if (lf_off != -1) {

    lf_hdr = (LF_HDR *)LOCN(regf->base, lf_off);
    
    tmp->sub_keys = process_lf(regf, lf_hdr, BLK_SIZE(lf_hdr));
    if (!tmp->sub_keys){
      goto error;
    }

  }

  return tmp;

 error:
  if (tmp) nt_delete_reg_key(tmp);
  return NULL;
}

int nt_load_registry(REGF *regf)
{
  REGF_HDR *regf_hdr;
  unsigned int regf_id, hbin_id;
  unsigned int hbin_off;
  HBIN_HDR *hbin_hdr;
  NK_HDR *first_key;

  /* Get the header */

  if ((regf_hdr = nt_get_regf_hdr(regf)) == NULL) {
    return -1;
  }

  /* Now process that header and start to read the rest in */

  if ((regf_id = IVAL(&regf_hdr->REGF_ID)) != REG_REGF_ID) {
    fprintf(stderr, "Unrecognized NT registry header id: %0X, %s\n",
	    regf_id, regf->regfile_name);
    return -1;
  }

  /*
   * Validate the header ...
   */
  if (!valid_regf_hdr(regf_hdr)) {
    fprintf(stderr, "Registry file header does not validate: %s\n",
	    regf->regfile_name);
    return -1;
  }

  /* Update the last mod date, and then go get the first NK record and on */

  TTTONTTIME(regf, IVAL(&regf_hdr->tim1), IVAL(&regf_hdr->tim2));

  /* 
   * The hbin hdr seems to be just uninteresting garbage. Check that
   * it is there, but that is all.
   */

  hbin_hdr = (HBIN_HDR *)(regf->base + REGF_HDR_BLKSIZ);

  if ((hbin_id = IVAL(&hbin_hdr->HBIN_ID)) != REG_HBIN_ID) {
    fprintf(stderr, "Unrecognized registry hbin hdr ID: %0X, %s\n", 
	    hbin_id, regf->regfile_name);
    return -1;
  } 

  /*
   * Get a pointer to the first key from the hreg_hdr
   */

  first_key = (NK_HDR *)LOCN(regf->base, IVAL(&regf_hdr->first_key));

  /*
   * Now, get the registry tree by processing that NK recursively
   */

  regf->root = nt_get_key_tree(regf, first_key, BLK_SIZE(first_key));

  assert(regf->root != NULL);

  return 1;
}

/*
 * Main code from here on ...
 */

void usage(void)
{
  fprintf(stderr, "Usage: editreg <registryfile>\n");
  fprintf(stderr, "Version: 0.1\n\n"); 
}

int main(int argc, char *argv[])
{
  REGF *regf;

  if (argc < 2) {
    usage();
    exit(1);
  }

  if ((regf = nt_create_regf()) == NULL) {
    fprintf(stderr, "Could not create registry object: %s\n", strerror(errno));
    exit(2);
  }

  if (!nt_set_regf_input_file(regf, argv[1])) {
    fprintf(stderr, "Could not set name of registry file: %s, %s\n", 
	    argv[1], strerror(errno));
    exit(3);
  }

  /* Now, open it, and bring it into memory :-) */

  if (nt_load_registry(regf) < 0) {
    fprintf(stderr, "Could not load registry: %s\n", argv[1]);
    exit(4);
  }

  /*
   * At this point, we should have a registry in memory and should be able
   * to iterate over it.
   */

}
