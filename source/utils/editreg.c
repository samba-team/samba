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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>

#define False 0
#define True 1
#define REG_KEY_LIST_SIZE 10

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

#define CVAL(buf) ((unsigned char)*((unsigned char *)(buf)))

#define SIVAL(buf, val) \
            ((((unsigned char *)(buf))[0])=(unsigned char)((val)&0xFF),\
             (((unsigned char *)(buf))[1])=(unsigned char)(((val)>>8)&0xFF),\
             (((unsigned char *)(buf))[2])=(unsigned char)(((val)>>16)&0xFF),\
             (((unsigned char *)(buf))[3])=(unsigned char)((val)>>24))

#define SSVAL(buf, val) \
            ((((unsigned char *)(buf))[0])=(unsigned char)((val)&0xFF),\
             (((unsigned char *)(buf))[1])=(unsigned char)((val)>>8))

static int verbose = 0;
static int print_security = 0;
static int full_print = 0;
static const char *def_owner_sid_str = NULL;

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
#define REG_SUB_KEY  2
#define REG_SYM_LINK 3

typedef struct key_sec_desc_s KEY_SEC_DESC;

typedef struct reg_key_s {
  char *name;         /* Name of the key                    */
  char *class_name;
  int type;           /* One of REG_ROOT_KEY or REG_SUB_KEY */
  NTTIME last_mod; /* Time last modified                 */
  struct reg_key_s *owner;
  struct key_list_s *sub_keys;
  struct val_list_s *values;
  KEY_SEC_DESC *security;
  unsigned int offset;  /* Offset of the record in the file */
} REG_KEY;

/*
 * The KEY_LIST struct lists sub-keys.
 */

typedef struct key_list_s {
  int key_count;
  int max_keys;
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
  int max_vals;
  VAL_KEY *vals[1];
} VAL_LIST;

#ifndef MAXSUBAUTHS
#define MAXSUBAUTHS 15
#endif

typedef struct sid_s {
  unsigned char ver, auths;
  unsigned char auth[6];
  unsigned int sub_auths[MAXSUBAUTHS];
} sid_t;

typedef struct ace_struct_s {
  unsigned char type, flags;
  unsigned int perms;   /* Perhaps a better def is in order */
  sid_t *trustee;
} ACE; 

typedef struct acl_struct_s {
  unsigned short rev, refcnt;
  unsigned short num_aces;
  ACE *aces[1];
} ACL;

typedef struct sec_desc_s {
  unsigned int rev, type;
  sid_t *owner, *group;
  ACL *sacl, *dacl;
} SEC_DESC;

#define SEC_DESC_NON 0
#define SEC_DESC_RES 1
#define SEC_DESC_OCU 2
#define SEC_DESC_NBK 3
typedef struct sk_struct SK_HDR;
struct key_sec_desc_s {
  struct key_sec_desc_s *prev, *next;
  int ref_cnt;
  int state;
  int offset;
  SK_HDR *sk_hdr;     /* This means we must keep the registry in memory */
  SEC_DESC *sec_desc;
}; 

/* 
 * All of the structures below actually have a four-byte length before them
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
  DWORD off_from_first;
  DWORD off_to_next;
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

struct sk_struct {
  WORD SK_ID;
  WORD uk1;
  DWORD prev_off;
  DWORD next_off;
  DWORD ref_cnt;
  DWORD rec_size;
  char sec_desc[1];
};

typedef struct ace_struct {
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned int perms;
    sid_t trustee;
} REG_ACE;

typedef struct acl_struct {
  WORD rev;
  WORD size;
  DWORD num_aces;
  REG_ACE *aces;   /* One or more ACEs */
} REG_ACL;

typedef struct sec_desc_rec {
  WORD rev;
  WORD type;
  DWORD owner_off;
  DWORD group_off;
  DWORD sacl_off;
  DWORD dacl_off;
} REG_SEC_DESC;

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

#define REG_TYPE_DELETE    -1
#define REG_TYPE_NONE      0
#define REG_TYPE_REGSZ     1
#define REG_TYPE_EXPANDSZ  2
#define REG_TYPE_BIN       3  
#define REG_TYPE_DWORD     4
#define REG_TYPE_MULTISZ   7

typedef struct _val_str { 
  unsigned int val;
  const char * str;
} VAL_STR;

/* A map of sk offsets in the regf to KEY_SEC_DESCs for quick lookup etc */
typedef struct sk_map_s {
  int sk_off;
  KEY_SEC_DESC *key_sec_desc;
} SK_MAP;

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

/*
 * This structure keeps all the registry stuff in one place
 */
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
  SK_MAP *sk_map;
  const char *owner_sid_str;
  SEC_DESC *def_sec_desc;
  /*
   * These next pointers point to the blocks used to contain the 
   * keys when we are preparing to write them to a file
   */
  HBIN_BLK *blk_head, *blk_tail, *free_space;
} REGF;

/*
 * An API for accessing/creating/destroying items above
 */

/*
 * Iterate over the keys, depth first, calling a function for each key
 * and indicating if it is terminal or non-terminal and if it has values.
 *
 * In addition, for each value in the list, call a value list function
 */

typedef int (*key_print_f)(const char *path, char *key_name, char *class_name, 
			   int root, int terminal, int values);

typedef int (*val_print_f)(const char *path, char *val_name, int val_type, 
			   int data_len, void *data_blk, int terminal,
			   int first, int last);

typedef int (*sec_print_f)(SEC_DESC *sec_desc);

static
int nt_key_iterator(REGF *regf, REG_KEY *key_tree, int bf, const char *path, 
		    key_print_f key_print, sec_print_f sec_print,
		    val_print_f val_print);

static
int nt_val_list_iterator(REGF *regf, VAL_LIST *val_list, int bf, char *path,
			 int terminal, val_print_f val_print)
{
  int i;

  if (!val_list) return 1;

  if (!val_print) return 1;

  for (i=0; i<val_list->val_count; i++) {
    if (!val_print(path, val_list->vals[i]->name, val_list->vals[i]->data_type,
		   val_list->vals[i]->data_len, val_list->vals[i]->data_blk,
		   terminal,
		   (i == 0),
		   (i == val_list->val_count))) {

      return 0;

    }
  }

  return 1;
}

static
int nt_key_list_iterator(REGF *regf, KEY_LIST *key_list, int bf, 
			 const char *path,
			 key_print_f key_print, sec_print_f sec_print, 
			 val_print_f val_print)
{
  int i;

  if (!key_list) return 1;

  for (i=0; i< key_list->key_count; i++) {
    if (!nt_key_iterator(regf, key_list->keys[i], bf, path, key_print, 
			 sec_print, val_print)) {
      return 0;
    }
  }
  return 1;
}

static
int nt_key_iterator(REGF *regf, REG_KEY *key_tree, int bf, const char *path,
		    key_print_f key_print, sec_print_f sec_print,
		    val_print_f val_print)
{
  int path_len = strlen(path);
  char *new_path;

  if (!regf || !key_tree)
    return -1;

  /* List the key first, then the values, then the sub-keys */

  if (key_print) {

    if (!(*key_print)(path, key_tree->name, 
		      key_tree->class_name, 
		      (key_tree->type == REG_ROOT_KEY),
		      (key_tree->sub_keys == NULL),
		      (key_tree->values?(key_tree->values->val_count):0)))
      return 0;
  }

  /*
   * If we have a security print routine, call it
   * If the security print routine returns false, stop.
   */
  if (sec_print) {
    if (key_tree->security && !(*sec_print)(key_tree->security->sec_desc))
      return 0;
  }

  new_path = (char *)malloc(path_len + 1 + strlen(key_tree->name) + 1);
  if (!new_path) return 0; /* Errors? */
  new_path[0] = '\0';
  strcat(new_path, path);
  strcat(new_path, key_tree->name);
  strcat(new_path, "\\");

  /*
   * Now, iterate through the values in the val_list 
   */

  if (key_tree->values &&
      !nt_val_list_iterator(regf, key_tree->values, bf, new_path, 
			    (key_tree->values!=NULL),
			    val_print)) {

    free(new_path);
    return 0;
  } 

  /* 
   * Now, iterate through the keys in the key list
   */

  if (key_tree->sub_keys && 
      !nt_key_list_iterator(regf, key_tree->sub_keys, bf, new_path, key_print, 
			    sec_print, val_print)) {
    free(new_path);
    return 0;
  } 

  free(new_path);
  return 1;
}

static
REG_KEY *nt_find_key_by_name(REG_KEY *tree, char *key);

/*
 * Find key by name in a list ...
 * Take the first component and search for that in the list
 */
static
REG_KEY *nt_find_key_in_list_by_name(KEY_LIST *list, char *key)
{
  int i;
  REG_KEY *res = NULL;

  if (!list || !key || !*key) return NULL;

  for (i = 0; i < list->key_count; i++)
    if ((res = nt_find_key_by_name(list->keys[i], key)))
      return res;
  
  return NULL;
}

/* 
 * Find key by name in a tree ... We will assume absolute names here, but we
 * need the root of the tree ...
 */
static
REG_KEY *nt_find_key_by_name(REG_KEY *tree, char *key)
{
  char *lname = NULL, *c1, *c2;
  REG_KEY *tmp;

  if (!tree || !key || !*key) return NULL;

  lname = strdup(key);
  if (!lname) return NULL;

  /*
   * Make sure that the first component is correct ...
   */
  c1 = lname;
  c2 = strchr(c1, '\\');
  if (c2) { /* Split here ... */
    *c2 = 0;
    c2++;
  }
  if (strcmp(c1, tree->name) != 0) goto error; 

  if (c2) {
    tmp = nt_find_key_in_list_by_name(tree->sub_keys, c2);
    free(lname);
    return tmp;
  }
  else {
    if (lname) free(lname);
    return tree;
  }
 error:
  if (lname) free(lname);
  return NULL;
}

/* Make, delete keys */
static
int nt_delete_val_key(VAL_KEY *val_key)
{

  if (val_key) {
    if (val_key->name) free(val_key->name);
    if (val_key->data_blk) free(val_key->data_blk);
    free(val_key);
  };
  return 1;
}

static
int nt_delete_val_list(VAL_LIST *vl)
{
  int i;

  if (vl) {
    for (i=0; i<vl->val_count; i++)
      nt_delete_val_key(vl->vals[i]);
    free(vl);
  }
  return 1;
}

static
int nt_delete_reg_key(REG_KEY *key, int delete_name);

static
int nt_delete_key_list(KEY_LIST *key_list, int delete_name)
{
  int i;

  if (key_list) {
    for (i=0; i<key_list->key_count; i++) 
      nt_delete_reg_key(key_list->keys[i], False);
    free(key_list);
  }
  return 1;
}

/*
 * Find the key, and if it exists, delete it ...
 */
static
int nt_delete_key_by_name(REGF *regf, char *name)
{
  REG_KEY *key;

  if (!name || !*name) return 0;

  key = nt_find_key_by_name(regf->root, name);

  if (key) {
    if (key == regf->root) regf->root = NULL;
    return nt_delete_reg_key(key, True);
  }

  return 0;

}

static
int nt_delete_sid(sid_t *sid)
{

  if (sid) free(sid);
  return 1;

}

static
int nt_delete_ace(ACE *ace)
{

  if (ace) {
    nt_delete_sid(ace->trustee);
    free(ace);
  }
  return 1;

}

static
int nt_delete_acl(ACL *acl)
{

  if (acl) {
    int i;

    for (i=0; i<acl->num_aces; i++)
      nt_delete_ace(acl->aces[i]);

    free(acl);
  }
  return 1;
}

static
int nt_delete_sec_desc(SEC_DESC *sec_desc)
{

  if (sec_desc) {

    nt_delete_sid(sec_desc->owner);
    nt_delete_sid(sec_desc->group);
    nt_delete_acl(sec_desc->sacl);
    nt_delete_acl(sec_desc->dacl);
    free(sec_desc);

  }
  return 1;
}

static
int nt_delete_key_sec_desc(KEY_SEC_DESC *key_sec_desc)
{

  if (key_sec_desc) {
    key_sec_desc->ref_cnt--;
    if (key_sec_desc->ref_cnt<=0) {
      /*
       * There should always be a next and prev, even if they point to us 
       */
      key_sec_desc->next->prev = key_sec_desc->prev;
      key_sec_desc->prev->next = key_sec_desc->next;
      nt_delete_sec_desc(key_sec_desc->sec_desc);
    }
  }
  return 1;
}

static
int nt_delete_reg_key(REG_KEY *key, int delete_name)
{

  if (key) {
    if (key->name) free(key->name);
    if (key->class_name) free(key->class_name);

    /*
     * We will delete the owner if we are not the root and told to ...
     */

    if (key->owner && key->owner->sub_keys && delete_name) {
      REG_KEY *own;
      KEY_LIST *kl;
      int i;
      /* Find our owner, look in keylist for us and shuffle up */
      /* Perhaps should be a function                          */

      own = key->owner;
      kl = own->sub_keys;

      for (i=0; i < kl->key_count && kl->keys[i] != key ; i++) {
	/* Just find the entry ... */
      }

      if (i == kl->key_count) {
	fprintf(stderr, "Bad data structure. Key not found in key list of owner\n");
      }
      else {
	int j;

	/*
	 * Shuffle up. Works for the last one also 
	 */
	for (j = i + 1; j < kl->key_count; j++) {
	  kl->keys[j - 1] = kl->keys[j];
	}

	kl->key_count--;
      }
    }

    if (key->sub_keys) nt_delete_key_list(key->sub_keys, False);
    if (key->values) nt_delete_val_list(key->values);
    if (key->security) nt_delete_key_sec_desc(key->security);
    free(key);
  }
  return 1;
}

/*
 * Convert a string to a value ...
 * FIXME: Error handling and convert this at command parse time ... 
 */
static
void *str_to_val(int type, char *val, int *len)
{
  unsigned int *dwordp = NULL;

  if (!len || !val) return NULL;

  switch (type) {
  case REG_TYPE_REGSZ:
    *len = strlen(val);
    return (void *)val;

  case REG_TYPE_DWORD:
    dwordp = (unsigned int *)malloc(sizeof(unsigned int));
    if (!dwordp) return NULL;
    /* Allow for ddddd and 0xhhhhh and 0ooooo */
    if (strncmp(val, "0x", 2) == 0 || strncmp(val, "0X", 2) == 0) {
      sscanf(&val[2], "%X", dwordp);
    }
    else if (*val == '0') {
      sscanf(&val[1], "%o", dwordp);
    }
    else { 
      sscanf(val, "%d", dwordp);
    }
    *len = sizeof(unsigned int);
    return (void *)dwordp;

    /* FIXME: Implement more of these */

  default:
    return NULL;
  }

  return NULL;
}

/*
 * Add a value to the key specified ... We have to parse the value some more
 * based on the type to get it in the correct internal form
 * An empty name will be converted to "<No Name>" before here
 * Hmmm, maybe not. has_name is for that
 */
static
VAL_KEY *nt_add_reg_value(REG_KEY *key, char *name, int type, char *value)
{
  int i;
  VAL_KEY *tmp = NULL;

  if (!key || !key->values || !name || !*name) return NULL;

  assert(type != REG_TYPE_DELETE); /* We never process deletes here */

  for (i = 0; i < key->values->val_count; i++) {
    if ((!key->values->vals[i]->has_name && !*name) || 
	(key->values->vals[i]->has_name &&
	 strcmp(name, key->values->vals[i]->name) == 0)){ /* Change the value */
      free(key->values->vals[i]->data_blk);
      key->values->vals[i]->data_blk = str_to_val(type, value, &
						  key->values->vals[i]->data_len);
      return key->values->vals[i];
    }
  }

  /* 
   * If we get here, the name was not found, so insert it 
   */

  tmp = (VAL_KEY *)malloc(sizeof(VAL_KEY));
  if (!tmp) goto error;

  memset(tmp, 0, sizeof(VAL_KEY));
  tmp->name = strdup(name);
  tmp->has_name = True;
  if (!tmp->name) goto error;
  tmp->data_type = type;
  tmp->data_blk = str_to_val(type, value, &tmp->data_len);

  /* Now, add to val list */

  if (key->values->val_count >= key->values->max_vals) {
    /*
     * Allocate some more space 
     */

    if ((key->values = (VAL_LIST *)realloc(key->values, sizeof(VAL_LIST) + 
					   key->values->val_count - 1 +
					   REG_KEY_LIST_SIZE))) {
      key->values->max_vals += REG_KEY_LIST_SIZE;
    }
    else goto error;
  }

  i = key->values->val_count;
  key->values->val_count++;
  key->values->vals[i] = tmp;
  return tmp;

 error:
  if (tmp) nt_delete_val_key(tmp);
  return NULL;
}

/*
 * Delete a value. We return the value and let the caller deal with it. 
 */
static
VAL_KEY *nt_delete_reg_value(REG_KEY *key, char *name)
{
  int i, j;

  if (!key || !key->values || !name || !*name) return NULL;

  /* FIXME: Allow empty value name */
  for (i = 0; i< key->values->val_count; i++) {
    if ((!key->values->vals[i]->has_name && !*name) || 
	(key->values->vals[i]->has_name &&
	 strcmp(name, key->values->vals[i]->name) == 0)) {
      VAL_KEY *val;

      val = key->values->vals[i];

      /* Shuffle down */
      for (j = i + 1; j < key->values->val_count; j++)
	key->values->vals[j - 1] = key->values->vals[j];

      key->values->val_count--;

      return val;
    }
  }
  return NULL;
}

/* 
 * Add a key to the tree ... We walk down the components matching until
 * we don't find any. There must be a match on the first component ...
 * We return the key structure for the final component as that is 
 * often where we want to add values ...
 */

/*
 * Convert a string of the form S-1-5-x[-y-z-r] to a SID
 */
static
int sid_string_to_sid(sid_t **sid, const char *sid_str)
{
  int i = 0, auth;
  const char *lstr; 

  *sid = (sid_t *)malloc(sizeof(sid_t));
  if (!*sid) return 0;

  memset(*sid, 0, sizeof(sid_t));

  if (strncmp(sid_str, "S-1-5", 5)) {
    fprintf(stderr, "Does not conform to S-1-5...: %s\n", sid_str);
    return 0;
  }

  /* We only allow strings of form S-1-5... */

  (*sid)->ver = 1;
  (*sid)->auth[5] = 5;

  lstr = sid_str + 5;

  while (1) {
    if (!lstr || !lstr[0] || sscanf(lstr, "-%u", &auth) == 0) {
      if (i < 1) {
	fprintf(stderr, "Not of form -d-d...: %s, %u\n", lstr, i);
	return 0;
      }
      (*sid)->auths=i;
      return 1;
    }

    (*sid)->sub_auths[i] = auth;
    i++;
    lstr = strchr(lstr + 1, '-'); 
  }

  /*return 1; */ /* Not Reached ... */
}

/*
 * Create an ACE
 */
static
ACE *nt_create_ace(int type, int flags, unsigned int perms, const char *sid)
{
  ACE *ace;

  ace = (ACE *)malloc(sizeof(ACE));
  if (!ace) goto error;
  ace->type = type;
  ace->flags = flags;
  ace->perms = perms;
  if (!sid_string_to_sid(&ace->trustee, sid))
    goto error;
  return ace;

 error:
  if (ace) nt_delete_ace(ace);
  return NULL;
}

/*
 * Create a default ACL
 */
static
ACL *nt_create_default_acl(REGF *regf)
{
  ACL *acl;

  acl = (ACL *)malloc(sizeof(ACL) + 7*sizeof(ACE *));
  if (!acl) goto error;

  acl->rev = 2;
  acl->refcnt = 1;
  acl->num_aces = 8;

  acl->aces[0] = nt_create_ace(0x00, 0x0, 0xF003F, regf->owner_sid_str);
  if (!acl->aces[0]) goto error;
  acl->aces[1] = nt_create_ace(0x00, 0x0, 0xF003F, "S-1-5-18");
  if (!acl->aces[1]) goto error;
  acl->aces[2] = nt_create_ace(0x00, 0x0, 0xF003F, "S-1-5-32-544");
  if (!acl->aces[2]) goto error;
  acl->aces[3] = nt_create_ace(0x00, 0x0, 0x20019, "S-1-5-12");
  if (!acl->aces[3]) goto error;
  acl->aces[4] = nt_create_ace(0x00, 0x0B, 0x10000000, regf->owner_sid_str);
  if (!acl->aces[4]) goto error;
  acl->aces[5] = nt_create_ace(0x00, 0x0B, 0x10000000, "S-1-5-18");
  if (!acl->aces[5]) goto error;
  acl->aces[6] = nt_create_ace(0x00, 0x0B, 0x10000000, "S-1-5-32-544");
  if (!acl->aces[6]) goto error;
  acl->aces[7] = nt_create_ace(0x00, 0x0B, 0x80000000, "S-1-5-12");
  if (!acl->aces[7]) goto error;
  return acl;

 error:
  if (acl) nt_delete_acl(acl);
  return NULL;
}

/*
 * Create a default security descriptor. We pull in things from env
 * if need be 
 */
static
SEC_DESC *nt_create_def_sec_desc(REGF *regf)
{
  SEC_DESC *tmp;

  tmp = (SEC_DESC *)malloc(sizeof(SEC_DESC));
  if (!tmp) return NULL;

  tmp->rev = 1;
  tmp->type = 0x8004;
  if (!sid_string_to_sid(&tmp->owner, "S-1-5-32-544")) goto error;
  if (!sid_string_to_sid(&tmp->group, "S-1-5-18")) goto error;
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
static
KEY_SEC_DESC *nt_inherit_security(REG_KEY *key)
{

  if (!key) return NULL;
  return key->security;
}

/*
 * Create an initial security descriptor and init other structures, if needed
 * We assume that the initial security stuff is empty ...
 */
static
KEY_SEC_DESC *nt_create_init_sec(REGF *regf)
{
  KEY_SEC_DESC *tsec = NULL;
  
  tsec = (KEY_SEC_DESC *)malloc(sizeof(KEY_SEC_DESC));
  if (!tsec) return NULL;

  tsec->ref_cnt = 1;
  tsec->state = SEC_DESC_NBK;
  tsec->offset = 0;

  tsec->sec_desc = regf->def_sec_desc;

  return tsec;
}

/*
 * Add a sub-key 
 */
static
REG_KEY *nt_add_reg_key_list(REGF *regf, REG_KEY *key, char * name, int create)
{
  int i;
  REG_KEY *ret = NULL, *tmp = NULL;
  KEY_LIST *list;
  char *lname, *c1, *c2;

  if (!key || !name || !*name) return NULL;
  
  list = key->sub_keys;
  if (!list) { /* Create an empty list */

    list = (KEY_LIST *)malloc(sizeof(KEY_LIST) + (REG_KEY_LIST_SIZE - 1) * sizeof(REG_KEY *));
    list->key_count = 0;
    list->max_keys = REG_KEY_LIST_SIZE;

  }

  lname = strdup(name);
  if (!lname) return NULL;

  c1 = lname;
  c2 = strchr(c1, '\\');
  if (c2) { /* Split here ... */
    *c2 = 0;
    c2++;
  }

  for (i = 0; i < list->key_count; i++) {
    if (strcmp(list->keys[i]->name, c1) == 0) {
      ret = nt_add_reg_key_list(regf, list->keys[i], c2, create);
      free(lname);
      return ret;
    }
  }

  /*
   * If we reach here we could not find the the first component
   * so create it ...
   */

  if (list->key_count < list->max_keys){
    list->key_count++;
  }
  else { /* Create more space in the list ... */
    if (!(list = (KEY_LIST *)realloc(list, sizeof(KEY_LIST) + 
				     (list->max_keys + REG_KEY_LIST_SIZE - 1) 
				     * sizeof(REG_KEY *))))
      goto error;

    list->max_keys += REG_KEY_LIST_SIZE;
    list->key_count++;
  }

  /*
   * add the new key at the new slot 
   * FIXME: Sort the list someday
   */

  /*
   * We want to create the key, and then do the rest
   */

  tmp = (REG_KEY *)malloc(sizeof(REG_KEY)); 

  memset(tmp, 0, sizeof(REG_KEY));

  tmp->name = strdup(c1);
  if (!tmp->name) goto error;
  tmp->owner = key;
  tmp->type = REG_SUB_KEY;
  /*
   * Next, pull security from the parent, but override with
   * anything passed in on the command line
   */
  tmp->security = nt_inherit_security(key);

  list->keys[list->key_count - 1] = tmp;

  if (c2) {
    ret = nt_add_reg_key_list(regf, key, c2, True);
  }

  if (lname) free(lname);

  return ret;

 error:
  if (tmp) free(tmp);
  if (lname) free(lname);
  return NULL;
}

/*
 * This routine only adds a key from the root down.
 * It calls helper functions to handle sub-key lists and sub-keys
 */
static
REG_KEY *nt_add_reg_key(REGF *regf, char *name, int create)
{
  char *lname = NULL, *c1, *c2;
  REG_KEY * tmp = NULL;

  /*
   * Look until we hit the first component that does not exist, and
   * then add from there. However, if the first component does not 
   * match and the path we are given is the root, then it must match
   */
  if (!regf || !name || !*name) return NULL;

  lname = strdup(name);
  if (!lname) return NULL;

  c1 = lname;
  c2 = strchr(c1, '\\');
  if (c2) { /* Split here ... */
    *c2 = 0;
    c2++;
  }

  /*
   * If the root does not exist, create it and make it equal to the
   * first component ...
   */

  if (!regf->root) {
    
    tmp = (REG_KEY *)malloc(sizeof(REG_KEY));
    if (!tmp) goto error;
    memset(tmp, 0, sizeof(REG_KEY));
    tmp->name = strdup(c1);
    if (!tmp->name) goto error;
    tmp->security = nt_create_init_sec(regf);
    if (!tmp->security) goto error;
    regf->root = tmp;

  }
  else {
    /*
     * If we don't match, then we have to return error ...
     * If we do match on this component, check the next one in the
     * list, and if not found, add it ... short circuit, add all the
     * way down
     */

    if (strcmp(c1, regf->root->name) != 0)
      goto error;
  }

  tmp = nt_add_reg_key_list(regf, regf->root, c2, True);
  free(lname);
  return tmp;
  
 error:
  if (tmp) free(tmp);
  if (lname) free(lname);
  return NULL;
}

/*
 * Load and unload a registry file.
 *
 * Load, loads it into memory as a tree, while unload sealizes/flattens it
 */

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

#define REGF_REGTYPE_NONE 0
#define REGF_REGTYPE_NT   1
#define REGF_REGTYPE_W9X  2

#define TTTONTTIME(r, t1, t2) (r)->last_mod_time.low = (t1); \
                              (r)->last_mod_time.high = (t2);

#define REGF_HDR_BLKSIZ 0x1000 

#define OFF(f) ((f) + REGF_HDR_BLKSIZ + 4) 
#define LOCN(base, f) ((base) + OFF(f))

const VAL_STR reg_type_names[] = {
   { REG_TYPE_REGSZ,    "REG_SZ" },
   { REG_TYPE_EXPANDSZ, "REG_EXPAND_SZ" },
   { REG_TYPE_BIN,      "REG_BIN" },
   { REG_TYPE_DWORD,    "REG_DWORD" },
   { REG_TYPE_MULTISZ,  "REG_MULTI_SZ" },
   { 0, NULL },
};

static
const char *val_to_str(unsigned int val, const VAL_STR *val_array)
{
  int i = 0;

  if (!val_array) return NULL;

  while (val_array[i].val && val_array[i].str) {

    if (val_array[i].val == val) return val_array[i].str;
    i++;

  }

  return NULL;

}

/*
 * Convert from UniCode to Ascii ... Does not take into account other lang
 * Restrict by ascii_max if > 0
 */
static
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

/*
 * Convert a data value to a string for display
 */
static
int data_to_ascii(unsigned char *datap, int len, int type, char *ascii, int ascii_max)
{ 
  unsigned char *asciip;
  int i;

  switch (type) {
  case REG_TYPE_REGSZ:
    if (verbose) fprintf(stderr, "Len: %d\n", len);
    /* FIXME. This has to be fixed. It has to be UNICODE */ 
    return uni_to_ascii(datap, ascii, len, ascii_max);
    break; /*NOTREACHED*/

  case REG_TYPE_EXPANDSZ:
    return uni_to_ascii(datap, ascii, len, ascii_max);
    break;

  case REG_TYPE_BIN:
    asciip = ascii;
    for (i=0; (i<len)&&(i+1)*3<ascii_max; i++) { 
      int str_rem = ascii_max - ((int)asciip - (int)ascii);
      asciip += snprintf(asciip, str_rem, "%02x", *(unsigned char *)(datap+i));
      if (i < len && str_rem > 0)
	*asciip = ' '; asciip++;	
    }
    *asciip = '\0';
    return ((int)asciip - (int)ascii);
    break;

  case REG_TYPE_DWORD:
    if (*(int *)datap == 0)
      return snprintf(ascii, ascii_max, "0");
    else
      return snprintf(ascii, ascii_max, "0x%x", *(int *)datap);
    break;

  case REG_TYPE_MULTISZ:

    break;

  default:
    return 0;
    break;
  } 

  return len;

}

static
REG_KEY *nt_get_key_tree(REGF *regf, NK_HDR *nk_hdr, int size, REG_KEY *parent);

static
int nt_set_regf_input_file(REGF *regf, char *filename)
{
  return ((regf->regfile_name = strdup(filename)) != NULL); 
}

static
int nt_set_regf_output_file(REGF *regf, char *filename)
{
  return ((regf->outfile_name = strdup(filename)) != NULL); 
}

/* Create a regf structure and init it */

static
REGF *nt_create_regf(void)
{
  REGF *tmp = (REGF *)malloc(sizeof(REGF));
  if (!tmp) return tmp;
  memset(tmp, 0, sizeof(REGF));
  tmp->owner_sid_str = def_owner_sid_str;
  return tmp;
} 

/* Free all the bits and pieces ... Assumes regf was malloc'd */
/* If you add stuff to REGF, add the relevant free bits here  */
static
int nt_free_regf(REGF *regf)
{
  if (!regf) return 0;

  if (regf->regfile_name) free(regf->regfile_name);
  if (regf->outfile_name) free(regf->outfile_name);

  nt_delete_reg_key(regf->root, False); /* Free the tree */
  free(regf->sk_map);
  regf->sk_count = regf->sk_map_size = 0;

  free(regf);

  return 1;
}

/* Get the header of the registry. Return a pointer to the structure 
 * If the mmap'd area has not been allocated, then mmap the input file
 */
static
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
static
int valid_regf_hdr(REGF_HDR *regf_hdr)
{
  if (!regf_hdr) return 0;

  return 1;
}

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
static
SK_MAP *alloc_sk_map_entry(REGF *regf, KEY_SEC_DESC *tmp, int sk_off)
{
 if (!regf->sk_map) { /* Allocate a block of 10 */
    regf->sk_map = (SK_MAP *)malloc(sizeof(SK_MAP) * 10);
    if (!regf->sk_map) {
      free(tmp);
      return NULL;
    }
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
static
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
static
KEY_SEC_DESC *lookup_create_sec_key(REGF *regf, SK_MAP *sk_map, int sk_off)
{
  KEY_SEC_DESC *tmp = lookup_sec_key(regf->sk_map, regf->sk_count, sk_off);

  if (tmp) {
    return tmp;
  }
  else { /* Allocate a new one */
    tmp = (KEY_SEC_DESC *)malloc(sizeof(KEY_SEC_DESC));
    if (!tmp) {
      return NULL;
    }
    memset(tmp, 0, sizeof(KEY_SEC_DESC)); /* Neatly sets offset to 0 */
    tmp->state = SEC_DESC_RES;
    if (!alloc_sk_map_entry(regf, tmp, sk_off)) {
      return NULL;
    }
    return tmp;
  }
}

/*
 * Allocate storage and duplicate a SID 
 * We could allocate the SID to be only the size needed, but I am too lazy. 
 */
static
sid_t *dup_sid(sid_t *sid)
{
  sid_t *tmp = (sid_t *)malloc(sizeof(sid_t));
  int i;
  
  if (!tmp) return NULL;
  tmp->ver = sid->ver;
  tmp->auths = sid->auths;
  for (i=0; i<6; i++) {
    tmp->auth[i] = sid->auth[i];
  }
  for (i=0; i<tmp->auths&&i<MAXSUBAUTHS; i++) {
    tmp->sub_auths[i] = sid->sub_auths[i];
  }
  return tmp;
}

/*
 * Allocate space for an ACE and duplicate the registry encoded one passed in
 */
static
ACE *dup_ace(REG_ACE *ace)
{
  ACE *tmp = NULL; 

  tmp = (ACE *)malloc(sizeof(ACE));

  if (!tmp) return NULL;

  tmp->type = CVAL(&ace->type);
  tmp->flags = CVAL(&ace->flags);
  tmp->perms = IVAL(&ace->perms);
  tmp->trustee = dup_sid(&ace->trustee);
  return tmp;
}

/*
 * Allocate space for an ACL and duplicate the registry encoded one passed in 
 */
static
ACL *dup_acl(REG_ACL *acl)
{
  ACL *tmp = NULL;
  REG_ACE* ace;
  int i, num_aces;

  num_aces = IVAL(&acl->num_aces);

  tmp = (ACL *)malloc(sizeof(ACL) + (num_aces - 1)*sizeof(ACE *));
  if (!tmp) return NULL;

  tmp->num_aces = num_aces;
  tmp->refcnt = 1;
  tmp->rev = SVAL(&acl->rev);
  if (verbose) fprintf(stdout, "ACL: refcnt: %u, rev: %u\n", tmp->refcnt, 
		       tmp->rev);
  ace = (REG_ACE *)&acl->aces;
  for (i=0; i<num_aces; i++) {
    tmp->aces[i] = dup_ace(ace);
    ace = (REG_ACE *)((char *)ace + SVAL(&ace->length));
    /* XXX: FIXME, should handle malloc errors */
  }

  return tmp;
}

static
SEC_DESC *process_sec_desc(REGF *regf, REG_SEC_DESC *sec_desc)
{
  SEC_DESC *tmp = NULL;
  
  tmp = (SEC_DESC *)malloc(sizeof(SEC_DESC));

  if (!tmp) {
    return NULL;
  }
  
  tmp->rev = SVAL(&sec_desc->rev);
  tmp->type = SVAL(&sec_desc->type);
  if (verbose) fprintf(stdout, "SEC_DESC Rev: %0X, Type: %0X\n", 
		       tmp->rev, tmp->type);
  if (verbose) fprintf(stdout, "SEC_DESC Owner Off: %0X\n",
		       IVAL(&sec_desc->owner_off));
  if (verbose) fprintf(stdout, "SEC_DESC Group Off: %0X\n",
		       IVAL(&sec_desc->group_off));
  if (verbose) fprintf(stdout, "SEC_DESC DACL Off: %0X\n",
		       IVAL(&sec_desc->dacl_off));
  tmp->owner = dup_sid((sid_t *)((char *)sec_desc + IVAL(&sec_desc->owner_off)));
  if (!tmp->owner) {
    free(tmp);
    return NULL;
  }
  tmp->group = dup_sid((sid_t *)((char *)sec_desc + IVAL(&sec_desc->group_off)));
  if (!tmp->group) {
    free(tmp);
    return NULL;
  }

  /* Now pick up the SACL and DACL */

  if (sec_desc->sacl_off)
    tmp->sacl = dup_acl((REG_ACL *)((char *)sec_desc + IVAL(&sec_desc->sacl_off)));
  else
    tmp->sacl = NULL;

  if (sec_desc->dacl_off)
    tmp->dacl = dup_acl((REG_ACL *)((char *)sec_desc + IVAL(&sec_desc->dacl_off)));
  else
    tmp->dacl = NULL;

  return tmp;
}

static
KEY_SEC_DESC *process_sk(REGF *regf, SK_HDR *sk_hdr, int sk_off, int size)
{
  KEY_SEC_DESC *tmp = NULL;
  int sk_next_off, sk_prev_off, sk_size;
  REG_SEC_DESC *sec_desc;

  if (!sk_hdr) return NULL;

  if (SVAL(&sk_hdr->SK_ID) != REG_SK_ID) {
    fprintf(stderr, "Unrecognized SK Header ID: %08X, %s\n", (int)sk_hdr,
	    regf->regfile_name);
    return NULL;
  }

  if (-size < (sk_size = IVAL(&sk_hdr->rec_size))) {
    fprintf(stderr, "Incorrect SK record size: %d vs %d. %s\n",
	    -size, sk_size, regf->regfile_name);
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

  assert(tmp == NULL || (tmp && tmp->state != SEC_DESC_NON));

  /*
   * Now, allocate a KEY_SEC_DESC, and parse the structure here, and add the
   * new KEY_SEC_DESC to the mapping structure, since the offset supplied is 
   * the actual offset of structure. The same offset will be used by
   * all future references to this structure
   * We could put all this unpleasantness in a function.
   */

  if (!tmp) {
    tmp = (KEY_SEC_DESC *)malloc(sizeof(KEY_SEC_DESC));
    if (!tmp) return NULL;
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

  sec_desc = (REG_SEC_DESC *)&sk_hdr->sec_desc[0];
  tmp->sec_desc = process_sec_desc(regf, sec_desc);

  /*
   * Now forward and back links. Here we allocate an entry in the sk_map
   * if it does not exist, and mark it reserved
   */

  sk_prev_off = IVAL(&sk_hdr->prev_off);
  tmp->prev = lookup_create_sec_key(regf, regf->sk_map, sk_prev_off);
  assert(tmp->prev != NULL);
  sk_next_off = IVAL(&sk_hdr->next_off);
  tmp->next = lookup_create_sec_key(regf, regf->sk_map, sk_next_off);
  assert(tmp->next != NULL);

  return tmp;
}

/*
 * Process a VK header and return a value
 */
static
VAL_KEY *process_vk(REGF *regf, VK_HDR *vk_hdr, int size)
{
  char val_name[1024];
  int nam_len, dat_len, flag, dat_type, dat_off, vk_id;
  const char *val_type;
  VAL_KEY *tmp = NULL; 

  if (!vk_hdr) return NULL;

  if ((vk_id = SVAL(&vk_hdr->VK_ID)) != REG_VK_ID) {
    fprintf(stderr, "Unrecognized VK header ID: %0X, block: %0X, %s\n",
	    vk_id, (int)vk_hdr, regf->regfile_name);
    return NULL;
  }

  nam_len = SVAL(&vk_hdr->nam_len);
  val_name[nam_len] = '\0';
  flag = SVAL(&vk_hdr->flag);
  dat_type = IVAL(&vk_hdr->dat_type);
  dat_len = IVAL(&vk_hdr->dat_len);  /* If top bit, offset contains data */
  dat_off = IVAL(&vk_hdr->dat_off);

  tmp = (VAL_KEY *)malloc(sizeof(VAL_KEY));
  if (!tmp) {
    goto error;
  }
  memset(tmp, 0, sizeof(VAL_KEY));
  tmp->has_name = flag;
  tmp->data_type = dat_type;

  if (flag & 0x01) {
    strncpy(val_name, vk_hdr->dat_name, nam_len);
    tmp->name = strdup(val_name);
    if (!tmp->name) {
      goto error;
    }
  }
  else
    strncpy(val_name, "<No Name>", 10);

  /*
   * Allocate space and copy the data as a BLOB
   */

  if (dat_len) {
    
    char *dtmp = (char *)malloc(dat_len&0x7FFFFFFF);
    
    if (!dtmp) {
      goto error;
    }

    tmp->data_blk = dtmp;

    if ((dat_len&0x80000000) == 0) { /* The data is pointed to by the offset */
      char *dat_ptr = LOCN(regf->base, dat_off);
      bcopy(dat_ptr, dtmp, dat_len);
    }
    else { /* The data is in the offset or type */
      /*
       * FIXME.
       * Some registry files seem to have wierd fields. If top bit is set,
       * but len is 0, the type seems to be the value ...
       * Not sure how to handle this last type for the moment ...
       */
      dat_len = dat_len & 0x7FFFFFFF;
      bcopy(&dat_off, dtmp, dat_len);
    }

    tmp->data_len = dat_len;
  }

  val_type = val_to_str(dat_type, reg_type_names);

  /*
   * We need to save the data area as well
   */

  if (verbose) fprintf(stdout, "  %s : %s : \n", val_name, val_type);

  return tmp;

 error:
  if (tmp) nt_delete_val_key(tmp);
  return NULL;

}

/*
 * Process a VL Header and return a list of values
 */
static
VAL_LIST *process_vl(REGF *regf, VL_TYPE vl, int count, int size)
{
  int i, vk_off;
  VK_HDR *vk_hdr;
  VAL_LIST *tmp = NULL;

  if (!vl) return NULL;

  if (-size < (count+1)*sizeof(int)){
    fprintf(stderr, "Error in VL header format. Size less than space required. %d\n", -size);
    return NULL;
  }

  tmp = (VAL_LIST *)malloc(sizeof(VAL_LIST) + (count - 1) * sizeof(VAL_KEY *));
  if (!tmp) {
    goto error;
  }

  for (i=0; i<count; i++) {
    vk_off = IVAL(&vl[i]);
    vk_hdr = (VK_HDR *)LOCN(regf->base, vk_off);
    tmp->vals[i] = process_vk(regf, vk_hdr, BLK_SIZE(vk_hdr));
    if (!tmp->vals[i]){
      goto error;
    }
  }

  tmp->val_count = count;
  tmp->max_vals = count;

  return tmp;

 error:
  /* XXX: FIXME, free the partially allocated structure */
  return NULL;
} 

/*
 * Process an LF Header and return a list of sub-keys
 */
static
KEY_LIST *process_lf(REGF *regf, LF_HDR *lf_hdr, int size, REG_KEY *parent)
{
  int count, i, nk_off;
  unsigned int lf_id;
  KEY_LIST *tmp;

  if (!lf_hdr) return NULL;

  if ((lf_id = SVAL(&lf_hdr->LF_ID)) != REG_LF_ID) {
    fprintf(stderr, "Unrecognized LF Header format: %0X, Block: %0X, %s.\n",
	    lf_id, (int)lf_hdr, regf->regfile_name);
    return NULL;
  }

  assert(size < 0);

  count = SVAL(&lf_hdr->key_count);
  if (verbose) fprintf(stdout, "Key Count: %u\n", count);
  if (count <= 0) return NULL;

  /* Now, we should allocate a KEY_LIST struct and fill it in ... */

  tmp = (KEY_LIST *)malloc(sizeof(KEY_LIST) + (count - 1) * sizeof(REG_KEY *));
  if (!tmp) {
    goto error;
  }

  tmp->key_count = count;
  tmp->max_keys = count;

  for (i=0; i<count; i++) {
    NK_HDR *nk_hdr;

    nk_off = IVAL(&lf_hdr->hr[i].nk_off);
    if (verbose) fprintf(stdout, "NK Offset: %0X\n", nk_off);
    nk_hdr = (NK_HDR *)LOCN(regf->base, nk_off);
    tmp->keys[i] = nt_get_key_tree(regf, nk_hdr, BLK_SIZE(nk_hdr), parent);
    if (!tmp->keys[i]) {
      goto error;
    }
  }

  return tmp;

 error:
  if (tmp) nt_delete_key_list(tmp, False);
  return NULL;
}

/*
 * This routine is passed an NK_HDR pointer and retrieves the entire tree
 * from there down. It returns a REG_KEY *.
 */
static
REG_KEY *nt_get_key_tree(REGF *regf, NK_HDR *nk_hdr, int size, REG_KEY *parent)
{
  REG_KEY *tmp = NULL, *own;
  int name_len, clsname_len, lf_off, val_off, val_count, sk_off, own_off;
  unsigned int nk_id;
  LF_HDR *lf_hdr;
  VL_TYPE *vl;
  SK_HDR *sk_hdr;
  char key_name[1024], cls_name[1024];

  if (!nk_hdr) return NULL;

  if ((nk_id = SVAL(&nk_hdr->NK_ID)) != REG_NK_ID) {
    fprintf(stderr, "Unrecognized NK Header format: %08X, Block: %0X. %s\n", 
	    nk_id, (int)nk_hdr, regf->regfile_name);
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
    fprintf(stderr, "Incorrect NK_HDR size: %d, %0X\n", -size, (int)nk_hdr);
    fprintf(stderr, "Sizeof NK_HDR: %d, name_len %d, clsname_len %d\n",
	    sizeof(NK_HDR), name_len, clsname_len);
    /*return NULL;*/
  }

  if (verbose) fprintf(stdout, "NK HDR: Name len: %d, class name len: %d\n", 
		       name_len, clsname_len);

  /* Fish out the key name and process the LF list */

  assert(name_len < sizeof(key_name));

  /* Allocate the key struct now */
  tmp = (REG_KEY *)malloc(sizeof(REG_KEY));
  if (!tmp) return tmp;
  memset(tmp, 0, sizeof(REG_KEY));

  tmp->type = (SVAL(&nk_hdr->type)==0x2C?REG_ROOT_KEY:REG_SUB_KEY);
  
  strncpy(key_name, nk_hdr->key_nam, name_len);
  key_name[name_len] = '\0';

  if (verbose) fprintf(stdout, "Key name: %s\n", key_name);

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
    if (verbose) fprintf(stdout, "Class Name Offset: %0X\n", clsnam_off);
 
    memset(cls_name, 0, clsname_len);
    uni_to_ascii(clsnamep, cls_name, sizeof(cls_name), clsname_len);
    
    /*
     * I am keeping class name as an ascii string for the moment.
     * That means it needs to be converted on output.
     * It will also piss off people who need Unicode/UTF-8 strings. Sorry. 
     * XXX: FIXME
     */

    tmp->class_name = strdup(cls_name);
    if (!tmp->class_name) {
      goto error;
    }

    if (verbose) fprintf(stdout, "  Class Name: %s\n", cls_name);

  }

  /*
   * Process the owner offset ...
   */

  own_off = IVAL(&nk_hdr->own_off);
  own = (REG_KEY *)LOCN(regf->base, own_off);
  if (verbose) fprintf(stdout, "Owner Offset: %0X\n", own_off);

  if (verbose) fprintf(stdout, "  Owner locn: %0X, Our locn: %0X\n", 
		       (unsigned int)own, (unsigned int)nk_hdr);

  /* 
   * We should verify that the owner field is correct ...
   * for now, we don't worry ...
   */

  tmp->owner = parent;

  /*
   * If there are any values, process them here
   */

  val_count = IVAL(&nk_hdr->val_cnt);
  if (verbose) fprintf(stdout, "Val Count: %d\n", val_count);
  if (val_count) {

    val_off = IVAL(&nk_hdr->val_off);
    vl = (VL_TYPE *)LOCN(regf->base, val_off);
    if (verbose) fprintf(stdout, "Val List Offset: %0X\n", val_off);

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
  if (verbose) fprintf(stdout, "SK Offset: %0X\n", sk_off);

  if (sk_off != -1) {

    tmp->security = process_sk(regf, sk_hdr, sk_off, BLK_SIZE(sk_hdr));

  } 

  lf_off = IVAL(&nk_hdr->lf_off);
  if (verbose) fprintf(stdout, "SubKey list offset: %0X\n", lf_off);

  /*
   * No more subkeys if lf_off == -1
   */

  if (lf_off != -1) {

    lf_hdr = (LF_HDR *)LOCN(regf->base, lf_off);
    
    tmp->sub_keys = process_lf(regf, lf_hdr, BLK_SIZE(lf_hdr), tmp);
    if (!tmp->sub_keys){
      goto error;
    }

  }

  return tmp;

 error:
  if (tmp) nt_delete_reg_key(tmp, False);
  return NULL;
}

static
int nt_load_registry(REGF *regf)
{
  REGF_HDR *regf_hdr;
  unsigned int regf_id, hbin_id;
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

  if (verbose) fprintf(stdout, "First Key: %0X\n",
		       IVAL(&regf_hdr->first_key));

  first_key = (NK_HDR *)LOCN(regf->base, IVAL(&regf_hdr->first_key));
  if (verbose) fprintf(stdout, "First Key Offset: %0X\n", 
		       IVAL(&regf_hdr->first_key));

  if (verbose) fprintf(stdout, "Data Block Size: %d\n",
		       IVAL(&regf_hdr->dblk_size));

  if (verbose) fprintf(stdout, "Offset to next hbin block: %0X\n",
		       IVAL(&hbin_hdr->off_to_next));

  if (verbose) fprintf(stdout, "HBIN block size: %0X\n",
		       IVAL(&hbin_hdr->blk_size));

  /*
   * Now, get the registry tree by processing that NK recursively
   */

  regf->root = nt_get_key_tree(regf, first_key, BLK_SIZE(first_key), NULL);

  assert(regf->root != NULL);

  /*
   * Unmap the registry file, as we might want to read in another
   * tree etc.
   */

  if (regf->base) munmap(regf->base, regf->sbuf.st_size);
  regf->base = NULL;
  close(regf->fd);    /* Ignore the error :-) */

  return 1;
}

/*
 * Allocate a new hbin block, set up the header for the block etc 
 */
static
HBIN_BLK *nt_create_hbin_blk(REGF *regf, int size)
{
  HBIN_BLK *tmp;
  HBIN_HDR *hdr;

  if (!regf || !size) return NULL;

  /* Round size up to multiple of REGF_HDR_BLKSIZ */

  size = (size + (REGF_HDR_BLKSIZ - 1)) & ~(REGF_HDR_BLKSIZ - 1);

  tmp = (HBIN_BLK *)malloc(sizeof(HBIN_BLK));
  memset(tmp, 0, sizeof(HBIN_BLK));

  tmp->data = malloc(size);
  if (!tmp->data) goto error;

  memset(tmp->data, 0, size);  /* Make it pristine */

  tmp->size = size;
  tmp->file_offset = regf->blk_tail->file_offset + regf->blk_tail->size;

  tmp->free_space = size - (sizeof(HBIN_HDR) - sizeof(HBIN_SUB_HDR));
  tmp->fsp_off = size - tmp->free_space;

  /* 
   * Now, build the header in the data block 
   */
  hdr = (HBIN_HDR *)tmp->data;
  hdr->HBIN_ID = REG_HBIN_ID;
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
 error:
  if (tmp) free(tmp);
  return NULL;
}

/*
 * Allocate a unit of space ... and return a pointer as function param
 * and the block's offset as a side effect
 */
static
void *nt_alloc_regf_space(REGF *regf, int size, unsigned int *off)
{
  int tmp = 0;
  void *ret = NULL;
  HBIN_BLK *blk;
  
  if (!regf || !size || !off) return NULL;

  assert(regf->blk_head != NULL);

  /*
   * round up size to include header and then to 8-byte boundary
   */
  size = (size + 4 + 7) & ~7;

  /*
   * Check if there is space, if none, grab a block
   */
  if (!regf->free_space) {
    if (!nt_create_hbin_blk(regf, REGF_HDR_BLKSIZ))
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
  if (nt_create_hbin_blk(regf, REGF_HDR_BLKSIZ)) {
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
 * Compute the size of a SID stored ...
 */
static
unsigned int sid_size(sid_t *sid)
{
  unsigned int size;

  if (!sid) return 0;

  size = 8 + (sid->auths * sizeof(unsigned int));

  return size;
}

/*
 * Compute the size of an ACE on disk from its components
 */
static
unsigned int ace_size(ACE *ace)
{
  unsigned int size;

  if (!ace) return 0;

  size = 8 + sid_size(ace->trustee);

  return size;
}     

/* 
 * Compute the size of an ACL from its components ...
 */
static
unsigned int acl_size(ACL *acl)
{
  unsigned int size;
  int i;

  if (!acl) return 0;

  size = 8; 
  for (i = 0; i < acl->num_aces; i++)
    size += ace_size(acl->aces[i]);

  return size;
}

/*
 * Compute the size of the sec desc as a self-relative SD
 */
static
unsigned int sec_desc_size(SEC_DESC *sd)
{
  unsigned int size;
  
  if (!sd) return 0;

  size = 20;

  if (sd->owner) size += sid_size(sd->owner);
  if (sd->group) size += sid_size(sd->group);
  if (sd->sacl) size += acl_size(sd->sacl);
  if (sd->dacl) size += acl_size(sd->dacl);

  return size;
}

/*
 * Store a SID at the location provided
 */
static
int nt_store_SID(REGF *regf, sid_t *sid, unsigned char *locn)
{
  int i;
  unsigned char *p = locn;

  if (!regf || !sid || !locn) return 0;

  *p = sid->ver; p++;
  *p = sid->auths; p++;
  
  for (i=0; i < 6; i++) {
    *p = sid->auth[i]; p++;
  }

  for (i=0; i < sid->auths; i++) {
    SIVAL(p, sid->sub_auths[i]); p+=4;
  }

  return p - locn;
  
}

static
int nt_store_ace(REGF *regf, ACE *ace, unsigned char *locn)
{
  int size = 0;
  REG_ACE *reg_ace = (REG_ACE *)locn;
  unsigned char *p;

  if (!regf || !ace || !locn) return 0;

  reg_ace->type = ace->type;
  reg_ace->flags = ace->flags;

  /* Deal with the length when we have stored the SID */

  p = (unsigned char *)&reg_ace->perms;

  SIVAL(p, ace->perms); p += 4;

  size = nt_store_SID(regf, ace->trustee, p);

  size += 8; /* Size of the fixed header */

  p = (unsigned char *)&reg_ace->length;

  SSVAL(p, size);

  return size;
}

/*
 * Store an ACL at the location provided
 */
static
int nt_store_acl(REGF *regf, ACL *acl, unsigned char *locn)
{
  int size = 0, i;
  unsigned char *p = locn, *s;

  if (!regf || !acl || !locn) return 0;

  /*
   * Now store the header and then the ACEs ...
   */

  SSVAL(p, acl->rev);

  p += 2; s = p; /* Save this for the size field */

  p += 2;

  SIVAL(p, acl->num_aces);

  p += 4;

  for (i = 0; i < acl->num_aces; i++) {
    size = nt_store_ace(regf, acl->aces[i], p);
    p += size;
  }

  size = s - locn;
  SSVAL(s, size);
  return size;
}

/*
 * Flatten and store the Sec Desc 
 * Windows lays out the DACL first, but since there is no SACL, it might be
 * that first, then the owner, then the group SID. So, we do it that way
 * too.
 */
static
unsigned int nt_store_sec_desc(REGF *regf, SEC_DESC *sd, char *locn)
{
  REG_SEC_DESC *rsd = (REG_SEC_DESC *)locn;
  unsigned int size = 0, off = 0;

  if (!regf || !sd || !locn) return 0;

  /* 
   * Now, fill in the first two fields, then lay out the various fields
   * as needed
   */

  rsd->rev = 0x01;
  /* Self relative, DACL pres, owner and group not defaulted */
  rsd->type = 0x8004;  

  off = 4 * sizeof(DWORD) + 4;

  if (sd->sacl){
    size = nt_store_acl(regf, sd->sacl, (char *)(locn + off));
    rsd->sacl_off = off;
  }
  else
    rsd->sacl_off = 0;

  off += size;

  if (sd->dacl) {
    rsd->dacl_off = off;
    size = nt_store_acl(regf, sd->dacl, (char *)(locn + off));
  }
  else {
    rsd->dacl_off = 0;
  }

  off += size;

  /* Now the owner and group SIDs */

  if (sd->owner) {
    rsd->owner_off = off;
    size = nt_store_SID(regf, sd->owner, (char *)(locn + off));
  }
  else {
    rsd->owner_off = 0;
  }

  off += size;

  if (sd->group) {
    rsd->group_off = off;
    size = nt_store_SID(regf, sd->group, (char *)(locn + off));
  }
  else {
    rsd->group_off = 0;
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
static
unsigned int nt_store_security(REGF *regf, KEY_SEC_DESC *sec)
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

  size = sec_desc_size(sec->sec_desc);

  /* Allocate that much space */

  sk_hdr = nt_alloc_regf_space(regf, size, &sk_off);
  sec->sk_hdr = sk_hdr;

  if (!sk_hdr) return 0;

  /* Now, lay out the sec_desc in the space provided */

  sk_hdr->SK_ID = REG_SK_ID;
  
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
 * Store a VAL LIST
 */
static
int nt_store_val_list(REGF *regf, VAL_LIST * values)
{

  return 0;
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
static
int nt_store_reg_key(REGF *regf, REG_KEY *key)
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

  nk_hdr->NK_ID = REG_NK_ID; 
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
static
REGF_HDR *nt_get_reg_header(REGF *regf)
{
  HBIN_BLK *tmp = NULL;
  
  tmp = (HBIN_BLK *)malloc(sizeof(HBIN_BLK));
  if (!tmp) return 0;

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

/*
 * Store the registry in the output file
 * We write out the header and then each of the keys etc into the file
 * We have to flatten the data structure ...
 *
 * The structures are stored in a depth-first fashion, with all records
 * aligned on 8-byte boundaries, with sub-keys and values layed down before
 * the lists that contain them. SK records are layed down first, however.
 * The lf fields are layed down after all sub-keys have been layed down, it
 * seems, including the whole tree associated with each sub-key.
 */
static
int nt_store_registry(REGF *regf)
{
  REGF_HDR *reg;
  int fkey, fd;

  /*
   * Get a header ... and partially fill it in ...
   */
  reg = nt_get_reg_header(regf);

  /*
   * Store the first key, which will store the whole thing
   */
  fkey = nt_store_reg_key(regf, regf->root);

  /*
   * At this point we have the registry as a series of blocks, so
   * run down that series of blocks and save them ...
   */

  if (!regf->outfile_name) {
    fprintf(stderr, "Cannot write file without a name!\n");
    return 0;
  }

  if ((fd = open(regf->outfile_name, O_WRONLY, 0666)) < 0) {
    fprintf(stderr, "Unable to create file %s: %s\n", regf->outfile_name,
	    strerror(errno));
    return 0;
  }

  return 1;
}

/*
 * Routines to parse a REGEDIT4 file
 * 
 * The file consists of:
 * 
 * REGEDIT4
 * \[[-]key-path\]\n
 * <value-spec>*
 *
 * Format:
 * [cmd:]name=type:value
 *
 * cmd = a|d|c|add|delete|change|as|ds|cs
 *
 * There can be more than one key-path and value-spec.
 *
 * Since we want to support more than one type of file format, we
 * construct a command-file structure that keeps info about the command file
 */

#define FMT_UNREC -1
#define FMT_REGEDIT4 0
#define FMT_EDITREG1_1 1

#define FMT_STRING_REGEDIT4 "REGEDIT4"
#define FMT_STRING_EDITREG1_0 "EDITREG1.0"

#define CMD_NONE     0
#define CMD_ADD_KEY  1
#define CMD_DEL_KEY  2

#define CMD_KEY 1
#define CMD_VAL 2

typedef struct val_spec_list {
  struct val_spec_list *next;
  char *name;
  int type;
  char *val;    /* Kept as a char string, really? */
} VAL_SPEC_LIST;

typedef struct command_s {
  int cmd;
  char *key;
  int val_count;
  VAL_SPEC_LIST *val_spec_list, *val_spec_last;
} CMD;

typedef struct cmd_line {
  int len, line_len;
  char *line;
} CMD_LINE;

static
void free_val_spec_list(VAL_SPEC_LIST *vl)
{
  if (!vl) return;
  if (vl->name) free(vl->name);
  if (vl->val) free(vl->val);
  free(vl);

}

/* 
 * Some routines to handle lines of info in the command files
 */
static
void skip_to_eol(int fd)
{
  int rc;
  char ch = 0;

  while ((rc = read(fd, &ch, 1)) == 1) {
    if (ch == 0x0A) return;
  }
  if (rc < 0) {
    fprintf(stderr, "Could not read file descriptor: %d, %s\n",
	    fd, strerror(errno));
    exit(1);
  }
}

static
void free_cmd(CMD *cmd)
{
  if (!cmd) return;

  while (cmd->val_spec_list) {
    VAL_SPEC_LIST *tmp;

    tmp = cmd->val_spec_list;
    cmd->val_spec_list = tmp->next;
    free(tmp);
  }

  free(cmd);

}

static
void free_cmd_line(CMD_LINE *cmd_line)
{
  if (cmd_line) {
    if (cmd_line->line) free(cmd_line->line);
    free(cmd_line);
  }
}

static
void print_line(struct cmd_line *cl)
{
  char *pl;

  if (!cl) return;

  if ((pl = malloc(cl->line_len + 1)) == NULL) {
    fprintf(stderr, "Unable to allocate space to print line: %s\n",
	    strerror(errno));
    exit(1);
  }

  strncpy(pl, cl->line, cl->line_len);
  pl[cl->line_len] = 0;

  fprintf(stdout, "%s\n", pl);
  free(pl);
}

#define INIT_ALLOC 10 

/*
 * Read a line from the input file.
 * NULL returned when EOF and no chars read
 * Otherwise we return a cmd_line *
 * Exit if other errors
 */
static
struct cmd_line *get_cmd_line(int fd)
{
  struct cmd_line *cl = (CMD_LINE *)malloc(sizeof(CMD_LINE));
  int i = 0, rc;
  unsigned char ch;

  if (!cl) {
    fprintf(stderr, "Unable to allocate structure for command line: %s\n",
	    strerror(errno));
    exit(1);
  }

  cl->len = INIT_ALLOC;

  /*
   * Allocate some space for the line. We extend later if needed.
   */

  if ((cl->line = (char *)malloc(INIT_ALLOC)) == NULL) {
    fprintf(stderr, "Unable to allocate initial space for line: %s\n",
	    strerror(errno));
    exit(1);
  }

  /*
   * Now read in the chars to EOL. Don't store the EOL in the 
   * line. What about CR?
   */

  while ((rc = read(fd, &ch, 1)) == 1 && ch != '\n') {
    if (ch == '\r') continue; /* skip CR */
    if (i == cl->len) {
      /*
       * Allocate some more memory
       */
      if ((cl->line = realloc(cl->line, cl->len + INIT_ALLOC)) == NULL) {
	fprintf(stderr, "Unable to realloc space for line: %s\n",
		strerror(errno));
	exit(1);
      }
      cl->len += INIT_ALLOC;
    }
    cl->line[i] = ch;
    i++;
  }

  /* read 0 and we were at loc'n 0, return NULL */
  if (rc == 0 && i == 0) {
    free_cmd_line(cl);
    return NULL;
  }

  cl->line_len = i;

  return cl;

}

/*
 * parse_value: parse out a value. We pull it apart as:
 *
 * <value> ::= <value-name>=<type>:<value-string>
 *
 * <value-name> ::= char-string-without-spaces | '"' char-string '"'
 *
 * If it parsed OK, return the <value-name> as a string, and the
 * value type and value-string in parameters.
 *
 * The value name can be empty. There can only be one empty name in 
 * a list of values. A value of - removes the value entirely.  
 */
static
char *dup_str(char *s, int len) 
{ 
  char *nstr; 
  nstr = (char *)malloc(len + 1);
  if (nstr) {
    memcpy(nstr, s, len);
    nstr[len] = 0;
  }
  return nstr;
}

static
char *parse_name(char *nstr)
{
  int len = 0, start = 0;
  if (!nstr) return NULL;

  len = strlen(nstr);

  while (len && nstr[len - 1] == ' ') len--;

  nstr[len] = 0; /* Trim any spaces ... if there were none, doesn't matter */

  /*
   * Beginning and end should be '"' or neither should be so
   */
  if ((nstr[0] == '"' && nstr[len - 1] != '"') ||
      (nstr[0] != '"' && nstr[len - 1] == '"'))
    return NULL;

  if (nstr[0] == '"') {
    start = 1;
    len -= 2;
  }

  return dup_str(&nstr[start], len);
}

static
int parse_value_type(char *tstr)
{
  int len = strlen(tstr);
  
  while (len && tstr[len - 1] == ' ') len--;
  tstr[len] = 0;

  if (strcmp(tstr, "REG_DWORD") == 0)
    return REG_TYPE_DWORD;
  else if (strcmp(tstr, "dword") == 0)
    return REG_TYPE_DWORD;
  else if (strcmp(tstr, "REG_EXPAND_SZ") == 0)
    return REG_TYPE_EXPANDSZ;
  else if (strcmp(tstr, "REG_BIN") == 0)
    return REG_TYPE_BIN;
  else if (strcmp(tstr, "REG_SZ") == 0)
    return REG_TYPE_REGSZ;
  else if (strcmp(tstr, "REG_MULTI_SZ") == 0)
    return REG_TYPE_MULTISZ;
  else if (strcmp(tstr, "-") == 0)
    return REG_TYPE_DELETE;

  return 0;
}

static
char *parse_val_str(char *vstr)
{
  
  return dup_str(vstr, strlen(vstr));

}

static
char *parse_value(struct cmd_line *cl, int *vtype, char **val)
{
  char *p1 = NULL, *p2 = NULL, *nstr = NULL, *tstr = NULL, *vstr = NULL;
  
  if (!cl || !vtype || !val) return NULL;
  if (!cl->line_len) return NULL;

  p1 = dup_str(cl->line, cl->line_len);
  /* FIXME: Better return codes etc ... */
  if (!p1) return NULL;
  p2 = strchr(p1, '=');
  if (!p2) return NULL;

  *p2 = 0; p2++; /* Split into two strings at p2 */

  /* Now, parse the name ... */

  nstr = parse_name(p1);
  if (!nstr) goto error;

  /* Now, split the remainder and parse on type and val ... */

  tstr = p2;
  while (*tstr == ' ') tstr++; /* Skip leading white space */
  p2 = strchr(p2, ':');

  if (p2) {
    *p2 = 0; p2++; /* split on the : */
  }

  *vtype = parse_value_type(tstr);

  if (!vtype) goto error;

  if (!p2 || !*p2) return nstr;

  /* Now, parse the value string. It should return a newly malloc'd string */
  
  while (*p2 == ' ') p2++; /* Skip leading space */
  vstr = parse_val_str(p2);

  if (!vstr) goto error;

  *val = vstr;

  return nstr;

 error:
  if (p1) free(p1);
  if (nstr) free(nstr);
  if (vstr) free(vstr);
  return NULL;
}

/*
 * Parse out a key. Look for a correctly formatted key [...] 
 * and whether it is a delete or add? A delete is signalled 
 * by a - in front of the key.
 * Assumes that there are no leading and trailing spaces
 */

static
char *parse_key(struct cmd_line *cl, int *cmd)
{
  int start = 1;
  char *tmp;

  if (cl->line[0] != '[' ||
      cl->line[cl->line_len - 1] != ']') return NULL;
  if (cl->line_len == 2) return NULL;
  *cmd = CMD_ADD_KEY;
  if (cl->line[1] == '-') {
    if (cl->line_len == 3) return NULL;
    start = 2;
    *cmd = CMD_DEL_KEY;
  }
  tmp = malloc(cl->line_len - 1 - start + 1);
  if (!tmp) return tmp; /* Bail out on no mem ... FIXME */
  strncpy(tmp, &cl->line[start], cl->line_len - 1 - start);
  tmp[cl->line_len - 1 - start] = 0;
  return tmp;
}

/*
 * Parse a line to determine if we have a key or a value
 * We only check for key or val ...
 */

static
int parse_line(struct cmd_line *cl)
{

  if (!cl || cl->len == 0) return 0;

  if (cl->line[0] == '[')  /* No further checking for now */
    return CMD_KEY;
  else 
    return CMD_VAL;
}

/*
 * We seek to offset 0, read in the required number of bytes, 
 * and compare to the correct value.
 * We then seek back to the original location
 */
static
int regedit4_file_type(int fd)
{
  int cur_ofs = 0;
  char desc[9];

  cur_ofs = lseek(fd, 0, SEEK_CUR); /* Get current offset */
  if (cur_ofs < 0) {
    fprintf(stderr, "Unable to get current offset: %s\n", strerror(errno));
    exit(1);  /* FIXME */
  }

  if (cur_ofs) {
    lseek(fd, 0, SEEK_SET);
  }

  if (read(fd, desc, 8) < 8) {
    fprintf(stderr, "Unable to read command file format\n"); 
    exit(2);  /* FIXME */
  }

  desc[8] = 0;

  if (strcmp(desc, FMT_STRING_REGEDIT4) == 0) {
    if (cur_ofs) {
      lseek(fd, cur_ofs, SEEK_SET);
    }
    else {
      skip_to_eol(fd);
    }
    return FMT_REGEDIT4;
  }

  return FMT_UNREC;
}

/*
 * Run though the data in the line and strip anything after a comment
 * char.
 */
static
void strip_comment(struct cmd_line *cl)
{
  int i;

  if (!cl) return;

  for (i = 0; i < cl->line_len; i++) {
    if (cl->line[i] == ';') {
      cl->line_len = i;
      return;
    }
  }
}

/* 
 * trim leading space
 */

static
void trim_leading_spaces(struct cmd_line *cl)
{
  int i;

  if (!cl) return;

  for (i = 0; i < cl->line_len; i++) {
    if (cl->line[i] != ' '){
      if (i) memcpy(cl->line, &cl->line[i], cl->line_len - i);
      return;
    }
  }
}

/* 
 * trim trailing spaces
 */
static
void trim_trailing_spaces(struct cmd_line *cl)
{
  int i;

  if (!cl) return;

  for (i = cl->line_len; i == 0; i--) {
    if (cl->line[i-1] != ' ' &&
	cl->line[i-1] != '\t') {
      cl->line_len = i;
    }
  }
}

/* 
 * Get a command ... This consists of possibly multiple lines:
 * [key]
 * values*
 * possibly Empty line
 *
 * value ::= <value-name>=<value-type>':'<value-string>
 * <value-name> is some path, possibly enclosed in quotes ...
 * We alctually look for the next key to terminate a previous key
 * if <value-type> == '-', then it is a delete type.
 */
static
CMD *regedit4_get_cmd(int fd)
{
  struct command_s *cmd = NULL;
  struct cmd_line *cl = NULL;
  struct val_spec_list *vl = NULL;

  if ((cmd = (struct command_s *)malloc(sizeof(struct command_s))) == NULL) {
    fprintf(stderr, "Unable to malloc space for command: %s\n",
	    strerror(errno));
    exit(1);
  }

  cmd->cmd = CMD_NONE;
  cmd->key = NULL;
  cmd->val_count = 0;
  cmd->val_spec_list = cmd->val_spec_last = NULL;
  while ((cl = get_cmd_line(fd))) {

    /*
     * If it is an empty command line, and we already have a key
     * then exit from here ... FIXME: Clean up the parser
     */

    if (cl->line_len == 0 && cmd->key) {
      free_cmd_line(cl);
      break;
    } 

    strip_comment(cl);     /* remove anything beyond a comment char */
    trim_trailing_spaces(cl);
    trim_leading_spaces(cl);

    if (cl->line_len == 0) {    /* An empty line */
      free_cmd_line(cl);
    }
    else {                 /* Else, non-empty ... */
      /* 
       * Parse out the bits ... 
       */
      switch (parse_line(cl)) {
      case CMD_KEY:
	if ((cmd->key = parse_key(cl, &cmd->cmd)) == NULL) {
	  fprintf(stderr, "Error parsing key from line: ");
	  print_line(cl);
	  fprintf(stderr, "\n");
	}
	break;

      case CMD_VAL:
	/*
	 * We need to add the value stuff to the list
	 * There could be a \ on the end which we need to 
	 * handle at some time
	 */
	vl = (struct val_spec_list *)malloc(sizeof(struct val_spec_list));
	if (!vl) goto error;
	vl->next = NULL;
	vl->val = NULL;
	vl->name = parse_value(cl, &vl->type, &vl->val);
	if (!vl->name) goto error;
	if (cmd->val_spec_list == NULL) {
	  cmd->val_spec_list = cmd->val_spec_last = vl;
	}
	else {
	  cmd->val_spec_last->next = vl;
	  cmd->val_spec_last = vl;
	}
	cmd->val_count++;
	break;

      default:
	fprintf(stderr, "Unrecognized line in command file: \n");
	print_line(cl);
	break;
      }
    }

  }
  if (!cmd->cmd) goto error; /* End of file ... */

  return cmd;

 error:
  if (vl) free(vl);
  if (cmd) free_cmd(cmd);
  return NULL;
}

static
int regedit4_exec_cmd(CMD *cmd)
{

  return 0;
}

static
int editreg_1_0_file_type(int fd)
{
  int cur_ofs = 0;
  char desc[11];

  cur_ofs = lseek(fd, 0, SEEK_CUR); /* Get current offset */
  if (cur_ofs < 0) {
    fprintf(stderr, "Unable to get current offset: %s\n", strerror(errno));
    exit(1);  /* FIXME */
  }

  if (cur_ofs) {
    lseek(fd, 0, SEEK_SET);
  }

  if (read(fd, desc, 10) < 10) {
    fprintf(stderr, "Unable to read command file format\n"); 
    exit(2);  /* FIXME */
  }

  desc[10] = 0;

  if (strcmp(desc, FMT_STRING_EDITREG1_0) == 0) {
    lseek(fd, cur_ofs, SEEK_SET);
    return FMT_REGEDIT4;
  }

  return FMT_UNREC;
}

static
CMD *editreg_1_0_get_cmd(int fd)
{
  return NULL;
}

static
int editreg_1_0_exec_cmd(CMD *cmd)
{

  return -1;
}

typedef struct command_ops_s {
  int type;
  int (*file_type)(int fd);
  CMD *(*get_cmd)(int fd);
  int (*exec_cmd)(CMD *cmd);
} CMD_OPS;

CMD_OPS default_cmd_ops[] = {
  {0, regedit4_file_type, regedit4_get_cmd, regedit4_exec_cmd},
  {1, editreg_1_0_file_type, editreg_1_0_get_cmd, editreg_1_0_exec_cmd},
  {-1,  NULL, NULL, NULL}
}; 

typedef struct command_file_s {
  char *name;
  int type, fd;
  CMD_OPS cmd_ops;
} CMD_FILE;

/*
 * Create a new command file structure
 */

static
CMD_FILE *cmd_file_create(char *file)
{
  CMD_FILE *tmp;
  struct stat sbuf;
  int i = 0;

  /*
   * Let's check if the file exists ...
   * No use creating the cmd_file structure if the file does not exist
   */

  if (stat(file, &sbuf) < 0) { /* Not able to access file */

    return NULL;
  }

  tmp = (CMD_FILE *)malloc(sizeof(CMD_FILE)); 
  if (!tmp) {
    return NULL;
  }

  /*
   * Let's fill in some of the fields;
   */

  tmp->name = strdup(file);

  if ((tmp->fd = open(file, O_RDONLY, 666)) < 0) {
    free(tmp);
    return NULL;
  }

  /*
   * Now, try to find the format by indexing through the table
   */
  while (default_cmd_ops[i].type != -1) {
    if ((tmp->type = default_cmd_ops[i].file_type(tmp->fd)) >= 0) {
      tmp->cmd_ops = default_cmd_ops[i];
      return tmp;
    }
    i++;
  }

  /* 
   * If we got here, return NULL, as we could not figure out the type
   * of command file.
   *
   * What about errors? 
   */

  free(tmp);
  return NULL;
}

/*
 * Extract commands from the command file, and execute them.
 * We pass a table of command callbacks for that 
 */

/*
 * Main code from here on ...
 */

/*
 * key print function here ...
 */

static
int print_key(const char *path, char *name, char *class_name, int root, 
	      int terminal, int vals)
{

  if (full_print || terminal) fprintf(stdout, "[%s%s]\n", path, name);

  return 1;
}

/*
 * Sec Desc print functions 
 */

static
void print_type(unsigned char type)
{
  switch (type) {
  case 0x00:
    fprintf(stdout, "    ALLOW");
    break;
  case 0x01:
    fprintf(stdout, "     DENY");
    break;
  case 0x02:
    fprintf(stdout, "    AUDIT");
    break;
  case 0x03:
    fprintf(stdout, "    ALARM");
    break;
  case 0x04:
    fprintf(stdout, "ALLOW CPD");
    break;
  case 0x05:
    fprintf(stdout, "OBJ ALLOW");
    break;
  case 0x06:
    fprintf(stdout, " OBJ DENY");
  default:
    fprintf(stdout, "  UNKNOWN");
    break;
  }
}

static
void print_flags(unsigned char flags)
{
  char flg_output[21];
  int some = 0;

  flg_output[0] = 0;
  if (!flags) {
    fprintf(stdout, "         ");
    return;
  }
  if (flags & 0x01) {
    if (some) strcat(flg_output, ",");
    some = 1;
    strcat(flg_output, "OI");
  }
  if (flags & 0x02) {
    if (some) strcat(flg_output, ",");
    some = 1;
    strcat(flg_output, "CI");
  }
  if (flags & 0x04) {
    if (some) strcat(flg_output, ",");
    some = 1;
    strcat(flg_output, "NP");
  }
  if (flags & 0x08) {
    if (some) strcat(flg_output, ",");
    some = 1;
    strcat(flg_output, "IO");
  }
  if (flags & 0x10) {
    if (some) strcat(flg_output, ",");
    some = 1;
    strcat(flg_output, "IA");
  }
  if (flags == 0xF) {
    if (some) strcat(flg_output, ",");
    some = 1;
    strcat(flg_output, "VI");
  }
  fprintf(stdout, " %s", flg_output);
}

static
void print_perms(int perms)
{
  fprintf(stdout, " %8X", perms);
}

static
void print_sid(sid_t *sid)
{
  int i, comps = sid->auths;
  fprintf(stdout, "S-%u-%u", sid->ver, sid->auth[5]);

  for (i = 0; i < comps; i++) {

    fprintf(stdout, "-%u", sid->sub_auths[i]);

  }
  fprintf(stdout, "\n");
}

static
void print_acl(ACL *acl, const char *prefix)
{
  int i;

  for (i = 0; i < acl->num_aces; i++) {
    fprintf(stdout, ";;%s", prefix);
    print_type(acl->aces[i]->type);
    print_flags(acl->aces[i]->flags);
    print_perms(acl->aces[i]->perms);
    fprintf(stdout, " ");
    print_sid(acl->aces[i]->trustee);
  }
}

static
int print_sec(SEC_DESC *sec_desc)
{
  if (!print_security) return 1;
  fprintf(stdout, ";;  SECURITY\n");
  fprintf(stdout, ";;   Owner: ");
  print_sid(sec_desc->owner);
  fprintf(stdout, ";;   Group: ");
  print_sid(sec_desc->group);
  if (sec_desc->sacl) {
    fprintf(stdout, ";;    SACL:\n");
    print_acl(sec_desc->sacl, " ");
  }
  if (sec_desc->dacl) {
    fprintf(stdout, ";;    DACL:\n");
    print_acl(sec_desc->dacl, " ");
  }
  return 1;
}

/*
 * Value print function here ...
 */
static
int print_val(const char *path, char *val_name, int val_type, int data_len, 
	      void *data_blk, int terminal, int first, int last)
{
  char data_asc[1024];

  memset(data_asc, 0, sizeof(data_asc));
  if (!terminal && first)
    fprintf(stdout, "%s\n", path);
  data_to_ascii((unsigned char *)data_blk, data_len, val_type, data_asc, 
		sizeof(data_asc) - 1);
  fprintf(stdout, "  %s = %s : %s\n", (val_name?val_name:"<No Name>"), 
		   val_to_str(val_type, reg_type_names), data_asc);
  return 1;
}

static
void usage(void)
{
  fprintf(stderr, "Usage: editreg [-f] [-v] [-p] [-k] [-s] [-c <command-file>] <registryfile>\n");
  fprintf(stderr, "Version: 0.1\n\n");
  fprintf(stderr, "\n\t-v\t sets verbose mode");
  fprintf(stderr, "\n\t-f\t sets full print mode where non-terminals are printed");
  fprintf(stderr, "\n\t-p\t prints the registry");
  fprintf(stderr, "\n\t-s\t prints security descriptors");
  fprintf(stderr, "\n\t-c <command-file>\t specifies a command file");
  fprintf(stderr, "\n");
}

int main(int argc, char *argv[])
{
  REGF *regf;
  extern char *optarg;
  extern int optind;
  int opt, print_keys = 0;
  int regf_opt = 1; /* Command name */
  int commands = 0, modified = 0;
  char *cmd_file_name = NULL;
  char *out_file_name = NULL;
  CMD_FILE *cmd_file = NULL;
  sid_t *lsid;

  if (argc < 2) {
    usage();
    exit(1);
  }
  
  /* 
   * Now, process the arguments
   */

  while ((opt = getopt(argc, argv, "fspvko:O:c:")) != EOF) {
    switch (opt) {
    case 'c':
      commands = 1;
      cmd_file_name = optarg;
      regf_opt += 2;
      break;

    case 'f':
      full_print = 1;
      regf_opt++;
      break;

    case 'o':
      out_file_name = optarg;
      regf_opt += 2;
      break;

    case 'O':
      def_owner_sid_str = strdup(optarg);
      regf_opt += 2;
      if (!sid_string_to_sid(&lsid, def_owner_sid_str)) {
	fprintf(stderr, "Default Owner SID: %s is incorrectly formatted\n",
		def_owner_sid_str);
	free(&def_owner_sid_str[0]);
	def_owner_sid_str = NULL;
      }
      else 
	nt_delete_sid(lsid);
      break;

    case 'p':
      print_keys++;
      regf_opt++;
      break;

    case 's':
      print_security++;
      full_print++;
      regf_opt++;
      break;

    case 'v':
      verbose++;
      regf_opt++;
      break;

    case 'k':
      regf_opt++;
      break;

    default:
      usage();
      exit(1);
      break;
    }
  }

  /*
   * We only want to complain about the lack of a default owner SID if
   * we need one. This approximates that need 
   */
  if (!def_owner_sid_str) {
    def_owner_sid_str = "S-1-5-21-1-2-3-4";
    if (out_file_name || verbose)
      fprintf(stderr, "Warning, default owner SID not set. Setting to %s\n",
	      def_owner_sid_str);
  }

  if ((regf = nt_create_regf()) == NULL) {
    fprintf(stderr, "Could not create registry object: %s\n", strerror(errno));
    exit(2);
  }

  if (regf_opt < argc) { /* We have a registry file */
    if (!nt_set_regf_input_file(regf, argv[regf_opt])) {
      fprintf(stderr, "Could not set name of registry file: %s, %s\n", 
	      argv[regf_opt], strerror(errno));
      exit(3);
    }

    /* Now, open it, and bring it into memory :-) */

    if (nt_load_registry(regf) < 0) {
      fprintf(stderr, "Could not load registry: %s\n", argv[1]);
      exit(4);
    }
  }

  if (out_file_name) {
    if (!nt_set_regf_output_file(regf, out_file_name)) {
      fprintf(stderr, "Could not set name of output registry file: %s, %s\n", 
	      out_file_name, strerror(errno));
      exit(3);
    }

  }

  if (commands) {
    CMD *cmd;

    cmd_file = cmd_file_create(cmd_file_name);

    while ((cmd = cmd_file->cmd_ops.get_cmd(cmd_file->fd)) != NULL) {

      /*
       * Now, apply the requests to the tree ...
       */
      switch (cmd->cmd) {
      case CMD_ADD_KEY: {
	REG_KEY *tmp = NULL;

	tmp = nt_find_key_by_name(regf->root, cmd->key);

	/* If we found it, apply the other bits, else create such a key */

	if (!tmp) {
	  tmp = nt_add_reg_key(regf, cmd->key, True);
	  modified = 1;
	}

	while (cmd->val_count) {
	  VAL_SPEC_LIST *val = cmd->val_spec_list;
	  VAL_KEY *reg_val = NULL;
	  
	  if (val->type == REG_TYPE_DELETE) {
	    reg_val = nt_delete_reg_value(tmp, val -> name);
	    if (reg_val) nt_delete_val_key(reg_val);
	    modified = 1;
	  }
	  else {
	    reg_val = nt_add_reg_value(tmp, val->name, val->type, 
				       val->val);
	    modified = 1;
	  }

	  cmd->val_spec_list = val->next;
	  free_val_spec_list(val);
	  cmd->val_count--;
	}

	break;
      }
      
      case CMD_DEL_KEY:
	/* 
	 * Any value does not matter ...
	 * Find the key if it exists, and delete it ...
	 */
	
	nt_delete_key_by_name(regf, cmd->key);
	modified = 1;
	break;
      }
    }
    free_cmd(cmd);
  }

  /*
   * At this point, we should have a registry in memory and should be able
   * to iterate over it.
   */

  if (print_keys) {
    nt_key_iterator(regf, regf->root, 0, "", print_key, print_sec, print_val);
  }

  /*
   * If there was an out_file_name and the tree was modified, print it
   */
  if (modified && out_file_name) 
    if (!nt_store_registry(regf)) {
      fprintf(stdout, "Error storing registry\n");
    }

  return 0;
}
