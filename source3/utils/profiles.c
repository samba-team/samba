/* 
   Samba Unix/Linux SMB client utility profiles.c 
   Copyright (C) 2002 Richard Sharpe, rsharpe@richardsharpe.com
   Copyright (C) 2003 Jelmer Vernooij (conversion to popt)

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
                                                       
 A utility to report and change SIDs in registry files 
                                     
 Many of the ideas in here come from other people and software. 
 I first looked in Wine in misc/registry.c and was also influenced by
 http://www.wednesday.demon.co.uk/dosreg.html

 Which seems to contain comments from someone else. I reproduce them here
 incase the site above disappears. It actually comes from 
 http://home.eunet.no/~pnordahl/ntpasswd/WinReg.txt. 

The windows NT registry has 2 different blocks, where one can occure many
times...

the "regf"-Block
================
 
"regf" is obviously the abbreviation for "Registry file". "regf" is the
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
0x0007      RegMultiSZ:      multiple strings, separated with 0
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
   |  |         ^          |          |
      |         +----------+          |
      +-------------------------------+

---------------------------------------------------------------------------

Hope this helps....  (Although it was "fun" for me to uncover this things,
                  it took me several sleepless nights ;)

            B.D.

*************************************************************************/
#include "includes.h"
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

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

typedef struct sec_desc_rec {
  WORD rev;
  WORD type;
  DWORD owner_off;
  DWORD group_off;
  DWORD sacl_off;
  DWORD dacl_off;
} MY_SEC_DESC;

typedef struct ace_struct {
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned int perms;
    DOM_SID trustee;
} ACE;

typedef struct acl_struct {
  WORD rev;
  WORD size;
  DWORD num_aces;
  ACE *aces;   /* One or more ACEs */
} ACL;

#define OFF(f) (0x1000 + (f) + 4) 

static void print_sid(DOM_SID *sid);

int verbose = 1;
DOM_SID old_sid, new_sid;
int change = 0, new = 0;

/* Compare two SIDs for equality */
static int my_sid_equal(DOM_SID *s1, DOM_SID *s2)
{
  int sa1, sa2;

  if (s1->sid_rev_num != s2->sid_rev_num) return 0;

  sa1 = s1->num_auths; sa2 = s2->num_auths;

  if (sa1 != sa2) return 0;

  return !memcmp((char *)&s1->id_auth, (char *)&s2->id_auth,
		6 + sa1 * 4);

}

/*
 * Quick and dirty to read a SID in S-1-5-21-x-y-z-rid format and 
 * construct a DOM_SID
 */
static int get_sid(DOM_SID *sid, const unsigned char *sid_str)
{
  int i = 0, auth;
  const unsigned char *lstr; 

  if (strncmp(sid_str, "S-1-5", 5)) {
    fprintf(stderr, "Does not conform to S-1-5...: %s\n", sid_str);
    return 0;
  }

  /* We only allow strings of form S-1-5... */

  sid->sid_rev_num = 1;
  sid->id_auth[5] = 5;

  lstr = sid_str + 5;

  while (1) {
    if (!lstr || !lstr[0] || sscanf(lstr, "-%u", &auth) == 0) {
      if (i < 4) {
	fprintf(stderr, "Not of form -d-d...: %s, %u\n", lstr, i);
	return 0;
      }
      sid->num_auths=i;
      print_sid(sid);
      return 1;
    }

    SIVAL(&sid->sub_auths[i], 0, auth);
    i++;
    lstr = (const unsigned char *)strchr(lstr + 1, '-'); 
  }

  return 1;
}

#if 0

/* 
 * Replace SID1, component by component with SID2
 * Assumes will never be called with unequal length SIDS
 * so only touches 21-x-y-z-rid portion
 * This routine does not need to deal with endianism as 
 * long as the incoming SIDs are both in the same (LE) format.
 */
static void change_sid(DOM_SID *s1, DOM_SID *s2)
{
  int i;
  
  for (i=0; i<s1->num_auths; i++) {
    s1->sub_auths[i] = s2->sub_auths[i];
  }
}

#endif

static void print_sid(DOM_SID *sid)
{
  int i, comps = sid->num_auths;
  fprintf(stdout, "S-%u-%u", sid->sid_rev_num, sid->id_auth[5]);

  for (i = 0; i < comps; i++) {

    fprintf(stdout, "-%u", IVAL(&sid->sub_auths[i],0));

  }
  fprintf(stdout, "\n");
}

static void process_sid(DOM_SID *sid, DOM_SID *o_sid, DOM_SID *n_sid) 
{
  int i;
  if (my_sid_equal(sid, o_sid)) {

    for (i=0; i<sid->num_auths; i++) {
      sid->sub_auths[i] = n_sid->sub_auths[i];

    }

  }

}

static void process_acl(ACL *acl, const char *prefix)
{
  int ace_cnt, i;
  ACE *ace;

  ace_cnt = IVAL(&acl->num_aces, 0);
  ace = (ACE *)&acl->aces;
  if (verbose) fprintf(stdout, "%sACEs: %u\n", prefix, ace_cnt);
  for (i=0; i<ace_cnt; i++) {
    if (verbose) fprintf(stdout, "%s  Perms: %08X, SID: ", prefix,
			 IVAL(&ace->perms, 0));
    if (change)
      process_sid(&ace->trustee, &old_sid, &new_sid);
    print_sid(&ace->trustee);
    ace = (ACE *)((char *)ace + SVAL(&ace->length, 0));
  }
} 

int main(int argc, char *argv[])
{
  int opt;
  int fd, start = 0;
  char *base;
  struct stat sbuf;
  REGF_HDR *regf_hdr;
  HBIN_HDR *hbin_hdr;
  NK_HDR *nk_hdr;
  SK_HDR *sk_hdr;
  DWORD first_sk_off, sk_off;
  MY_SEC_DESC *sec_desc;
  int *ptr;
  struct poptOption long_options[] = {
	  POPT_AUTOHELP
	  { "verbose", 'v', POPT_ARG_NONE, NULL, 'v', "Sets verbose mode" },
	  { "change-sid", 'c', POPT_ARG_STRING, NULL, 'c', "Provides SID to change" },
	  { "new-sid", 'n', POPT_ARG_STRING, NULL, 'n', "Provides SID to change to" },
	  { 0, 0, 0, 0 }
  };

  poptContext pc;

  pc = poptGetContext("profiles", argc, (const char **)argv, long_options, 
					  POPT_CONTEXT_KEEP_FIRST);

  poptSetOtherOptionHelp(pc, "<profilefile>");

  /*
   * Now, process the arguments
   */

  while ((opt = poptGetNextOpt(pc)) != -1) {
    switch (opt) {
	case 'c':
		change = 1;
		if (!get_sid(&old_sid, poptGetOptArg(pc))) {
			fprintf(stderr, "Argument to -c should be a SID in form of S-1-5-...\n");
			poptPrintUsage(pc, stderr, 0);
			exit(254);
		}
		break;

	case 'n':
		new = 1;
		if (!get_sid(&new_sid, poptGetOptArg(pc))) {
			fprintf(stderr, "Argument to -n should be a SID in form of S-1-5-...\n");
			poptPrintUsage(pc, stderr, 0);
			exit(253);
		}

		break;

	case 'v':
		verbose++;
		break;
	}
  }

  if (!poptPeekArg(pc)) {
	  poptPrintUsage(pc, stderr, 0);
	  exit(1);
  }

  if ((!change & new) || (change & !new)) {
	  fprintf(stderr, "You must specify both -c and -n if one or the other is set!\n");
	  poptPrintUsage(pc, stderr, 0);
	  exit(252);
  }

  poptGetArg(pc); /* To get argv[0] */

  fd = open(poptPeekArg(pc), O_RDWR, 0000);

  if (fd < 0) {
    fprintf(stderr, "Could not open %s: %s\n", poptPeekArg(pc), 
	strerror(errno));
    exit(2);
  }

  if (fstat(fd, &sbuf) < 0) {
    fprintf(stderr, "Could not stat file %s, %s\n", poptPeekArg(pc),
	strerror(errno));
    exit(3);
  }

  /*
   * Now, mmap the file into memory, check the header and start
   * dealing with the records. We are interested in the sk record
   */
  start = 0;

#ifdef HAVE_MMAP
  base = mmap(&start, sbuf.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
#else
  base = (char *)-1;
  errno = ENOSYS;
#endif

  if ((int)base == -1) {
    fprintf(stderr, "Could not mmap file: %s, %s\n", poptPeekArg(pc),
	strerror(errno));
    exit(4);
  }

  /*
   * In what follows, and in places above, in order to work on both LE and
   * BE platforms, we have to use the Samba macros to extract SHORT, LONG
   * and associated UNSIGNED quantities from the data in the mmap'd file.
   * NOTE, however, that we do not need to do anything with memory
   * addresses that we construct from pointers in our address space.
   * For example, 
   *
   *    sec_desc = (MY_SEC_DESC *)&(sk_hdr->sec_desc[0]);
   *
   * is simply taking the address of a structure we already have the address
   * of in our address space, while, the fields within it, will have to 
   * be accessed with the macros:
   *
   * owner_sid = (DOM_SID *)(&sk_hdr->sec_desc[0] + 
   *                         IVAL(&sec_desc->owner_off, 0));
   *
   * Which is pulling out an offset and adding it to an existing pointer.
   *
   */

  regf_hdr = (REGF_HDR *)base;

  if (verbose) fprintf(stdout, "Registry file size: %u\n", (unsigned int)sbuf.st_size);

  if (IVAL(&regf_hdr->REGF_ID, 0) != REG_REGF_ID) {
    fprintf(stderr, "Incorrect Registry file (doesn't have header ID): %s\n", poptPeekArg(pc));
    exit(5);
  }

  if (verbose) fprintf(stdout, "First Key Off: %u, Data Block Size: %u\n",
		       IVAL(&regf_hdr->first_key, 0), 
		       IVAL(&regf_hdr->dblk_size, 0));

  hbin_hdr = (HBIN_HDR *)(base + 0x1000); /* No need for Endian stuff */

  /*
   * This should be the hbin_hdr 
   */

  if (IVAL(&hbin_hdr->HBIN_ID, 0) != REG_HBIN_ID) {
    fprintf(stderr, "Incorrect hbin hdr: %s\n", poptPeekArg(pc));
    exit(6);
  } 

  if (verbose) fprintf(stdout, "Next Off: %u, Prev Off: %u\n", 
		       IVAL(&hbin_hdr->next_off, 0), 
		       IVAL(&hbin_hdr->prev_off, 0));

  nk_hdr = (NK_HDR *)(base + 0x1000 + IVAL(&regf_hdr->first_key, 0) + 4);

  if (SVAL(&nk_hdr->NK_ID, 0) != REG_NK_ID) {
    fprintf(stderr, "Incorrect NK Header: %s\n", poptPeekArg(pc));
    exit(7);
  }

  sk_off = first_sk_off = IVAL(&nk_hdr->sk_off, 0);
  if (verbose) {
    fprintf(stdout, "Type: %0x\n", SVAL(&nk_hdr->type, 0));
    fprintf(stdout, "SK Off    : %o\n", (0x1000 + sk_off + 4));  
  }

  sk_hdr = (SK_HDR *)(base + 0x1000 + sk_off + 4);

  do {
    DOM_SID *owner_sid, *group_sid;
    ACL *sacl, *dacl;
    if (SVAL(&sk_hdr->SK_ID, 0) != REG_SK_ID) {
      fprintf(stderr, "Incorrect SK Header format: %08X\n", 
	      (0x1000 + sk_off + 4));
      exit(8);
    }
    ptr = (int *)sk_hdr;
    if (verbose) fprintf(stdout, "Off: %08X, Refs: %u, Size: %u\n",
			 sk_off, IVAL(&sk_hdr->ref_cnt, 0), 
			 IVAL(&sk_hdr->rec_size, 0));

    sec_desc = (MY_SEC_DESC *)&(sk_hdr->sec_desc[0]);
    owner_sid = (DOM_SID *)(&sk_hdr->sec_desc[0] +
			    IVAL(&sec_desc->owner_off, 0));
    group_sid = (DOM_SID *)(&sk_hdr->sec_desc[0] + 
			    IVAL(&sec_desc->group_off, 0));
    sacl = (ACL *)(&sk_hdr->sec_desc[0] + 
		   IVAL(&sec_desc->sacl_off, 0));
    dacl = (ACL *)(&sk_hdr->sec_desc[0] + 
		   IVAL(&sec_desc->dacl_off, 0));
    if (verbose)fprintf(stdout, "  Owner SID: "); 
    if (change) process_sid(owner_sid, &old_sid, &new_sid);
    if (verbose) print_sid(owner_sid);
    if (verbose) fprintf(stdout, "  Group SID: "); 
    if (change) process_sid(group_sid, &old_sid, &new_sid);
    if (verbose) print_sid(group_sid);
    fprintf(stdout, "  SACL: ");
    if (!sec_desc->sacl_off) { /* LE zero == BE zero */
      if (verbose) fprintf(stdout, "NONE\n");
    }
    else 
      process_acl(sacl, "    ");
    if (verbose) fprintf(stdout, "  DACL: ");
    if (!sec_desc->dacl_off) {
      if (verbose) fprintf(stdout, "NONE\n");
    }
    else 
      process_acl(dacl, "    ");
    sk_off = IVAL(&sk_hdr->prev_off, 0);
    sk_hdr = (SK_HDR *)(base + OFF(IVAL(&sk_hdr->prev_off, 0)));
  } while (sk_off != first_sk_off);

#ifdef HAVE_MMAP
  munmap(base, sbuf.st_size); 
#endif

  poptFreeContext(pc);

  close(fd);
  return 0;
}
