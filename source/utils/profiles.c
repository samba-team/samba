#include "includes.h"
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>

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

void print_sid(DOM_SID *sid)
{
  int i, comps = sid->num_auths;
  fprintf(stdout, "S-%u-%u", sid->sid_rev_num, sid->id_auth[5]);

  for (i = 0; i < comps; i++) {

    fprintf(stdout, "-%u", sid->sub_auths[i]);

  }
  fprintf(stdout, "\n");
}

void print_acl(ACL *acl, char *prefix)
{
  int ace_cnt, i;
  ACE *ace;

  ace_cnt = acl->num_aces;
  ace = &acl->aces;
  fprintf(stdout, "%sACEs: %u\n", prefix, ace_cnt);
  for (i=0; i<ace_cnt; i++) {
    fprintf(stdout, "%s  Perms: %08X, SID: ", prefix, ace->perms);
    print_sid(&ace->trustee);
    ace = (ACE *)((char *)ace + ace->length);
  }
} 

int main(int argc, char *argv[])
{
  int i, fd, aces, start = 0;
  void *base;
  struct stat sbuf;
  fstring sid_str;
  REGF_HDR *regf_hdr;
  HBIN_HDR *hbin_hdr;
  NK_HDR *nk_hdr;
  SK_HDR *sk_hdr;
  WORD first_sk_off, sk_off;
  MY_SEC_DESC *sec_desc;
  int *ptr;

  if (argc < 2) {
    fprintf(stderr, "Usage: profiles profile-file\n");
    exit(1);
  }

  fd = open(argv[1], O_RDWR, 0000);

  if (fd < 0) {
    fprintf(stderr, "Could not open %s: %s\n", argv[1], 
	strerror(errno));
    exit(2);
  }

  if (fstat(fd, &sbuf) < 0) {
    fprintf(stderr, "Could not stat file %s, %s\n", argv[1],
	strerror(errno));
    exit(3);
  }

  /*
   * Now, mmap the file into memory, check the header and start
   * dealing with the records. We are interested in the sk record
   */
  start = 0;
  base = mmap(&start, sbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if ((int)base == -1) {
    fprintf(stderr, "Could not mmap file: %s, %s\n", argv[1],
	strerror(errno));
    exit(4);
  }

  regf_hdr = (REGF_HDR *)base;

  fprintf(stdout, "Registry file size: %u\n", sbuf.st_size);

  if (regf_hdr->REGF_ID != REG_REGF_ID) {
    fprintf(stderr, "Incorrect Registry file (doesn't have header ID): %s\n", argv[1]);
    exit(5);
  }

  fprintf(stdout, "First Key Off: %u, Data Block Size: %u\n",
	  regf_hdr->first_key, regf_hdr->dblk_size);

  hbin_hdr = (HBIN_HDR *)(base + 0x1000);

  /*
   * This should be the hbin_hdr 
   */

  if (hbin_hdr->HBIN_ID != REG_HBIN_ID) {
    fprintf(stderr, "Incorrect hbin hdr: %s\n", argv[1]);
    exit(6);
  } 

  fprintf(stdout, "Next Off: %u, Prev Off: %u\n", 
	  hbin_hdr->next_off, hbin_hdr->prev_off);

  nk_hdr = (NK_HDR *)(base + 0x1000 + regf_hdr->first_key + 4);

  if (nk_hdr->NK_ID != REG_NK_ID) {
    fprintf(stderr, "Incorrect NK Header: %s\n", argv[1]);
    exit(7);
  }

  fprintf(stdout, "Type: %0x\n", nk_hdr->type);
  fprintf(stdout, "SK Off    : %o\n", (0x1000 + nk_hdr->sk_off + 4));  

  sk_hdr = (SK_HDR *)(base + 0x1000 + nk_hdr->sk_off + 4);
  sk_off = first_sk_off = nk_hdr->sk_off;

  do {
    DOM_SID *owner_sid, *group_sid;
    ACL *sacl, *dacl;
    if (sk_hdr->SK_ID != REG_SK_ID) {
      fprintf(stderr, "Incorrect SK Header format: %08X\n", 
	      (0x1000 + nk_hdr->sk_off + 4));
      exit(8);
    }
    ptr = (int *)sk_hdr;
    fprintf(stdout, "Off: %08X, Refs: %u, Size: %u\n",
	    sk_off, sk_hdr->ref_cnt, sk_hdr->rec_size);
    sec_desc = &(sk_hdr->sec_desc[0]);
    owner_sid = (DOM_SID *)(&sk_hdr->sec_desc[0] + sec_desc->owner_off);
    group_sid = (DOM_SID *)(&sk_hdr->sec_desc[0] + sec_desc->group_off);
    sacl = (ACL *)(&sk_hdr->sec_desc[0] + sec_desc->sacl_off);
    dacl = (ACL *)(&sk_hdr->sec_desc[0] + sec_desc->dacl_off);
    fprintf(stdout, "  Owner SID: "); print_sid(owner_sid);
    fprintf(stdout, "  Group SID: "); print_sid(group_sid);
    fprintf(stdout, "  SACL: ");
    if (!sec_desc->sacl_off)
      fprintf(stdout, "NONE\n");
    else 
      print_acl(sacl, "    ");
    fprintf(stdout, "  DACL: ");
    if (!sec_desc->dacl_off)
      fprintf(stdout, "NONE\n");
    else 
      print_acl(dacl, "    ");
    sk_off = sk_hdr->prev_off;
    sk_hdr = (SK_HDR *)(base + OFF(sk_hdr->prev_off));
  } while (sk_off != first_sk_off);

}

