/* des.h */
/* Copyright (C) 1993 Eric Young - see README for more details */
#ifndef DES_DEFS
#define DES_DEFS

#include <sys/bitypes.h>
#include <sys/cdefs.h>

typedef unsigned char des_cblock[8];
typedef struct des_ks_struct
	{
	union	{
		des_cblock _;
		/* make sure things are correct size on machines with
		 * 8 byte longs */
		u_int32_t pad[2];
		} ks;
#define _	ks._
	} des_key_schedule[16];

#define DES_KEY_SZ 	(sizeof(des_cblock))
#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#define DES_CBC_MODE	0
#define DES_PCBC_MODE	1

#if !defined(NCOMPAT)
#define C_Block des_cblock
#define Key_schedule des_key_schedule
#define ENCRYPT DES_ENCRYPT
#define DECRYPT DES_DECRYPT
#define KEY_SZ DES_KEY_SZ
#define string_to_key des_string_to_key
#define read_pw_string des_read_pw_string
#define random_key des_random_key
#define pcbc_encrypt des_pcbc_encrypt
#define set_key des_set_key
#define key_sched des_key_sched
#define ecb_encrypt des_ecb_encrypt
#define cbc_encrypt des_cbc_encrypt
#define cbc_cksum des_cbc_cksum
#define quad_cksum des_quad_cksum

/* For compatibility with the MIT lib - eay 20/05/92 */
typedef struct des_ks_struct bit_64;
#endif

extern int des_check_key;	/* defaults to false */
extern int des_rw_mode;		/* defaults to DES_PCBC_MODE */

extern int des_3ecb_encrypt __P((des_cblock *input,des_cblock *output,des_key_schedule ks1,des_key_schedule ks2,int encrypt));
extern int des_3cbc_encrypt __P((des_cblock *input,des_cblock *output,long length,des_key_schedule sk1,des_key_schedule sk2,des_cblock *ivec1,des_cblock *ivec2,int encrypt));
extern u_int32_t des_cbc_cksum __P((des_cblock *input,des_cblock *output,long length,des_key_schedule schedule,des_cblock *ivec));
extern int des_cbc_encrypt __P((des_cblock *input,des_cblock *output,long length,des_key_schedule schedule,des_cblock *ivec,int encrypt));
extern int des_cfb_encrypt __P((unsigned char *in,unsigned char *out,int numbits,long length,des_key_schedule schedule,des_cblock *ivec,int encrypt));
extern int des_ecb_encrypt __P((des_cblock *input,des_cblock *output,des_key_schedule ks,int encrypt));
extern int des_encrypt __P((u_int32_t *input,u_int32_t *output,des_key_schedule ks, int encrypt));
extern int des_enc_read __P((int fd,char *buf,int len,des_key_schedule sched,des_cblock *iv));
extern int des_enc_write __P((int fd,char *buf,int len,des_key_schedule sched,des_cblock *iv));
extern int des_ofb_encrypt __P((unsigned char *in,unsigned char *out,int numbits,long length,des_key_schedule schedule,des_cblock *ivec));
extern int des_pcbc_encrypt __P((des_cblock *input,des_cblock *output,long length,des_key_schedule schedule,des_cblock *ivec,int encrypt));

extern void des_set_odd_parity __P((des_cblock *key));
extern int des_is_weak_key __P((des_cblock *key));
extern int des_set_key __P((des_cblock *key,des_key_schedule schedule));
extern int des_key_sched __P((des_cblock *key,des_key_schedule schedule));
extern void des_fixup_key_parity __P((des_cblock *key));

extern int des_string_to_key __P((char *str,des_cblock *key));
extern int des_string_to_2keys __P((char *str,des_cblock *key1,des_cblock *key2));

extern void des_set_random_generator_seed __P((des_cblock *seed));
extern int des_new_random_key __P((des_cblock *key));
extern void des_init_random_number_generator __P((des_cblock *seed));
extern int des_random_key __P((des_cblock ret));
extern int des_read_password __P((des_cblock *key,char *prompt,int verify));
extern int des_read_2passwords __P((des_cblock *key1,des_cblock *key2,char *prompt,int verify));
extern int des_read_pw_string __P((char *buf,int length,char *prompt,int verify));

extern u_int32_t des_quad_cksum __P((des_cblock *input,des_cblock *output,long length,int out_count,des_cblock *seed));

#endif /* DES_DEFS */
