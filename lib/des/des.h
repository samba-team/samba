/* crypto/des/des.h */
/* Copyright (C) 1995-1997 Eric Young (eay@mincom.oz.au)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@mincom.oz.au).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@mincom.oz.au).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@mincom.oz.au)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@mincom.oz.au)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef HEADER_NEW_DES_H
#define HEADER_NEW_DES_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdio.h>

#ifndef DES_LIB_FUNCTION
#if defined(__BORLANDC__)
#define DES_LIB_FUNCTION /* not-ready-definition-yet */
#elif defined(_MSC_VER)
#define DES_LIB_FUNCTION /* not-ready-definition-yet2 */
#else
#define DES_LIB_FUNCTION
#endif
#endif

/* If this is set to 'unsigned int' on a DEC Alpha, this gives about a
 * %20 speed up (longs are 8 bytes, int's are 4). */
#ifndef DES_LONG
#if defined(__alpha) || defined(__sparcv9) || defined(__sparc_v9__) || _MIPS_SZLONG == 64
#define DES_LONG unsigned int
#else /* Not a 64 bit machine */
#define DES_LONG unsigned long
#endif
#endif

typedef unsigned char DES_cblock[8];
typedef struct DES_ks_struct
	{
	union	{
		DES_cblock _;
		/* make sure things are correct size on machines with
		 * 8 byte longs */
		DES_LONG pad[2];
		} ks[16];
#undef _
#define _	ks._
	} DES_key_schedule;

#define DES_KEY_SZ 	(sizeof(DES_cblock))
#define DES_SCHEDULE_SZ (sizeof(DES_key_schedule))

#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#define DES_CBC_MODE	0
#define DES_PCBC_MODE	1

#define DES_ecb2_encrypt(i,o,k1,k2,e) \
	DES_ecb3_encrypt((i),(o),(k1),(k2),(k1),(e))

#define DES_ede2_cbc_encrypt(i,o,l,k1,k2,iv,e) \
	DES_ede3_cbc_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(e))

#define DES_ede2_cfb64_encrypt(i,o,l,k1,k2,iv,n,e) \
	DES_ede3_cfb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n),(e))

#define DES_ede2_ofb64_encrypt(i,o,l,k1,k2,iv,n) \
	DES_ede3_ofb64_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(n))

#define C_Block DES_cblock
#define Key_schedule DES_key_schedule

/* some glue for openssl compat */
#define UI_UTIL_read_pw_string DES_read_pw_string

#ifdef KERBEROS
#define ENCRYPT DES_ENCRYPT
#define DECRYPT DES_DECRYPT
#endif
#define KEY_SZ DES_KEY_SZ
#define string_to_key DES_string_to_key
#define read_pw_string DES_read_pw_string
#define random_key DES_random_key
#define pcbc_encrypt DES_pcbc_encrypt
#define set_key DES_set_key
#define key_sched DES_key_sched
#define ecb_encrypt DES_ecb_encrypt
#define cbc_encrypt DES_cbc_encrypt
#define ncbc_encrypt DES_ncbc_encrypt
#define xcbc_encrypt DES_xcbc_encrypt
#define cbc_cksum DES_cbc_cksum
#define quad_cksum DES_quad_cksum

/* For compatibility with the MIT lib - eay 20/05/92 */
typedef DES_key_schedule bit_64;
#define DES_fixup_key_parity DES_set_odd_parity
#define DES_check_key_parity check_parity

extern int DES_check_key;	/* defaults to false */
extern int DES_rw_mode;		/* defaults to DES_PCBC_MODE */

#ifdef cplusplus
extern "C" {
#endif

/* The next line is used to disable full ANSI prototypes, if your
 * compiler has problems with the prototypes, make sure this line always
 * evaluates to true :-) */
#if defined(MSDOS) || defined(__STDC__)
#undef NOPROTO
#endif
#ifndef NOPROTO
char *DES_LIB_FUNCTION DES_options(void);
void DES_LIB_FUNCTION DES_ecb3_encrypt(DES_cblock *input,DES_cblock *output,
	DES_key_schedule *ks1,DES_key_schedule *ks2,
	DES_key_schedule *ks3, int enc);
DES_LONG DES_LIB_FUNCTION DES_cbc_cksum(DES_cblock *input,DES_cblock *output,
	long length,DES_key_schedule *schedule,DES_cblock *ivec);
void DES_LIB_FUNCTION DES_cbc_encrypt(DES_cblock *input,DES_cblock *output,long length,
	DES_key_schedule *schedule,DES_cblock *ivec,int enc);
void DES_LIB_FUNCTION DES_ncbc_encrypt(DES_cblock *input,DES_cblock *output,long length,
	DES_key_schedule *schedule,DES_cblock *ivec,int enc);
void DES_LIB_FUNCTION DES_xcbc_encrypt(DES_cblock *input,DES_cblock *output,long length,
	DES_key_schedule *schedule,DES_cblock *ivec,
	DES_cblock *inw,DES_cblock *outw,int enc);
void DES_LIB_FUNCTION DES_3cbc_encrypt(DES_cblock *input,DES_cblock *output,long length,
	DES_key_schedule *sk1,DES_key_schedule *sk2,
	DES_cblock *ivec1,DES_cblock *ivec2,int enc);
void DES_LIB_FUNCTION DES_cfb_encrypt(unsigned char *in,unsigned char *out,int numbits,
	long length,DES_key_schedule *schedule,DES_cblock *ivec,int enc);
void DES_LIB_FUNCTION DES_ecb_encrypt(DES_cblock *input,DES_cblock *output,
	DES_key_schedule *ks,int enc);
void DES_LIB_FUNCTION DES_encrypt(DES_LONG *data,DES_key_schedule *ks, int enc);
void DES_LIB_FUNCTION DES_encrypt2(DES_LONG *data,DES_key_schedule *ks, int enc);
void DES_LIB_FUNCTION DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1,
	DES_key_schedule *ks2, DES_key_schedule *ks3);
void DES_LIB_FUNCTION DES_decrypt3(DES_LONG *data, DES_key_schedule *ks1,
	DES_key_schedule *ks2, DES_key_schedule *ks3);
void DES_LIB_FUNCTION DES_ede3_cbc_encrypt(DES_cblock *input, DES_cblock *output, 
	long length, DES_key_schedule *ks1, DES_key_schedule *ks2, 
	DES_key_schedule *ks3, DES_cblock *ivec, int enc);
void DES_LIB_FUNCTION DES_ede3_cfb64_encrypt(unsigned char *in, unsigned char *out,
	long length, DES_key_schedule *ks1, DES_key_schedule *ks2,
	DES_key_schedule *ks3, DES_cblock *ivec, int *num, int encrypt);
void DES_LIB_FUNCTION DES_ede3_ofb64_encrypt(unsigned char *in, unsigned char *out,
	long length, DES_key_schedule *ks1, DES_key_schedule *ks2,
	DES_key_schedule *ks3, DES_cblock *ivec, int *num);

int DES_LIB_FUNCTION DES_enc_read(int fd,char *buf,int len,DES_key_schedule *sched,
	DES_cblock *iv);
int DES_LIB_FUNCTION DES_enc_write(int fd,char *buf,int len,DES_key_schedule *sched,
	DES_cblock *iv);
char *DES_LIB_FUNCTION DES_fcrypt(const char *buf,const char *salt, char *ret);
#ifdef PERL5
char *DES_crypt(const char *buf,const char *salt);
#else
/* some stupid compilers complain because I have declared char instead
 * of const char */
#ifdef HEADER_DES_LOCL_H
char *DES_LIB_FUNCTION crypt(const char *buf,const char *salt);
#else
char *crypt();
#endif
#endif
void DES_LIB_FUNCTION DES_ofb_encrypt(unsigned char *in,unsigned char *out,
	int numbits,long length,DES_key_schedule *schedule,DES_cblock *ivec);
void DES_LIB_FUNCTION DES_pcbc_encrypt(DES_cblock *input,DES_cblock *output,long length,
	DES_key_schedule *schedule,DES_cblock *ivec,int enc);
DES_LONG DES_LIB_FUNCTION DES_quad_cksum(DES_cblock *input,DES_cblock *output,
	long length,int out_count,DES_cblock *seed);
void DES_LIB_FUNCTION DES_random_seed(DES_cblock key);
void DES_LIB_FUNCTION DES_random_key(DES_cblock ret);
int DES_LIB_FUNCTION DES_read_password(DES_cblock *key,char *prompt,int verify);
int DES_LIB_FUNCTION DES_read_2passwords(DES_cblock *key1,DES_cblock *key2,
	char *prompt,int verify);
int DES_LIB_FUNCTION DES_read_pw_string(char *buf,int length,char *prompt,int verify);
void DES_LIB_FUNCTION DES_set_odd_parity(DES_cblock *key);
int DES_LIB_FUNCTION DES_is_weak_key(DES_cblock *key);
int DES_LIB_FUNCTION DES_set_key(DES_cblock *key,DES_key_schedule *schedule);
int DES_LIB_FUNCTION DES_key_sched(DES_cblock *key,DES_key_schedule *schedule);
void DES_LIB_FUNCTION DES_string_to_key(char *str,DES_cblock *key);
void DES_LIB_FUNCTION DES_string_to_2keys(char *str,DES_cblock *key1,DES_cblock *key2);
void DES_LIB_FUNCTION DES_cfb64_encrypt(unsigned char *in, unsigned char *out, long length,
	DES_key_schedule *schedule, DES_cblock *ivec, int *num, int enc);
void DES_LIB_FUNCTION DES_ofb64_encrypt(unsigned char *in, unsigned char *out, long length,
	DES_key_schedule *schedule, DES_cblock *ivec, int *num);

/* Extra functions from Mark Murray <mark@grondar.za> */
void DES_LIB_FUNCTION DES_cblock_print_file(DES_cblock *cb, FILE *fp);
/* The following functions are not in the normal unix build or the
 * SSLeay build.  When using the SSLeay build, use RAND_seed()
 * and RAND_bytes() instead. */
int DES_LIB_FUNCTION DES_new_random_key(DES_cblock *key);
void DES_LIB_FUNCTION DES_init_random_number_generator(DES_cblock *key);
void DES_LIB_FUNCTION DES_set_random_generator_seed(DES_cblock *key);
void DES_LIB_FUNCTION DES_set_sequence_number(DES_cblock new_sequence_number);
void DES_LIB_FUNCTION DES_generate_random_block(DES_cblock *block);
void DES_LIB_FUNCTION DES_rand_data(unsigned char *data, int size);

#else

char *DES_options();
void DES_ecb3_encrypt();
DES_LONG DES_cbc_cksum();
void DES_cbc_encrypt();
void DES_ncbc_encrypt();
void DES_xcbc_encrypt();
void DES_3cbc_encrypt();
void DES_cfb_encrypt();
void DES_ede3_cfb64_encrypt();
void DES_ede3_ofb64_encrypt();
void DES_ecb_encrypt();
void DES_encrypt();
void DES_encrypt2();
void DES_encrypt3();
void DES_decrypt3();
void DES_ede3_cbc_encrypt();
int DES_enc_read();
int DES_enc_write();
char *DES_fcrypt();
#ifdef PERL5
char *DES_crypt();
#else
char *crypt();
#endif
void DES_ofb_encrypt();
void DES_pcbc_encrypt();
DES_LONG DES_quad_cksum();
void DES_random_seed();
void DES_random_key();
int DES_read_password();
int DES_read_2passwords();
int DES_read_pw_string();
void DES_set_odd_parity();
int DES_is_weak_key();
int DES_set_key();
int DES_key_sched();
void DES_string_to_key();
void DES_string_to_2keys();
void DES_cfb64_encrypt();
void DES_ofb64_encrypt();

/* Extra functions from Mark Murray <mark@grondar.za> */
void DES_cblock_print_file();
/* The following functions are not in the normal unix build or the
 * SSLeay build.  When using the SSLeay build, use RAND_seed()
 * and RAND_bytes() instead. */
int DES_new_random_key();
void DES_init_random_number_generator();
void DES_set_random_generator_seed();
void DES_set_sequence_number();
void DES_generate_random_block();
void DES_rand_data();

#endif

#ifdef __cplusplus
}
#endif

#endif
