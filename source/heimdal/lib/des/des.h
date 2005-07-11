/*
 * Copyright (c) 2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $Id: des.h,v 1.23 2005/04/30 14:09:50 lha Exp $ */

#ifndef _DESperate_H
#define _DESperate_H 1

#define DES_CBLOCK_LEN 8
#define DES_KEY_SZ 8

#define DES_ENCRYPT 1
#define DES_DECRYPT 0

typedef unsigned char DES_cblock[DES_CBLOCK_LEN];
typedef struct DES_key_schedule
{
	uint32_t ks[32];
} DES_key_schedule;

int	DES_set_odd_parity(DES_cblock *);
int	DES_is_weak_key(DES_cblock *);
int	DES_set_key(DES_cblock *, DES_key_schedule *);
int	DES_set_key_checked(DES_cblock *, DES_key_schedule *);
int	DES_key_sched(DES_cblock *, DES_key_schedule *);
int	DES_new_random_key(DES_cblock *);
void	DES_string_to_key(const char *, DES_cblock *);
int	DES_read_password(DES_cblock *, char *, int);

int	UI_UTIL_read_pw_string(char *, int, const char *, int); /* XXX */

void	DES_rand_data(unsigned char *, int);
void	DES_set_random_generator_seed(DES_cblock *);
void	DES_generate_random_block(DES_cblock *);
void	DES_set_sequence_number(unsigned char *);
void 	DES_init_random_number_generator(DES_cblock *);
void	DES_random_key(DES_cblock *);


void	DES_encrypt(uint32_t [2], DES_key_schedule *, int);
void	DES_ecb_encrypt(DES_cblock *, DES_cblock *, DES_key_schedule *, int);
void	DES_ecb3_encrypt(DES_cblock *,DES_cblock *, DES_key_schedule *,
			 DES_key_schedule *, DES_key_schedule *, int);
void	DES_pcbc_encrypt(unsigned char *, unsigned char *, long,
			 DES_key_schedule *, DES_cblock *, int);
void	DES_cbc_encrypt(unsigned char *, unsigned char *, long,
			DES_key_schedule *, DES_cblock *, int);
void	DES_ede3_cbc_encrypt(const unsigned char *, unsigned char *, long, 
			     DES_key_schedule *, DES_key_schedule *, 
			     DES_key_schedule *, DES_cblock *, int);
void DES_cfb64_encrypt(unsigned char *, unsigned char *, long,
		       DES_key_schedule *, DES_cblock *, int *, int);


uint32_t DES_cbc_cksum(const unsigned char *, DES_cblock *,
		      long, DES_key_schedule *, DES_cblock *);


void	_DES_ipfp_test(void);


#endif /* _DESperate_H */
