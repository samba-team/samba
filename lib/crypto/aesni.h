/*
 * Copyright (C) 2008, Intel Corp.
 *    Author: Huang Ying <ying.huang@intel.com>
 *            Vinodh Gopal <vinodh.gopal@intel.com>
 *            Kahraman Akdemir
 *
 * Ported x86_64 version to x86:
 *    Author: Mathias Krause <minipli@googlemail.com>
 *
 * Modified for use in Samba by Justin Maggard <jmaggard@netgear.com>
 * and Jeremy Allison <jra@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIB_CRYPTO_AESNI_H
#define LIB_CRYPTO_AESNI_H 1

#if defined(HAVE_AESNI_INTEL)

#define AES_MAX_KEYLENGTH      (15 * 16)
#define AES_MAX_KEYLENGTH_U32  (AES_MAX_KEYLENGTH / sizeof(uint32_t))

/*
 * Please ensure that the first two fields are 16-byte aligned
 * relative to the start of the structure, i.e., don't move them!
 */
struct crypto_aes_ctx {
	uint32_t key_enc[AES_MAX_KEYLENGTH_U32];
	uint32_t key_dec[AES_MAX_KEYLENGTH_U32];
	uint32_t key_length;
};

struct crypto_aesni_ctx {
	uint8_t _acc_ctx[sizeof(struct crypto_aes_ctx) + 16];
	struct crypto_aes_ctx *acc_ctx;
};

/*
 * These next 4 functions are actually implemented
 * in the assembly language file:
 * third_party/aesni-intel/aesni-intel_asm.c
 */

int aesni_set_key(struct crypto_aes_ctx *ctx,
		const uint8_t *in_key,
		unsigned int key_len);
void aesni_enc(struct crypto_aes_ctx *ctx, uint8_t *dst, const uint8_t *src);
void aesni_dec(struct crypto_aes_ctx *ctx, uint8_t *dst, const uint8_t *src);

#else /* #if defined(HAVE_AESNI_INTEL) */

/*
 * We need a dummy definition of struct crypto_aesni_ctx to allow compiles.
 */

struct crypto_aesni_ctx {
	int dummy;
};

#endif /* #if defined(HAVE_AESNI_INTEL) */

#endif /* LIB_CRYPTO_AESNI_H */
