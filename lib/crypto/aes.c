/*
 * Copyright (c) 2003 Kungliga Tekniska Högskolan
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

#include "replace.h"
#include "aes.h"

#ifdef SAMBA_RIJNDAEL
#include "rijndael-alg-fst.h"

#if defined(HAVE_AESNI_INTEL)

/*
 * NB. HAVE_AESNI_INTEL is only defined if -lang-asm is
 * available.
 */

static inline void __cpuid(unsigned int where[4], unsigned int leaf)
{
	asm volatile("cpuid" :
			"=a" (where[0]),
			"=b" (where[1]),
			"=c" (where[2]),
			"=d" (where[3]): "a" (leaf));
}

/*
 * has_intel_aes_instructions()
 * return true if supports AES-NI and false if doesn't
 */
static bool has_intel_aes_instructions(void)
{
	static int has_aes_instructions = -1;
	unsigned int cpuid_results[4];

	if (has_aes_instructions != -1) {
		return (bool)has_aes_instructions;
	}

	__cpuid(cpuid_results, 1);
	has_aes_instructions = !!(cpuid_results[2] & (1 << 25));
	return (bool)has_aes_instructions;
}

/*
 * Macro to ensure the AES key schedule starts on a 16 byte boundary.
 */

#define SET_ACC_CTX(k) \
	do {    \
		(k)->u.aes_ni.acc_ctx =  \
		(struct crypto_aes_ctx *)(((unsigned long)(k)->u.aes_ni._acc_ctx + 15) & ~0xfUL); \
	} while (0)

/*
 * The next 4 functions call the Intel AES hardware implementations
 * of:
 *
 * AES_set_encrypt_key()
 * AES_set_decrypt_key()
 * AES_encrypt()
 * AES_decrypt()
 */

static int AES_set_encrypt_key_aesni(const unsigned char *userkey,
				const int bits,
				AES_KEY *key)
{
	SET_ACC_CTX(key);
	return aesni_set_key(key->u.aes_ni.acc_ctx, userkey, bits/8);
}

static int AES_set_decrypt_key_aesni(const unsigned char *userkey,
				const int bits,
				AES_KEY *key)
{
	SET_ACC_CTX(key);
	return aesni_set_key(key->u.aes_ni.acc_ctx, userkey, bits/8);
}

static void AES_encrypt_aesni(const unsigned char *in,
				unsigned char *out,
				const AES_KEY *key)
{
	aesni_enc(key->u.aes_ni.acc_ctx, out, in);
}

static void AES_decrypt_aesni(const unsigned char *in,
				unsigned char *out,
				const AES_KEY *key)
{
	aesni_dec(key->u.aes_ni.acc_ctx, out, in);
}
#else /* defined(HAVE_AESNI_INTEL) */

/*
 * Dummy implementations if no Intel AES instructions present.
 * Only has_intel_aes_instructions() will ever be called.
*/

static bool has_intel_aes_instructions(void)
{
	return false;
}

static int AES_set_encrypt_key_aesni(const unsigned char *userkey,
				const int bits,
				AES_KEY *key)
{
	return -1;
}

static int AES_set_decrypt_key_aesni(const unsigned char *userkey,
				const int bits,
				AES_KEY *key)
{
	return -1;
}

static void AES_encrypt_aesni(const unsigned char *in,
				unsigned char *out,
				const AES_KEY *key)
{
	abort();
}

static void AES_decrypt_aesni(const unsigned char *in,
				unsigned char *out,
				const AES_KEY *key)
{
	abort();
}
#endif /* defined(HAVE_AENI_INTEL) */

/*
 * The next 4 functions are the pure software implementations
 * of:
 *
 * AES_set_encrypt_key()
 * AES_set_decrypt_key()
 * AES_encrypt()
 * AES_decrypt()
 */

static int
AES_set_encrypt_key_rj(const unsigned char *userkey, const int bits, AES_KEY *key)
{
    key->u.aes_rj.rounds = rijndaelKeySetupEnc(key->u.aes_rj.key, userkey, bits);
    if (key->u.aes_rj.rounds == 0)
	return -1;
    return 0;
}

static int
AES_set_decrypt_key_rj(const unsigned char *userkey, const int bits, AES_KEY *key)
{
    key->u.aes_rj.rounds = rijndaelKeySetupDec(key->u.aes_rj.key, userkey, bits);
    if (key->u.aes_rj.rounds == 0)
	return -1;
    return 0;
}

static void
AES_encrypt_rj(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
    rijndaelEncrypt(key->u.aes_rj.key, key->u.aes_rj.rounds, in, out);
}

static void
AES_decrypt_rj(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
    rijndaelDecrypt(key->u.aes_rj.key, key->u.aes_rj.rounds, in, out);
}

/*
 * The next 4 functions are the runtime switch for Intel AES hardware
 * implementations of:
 *
 * AES_set_encrypt_key()
 * AES_set_decrypt_key()
 * AES_encrypt()
 * AES_decrypt()
 *
 * If the hardware instructions don't exist, fall back to the software
 * versions.
 */

int
AES_set_encrypt_key(const unsigned char *userkey, const int bits, AES_KEY *key)
{
	if (has_intel_aes_instructions()) {
		return AES_set_encrypt_key_aesni(userkey, bits, key);
	}
	return AES_set_encrypt_key_rj(userkey, bits, key);
}

int
AES_set_decrypt_key(const unsigned char *userkey, const int bits, AES_KEY *key)
{
	if (has_intel_aes_instructions()) {
		return AES_set_decrypt_key_aesni(userkey, bits, key);
	}
	return AES_set_decrypt_key_rj(userkey, bits, key);
}

void
AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
	if (has_intel_aes_instructions()) {
		AES_encrypt_aesni(in, out, key);
		return;
	}
	AES_encrypt_rj(in, out, key);
}

void
AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
	if (has_intel_aes_instructions()) {
		AES_decrypt_aesni(in, out, key);
		return;
	}
	AES_decrypt_rj(in, out, key);
}

#endif /* SAMBA_RIJNDAEL */

#ifdef SAMBA_AES_CBC_ENCRYPT
void
AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
		unsigned long size, const AES_KEY *key,
		unsigned char *iv, int forward_encrypt)
{
    unsigned char tmp[AES_BLOCK_SIZE];
    int i;

    if (forward_encrypt) {
	while (size >= AES_BLOCK_SIZE) {
	    for (i = 0; i < AES_BLOCK_SIZE; i++)
		tmp[i] = in[i] ^ iv[i];
	    AES_encrypt(tmp, out, key);
	    memcpy(iv, out, AES_BLOCK_SIZE);
	    size -= AES_BLOCK_SIZE;
	    in += AES_BLOCK_SIZE;
	    out += AES_BLOCK_SIZE;
	}
	if (size) {
	    for (i = 0; i < size; i++)
		tmp[i] = in[i] ^ iv[i];
	    for (i = size; i < AES_BLOCK_SIZE; i++)
		tmp[i] = iv[i];
	    AES_encrypt(tmp, out, key);
	    memcpy(iv, out, AES_BLOCK_SIZE);
	}
    } else {
	while (size >= AES_BLOCK_SIZE) {
	    memcpy(tmp, in, AES_BLOCK_SIZE);
	    AES_decrypt(tmp, out, key);
	    for (i = 0; i < AES_BLOCK_SIZE; i++)
		out[i] ^= iv[i];
	    memcpy(iv, tmp, AES_BLOCK_SIZE);
	    size -= AES_BLOCK_SIZE;
	    in += AES_BLOCK_SIZE;
	    out += AES_BLOCK_SIZE;
	}
	if (size) {
	    memcpy(tmp, in, AES_BLOCK_SIZE);
	    AES_decrypt(tmp, out, key);
	    for (i = 0; i < size; i++)
		out[i] ^= iv[i];
	    memcpy(iv, tmp, AES_BLOCK_SIZE);
	}
    }
}
#endif /* SAMBA_AES_CBC_ENCRYPT */

#ifdef SAMBA_AES_CFB8_ENCRYPT
void
AES_cfb8_encrypt(const unsigned char *in, unsigned char *out,
                 unsigned long size, const AES_KEY *key,
                 unsigned char *iv, int forward_encrypt)
{
    int i;

    for (i = 0; i < size; i++) {
        unsigned char tmp[AES_BLOCK_SIZE + 1];

        memcpy(tmp, iv, AES_BLOCK_SIZE);
        AES_encrypt(iv, iv, key);
        if (!forward_encrypt) {
            tmp[AES_BLOCK_SIZE] = in[i];
        }
        out[i] = in[i] ^ iv[0];
        if (forward_encrypt) {
            tmp[AES_BLOCK_SIZE] = out[i];
        }
        memcpy(iv, &tmp[1], AES_BLOCK_SIZE);
    }
}
#endif /* SAMBA_AES_CFB8_ENCRYPT */
