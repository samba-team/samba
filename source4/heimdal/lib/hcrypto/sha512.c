/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
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

#include "config.h"

#include "hash.h"
#include "sha.h"

#define Ch(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROTR(x,n)   (((x)>>(n)) | ((x) << (64 - (n))))

#define Sigma0(x)	(ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define Sigma1(x)	(ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
#define sigma0(x)	(ROTR(x,1)  ^ ROTR(x,8)  ^ ((x)>>7))
#define sigma1(x)	(ROTR(x,19) ^ ROTR(x,61) ^ ((x)>>6))

#define A m->counter[0]
#define B m->counter[1]
#define C m->counter[2]
#define D m->counter[3]
#define E m->counter[4]
#define F m->counter[5]
#define G m->counter[6]
#define H m->counter[7]

static const uint64_t constant_512[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

void
SHA512_Init (SHA512_CTX *m)
{
    m->sz[0] = 0;
    m->sz[1] = 0;
    A = 0x6a09e667f3bcc908;
    B = 0xbb67ae8584caa73b;
    C = 0x3c6ef372fe94f82b;
    D = 0xa54ff53a5f1d36f1;
    E = 0x510e527fade682d1;
    F = 0x9b05688c2b3e6c1f;
    G = 0x1f83d9abfb41bd6b;
    H = 0x5be0cd19137e2179;
}

static void
calc (SHA512_CTX *m, uint64_t *in)
{
    uint64_t AA, BB, CC, DD, EE, FF, GG, HH;
    uint64_t data[80];
    int i;

    AA = A;
    BB = B;
    CC = C;
    DD = D;
    EE = E;
    FF = F;
    GG = G;
    HH = H;

    for (i = 0; i < 16; ++i)
	data[i] = in[i];
    for (i = 16; i < 80; ++i)
	data[i] = sigma1(data[i-2]) + data[i-7] +
	    sigma0(data[i-15]) + data[i - 16];

    for (i = 0; i < 80; i++) {
	uint64_t T1, T2;

	T1 = HH + Sigma1(EE) + Ch(EE, FF, GG) + constant_512[i] + data[i];
	T2 = Sigma0(AA) + Maj(AA,BB,CC);
			
	HH = GG;
	GG = FF;
	FF = EE;
	EE = DD + T1;
	DD = CC;
	CC = BB;
	BB = AA;
	AA = T1 + T2;
    }

    A += AA;
    B += BB;
    C += CC;
    D += DD;
    E += EE;
    F += FF;
    G += GG;
    H += HH;
}

/*
 * From `Performance analysis of MD5' by Joseph D. Touch <touch@isi.edu>
 */

#if !defined(WORDS_BIGENDIAN) || defined(_CRAY)
static inline uint64_t
swap_uint64_t (uint64_t t)
{
    uint64_t temp;

    temp   = cshift64(t, 32);
    temp = ((temp & 0xff00ff00ff00ff00) >> 8) |
           ((temp & 0x00ff00ff00ff00ff) << 8);
    return ((temp & 0xffff0000ffff0000) >> 16) |
           ((temp & 0x0000ffff0000ffff) << 16);
}
#endif

struct x64{
    uint64_t a:64;
    uint64_t b:64;
};

void
SHA512_Update (SHA512_CTX *m, const void *v, size_t len)
{
    const unsigned char *p = v;
    size_t old_sz = m->sz[0];
    size_t offset;

    m->sz[0] += len * 8;
    if (m->sz[0] < old_sz)
	++m->sz[1];
    offset = (old_sz / 8) % 128;
    while(len > 0){
	size_t l = min(len, 128 - offset);
	memcpy(m->save + offset, p, l);
	offset += l;
	p += l;
	len -= l;
	if(offset == 128){
#if !defined(WORDS_BIGENDIAN) || defined(_CRAY)
	    int i;
	    uint64_t current[16];
	    struct x64 *us = (struct x64*)m->save;
	    for(i = 0; i < 8; i++){
		current[2*i+0] = swap_uint64_t(us[i].a);
		current[2*i+1] = swap_uint64_t(us[i].b);
	    }
	    calc(m, current);
#else
	    calc(m, (uint64_t*)m->save);
#endif
	    offset = 0;
	}
    }
}

void
SHA512_Final (void *res, SHA512_CTX *m)
{
    unsigned char zeros[128 + 16];
    unsigned offset = (m->sz[0] / 8) % 128;
    unsigned int dstart = (240 - offset - 1) % 128 + 1;

    *zeros = 0x80;
    memset (zeros + 1, 0, sizeof(zeros) - 1);
    zeros[dstart+15] = (m->sz[0] >> 0) & 0xff;
    zeros[dstart+14] = (m->sz[0] >> 8) & 0xff;
    zeros[dstart+13] = (m->sz[0] >> 16) & 0xff;
    zeros[dstart+12] = (m->sz[0] >> 24) & 0xff;
    zeros[dstart+11] = (m->sz[0] >> 32) & 0xff;
    zeros[dstart+10] = (m->sz[0] >> 40) & 0xff;
    zeros[dstart+9]  = (m->sz[0] >> 48) & 0xff;
    zeros[dstart+8]  = (m->sz[0] >> 56) & 0xff;

    zeros[dstart+7] = (m->sz[1] >> 0) & 0xff;
    zeros[dstart+6] = (m->sz[1] >> 8) & 0xff;
    zeros[dstart+5] = (m->sz[1] >> 16) & 0xff;
    zeros[dstart+4] = (m->sz[1] >> 24) & 0xff;
    zeros[dstart+3] = (m->sz[1] >> 32) & 0xff;
    zeros[dstart+2] = (m->sz[1] >> 40) & 0xff;
    zeros[dstart+1] = (m->sz[1] >> 48) & 0xff;
    zeros[dstart+0] = (m->sz[1] >> 56) & 0xff;
    SHA512_Update (m, zeros, dstart + 16);
    {
	int i;
	unsigned char *r = (unsigned char*)res;

	for (i = 0; i < 8; ++i) {
	    r[8*i+7] = m->counter[i] & 0xFF;
	    r[8*i+6] = (m->counter[i] >> 8) & 0xFF;
	    r[8*i+5] = (m->counter[i] >> 16) & 0xFF;
	    r[8*i+4] = (m->counter[i] >> 24) & 0xFF;
	    r[8*i+3] = (m->counter[i] >> 32) & 0XFF;
	    r[8*i+2] = (m->counter[i] >> 40) & 0xFF;
	    r[8*i+1] = (m->counter[i] >> 48) & 0xFF;
	    r[8*i]   = (m->counter[i] >> 56) & 0xFF;
	}
    }
}

void
SHA384_Init(SHA384_CTX *m)
{
    m->sz[0] = 0;
    m->sz[1] = 0;
    A = 0xcbbb9d5dc1059ed8;
    B = 0x629a292a367cd507;
    C = 0x9159015a3070dd17;
    D = 0x152fecd8f70e5939;
    E = 0x67332667ffc00b31;
    F = 0x8eb44a8768581511;
    G = 0xdb0c2e0d64f98fa7;
    H = 0x47b5481dbefa4fa4;
}

void
SHA384_Update (SHA384_CTX *m, const void *v, size_t len)
{
    SHA512_Update(m, v, len);
}

void
SHA384_Final (void *res, SHA384_CTX *m)
{
    unsigned char data[SHA512_DIGEST_LENGTH];
    SHA512_Final(data, m);
    memcpy(res, data, SHA384_DIGEST_LENGTH);
}

