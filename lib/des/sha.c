/*
 * Copyright (c) 1995, 1996, 1997 Kungliga Tekniska Högskolan
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the Kungliga Tekniska
 *      Högskolan and its contributors.
 * 
 * 4. Neither the name of the Institute nor the names of its contributors
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

#ifdef HAVE_CONFIG_H
#include "config.h"

RCSID("$Id$");
#endif

#include <stdlib.h>
#include <string.h>

#include "sha.h"

#ifndef min
#define min(a,b) (((a)>(b))?(b):(a))
#endif

#define A m->counter[0]
#define B m->counter[1]
#define C m->counter[2]
#define D m->counter[3]
#define E m->counter[4]
#define X data

void
sha_init (struct sha *m)
{
  m->offset = 0;
  m->sz = 0;
  A = 0x67452301;
  B = 0xefcdab89;
  C = 0x98badcfe;
  D = 0x10325476;
  E = 0xc3d2e1f0;
}

static u_int32_t
cshift (u_int32_t x, unsigned n)
{
  return (x << n) | (x >> (32 - n));
}

#define F0(x,y,z) ((x & y) | (~x & z))
#define F1(x,y,z) (x ^ y ^ z)
#define F2(x,y,z) ((x & y) | (x & z) | (y & z))
#define F3(x,y,z) F1(x,y,z)

#define K0 0x5a827999
#define K1 0x6ed9eba1
#define K2 0x8f1bbcdc
#define K3 0xca62c1d6

#define DO(t,f,k) \
do { \
  u_int32_t temp; \
 \
  temp = cshift(AA, 5) + f(BB,CC,DD) + EE + data[t] + k; \
  EE = DD; \
  DD = CC; \
  CC = cshift(BB, 30); \
  BB = AA; \
  AA = temp; \
} while(0)

static void
calc (struct sha *m, u_int32_t *in)
{
  u_int32_t AA, BB, CC, DD, EE;
  u_int32_t data[80];
  int i;

  AA = A;
  BB = B;
  CC = C;
  DD = D;
  EE = E;

  for (i = 0; i < 16; ++i)
    data[i] = in[i];
  for (i = 16; i < 80; ++i)
    data[i] = cshift(data[i-3] ^ data[i-8] ^ data[i-14] ^ data[i-16], 1);

  /* t=[0,19] */

  DO(0,F0,K0);
  DO(1,F0,K0);
  DO(2,F0,K0);
  DO(3,F0,K0);
  DO(4,F0,K0);
  DO(5,F0,K0);
  DO(6,F0,K0);
  DO(7,F0,K0);
  DO(8,F0,K0);
  DO(9,F0,K0);
  DO(10,F0,K0);
  DO(11,F0,K0);
  DO(12,F0,K0);
  DO(13,F0,K0);
  DO(14,F0,K0);
  DO(15,F0,K0);
  DO(16,F0,K0);
  DO(17,F0,K0);
  DO(18,F0,K0);
  DO(19,F0,K0);

  /* t=[20,39] */

  DO(20,F1,K1);
  DO(21,F1,K1);
  DO(22,F1,K1);
  DO(23,F1,K1);
  DO(24,F1,K1);
  DO(25,F1,K1);
  DO(26,F1,K1);
  DO(27,F1,K1);
  DO(28,F1,K1);
  DO(29,F1,K1);
  DO(30,F1,K1);
  DO(31,F1,K1);
  DO(32,F1,K1);
  DO(33,F1,K1);
  DO(34,F1,K1);
  DO(35,F1,K1);
  DO(36,F1,K1);
  DO(37,F1,K1);
  DO(38,F1,K1);
  DO(39,F1,K1);

  /* t=[40,59] */

  DO(40,F2,K2);
  DO(41,F2,K2);
  DO(42,F2,K2);
  DO(43,F2,K2);
  DO(44,F2,K2);
  DO(45,F2,K2);
  DO(46,F2,K2);
  DO(47,F2,K2);
  DO(48,F2,K2);
  DO(49,F2,K2);
  DO(50,F2,K2);
  DO(51,F2,K2);
  DO(52,F2,K2);
  DO(53,F2,K2);
  DO(54,F2,K2);
  DO(55,F2,K2);
  DO(56,F2,K2);
  DO(57,F2,K2);
  DO(58,F2,K2);
  DO(59,F2,K2);

  /* t=[60,79] */

  DO(60,F3,K3);
  DO(61,F3,K3);
  DO(62,F3,K3);
  DO(63,F3,K3);
  DO(64,F3,K3);
  DO(65,F3,K3);
  DO(66,F3,K3);
  DO(67,F3,K3);
  DO(68,F3,K3);
  DO(69,F3,K3);
  DO(70,F3,K3);
  DO(71,F3,K3);
  DO(72,F3,K3);
  DO(73,F3,K3);
  DO(74,F3,K3);
  DO(75,F3,K3);
  DO(76,F3,K3);
  DO(77,F3,K3);
  DO(78,F3,K3);
  DO(79,F3,K3);

  A += AA;
  B += BB;
  C += CC;
  D += DD;
  E += EE;
}

/*
 * From `Performance analysis of SHA' by Joseph D. Touch <touch@isi.edu>
 */

static u_int32_t
swap_u_int32_t (u_int32_t t)
{
#if !defined(WORDS_BIGENDIAN)
#define ROL(x,n) ((x)<<(n))|((x)>>(32-(n)))
  u_int32_t temp1, temp2;

  temp1   = ROL(t,16);
  temp2   = temp1 >> 8;
  temp1  &= 0x00ff00ff;
  temp2  &= 0x00ff00ff;
  temp1 <<= 8;
  return temp1 | temp2;
#else
  return t;
#endif
}

void
sha_update (struct sha *m, void *v, size_t len)
{
  u_char *p = (u_char *)v;
  m->sz += len;
  if (m->offset == 0 && len % 64 == 0) 
    while (len > 0) {
#if !defined(WORDS_BIGENDIAN)
      {
	int i;
	u_int32_t *u = (u_int32_t *)p;

	for (i = 0; i < 16; ++i)
	  m->current[i] = swap_u_int32_t (u[i]);
      }
      calc (m, m->current);
#else
      calc (m, (u_int32_t *)p);
#endif
      p += 64;
      len -= 64;
    }
  else
    while (len > 0) {
      unsigned l;

      l = min(64 - m->offset, len);
      memcpy ((char *)m->current + m->offset, p, l);
      p += l;
      len -= l;
      m->offset += l;
      if (m->offset == 64) {
#if !defined(WORDS_BIGENDIAN)
	int i;

	for (i = 0; i < 16; ++i)
	  m->current[i] = swap_u_int32_t (m->current[i]);
#endif
	calc (m, m->current);
	m->offset = 0;
      }
    }
}

void
sha_finito (struct sha *m, void *res)
{
  static unsigned char zeros[72];
  u_int32_t len;
  unsigned dstart = (120 - m->offset - 1) % 64 + 1;

  *zeros = 0x80;
  memset (zeros + 1, 0, sizeof(zeros) - 1);
  len = 8 * m->sz;
  len = swap_u_int32_t (len);
  memcpy (zeros + dstart + 4, &len, sizeof(len));
  sha_update (m, zeros, dstart + 8);
  {
    int i;
    u_int32_t *r = (u_int32_t *)res;

    for (i = 0; i < 5; ++i)
      r[i] = swap_u_int32_t (m->counter[i]);
  }
}
