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

#include <config.h>
#include <stdlib.h>
#include <string.h>

#ifndef HAVE_MEMMEM
#include "roken.h"
ROKEN_LIB_FUNCTION void * ROKEN_LIB_CALL
memmem(const void *haystack,
       size_t haystacklen,
       const void *needle,
       size_t needlelen)
{
  const unsigned char *hs = haystack;
  const unsigned char *n = needle;
  size_t hsi, ni;

  if (haystacklen < needlelen || haystacklen == 0)
      return NULL;
  /*
   * Imagine a haystack of length 5 and needle of length 2, then the largest
   * index in the haystack at which we can bother looking for the needle is:
   *
   *    0 1 2 3 4
   *   +---------+
   *   |?|?|?|?|?|
   *   +---------+
   *          ^
   *           \
   *            here, at index 3, which is 5 - 2, and less than (5 - 2 + 1).
   */
  for (hsi = 0, ni = 0; hsi < (haystacklen - needlelen + 1); hsi++, ni = 0) {
      while (ni < needlelen && n[ni] == hs[hsi + ni])
          ni++;
      if (ni == needlelen)
          return rk_UNCONST(&hs[hsi]);
  }
  return NULL;
}
#endif
