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

#include <stdio.h>
#include <string.h>
#include <otp.h>

static int
test_one(OtpKey key1, char *name, char *val, void (*print)(OtpKey,char*),
	 OtpAlgorithm *alg)
{
  char buf[256];
  OtpKey key2;

  (*print)(key1, buf);
  printf ("%s: %s, ", name, buf);
  if (strcmp (buf, val) != 0) {
    printf ("failed(*%s* != *%s*)\n", buf, val);
    return 1;
  }
  if (otp_parse (key2, buf, alg)) {
    printf ("parse of %s failed\n", name);
    return 1;
  }
  if (memcmp (key1, key2, OTPKEYSIZE) != 0) {
    printf ("key1 != key2\n");
    return 1;
  }
  printf ("success\n");
  return 0;
}

static int
test ()
{
  OtpAlgorithm *alg = otp_find_alg ("md5");
  char *passphrase = "This is a test.";
  char *seed = "ke1234";
  char *hex = "5bf075d9959d036f";
  char *hex_extended = "hex:5bf075d9959d036f";
  char *standard_word = "BOND FOGY DRAB NE RISE MART";
  char *standard_word_extended = "word:BOND FOGY DRAB NE RISE MART";
  OtpKey key;
  int i;
  int n = 499;

  if (alg == NULL) {
    printf ("Could not find md5\n");
    return 1;
  }
  if(alg->init (key, passphrase, seed))
    return 1;
  for (i = 0; i < n; ++i) {
    if (alg->next (key))
      return 1;
  }
  return test_one (key, "hexadecimal", hex, otp_print_hex, alg) +
    test_one (key, "extended hexadecimal", hex_extended,
	      otp_print_hex_extended, alg) +
    test_one (key, "standard word", standard_word, otp_print_stddict, alg) +
    test_one (key, "extended standard word", standard_word_extended,
	      otp_print_stddict_extended, alg);
}

int
main (void)
{
  return test ();
}
