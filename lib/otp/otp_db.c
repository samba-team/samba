/*
 * Copyright (c) 1995, 1996 Kungliga Tekniska Hoegskolan (Royal Institute
 * of Technology, Stockholm, Sweden).
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
 *      Hoegskolan and its contributors.
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

#include "otp_locl.h"

void *
otp_db_open ()
{
  int lock;

  do {
    struct stat statbuf;
    lock = open (OTP_DB_LOCK, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (lock >= 0) {
      close(lock);
      break;
    }
    if (stat (OTP_DB_LOCK, &statbuf) < 0)
      if (errno == ENOENT)
	continue;
      else
	return NULL;
    if (time(NULL) - statbuf.st_mtime > OTP_DB_TIMEOUT)
      unlink (OTP_DB_LOCK);
  } while(1);
  return dbm_open (OTP_DB, O_RDWR | O_CREAT, 0600);
}

void
otp_db_close (void *dbm)
{
  dbm_close ((DBM *)dbm);
  unlink (OTP_DB_LOCK);
}

/*
 * Read this entry from the database and lock it.
 */

int
otp_get (void *v, OtpContext *ctx)
{
  DBM *dbm = (DBM *)v;
  datum dat, key;
  unsigned char *p;
  time_t now, then;

  key.dsize = strlen(ctx->user);
  key.dptr  = ctx->user;

  dat = dbm_fetch (dbm, key);
  if (dat.dptr == NULL)
    return -1;
  p = dat.dptr;
  time(&now);
  memcpy (&then, p, sizeof(then));
  if (then && now - then < OTP_USER_TIMEOUT)
    return -1;
  memcpy (p, &now, sizeof(now));
  p += sizeof(now);
  ctx->alg = otp_find_alg (p);
  if (ctx->alg == NULL)
    return -1;
  p += strlen(p) + 1;
  ctx->n = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
  p += 4;
  memcpy (ctx->key, p, OTPKEYSIZE);
  p += OTPKEYSIZE;
  strncpy (ctx->seed, p, sizeof(ctx->seed));
  ctx->seed[sizeof(ctx->seed) - 1] = '\0';
  return dbm_store (dbm, key, dat, DBM_REPLACE);
}

/*
 * Write this entry to the database.
 */

int
otp_put (void *v, OtpContext *ctx)
{
  DBM *dbm = (DBM *)v;
  datum dat, key;
  unsigned char buf[1024], *p;
  time_t zero = 0;

  key.dsize = strlen(ctx->user);
  key.dptr  = ctx->user;

  p = buf;
  memcpy (p, &zero, sizeof(zero));
  p += sizeof(zero);
  strcpy (p, ctx->alg->name);
  p += strlen(p) + 1;
  *p++ = (ctx->n >> 24) & 0xFF;
  *p++ = (ctx->n >> 16) & 0xFF;
  *p++ = (ctx->n >>  8) & 0xFF;
  *p++ = (ctx->n >>  0) & 0xFF;
  memcpy (p, ctx->key, OTPKEYSIZE);
  p += OTPKEYSIZE;
  strcpy (p, ctx->seed);
  p += strlen(p) + 1;
  dat.dptr  = buf;
  dat.dsize = p - buf;
  return dbm_store (dbm, key, dat, DBM_REPLACE);
}
