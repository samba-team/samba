#ifdef HAVE_CONFIG_H
#include "config.h"
RCSID("$Id$");
#endif

#include "otp_locl.h"

void *
otp_db_open ()
{
  DBM *ret;
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
