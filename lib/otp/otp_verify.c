#ifdef HAVE_CONFIG_H
#include "config.h"
RCSID("$Id$");
#endif

#include "otp_locl.h"

int
otp_verify_user_1 (OtpContext *ctx, char *passwd)
{
  OtpKey key1, key2;

  if (otp_parse (key1, passwd, ctx->alg))
    return -1;
  memcpy (key2, key1, sizeof(key1));
  ctx->alg->next (key2);
  if (memcmp (ctx->key, key2, sizeof(key2)) == 0) {
    --ctx->n;
    memcpy (ctx->key, key1, sizeof(key1));
    return 0;
  } else
    return -1;
}

int
otp_verify_user (OtpContext *ctx, char *passwd)
{
  void *dbm;
  int ret;

  otp_verify_user_1 (ctx, passwd);
  dbm = otp_db_open ();
  if (dbm == NULL) {
    free(ctx->user);
    return -1;
  }
  ret = otp_put (dbm, ctx);
  free(ctx->user);
  otp_db_close (dbm);
  return ret;
}
