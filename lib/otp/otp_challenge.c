#ifdef HAVE_CONFIG_H
#include "config.h"
RCSID("$Id$");
#endif

#include "otp_locl.h"

int
otp_challenge (OtpContext *ctx, char *user, char *str, size_t len)
{
  void *dbm;
  int ret;

  ctx->user = strdup(user);
  dbm = otp_db_open ();
  if (dbm == NULL)
    return -1;
  ret = otp_get (dbm, ctx);
  otp_db_close (dbm);
  if (ret)
    return ret;
  sprintf (str, "[ otp-%s %u %s ]", ctx->alg->name, ctx->n-1, ctx->seed);
  return 0;
}
