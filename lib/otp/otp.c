#ifdef HAVE_CONFIG_H
#include "config.h"
RCSID("$Id$");
#endif

#include "otp_locl.h"
#include "otp_md.h"

static OtpAlgorithm algorithms[] = {
  {ALG_MD4, "md4", 16, otp_md4_hash, otp_md4_init, otp_md4_next},
  {ALG_MD5, "md5", 16, otp_md5_hash, otp_md5_init, otp_md5_next},
  {ALG_SHA, "sha", 16, otp_sha_hash, otp_sha_init, otp_sha_next}
};

OtpAlgorithm *
otp_find_alg (char *name)
{
  int i;

  for (i = 0; i < sizeof(algorithms)/sizeof(*algorithms); ++i)
    if (strcmp (name, algorithms[i].name) == 0)
      return &algorithms[i];
  return NULL;
}
