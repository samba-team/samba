/* $Id$ */

#include <stdlib.h>

enum {OTPKEYSIZE = 8};

typedef unsigned char OtpKey[OTPKEYSIZE];

#define OTP_MIN_PASSPHRASE 10
#define OTP_MAX_PASSPHRASE 63

#define OTP_USER_TIMEOUT   60
#define OTP_DB_TIMEOUT     60

typedef enum { ALG_MD4, ALG_MD5, ALG_SHA } OtpAlgID;

typedef struct {
  OtpAlgID id;
  char *name;
  int hashsize;
  int (*hash)(char *s, size_t len, char *res);
  int (*init)(OtpKey key, char *pwd, char *seed);
  int (*next)(OtpKey key);
} OtpAlgorithm;

typedef struct {
  char *user;
  OtpAlgorithm *alg;
  unsigned n;
  char seed[17];
  OtpKey key;
} OtpContext;

OtpAlgorithm *otp_find_alg (char *name);
void otp_print_stddict (OtpKey key, char *str);
void otp_print_hex (OtpKey key, char *str);
unsigned opt_checksum (OtpKey key);
int otp_parse_hex (OtpKey key, char *);
int otp_parse_stddict (OtpKey key, char *);
int otp_parse_altdict (OtpKey key, char *, OtpAlgorithm *);
int otp_parse (OtpKey key, char *, OtpAlgorithm *);
int otp_challenge (OtpContext *ctx, char *user, char *str, size_t len);
int otp_verify_user (OtpContext *ctx, char *passwd);
int otp_verify_user_1 (OtpContext *ctx, char *passwd);

void *otp_db_open ();
void otp_db_close (void *);
int otp_put (void *, OtpContext *ctx);
int otp_get (void *, OtpContext *ctx);
