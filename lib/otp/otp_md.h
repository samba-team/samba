/* $Id$ */

int otp_md4_init (OtpKey key, char *pwd, char *seed);
int otp_md4_hash (char *, size_t, char *res);
int otp_md4_next (OtpKey key);

int otp_md5_init (OtpKey key, char *pwd, char *seed);
int otp_md5_hash (char *, size_t, char *res);
int otp_md5_next (OtpKey key);

int otp_sha_init (OtpKey key, char *pwd, char *seed);
int otp_sha_hash (char *, size_t, char *res);
int otp_sha_next (OtpKey key);
