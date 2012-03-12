#ifndef MD5_H
#define MD5_H

#ifndef HEADER_MD5_H
/* Try to avoid clashes with OpenSSL */
#define HEADER_MD5_H 
#endif

#ifdef HAVE_BSD_MD5_H
/* Try to avoid clashes with BSD MD5 implementation */
#include <bsd/md5.h>
#else
/* Try to use CommonCrypto on Mac as otherwise we can get MD5Final twice */
#ifdef HAVE_COMMONCRYPTO_COMMONDIGEST_H
#include <CommonCrypto/CommonDigest.h>

#define MD5Init(c)					CC_MD5_Init(c)
#define MD5Update(c,d,l)			CC_MD5_Update(c,d,l)
#define MD5Final(m, c)				CC_MD5_Final((unsigned char *)m,c)
#define MD5Context CC_MD5state_st

#else
typedef struct MD5Context {
	uint32_t buf[4];
	uint32_t bits[2];
	uint8_t in[64];
} MD5_CTX;

#define MD5_DIGEST_LENGTH 16

void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context, const uint8_t *buf,
	       size_t len);
void MD5Final(uint8_t digest[MD5_DIGEST_LENGTH], MD5_CTX *context);
#endif /* HAVE_COMMONCRYPTO_COMMONDIGEST_H */

#endif /* HAVE_BSD_MD5_H */

#endif /* !MD5_H */
