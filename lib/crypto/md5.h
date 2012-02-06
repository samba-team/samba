#ifndef MD5_H
#define MD5_H
#ifndef HEADER_MD5_H
/* Try to avoid clashes with OpenSSL */
#define HEADER_MD5_H 
#endif

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

#endif /* !MD5_H */
