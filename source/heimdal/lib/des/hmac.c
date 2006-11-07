#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hmac.h>

void
HMAC_CTX_init(HMAC_CTX *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void
HMAC_CTX_cleanup(HMAC_CTX *ctx)
{
    if (ctx->buf) {
	memset(ctx->buf, 0, ctx->key_length);
	free(ctx->buf);
	ctx->buf = NULL;
    }
    if (ctx->opad) {
	memset(ctx->ipad, 0, ctx->key_length);
	free(ctx->opad);
	ctx->opad = NULL;
    }
    if (ctx->ipad) {
	memset(ctx->ipad, 0, ctx->key_length);
	free(ctx->ipad);
	ctx->ipad = NULL;
    }
    if (ctx->ctx) {
	EVP_MD_CTX_destroy(ctx->ctx);
	ctx->ctx = NULL;
    }
}

size_t
HMAC_size(const HMAC_CTX *ctx)
{
    return EVP_MD_size(ctx->md);
}

void
HMAC_Init_ex(HMAC_CTX *ctx,
	     const void *key,
	     size_t keylen,
	     const EVP_MD *md,
	     ENGINE *engine)
{
    unsigned char *p;
    size_t i;

    if (ctx->md != md) {
	ctx->md = md;
	if (ctx->buf)
	    free (ctx->buf);
	ctx->key_length = EVP_MD_size(ctx->md);
	ctx->buf = malloc(ctx->key_length);
    }
#if 0
    ctx->engine = engine;
#endif

    if (keylen > EVP_MD_block_size(ctx->md)) {
	EVP_Digest(key, keylen, ctx->buf, NULL, ctx->md, engine);
	key = ctx->buf;
	keylen = EVP_MD_size(ctx->md);
    }

    if (ctx->opad)
	free(ctx->opad);
    if (ctx->ipad)
	free(ctx->ipad);

    ctx->opad = malloc(EVP_MD_block_size(ctx->md));
    ctx->ipad = malloc(EVP_MD_block_size(ctx->md));
    memset(ctx->ipad, 0x36, EVP_MD_block_size(ctx->md));
    memset(ctx->opad, 0x5c, EVP_MD_block_size(ctx->md));

    for (i = 0, p = ctx->ipad; i < keylen; i++)
	p[i] ^= ((const unsigned char *)key)[i];
    for (i = 0, p = ctx->opad; i < keylen; i++)
	p[i] ^= ((const unsigned char *)key)[i];

    ctx->ctx = EVP_MD_CTX_create();

    EVP_DigestInit_ex(ctx->ctx, ctx->md, ctx->engine);
    EVP_DigestUpdate(ctx->ctx, ctx->ipad, EVP_MD_block_size(ctx->md));
}

void
HMAC_Update(HMAC_CTX *ctx, const void *data, size_t len)
{
    EVP_DigestUpdate(ctx->ctx, data, len);
}

void
HMAC_Final(HMAC_CTX *ctx, void *md, unsigned int *len)
{
    EVP_DigestFinal_ex(ctx->ctx, ctx->buf, NULL);

    EVP_DigestInit_ex(ctx->ctx, ctx->md, ctx->engine);
    EVP_DigestUpdate(ctx->ctx, ctx->opad, EVP_MD_block_size(ctx->md));
    EVP_DigestUpdate(ctx->ctx, ctx->buf, ctx->key_length);
    EVP_DigestFinal_ex(ctx->ctx, md, len);
}

void *
HMAC(const EVP_MD *md,
     const void *key, size_t key_size,
     const void *data, size_t data_size, 
     void *hash, unsigned int *hash_len)
{
    HMAC_CTX ctx;

    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key, key_size, md, NULL);
    HMAC_Update(&ctx, data, data_size);
    HMAC_Final(&ctx, hash, hash_len);
    HMAC_CTX_cleanup(&ctx);
    return hash;
}
