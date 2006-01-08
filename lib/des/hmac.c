#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hmac.h>

HMAC_CTX *
HMAC_CTX_create(void)
{
    return NULL;
}

void
HMAC_CTX_destroy(HMAC_CTX *ctx)
{
    HMAC_CTX_cleanup(ctx);
    if (ctx->buf) {
	free(ctx->buf);
	ctx->buf = NULL;
    }
    if (ctx->opad) {
	free(ctx->opad);
	ctx->opad = NULL;
    }
    if (ctx->ipad) {
	free(ctx->ipad);
	ctx->ipad = NULL;
    }
    free(ctx);
}

void
HMAC_CTX_init(HMAC_CTX *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void
HMAC_CTX_cleanup(HMAC_CTX *ctx)
{
    EVP_MD_CTX_cleanup(ctx->ctx);
}

size_t
HMAC_size(const HMAC_CTX *ctx)
{
    return EVP_MD_size(ctx->md);
}

void
HMAC_Init_ex(HMAC_CTX *ctx,
	     const void *key,
	     size_t len,
	     const EVP_MD *md,
	     ENGINE *engine)
{
    unsigned char *p;
    size_t i;

    if (ctx->md != md) {
	ctx->md = md;
	if (ctx->buf)
	    free (ctx->buf);
	ctx->buf = malloc(EVP_MD_size(ctx->md));
    }
    ctx->engine = engine;

    if (len < EVP_MD_size(ctx->md)) {
	key = ctx->buf;
	EVP_Digest(key, len, ctx->buf, NULL, ctx->md, engine);
	len = EVP_MD_size(ctx->md);
    }

    if (ctx->opad)
	free(ctx->opad);
    if (ctx->ipad)
	free(ctx->ipad);

    ctx->opad = malloc(len);
    ctx->ipad = malloc(len);
    ctx->key_length = len;

    for (i = 0, p = ctx->opad; i < len; i++)
	p[i] = ((const unsigned char *)key)[i] ^ 0x36;
    for (i = 0, p = ctx->ipad; i < len; i++)
	p[i] = ((const unsigned char *)key)[i] ^ 0x5c;

    ctx->ctx = EVP_MD_CTX_create();

    EVP_DigestInit_ex(ctx->ctx, ctx->md, ctx->engine);
    EVP_DigestUpdate(ctx->ctx, ctx->ipad, ctx->key_length);
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
    EVP_DigestUpdate(ctx->ctx, ctx->opad, ctx->key_length);
    EVP_DigestUpdate(ctx->ctx, ctx->buf, EVP_MD_size(ctx->md));
    EVP_DigestFinal_ex(ctx->ctx, md, len);
}

void *
HMAC(const EVP_MD *md,
     const void *key, size_t key_size,
     const void *data, size_t data_size, 
     void *hash, unsigned int *hash_len)
{
    HMAC_CTX *ctx;

    ctx = HMAC_CTX_create();
    if (ctx == NULL)
	return NULL;
    HMAC_Init_ex(ctx, key, key_size, md, NULL);
    HMAC_Update(ctx, data, data_size);
    HMAC_Final(ctx, hash, hash_len);
    HMAC_CTX_destroy(ctx);
    return hash;
}
