/*
 * Copyright (c) 2006 - 2007 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>
#include <roken.h>

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
	memset_s(ctx->buf, ctx->key_length, 0, ctx->key_length);
	free(ctx->buf);
	ctx->buf = NULL;
    }
    if (ctx->opad) {
	memset_s(ctx->opad, EVP_MD_block_size(ctx->md), 0, EVP_MD_block_size(ctx->md));
	free(ctx->opad);
	ctx->opad = NULL;
    }
    if (ctx->ipad) {
	memset_s(ctx->ipad, EVP_MD_block_size(ctx->md), 0, EVP_MD_block_size(ctx->md));
	free(ctx->ipad);
	ctx->ipad = NULL;
    }
    if (ctx->ctx) {
	EVP_MD_CTX_destroy(ctx->ctx);
	ctx->ctx = NULL;
    }
}

HMAC_CTX *
HMAC_CTX_new(void)
{
    return calloc(1, sizeof(HMAC_CTX));
}

void
HMAC_CTX_free(HMAC_CTX *ctx)
{
    HMAC_CTX_cleanup(ctx);
    free(ctx);
}

size_t
HMAC_size(const HMAC_CTX *ctx)
{
    return EVP_MD_size(ctx->md);
}

int
HMAC_Init_ex(HMAC_CTX *ctx,
	     const void *key,
	     size_t keylen,
	     const EVP_MD *md,
	     ENGINE *engine)
{
    unsigned char *p;
    size_t i, blockSize;

    blockSize = EVP_MD_block_size(md);

    if (ctx->md != md) {
        if (ctx->md != NULL)
            HMAC_CTX_cleanup(ctx);

	ctx->md = md;
	ctx->key_length = EVP_MD_size(ctx->md);
        ctx->opad = NULL;
        ctx->ipad = NULL;
        ctx->ctx = NULL;
	ctx->buf = malloc(ctx->key_length);
        if (ctx->buf)
            ctx->opad = malloc(blockSize);
        if (ctx->opad)
            ctx->ipad = malloc(blockSize);
        if (ctx->ipad)
            ctx->ctx = EVP_MD_CTX_create();
        if (!ctx->buf || !ctx->opad || !ctx->ipad || !ctx->ctx)
            return 0;
    }
#if 0
    ctx->engine = engine;
#endif

    if (keylen > blockSize) {
	if (EVP_Digest(key, keylen, ctx->buf, NULL, ctx->md, engine) == 0)
            return 0;
	key = ctx->buf;
	keylen = EVP_MD_size(ctx->md);
    }

    memset(ctx->ipad, 0x36, blockSize);
    memset(ctx->opad, 0x5c, blockSize);

    for (i = 0, p = ctx->ipad; i < keylen; i++)
	p[i] ^= ((const unsigned char *)key)[i];
    for (i = 0, p = ctx->opad; i < keylen; i++)
	p[i] ^= ((const unsigned char *)key)[i];

    if (EVP_DigestInit_ex(ctx->ctx, ctx->md, ctx->engine) == 0)
        return 0;
    EVP_DigestUpdate(ctx->ctx, ctx->ipad, EVP_MD_block_size(ctx->md));
    return 1;
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
    if (HMAC_Init_ex(&ctx, key, key_size, md, NULL) == 0) {
        HMAC_CTX_cleanup(&ctx);
        return NULL;
    }
    HMAC_Update(&ctx, data, data_size);
    HMAC_Final(&ctx, hash, hash_len);
    HMAC_CTX_cleanup(&ctx);
    return hash;
}
