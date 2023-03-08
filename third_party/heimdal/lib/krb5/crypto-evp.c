/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"

void
_krb5_evp_schedule(krb5_context context,
		   struct _krb5_key_type *kt,
		   struct _krb5_key_data *kd)
{
    struct _krb5_evp_schedule *key = kd->schedule->data;
    const EVP_CIPHER *c = (*kt->evp)();

    EVP_CIPHER_CTX_init(&key->ectx);
    EVP_CIPHER_CTX_init(&key->dctx);

    EVP_CipherInit_ex(&key->ectx, c, NULL, kd->key->keyvalue.data, NULL, 1);
    EVP_CipherInit_ex(&key->dctx, c, NULL, kd->key->keyvalue.data, NULL, 0);
}

void
_krb5_evp_cleanup(krb5_context context, struct _krb5_key_data *kd)
{
    struct _krb5_evp_schedule *key = kd->schedule->data;
    EVP_CIPHER_CTX_cleanup(&key->ectx);
    EVP_CIPHER_CTX_cleanup(&key->dctx);
}

int
_krb5_evp_digest_iov(krb5_crypto crypto,
		     const struct krb5_crypto_iov *iov,
		     int niov,
		     void *hash,
		     unsigned int *hsize,
		     const EVP_MD *md,
		     ENGINE *engine)
{
    EVP_MD_CTX *ctx;
    int ret, i;
    krb5_data current = {0,0};

    if (crypto != NULL) {
	if (crypto->mdctx == NULL)
	    crypto->mdctx = EVP_MD_CTX_create();
	if (crypto->mdctx == NULL)
	    return 0;
	ctx = crypto->mdctx;
    } else
        ctx = EVP_MD_CTX_create();

    ret = EVP_DigestInit_ex(ctx, md, engine);
    if (ret != 1)
	goto out;

    /* Minimize EVP calls by coalescing contiguous iovec elements */
    for (i = 0; i < niov; i++) {
        if (_krb5_crypto_iov_should_sign(&iov[i])) {
	    if (current.data &&
                (char *)current.data + current.length == iov[i].data.data) {
		current.length += iov[i].data.length;
	    } else {
		if (current.data) {
		    ret = EVP_DigestUpdate(ctx, current.data, current.length);
		    if (ret != 1)
		        goto out;
		}
		current = iov[i].data;
	    }
	}
    }

    if (current.data) {
	ret = EVP_DigestUpdate(ctx, current.data, current.length);
	if (ret != 1)
	    goto out;
    }

    ret = EVP_DigestFinal_ex(ctx, hash, hsize);

out:
    if (crypto == NULL)
        EVP_MD_CTX_destroy(ctx);

    return ret;
}

krb5_error_code
_krb5_evp_hmac_iov(krb5_context context,
                   krb5_crypto crypto,
                   struct _krb5_key_data *key,
                   const struct krb5_crypto_iov *iov,
                   int niov,
                   void *hmac,
                   unsigned int *hmaclen,
                   const EVP_MD *md,
                   ENGINE *engine)
{
    HMAC_CTX *ctx;
    krb5_data current = {0, 0};
    int i;

    if (crypto != NULL) {
	if (crypto->hmacctx == NULL)
	    crypto->hmacctx = HMAC_CTX_new();
	ctx = crypto->hmacctx;
    } else {
	ctx = HMAC_CTX_new();
    }
    if (ctx == NULL)
        return krb5_enomem(context);

    if (HMAC_Init_ex(ctx, key->key->keyvalue.data, key->key->keyvalue.length,
                     md, engine) == 0) {
        HMAC_CTX_free(ctx);
        return krb5_enomem(context);
    }

    for (i = 0; i < niov; i++) {
        if (_krb5_crypto_iov_should_sign(&iov[i])) {
	    if (current.data &&
                (char *)current.data + current.length == iov[i].data.data) {
		current.length += iov[i].data.length;
	    } else {
		if (current.data)
		    HMAC_Update(ctx, current.data, current.length);
		current = iov[i].data;
	    }
	}
    }

    if (current.data)
	HMAC_Update(ctx, current.data, current.length);

    HMAC_Final(ctx, hmac, hmaclen);

    if (crypto == NULL)
        HMAC_CTX_free(ctx);

    return 0;
}

krb5_error_code
_krb5_evp_encrypt(krb5_context context,
		struct _krb5_key_data *key,
		void *data,
		size_t len,
		krb5_boolean encryptp,
		int usage,
		void *ivec)
{
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    EVP_CIPHER_CTX *c;
    c = encryptp ? &ctx->ectx : &ctx->dctx;
    if (ivec == NULL) {
	/* alloca ? */
	size_t len2 = EVP_CIPHER_CTX_iv_length(c);
	void *loiv = malloc(len2);
	if (loiv == NULL)
	    return krb5_enomem(context);
	memset(loiv, 0, len2);
	EVP_CipherInit_ex(c, NULL, NULL, NULL, loiv, -1);
	free(loiv);
    } else
	EVP_CipherInit_ex(c, NULL, NULL, NULL, ivec, -1);
    EVP_Cipher(c, data, data, len);
    return 0;
}

struct _krb5_evp_iov_cursor
{
    struct krb5_crypto_iov *iov;
    int niov;
    krb5_data current;
    int nextidx;
};

static const unsigned char zero_ivec[EVP_MAX_BLOCK_LENGTH] = { 0 };

static inline int
_krb5_evp_iov_should_encrypt(struct krb5_crypto_iov *iov)
{
    return (iov->flags == KRB5_CRYPTO_TYPE_DATA
	    || iov->flags == KRB5_CRYPTO_TYPE_HEADER
	    || iov->flags == KRB5_CRYPTO_TYPE_PADDING);
}
/*
 * If we have a group of iovecs which have been split up from
 * a single common buffer, expand the 'current' iovec out to
 * be as large as possible.
 */

static inline void
_krb5_evp_iov_cursor_expand(struct _krb5_evp_iov_cursor *cursor)
{
    if (cursor->nextidx == cursor->niov)
       return;

    while (_krb5_evp_iov_should_encrypt(&cursor->iov[cursor->nextidx])) {
	if (cursor->iov[cursor->nextidx].data.length != 0 &&
	    ((char *)cursor->current.data + cursor->current.length
	     != cursor->iov[cursor->nextidx].data.data)) {
            return;
        }
	cursor->current.length += cursor->iov[cursor->nextidx].data.length;
	cursor->nextidx++;
    }

    return;
}

/* Move the cursor along to the start of the next block to be
 * encrypted */
static inline void
_krb5_evp_iov_cursor_nextcrypt(struct _krb5_evp_iov_cursor *cursor)
{
    for (; cursor->nextidx < cursor->niov; cursor->nextidx++) {
	if (_krb5_evp_iov_should_encrypt(&cursor->iov[cursor->nextidx])
	    && cursor->iov[cursor->nextidx].data.length != 0) {
	    cursor->current = cursor->iov[cursor->nextidx].data;
	    cursor->nextidx++;
	    _krb5_evp_iov_cursor_expand(cursor);
	    return;
	}
    }

    cursor->current.length = 0; /* No matches, so we're done here */
}

static inline void
_krb5_evp_iov_cursor_init(struct _krb5_evp_iov_cursor *cursor,
                          struct krb5_crypto_iov *iov, int niov)
{
    memset(cursor, 0, sizeof(struct _krb5_evp_iov_cursor));

    cursor->iov = iov;
    cursor->niov = niov;
    cursor->nextidx = 0;

    /* Move along to the first block we're going to be encrypting */
    _krb5_evp_iov_cursor_nextcrypt(cursor);
}

static inline void
_krb5_evp_iov_cursor_advance(struct _krb5_evp_iov_cursor *cursor,
                             size_t amount)
{
    while (amount > 0) {
        if (cursor->current.length > amount) {
            cursor->current.data = (char *)cursor->current.data + amount;
            cursor->current.length -= amount;
            return;
        }
	amount -= cursor->current.length;
	_krb5_evp_iov_cursor_nextcrypt(cursor);
    }
}

static inline int
_krb5_evp_iov_cursor_done(struct _krb5_evp_iov_cursor *cursor)
{
    return (cursor->nextidx == cursor->niov && cursor->current.length == 0);
}

/* Fill a memory buffer with data from one or more iovecs. Doesn't
 * advance the passed in cursor - use outcursor for the position
 * at the end
 */
static inline void
_krb5_evp_iov_cursor_fillbuf(struct _krb5_evp_iov_cursor *cursor,
                             unsigned char *buf, size_t length,
                             struct _krb5_evp_iov_cursor *outcursor)
{
    struct _krb5_evp_iov_cursor cursorint;

    cursorint = *cursor;

    while (length > 0 && !_krb5_evp_iov_cursor_done(&cursorint)) {
	if (cursorint.current.length > length) {
	    memcpy(buf, cursorint.current.data, length);
	    _krb5_evp_iov_cursor_advance(&cursorint, length);
	    length = 0;
	} else {
	    memcpy(buf, cursorint.current.data, cursorint.current.length);
	    length -= cursorint.current.length;
	    buf += cursorint.current.length;
	    _krb5_evp_iov_cursor_nextcrypt(&cursorint);
	}
    }

    if (outcursor != NULL)
	*outcursor = cursorint;
}

/* Fill an iovec from a memory buffer. Always advances the cursor to
 * the end of the filled region
 */
static inline void
_krb5_evp_iov_cursor_fillvec(struct _krb5_evp_iov_cursor *cursor,
                             unsigned char *buf, size_t length)
{
    while (length > 0 && !_krb5_evp_iov_cursor_done(cursor)) {
	if (cursor->current.length > length) {
	    memcpy(cursor->current.data, buf, length);
	    _krb5_evp_iov_cursor_advance(cursor, length);
	    length = 0;
	} else {
	    memcpy(cursor->current.data, buf, cursor->current.length);
	    length -= cursor->current.length;
	    buf += cursor->current.length;
	    _krb5_evp_iov_cursor_nextcrypt(cursor);
	}
    }
}

static size_t
_krb5_evp_iov_cryptlength(struct krb5_crypto_iov *iov, int niov)
{
    int i;
    size_t length = 0;

    for (i = 0; i < niov; i++) {
	if (_krb5_evp_iov_should_encrypt(&iov[i]))
	    length += iov[i].data.length;
    }

    return length;
}

int
_krb5_evp_encrypt_iov(krb5_context context,
		      struct _krb5_key_data *key,
		      struct krb5_crypto_iov *iov,
		      int niov,
		      krb5_boolean encryptp,
		      int usage,
		      void *ivec)
{
    size_t blocksize, blockmask, wholeblocks;
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    unsigned char tmp[EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *c;
    struct _krb5_evp_iov_cursor cursor;

    c = encryptp ? &ctx->ectx : &ctx->dctx;

    blocksize = EVP_CIPHER_CTX_block_size(c);

    blockmask = ~(blocksize - 1);

    if (ivec)
	EVP_CipherInit_ex(c, NULL, NULL, NULL, ivec, -1);
    else
	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);

    _krb5_evp_iov_cursor_init(&cursor, iov, niov);

    while (!_krb5_evp_iov_cursor_done(&cursor)) {

	/* Number of bytes of data in this iovec that are in whole blocks */
        wholeblocks = cursor.current.length & ~blockmask;

        if (wholeblocks != 0) {
            EVP_Cipher(c, cursor.current.data,
                       cursor.current.data, wholeblocks);
            _krb5_evp_iov_cursor_advance(&cursor, wholeblocks);
        }

        /* If there's a partial block of data remaining in the current
         * iovec, steal enough from subsequent iovecs to form a whole block */
        if (cursor.current.length > 0 && cursor.current.length < blocksize) {
	    /* Build up a block's worth of data in tmp, leaving the cursor
	     * pointing at where we started */
            _krb5_evp_iov_cursor_fillbuf(&cursor, tmp, blocksize, NULL);

            EVP_Cipher(c, tmp, tmp, blocksize);

            /* Copy the data in tmp back into the iovecs that it came from,
             * advancing the cursor */
            _krb5_evp_iov_cursor_fillvec(&cursor, tmp, blocksize);
        }
    }

    return 0;
}

int
_krb5_evp_encrypt_iov_cts(krb5_context context,
			  struct _krb5_key_data *key,
			  struct krb5_crypto_iov *iov,
			  int niov,
			  krb5_boolean encryptp,
			  int usage,
			  void *ivec)
{
    size_t blocksize, blockmask, wholeblocks, length;
    size_t remaining, partiallen;
    struct _krb5_evp_iov_cursor cursor, lastpos;
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    unsigned char tmp[EVP_MAX_BLOCK_LENGTH], tmp2[EVP_MAX_BLOCK_LENGTH];
    unsigned char tmp3[EVP_MAX_BLOCK_LENGTH], ivec2[EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *c;
    int i;

    c = encryptp ? &ctx->ectx : &ctx->dctx;

    blocksize = EVP_CIPHER_CTX_block_size(c);
    blockmask = ~(blocksize - 1);

    length = _krb5_evp_iov_cryptlength(iov, niov);

    if (length < blocksize) {
	krb5_set_error_message(context, EINVAL,
			       "message block too short");
	return EINVAL;
    }

    if (length == blocksize)
	return _krb5_evp_encrypt_iov(context, key, iov, niov,
	                             encryptp, usage, ivec);

    if (ivec)
	EVP_CipherInit_ex(c, NULL, NULL, NULL, ivec, -1);
    else
	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);

    if (encryptp) {
	/* On our first pass, we want to process everything but the
	 * final partial block */
	remaining = ((length - 1) & blockmask);
	partiallen = length - remaining;

	memset(&lastpos, 0, sizeof(lastpos)); /* Keep the compiler happy */
    } else {
	/* Decryption needs to leave 2 whole blocks and a partial for
	 * further processing */
	if (length > 2 * blocksize) {
	    remaining = (((length - 1) / blocksize) * blocksize) - (blocksize*2);
	    partiallen = length - remaining - (blocksize * 2);
	} else {
	    remaining = 0;
	    partiallen = length - blocksize;
	}
    }

    _krb5_evp_iov_cursor_init(&cursor, iov, niov);
    while (remaining > 0) {
	/* If the iovec has more data than we need, just use it */
	if (cursor.current.length >= remaining) {
	    EVP_Cipher(c, cursor.current.data, cursor.current.data, remaining);

	    if (encryptp) {
	        /* We've just encrypted the last block of data. Make a copy
	         * of it (and its location) for the CTS dance, below */
	        lastpos = cursor;
	        _krb5_evp_iov_cursor_advance(&lastpos, remaining - blocksize);
	        memcpy(ivec2, lastpos.current.data, blocksize);
	    }

	    _krb5_evp_iov_cursor_advance(&cursor, remaining);
	    remaining = 0;
	} else {
	    /* Use as much as we can, firstly all of the whole blocks */
	    wholeblocks = cursor.current.length & blockmask;

	    if (wholeblocks > 0) {
		EVP_Cipher(c, cursor.current.data, cursor.current.data,
		           wholeblocks);
		_krb5_evp_iov_cursor_advance(&cursor, wholeblocks);
		remaining -= wholeblocks;
	    }

	    /* Then, if we have partial data left, steal enough from subsequent
	     * iovecs to make a whole block */
	    if (cursor.current.length > 0 && cursor.current.length < blocksize) {
		if (encryptp && remaining == blocksize)
		    lastpos = cursor;

		_krb5_evp_iov_cursor_fillbuf(&cursor, ivec2, blocksize, NULL);
		EVP_Cipher(c, ivec2, ivec2, blocksize);
		_krb5_evp_iov_cursor_fillvec(&cursor, ivec2, blocksize);

		remaining -= blocksize;
            }
        }
    }

    /* Encryption */
    if (encryptp) {
	/* Copy the partial block into tmp */
	_krb5_evp_iov_cursor_fillbuf(&cursor, tmp, partiallen, NULL);

	/* XOR the final partial block with ivec2 */
	for (i = 0; i < partiallen; i++)
	    tmp[i] = tmp[i] ^ ivec2[i];
	for (; i < blocksize; i++)
	    tmp[i] = 0 ^ ivec2[i]; /* XOR 0s if partial block exhausted */

	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
	EVP_Cipher(c, tmp, tmp, blocksize);

	_krb5_evp_iov_cursor_fillvec(&lastpos, tmp, blocksize);
	_krb5_evp_iov_cursor_fillvec(&cursor, ivec2, partiallen);

        if (ivec)
	    memcpy(ivec, tmp, blocksize);

        return 0;
    }

    /* Decryption */

    /* Make a copy of the 2nd last full ciphertext block in ivec2 before
     * decrypting it. If no such block exists, use ivec or zero_ivec */
    if (length <= blocksize * 2) {
	if (ivec)
	   memcpy(ivec2, ivec, blocksize);
	else
	   memcpy(ivec2, zero_ivec, blocksize);
    } else {
	_krb5_evp_iov_cursor_fillbuf(&cursor, ivec2, blocksize, NULL);
	EVP_Cipher(c, tmp, ivec2, blocksize);
	_krb5_evp_iov_cursor_fillvec(&cursor, tmp, blocksize);
    }

    lastpos = cursor; /* Remember where the last block is */
    _krb5_evp_iov_cursor_fillbuf(&cursor, tmp, blocksize, &cursor);
    EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
    EVP_Cipher(c, tmp2, tmp, blocksize); /* tmp eventually becomes output ivec */

    _krb5_evp_iov_cursor_fillbuf(&cursor, tmp3, partiallen, NULL);

    memcpy(tmp3 + partiallen, tmp2 + partiallen, blocksize - partiallen); /* xor 0 */
    for (i = 0; i < partiallen; i++)
	tmp2[i] = tmp2[i] ^ tmp3[i];

    _krb5_evp_iov_cursor_fillvec(&cursor, tmp2, partiallen);

    EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
    EVP_Cipher(c, tmp3, tmp3, blocksize);

    for (i = 0; i < blocksize; i++)
	tmp3[i] ^= ivec2[i];

    _krb5_evp_iov_cursor_fillvec(&lastpos, tmp3, blocksize);

    if (ivec)
	memcpy(ivec, tmp, blocksize);

    return 0;
}

krb5_error_code
_krb5_evp_encrypt_cts(krb5_context context,
		      struct _krb5_key_data *key,
		      void *data,
		      size_t len,
		      krb5_boolean encryptp,
		      int usage,
		      void *ivec)
{
    size_t i, blocksize;
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    unsigned char tmp[EVP_MAX_BLOCK_LENGTH], ivec2[EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *c;
    unsigned char *p;

    c = encryptp ? &ctx->ectx : &ctx->dctx;

    blocksize = EVP_CIPHER_CTX_block_size(c);

    if (len < blocksize) {
	krb5_set_error_message(context, EINVAL,
			       "message block too short");
	return EINVAL;
    } else if (len == blocksize) {
	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
	EVP_Cipher(c, data, data, len);
	return 0;
    }

    if (ivec)
	EVP_CipherInit_ex(c, NULL, NULL, NULL, ivec, -1);
    else
	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);

    if (encryptp) {

	p = data;
	i = ((len - 1) / blocksize) * blocksize;
	EVP_Cipher(c, p, p, i);
	p += i - blocksize;
	len -= i;
	memcpy(ivec2, p, blocksize);

	for (i = 0; i < len; i++)
	    tmp[i] = p[i + blocksize] ^ ivec2[i];
	for (; i < blocksize; i++)
	    tmp[i] = 0 ^ ivec2[i];

	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
	EVP_Cipher(c, p, tmp, blocksize);

	memcpy(p + blocksize, ivec2, len);
	if (ivec)
	    memcpy(ivec, p, blocksize);
    } else {
	unsigned char tmp2[EVP_MAX_BLOCK_LENGTH], tmp3[EVP_MAX_BLOCK_LENGTH];

	p = data;
	if (len > blocksize * 2) {
	    /* remove last two blocks and round up, decrypt this with cbc, then do cts dance */
	    i = ((((len - blocksize * 2) + blocksize - 1) / blocksize) * blocksize);
	    memcpy(ivec2, p + i - blocksize, blocksize);
	    EVP_Cipher(c, p, p, i);
	    p += i;
	    len -= i + blocksize;
	} else {
	    if (ivec)
		memcpy(ivec2, ivec, blocksize);
	    else
		memcpy(ivec2, zero_ivec, blocksize);
	    len -= blocksize;
	}

	memcpy(tmp, p, blocksize);
	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
	EVP_Cipher(c, tmp2, p, blocksize);

	memcpy(tmp3, p + blocksize, len);
	memcpy(tmp3 + len, tmp2 + len, blocksize - len); /* xor 0 */

	for (i = 0; i < len; i++)
	    p[i + blocksize] = tmp2[i] ^ tmp3[i];

	EVP_CipherInit_ex(c, NULL, NULL, NULL, zero_ivec, -1);
	EVP_Cipher(c, p, tmp3, blocksize);

	for (i = 0; i < blocksize; i++)
	    p[i] ^= ivec2[i];
	if (ivec)
	    memcpy(ivec, tmp, blocksize);
    }
    return 0;
}
