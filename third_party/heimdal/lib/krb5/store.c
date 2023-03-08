/*
 * Copyright (c) 1997-2008 Kungliga Tekniska Högskolan
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
#include "store-int.h"

#define BYTEORDER_IS(SP, V) (((SP)->flags & KRB5_STORAGE_BYTEORDER_MASK) == (V))
#define BYTEORDER_IS_LE(SP) BYTEORDER_IS((SP), KRB5_STORAGE_BYTEORDER_LE)
#define BYTEORDER_IS_BE(SP) BYTEORDER_IS((SP), KRB5_STORAGE_BYTEORDER_BE)
#define BYTEORDER_IS_HOST(SP) (BYTEORDER_IS((SP), KRB5_STORAGE_BYTEORDER_HOST) || \
			       krb5_storage_is_flags((SP), KRB5_STORAGE_HOST_BYTEORDER))
#define BYTEORDER_IS_PACKED(SP) BYTEORDER_IS((SP), KRB5_STORAGE_BYTEORDER_PACKED)

/**
 * Add the flags on a storage buffer by or-ing in the flags to the buffer.
 *
 * @param sp the storage buffer to set the flags on
 * @param flags the flags to set
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_storage_set_flags(krb5_storage *sp, krb5_flags flags)
{
    sp->flags |= flags;
}

/**
 * Clear the flags on a storage buffer
 *
 * @param sp the storage buffer to clear the flags on
 * @param flags the flags to clear
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_storage_clear_flags(krb5_storage *sp, krb5_flags flags)
{
    sp->flags &= ~flags;
}

/**
 * Return true or false depending on if the storage flags is set or
 * not. NB testing for the flag 0 always return true.
 *
 * @param sp the storage buffer to check flags on
 * @param flags The flags to test for
 *
 * @return true if all the flags are set, false if not.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_storage_is_flags(krb5_storage *sp, krb5_flags flags)
{
    return (sp->flags & flags) == flags;
}

/**
 * Set the new byte order of the storage buffer.
 *
 * @param sp the storage buffer to set the byte order for.
 * @param byteorder the new byte order.
 *
 * The byte order are: KRB5_STORAGE_BYTEORDER_BE,
 * KRB5_STORAGE_BYTEORDER_LE and KRB5_STORAGE_BYTEORDER_HOST.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_storage_set_byteorder(krb5_storage *sp, krb5_flags byteorder)
{
    sp->flags &= ~KRB5_STORAGE_BYTEORDER_MASK;
    sp->flags |= byteorder;
}

/**
 * Return the current byteorder for the buffer. See krb5_storage_set_byteorder() for the list or byte order contants.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_flags KRB5_LIB_CALL
krb5_storage_get_byteorder(krb5_storage *sp)
{
    return sp->flags & KRB5_STORAGE_BYTEORDER_MASK;
}

/**
 * Set the max alloc value
 *
 * @param sp the storage buffer set the max allow for
 * @param size maximum size to allocate, use 0 to remove limit
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_storage_set_max_alloc(krb5_storage *sp, size_t size)
{
    sp->max_alloc = size;
}

/* don't allocate unresonable amount of memory */
static krb5_error_code
size_too_large(krb5_storage *sp, size_t size)
{
    if (sp->max_alloc && sp->max_alloc < size)
	return HEIM_ERR_TOO_BIG;
    return 0;
}

static krb5_error_code
size_too_large_num(krb5_storage *sp, size_t count, size_t size)
{
    if (sp->max_alloc == 0 || size == 0)
	return 0;
    size = sp->max_alloc / size;
    if (size < count)
	return HEIM_ERR_TOO_BIG;
    return 0;
}

/**
 * Seek to a new offset.
 *
 * @param sp the storage buffer to seek in.
 * @param offset the offset to seek
 * @param whence relateive searching, SEEK_CUR from the current
 * position, SEEK_END from the end, SEEK_SET absolute from the start.
 *
 * @return The new current offset
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION off_t KRB5_LIB_CALL
krb5_storage_seek(krb5_storage *sp, off_t offset, int whence)
{
    return (*sp->seek)(sp, offset, whence);
}

/**
 * Truncate the storage buffer in sp to offset.
 *
 * @param sp the storage buffer to truncate.
 * @param offset the offset to truncate too.
 *
 * @return An Kerberos 5 error code.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_storage_truncate(krb5_storage *sp, off_t offset)
{
    return (*sp->trunc)(sp, offset);
}

/**
 * Sync the storage buffer to its backing store.  If there is no
 * backing store this function will return success.
 *
 * @param sp the storage buffer to sync
 *
 * @return A Kerberos 5 error code
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_storage_fsync(krb5_storage *sp)
{
    if (sp->fsync != NULL)
	return sp->fsync(sp);
    return 0;
}

/**
 * Read to the storage buffer.
 *
 * @param sp the storage buffer to read from
 * @param buf the buffer to store the data in
 * @param len the length to read
 *
 * @return The length of data read (can be shorter then len), or negative on error.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_ssize_t KRB5_LIB_CALL
krb5_storage_read(krb5_storage *sp, void *buf, size_t len)
{
    return sp->fetch(sp, buf, len);
}

/**
 * Write to the storage buffer.
 *
 * @param sp the storage buffer to write to
 * @param buf the buffer to write to the storage buffer
 * @param len the length to write
 *
 * @return The length of data written (can be shorter then len), or negative on error.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_ssize_t KRB5_LIB_CALL
krb5_storage_write(krb5_storage *sp, const void *buf, size_t len)
{
    return sp->store(sp, buf, len);
}

/**
 * Set the return code that will be used when end of storage is reached.
 *
 * @param sp the storage
 * @param code the error code to return on end of storage
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_storage_set_eof_code(krb5_storage *sp, int code)
{
    sp->eof_code = code;
}

/**
 * Get the return code that will be used when end of storage is reached.
 *
 * @param sp the storage
 *
 * @return storage error code
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_storage_get_eof_code(krb5_storage *sp)
{
    return sp->eof_code;
}

/**
 * Free a krb5 storage.
 *
 * @param sp the storage to free.
 *
 * @return An Kerberos 5 error code.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_storage_free(krb5_storage *sp)
{
    if (sp == NULL)
        return 0;
    if(sp->free)
	(*sp->free)(sp);
    free(sp->data);
    free(sp);
    return 0;
}

/**
 * Copy the content of storage to a krb5_data.
 *
 * @param sp the storage to copy to a data
 * @param data the copied data, free with krb5_data_free()
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_storage_to_data(krb5_storage *sp, krb5_data *data)
{
    off_t pos, size;
    krb5_error_code ret;

    pos = sp->seek(sp, 0, SEEK_CUR);
    if (pos < 0)
	return HEIM_ERR_NOT_SEEKABLE;
    size = sp->seek(sp, 0, SEEK_END);
    ret = size_too_large(sp, size);
    if (ret)
	return ret;
    ret = krb5_data_alloc(data, size);
    if (ret) {
	sp->seek(sp, pos, SEEK_SET);
	return ret;
    }
    if (size) {
        ssize_t bytes;

	sp->seek(sp, 0, SEEK_SET);
	bytes = sp->fetch(sp, data->data, data->length);
	sp->seek(sp, pos, SEEK_SET);

        /* sp->fetch() really shouldn't fail */
        if (bytes < 0)
            return sp->eof_code;

        /* Maybe the underlying file (or whatever) got truncated? */
        data->length = bytes;
    }
    return 0;
}

static size_t
pack_int(uint8_t *p, uint64_t val)
{
    size_t l = 0;

    if (val < 128) {
        *p = val;
    } else {
        while (val > 0) {
            *p-- = val % 256;
            val /= 256;
            l++;
        }
        *p = 0x80 | l;
    }
    return l + 1;
}

static size_t
unpack_int_length(uint8_t *v)
{
    size_t size;

    if (*v < 128)
        size = 0;
    else
        size = *v & 0x7f;

    return size + 1;
}

static int
unpack_int(uint8_t *p, size_t len, uint64_t *val, size_t *size)
{
    size_t v;

    if (len == 0)
        return EINVAL;
    --len;
    v = *p++;
    if (v < 128) {
        *val = v;
        *size = 1;
    } else {
        int e;
        size_t l;
        uint64_t tmp;

        if (v == 0x80) {
            *size = 1;
            return EINVAL;
        }
        v &= 0x7F;
        if (len < v)
            return ERANGE;
        e = der_get_unsigned64(p, v, &tmp, &l);
        if (e)
            return ERANGE;
        *val = tmp;
        *size = l + 1;
    }
    return 0;
}

static krb5_error_code
krb5_store_int(krb5_storage *sp,
	       int64_t value,
	       size_t len)
{
    int ret;
    uint8_t v[9], *p = v;

    if (len > sizeof(value))
	return EINVAL;

    if (BYTEORDER_IS_PACKED(sp)) {
        uint64_t mask = ~0ULL >> (64 - len * 8);
        value &= mask;
        p += sizeof(v) - 1;
        len = pack_int(p, value);
        p = v + sizeof(v) - len;
    } else
        _krb5_put_int(v, value, len);
    ret = sp->store(sp, p, len);
    if (ret < 0)
	return errno;
    if ((size_t)ret != len)
	return sp->eof_code;
    return 0;
}

/**
 * Store a int32 to storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_int32(krb5_storage *sp,
		 int32_t value)
{
    if(BYTEORDER_IS_HOST(sp))
	value = htonl(value);
    else if(BYTEORDER_IS_LE(sp))
	value = bswap32(value);
    return krb5_store_int(sp, value, 4);
}

/**
 * Store a int64 to storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_int64(krb5_storage *sp,
		 int64_t value)
{
    if (BYTEORDER_IS_HOST(sp))
#ifdef WORDS_BIGENDIAN
        ;
#else
	value = bswap64(value); /* There's no ntohll() */
#endif
    else if (BYTEORDER_IS_LE(sp))
	value = bswap64(value);
    return krb5_store_int(sp, value, 8);
}

/**
 * Store a uint32 to storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_uint32(krb5_storage *sp,
		  uint32_t value)
{
    return krb5_store_int32(sp, (int32_t)value);
}

/**
 * Store a uint64 to storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_uint64(krb5_storage *sp,
		  uint64_t value)
{
    return krb5_store_int64(sp, (int64_t)value);
}

static krb5_error_code
krb5_ret_int(krb5_storage *sp,
	     int64_t *value,
	     size_t len)
{
    int ret;
    unsigned char v[9];
    uint64_t w = 0;
    *value = 0; /* quiets warnings */
    if (BYTEORDER_IS_PACKED(sp)) {
        ret = sp->fetch(sp, v, 1);
        if (ret < 0)
            return errno;
        if (ret != 1)
            return sp->eof_code;

        len = unpack_int_length(v);
        if (len < 1)
            return ERANGE;
        else if (len > 1) {
            ret = sp->fetch(sp, v + 1, len - 1);
            if (ret < 0)
                return errno;
            if (ret != len - 1)
                return sp->eof_code;
        }
        ret = unpack_int(v, len, &w, &len);
        if (ret)
            return ret;
        *value = w;
        return 0;
    }
    ret = sp->fetch(sp, v, len);
    if (ret < 0)
	return errno;
    if ((size_t)ret != len)
	return sp->eof_code;
    _krb5_get_int64(v, &w, len);
    *value = w;
    return 0;
}

/**
 * Read a int64 from storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_int64(krb5_storage *sp,
	       int64_t *value)
{
    krb5_error_code ret = krb5_ret_int(sp, value, 8);
    if(ret)
	return ret;
    if(BYTEORDER_IS_HOST(sp))
#ifdef WORDS_BIGENDIAN
        ;
#else
	*value = bswap64(*value); /* There's no ntohll() */
#endif
    else if(BYTEORDER_IS_LE(sp))
	*value = bswap64(*value);
    return 0;
}

/**
 * Read a uint64 from storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_uint64(krb5_storage *sp,
		uint64_t *value)
{
    krb5_error_code ret;
    int64_t v;

    ret = krb5_ret_int64(sp, &v);
    if (ret == 0)
	*value = (uint64_t)v;

    return ret;
}

/**
 * Read a int32 from storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_int32(krb5_storage *sp,
	       int32_t *value)
{
    int64_t v;

    krb5_error_code ret = krb5_ret_int(sp, &v, 4);
    if (ret)
	return ret;
    *value = v;
    if (BYTEORDER_IS_HOST(sp))
	*value = htonl(*value);
    else if (BYTEORDER_IS_LE(sp))
	*value = bswap32(*value);
    return 0;
}

/**
 * Read a uint32 from storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_uint32(krb5_storage *sp, uint32_t *value)
{
    krb5_error_code ret;
    int32_t v;

    ret = krb5_ret_int32(sp, &v);
    if (ret == 0)
	*value = (uint32_t)v;

    return ret;
}

/**
 * Store a int16 to storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_int16(krb5_storage *sp,
		 int16_t value)
{
    if(BYTEORDER_IS_HOST(sp))
	value = htons(value);
    else if(BYTEORDER_IS_LE(sp))
	value = bswap16(value);
    return krb5_store_int(sp, value, 2);
}

/**
 * Store a uint16 to storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_uint16(krb5_storage *sp,
		  uint16_t value)
{
    return krb5_store_int16(sp, (int16_t)value);
}

/**
 * Read a int16 from storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_int16(krb5_storage *sp,
	       int16_t *value)
{
    int64_t v;
    int ret;
    ret = krb5_ret_int(sp, &v, 2);
    if(ret)
	return ret;
    *value = v;
    if(BYTEORDER_IS_HOST(sp))
	*value = htons(*value);
    else if(BYTEORDER_IS_LE(sp))
	*value = bswap16(*value);
    return 0;
}

/**
 * Read a int16 from storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_uint16(krb5_storage *sp,
		uint16_t *value)
{
    krb5_error_code ret;
    int16_t v;

    ret = krb5_ret_int16(sp, &v);
    if (ret == 0)
	*value = (uint16_t)v;

    return ret;
}

/**
 * Store a int8 to storage.
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_int8(krb5_storage *sp,
		int8_t value)
{
    int ret;

    ret = sp->store(sp, &value, sizeof(value));
    if (ret != sizeof(value))
	return (ret<0)?errno:sp->eof_code;
    return 0;
}

/**
 * Store a uint8 to storage.
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_uint8(krb5_storage *sp,
		 uint8_t value)
{
    return krb5_store_int8(sp, (int8_t)value);
}

/**
 * Read a int8 from storage
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_int8(krb5_storage *sp,
	      int8_t *value)
{
    ssize_t ret;

    ret = sp->fetch(sp, value, sizeof(*value));
    if (ret < 0 || (size_t)ret != sizeof(*value))
	return (ret<0)?errno:sp->eof_code;
    return 0;
}

/**
 * Read a uint8 from storage
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_uint8(krb5_storage *sp,
	       uint8_t *value)
{
    krb5_error_code ret;
    int8_t v;

    ret = krb5_ret_int8(sp, &v);
    if (ret == 0)
	*value = (uint8_t)v;

    return ret;
}

/**
 * Store a data to the storage. The data is stored with an int32 as
 * lenght plus the data (not padded).
 *
 * @param sp the storage buffer to write to
 * @param data the buffer to store.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_data(krb5_storage *sp,
		krb5_data data)
{
    int ret;
    ret = krb5_store_int32(sp, data.length);
    if(ret < 0)
	return ret;
    ret = sp->store(sp, data.data, data.length);
    if(ret < 0)
	return errno;
    if((size_t)ret != data.length)
	return sp->eof_code;
    return 0;
}

/**
 * Store a data blob to the storage. The data is stored with an int32 as
 * length plus the data (not padded).  This function only differs from
 * krb5_store_data() insofar as it takes a void * and a length as parameters.
 *
 * @param sp the storage buffer to write to
 * @param s the string to store.
 * @param len length of the string to be stored.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_datalen(krb5_storage *sp, const void *d, size_t len)
{
    krb5_data data;
    data.length = len;
    data.data = (void *)d;
    return krb5_store_data(sp, data);
}

/**
 * Store a data blob to the storage. The data is stored without a length.
 *
 * @param sp the storage buffer to write to
 * @param s the string to store.
 * @param len length of the string to be stored.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */
KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_bytes(krb5_storage *sp, const void *d, size_t len)
{
    ssize_t ssize;

    ssize = krb5_storage_write(sp, d, len);
    if (ssize != len)
	return ENOMEM;

    return 0;
}

/**
 * Parse a data from the storage.
 *
 * @param sp the storage buffer to read from
 * @param data the parsed data
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_data(krb5_storage *sp,
	      krb5_data *data)
{
    krb5_error_code ret;
    int32_t size;

    ret = krb5_ret_int32(sp, &size);
    if(ret)
	return ret;
    ret = size_too_large(sp, size);
    if (ret)
	return ret;
    ret = krb5_data_alloc (data, size);
    if (ret)
	return ret;
    if (size) {
        ssize_t bytes;

	bytes = sp->fetch(sp, data->data, size);
	if (bytes < 0 || bytes != size) {
            krb5_data_free(data);
	    return (ret < 0)? errno : sp->eof_code;
	}
    }
    return 0;
}

/**
 * Store a string to the buffer. The data is formated as an len:uint32
 * plus the string itself (not padded).
 *
 * @param sp the storage buffer to write to
 * @param s the string to store.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_string(krb5_storage *sp, const char *s)
{
    krb5_data data;

    if (s == NULL)
	return EINVAL;

    data.length = strlen(s);
    data.data = rk_UNCONST(s);
    return krb5_store_data(sp, data);
}

/**
 * Parse a string from the storage.
 *
 * @param sp the storage buffer to read from
 * @param string the parsed string
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_string(krb5_storage *sp,
		char **string)
{
    int ret;
    krb5_data data;

    *string = NULL;
    ret = krb5_ret_data(sp, &data);
    if(ret)
	return ret;
    *string = realloc(data.data, data.length + 1);
    if(*string == NULL){
	free(data.data);
	return ENOMEM;
    }
    (*string)[data.length] = 0;
    return 0;
}

/**
 * Store a zero terminated string to the buffer. The data is stored
 * one character at a time until a NUL is stored.
 *
 * @param sp the storage buffer to write to
 * @param s the string to store.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_stringz(krb5_storage *sp, const char *s)
{
    size_t len;
    ssize_t ret;

    if (s == NULL)
	return EINVAL;

    len = strlen(s) + 1;
    ret = sp->store(sp, s, len);
    if(ret < 0)
	return ret;
    if((size_t)ret != len)
	return sp->eof_code;
    return 0;
}

/**
 * Parse zero terminated string from the storage.
 *
 * @param sp the storage buffer to read from
 * @param string the parsed string
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_stringz(krb5_storage *sp,
		char **string)
{
    char c;
    char *s = NULL;
    size_t len = 0;
    ssize_t ret;

    while((ret = sp->fetch(sp, &c, 1)) == 1){
	krb5_error_code eret;
	char *tmp;

	len++;
	eret = size_too_large(sp, len);
	if (eret) {
	    free(s);
	    return eret;
	}
	tmp = realloc (s, len);
	if (tmp == NULL) {
	    free (s);
	    return ENOMEM;
	}
	s = tmp;
	s[len - 1] = c;
	if(c == 0)
	    break;
    }
    if(ret != 1){
	free(s);
	if(ret == 0)
	    return sp->eof_code;
	return ret;
    }
    *string = s;
    return 0;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_stringnl(krb5_storage *sp, const char *s)
{
    size_t len;
    ssize_t ret;

    if (s == NULL)
	return EINVAL;

    len = strlen(s);
    ret = sp->store(sp, s, len);
    if(ret < 0)
	return ret;
    if((size_t)ret != len)
	return sp->eof_code;
    ret = sp->store(sp, "\n", 1);
    if(ret != 1) {
	if(ret < 0)
	    return ret;
	else
	    return sp->eof_code;
    }

    return 0;

}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_stringnl(krb5_storage *sp,
		  char **string)
{
    int expect_nl = 0;
    char c;
    char *s = NULL;
    size_t len = 0;
    ssize_t ret;

    while((ret = sp->fetch(sp, &c, 1)) == 1){
	krb5_error_code eret;
	char *tmp;

	if (c == '\r') {
	    expect_nl = 1;
	    continue;
	}
	if (expect_nl && c != '\n') {
	    free(s);
	    return KRB5_BADMSGTYPE;
	}

	len++;
	eret = size_too_large(sp, len);
	if (eret) {
	    free(s);
	    return eret;
	}
	tmp = realloc (s, len);
	if (tmp == NULL) {
	    free (s);
	    return ENOMEM;
	}
	s = tmp;
	if(c == '\n') {
	    s[len - 1] = '\0';
	    break;
	}
	s[len - 1] = c;
    }
    if(ret != 1){
	free(s);
	if(ret == 0)
	    return sp->eof_code;
	return ret;
    }
    *string = s;
    return 0;
}

/**
 * Write a principal block to storage.
 *
 * @param sp the storage buffer to write to
 * @param p the principal block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_principal(krb5_storage *sp,
		     krb5_const_principal p)
{
    size_t i;
    int ret;

    if(!krb5_storage_is_flags(sp, KRB5_STORAGE_PRINCIPAL_NO_NAME_TYPE)) {
	ret = krb5_store_int32(sp, p->name.name_type);
	if(ret) return ret;
    }
    if(krb5_storage_is_flags(sp, KRB5_STORAGE_PRINCIPAL_WRONG_NUM_COMPONENTS))
	ret = krb5_store_int32(sp, p->name.name_string.len + 1);
    else
	ret = krb5_store_int32(sp, p->name.name_string.len);

    if(ret) return ret;
    ret = krb5_store_string(sp, p->realm);
    if(ret) return ret;
    for(i = 0; i < p->name.name_string.len; i++){
	ret = krb5_store_string(sp, p->name.name_string.val[i]);
	if(ret) return ret;
    }
    return 0;
}

/**
 * Parse principal from the storage.
 *
 * @param sp the storage buffer to read from
 * @param princ the parsed principal
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_principal(krb5_storage *sp,
		   krb5_principal *princ)
{
    int i;
    int ret;
    krb5_principal p;
    int32_t type;
    int32_t ncomp;

    p = calloc(1, sizeof(*p));
    if(p == NULL)
	return ENOMEM;

    if(krb5_storage_is_flags(sp, KRB5_STORAGE_PRINCIPAL_NO_NAME_TYPE))
	type = KRB5_NT_UNKNOWN;
    else if((ret = krb5_ret_int32(sp, &type))){
	free(p);
	return ret;
    }
    if((ret = krb5_ret_int32(sp, &ncomp))){
	free(p);
	return ret;
    }
    if(krb5_storage_is_flags(sp, KRB5_STORAGE_PRINCIPAL_WRONG_NUM_COMPONENTS))
	ncomp--;
    if (ncomp < 0) {
	free(p);
	return EINVAL;
    }
    ret = size_too_large_num(sp, ncomp, sizeof(p->name.name_string.val[0]));
    if (ret) {
	free(p);
	return ret;
    }
    p->name.name_type = type;
    p->name.name_string.len = ncomp;
    ret = krb5_ret_string(sp, &p->realm);
    if(ret) {
	free(p);
	return ret;
    }
    p->name.name_string.val = calloc(ncomp, sizeof(p->name.name_string.val[0]));
    if(p->name.name_string.val == NULL && ncomp != 0){
	free(p->realm);
	free(p);
	return ENOMEM;
    }
    for(i = 0; i < ncomp; i++){
	ret = krb5_ret_string(sp, &p->name.name_string.val[i]);
	if(ret) {
	    while (i >= 0)
		free(p->name.name_string.val[i--]);
	    free(p->realm);
	    free(p);
	    return ret;
	}
    }
    *princ = p;
    return 0;
}

/**
 * Store a keyblock to the storage.
 *
 * @param sp the storage buffer to write to
 * @param p the keyblock to write
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_keyblock(krb5_storage *sp, krb5_keyblock p)
{
    int ret;
    ret = krb5_store_int16(sp, p.keytype);
    if(ret) return ret;

    if(krb5_storage_is_flags(sp, KRB5_STORAGE_KEYBLOCK_KEYTYPE_TWICE)){
	/* this should really be enctype, but it is the same as
           keytype nowadays */
    ret = krb5_store_int16(sp, p.keytype);
    if(ret) return ret;
    }

    ret = krb5_store_data(sp, p.keyvalue);
    return ret;
}

/**
 * Read a keyblock from the storage.
 *
 * @param sp the storage buffer to write to
 * @param p the keyblock read from storage, free using krb5_free_keyblock()
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_keyblock(krb5_storage *sp, krb5_keyblock *p)
{
    int ret;
    int16_t tmp;

    ret = krb5_ret_int16(sp, &tmp);
    if(ret) return ret;
    p->keytype = tmp;

    if(krb5_storage_is_flags(sp, KRB5_STORAGE_KEYBLOCK_KEYTYPE_TWICE)){
    ret = krb5_ret_int16(sp, &tmp);
    if(ret) return ret;
    }

    ret = krb5_ret_data(sp, &p->keyvalue);
    return ret;
}

/**
 * Write a times block to storage.
 *
 * @param sp the storage buffer to write to
 * @param times the times block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_times(krb5_storage *sp, krb5_times times)
{
    int ret;
    ret = krb5_store_int32(sp, times.authtime);
    if(ret) return ret;
    ret = krb5_store_int32(sp, times.starttime);
    if(ret) return ret;
    ret = krb5_store_int32(sp, times.endtime);
    if(ret) return ret;
    ret = krb5_store_int32(sp, times.renew_till);
    return ret;
}

/**
 * Read a times block from the storage.
 *
 * @param sp the storage buffer to write to
 * @param times the times block read from storage
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_times(krb5_storage *sp, krb5_times *times)
{
    int ret;
    int32_t tmp;

    ret = krb5_ret_int32(sp, &tmp);
    if (ret) return ret;
    times->authtime = tmp;
    ret = krb5_ret_int32(sp, &tmp);
    if (ret) return ret;
    times->starttime = tmp;
    ret = krb5_ret_int32(sp, &tmp);
    if (ret) return ret;
    times->endtime = tmp;
    ret = krb5_ret_int32(sp, &tmp);
    if (ret) return ret;
    times->renew_till = tmp;
    return ret;
}

/**
 * Write a address block to storage.
 *
 * @param sp the storage buffer to write to
 * @param p the address block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_address(krb5_storage *sp, krb5_address p)
{
    int ret;
    ret = krb5_store_int16(sp, p.addr_type);
    if(ret) return ret;
    ret = krb5_store_data(sp, p.address);
    return ret;
}

/**
 * Read a address block from the storage.
 *
 * @param sp the storage buffer to write to
 * @param adr the address block read from storage
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_address(krb5_storage *sp, krb5_address *adr)
{
    int16_t t;
    int ret;
    ret = krb5_ret_int16(sp, &t);
    if(ret) return ret;
    adr->addr_type = t;
    ret = krb5_ret_data(sp, &adr->address);
    return ret;
}

/**
 * Write a addresses block to storage.
 *
 * @param sp the storage buffer to write to
 * @param p the addresses block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_addrs(krb5_storage *sp, krb5_addresses p)
{
    size_t i;
    int ret;
    ret = krb5_store_int32(sp, p.len);
    if(ret) return ret;
    for(i = 0; i<p.len; i++){
	ret = krb5_store_address(sp, p.val[i]);
	if(ret) break;
    }
    return ret;
}

/**
 * Read a addresses block from the storage.
 *
 * @param sp the storage buffer to write to
 * @param adr the addresses block read from storage
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_addrs(krb5_storage *sp, krb5_addresses *adr)
{
    size_t i;
    int ret;
    int32_t tmp;

    ret = krb5_ret_int32(sp, &tmp);
    if(ret) return ret;
    ret = size_too_large_num(sp, tmp, sizeof(adr->val[0]));
    if (ret) return ret;
    adr->len = tmp;
    ALLOC(adr->val, adr->len);
    if (adr->val == NULL && adr->len != 0)
	return ENOMEM;
    for(i = 0; i < adr->len; i++){
	ret = krb5_ret_address(sp, &adr->val[i]);
	if(ret) break;
    }
    return ret;
}

/**
 * Write a auth data block to storage.
 *
 * @param sp the storage buffer to write to
 * @param auth the auth data block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_authdata(krb5_storage *sp, krb5_authdata auth)
{
    krb5_error_code ret;
    size_t i;
    ret = krb5_store_int32(sp, auth.len);
    if(ret) return ret;
    for(i = 0; i < auth.len; i++){
	ret = krb5_store_int16(sp, auth.val[i].ad_type);
	if(ret) break;
	ret = krb5_store_data(sp, auth.val[i].ad_data);
	if(ret) break;
    }
    return 0;
}

/**
 * Read a auth data from the storage.
 *
 * @param sp the storage buffer to write to
 * @param auth the auth data block read from storage
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_authdata(krb5_storage *sp, krb5_authdata *auth)
{
    krb5_error_code ret;
    int32_t tmp;
    int16_t tmp2;
    int i;
    ret = krb5_ret_int32(sp, &tmp);
    if(ret) return ret;
    ret = size_too_large_num(sp, tmp, sizeof(auth->val[0]));
    if (ret) return ret;
    ALLOC_SEQ(auth, tmp);
    if (auth->val == NULL && tmp != 0)
	return ENOMEM;
    for(i = 0; i < tmp; i++){
	ret = krb5_ret_int16(sp, &tmp2);
	if(ret) break;
	auth->val[i].ad_type = tmp2;
	ret = krb5_ret_data(sp, &auth->val[i].ad_data);
	if(ret) break;
    }
    return ret;
}

static int32_t
bitswap32(int32_t b)
{
    int32_t r = 0;
    int i;
    for (i = 0; i < 32; i++) {
	r = r << 1 | (b & 1);
	b = b >> 1;
    }
    return r;
}

/**
 * Write a credentials block to storage.
 *
 * @param sp the storage buffer to write to
 * @param creds the creds block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_creds(krb5_storage *sp, krb5_creds *creds)
{
    int ret;

    ret = krb5_store_principal(sp, creds->client);
    if(ret)
	return ret;
    ret = krb5_store_principal(sp, creds->server);
    if(ret)
	return ret;
    ret = krb5_store_keyblock(sp, creds->session);
    if(ret)
	return ret;
    ret = krb5_store_times(sp, creds->times);
    if(ret)
	return ret;
    ret = krb5_store_int8(sp, creds->second_ticket.length != 0); /* is_skey */
    if(ret)
	return ret;
    ret = krb5_store_int32(sp, bitswap32(TicketFlags2int(creds->flags.b)));
    if(ret)
	return ret;
    ret = krb5_store_addrs(sp, creds->addresses);
    if(ret)
	return ret;
    ret = krb5_store_authdata(sp, creds->authdata);
    if(ret)
	return ret;
    ret = krb5_store_data(sp, creds->ticket);
    if(ret)
	return ret;
    ret = krb5_store_data(sp, creds->second_ticket);
    return ret;
}

/**
 * Read a credentials block from the storage.
 *
 * @param sp the storage buffer to write to
 * @param creds the credentials block read from storage
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_creds(krb5_storage *sp, krb5_creds *creds)
{
    krb5_error_code ret;
    int8_t dummy8;
    int32_t dummy32;

    memset(creds, 0, sizeof(*creds));
    ret = krb5_ret_principal (sp,  &creds->client);
    if(ret) goto cleanup;
    ret = krb5_ret_principal (sp,  &creds->server);
    if(ret) goto cleanup;
    ret = krb5_ret_keyblock (sp,  &creds->session);
    if(ret) goto cleanup;
    ret = krb5_ret_times (sp,  &creds->times);
    if(ret) goto cleanup;
    ret = krb5_ret_int8 (sp,  &dummy8);
    if(ret) goto cleanup;
    ret = krb5_ret_int32 (sp,  &dummy32);
    if(ret) goto cleanup;
    creds->flags.b = int2TicketFlags(bitswap32(dummy32));
    ret = krb5_ret_addrs (sp,  &creds->addresses);
    if(ret) goto cleanup;
    ret = krb5_ret_authdata (sp,  &creds->authdata);
    if(ret) goto cleanup;
    ret = krb5_ret_data (sp,  &creds->ticket);
    if(ret) goto cleanup;
    ret = krb5_ret_data (sp,  &creds->second_ticket);
cleanup:
    if(ret) {
#if 0
	krb5_free_cred_contents(context, creds); /* XXX */
#endif
    }
    return ret;
}

#define SC_CLIENT_PRINCIPAL	    0x0001
#define SC_SERVER_PRINCIPAL	    0x0002
#define SC_SESSION_KEY		    0x0004
#define SC_TICKET		    0x0008
#define SC_SECOND_TICKET	    0x0010
#define SC_AUTHDATA		    0x0020
#define SC_ADDRESSES		    0x0040

/**
 * Write a tagged credentials block to storage.
 *
 * @param sp the storage buffer to write to
 * @param creds the creds block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_creds_tag(krb5_storage *sp, krb5_creds *creds)
{
    int ret;
    int32_t header = 0;

    if (creds->client)
	header |= SC_CLIENT_PRINCIPAL;
    if (creds->server)
	header |= SC_SERVER_PRINCIPAL;
    if (creds->session.keytype != ETYPE_NULL)
	header |= SC_SESSION_KEY;
    if (creds->ticket.data)
	header |= SC_TICKET;
    if (creds->second_ticket.length)
	header |= SC_SECOND_TICKET;
    if (creds->authdata.len)
	header |= SC_AUTHDATA;
    if (creds->addresses.len)
	header |= SC_ADDRESSES;

    ret = krb5_store_int32(sp, header);
    if (ret)
	return ret;

    if (creds->client) {
	ret = krb5_store_principal(sp, creds->client);
	if(ret)
	    return ret;
    }

    if (creds->server) {
	ret = krb5_store_principal(sp, creds->server);
	if(ret)
	    return ret;
    }

    if (creds->session.keytype != ETYPE_NULL) {
	ret = krb5_store_keyblock(sp, creds->session);
	if(ret)
	    return ret;
    }

    ret = krb5_store_times(sp, creds->times);
    if(ret)
	return ret;
    ret = krb5_store_int8(sp, creds->second_ticket.length != 0); /* is_skey */
    if(ret)
	return ret;

    ret = krb5_store_int32(sp, bitswap32(TicketFlags2int(creds->flags.b)));
    if(ret)
	return ret;

    if (creds->addresses.len) {
	ret = krb5_store_addrs(sp, creds->addresses);
	if(ret)
	    return ret;
    }

    if (creds->authdata.len) {
	ret = krb5_store_authdata(sp, creds->authdata);
	if(ret)
	    return ret;
    }

    if (creds->ticket.data) {
	ret = krb5_store_data(sp, creds->ticket);
	if(ret)
	    return ret;
    }

    if (creds->second_ticket.data) {
	ret = krb5_store_data(sp, creds->second_ticket);
	if (ret)
	    return ret;
    }

    return ret;
}

/**
 * Read a tagged credentials block from the storage.
 *
 * @param sp the storage buffer to write to
 * @param creds the credentials block read from storage
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_creds_tag(krb5_storage *sp,
		   krb5_creds *creds)
{
    krb5_error_code ret;
    int8_t dummy8;
    int32_t dummy32, header;

    memset(creds, 0, sizeof(*creds));

    ret = krb5_ret_int32 (sp, &header);
    if (ret) goto cleanup;

    if (header & SC_CLIENT_PRINCIPAL) {
	ret = krb5_ret_principal (sp,  &creds->client);
	if(ret) goto cleanup;
    }
    if (header & SC_SERVER_PRINCIPAL) {
	ret = krb5_ret_principal (sp,  &creds->server);
	if(ret) goto cleanup;
    }
    if (header & SC_SESSION_KEY) {
	ret = krb5_ret_keyblock (sp,  &creds->session);
	if(ret) goto cleanup;
    }
    ret = krb5_ret_times (sp,  &creds->times);
    if(ret) goto cleanup;
    ret = krb5_ret_int8 (sp,  &dummy8);
    if(ret) goto cleanup;
    ret = krb5_ret_int32 (sp,  &dummy32);
    if(ret) goto cleanup;
    creds->flags.b = int2TicketFlags(bitswap32(dummy32));
    if (header & SC_ADDRESSES) {
	ret = krb5_ret_addrs (sp,  &creds->addresses);
	if(ret) goto cleanup;
    }
    if (header & SC_AUTHDATA) {
	ret = krb5_ret_authdata (sp,  &creds->authdata);
	if(ret) goto cleanup;
    }
    if (header & SC_TICKET) {
	ret = krb5_ret_data (sp,  &creds->ticket);
	if(ret) goto cleanup;
    }
    if (header & SC_SECOND_TICKET) {
	ret = krb5_ret_data (sp,  &creds->second_ticket);
	if(ret) goto cleanup;
    }

cleanup:
    if(ret) {
#if 0
	krb5_free_cred_contents(context, creds); /* XXX */
#endif
    }
    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_ret_data_at_offset(krb5_storage *sp,
			 size_t offset,
			 size_t length,
			 krb5_data *data)
{
    krb5_error_code ret;
    off_t cur, size;

    krb5_data_zero(data);

    cur = sp->seek(sp, 0, SEEK_CUR);
    if (cur < 0)
	return HEIM_ERR_NOT_SEEKABLE;

    size = sp->seek(sp, 0, SEEK_END);
    if (offset + length > size) {
	ret = ERANGE;
	goto cleanup;
    }

    ret = krb5_data_alloc(data, length);
    if (ret)
	goto cleanup;

    if (length) {
	sp->seek(sp, offset, SEEK_SET);

	size = sp->fetch(sp, data->data, length);
        if (size < 0 || (size_t)size != length)
            return sp->eof_code;
    }

cleanup:
    sp->seek(sp, cur, SEEK_SET);

    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_ret_utf8_from_ucs2le_at_offset(krb5_storage *sp,
				     off_t offset,
				     size_t length,
				     char **utf8)
{
    krb5_error_code ret;
    krb5_data data;
    size_t ucs2len = length / 2;
    uint16_t *ucs2 = NULL;
    size_t u8len;
    unsigned int flags = WIND_RW_LE;

    *utf8 = NULL;

    krb5_data_zero(&data);

    ret = _krb5_ret_data_at_offset(sp, offset, length, &data);
    if (ret)
	goto out;

    ucs2 = malloc(sizeof(ucs2[0]) * ucs2len);
    if (ucs2 == NULL) {
	ret = ENOMEM;
	goto out;
    }

    ret = wind_ucs2read(data.data, data.length, &flags, ucs2, &ucs2len);
    if (ret)
	goto out;

    ret = wind_ucs2utf8_length(ucs2, ucs2len, &u8len);
    if (ret)
	goto out;

    u8len += 1; /* Add space for NUL */

    *utf8 = malloc(u8len);
    if (*utf8 == NULL) {
	ret = ENOMEM;
	goto out;
    }

    ret = wind_ucs2utf8(ucs2, ucs2len, *utf8, &u8len);
    if (ret)
	goto out;

out:
    if (ret && *utf8) {
	free(*utf8);
	*utf8 = NULL;
    }
    free(ucs2);
    krb5_data_free(&data);

    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_store_data_at_offset(krb5_storage *sp,
			   size_t offset,
			   const krb5_data *data)
{
    krb5_error_code ret;
    krb5_ssize_t nbytes;
    off_t pos;

    if (offset == (size_t)-1) {
	if (data == NULL || data->data == NULL) {
	    offset = 0;
	} else {
	    pos = sp->seek(sp, 0, SEEK_CUR);
	    offset = sp->seek(sp, 0, SEEK_END);
	    sp->seek(sp, pos, SEEK_SET);

	    if (offset == (size_t)-1)
		return HEIM_ERR_NOT_SEEKABLE;
	}
    }

    if (offset > 0xFFFF)
	return ERANGE;
    else if ((offset != 0) != (data && data->data))
	return EINVAL;
    else if (data && data->length > 0xFFFF)
	return ERANGE;

    ret = krb5_store_uint16(sp, data ? (uint16_t)data->length : 0);
    if (ret == 0)
	ret = krb5_store_uint16(sp, (uint16_t)offset);
    if (ret == 0 && offset) {
	pos = sp->seek(sp, 0, SEEK_CUR);
	sp->seek(sp, offset, SEEK_SET);
	nbytes = krb5_storage_write(sp, data->data, data->length);
	if ((size_t)nbytes != data->length)
	    ret = sp->eof_code;
	sp->seek(sp, pos, SEEK_SET);
    }

    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_store_utf8_as_ucs2le_at_offset(krb5_storage *sp,
				     off_t offset,
				     const char *utf8)
{
    krb5_error_code ret;
    size_t ucs2_len, ucs2le_size;
    uint16_t *ucs2, *ucs2le;
    unsigned int flags;

    if (utf8) {
	ret = wind_utf8ucs2_length(utf8, &ucs2_len);
	if (ret)
	    return ret;

	ucs2 = malloc(sizeof(ucs2[0]) * ucs2_len);
	if (ucs2 == NULL)
	    return ENOMEM;

	ret = wind_utf8ucs2(utf8, ucs2, &ucs2_len);
	if (ret) {
	    free(ucs2);
	    return ret;
	}

	ucs2le_size = (ucs2_len + 1) * 2;
	ucs2le = malloc(ucs2le_size);
	    if (ucs2le == NULL) {
		free(ucs2);
		return ENOMEM;
	}

	flags = WIND_RW_LE;
	ret = wind_ucs2write(ucs2, ucs2_len, &flags, ucs2le, &ucs2le_size);
	free(ucs2);
	if (ret) {
	    free(ucs2le);
	    return ret;
	}

	ucs2le_size = ucs2_len * 2;
    } else {
	ucs2le = NULL;
	ucs2le_size = 0;
	offset = 0;
    }

    {
	krb5_data data;

	data.data = ucs2le;
	data.length = ucs2le_size;

	ret = _krb5_store_data_at_offset(sp, offset, &data);
    }

    free(ucs2le);

    return ret;
}
