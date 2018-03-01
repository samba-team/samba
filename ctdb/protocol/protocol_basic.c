/*
   CTDB protocol marshalling

   Copyright (C) Amitay Isaacs  2015-2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"

#include <talloc.h>

#include "protocol_basic.h"

/*
 * Basic data types
 */

size_t ctdb_uint8_len(uint8_t *in)
{
	return sizeof(uint8_t);
}

void ctdb_uint8_push(uint8_t *in, uint8_t *buf, size_t *npush)
{
	*buf = *in;
	*npush = sizeof(uint8_t);
}

int ctdb_uint8_pull(uint8_t *buf, size_t buflen, uint8_t *out, size_t *npull)
{
	if (buflen < sizeof(uint8_t)) {
		return EMSGSIZE;
	}

	*out = *buf;
	*npull = sizeof(uint8_t);
	return 0;
}

size_t ctdb_uint16_len(uint16_t *in)
{
	return sizeof(uint16_t);
}

void ctdb_uint16_push(uint16_t *in, uint8_t *buf, size_t *npush)
{
	memcpy(buf, in, sizeof(uint16_t));
	*npush = sizeof(uint16_t);
}

int ctdb_uint16_pull(uint8_t *buf, size_t buflen, uint16_t *out, size_t *npull)
{
	if (buflen < sizeof(uint16_t)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(uint16_t));
	*npull = sizeof(uint16_t);
	return 0;
}

size_t ctdb_int32_len(int32_t *in)
{
	return sizeof(int32_t);
}

void ctdb_int32_push(int32_t *in, uint8_t *buf, size_t *npush)
{
	memcpy(buf, in, sizeof(int32_t));
	*npush = sizeof(int32_t);
}

int ctdb_int32_pull(uint8_t *buf, size_t buflen, int32_t *out, size_t *npull)
{
	if (buflen < sizeof(int32_t)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(int32_t));
	*npull = sizeof(int32_t);
	return 0;
}

size_t ctdb_uint32_len(uint32_t *in)
{
	return sizeof(uint32_t);
}

void ctdb_uint32_push(uint32_t *in, uint8_t *buf, size_t *npush)
{
	memcpy(buf, in, sizeof(uint32_t));
	*npush = sizeof(uint32_t);
}

int ctdb_uint32_pull(uint8_t *buf, size_t buflen, uint32_t *out, size_t *npull)
{
	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(uint32_t));
	*npull = sizeof(uint32_t);
	return 0;
}

size_t ctdb_uint64_len(uint64_t *in)
{
	return sizeof(uint64_t);
}

void ctdb_uint64_push(uint64_t *in, uint8_t *buf, size_t *npush)
{
	memcpy(buf, in, sizeof(uint64_t));
	*npush = sizeof(uint64_t);
}

int ctdb_uint64_pull(uint8_t *buf, size_t buflen, uint64_t *out, size_t *npull)
{
	if (buflen < sizeof(uint64_t)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(uint64_t));
	*npull = sizeof(uint64_t);
	return 0;
}

size_t ctdb_double_len(double *in)
{
	return sizeof(double);
}

void ctdb_double_push(double *in, uint8_t *buf, size_t *npush)
{
	memcpy(buf, in, sizeof(double));
	*npush = sizeof(double);
}

int ctdb_double_pull(uint8_t *buf, size_t buflen, double *out, size_t *npull)
{
	if (buflen < sizeof(double)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(double));
	*npull = sizeof(double);
	return 0;
}

size_t ctdb_bool_len(bool *in)
{
	uint8_t u8 = *in;

	return ctdb_uint8_len(&u8);
}

void ctdb_bool_push(bool *in, uint8_t *buf, size_t *npush)
{
	size_t np;
	uint8_t u8 = *in;

	ctdb_uint8_push(&u8, buf, &np);
	*npush = np;
}

int ctdb_bool_pull(uint8_t *buf, size_t buflen, bool *out, size_t *npull)
{
	size_t np;
	uint8_t u8;
	int ret;

	ret = ctdb_uint8_pull(buf, buflen, &u8, &np);
	if (ret != 0) {
		return ret;
	}

	if (u8 == 0) {
		*out = false;
	} else if (u8 == 1) {
		*out = true;
	} else {
		return EINVAL;
	}

	*npull = np;
	return 0;
}

size_t ctdb_chararray_len(char *in, size_t len)
{
	return len;
}

void ctdb_chararray_push(char *in, size_t len, uint8_t *buf, size_t *npush)
{
	memcpy(buf, in, len);
	*npush = len;
}

int ctdb_chararray_pull(uint8_t *buf, size_t buflen, char *out, size_t len,
			size_t *npull)
{
	if (buflen < len) {
		return EMSGSIZE;
	}

	memcpy(out, buf, len);
	out[len-1] = '\0';
	*npull = len;
	return 0;
}

size_t ctdb_string_len(const char **in)
{
	if (*in == NULL) {
		return 0;
	}

	return strlen(*in) + 1;
}

void ctdb_string_push(const char **in, uint8_t *buf, size_t *npush)
{
	size_t len;

	len = ctdb_string_len(in);
	if (len > 0) {
		memcpy(buf, *in, len);
	}

	*npush = len;
}

int ctdb_string_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     const char **out, size_t *npull)
{
	const char *str;

	if (buflen > UINT32_MAX) {
		return EMSGSIZE;
	}

	if (buflen == 0) {
		*out = NULL;
		*npull = 0;
		return 0;
	}

	str = talloc_strndup(mem_ctx, (char *)buf, buflen);
	if (str == NULL) {
		return ENOMEM;
	}

	*out = str;
	*npull = ctdb_string_len(&str);
	return 0;
}

size_t ctdb_stringn_len(const char **in)
{
	uint32_t u32 = ctdb_string_len(in);

	return ctdb_uint32_len(&u32) + u32;
}

void ctdb_stringn_push(const char **in, uint8_t *buf, size_t *npush)
{
	size_t offset = 0, np;
	uint32_t u32 = ctdb_string_len(in);

	ctdb_uint32_push(&u32, buf+offset, &np);
	offset += np;

	ctdb_string_push(in, buf+offset, &np);
	offset += np;

	*npush = offset;
}

int ctdb_stringn_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      const char **out, size_t *npull)
{
	size_t offset = 0, np;
	uint32_t u32;
	int ret;

	ret = ctdb_uint32_pull(buf+offset, buflen-offset, &u32, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	if (buflen-offset < u32) {
		return EMSGSIZE;
	}

	ret = ctdb_string_pull(buf+offset, u32, mem_ctx, out, &np);
	if (ret != 0) {
		return ret;
	}
	offset += np;

	*npull = offset;
	return 0;
}

/*
 * System defined data types
 */

size_t ctdb_pid_len(pid_t *in)
{
	return sizeof(pid_t);
}

void ctdb_pid_push(pid_t *in, uint8_t *buf, size_t *npush)
{
	memcpy(buf, in, sizeof(pid_t));
	*npush = sizeof(pid_t);
}

int ctdb_pid_pull(uint8_t *buf, size_t buflen, pid_t *out, size_t *npull)
{
	if (buflen < sizeof(pid_t)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(pid_t));
	*npull = sizeof(pid_t);
	return 0;
}

size_t ctdb_timeval_len(struct timeval *in)
{
	return sizeof(struct timeval);
}

void ctdb_timeval_push(struct timeval *in, uint8_t *buf, size_t *npush)
{
	memcpy(buf, in, sizeof(struct timeval));
	*npush = sizeof(struct timeval);
}

int ctdb_timeval_pull(uint8_t *buf, size_t buflen, struct timeval *out,
		      size_t *npull)
{
	if (buflen < sizeof(struct timeval)) {
		return EMSGSIZE;
	}

	memcpy(out, buf, sizeof(struct timeval));
	*npull = sizeof(struct timeval);
	return 0;
}

/*
 * Dummy type to tackle structure padding
 */

size_t ctdb_padding_len(int count)
{
	return count % SIZEOF_VOID_P;
}

void ctdb_padding_push(int count, uint8_t *buf, size_t *npush)
{
	uint8_t padding[count];
	size_t aligned_count = count % SIZEOF_VOID_P;

	if (aligned_count > 0) {
		memset(padding, 0, aligned_count);
		memcpy(buf, padding, aligned_count);
	}
	*npush = aligned_count;
}

int ctdb_padding_pull(uint8_t *buf, size_t buflen, int count, size_t *npull)
{
	size_t aligned_count = count % SIZEOF_VOID_P;

	if (buflen < aligned_count) {
		return EMSGSIZE;
	}

	*npull = aligned_count;
	return 0;
}
