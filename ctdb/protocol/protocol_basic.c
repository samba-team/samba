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
#include <tdb.h>

#include "protocol.h"
#include "protocol_private.h"

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

size_t ctdb_int32_len(int32_t val)
{
	return sizeof(int32_t);
}

void ctdb_int32_push(int32_t val, uint8_t *buf)
{
	memcpy(buf, &val, sizeof(int32_t));
}

int ctdb_int32_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		    int32_t *out)
{
	if (buflen < sizeof(int32_t)) {
		return EMSGSIZE;
	}

	*out = *(int32_t *)buf;
	return 0;
}

size_t ctdb_uint32_len(uint32_t val)
{
	return sizeof(uint32_t);
}

void ctdb_uint32_push(uint32_t val, uint8_t *buf)
{
	memcpy(buf, &val, sizeof(uint32_t));
}

int ctdb_uint32_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     uint32_t *out)
{
	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}

	*out = *(uint32_t *)buf;
	return 0;
}

size_t ctdb_uint64_len(uint64_t val)
{
	return sizeof(uint64_t);
}

void ctdb_uint64_push(uint64_t val, uint8_t *buf)
{
	memcpy(buf, &val, sizeof(uint64_t));
}

int ctdb_uint64_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     uint64_t *out)
{
	if (buflen < sizeof(uint64_t)) {
		return EMSGSIZE;
	}

	*out = *(uint64_t *)buf;
	return 0;
}

size_t ctdb_double_len(double val)
{
	return sizeof(double);
}

void ctdb_double_push(double val, uint8_t *buf)
{
	memcpy(buf, &val, sizeof(double));
}

int ctdb_double_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     double *out)
{
	if (buflen < sizeof(double)) {
		return EMSGSIZE;
	}

	*out = *(double *)buf;
	return 0;
}

size_t ctdb_string_len(const char *str)
{
	if (str == NULL) {
		return 0;
	}
	return strlen(str) + 1;
}

void ctdb_string_push(const char *str, uint8_t *buf)
{
	if (str == NULL) {
		return;
	}
	memcpy(buf, str, strlen(str)+1);
}

int ctdb_string_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     const char **out)
{
	char *str;

	if (buflen == 0) {
		*out = NULL;
		return 0;
	}

	str = talloc_strndup(mem_ctx, (char *)buf, buflen);
	if (str == NULL) {
		return ENOMEM;
	}

	*out = str;
	return 0;
}

struct stringn_wire {
	uint32_t length;
	uint8_t str[1];
};

size_t ctdb_stringn_len(const char *str)
{
	return sizeof(uint32_t) + ctdb_string_len(str);
}

void ctdb_stringn_push(const char *str, uint8_t *buf)
{
	struct stringn_wire *wire = (struct stringn_wire *)buf;

	wire->length = ctdb_string_len(str);
	ctdb_string_push(str, wire->str);
}

int ctdb_stringn_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      const char **out)
{
	char *str;
	struct stringn_wire *wire = (struct stringn_wire *)buf;

	if (buflen < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (wire->length > buflen) {
		return EMSGSIZE;
	}
	if (sizeof(uint32_t) + wire->length < sizeof(uint32_t)) {
		return EMSGSIZE;
	}
	if (buflen < sizeof(uint32_t) + wire->length) {
		return EMSGSIZE;
	}

	if (wire->length == 0) {
		*out = NULL;
		return 0;
	}

	str = talloc_strndup(mem_ctx, (char *)wire->str, wire->length);
	if (str == NULL) {
		return ENOMEM;
	}

	*out = str;
	return 0;
}

/*
 * System defined data types
 */

size_t ctdb_pid_len(pid_t pid)
{
	return sizeof(pid_t);
}

void ctdb_pid_push(pid_t pid, uint8_t *buf)
{
	memcpy(buf, &pid, sizeof(pid_t));
}

int ctdb_pid_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		  pid_t *out)
{
	if (buflen < sizeof(pid_t)) {
		return EMSGSIZE;
	}

	*out = *(pid_t *)buf;
	return 0;
}
