/*
   CTDB protocol marshalling

   Copyright (C) Amitay Isaacs  2018

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

#ifndef __PROTOCOL_BASIC_H__
#define __PROTOCOL_BASIC_H__

/*
 * From protocol/protocol_basic.c
 */

size_t ctdb_uint8_len(uint8_t *in);
void ctdb_uint8_push(uint8_t *in, uint8_t *buf, size_t *npush);
int ctdb_uint8_pull(uint8_t *buf, size_t buflen, uint8_t *out, size_t *npull);

size_t ctdb_uint16_len(uint16_t *in);
void ctdb_uint16_push(uint16_t *in, uint8_t *buf, size_t *npush);
int ctdb_uint16_pull(uint8_t *buf, size_t buflen, uint16_t *out,
		     size_t *npull);

size_t ctdb_int32_len(int32_t *in);
void ctdb_int32_push(int32_t *in, uint8_t *buf, size_t *npush);
int ctdb_int32_pull(uint8_t *buf, size_t buflen, int32_t *out, size_t *npull);

size_t ctdb_uint32_len(uint32_t *in);
void ctdb_uint32_push(uint32_t *in, uint8_t *buf, size_t *npush);
int ctdb_uint32_pull(uint8_t *buf, size_t buflen, uint32_t *out,
		     size_t *npull);

size_t ctdb_uint64_len(uint64_t *in);
void ctdb_uint64_push(uint64_t *in, uint8_t *buf, size_t *npush);
int ctdb_uint64_pull(uint8_t *buf, size_t buflen, uint64_t *out,
		     size_t *npull);

size_t ctdb_double_len(double *in);
void ctdb_double_push(double *in, uint8_t *buf, size_t *npush);
int ctdb_double_pull(uint8_t *buf, size_t buflen, double *out, size_t *npull);

size_t ctdb_bool_len(bool *in);
void ctdb_bool_push(bool *in, uint8_t *buf, size_t *npush);
int ctdb_bool_pull(uint8_t *buf, size_t buflen, bool *out, size_t *npull);

size_t ctdb_chararray_len(char *in, size_t len);
void ctdb_chararray_push(char *in, size_t len, uint8_t *buf, size_t *npush);
int ctdb_chararray_pull(uint8_t *buf, size_t buflen, char *out, size_t len,
			size_t *npull);

size_t ctdb_string_len(const char **in);
void ctdb_string_push(const char **in, uint8_t *buf, size_t *npush);
int ctdb_string_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		     const char **out, size_t *npull);

size_t ctdb_stringn_len(const char **in);
void ctdb_stringn_push(const char **in, uint8_t *buf, size_t *npush);
int ctdb_stringn_pull(uint8_t *buf, size_t buflen, TALLOC_CTX *mem_ctx,
		      const char **out, size_t *npull);

size_t ctdb_pid_len(pid_t *in);
void ctdb_pid_push(pid_t *in, uint8_t *buf, size_t *npush);
int ctdb_pid_pull(uint8_t *buf, size_t buflen, pid_t *out, size_t *npull);

size_t ctdb_timeval_len(struct timeval *in);
void ctdb_timeval_push(struct timeval *in, uint8_t *buf, size_t *npush);
int ctdb_timeval_pull(uint8_t *buf, size_t buflen, struct timeval *out,
		      size_t *npull);

size_t ctdb_padding_len(int count);
void ctdb_padding_push(int count, uint8_t *buf, size_t *npush);
int ctdb_padding_pull(uint8_t *buf, size_t buflen, int count, size_t *npull);

#endif /* __PROTOCOL_BASIC_H__ */
