/*
 * Unix SMB/CIFS implementation.
 *
 * Helpers around tevent_req_profile
 *
 * Copyright (C) Volker Lendecke 2018
 *
 *   ** NOTE! The following LGPL license applies to the tevent
 *   ** library. This does NOT imply that all of Samba is released
 *   ** under the LGPL
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include <tevent.h>
#include "lib/util/tevent_req_profile.h"
#include "lib/util/time_basic.h"
#include "lib/util/memory.h"

static bool tevent_req_profile_string_internal(
	const struct tevent_req_profile *profile,
	unsigned indent,
	unsigned max_indent,
	char **string)
{
	struct timeval start, stop, diff;
	struct timeval_buf start_buf, stop_buf;
	const char *req_name = NULL;
	const char *start_location = NULL;
	const char *stop_location = NULL;
	pid_t pid;
	enum tevent_req_state state;
	const char *state_buf = NULL;
	uint64_t user_error;
	const struct tevent_req_profile *sub = NULL;
	char *result;

	tevent_req_profile_get_name(profile, &req_name);

	tevent_req_profile_get_start(profile, &start_location, &start);
	timeval_str_buf(&start, false, true, &start_buf);

	tevent_req_profile_get_stop(profile, &stop_location, &stop);
	timeval_str_buf(&stop, false, true, &stop_buf);

	diff = tevent_timeval_until(&start, &stop);

	tevent_req_profile_get_status(profile, &pid, &state, &user_error);

	switch(state) {
	case TEVENT_REQ_INIT:
		state_buf = "TEVENT_REQ_INIT";
		break;
	case TEVENT_REQ_IN_PROGRESS:
		state_buf = "TEVENT_REQ_IN_PROGRESS";
		break;
	case TEVENT_REQ_DONE:
		state_buf = "TEVENT_REQ_DONE";
		break;
	case TEVENT_REQ_USER_ERROR:
		state_buf = "TEVENT_REQ_USER_ERROR";
		break;
	case TEVENT_REQ_TIMED_OUT:
		state_buf = "TEVENT_REQ_TIMED_OUT";
		break;
	case TEVENT_REQ_NO_MEMORY:
		state_buf = "TEVENT_REQ_NO_MEMORY";
		break;
	case TEVENT_REQ_RECEIVED:
		state_buf = "TEVENT_REQ_RECEIVED";
		break;
	default:
		state_buf = "unknown";
		break;
	}

	result = talloc_asprintf_append_buffer(
		*string,
		"%*s[%s] %s [%s] %s [%s] [%ju.%.6ju] -> %s (%d %"PRIu64"))\n",
		indent,
		"",
		req_name,
		start_location,
		start_buf.buf,
		stop_location,
		stop_buf.buf,
		(uintmax_t)diff.tv_sec,
		(uintmax_t)diff.tv_usec,
		state_buf,
		(int)state,
		user_error);
	if (result == NULL) {
		return false;
	}
	*string = result;

	indent += 1;

	if (indent >= max_indent) {
		return true;
	}

	for (sub = tevent_req_profile_get_subprofiles(profile);
	     sub != NULL;
	     sub = tevent_req_profile_next(sub)) {
		bool ret;

		ret = tevent_req_profile_string_internal(
			sub,
			indent,
			max_indent,
			string);
		if (!ret) {
			return false;
		}
	}

	return true;
}

char *tevent_req_profile_string(TALLOC_CTX *mem_ctx,
				const struct tevent_req_profile *profile,
				unsigned indent,
				unsigned max_indent)
{
	char *result;
	bool ret;

	result = talloc_strdup(mem_ctx, "");
	if (result == NULL) {
		return NULL;
	}

	ret = tevent_req_profile_string_internal(
		profile,
		indent,
		max_indent,
		&result);
	if (!ret) {
		TALLOC_FREE(result);
		return NULL;
	}

	return result;
}

static ssize_t tevent_req_profile_pack_one(
	const struct tevent_req_profile *profile,
	uint8_t *buf,
	size_t buflen)
{
	const char *req_name = NULL;
	const char *start_location = NULL;
	const char *stop_location = NULL;
	struct timeval start_time, stop_time;
	pid_t pid;
	enum tevent_req_state state;
	uint64_t user_error;
	size_t pack_len, len;
	int ret;

	tevent_req_profile_get_name(profile, &req_name);
	tevent_req_profile_get_start(profile, &start_location, &start_time);
	tevent_req_profile_get_stop(profile, &stop_location, &stop_time);
	tevent_req_profile_get_status(profile, &pid, &state, &user_error);

	len = strlen(req_name)+1;
	if (buflen >= len) {
		memcpy(buf, req_name, len);
		buf += len;
		buflen -= len;
	}

	pack_len = len;

	len = strlen(start_location)+1;
	pack_len += len;
	if (pack_len < len) {
		return -1;	/* overflow */
	}

	if (buflen >= len) {
		memcpy(buf, start_location, len);
		buf += len;
		buflen -= len;
	}

	len = strlen(stop_location)+1;
	pack_len += len;
	if (pack_len < len) {
		return -1;	/* overflow */
	}

	if (buflen >= len) {
		memcpy(buf, stop_location, len);
		buf += len;
		buflen -= len;
	}

	ret = snprintf((char *)buf,
		       buflen,
		       "%ju %ju %ju %ju %d %d %"PRIu64"",
		       (uintmax_t)start_time.tv_sec,
		       (uintmax_t)start_time.tv_usec,
		       (uintmax_t)stop_time.tv_sec,
		       (uintmax_t)stop_time.tv_usec,
		       (int)pid,
		       (int)state,
		       user_error);
	if (ret < 0) {
		return -1;
	}

	/*
	 * Take care of the trailing 0. No overflow check, this would
	 * be a VERY small number of bits for "int".
	 */
	ret += 1;

	pack_len += ret;

	return pack_len;
}

ssize_t tevent_req_profile_pack(
	const struct tevent_req_profile *profile,
	uint8_t *buf,
	size_t buflen)
{
	const struct tevent_req_profile *sub = NULL;
	size_t num_sub;
	ssize_t pack_len, profile_len;
	int ret;

	num_sub = 0;
	pack_len = 0;

	for (sub = tevent_req_profile_get_subprofiles(profile);
	     sub != NULL;
	     sub = tevent_req_profile_next(sub)) {
		num_sub += 1;
	}

	ret = snprintf((char *)buf, buflen, "%zu ", num_sub);
	if (ret < 0) {
		return -1;
	}

	if (buflen > (size_t)ret) {
		buf += ret;
		buflen -= ret;
	}

	pack_len = ret;

	profile_len = tevent_req_profile_pack_one(profile, buf, buflen);
	if (profile_len == -1) {
		return -1;
	}

	if (buflen >= (size_t)profile_len) {
		buf += profile_len;
		buflen -= profile_len;
	}

	pack_len += profile_len;
	if (pack_len < profile_len) {
		return -1;	/* overflow */
	}

	for (sub = tevent_req_profile_get_subprofiles(profile);
	     sub != NULL;
	     sub = tevent_req_profile_next(sub)) {

		profile_len = tevent_req_profile_pack(sub, buf, buflen);
		if (profile_len == -1) {
			return -1;
		}

		if (buflen >= (size_t)profile_len) {
			buf += profile_len;
			buflen -= profile_len;
		}

		pack_len += profile_len;
		if (pack_len < profile_len) {
			return -1;	/* overflow */
		}
	}

	return pack_len;
}

static bool parse_uintmax(const char *buf,
			  char delimiter,
			  uintmax_t *presult,
			  char **p_endptr)
{
	uintmax_t result;
	char *endptr;

	result = strtoumax(buf, &endptr, 10);
	if ((result == UINTMAX_MAX) && (errno == ERANGE)) {
		return false;
	}
	if (*endptr != delimiter) {
		return false;
	}

	*presult = result;
	*p_endptr = endptr+1;

	return true;
}

static ssize_t tevent_req_profile_unpack_one(
	const uint8_t *buf,
	size_t buflen,
	struct tevent_req_profile *profile)
{
	const char *orig_buf = (const char *)buf;
	const char *req_name = NULL;
	const char *start_location = NULL;
	const char *stop_location = NULL;
	uintmax_t start_sec, start_usec, stop_sec, stop_usec, pid, state;
	uintmax_t user_error;
	char *next = NULL;
	size_t len;
	bool ok;

	if (buflen == 0) {
		return -1;
	}
	if (buf[buflen-1] != '\0') {
		return -1;
	}

	req_name = (const char *)buf;
	len = strlen(req_name)+1;

	buf += len;
	buflen -= len;
	if (buflen == 0) {
		return -1;
	}

	start_location = (const char *)buf;
	len = strlen(start_location)+1;

	buf += len;
	buflen -= len;
	if (buflen == 0) {
		return -1;
	}

	stop_location = (const char *)buf;
	len = strlen(stop_location)+1;

	buf += len;
	buflen -= len;
	if (buflen == 0) {
		return -1;
	}

	ok = parse_uintmax((const char *)buf, ' ', &start_sec, &next);
	if (!ok) {
		return -1;
	}

	ok = parse_uintmax(next, ' ', &start_usec, &next);
	if (!ok) {
		return -1;
	}

	ok = parse_uintmax(next, ' ', &stop_sec, &next);
	if (!ok) {
		return -1;
	}

	ok = parse_uintmax(next, ' ', &stop_usec, &next);
	if (!ok) {
		return -1;
	}

	ok = parse_uintmax(next, ' ', &pid, &next);
	if (!ok) {
		return -1;
	}

	ok = parse_uintmax(next, ' ', &state, &next);
	if (!ok) {
		return -1;
	}

	ok = parse_uintmax(next, '\0', &user_error, &next);
	if (!ok) {
		return -1;
	}

	ok = tevent_req_profile_set_name(profile, req_name);
	if (!ok) {
		return -1;
	}

	ok = tevent_req_profile_set_start(
		profile,
		start_location,
		(struct timeval){ .tv_sec=start_sec, .tv_usec=start_usec });
	if (!ok) {
		return -1;
	}

	ok = tevent_req_profile_set_stop(
		profile,
		stop_location,
		(struct timeval){ .tv_sec=stop_sec, .tv_usec=stop_usec });
	if (!ok) {
		return -1;
	}

	tevent_req_profile_set_status(
		profile,
		pid,
		(enum tevent_req_state)state,
		user_error);

	return next - orig_buf;
}

ssize_t tevent_req_profile_unpack(
	const uint8_t *buf,
	size_t buflen,
	TALLOC_CTX *mem_ctx,
	struct tevent_req_profile **p_profile)
{
	const uint8_t *orig_buf = buf;
	struct tevent_req_profile *profile = NULL;
	uintmax_t i, num_subprofiles;
	char *next = NULL;
	bool ok;
	ssize_t len;

	errno = 0;

	if (buf[buflen-1] != '\0') {
		return -1;
	}

	ok = parse_uintmax((const char *)buf, ' ', &num_subprofiles, &next);
	if (!ok) {
		return -1;
	}

	len = (next - (const char *)buf);

	buf += len;
	buflen -= len;

	profile = tevent_req_profile_create(mem_ctx);
	if (profile == NULL) {
		return -1;
	}

	len = tevent_req_profile_unpack_one(buf, buflen, profile);
	if (len == -1) {
		TALLOC_FREE(profile);
		return -1;
	}

	buf += len;
	buflen -= len;

	for (i=0; i<num_subprofiles; i++) {
		struct tevent_req_profile *subprofile;

		len = tevent_req_profile_unpack(
			buf,
			buflen,
			profile,
			&subprofile);
		if (len == -1) {
			TALLOC_FREE(profile);
			return -1;
		}
		buf += len;
		buflen -= len;

		tevent_req_profile_append_sub(profile, &subprofile);
	}

	*p_profile = profile;

	return buf - orig_buf;
}
