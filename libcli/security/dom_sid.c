/*
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Stefan (metze) Metzmacher 	2002-2004
   Copyright (C) Andrew Tridgell 		1992-2004
   Copyright (C) Jeremy Allison  		1999

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "lib/util/data_blob.h"
#include "system/locale.h"
#include "lib/util/debug.h"
#include "lib/util/util.h"
#include "librpc/gen_ndr/security.h"
#include "dom_sid.h"

/*****************************************************************
 Compare the auth portion of two sids.
*****************************************************************/

int dom_sid_compare_auth(const struct dom_sid *sid1,
			 const struct dom_sid *sid2)
{
	int i;

	if (sid1 == sid2)
		return 0;
	if (!sid1)
		return -1;
	if (!sid2)
		return 1;

	if (sid1->sid_rev_num != sid2->sid_rev_num)
		return sid1->sid_rev_num - sid2->sid_rev_num;

	for (i = 0; i < 6; i++)
		if (sid1->id_auth[i] != sid2->id_auth[i])
			return sid1->id_auth[i] - sid2->id_auth[i];

	return 0;
}

/*****************************************************************
 Compare two sids.
*****************************************************************/

int dom_sid_compare(const struct dom_sid *sid1, const struct dom_sid *sid2)
{
	int i;

	if (sid1 == sid2)
		return 0;
	if (!sid1)
		return -1;
	if (!sid2)
		return 1;

	/* Compare most likely different rids, first: i.e start at end */
	if (sid1->num_auths != sid2->num_auths)
		return sid1->num_auths - sid2->num_auths;

	for (i = sid1->num_auths-1; i >= 0; --i)
		if (sid1->sub_auths[i] != sid2->sub_auths[i])
			return sid1->sub_auths[i] - sid2->sub_auths[i];

	return dom_sid_compare_auth(sid1, sid2);
}

/*****************************************************************
 Compare two sids.
*****************************************************************/

bool dom_sid_equal(const struct dom_sid *sid1, const struct dom_sid *sid2)
{
	return dom_sid_compare(sid1, sid2) == 0;
}

/*****************************************************************
 Add a rid to the end of a sid
*****************************************************************/

bool sid_append_rid(struct dom_sid *sid, uint32_t rid)
{
	if (sid->num_auths < ARRAY_SIZE(sid->sub_auths)) {
		sid->sub_auths[sid->num_auths++] = rid;
		return true;
	}
	return false;
}

/*
  See if 2 SIDs are in the same domain
  this just compares the leading sub-auths
*/
int dom_sid_compare_domain(const struct dom_sid *sid1,
			   const struct dom_sid *sid2)
{
	int n, i;

	n = MIN(sid1->num_auths, sid2->num_auths);

	for (i = n-1; i >= 0; --i)
		if (sid1->sub_auths[i] != sid2->sub_auths[i])
			return sid1->sub_auths[i] - sid2->sub_auths[i];

	return dom_sid_compare_auth(sid1, sid2);
}

/*****************************************************************
 Convert a string to a SID. Returns True on success, False on fail.
 Return the first character not parsed in endp.
*****************************************************************/
#define AUTHORITY_MASK (~(0xffffffffffffULL))

bool dom_sid_parse_endp(const char *sidstr,struct dom_sid *sidout,
			const char **endp)
{
	const char *p;
	char *q;
	/* BIG NOTE: this function only does SIDS where the identauth is not >= 2^32 */
	uint64_t conv;
	int error = 0;

	ZERO_STRUCTP(sidout);

	if ((sidstr[0] != 'S' && sidstr[0] != 's') || sidstr[1] != '-') {
		goto format_error;
	}

	/* Get the revision number. */
	p = sidstr + 2;

	if (!isdigit(*p)) {
		goto format_error;
	}

	conv = smb_strtoul(p, &q, 10, &error, SMB_STR_STANDARD);
	if (error != 0 || (*q != '-') || conv > UINT8_MAX) {
		goto format_error;
	}
	sidout->sid_rev_num = (uint8_t) conv;
	q++;

	if (!isdigit(*q)) {
		goto format_error;
	}

	/* get identauth */
	conv = smb_strtoull(q, &q, 0, &error, SMB_STR_STANDARD);
	if (conv & AUTHORITY_MASK || error != 0) {
		goto format_error;
	}

	/* When identauth >= UINT32_MAX, it's in hex with a leading 0x */
	/* NOTE - the conv value is in big-endian format. */
	sidout->id_auth[0] = (conv & 0xff0000000000ULL) >> 40;
	sidout->id_auth[1] = (conv & 0x00ff00000000ULL) >> 32;
	sidout->id_auth[2] = (conv & 0x0000ff000000ULL) >> 24;
	sidout->id_auth[3] = (conv & 0x000000ff0000ULL) >> 16;
	sidout->id_auth[4] = (conv & 0x00000000ff00ULL) >> 8;
	sidout->id_auth[5] = (conv & 0x0000000000ffULL);

	sidout->num_auths = 0;
	if (*q != '-') {
		/* Just id_auth, no subauths */
		goto done;
	}

	q++;

	while (true) {
		char *end;

		if (!isdigit(*q)) {
			goto format_error;
		}

		conv = smb_strtoull(q, &end, 10, &error, SMB_STR_STANDARD);
		if (conv > UINT32_MAX || error != 0) {
			goto format_error;
		}

		if (!sid_append_rid(sidout, conv)) {
			DEBUG(3, ("Too many sid auths in %s\n", sidstr));
			return false;
		}

		q = end;
		if (*q != '-') {
			break;
		}
		q += 1;
	}
done:
	if (endp != NULL) {
		*endp = q;
	}
	return true;

format_error:
	DEBUG(3, ("string_to_sid: SID %s is not in a valid format\n", sidstr));
	return false;
}

bool string_to_sid(struct dom_sid *sidout, const char *sidstr)
{
	return dom_sid_parse(sidstr, sidout);
}

bool dom_sid_parse(const char *sidstr, struct dom_sid *ret)
{
	return dom_sid_parse_endp(sidstr, ret, NULL);
}

/*
  convert a string to a dom_sid, returning a talloc'd dom_sid
*/
struct dom_sid *dom_sid_parse_talloc(TALLOC_CTX *mem_ctx, const char *sidstr)
{
	struct dom_sid *ret;
	ret = talloc(mem_ctx, struct dom_sid);
	if (!ret) {
		return NULL;
	}
	if (!dom_sid_parse(sidstr, ret)) {
		talloc_free(ret);
		return NULL;
	}

	return ret;
}

/*
  convert a string to a dom_sid, returning a talloc'd dom_sid
*/
struct dom_sid *dom_sid_parse_length(TALLOC_CTX *mem_ctx, const DATA_BLOB *sid)
{
	char p[sid->length+1];
	memcpy(p, sid->data, sid->length);
	p[sid->length] = '\0';
	return dom_sid_parse_talloc(mem_ctx, p);
}

/*
  copy a dom_sid structure
*/
struct dom_sid *dom_sid_dup(TALLOC_CTX *mem_ctx, const struct dom_sid *dom_sid)
{
	struct dom_sid *ret;
	int i;

	if (!dom_sid) {
		return NULL;
	}

	ret = talloc(mem_ctx, struct dom_sid);
	if (!ret) {
		return NULL;
	}

	ret->sid_rev_num = dom_sid->sid_rev_num;
	ret->id_auth[0] = dom_sid->id_auth[0];
	ret->id_auth[1] = dom_sid->id_auth[1];
	ret->id_auth[2] = dom_sid->id_auth[2];
	ret->id_auth[3] = dom_sid->id_auth[3];
	ret->id_auth[4] = dom_sid->id_auth[4];
	ret->id_auth[5] = dom_sid->id_auth[5];
	ret->num_auths = dom_sid->num_auths;

	for (i=0;i<dom_sid->num_auths;i++) {
		ret->sub_auths[i] = dom_sid->sub_auths[i];
	}

	return ret;
}

/*
  add a rid to a domain dom_sid to make a full dom_sid. This function
  returns a new sid in the supplied memory context
*/
struct dom_sid *dom_sid_add_rid(TALLOC_CTX *mem_ctx,
				const struct dom_sid *domain_sid,
				uint32_t rid)
{
	struct dom_sid *sid;

	sid = dom_sid_dup(mem_ctx, domain_sid);
	if (!sid) return NULL;

	if (!sid_append_rid(sid, rid)) {
		talloc_free(sid);
		return NULL;
	}

	return sid;
}

/*
  Split up a SID into its domain and RID part
*/
NTSTATUS dom_sid_split_rid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
			   struct dom_sid **domain, uint32_t *rid)
{
	if (sid->num_auths == 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (domain) {
		if (!(*domain = dom_sid_dup(mem_ctx, sid))) {
			return NT_STATUS_NO_MEMORY;
		}

		(*domain)->num_auths -= 1;
	}

	if (rid) {
		*rid = sid->sub_auths[sid->num_auths - 1];
	}

	return NT_STATUS_OK;
}

/*
  return true if the 2nd sid is in the domain given by the first sid
*/
bool dom_sid_in_domain(const struct dom_sid *domain_sid,
		       const struct dom_sid *sid)
{
	int i;

	if (!domain_sid || !sid) {
		return false;
	}

	if (sid->num_auths < 2) {
		return false;
	}

	if (domain_sid->num_auths != (sid->num_auths - 1)) {
		return false;
	}

	for (i = domain_sid->num_auths-1; i >= 0; --i) {
		if (domain_sid->sub_auths[i] != sid->sub_auths[i]) {
			return false;
		}
	}

	return dom_sid_compare_auth(domain_sid, sid) == 0;
}

bool dom_sid_is_valid_account_domain(const struct dom_sid *sid)
{
	/*
	 * We expect S-1-5-21-9-8-7, but we don't
	 * allow S-1-5-21-0-0-0 as this is used
	 * for claims and compound identities.
	 *
	 * With this structure:
	 *
	 * struct dom_sid {
	 *     uint8_t sid_rev_num;
	 *     int8_t num_auths; [range(0,15)]
	 *     uint8_t id_auth[6];
	 *     uint32_t sub_auths[15];
	 * }
	 *
	 * S-1-5-21-9-8-7 looks like this:
	 * {1, 4, {0,0,0,0,0,5}, {21,9,8,7,0,0,0,0,0,0,0,0,0,0,0}};
	 */
	if (sid == NULL) {
		return false;
	}

	if (sid->sid_rev_num != 1) {
		return false;
	}
	if (sid->num_auths != 4) {
		return false;
	}
	if (sid->id_auth[5] != 5) {
		return false;
	}
	if (sid->id_auth[4] != 0) {
		return false;
	}
	if (sid->id_auth[3] != 0) {
		return false;
	}
	if (sid->id_auth[2] != 0) {
		return false;
	}
	if (sid->id_auth[1] != 0) {
		return false;
	}
	if (sid->id_auth[0] != 0) {
		return false;
	}
	if (sid->sub_auths[0] != 21) {
		return false;
	}
	if (sid->sub_auths[1] == 0) {
		return false;
	}
	if (sid->sub_auths[2] == 0) {
		return false;
	}
	if (sid->sub_auths[3] == 0) {
		return false;
	}

	return true;
}

/*
  Convert a dom_sid to a string, printing into a buffer. Return the
  string length. If it overflows, return the string length that would
  result (buflen needs to be +1 for the terminating 0).
*/
static int dom_sid_string_buf(const struct dom_sid *sid, char *buf, int buflen)
{
	int i, ofs, ret;
	uint64_t ia;

	if (!sid) {
		return strlcpy(buf, "(NULL SID)", buflen);
	}

	ia = ((uint64_t)sid->id_auth[5]) +
		((uint64_t)sid->id_auth[4] << 8 ) +
		((uint64_t)sid->id_auth[3] << 16) +
		((uint64_t)sid->id_auth[2] << 24) +
		((uint64_t)sid->id_auth[1] << 32) +
		((uint64_t)sid->id_auth[0] << 40);

	ret = snprintf(buf, buflen, "S-%"PRIu8"-", sid->sid_rev_num);
	if (ret < 0) {
		return ret;
	}
	ofs = ret;

	if (ia >= UINT32_MAX) {
		ret = snprintf(buf+ofs, MAX(buflen-ofs, 0), "0x%"PRIx64, ia);
	} else {
		ret = snprintf(buf+ofs, MAX(buflen-ofs, 0), "%"PRIu64, ia);
	}
	if (ret < 0) {
		return ret;
	}
	ofs += ret;

	for (i = 0; i < sid->num_auths; i++) {
		ret = snprintf(
			buf+ofs,
			MAX(buflen-ofs, 0),
			"-%"PRIu32,
			sid->sub_auths[i]);
		if (ret < 0) {
			return ret;
		}
		ofs += ret;
	}
	return ofs;
}

/*
  convert a dom_sid to a string
*/
char *dom_sid_string(TALLOC_CTX *mem_ctx, const struct dom_sid *sid)
{
	char buf[DOM_SID_STR_BUFLEN];
	char *result;
	int len;

	len = dom_sid_string_buf(sid, buf, sizeof(buf));

	if ((len < 0) || (len+1 > sizeof(buf))) {
		return talloc_strdup(mem_ctx, "(SID ERR)");
	}

	/*
	 * Avoid calling strlen (via talloc_strdup), we already have
	 * the length
	 */
	result = (char *)talloc_memdup(mem_ctx, buf, len+1);
	if (result == NULL) {
		return NULL;
	}

	/*
	 * beautify the talloc_report output
	 */
	talloc_set_name_const(result, result);
	return result;
}

char *dom_sid_str_buf(const struct dom_sid *sid, struct dom_sid_buf *dst)
{
	int ret;
	ret = dom_sid_string_buf(sid, dst->buf, sizeof(dst->buf));
	if ((ret < 0) || (ret >= sizeof(dst->buf))) {
		strlcpy(dst->buf, "(INVALID SID)", sizeof(dst->buf));
	}
	return dst->buf;
}
