/*
   Unix SMB/CIFS implementation.

   security descriptor description language functions

   Copyright (C) Andrew Tridgell 		2005

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
#include "lib/util/debug.h"
#include "libcli/security/security.h"
#include "libcli/security/conditional_ace.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "lib/util/smb_strtox.h"
#include "libcli/security/sddl.h"
#include "system/locale.h"
#include "lib/util/util_str_hex.h"


struct sddl_transition_state {
	const struct dom_sid *machine_sid;
	const struct dom_sid *domain_sid;
	const struct dom_sid *forest_sid;
};

struct flag_map {
	const char *name;
	uint32_t flag;
};

static bool sddl_map_flag(
	const struct flag_map *map,
	const char *str,
	size_t *plen,
	uint32_t *pflag)
{
	while (map->name != NULL) {
		size_t len = strlen(map->name);
		int cmp = strncmp(map->name, str, len);

		if (cmp == 0) {
			*plen = len;
			*pflag = map->flag;
			return true;
		}
		map += 1;
	}
	return false;
}

/*
  map a series of letter codes into a uint32_t
*/
static bool sddl_map_flags(const struct flag_map *map, const char *str,
			   uint32_t *pflags, size_t *plen,
			   bool unknown_flag_is_part_of_next_thing)
{
	const char *str0 = str;
	if (plen != NULL) {
		*plen = 0;
	}
	*pflags = 0;
	while (str[0] != '\0' && isupper((unsigned char)str[0])) {
		size_t len;
		uint32_t flags;
		bool found;

		found = sddl_map_flag(map, str, &len, &flags);
		if (!found) {
			break;
		}

		*pflags |= flags;
		if (plen != NULL) {
			*plen += len;
		}
		str += len;
	}
	/*
	 * For ACL flags, unknown_flag_is_part_of_next_thing is set,
	 * and we expect some more stuff that isn't flags.
	 *
	 * For ACE flags, unknown_flag_is_part_of_next_thing is unset,
	 * and the flags have been tokenised into their own little
	 * string. We don't expect anything here, even whitespace.
	 */
	if (*str == '\0' || unknown_flag_is_part_of_next_thing) {
		return true;
	}
	DBG_WARNING("Unknown flag - '%s' in '%s'\n", str, str0);
	return false;
}


/*
  a mapping between the 2 letter SID codes and sid strings
*/
static const struct {
	const char *code;
	const char *sid;
	uint32_t machine_rid;
	uint32_t domain_rid;
	uint32_t forest_rid;
} sid_codes[] = {
	{ .code = "WD", .sid = SID_WORLD },

	{ .code = "CO", .sid = SID_CREATOR_OWNER },
	{ .code = "CG", .sid = SID_CREATOR_GROUP },
	{ .code = "OW", .sid = SID_OWNER_RIGHTS },

	{ .code = "NU", .sid = SID_NT_NETWORK },
	{ .code = "IU", .sid = SID_NT_INTERACTIVE },
	{ .code = "SU", .sid = SID_NT_SERVICE },
	{ .code = "AN", .sid = SID_NT_ANONYMOUS },
	{ .code = "ED", .sid = SID_NT_ENTERPRISE_DCS },
	{ .code = "PS", .sid = SID_NT_SELF },
	{ .code = "AU", .sid = SID_NT_AUTHENTICATED_USERS },
	{ .code = "RC", .sid = SID_NT_RESTRICTED },
	{ .code = "SY", .sid = SID_NT_SYSTEM },
	{ .code = "LS", .sid = SID_NT_LOCAL_SERVICE },
	{ .code = "NS", .sid = SID_NT_NETWORK_SERVICE },
	{ .code = "WR", .sid = SID_SECURITY_RESTRICTED_CODE },

	{ .code = "BA", .sid = SID_BUILTIN_ADMINISTRATORS },
	{ .code = "BU", .sid = SID_BUILTIN_USERS },
	{ .code = "BG", .sid = SID_BUILTIN_GUESTS },
	{ .code = "PU", .sid = SID_BUILTIN_POWER_USERS },
	{ .code = "AO", .sid = SID_BUILTIN_ACCOUNT_OPERATORS },
	{ .code = "SO", .sid = SID_BUILTIN_SERVER_OPERATORS },
	{ .code = "PO", .sid = SID_BUILTIN_PRINT_OPERATORS },
	{ .code = "BO", .sid = SID_BUILTIN_BACKUP_OPERATORS },
	{ .code = "RE", .sid = SID_BUILTIN_REPLICATOR },
	{ .code = "RU", .sid = SID_BUILTIN_PREW2K },
	{ .code = "RD", .sid = SID_BUILTIN_REMOTE_DESKTOP_USERS },
	{ .code = "NO", .sid = SID_BUILTIN_NETWORK_CONF_OPERATORS },

	{ .code = "MU", .sid = SID_BUILTIN_PERFMON_USERS },
	{ .code = "LU", .sid = SID_BUILTIN_PERFLOG_USERS },
	{ .code = "IS", .sid = SID_BUILTIN_IUSERS },
	{ .code = "CY", .sid = SID_BUILTIN_CRYPTO_OPERATORS },
	{ .code = "ER", .sid = SID_BUILTIN_EVENT_LOG_READERS },
	{ .code = "CD", .sid = SID_BUILTIN_CERT_SERV_DCOM_ACCESS },
	{ .code = "RA", .sid = SID_BUILTIN_RDS_REMOTE_ACCESS_SERVERS },
	{ .code = "ES", .sid = SID_BUILTIN_RDS_ENDPOINT_SERVERS },
	{ .code = "MS", .sid = SID_BUILTIN_RDS_MANAGEMENT_SERVERS },
	{ .code = "HA", .sid = SID_BUILTIN_HYPER_V_ADMINS },
	{ .code = "AA", .sid = SID_BUILTIN_ACCESS_CONTROL_ASSISTANCE_OPS },
	{ .code = "RM", .sid = SID_BUILTIN_REMOTE_MANAGEMENT_USERS },

	{ .code = "UD", .sid = SID_USER_MODE_DRIVERS },

	{ .code = "AC", .sid = SID_SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE },

	{ .code = "LW", .sid = SID_SECURITY_MANDATORY_LOW },
	{ .code = "ME", .sid = SID_SECURITY_MANDATORY_MEDIUM },
	{ .code = "MP", .sid = SID_SECURITY_MANDATORY_MEDIUM_PLUS },
	{ .code = "HI", .sid = SID_SECURITY_MANDATORY_HIGH },
	{ .code = "SI", .sid = SID_SECURITY_MANDATORY_SYSTEM },

	{ .code = "AS", .sid = SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY },
	{ .code = "SS", .sid = SID_SERVICE_ASSERTED_IDENTITY },

	{ .code = "RO", .forest_rid = DOMAIN_RID_ENTERPRISE_READONLY_DCS },

	{ .code = "LA", .machine_rid = DOMAIN_RID_ADMINISTRATOR },
	{ .code = "LG", .machine_rid = DOMAIN_RID_GUEST },

	{ .code = "DA", .domain_rid = DOMAIN_RID_ADMINS },
	{ .code = "DU", .domain_rid = DOMAIN_RID_USERS },
	{ .code = "DG", .domain_rid = DOMAIN_RID_GUESTS },
	{ .code = "DC", .domain_rid = DOMAIN_RID_DOMAIN_MEMBERS },
	{ .code = "DD", .domain_rid = DOMAIN_RID_DCS },
	{ .code = "CA", .domain_rid = DOMAIN_RID_CERT_ADMINS },
	{ .code = "SA", .forest_rid = DOMAIN_RID_SCHEMA_ADMINS },
	{ .code = "EA", .forest_rid = DOMAIN_RID_ENTERPRISE_ADMINS },
	{ .code = "PA", .domain_rid = DOMAIN_RID_POLICY_ADMINS },

	{ .code = "CN", .domain_rid = DOMAIN_RID_CLONEABLE_CONTROLLERS },

	{ .code = "AP", .domain_rid = DOMAIN_RID_PROTECTED_USERS },
	{ .code = "KA", .domain_rid = DOMAIN_RID_KEY_ADMINS },
	{ .code = "EK", .forest_rid = DOMAIN_RID_ENTERPRISE_KEY_ADMINS },

	{ .code = "RS", .domain_rid = DOMAIN_RID_RAS_SERVERS }
};

/*
  decode a SID
  It can either be a special 2 letter code, or in S-* format
*/
static struct dom_sid *sddl_transition_decode_sid(TALLOC_CTX *mem_ctx, const char **sddlp,
						  struct sddl_transition_state *state)
{
	const char *sddl = (*sddlp);
	size_t i;

	/* see if its in the numeric format */
	if (strncasecmp(sddl, "S-", 2) == 0) {
		struct dom_sid *sid = NULL;
		char *sid_str = NULL;
		const char *end = NULL;
		bool ok;
		size_t len = strspn(sddl + 2, "-0123456789ABCDEFabcdefxX") + 2;
		if (len < 5) { /* S-1-x */
			return NULL;
		}
		if (sddl[len - 1] == 'D' && sddl[len] == ':') {
			/*
			 * we have run into the "D:" dacl marker, mistaking it
			 * for a hex digit. There is no other way for this
			 * pair to occur at the end of a SID in SDDL.
			 */
			len--;
		}

		sid_str = talloc_strndup(mem_ctx, sddl, len);
		if (sid_str == NULL) {
			return NULL;
		}
		if (sid_str[0] == 's') {
			/*
			 * In SDDL, but not in the dom_sid parsers, a
			 * lowercase "s-1-1-0" is accepted.
			 */
			sid_str[0] = 'S';
		}
		sid = talloc(mem_ctx, struct dom_sid);
		if (sid == NULL) {
			TALLOC_FREE(sid_str);
			return NULL;
		};
		ok = dom_sid_parse_endp(sid_str, sid, &end);
		if (!ok) {
			DBG_WARNING("could not parse SID '%s'\n", sid_str);
			TALLOC_FREE(sid_str);
			TALLOC_FREE(sid);
			return NULL;
		}
		if (end - sid_str != len) {
			DBG_WARNING("trailing junk after SID '%s'\n", sid_str);
			TALLOC_FREE(sid_str);
			TALLOC_FREE(sid);
			return NULL;
		}
		TALLOC_FREE(sid_str);
		(*sddlp) += len;
		return sid;
	}

	/* now check for one of the special codes */
	for (i=0;i<ARRAY_SIZE(sid_codes);i++) {
		if (strncmp(sid_codes[i].code, sddl, 2) == 0) break;
	}
	if (i == ARRAY_SIZE(sid_codes)) {
		DEBUG(1,("Unknown sddl sid code '%2.2s'\n", sddl));
		return NULL;
	}

	(*sddlp) += 2;


	if (sid_codes[i].machine_rid != 0) {
		return dom_sid_add_rid(mem_ctx, state->machine_sid,
				       sid_codes[i].machine_rid);
	}

	if (sid_codes[i].domain_rid != 0) {
		return dom_sid_add_rid(mem_ctx, state->domain_sid,
				       sid_codes[i].domain_rid);
	}

	if (sid_codes[i].forest_rid != 0) {
		return dom_sid_add_rid(mem_ctx, state->forest_sid,
				       sid_codes[i].forest_rid);
	}

	return dom_sid_parse_talloc(mem_ctx, sid_codes[i].sid);
}

struct dom_sid *sddl_decode_sid(TALLOC_CTX *mem_ctx, const char **sddlp,
				const struct dom_sid *domain_sid)
{
	struct sddl_transition_state state = {
		/*
		 * TODO: verify .machine_rid values really belong
		 * to the machine_sid on a member, once
		 * we pass machine_sid from the caller...
		 */
		.machine_sid = domain_sid,
		.domain_sid = domain_sid,
		.forest_sid = domain_sid,
	};
	return sddl_transition_decode_sid(mem_ctx, sddlp, &state);
}


static const struct flag_map ace_types[] = {
	{ "AU", SEC_ACE_TYPE_SYSTEM_AUDIT },
	{ "AL", SEC_ACE_TYPE_SYSTEM_ALARM },
	{ "OA", SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT },
	{ "OD", SEC_ACE_TYPE_ACCESS_DENIED_OBJECT },
	{ "OU", SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT },
	{ "OL", SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT },
	{ "A",	SEC_ACE_TYPE_ACCESS_ALLOWED },
	{ "D",	SEC_ACE_TYPE_ACCESS_DENIED },

	{ "XA", SEC_ACE_TYPE_ACCESS_ALLOWED_CALLBACK },
	{ "XD", SEC_ACE_TYPE_ACCESS_DENIED_CALLBACK },
	{ "ZA", SEC_ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT },
	/*
	 * SEC_ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT exists but has
	 * no SDDL flag.
	 *
	 * ZA and XU are switched in [MS-DTYP] as of version 36.0,
	 * but this should be corrected in later versions.
	 */
	{ "XU", SEC_ACE_TYPE_SYSTEM_AUDIT_CALLBACK },

	{ "RA", SEC_ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE },
	{ NULL, 0 }
};

static const struct flag_map ace_flags[] = {
	{ "OI", SEC_ACE_FLAG_OBJECT_INHERIT },
	{ "CI", SEC_ACE_FLAG_CONTAINER_INHERIT },
	{ "NP", SEC_ACE_FLAG_NO_PROPAGATE_INHERIT },
	{ "IO", SEC_ACE_FLAG_INHERIT_ONLY },
	{ "ID", SEC_ACE_FLAG_INHERITED_ACE },
	{ "SA", SEC_ACE_FLAG_SUCCESSFUL_ACCESS },
	{ "FA", SEC_ACE_FLAG_FAILED_ACCESS },
	{ NULL, 0 },
};

static const struct flag_map ace_access_mask[] = {
	{ "CC", SEC_ADS_CREATE_CHILD },
	{ "DC", SEC_ADS_DELETE_CHILD },
	{ "LC", SEC_ADS_LIST },
	{ "SW", SEC_ADS_SELF_WRITE },
	{ "RP", SEC_ADS_READ_PROP },
	{ "WP", SEC_ADS_WRITE_PROP },
	{ "DT", SEC_ADS_DELETE_TREE },
	{ "LO", SEC_ADS_LIST_OBJECT },
	{ "CR", SEC_ADS_CONTROL_ACCESS },
	{ "SD", SEC_STD_DELETE },
	{ "RC", SEC_STD_READ_CONTROL },
	{ "WD", SEC_STD_WRITE_DAC },
	{ "WO", SEC_STD_WRITE_OWNER },
	{ "GA", SEC_GENERIC_ALL },
	{ "GX", SEC_GENERIC_EXECUTE },
	{ "GW", SEC_GENERIC_WRITE },
	{ "GR", SEC_GENERIC_READ },
	{ NULL, 0 }
};

static const struct flag_map decode_ace_access_mask[] = {
	{ "FA", FILE_GENERIC_ALL },
	{ "FR", FILE_GENERIC_READ },
	{ "FW", FILE_GENERIC_WRITE },
	{ "FX", FILE_GENERIC_EXECUTE },
	{ NULL, 0 },
};


static char *sddl_match_file_rights(TALLOC_CTX *mem_ctx,
				uint32_t flags)
{
	int i;

	/* try to find an exact match */
	for (i=0;decode_ace_access_mask[i].name;i++) {
		if (decode_ace_access_mask[i].flag == flags) {
			return talloc_strdup(mem_ctx,
					decode_ace_access_mask[i].name);
		}
	}
	return NULL;
}

static bool sddl_decode_access(const char *str, uint32_t *pmask)
{
	const char *str0 = str;
	char *end = NULL;
	uint32_t mask = 0;
	unsigned long long numeric_mask;
	int err;
	/*
	 * The access mask can be a number or a series of flags.
	 *
	 * Canonically the number is expressed in hexadecimal (with 0x), but
	 * per MS-DTYP and Windows behaviour, octal and decimal numbers are
	 * also accepted.
	 *
	 * Windows has two behaviours we choose not to replicate:
	 *
	 * 1. numbers exceeding 0xffffffff are truncated at that point,
	 *    turning on all access flags.
	 *
	 * 2. negative numbers are accepted, so e.g. -2 becomes 0xfffffffe.
	 */
	numeric_mask = smb_strtoull(str, &end, 0, &err, SMB_STR_STANDARD);
	if (err == 0) {
		if (numeric_mask > UINT32_MAX) {
			DBG_WARNING("Bad numeric flag value - %llu in %s\n",
				    numeric_mask, str0);
			return false;
		}
		if (end - str > sizeof("037777777777")) {
			/* here's the tricky thing: if a number is big
			 * enough to overflow the uint64, it might end
			 * up small enough to fit in the uint32, and
			 * we'd miss that it overflowed. So we count
			 * the digits -- any more than 12 (for
			 * "037777777777") is too long for 32 bits,
			 * and the shortest 64-bit wrapping string is
			 * 19 (for "0x1" + 16 zeros).
			 */
			DBG_WARNING("Bad numeric flag value in '%s'\n", str0);
			return false;
		}
		if (*end != '\0') {
			DBG_WARNING("Bad characters in '%s'\n", str0);
			return false;
		}
		*pmask = numeric_mask;
		return true;
	}
	/* It's not a positive number, so we'll look for flags */

	while ((str[0] != '\0') &&
	       (isupper((unsigned char)str[0]) || str[0] == ' ')) {
		uint32_t flags = 0;
		size_t len = 0;
		bool found;
		while (str[0] == ' ') {
			/*
			 * Following Windows we accept spaces between flags
			 * but not after flags. Not tabs, though, never tabs.
			 */
			str++;
			if (str[0] == '\0') {
				DBG_WARNING("trailing whitespace in flags "
					    "- '%s'\n", str0);
				return false;
			}
		}
		found = sddl_map_flag(
			ace_access_mask, str, &len, &flags);
		found |= sddl_map_flag(
			decode_ace_access_mask, str, &len, &flags);
		if (!found) {
			DEBUG(1, ("Unknown flag - %s in %s\n", str, str0));
			return false;
		}
		mask |= flags;
		str += len;
	}
	if (*str != '\0') {
		DBG_WARNING("Bad characters in '%s'\n", str0);
		return false;
	}
	*pmask = mask;
	return true;
}


static bool sddl_decode_guid(const char *str, struct GUID *guid)
{
	if (strlen(str) != 36) {
		return false;
	}
	return parse_guid_string(str, guid);
}



static DATA_BLOB sddl_decode_conditions(TALLOC_CTX *mem_ctx,
					const enum ace_condition_flags ace_condition_flags,
					const char *conditions,
					size_t *length,
					const char **msg,
					size_t *msg_offset)
{
	DATA_BLOB blob = {0};
	struct ace_condition_script *script = NULL;
	script = ace_conditions_compile_sddl(mem_ctx,
					     ace_condition_flags,
					     conditions,
					     msg,
					     msg_offset,
					     length);
	if (script != NULL) {
		bool ok = conditional_ace_encode_binary(mem_ctx,
							script,
							&blob);
		if (! ok) {
			DBG_ERR("could not blobify '%s'\n", conditions);
		}
	}
	return blob;
}


/*
  decode an ACE
  return true on success, false on failure
  note that this routine modifies the string
*/
static bool sddl_decode_ace(TALLOC_CTX *mem_ctx,
			    struct security_ace *ace,
			    const enum ace_condition_flags ace_condition_flags,
			    char **sddl_copy,
			    struct sddl_transition_state *state,
			    const char **msg, size_t *msg_offset)
{
	const char *tok[7];
	const char *s;
	uint32_t v;
	struct dom_sid *sid;
	bool ok;
	size_t len;
	size_t count = 0;
	char *str = *sddl_copy;
	bool has_extra_data = false;
	ZERO_STRUCTP(ace);

	*msg_offset = 1;
	if (*str != '(') {
		*msg = talloc_strdup(mem_ctx, "Not an ACE");
		return false;
	}
	str++;
	/*
	 * First we split apart the 6 (or 7) tokens.
	 *
	 * 0.		 ace type
	 * 1.		 ace flags
	 * 2.		 access mask
	 * 3.		 object guid
	 * 4.		 inherit guid
	 * 5.		 sid
	 *
	 * 6/extra_data	 rare optional extra data
	 */
	tok[0] = str;
	while (*str != '\0') {
		if (*str == ';') {
			*str = '\0';
			str++;
			count++;
			tok[count] = str;
			if (count == 6) {
				/*
				 * this looks like a conditional ACE
				 * or resource ACE, but we can't say
				 * for sure until we look at the ACE
				 * type (tok[0]), after the loop.
				 */
				has_extra_data = true;
				break;
			}
			continue;
		}
		/*
		 * we are not expecting a ')' in the 6 sections of an
		 * ordinary ACE, except ending the last one.
		 */
		if (*str == ')') {
			count++;
			*str = '\0';
			str++;
			break;
		}
		str++;
	}
	if (count != 6) {
		/* we hit the '\0' or ')' before all of ';;;;;)' */
		*msg = talloc_asprintf(mem_ctx,
				       "malformed ACE with only %zu ';'",
				       MIN(count - 1, count));
		return false;
	}

	/* parse ace type */
	ok = sddl_map_flag(ace_types, tok[0], &len, &v);
	if (!ok) {
		*msg = talloc_asprintf(mem_ctx,
				       "Unknown ACE type - %s", tok[0]);
		return false;
	}
	if (tok[0][len] != '\0') {
		*msg = talloc_asprintf(mem_ctx,
				       "Garbage after ACE type - %s", tok[0]);
		return false;
	}

	ace->type = v;

	/*
	 * Only callback and resource aces should have trailing data.
	 */
	if (sec_ace_callback(ace->type)) {
		if (! has_extra_data) {
			*msg = talloc_strdup(
				mem_ctx,
				"callback ACE has no trailing data");
			*msg_offset = str - *sddl_copy;
			return false;
		}
	} else if (sec_ace_resource(ace->type)) {
		if (! has_extra_data) {
			*msg = talloc_strdup(
				mem_ctx,
				"resource attribute ACE has no trailing data");
			*msg_offset = str - *sddl_copy;
			return false;
		}
	} else if (has_extra_data) {
		*msg = talloc_strdup(
			mem_ctx,
			"ACE has trailing section but is not a "
			"callback or resource ACE");
		*msg_offset = str - *sddl_copy;
		return false;
	}

	/* ace flags */
	if (!sddl_map_flags(ace_flags, tok[1], &v, NULL, false)) {
		*msg = talloc_strdup(mem_ctx,
				     "could not parse flags");
		*msg_offset = tok[1] - *sddl_copy;
		return false;
	}
	ace->flags = v;

	/* access mask */
	ok = sddl_decode_access(tok[2], &ace->access_mask);
	if (!ok) {
		*msg = talloc_strdup(mem_ctx,
				     "could not parse access string");
		*msg_offset = tok[2] - *sddl_copy;
		return false;
	}

	/* object */
	if (tok[3][0] != 0) {
		ok = sddl_decode_guid(tok[3], &ace->object.object.type.type);
		if (!ok) {
			*msg = talloc_strdup(mem_ctx,
					     "could not parse object GUID");
			*msg_offset = tok[3] - *sddl_copy;
			return false;
		}
		ace->object.object.flags |= SEC_ACE_OBJECT_TYPE_PRESENT;
	}

	/* inherit object */
	if (tok[4][0] != 0) {
		ok = sddl_decode_guid(tok[4],
				      &ace->object.object.inherited_type.inherited_type);
		if (!ok) {
			*msg = talloc_strdup(
				mem_ctx,
				"could not parse inherited object GUID");
			*msg_offset = tok[4] - *sddl_copy;
			return false;
		}
		ace->object.object.flags |= SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT;
	}

	/* trustee */
	s = tok[5];
	sid = sddl_transition_decode_sid(mem_ctx, &s, state);
	if (sid == NULL) {
		*msg = talloc_strdup(
			mem_ctx,
			"could not parse trustee SID");
		*msg_offset = tok[5] - *sddl_copy;
		return false;
	}
	ace->trustee = *sid;
	talloc_free(sid);
	if (*s != '\0') {
		*msg = talloc_strdup(
			mem_ctx,
			"garbage after trustee SID");
		*msg_offset = s - *sddl_copy;
		return false;
	}

	if (sec_ace_callback(ace->type)) {
		/*
		 * This is either a conditional ACE or some unknown
		 * type of callback ACE that will be rejected by the
		 * conditional ACE compiler.
		 */
		size_t length;
		DATA_BLOB conditions = {0};
		s = tok[6];

		conditions = sddl_decode_conditions(mem_ctx,
						    ace_condition_flags,
						    s,
						    &length,
						    msg,
						    msg_offset);
		if (conditions.data == NULL) {
			DBG_NOTICE("Conditional ACE compilation failure at %zu: %s\n",
				   *msg_offset, *msg);
			*msg_offset += s - *sddl_copy;
			return false;
		}
		ace->coda.conditions = conditions;

		/*
		 * We have found the end of the conditions, and the
		 * next character should be the ')' to end the ACE.
		 */
		if (s[length] != ')') {
			*msg = talloc_strdup(
				mem_ctx,
				"Conditional ACE has trailing bytes"
				" or lacks ')'");
			*msg_offset = s + length - *sddl_copy;
			return false;
		}
		str = discard_const_p(char, s + length + 1);
	} else if (sec_ace_resource(ace->type)) {
		size_t length;
		struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim = NULL;

		if (! dom_sid_equal(&ace->trustee, &global_sid_World)) {
			/* these are just the rules */
			*msg = talloc_strdup(
				mem_ctx,
				"Resource Attribute ACE trustee must be "
				"'S-1-1-0' or 'WD'.");
			*msg_offset = tok[5] - *sddl_copy;
			return false;
		}

		s = tok[6];
		claim = sddl_decode_resource_attr(mem_ctx, s, &length);
		if (claim == NULL) {
			*msg = talloc_strdup(
				mem_ctx,
				"Resource Attribute ACE parse failure");
			*msg_offset = s - *sddl_copy;
			return false;
		}
		ace->coda.claim = *claim;

		/*
		 * We want a ')' to end the ACE.
		 */
		if (s[length] != ')') {
			*msg = talloc_strdup(
				mem_ctx,
				"Resource Attribute ACE has trailing bytes"
				" or lacks ')'");
			*msg_offset = s + length - *sddl_copy;
			return false;
		}
		str = discard_const_p(char, s + length + 1);
	}

	*sddl_copy = str;
	return true;
}

static const struct flag_map acl_flags[] = {
	{ "P", SEC_DESC_DACL_PROTECTED },
	{ "AR", SEC_DESC_DACL_AUTO_INHERIT_REQ },
	{ "AI", SEC_DESC_DACL_AUTO_INHERITED },
	{ NULL, 0 }
};

/*
  decode an ACL
*/
static struct security_acl *sddl_decode_acl(struct security_descriptor *sd,
					    const enum ace_condition_flags ace_condition_flags,
					    const char **sddlp, uint32_t *flags,
					    struct sddl_transition_state *state,
					    const char **msg, size_t *msg_offset)
{
	const char *sddl = *sddlp;
	char *sddl_copy = NULL;
	char *aces_start = NULL;
	struct security_acl *acl;
	size_t len;
	*flags = 0;

	acl = talloc_zero(sd, struct security_acl);
	if (acl == NULL) {
		return NULL;
	}
	acl->revision = SECURITY_ACL_REVISION_ADS;

	if (isupper((unsigned char)sddl[0]) && sddl[1] == ':') {
		/* its an empty ACL */
		return acl;
	}

	/* Windows AD allows spaces here */
	while (*sddl == ' ') {
		sddl++;
	}

	/* work out the ACL flags */
	if (!sddl_map_flags(acl_flags, sddl, flags, &len, true)) {
		*msg = talloc_strdup(sd, "bad ACL flags");
		*msg_offset = 0;
		talloc_free(acl);
		return NULL;
	}
	sddl += len;

	if (sddl[0] != '(') {
		/*
		 * it is empty apart from the flags
		 * (or the flags are bad, and we will find out when
		 * we try to parse the next bit as a top-level fragment)
		 */
		*sddlp = sddl;
		return acl;
	}

	/*
	 * now the ACEs
	 *
	 * For this we make a copy of the rest of the SDDL, which the ACE
	 * tokeniser will mutilate by putting '\0' where it finds ';'.
	 *
	 * We need to copy the rest of the SDDL string because it is not
	 * possible in general to find where an ACL ends if there are
	 * conditional ACEs.
	 */

	sddl_copy = talloc_strdup(acl, sddl);
	if (sddl_copy == NULL) {
		TALLOC_FREE(acl);
		return NULL;
	}
	aces_start = sddl_copy;

	while (*sddl_copy == '(') {
		bool ok;
		if (acl->num_aces > UINT16_MAX / 16) {
			/*
			 * We can't fit this many ACEs in a wire ACL
			 * which has a 16 bit size field (and 16 is
			 * the minimal size of an ACE with no subauths).
			 */
			talloc_free(acl);
			return NULL;
		}

		acl->aces = talloc_realloc(acl, acl->aces, struct security_ace,
					   acl->num_aces+1);
		if (acl->aces == NULL) {
			talloc_free(acl);
			return NULL;
		}
		ok = sddl_decode_ace(acl->aces, &acl->aces[acl->num_aces],
				     ace_condition_flags,
				     &sddl_copy, state, msg, msg_offset);
		if (!ok) {
			*msg_offset += sddl_copy - aces_start;
			talloc_steal(sd, *msg);
			talloc_free(acl);
			return NULL;
		}
		acl->num_aces++;
	}
	sddl += sddl_copy - aces_start;
	TALLOC_FREE(aces_start);
	(*sddlp) = sddl;
	return acl;
}

/*
 * Decode a security descriptor in SDDL format, catching compilation
 * error messages, if any.
 *
 * The message will be a direct talloc child of mem_ctx or NULL.
 */
struct security_descriptor *sddl_decode_err_msg(TALLOC_CTX *mem_ctx, const char *sddl,
						const struct dom_sid *domain_sid,
						const enum ace_condition_flags ace_condition_flags,
						const char **msg, size_t *msg_offset)
{
	struct sddl_transition_state state = {
		/*
		 * TODO: verify .machine_rid values really belong
		 * to the machine_sid on a member, once
		 * we pass machine_sid from the caller...
		 */
		.machine_sid = domain_sid,
		.domain_sid = domain_sid,
		.forest_sid = domain_sid,
	};
	const char *start = sddl;
	struct security_descriptor *sd = NULL;

	if (msg == NULL || msg_offset == NULL) {
		DBG_ERR("Programmer misbehaviour: use sddl_decode() "
			"or provide msg pointers.\n");
		return NULL;
	}
	*msg = NULL;
	*msg_offset = 0;

	sd = security_descriptor_initialise(mem_ctx);
	if (sd == NULL) {
		return NULL;
	}

	while (*sddl) {
		uint32_t flags;
		char c = sddl[0];
		if (sddl[1] != ':') {
			*msg = talloc_strdup(mem_ctx,
					     "expected '[OGDS]:' section start "
					     "(or the previous section ended prematurely)");
			goto failed;
		}
		sddl += 2;
		switch (c) {
		case 'D':
			if (sd->dacl != NULL) goto failed;
			sd->dacl = sddl_decode_acl(sd, ace_condition_flags, &sddl, &flags, &state, msg, msg_offset);
			if (sd->dacl == NULL) goto failed;
			sd->type |= flags | SEC_DESC_DACL_PRESENT;
			break;
		case 'S':
			if (sd->sacl != NULL) goto failed;
			sd->sacl = sddl_decode_acl(sd, ace_condition_flags, &sddl, &flags, &state, msg, msg_offset);
			if (sd->sacl == NULL) goto failed;
			/* this relies on the SEC_DESC_SACL_* flags being
			   1 bit shifted from the SEC_DESC_DACL_* flags */
			sd->type |= (flags<<1) | SEC_DESC_SACL_PRESENT;
			break;
		case 'O':
			if (sd->owner_sid != NULL) goto failed;
			sd->owner_sid = sddl_transition_decode_sid(sd, &sddl, &state);
			if (sd->owner_sid == NULL) goto failed;
			break;
		case 'G':
			if (sd->group_sid != NULL) goto failed;
			sd->group_sid = sddl_transition_decode_sid(sd, &sddl, &state);
			if (sd->group_sid == NULL) goto failed;
			break;
		default:
			*msg = talloc_strdup(mem_ctx, "unexpected character (expected [OGDS])");
			goto failed;
		}
	}
	return sd;
failed:
	if (*msg != NULL) {
		*msg = talloc_steal(mem_ctx, *msg);
	}
	/*
	 * The actual message (*msg) might still be NULL, but the
	 * offset at least provides a clue.
	 */
	*msg_offset += sddl - start;

	if (*msg_offset > strlen(sddl)) {
		/*
		 * It's not that we *don't* trust our pointer difference
		 * arithmetic, just that we *shouldn't*. Let's render it
		 * harmless, before Python tries printing 18 quadrillion
		 * spaces.
		 */
		DBG_WARNING("sddl error message offset %zu is too big\n",
			    *msg_offset);
		*msg_offset = 0;
	}
	DEBUG(2,("Badly formatted SDDL '%s'\n", sddl));
	talloc_free(sd);
	return NULL;
}


/*
  decode a security descriptor in SDDL format
*/
struct security_descriptor *sddl_decode(TALLOC_CTX *mem_ctx, const char *sddl,
					const struct dom_sid *domain_sid)
{
	const char *msg = NULL;
	size_t msg_offset = 0;
	struct security_descriptor *sd = sddl_decode_err_msg(mem_ctx,
							     sddl,
							     domain_sid,
							     ACE_CONDITION_FLAG_ALLOW_DEVICE,
							     &msg,
							     &msg_offset);
	if (sd == NULL) {
		DBG_NOTICE("could not decode '%s'\n", sddl);
		if (msg != NULL) {
			DBG_NOTICE("                  %*c\n",
				   (int)msg_offset, '^');
			DBG_NOTICE("error '%s'\n", msg);
			talloc_free(discard_const(msg));
		}
	}
	return sd;
}

/*
  turn a set of flags into a string
*/
static char *sddl_flags_to_string(TALLOC_CTX *mem_ctx, const struct flag_map *map,
				  uint32_t flags, bool check_all)
{
	int i;
	char *s;

	/* try to find an exact match */
	for (i=0;map[i].name;i++) {
		if (map[i].flag == flags) {
			return talloc_strdup(mem_ctx, map[i].name);
		}
	}

	s = talloc_strdup(mem_ctx, "");

	/* now by bits */
	for (i=0;map[i].name;i++) {
		if ((flags & map[i].flag) != 0) {
			s = talloc_asprintf_append_buffer(s, "%s", map[i].name);
			if (s == NULL) goto failed;
			flags &= ~map[i].flag;
		}
	}

	if (check_all && flags != 0) {
		goto failed;
	}

	return s;

failed:
	talloc_free(s);
	return NULL;
}

/*
  encode a sid in SDDL format
*/
static char *sddl_transition_encode_sid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
					struct sddl_transition_state *state)
{
	bool in_machine = dom_sid_in_domain(state->machine_sid, sid);
	bool in_domain = dom_sid_in_domain(state->domain_sid, sid);
	bool in_forest = dom_sid_in_domain(state->forest_sid, sid);
	struct dom_sid_buf buf;
	const char *sidstr = dom_sid_str_buf(sid, &buf);
	uint32_t rid = 0;
	size_t i;

	if (sid->num_auths > 1) {
		rid = sid->sub_auths[sid->num_auths-1];
	}

	for (i=0;i<ARRAY_SIZE(sid_codes);i++) {
		/* seen if its a well known sid */
		if (sid_codes[i].sid != NULL) {
			int cmp;

			cmp = strcmp(sidstr, sid_codes[i].sid);
			if (cmp != 0) {
				continue;
			}

			return talloc_strdup(mem_ctx, sid_codes[i].code);
		}

		if (rid == 0) {
			continue;
		}

		if (in_machine && sid_codes[i].machine_rid == rid) {
			return talloc_strdup(mem_ctx, sid_codes[i].code);
		}
		if (in_domain && sid_codes[i].domain_rid == rid) {
			return talloc_strdup(mem_ctx, sid_codes[i].code);
		}
		if (in_forest && sid_codes[i].forest_rid == rid) {
			return talloc_strdup(mem_ctx, sid_codes[i].code);
		}
	}

	return talloc_strdup(mem_ctx, sidstr);
}

char *sddl_encode_sid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
		      const struct dom_sid *domain_sid)
{
	struct sddl_transition_state state = {
		/*
		 * TODO: verify .machine_rid values really belong
		 * to the machine_sid on a member, once
		 * we pass machine_sid from the caller...
		 */
		.machine_sid = domain_sid,
		.domain_sid = domain_sid,
		.forest_sid = domain_sid,
	};
	return sddl_transition_encode_sid(mem_ctx, sid, &state);
}



/*
  encode an ACE in SDDL format
*/
static char *sddl_transition_encode_ace(TALLOC_CTX *mem_ctx, const struct security_ace *ace,
					struct sddl_transition_state *state)
{
	char *sddl = NULL;
	TALLOC_CTX *tmp_ctx;
	struct GUID_txt_buf object_buf, iobject_buf;
	const char *sddl_type="", *sddl_flags="", *sddl_mask="",
		*sddl_object="", *sddl_iobject="", *sddl_trustee="";
	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		DEBUG(0, ("talloc_new failed\n"));
		return NULL;
	}

	sddl_type = sddl_flags_to_string(tmp_ctx, ace_types, ace->type, true);
	if (sddl_type == NULL) {
		goto failed;
	}

	sddl_flags = sddl_flags_to_string(tmp_ctx, ace_flags, ace->flags,
					  true);
	if (sddl_flags == NULL) {
		goto failed;
	}

	sddl_mask = sddl_flags_to_string(tmp_ctx, ace_access_mask,
					 ace->access_mask, true);
	if (sddl_mask == NULL) {
		sddl_mask = sddl_match_file_rights(tmp_ctx,
				ace->access_mask);
		if (sddl_mask == NULL) {
			sddl_mask = talloc_asprintf(tmp_ctx, "0x%x",
						    ace->access_mask);
		}
		if (sddl_mask == NULL) {
			goto failed;
		}
	}

	if (sec_ace_object(ace->type)) {
		const struct security_ace_object *object = &ace->object.object;

		if (ace->object.object.flags & SEC_ACE_OBJECT_TYPE_PRESENT) {
			sddl_object = GUID_buf_string(
				&object->type.type, &object_buf);
		}

		if (ace->object.object.flags &
		    SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT) {
			sddl_iobject = GUID_buf_string(
				&object->inherited_type.inherited_type,
				&iobject_buf);
		}
	}
	sddl_trustee = sddl_transition_encode_sid(tmp_ctx, &ace->trustee, state);
	if (sddl_trustee == NULL) {
		goto failed;
	}

	if (sec_ace_callback(ace->type)) {
		/* encode the conditional part */
		struct ace_condition_script *s = NULL;
		const char *sddl_conditions = NULL;

		s = parse_conditional_ace(tmp_ctx, ace->coda.conditions);

		if (s == NULL) {
			goto failed;
		}

		sddl_conditions = sddl_from_conditional_ace(tmp_ctx, s);
		if (sddl_conditions == NULL) {
			goto failed;
		}

		sddl = talloc_asprintf(mem_ctx, "%s;%s;%s;%s;%s;%s;%s",
				       sddl_type, sddl_flags, sddl_mask,
				       sddl_object, sddl_iobject,
				       sddl_trustee, sddl_conditions);
	} else if (sec_ace_resource(ace->type)) {
		/* encode the resource part */
		const char *coda = NULL;
		coda = sddl_resource_attr_from_claim(tmp_ctx,
						     &ace->coda.claim);

		if (coda == NULL) {
			DBG_WARNING("resource ACE has invalid claim\n");
			goto failed;
		}
		sddl = talloc_asprintf(mem_ctx, "%s;%s;%s;%s;%s;%s;%s",
				       sddl_type, sddl_flags, sddl_mask,
				       sddl_object, sddl_iobject,
				       sddl_trustee, coda);
	} else {
		sddl = talloc_asprintf(mem_ctx, "%s;%s;%s;%s;%s;%s",
				       sddl_type, sddl_flags, sddl_mask,
				       sddl_object, sddl_iobject, sddl_trustee);
	}
failed:
	talloc_free(tmp_ctx);
	return sddl;
}

char *sddl_encode_ace(TALLOC_CTX *mem_ctx, const struct security_ace *ace,
		      const struct dom_sid *domain_sid)
{
	struct sddl_transition_state state = {
		/*
		 * TODO: verify .machine_rid values really belong
		 * to the machine_sid on a member, once
		 * we pass machine_sid from the caller...
		 */
		.machine_sid = domain_sid,
		.domain_sid = domain_sid,
		.forest_sid = domain_sid,
	};
	return sddl_transition_encode_ace(mem_ctx, ace, &state);
}

/*
  encode an ACL in SDDL format
*/
static char *sddl_encode_acl(TALLOC_CTX *mem_ctx, const struct security_acl *acl,
			     uint32_t flags, struct sddl_transition_state *state)
{
	char *sddl;
	uint32_t i;

	/* add any ACL flags */
	sddl = sddl_flags_to_string(mem_ctx, acl_flags, flags, false);
	if (sddl == NULL) goto failed;

	/* now the ACEs, encoded in braces */
	for (i=0;i<acl->num_aces;i++) {
		char *ace = sddl_transition_encode_ace(sddl, &acl->aces[i], state);
		if (ace == NULL) goto failed;
		sddl = talloc_asprintf_append_buffer(sddl, "(%s)", ace);
		if (sddl == NULL) goto failed;
		talloc_free(ace);
	}

	return sddl;

failed:
	talloc_free(sddl);
	return NULL;
}


/*
  encode a security descriptor to SDDL format
*/
char *sddl_encode(TALLOC_CTX *mem_ctx, const struct security_descriptor *sd,
		  const struct dom_sid *domain_sid)
{
	struct sddl_transition_state state = {
		/*
		 * TODO: verify .machine_rid values really belong
		 * to the machine_sid on a member, once
		 * we pass machine_sid from the caller...
		 */
		.machine_sid = domain_sid,
		.domain_sid = domain_sid,
		.forest_sid = domain_sid,
	};
	char *sddl;
	TALLOC_CTX *tmp_ctx;

	/* start with a blank string */
	sddl = talloc_strdup(mem_ctx, "");
	if (sddl == NULL) goto failed;

	tmp_ctx = talloc_new(sddl);
	if (tmp_ctx == NULL) {
		goto failed;
	}

	if (sd->owner_sid != NULL) {
		char *sid = sddl_transition_encode_sid(tmp_ctx, sd->owner_sid, &state);
		if (sid == NULL) goto failed;
		sddl = talloc_asprintf_append_buffer(sddl, "O:%s", sid);
		if (sddl == NULL) goto failed;
	}

	if (sd->group_sid != NULL) {
		char *sid = sddl_transition_encode_sid(tmp_ctx, sd->group_sid, &state);
		if (sid == NULL) goto failed;
		sddl = talloc_asprintf_append_buffer(sddl, "G:%s", sid);
		if (sddl == NULL) goto failed;
	}

	if ((sd->type & SEC_DESC_DACL_PRESENT) && sd->dacl != NULL) {
		char *acl = sddl_encode_acl(tmp_ctx, sd->dacl, sd->type, &state);
		if (acl == NULL) goto failed;
		sddl = talloc_asprintf_append_buffer(sddl, "D:%s", acl);
		if (sddl == NULL) goto failed;
	}

	if ((sd->type & SEC_DESC_SACL_PRESENT) && sd->sacl != NULL) {
		char *acl = sddl_encode_acl(tmp_ctx, sd->sacl, sd->type>>1, &state);
		if (acl == NULL) goto failed;
		sddl = talloc_asprintf_append_buffer(sddl, "S:%s", acl);
		if (sddl == NULL) goto failed;
	}

	talloc_free(tmp_ctx);
	return sddl;

failed:
	talloc_free(sddl);
	return NULL;
}
