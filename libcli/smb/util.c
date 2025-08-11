/*
   Unix SMB/CIFS implementation.
   client file operations
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) James Myers 2003

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

#include "includes.h"
#include "libcli/smb/smb_common.h"
#include "system/filesys.h"
#include "lib/param/loadparm.h"
#include "lib/param/param.h"
#include "libcli/smb/smb2_negotiate_context.h"

const char *smb_protocol_types_string(enum protocol_types protocol)
{
	switch (protocol) {
	case PROTOCOL_DEFAULT:
		return "DEFAULT";
	case PROTOCOL_NONE:
		return "NONE";
	case PROTOCOL_CORE:
		return "CORE";
	case PROTOCOL_COREPLUS:
		return "COREPLUS";
	case PROTOCOL_LANMAN1:
		return "LANMAN1";
	case PROTOCOL_LANMAN2:
		return "LANMAN2";
	case PROTOCOL_NT1:
		return "NT1";
	case PROTOCOL_SMB2_02:
		return "SMB2_02";
	case PROTOCOL_SMB2_10:
		return "SMB2_10";
	case PROTOCOL_SMB3_00:
		return "SMB3_00";
	case PROTOCOL_SMB3_02:
		return "SMB3_02";
	case PROTOCOL_SMB3_11:
		return "SMB3_11";
	}

	return "Invalid protocol_types value";
}

/**
 Return a string representing a CIFS attribute for a file.
**/
char *attrib_string(TALLOC_CTX *mem_ctx, uint32_t attrib)
{
	size_t i, len;
	static const struct {
		char c;
		uint16_t attr;
	} attr_strs[] = {
		{'V', FILE_ATTRIBUTE_VOLUME},
		{'D', FILE_ATTRIBUTE_DIRECTORY},
		{'A', FILE_ATTRIBUTE_ARCHIVE},
		{'H', FILE_ATTRIBUTE_HIDDEN},
		{'S', FILE_ATTRIBUTE_SYSTEM},
		{'N', FILE_ATTRIBUTE_NORMAL},
		{'R', FILE_ATTRIBUTE_READONLY},
		{'d', FILE_ATTRIBUTE_DEVICE},
		{'t', FILE_ATTRIBUTE_TEMPORARY},
		{'s', FILE_ATTRIBUTE_SPARSE},
		{'r', FILE_ATTRIBUTE_REPARSE_POINT},
		{'c', FILE_ATTRIBUTE_COMPRESSED},
		{'o', FILE_ATTRIBUTE_OFFLINE},
		{'n', FILE_ATTRIBUTE_NONINDEXED},
		{'e', FILE_ATTRIBUTE_ENCRYPTED}
	};
	char *ret;

	ret = talloc_array(mem_ctx, char, ARRAY_SIZE(attr_strs)+1);
	if (!ret) {
		return NULL;
	}

	for (len=i=0; i<ARRAY_SIZE(attr_strs); i++) {
		if (attrib & attr_strs[i].attr) {
			ret[len++] = attr_strs[i].c;
		}
	}

	ret[len] = 0;

	talloc_set_name_const(ret, ret);

	return ret;
}

/****************************************************************************
 Map standard UNIX permissions onto wire representations.
****************************************************************************/

uint32_t unix_perms_to_wire(mode_t perms)
{
        unsigned int ret = 0;

        ret |= ((perms & S_IXOTH) ?  UNIX_X_OTH : 0);
        ret |= ((perms & S_IWOTH) ?  UNIX_W_OTH : 0);
        ret |= ((perms & S_IROTH) ?  UNIX_R_OTH : 0);
        ret |= ((perms & S_IXGRP) ?  UNIX_X_GRP : 0);
        ret |= ((perms & S_IWGRP) ?  UNIX_W_GRP : 0);
        ret |= ((perms & S_IRGRP) ?  UNIX_R_GRP : 0);
        ret |= ((perms & S_IXUSR) ?  UNIX_X_USR : 0);
        ret |= ((perms & S_IWUSR) ?  UNIX_W_USR : 0);
        ret |= ((perms & S_IRUSR) ?  UNIX_R_USR : 0);
#ifdef S_ISVTX
        ret |= ((perms & S_ISVTX) ?  UNIX_STICKY : 0);
#endif
#ifdef S_ISGID
        ret |= ((perms & S_ISGID) ?  UNIX_SET_GID : 0);
#endif
#ifdef S_ISUID
        ret |= ((perms & S_ISUID) ?  UNIX_SET_UID : 0);
#endif
        return ret;
}

/****************************************************************************
 Map wire permissions to standard UNIX.
****************************************************************************/

mode_t wire_perms_to_unix(uint32_t perms)
{
        mode_t ret = (mode_t)0;

        ret |= ((perms & UNIX_X_OTH) ? S_IXOTH : 0);
        ret |= ((perms & UNIX_W_OTH) ? S_IWOTH : 0);
        ret |= ((perms & UNIX_R_OTH) ? S_IROTH : 0);
        ret |= ((perms & UNIX_X_GRP) ? S_IXGRP : 0);
        ret |= ((perms & UNIX_W_GRP) ? S_IWGRP : 0);
        ret |= ((perms & UNIX_R_GRP) ? S_IRGRP : 0);
        ret |= ((perms & UNIX_X_USR) ? S_IXUSR : 0);
        ret |= ((perms & UNIX_W_USR) ? S_IWUSR : 0);
        ret |= ((perms & UNIX_R_USR) ? S_IRUSR : 0);
#ifdef S_ISVTX
        ret |= ((perms & UNIX_STICKY) ? S_ISVTX : 0);
#endif
#ifdef S_ISGID
        ret |= ((perms & UNIX_SET_GID) ? S_ISGID : 0);
#endif
#ifdef S_ISUID
        ret |= ((perms & UNIX_SET_UID) ? S_ISUID : 0);
#endif
        return ret;
}


/****************************************************************************
 * Return the file type from the wire filetype for UNIX extensions.
 *
 * This uses the fact that the unix file types are numbered from
 * FILE=0 to SOCKET=6. This is an accepted protocol element that will
 * never change.
 ****************************************************************************/

static const mode_t unix_filetypes[] =
	{S_IFREG, S_IFDIR, S_IFLNK, S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK};

mode_t wire_filetype_to_unix(uint32_t wire_type)
{
	if (wire_type >= ARRAY_SIZE(unix_filetypes)) {
		return (mode_t)0;
	}
	return unix_filetypes[wire_type];
}

uint32_t unix_filetype_to_wire(mode_t mode)
{
	mode_t type = mode & S_IFMT;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(unix_filetypes); i++) {
		if (type == unix_filetypes[i]) {
			return i;
		}
	}
	return UNIX_TYPE_UNKNOWN;
}

mode_t wire_mode_to_unix(uint32_t wire)
{
	uint32_t wire_type = (wire & UNIX_FILETYPE_MASK) >>
			     UNIX_FILETYPE_SHIFT;
	return wire_perms_to_unix(wire) | wire_filetype_to_unix(wire_type);
}

uint32_t unix_mode_to_wire(mode_t mode)
{
	uint32_t wire_type = unix_filetype_to_wire(mode);
	return unix_perms_to_wire(mode) | (wire_type << UNIX_FILETYPE_SHIFT);
}

bool smb_buffer_oob(uint32_t bufsize, uint32_t offset, uint32_t length)
{
	if ((offset + length < offset) || (offset + length < length)) {
		/* wrap */
		return true;
	}
	if ((offset > bufsize) || (offset + length > bufsize)) {
		/* overflow */
		return true;
	}
	return false;
}

/***********************************************************
 Common function for pushing strings, used by smb_bytes_push_str()
 and trans_bytes_push_str(). Only difference is the align_odd
 parameter setting.
***********************************************************/

static uint8_t *internal_bytes_push_str(uint8_t *buf, bool ucs2,
					const char *str, size_t str_len,
					bool align_odd,
					size_t *pconverted_size)
{
	TALLOC_CTX *frame = talloc_stackframe();
	size_t buflen;
	char *converted;
	size_t converted_size;

	/*
	 * This check prevents us from
	 * (re)alloc buf on a NULL TALLOC_CTX.
	 */
	if (buf == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	buflen = talloc_get_size(buf);

	if (ucs2 &&
	    ((align_odd && (buflen % 2 == 0)) ||
	     (!align_odd && (buflen % 2 == 1)))) {
		/*
		 * We're pushing into an SMB buffer, align odd
		 */
		buf = talloc_realloc(NULL, buf, uint8_t, buflen + 1);
		if (buf == NULL) {
			TALLOC_FREE(frame);
			return NULL;
		}
		buf[buflen] = '\0';
		buflen += 1;
	}

	if (!convert_string_talloc(frame, CH_UNIX,
				   ucs2 ? CH_UTF16LE : CH_DOS,
				   str, str_len, &converted,
				   &converted_size)) {
		TALLOC_FREE(buf);
		TALLOC_FREE(frame);
		return NULL;
	}

	buf = talloc_realloc(NULL, buf, uint8_t,
			     buflen + converted_size);
	if (buf == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	memcpy(buf + buflen, converted, converted_size);

	TALLOC_FREE(converted);

	if (pconverted_size) {
		*pconverted_size = converted_size;
	}

	TALLOC_FREE(frame);
	return buf;
}

/***********************************************************
 Push a string into an SMB buffer, with odd byte alignment
 if it's a UCS2 string.
***********************************************************/

uint8_t *smb_bytes_push_str(uint8_t *buf, bool ucs2,
			    const char *str, size_t str_len,
			    size_t *pconverted_size)
{
	return internal_bytes_push_str(buf, ucs2, str, str_len,
				       true, pconverted_size);
}

uint8_t *smb_bytes_push_bytes(uint8_t *buf, uint8_t prefix,
			      const uint8_t *bytes, size_t num_bytes)
{
	size_t buflen;

	/*
	 * This check prevents us from
	 * (re)alloc buf on a NULL TALLOC_CTX.
	 */
	if (buf == NULL) {
		return NULL;
	}
	buflen = talloc_get_size(buf);

	buf = talloc_realloc(NULL, buf, uint8_t,
			     buflen + 1 + num_bytes);
	if (buf == NULL) {
		return NULL;
	}
	buf[buflen] = prefix;
	memcpy(&buf[buflen+1], bytes, num_bytes);
	return buf;
}

/***********************************************************
 Same as smb_bytes_push_str(), but without the odd byte
 align for ucs2 (we're pushing into a param or data block).
 static for now, although this will probably change when
 other modules use async trans calls.
***********************************************************/

uint8_t *trans2_bytes_push_str(uint8_t *buf, bool ucs2,
			       const char *str, size_t str_len,
			       size_t *pconverted_size)
{
	return internal_bytes_push_str(buf, ucs2, str, str_len,
				       false, pconverted_size);
}

uint8_t *trans2_bytes_push_bytes(uint8_t *buf,
				 const uint8_t *bytes, size_t num_bytes)
{
	size_t buflen;

	if (buf == NULL) {
		return NULL;
	}
	buflen = talloc_get_size(buf);

	buf = talloc_realloc(NULL, buf, uint8_t,
			     buflen + num_bytes);
	if (buf == NULL) {
		return NULL;
	}
	memcpy(&buf[buflen], bytes, num_bytes);
	return buf;
}

static NTSTATUS internal_bytes_pull_str(TALLOC_CTX *mem_ctx, char **_str,
					bool ucs2, bool align_odd,
					const uint8_t *buf, size_t buf_len,
					const uint8_t *position,
					size_t *p_consumed)
{
	size_t pad = 0;
	size_t offset;
	char *str = NULL;
	size_t str_len = 0;
	bool ok;

	*_str = NULL;
	if (p_consumed != NULL) {
		*p_consumed = 0;
	}

	if (position < buf) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	offset = PTR_DIFF(position, buf);
	if (offset > buf_len) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	if (ucs2 &&
	    ((align_odd && (offset % 2 == 0)) ||
	     (!align_odd && (offset % 2 == 1)))) {
		pad += 1;
		offset += 1;
	}

	if (offset > buf_len) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	buf_len -= offset;
	buf += offset;

	if (ucs2) {
		buf_len = utf16_null_terminated_len_n(buf, buf_len);
	} else {
		size_t tmp = strnlen((const char *)buf, buf_len);
		if (tmp < buf_len) {
			tmp += 1;
		}
		buf_len = tmp;
	}

	ok = convert_string_talloc(mem_ctx,
				   ucs2 ? CH_UTF16LE : CH_DOS,
				   CH_UNIX,
				   buf, buf_len,
				   &str, &str_len);
	if (!ok) {
		return map_nt_error_from_unix_common(errno);
	}

	if (p_consumed != NULL) {
		*p_consumed = buf_len + pad;
	}
	*_str = str;
	return NT_STATUS_OK;
}

NTSTATUS smb_bytes_pull_str(TALLOC_CTX *mem_ctx, char **_str, bool ucs2,
			    const uint8_t *buf, size_t buf_len,
			    const uint8_t *position,
			    size_t *_consumed)
{
	return internal_bytes_pull_str(mem_ctx, _str, ucs2, true,
				       buf, buf_len, position, _consumed);
}

/**
 * @brief Translate SMB signing settings as string to an enum.
 *
 * @param[in]  str  The string to translate.
 *
 * @return A corresponding enum @smb_signing_setting translated from the string.
 */
enum smb_signing_setting smb_signing_setting_translate(const char *str)
{
	enum smb_signing_setting signing_state = SMB_SIGNING_REQUIRED;
	int32_t val = lpcfg_parse_enum_vals("client signing", str);

	if (val != INT32_MIN) {
		signing_state = val;
	}

	return signing_state;
}

/**
 * @brief Translate SMB encryption settings as string to an enum.
 *
 * @param[in]  str  The string to translate.
 *
 * @return A corresponding enum @smb_encryption_setting translated from the
 *         string.
 */
enum smb_encryption_setting smb_encryption_setting_translate(const char *str)
{
	enum smb_encryption_setting encryption_state = SMB_ENCRYPTION_REQUIRED;
	int32_t val = lpcfg_parse_enum_vals("client smb encrypt", str);

	if (val != INT32_MIN) {
		encryption_state = val;
	}

	return encryption_state;
}

static const struct enum_list enum_smb3_signing_algorithms[] = {
	{SMB2_SIGNING_AES128_GMAC, "AES-128-GMAC"},
	{SMB2_SIGNING_AES128_CMAC, "AES-128-CMAC"},
	{SMB2_SIGNING_HMAC_SHA256, "HMAC-SHA256"},
	{-1, NULL}
};

const char *smb3_signing_algorithm_name(uint16_t algo)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(enum_smb3_signing_algorithms); i++) {
		if (enum_smb3_signing_algorithms[i].value != algo) {
			continue;
		}

		return enum_smb3_signing_algorithms[i].name;
	}

	return NULL;
}

static const struct enum_list enum_smb3_encryption_algorithms[] = {
	{SMB2_ENCRYPTION_AES128_GCM, "AES-128-GCM"},
	{SMB2_ENCRYPTION_AES128_CCM, "AES-128-CCM"},
	{SMB2_ENCRYPTION_AES256_GCM, "AES-256-GCM"},
	{SMB2_ENCRYPTION_AES256_CCM, "AES-256-CCM"},
	{-1, NULL}
};

const char *smb3_encryption_algorithm_name(uint16_t algo)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(enum_smb3_encryption_algorithms); i++) {
		if (enum_smb3_encryption_algorithms[i].value != algo) {
			continue;
		}

		return enum_smb3_encryption_algorithms[i].name;
	}

	return NULL;
}

static int32_t parse_enum_val(const struct enum_list *e,
			      const char *param_name,
			      const char *param_value)
{
	struct parm_struct parm = {
		.label = param_name,
		.type = P_LIST,
		.p_class = P_GLOBAL,
		.enum_list = e,
	};
	int32_t ret = INT32_MIN;
	bool ok;

	ok = lp_set_enum_parm(&parm, param_value, &ret);
	if (!ok) {
		return INT32_MIN;
	}

	return ret;
}

struct smb311_capabilities smb311_capabilities_parse(const char *role,
				const char * const *signing_algos,
				const char * const *encryption_algos)
{
	struct smb311_capabilities c = {
		.signing = {
			.num_algos = 0,
		},
		.encryption = {
			.num_algos = 0,
		},
	};
	char sign_param[64] = { 0, };
	char enc_param[64] = { 0, };
	size_t ai;

	snprintf(sign_param, sizeof(sign_param),
		 "%s smb3 signing algorithms", role);
	snprintf(enc_param, sizeof(enc_param),
		 "%s smb3 encryption algorithms", role);

	for (ai = 0; signing_algos != NULL && signing_algos[ai] != NULL; ai++) {
		const char *algoname = signing_algos[ai];
		int32_t v32;
		uint16_t algo;
		size_t di;
		bool ignore = false;

		if (c.signing.num_algos >= SMB3_ENCRYTION_CAPABILITIES_MAX_ALGOS) {
			DBG_ERR("WARNING: Ignoring trailing value '%s' for parameter '%s'\n",
				  algoname, sign_param);
			continue;
		}

		v32 = parse_enum_val(enum_smb3_signing_algorithms,
				     sign_param, algoname);
		if (v32 == INT32_MAX) {
			continue;
		}
		algo = v32;

		for (di = 0; di < c.signing.num_algos; di++) {
			if (algo != c.signing.algos[di]) {
				continue;
			}

			ignore = true;
			break;
		}

		if (ignore) {
			DBG_ERR("WARNING: Ignoring duplicate value '%s' for parameter '%s'\n",
				  algoname, sign_param);
			continue;
		}

		c.signing.algos[c.signing.num_algos] = algo;
		c.signing.num_algos += 1;
	}

	for (ai = 0; encryption_algos != NULL && encryption_algos[ai] != NULL; ai++) {
		const char *algoname = encryption_algos[ai];
		int32_t v32;
		uint16_t algo;
		size_t di;
		bool ignore = false;

		if (c.encryption.num_algos >= SMB3_ENCRYTION_CAPABILITIES_MAX_ALGOS) {
			DBG_ERR("WARNING: Ignoring trailing value '%s' for parameter '%s'\n",
				  algoname, enc_param);
			continue;
		}

		v32 = parse_enum_val(enum_smb3_encryption_algorithms,
				     enc_param, algoname);
		if (v32 == INT32_MAX) {
			continue;
		}
		algo = v32;

		for (di = 0; di < c.encryption.num_algos; di++) {
			if (algo != c.encryption.algos[di]) {
				continue;
			}

			ignore = true;
			break;
		}

		if (ignore) {
			DBG_ERR("WARNING: Ignoring duplicate value '%s' for parameter '%s'\n",
				  algoname, enc_param);
			continue;
		}

		c.encryption.algos[c.encryption.num_algos] = algo;
		c.encryption.num_algos += 1;
	}

	return c;
}

NTSTATUS smb311_capabilities_check(const struct smb311_capabilities *c,
				   const char *debug_prefix,
				   int debug_lvl,
				   NTSTATUS error_status,
				   const char *role,
				   enum protocol_types protocol,
				   uint16_t sign_algo,
				   uint16_t cipher_algo)
{
	const struct smb3_signing_capabilities *sign_algos =
		&c->signing;
	const struct smb3_encryption_capabilities *ciphers =
		&c->encryption;
	bool found_signing = false;
	bool found_encryption = false;
	size_t i;

	for (i = 0; i < sign_algos->num_algos; i++) {
		if (sign_algo == sign_algos->algos[i]) {
			/*
			 * We found a match
			 */
			found_signing = true;
			break;
		}
	}

	for (i = 0; i < ciphers->num_algos; i++) {
		if (cipher_algo == SMB2_ENCRYPTION_NONE) {
			/*
			 * encryption not supported, we'll error out later
			 */
			found_encryption = true;
			break;
		}

		if (cipher_algo == ciphers->algos[i]) {
			/*
			 * We found a match
			 */
			found_encryption = true;
			break;
		}
	}

	if (!found_signing) {
		/*
		 * We negotiated a signing algo we don't allow,
		 * most likely for SMB < 3.1.1
		 */
		DEBUG(debug_lvl,("%s: "
		      "SMB3 signing algorithm[%u][%s] on dialect[%s] "
		      "not allowed by '%s smb3 signing algorithms' - %s.\n",
		      debug_prefix,
		      sign_algo,
		      smb3_signing_algorithm_name(sign_algo),
		      smb_protocol_types_string(protocol),
		      role,
		      nt_errstr(error_status)));
		return error_status;
	}

	if (!found_encryption) {
		/*
		 * We negotiated a cipher we don't allow,
		 * most likely for SMB 3.0 and 3.0.2
		 */
		DEBUG(debug_lvl,("%s: "
		      "SMB3 encryption algorithm[%u][%s] on dialect[%s] "
		      "not allowed by '%s smb3 encryption algorithms' - %s.\n",
		      debug_prefix,
		      cipher_algo,
		      smb3_encryption_algorithm_name(cipher_algo),
		      smb_protocol_types_string(protocol),
		      role,
		      nt_errstr(error_status)));
		return error_status;
	}

	return NT_STATUS_OK;
}

struct smb_transports smb_transports_parse(const char *param_name,
					   const char * const *transports)
{
	struct smb_transports ts = {
		.num_transports = 0,
	};
	size_t ti;

	for (ti = 0; transports != NULL && transports[ti] != NULL; ti++) {
		struct smb_transport t = {
			.type = SMB_TRANSPORT_TYPE_UNKNOWN,
		};
		bool ignore = false;
		size_t ei;
		bool ok = false;

		if (ts.num_transports >= SMB_TRANSPORTS_MAX_TRANSPORTS) {
			DBG_ERR("WARNING: Ignoring trailing value '%s' for parameter '%s'\n",
				transports[ti], param_name);
			continue;
		}

		ok = smb_transport_parse(transports[ti], &t);
		if (!ok) {
			DBG_ERR("WARNING: Ignoring invalid value '%s' for parameter '%s'\n",
				transports[ti], param_name);
			continue;
		}

		for (ei = 0; ei < ts.num_transports; ei++) {
			if (t.type != ts.transports[ei].type) {
				continue;
			}

			if (t.port != ts.transports[ei].port) {
				continue;
			}

			ignore = true;
			break;
		}

		if (ignore) {
			DBG_ERR("WARNING: Ignoring duplicate value '%s' for parameter '%s'\n",
				transports[ti], param_name);
			continue;
		}

		ts.transports[ts.num_transports] = t;
		ts.num_transports += 1;
	}

	return ts;
}
