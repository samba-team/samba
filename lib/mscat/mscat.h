/*
 * Copyright (c) 2016      Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _MSCAT_H
#define _MSCAT_H

#include <stdbool.h>
#include <talloc.h>
#include <gnutls/pkcs7.h>
#include <libtasn1.h>

enum mscat_mac_algorithm {
	MSCAT_MAC_UNKNOWN,
	MSCAT_MAC_NULL,
	MSCAT_MAC_MD5,
	MSCAT_MAC_SHA1,
	MSCAT_MAC_SHA256,
	MSCAT_MAC_SHA512
};

struct mscat_pkcs7;

struct mscat_pkcs7 *mscat_pkcs7_init(TALLOC_CTX *mem_ctx);

int mscat_pkcs7_import_catfile(struct mscat_pkcs7 *mp7,
			       const char *catfile);

int mscat_pkcs7_verify(struct mscat_pkcs7 *mp7,
		       const char *ca_file);

struct mscat_ctl;

struct mscat_ctl *mscat_ctl_init(TALLOC_CTX *mem_ctx);

int mscat_ctl_import(struct mscat_ctl *ctl,
		     struct mscat_pkcs7 *pkcs7);

int mscat_ctl_get_member_count(struct mscat_ctl *ctl);

enum mscat_checksum_type {
	MSCAT_CHECKSUM_STRING = 1,
	MSCAT_CHECKSUM_BLOB
};

struct mscat_ctl_member {
	struct {
		enum mscat_checksum_type type;
		union {
			const char *string;
			uint8_t *blob;
		};
		size_t size;
	} checksum;
	struct {
		const char *name;
		uint32_t flags;
	} file;
	struct {
		const char *value;
		uint32_t flags;
	} osattr;
	struct {
		const char *guid;
		uint32_t id;
	} info;
	struct {
		enum mscat_mac_algorithm type;
		uint8_t *digest;
		size_t digest_size;
	} mac;
};

int mscat_ctl_get_member(struct mscat_ctl *ctl,
			 TALLOC_CTX *mem_ctx,
			 unsigned int idx,
			 struct mscat_ctl_member **member);

int mscat_ctl_get_attribute_count(struct mscat_ctl *ctl);

struct mscat_ctl_attribute {
	const char *name;
	uint32_t flags;
	const char *value;
};

int mscat_ctl_get_attribute(struct mscat_ctl *ctl,
			    TALLOC_CTX *mem_ctx,
			    unsigned int idx,
			    struct mscat_ctl_attribute **pattribute);

#endif /* _MSCAT_H */
