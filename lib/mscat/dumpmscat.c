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

#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include <talloc.h>

#include <libtasn1.h>
#include <gnutls/pkcs7.h>

#include "mscat.h"

static const char *mac_to_string(enum mscat_mac_algorithm algo) {
	switch(algo) {
		case MSCAT_MAC_NULL:
			return "NULL";
		case MSCAT_MAC_MD5:
			return "MD5";
		case MSCAT_MAC_SHA1:
			return "SHA1";
		case MSCAT_MAC_SHA256:
			return "SHA256";
		case MSCAT_MAC_SHA512:
			return "SHA512";
		case MSCAT_MAC_UNKNOWN:
			return "UNKNOWN";
	}

	return "UNKNOWN";
}

int main(int argc, char *argv[]) {
	TALLOC_CTX *mem_ctx;
	const char *filename = NULL;
	const char *ca_file = NULL;
	struct mscat_pkcs7 *cat_pkcs7;
	struct mscat_ctl *msctl;
	unsigned int member_count = 0;
	unsigned int attribute_count = 0;
	unsigned int i;
	int rc;

	if (argc < 1) {
		return -1;
	}
	filename = argv[1];

	if (filename == NULL || filename[0] == '\0') {
		return -1;
	}

	mem_ctx = talloc_init("dumpmscat");
	if (mem_ctx == NULL) {
		fprintf(stderr, "Failed to initialize talloc\n");
		exit(1);
	}

	/* READ MS ROOT CERTIFICATE */

	cat_pkcs7 = mscat_pkcs7_init(mem_ctx);
	if (cat_pkcs7 == NULL) {
		exit(1);
	}

	rc = mscat_pkcs7_import_catfile(cat_pkcs7,
					filename);
	if (rc != 0) {
		exit(1);
	}

	if (argc >= 2) {
		ca_file = argv[2];
	}

	rc = mscat_pkcs7_verify(cat_pkcs7, ca_file);
	if (rc != 0) {
		printf("FAILED TO VERIFY CATALOG FILE!\n");
		exit(1);
	}
	printf("CATALOG FILE VERIFIED!\n\n");

	msctl = mscat_ctl_init(mem_ctx);
	if (msctl == NULL) {
		exit(1);
	}

	rc = mscat_ctl_import(msctl, cat_pkcs7);
	if (rc < 0) {
		exit(1);
	}

	rc = mscat_ctl_get_member_count(msctl);
	if (rc < 0) {
		exit(1);
	}

	member_count = rc;
	printf("CATALOG MEMBER COUNT=%d\n", member_count);

	for (i = 0; i < member_count; i++) {
		struct mscat_ctl_member *m;
		size_t j;

		rc = mscat_ctl_get_member(msctl,
					  mem_ctx,
					  i + 1,
					  &m);
		if (rc != 0) {
			exit(1);
		}

		printf("CATALOG MEMBER\n");
		if (m->checksum.type == MSCAT_CHECKSUM_STRING) {
			printf("  CHECKSUM: %s\n", m->checksum.string);
		} else if (m->checksum.type == MSCAT_CHECKSUM_BLOB) {
			printf("  CHECKSUM: ");
			for (j = 0; j < m->checksum.size; j++) {
				printf("%X", m->checksum.blob[j]);
			}
			printf("\n");
		}
		printf("\n");

		if (m->file.name != NULL) {
			printf("  FILE: %s, FLAGS=0x%08x\n",
			       m->file.name,
			       m->file.flags);
		}

		if (m->info.guid != NULL) {
			printf("  GUID: %s, ID=0x%08x\n",
			       m->info.guid,
			       m->info.id);
		}

		if (m->osattr.value != NULL) {
			printf("  OSATTR: %s, FLAGS=0x%08x\n",
			       m->osattr.value,
			       m->osattr.flags);
		}

		if (m->mac.type != MSCAT_MAC_UNKNOWN) {
			printf("  MAC: %s, DIGEST: ",
			       mac_to_string(m->mac.type));
			for (j = 0; j < m->mac.digest_size; j++) {
				printf("%X", m->mac.digest[j]);
			}
			printf("\n");
		}
		printf("\n");
	}
	printf("\n");

	rc = mscat_ctl_get_attribute_count(msctl);
	if (rc < 0) {
		exit(1);
	}
	attribute_count = rc;
	printf("CATALOG ATTRIBUTE COUNT=%d\n", attribute_count);

	for (i = 0; i < attribute_count; i++) {
		struct mscat_ctl_attribute *a;

		rc = mscat_ctl_get_attribute(msctl,
					     mem_ctx,
					     i + 1,
					     &a);
		if (rc != 0) {
			exit(1);
		}

		printf("  NAME=%s, FLAGS=0x%08x, VALUE=%s\n",
		       a->name,
		       a->flags,
		       a->value);
	}
	talloc_free(mem_ctx);
	return 0;
}
