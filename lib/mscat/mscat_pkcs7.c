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
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <util/debug.h>
#include <util/data_blob.h>

#include "mscat.h"
#include "mscat_private.h"

#define PKCS7_CTL_OBJID                "1.3.6.1.4.1.311.10.1"

static int mscat_pkcs7_cleanup(struct mscat_pkcs7 *mp7)
{
	if (mp7->c != NULL) {
		gnutls_pkcs7_deinit(mp7->c);
	}

	return 0;
}

struct mscat_pkcs7 *mscat_pkcs7_init(TALLOC_CTX *mem_ctx)
{
	struct mscat_pkcs7 *pkcs7;
	int rc;

	pkcs7 = talloc_zero(mem_ctx, struct mscat_pkcs7);
	if (pkcs7 == NULL) {
		return NULL;
	}
	talloc_set_destructor(pkcs7, mscat_pkcs7_cleanup);

	rc = gnutls_pkcs7_init(&pkcs7->c);
	if (rc != 0) {
		talloc_free(pkcs7);
		return NULL;
	}

	return pkcs7;
}

static int mscat_read_file(TALLOC_CTX *mem_ctx,
			   const char *filename,
			   DATA_BLOB *pblob)
{
	struct stat sb = {0};
	size_t alloc_size;
	size_t count;
	DATA_BLOB blob = data_blob_null;
	FILE *fp;
	int rc;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		return -1;
	}

	rc = fstat(fileno(fp), &sb);
	if (rc != 0) {
		goto error;
	}

	if (!S_ISREG(sb.st_mode)) {
		errno = EINVAL;
		rc = -1;
		goto error;
	}
	if (SIZE_MAX - 1 < (unsigned long)sb.st_size) {
		errno = ENOMEM;
		rc = -1;
		goto error;
	}
	alloc_size = sb.st_size + 1;

	blob = data_blob_talloc_zero(mem_ctx, alloc_size);
	if (blob.data == NULL) {
		rc = -1;
		goto error;
	}

	count = fread(blob.data, 1, blob.length, fp);
	if (count != blob.length) {
		if (ferror(fp)) {
			rc = -1;
			goto error;
		}
	}
	blob.data[count] = '\0';
	blob.length = count;
	fclose(fp);

	*pblob = blob;

	return 0;
error:
	data_blob_free(&blob);
	fclose(fp);
	return rc;
}

int mscat_pkcs7_import_catfile(struct mscat_pkcs7 *mp7,
			       const char *catfile)
{
	TALLOC_CTX *tmp_ctx;
	gnutls_datum_t mscat_data = {
		.size = 0,
	};
	DATA_BLOB blob = {
		.length = 0,
	};
	int rc;

	tmp_ctx = talloc_new(mp7);
	if (tmp_ctx == NULL) {
		return -1;
	}

	rc = mscat_read_file(tmp_ctx,
			     catfile,
			     &blob);
	if (rc == -1) {
		DBG_ERR("Failed to read catalog file '%s' - %s",
			catfile,
			strerror(errno));
		goto done;
	}

	mscat_data.data = blob.data;
	mscat_data.size = blob.length;

	rc = gnutls_pkcs7_import(mp7->c,
				 &mscat_data,
				 GNUTLS_X509_FMT_DER);
	if (rc < 0) {
		DBG_ERR("Failed to import PKCS7 from '%s' - %s",
			catfile,
			gnutls_strerror(rc));
		goto done;
	}

	rc = 0;
done:
	talloc_free(tmp_ctx);
	return rc;
}

int mscat_pkcs7_verify(struct mscat_pkcs7 *mp7,
		       const char *ca_file)
{
	TALLOC_CTX *tmp_ctx = NULL;
	gnutls_x509_trust_list_t tl = NULL;
	gnutls_datum_t ca_data;
	DATA_BLOB blob = {
		.length = 0,
	};
	uint32_t flags = 0;
	const char *oid;
	int count;
	int cmp;
	int rc;
	int i;

	oid = gnutls_pkcs7_get_embedded_data_oid(mp7->c);
	if (oid == NULL) {
		DBG_ERR("Failed to get oid - %s",
			gnutls_strerror(errno));
		return -1;
	}

	cmp = strcmp(oid, PKCS7_CTL_OBJID);
	if (cmp != 0) {
		DBG_ERR("Invalid oid in catalog file! oid: %s, expected: %s",
			oid,
			PKCS7_CTL_OBJID);
		return -1;
	}

	tmp_ctx = talloc_new(mp7);
	if (tmp_ctx == NULL) {
		return -1;
	}

	rc = gnutls_x509_trust_list_init(&tl,
					 0); /* default size */
	if (rc != 0) {
		DBG_ERR("Failed to create trust list - %s",
			gnutls_strerror(rc));
		goto done;
	}


	/* Load the system trust list */
	rc = gnutls_x509_trust_list_add_system_trust(tl, 0, 0);
	if (rc < 0) {
		DBG_ERR("Failed to add system trust list - %s",
			gnutls_strerror(rc));
		goto done;
	}
	DBG_INFO("Loaded %d CAs", rc);

	if (ca_file != NULL) {
		rc = mscat_read_file(tmp_ctx,
				     ca_file,
				     &blob);
		if (rc != 0) {
			DBG_ERR("Failed to read CA file '%s' - %s",
				ca_file,
				strerror(errno));
			goto done;
		}

		ca_data.data = blob.data;
		ca_data.size = blob.length;

		rc = gnutls_x509_trust_list_add_trust_mem(tl,
							  &ca_data,
							  NULL, /* crls */
							  GNUTLS_X509_FMT_DER,
							  0, /* tl_flags */
							  0); /* tl_vflags */
		if (rc < 0) {
			DBG_ERR("Failed to add '%s' to trust list - %s (%d)",
				ca_file,
				gnutls_strerror(rc),
				rc);
			goto done;
		}
		DBG_INFO("Loaded %d additional CAs", rc);
	}

	/*
	 * Drivers often exist for quite some time, so it is possible that one
	 * of the certificates in the trust list expired.
	 * This is not a big deal, but we need to disable the time checks
	 * or the verification will fail.
	 */
	flags = GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS|
		GNUTLS_VERIFY_DISABLE_TIME_CHECKS;

#if GNUTLS_VERSION_NUMBER >= 0x030600
	/* The "Microsoft Root Authority" certificate uses SHA1 */
	flags |= GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1;
#endif

	count = gnutls_pkcs7_get_signature_count(mp7->c);
	if (count == 0) {
		DBG_ERR("Failed to verify catalog file, no signatures found");
		goto done;
	}

	for (i = 0; i < count; i++) {
		rc = gnutls_pkcs7_verify(mp7->c,
					 tl,
					 NULL, /* vdata */
					 0,    /* vdata_size */
					 i,    /* index */
					 NULL, /* data */
					 flags);   /* flags */
		if (rc < 0) {
			DBG_ERR("Failed to verify catalog file - %s (%d)",
				gnutls_strerror(rc),
				rc);
			goto done;
		}
	}

	rc = 0;
done:
	gnutls_x509_trust_list_deinit(tl, 1);
	talloc_free(tmp_ctx);
	return rc;
}
