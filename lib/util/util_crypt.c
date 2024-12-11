#include <replace.h>
#include "data_blob.h"
#include <talloc.h>
#include <crypt.h>
#include "util_crypt.h"


static int crypt_as_best_we_can(const char *phrase,
				const char *setting,
				const char **hashp)
{
	int ret = 0;
	const char *hash = NULL;

#if defined(HAVE_CRYPT_R) || defined(HAVE_CRYPT_RN)
	struct crypt_data crypt_data = {
		.initialized = 0        /* working storage used by crypt */
	};
#endif

	/*
	 * crypt_r() and crypt() may return a null pointer upon error
	 * depending on how libcrypt was configured, so we prefer
	 * crypt_rn() from libcrypt / libxcrypt which always returns
	 * NULL on error.
	 *
	 * POSIX specifies returning a null pointer and setting
	 * errno.
	 *
	 * RHEL 7 (which does not use libcrypt / libxcrypt) returns a
	 * non-NULL pointer from crypt_r() on success but (always?)
	 * sets errno during internal processing in the NSS crypto
	 * subsystem.
	 *
	 * By preferring crypt_rn we avoid the 'return non-NULL but
	 * set-errno' that we otherwise cannot tell apart from the
	 * RHEL 7 behaviour.
	 */
	errno = 0;

#ifdef HAVE_CRYPT_RN
	hash = crypt_rn(phrase, setting,
			&crypt_data,
			sizeof(crypt_data));
#elif HAVE_CRYPT_R
	hash = crypt_r(phrase, setting, &crypt_data);
#else
	/*
	 * No crypt_r falling back to crypt, which is NOT thread safe
	 * Thread safety MT-Unsafe race:crypt
	 */
	hash = crypt(phrase, setting);
#endif
	/*
	* On error, crypt() and crypt_r() may return a null pointer,
	* or a pointer to an invalid hash beginning with a '*'.
	*/
	ret = errno;
	errno = 0;
	if (hash == NULL || hash[0] == '*') {
		if (ret == 0) {
			/* this is annoying */
			ret = ENOTRECOVERABLE;
		}
	}

	*hashp = hash;
	return ret;
}


int talloc_crypt_blob(TALLOC_CTX *mem_ctx,
		      const char *phrase,
		      const char *setting,
		      DATA_BLOB *blob)
{
	const char *hash = NULL;
	int ret = crypt_as_best_we_can(phrase, setting, &hash);
	if (ret != 0) {
		blob->data = NULL;
		blob->length = 0;
		return ret;
	}
	blob->length = strlen(hash);
	blob->data = talloc_memdup(mem_ctx, hash, blob->length);
	if (blob->data == NULL) {
		return ENOMEM;
	}
	return 0;
}


char *talloc_crypt_errstring(TALLOC_CTX *mem_ctx, int error)
{
	char buf[1024];
	int err;
	if (error == ERANGE) {
		return talloc_strdup(
			mem_ctx,
			"Password exceeds maximum length allowed for crypt() hashing");
	}
	if (error == ENOTRECOVERABLE) {
		/* probably weird RHEL7 crypt, see crypt_as_best_we_can() */
		goto unknown;
	}

	err = strerror_r(error, buf, sizeof(buf));
	if (err != 0) {
		goto unknown;
	}
	return talloc_strndup(mem_ctx, buf, sizeof(buf));
unknown:
	return talloc_strdup(mem_ctx, "Unknown error");
}
