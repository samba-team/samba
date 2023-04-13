/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Swen Schillig 2019
 *
 *   ** NOTE! The following LGPL license applies to this file.
 *   ** This does NOT imply that all of Samba is released
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
#include "smb_strtox.h"

/**
 * Convert a string to an unsigned long integer
 *
 * @param nptr		pointer to string which is to be converted
 * @param endptr	[optional] reference to remainder of the string
 * @param base		base of the numbering scheme
 * @param err		error occurred during conversion
 * @flags		controlling conversion feature
 * @result		result of the conversion as provided by strtoul
 *
 * The following flags are supported
 *	SMB_STR_STANDARD # raise error if negative or non-numeric
 *	SMB_STR_ALLOW_NEGATIVE # allow strings with a leading "-"
 *	SMB_STR_FULL_STR_CONV # entire string must be converted
 *	SMB_STR_ALLOW_NO_CONVERSION # allow empty strings or non-numeric
 *	SMB_STR_GLIBC_STANDARD # act exactly as the standard glibc strtoul
 *
 * The following errors are detected
 * - wrong base
 * - value overflow
 * - string with a leading "-" indicating a negative number
 * - no conversion due to empty string or not representing a number
 */
unsigned long int
smb_strtoul(const char *nptr, char **endptr, int base, int *err, int flags)
{
	unsigned long int val;
	int saved_errno = errno;
	char *needle = NULL;
	char *tmp_endptr = NULL;

	errno = 0;
	*err = 0;

	val = strtoul(nptr, &tmp_endptr, base);

	if (endptr != NULL) {
		*endptr = tmp_endptr;
	}

	if (errno != 0) {
		*err = errno;
		errno = saved_errno;
		return val;
	}

	if ((flags & SMB_STR_ALLOW_NO_CONVERSION) == 0) {
		/* got an invalid number-string resulting in no conversion */
		if (nptr == tmp_endptr) {
			*err = EINVAL;
			goto out;
		}
	}

	if ((flags & SMB_STR_ALLOW_NEGATIVE ) == 0) {
		/* did we convert a negative "number" ? */
		needle = strchr(nptr, '-');
		if (needle != NULL && needle < tmp_endptr) {
			*err = EINVAL;
			goto out;
		}
	}

	if ((flags & SMB_STR_FULL_STR_CONV) != 0) {
		/* did we convert the entire string ? */
		if (tmp_endptr[0] != '\0') {
			*err = EINVAL;
			goto out;
		}
	}

out:
	errno = saved_errno;
	return val;
}

/**
 * Convert a string to an unsigned long long integer
 *
 * @param nptr		pointer to string which is to be converted
 * @param endptr	[optional] reference to remainder of the string
 * @param base		base of the numbering scheme
 * @param err		error occurred during conversion
 * @flags		controlling conversion feature
 * @result		result of the conversion as provided by strtoull
 *
 * The following flags are supported
 *	SMB_STR_STANDARD # raise error if negative or non-numeric
 *	SMB_STR_ALLOW_NEGATIVE # allow strings with a leading "-"
 *	SMB_STR_FULL_STR_CONV # entire string must be converted
 *	SMB_STR_ALLOW_NO_CONVERSION # allow empty strings or non-numeric
 *	SMB_STR_GLIBC_STANDARD # act exactly as the standard glibc strtoul
 *
 * The following errors are detected
 * - wrong base
 * - value overflow
 * - string with a leading "-" indicating a negative number
 * - no conversion due to empty string or not representing a number
 */
unsigned long long int
smb_strtoull(const char *nptr, char **endptr, int base, int *err, int flags)
{
	unsigned long long int val;
	int saved_errno = errno;
	char *needle = NULL;
	char *tmp_endptr = NULL;

	errno = 0;
	*err = 0;

	val = strtoull(nptr, &tmp_endptr, base);

	if (endptr != NULL) {
		*endptr = tmp_endptr;
	}

	if (errno != 0) {
		*err = errno;
		errno = saved_errno;
		return val;
	}

	if ((flags & SMB_STR_ALLOW_NO_CONVERSION) == 0) {
		/* got an invalid number-string resulting in no conversion */
		if (nptr == tmp_endptr) {
			*err = EINVAL;
			goto out;
		}
	}

	if ((flags & SMB_STR_ALLOW_NEGATIVE ) == 0) {
		/* did we convert a negative "number" ? */
		needle = strchr(nptr, '-');
		if (needle != NULL && needle < tmp_endptr) {
			*err = EINVAL;
			goto out;
		}
	}

	if ((flags & SMB_STR_FULL_STR_CONV) != 0) {
		/* did we convert the entire string ? */
		if (tmp_endptr[0] != '\0') {
			*err = EINVAL;
			goto out;
		}
	}

out:
	errno = saved_errno;
	return val;
}
