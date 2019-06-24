/*
 * Copyright (c) 2019      Andreas Schneider <asn@samba.org>
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

#include "includes.h"
#include "gnutls_helpers.h"

#include <gnutls/gnutls.h>

NTSTATUS _gnutls_error_to_ntstatus(int gnutls_rc,
				   NTSTATUS blocked_status,
				   const char *function,
				   const char *location)
{
	NTSTATUS status;

	if (gnutls_rc == GNUTLS_E_SUCCESS) {
		return NT_STATUS_OK;
	}

	switch (gnutls_rc) {
	case GNUTLS_E_UNWANTED_ALGORITHM:
		status = blocked_status;
		break;
	case GNUTLS_E_MEMORY_ERROR:
		status = NT_STATUS_NO_MEMORY;
		break;
	case GNUTLS_E_INVALID_REQUEST:
		status = NT_STATUS_INVALID_VARIANT;
		break;
	case GNUTLS_E_DECRYPTION_FAILED:
		status = NT_STATUS_DECRYPTION_FAILED;
		break;
	case GNUTLS_E_ENCRYPTION_FAILED:
		status = NT_STATUS_ENCRYPTION_FAILED;
		break;
	case GNUTLS_E_SHORT_MEMORY_BUFFER:
		status = NT_STATUS_INVALID_PARAMETER;
		break;
	case GNUTLS_E_BASE64_DECODING_ERROR:
	case GNUTLS_E_HASH_FAILED:
	case GNUTLS_E_LIB_IN_ERROR_STATE:
	case GNUTLS_E_INTERNAL_ERROR:
	default:
		status = NT_STATUS_INTERNAL_ERROR;
		break;
	}

	D_WARNING("%s: GNUTLS ERROR: %s, NTSTATUS: %s at %s\n",
		  function,
		  gnutls_strerror_name(gnutls_rc),
		  nt_errstr(status),
		  location);

	return status;
}

WERROR _gnutls_error_to_werror(int gnutls_rc,
			       WERROR blocked_werr,
			       const char *function,
			       const char *location)
{
	WERROR werr;

	if (gnutls_rc == GNUTLS_E_SUCCESS) {
		return WERR_OK;
	}

	switch (gnutls_rc) {
	case GNUTLS_E_UNWANTED_ALGORITHM:
		werr = blocked_werr;
		break;
	case GNUTLS_E_MEMORY_ERROR:
		werr = WERR_NOT_ENOUGH_MEMORY;
		break;
	case GNUTLS_E_INVALID_REQUEST:
		werr = WERR_INVALID_VARIANT;
		break;
	case GNUTLS_E_DECRYPTION_FAILED:
		werr = WERR_DECRYPTION_FAILED;
		break;
	case GNUTLS_E_ENCRYPTION_FAILED:
		werr = WERR_ENCRYPTION_FAILED;
		break;
	case GNUTLS_E_SHORT_MEMORY_BUFFER:
		werr = WERR_INVALID_PARAMETER;
		break;
	case GNUTLS_E_BASE64_DECODING_ERROR:
	case GNUTLS_E_HASH_FAILED:
	case GNUTLS_E_LIB_IN_ERROR_STATE:
	case GNUTLS_E_INTERNAL_ERROR:
	default:
		werr = WERR_INTERNAL_ERROR;
		break;
	}

	D_WARNING("%s: GNUTLS ERROR: %s, WERROR: %s at %s\n",
		  function,
		  gnutls_strerror_name(gnutls_rc),
		  win_errstr(werr),
		  location);

	return werr;
}
