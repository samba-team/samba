/*
   Unix SMB/CIFS implementation.

   SASL/EXTERNAL authentication.

   Copyright (C) Howard Chu <hyc@symas.com> 2013

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
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "auth/gensec/gensec_proto.h"
#include "auth/gensec/gensec_toplevel_proto.h"

/* SASL/EXTERNAL is essentially a no-op; it is only usable when the transport
 * layer is already mutually authenticated.
 */

NTSTATUS gensec_external_init(void);

static NTSTATUS gensec_external_start(struct gensec_security *gensec_security)
{
	if (gensec_security->want_features & GENSEC_FEATURE_SIGN)
		return NT_STATUS_INVALID_PARAMETER;
	if (gensec_security->want_features & GENSEC_FEATURE_SEAL)
		return NT_STATUS_INVALID_PARAMETER;

	return NT_STATUS_OK;
}

static NTSTATUS gensec_external_update(struct gensec_security *gensec_security,
				   TALLOC_CTX *out_mem_ctx,
				   struct tevent_context *ev,
				   const DATA_BLOB in, DATA_BLOB *out)
{
	*out = data_blob_talloc(out_mem_ctx, "", 0);
	return NT_STATUS_OK;
}

/* We have no features */
static bool gensec_external_have_feature(struct gensec_security *gensec_security,
				     uint32_t feature)
{
	return false;
}

static const struct gensec_security_ops gensec_external_ops = {
	.name             = "sasl-EXTERNAL",
	.sasl_name        = "EXTERNAL",
	.client_start     = gensec_external_start,
	.update 	  = gensec_external_update,
	.have_feature     = gensec_external_have_feature,
	.enabled          = true,
	.priority         = GENSEC_EXTERNAL
};


NTSTATUS gensec_external_init(void)
{
	NTSTATUS ret;

	ret = gensec_register(&gensec_external_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' gensec backend!\n",
			 gensec_external_ops.name));
	}
	return ret;
}
