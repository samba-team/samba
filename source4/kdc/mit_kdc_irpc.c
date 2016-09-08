/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (c) 2015      Andreas Schneider <asn@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include "system/kerberos.h"
#include "source4/auth/kerberos/kerberos.h"
#include "auth/kerberos/pac_utils.h"

#include "librpc/gen_ndr/irpc.h"
#include "lib/messaging/irpc.h"
#include "source4/librpc/gen_ndr/ndr_irpc.h"
#include "source4/librpc/gen_ndr/irpc.h"

#include "librpc/gen_ndr/ndr_krb5pac.h"

#include "source4/smbd/process_model.h"
#include "lib/param/param.h"

#include "samba_kdc.h"
#include "db-glue.h"
#include "sdb.h"
#include "mit_kdc_irpc.h"

struct mit_kdc_irpc_context {
	struct task_server *task;
	krb5_context krb5_context;
	struct samba_kdc_db_context *db_ctx;
};

static NTSTATUS netr_samlogon_generic_logon(struct irpc_message *msg,
					    struct kdc_check_generic_kerberos *r)
{
	struct PAC_Validate pac_validate;
	DATA_BLOB pac_chksum;
	struct PAC_SIGNATURE_DATA pac_kdc_sig;
	struct mit_kdc_irpc_context *mki_ctx =
		talloc_get_type(msg->private_data,
				struct mit_kdc_irpc_context);
	enum ndr_err_code ndr_err;
	int code;
	krb5_principal principal;
	struct sdb_entry_ex sentry = {};
	struct sdb_keys skeys;
	unsigned int i;
	const uint8_t *d = NULL;

	/* There is no reply to this request */
	r->out.generic_reply = data_blob(NULL, 0);

	ndr_err =
		ndr_pull_struct_blob(&r->in.generic_request,
				     msg,
				     &pac_validate,
				     (ndr_pull_flags_fn_t)ndr_pull_PAC_Validate);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (pac_validate.MessageType != NETLOGON_GENERIC_KRB5_PAC_VALIDATE) {
		/*
		 * We don't implement any other message types - such as
		 * certificate validation - yet
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	if ((pac_validate.ChecksumAndSignature.length !=
	    (pac_validate.ChecksumLength + pac_validate.SignatureLength)) ||
	    (pac_validate.ChecksumAndSignature.length <
	     pac_validate.ChecksumLength) ||
	    (pac_validate.ChecksumAndSignature.length <
	     pac_validate.SignatureLength)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* PAC Checksum */
	pac_chksum = data_blob_const(pac_validate.ChecksumAndSignature.data,
				     pac_validate.ChecksumLength);

	/* Create the krbtgt principal */
	code = smb_krb5_make_principal(mki_ctx->krb5_context,
				      &principal,
				      lpcfg_realm(mki_ctx->task->lp_ctx),
				      "krbtgt",
				      lpcfg_realm(mki_ctx->task->lp_ctx),
				      NULL);
	if (code != 0) {
		DEBUG(0, ("Failed to create krbtgt@%s principal!\n",
			  lpcfg_realm(mki_ctx->task->lp_ctx)));
		return NT_STATUS_NO_MEMORY;
	}

	/* Get the krbtgt from the DB */
	code = samba_kdc_fetch(mki_ctx->krb5_context,
			       mki_ctx->db_ctx,
			       principal,
			       SDB_F_GET_KRBTGT | SDB_F_DECRYPT,
			       0,
			       &sentry);
	krb5_free_principal(mki_ctx->krb5_context, principal);
	if (code != 0) {
		DEBUG(0, ("Failed to fetch krbtgt@%s principal entry!\n",
			  lpcfg_realm(mki_ctx->task->lp_ctx)));
		return NT_STATUS_LOGON_FAILURE;
	}

	/* PAC Signature */
	pac_kdc_sig.type = pac_validate.SignatureType;

	d = &pac_validate.ChecksumAndSignature.data[pac_validate.ChecksumLength];
	pac_kdc_sig.signature =
		data_blob_const(d, pac_validate.SignatureLength);

	/*
	 * Brute force variant because MIT KRB5 doesn't provide a function like
	 * krb5_checksum_to_enctype().
	 */
	skeys = sentry.entry.keys;

	for (i = 0; i < skeys.len; i++) {
		krb5_keyblock krbtgt_keyblock = skeys.val[i].key;

		code = check_pac_checksum(pac_chksum,
					  &pac_kdc_sig,
					  mki_ctx->krb5_context,
					  &krbtgt_keyblock);
		if (code == 0) {
			break;
		}
	}

	sdb_free_entry(&sentry);

	if (code != 0) {
		return NT_STATUS_LOGON_FAILURE;
	}

	return NT_STATUS_OK;
}

NTSTATUS samba_setup_mit_kdc_irpc(struct task_server *task)
{
	struct samba_kdc_base_context base_ctx;
	struct mit_kdc_irpc_context *mki_ctx;
	NTSTATUS status;
	int code;

	mki_ctx = talloc_zero(task, struct mit_kdc_irpc_context);
	if (mki_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	mki_ctx->task = task;

	base_ctx.ev_ctx = task->event_ctx;
	base_ctx.lp_ctx = task->lp_ctx;

	/* db-glue.h */
	status = samba_kdc_setup_db_ctx(mki_ctx,
					&base_ctx,
					&mki_ctx->db_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	code = smb_krb5_init_context_basic(mki_ctx,
					   task->lp_ctx,
					   &mki_ctx->krb5_context);
	if (code != 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = IRPC_REGISTER(task->msg_ctx,
			       irpc,
			       KDC_CHECK_GENERIC_KERBEROS,
			       netr_samlogon_generic_logon,
			       mki_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	irpc_add_name(task->msg_ctx, "kdc_server");

	return status;
}
