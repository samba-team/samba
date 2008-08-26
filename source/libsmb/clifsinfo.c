/* 
   Unix SMB/CIFS implementation.
   FS info functions
   Copyright (C) Stefan (metze) Metzmacher	2003
   Copyright (C) Jeremy Allison 2007
   
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

/****************************************************************************
 Get UNIX extensions version info.
****************************************************************************/

bool cli_unix_extensions_version(struct cli_state *cli, uint16 *pmajor, uint16 *pminor,
                                        uint32 *pcaplow, uint32 *pcaphigh)
{
	bool ret = False;
	uint16 setup;
	char param[2];
	char *rparam=NULL, *rdata=NULL;
	unsigned int rparam_count=0, rdata_count=0;

	setup = TRANSACT2_QFSINFO;

	SSVAL(param,0,SMB_QUERY_CIFS_UNIX_INFO);

	if (!cli_send_trans(cli, SMBtrans2,
		    NULL,
		    0, 0,
		    &setup, 1, 0,
		    param, 2, 0,
		    NULL, 0, 560)) {
		goto cleanup;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
                              &rparam, &rparam_count,
                              &rdata, &rdata_count)) {
		goto cleanup;
	}

	if (cli_is_error(cli)) {
		ret = False;
		goto cleanup;
	} else {
		ret = True;
	}

	if (rdata_count < 12) {
		goto cleanup;
	}

	*pmajor = SVAL(rdata,0);
	*pminor = SVAL(rdata,2);
	cli->posix_capabilities = *pcaplow = IVAL(rdata,4);
	*pcaphigh = IVAL(rdata,8);

	/* todo: but not yet needed
	 *       return the other stuff
	 */

cleanup:
	SAFE_FREE(rparam);
	SAFE_FREE(rdata);

	return ret;
}

/****************************************************************************
 Set UNIX extensions capabilities.
****************************************************************************/

bool cli_set_unix_extensions_capabilities(struct cli_state *cli, uint16 major, uint16 minor,
                                        uint32 caplow, uint32 caphigh)
{
	bool ret = False;
	uint16 setup;
	char param[4];
	char data[12];
	char *rparam=NULL, *rdata=NULL;
	unsigned int rparam_count=0, rdata_count=0;

	setup = TRANSACT2_SETFSINFO;

	SSVAL(param,0,0);
	SSVAL(param,2,SMB_SET_CIFS_UNIX_INFO);

	SSVAL(data,0,major);
	SSVAL(data,2,minor);
	SIVAL(data,4,caplow);
	SIVAL(data,8,caphigh);

	if (!cli_send_trans(cli, SMBtrans2,
		    NULL,
		    0, 0,
		    &setup, 1, 0,
		    param, 4, 0,
		    data, 12, 560)) {
		goto cleanup;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
                              &rparam, &rparam_count,
                              &rdata, &rdata_count)) {
		goto cleanup;
	}

	if (cli_is_error(cli)) {
		ret = False;
		goto cleanup;
	} else {
		ret = True;
	}

cleanup:
	SAFE_FREE(rparam);
	SAFE_FREE(rdata);

	return ret;
}

bool cli_get_fs_attr_info(struct cli_state *cli, uint32 *fs_attr)
{
	bool ret = False;
	uint16 setup;
	char param[2];
	char *rparam=NULL, *rdata=NULL;
	unsigned int rparam_count=0, rdata_count=0;

	if (!cli||!fs_attr)
		smb_panic("cli_get_fs_attr_info() called with NULL Pionter!");

	setup = TRANSACT2_QFSINFO;

	SSVAL(param,0,SMB_QUERY_FS_ATTRIBUTE_INFO);

	if (!cli_send_trans(cli, SMBtrans2,
		    NULL,
		    0, 0,
		    &setup, 1, 0,
		    param, 2, 0,
		    NULL, 0, 560)) {
		goto cleanup;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
                              &rparam, &rparam_count,
                              &rdata, &rdata_count)) {
		goto cleanup;
	}

	if (cli_is_error(cli)) {
		ret = False;
		goto cleanup;
	} else {
		ret = True;
	}

	if (rdata_count < 12) {
		goto cleanup;
	}

	*fs_attr = IVAL(rdata,0);

	/* todo: but not yet needed
	 *       return the other stuff
	 */

cleanup:
	SAFE_FREE(rparam);
	SAFE_FREE(rdata);

	return ret;
}

bool cli_get_fs_volume_info_old(struct cli_state *cli, fstring volume_name, uint32 *pserial_number)
{
	bool ret = False;
	uint16 setup;
	char param[2];
	char *rparam=NULL, *rdata=NULL;
	unsigned int rparam_count=0, rdata_count=0;
	unsigned char nlen;

	setup = TRANSACT2_QFSINFO;

	SSVAL(param,0,SMB_INFO_VOLUME);

	if (!cli_send_trans(cli, SMBtrans2,
		    NULL,
		    0, 0,
		    &setup, 1, 0,
		    param, 2, 0,
		    NULL, 0, 560)) {
		goto cleanup;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
                              &rparam, &rparam_count,
                              &rdata, &rdata_count)) {
		goto cleanup;
	}

	if (cli_is_error(cli)) {
		ret = False;
		goto cleanup;
	} else {
		ret = True;
	}

	if (rdata_count < 5) {
		goto cleanup;
	}

	if (pserial_number) {
		*pserial_number = IVAL(rdata,0);
	}
	nlen = CVAL(rdata,l2_vol_cch);
	clistr_pull(cli, volume_name, rdata + l2_vol_szVolLabel, sizeof(fstring), nlen, STR_NOALIGN);

	/* todo: but not yet needed
	 *       return the other stuff
	 */

cleanup:
	SAFE_FREE(rparam);
	SAFE_FREE(rdata);

	return ret;
}

bool cli_get_fs_volume_info(struct cli_state *cli, fstring volume_name, uint32 *pserial_number, time_t *pdate)
{
	bool ret = False;
	uint16 setup;
	char param[2];
	char *rparam=NULL, *rdata=NULL;
	unsigned int rparam_count=0, rdata_count=0;
	unsigned int nlen;

	setup = TRANSACT2_QFSINFO;

	SSVAL(param,0,SMB_QUERY_FS_VOLUME_INFO);

	if (!cli_send_trans(cli, SMBtrans2,
		    NULL,
		    0, 0,
		    &setup, 1, 0,
		    param, 2, 0,
		    NULL, 0, 560)) {
		goto cleanup;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
                              &rparam, &rparam_count,
                              &rdata, &rdata_count)) {
		goto cleanup;
	}

	if (cli_is_error(cli)) {
		ret = False;
		goto cleanup;
	} else {
		ret = True;
	}

	if (rdata_count < 19) {
		goto cleanup;
	}

	if (pdate) {
		struct timespec ts;
		ts = interpret_long_date(rdata);
		*pdate = ts.tv_sec;
	}
	if (pserial_number) {
		*pserial_number = IVAL(rdata,8);
	}
	nlen = IVAL(rdata,12);
	clistr_pull(cli, volume_name, rdata + 18, sizeof(fstring), nlen, STR_UNICODE);

	/* todo: but not yet needed
	 *       return the other stuff
	 */

cleanup:
	SAFE_FREE(rparam);
	SAFE_FREE(rdata);

	return ret;
}

/******************************************************************************
 Send/receive the request encryption blob.
******************************************************************************/

static NTSTATUS enc_blob_send_receive(struct cli_state *cli, DATA_BLOB *in, DATA_BLOB *out, DATA_BLOB *param_out)
{
	uint16 setup;
	char param[4];
	char *rparam=NULL, *rdata=NULL;
	unsigned int rparam_count=0, rdata_count=0;
	NTSTATUS status = NT_STATUS_OK;

	setup = TRANSACT2_SETFSINFO;

	SSVAL(param,0,0);
	SSVAL(param,2,SMB_REQUEST_TRANSPORT_ENCRYPTION);

	if (!cli_send_trans(cli, SMBtrans2,
				NULL,
				0, 0,
				&setup, 1, 0,
				param, 4, 0,
				(char *)in->data, in->length, CLI_BUFFER_SIZE)) {
		status = cli_nt_error(cli);
		goto out;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
				&rparam, &rparam_count,
				&rdata, &rdata_count)) {
		status = cli_nt_error(cli);
		goto out;
	}

	if (cli_is_error(cli)) {
		status = cli_nt_error(cli);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			goto out;
		}
	}

	*out = data_blob(rdata, rdata_count);
	*param_out = data_blob(rparam, rparam_count);

  out:

	SAFE_FREE(rparam);
	SAFE_FREE(rdata);
	return status;
}

/******************************************************************************
 Make a client state struct.
******************************************************************************/

static struct smb_trans_enc_state *make_cli_enc_state(enum smb_trans_enc_type smb_enc_type)
{
	struct smb_trans_enc_state *es = NULL;
	es = SMB_MALLOC_P(struct smb_trans_enc_state);
	if (!es) {
		return NULL;
	}
	ZERO_STRUCTP(es);
	es->smb_enc_type = smb_enc_type;

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
	if (smb_enc_type == SMB_TRANS_ENC_GSS) {
		es->s.gss_state = SMB_MALLOC_P(struct smb_tran_enc_state_gss);
		if (!es->s.gss_state) {
			SAFE_FREE(es);
			return NULL;
		}
		ZERO_STRUCTP(es->s.gss_state);
	}
#endif
	return es;
}

/******************************************************************************
 Start a raw ntlmssp encryption.
******************************************************************************/

NTSTATUS cli_raw_ntlm_smb_encryption_start(struct cli_state *cli, 
				const char *user,
				const char *pass,
				const char *domain)
{
	DATA_BLOB blob_in = data_blob_null;
	DATA_BLOB blob_out = data_blob_null;
	DATA_BLOB param_out = data_blob_null;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	struct smb_trans_enc_state *es = make_cli_enc_state(SMB_TRANS_ENC_NTLM);

	if (!es) {
		return NT_STATUS_NO_MEMORY;
	}
	status = ntlmssp_client_start(&es->s.ntlmssp_state);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	ntlmssp_want_feature(es->s.ntlmssp_state, NTLMSSP_FEATURE_SESSION_KEY);
	es->s.ntlmssp_state->neg_flags |= (NTLMSSP_NEGOTIATE_SIGN|NTLMSSP_NEGOTIATE_SEAL);

	if (!NT_STATUS_IS_OK(status = ntlmssp_set_username(es->s.ntlmssp_state, user))) {
		goto fail;
	}
	if (!NT_STATUS_IS_OK(status = ntlmssp_set_domain(es->s.ntlmssp_state, domain))) {
		goto fail;
	}
	if (!NT_STATUS_IS_OK(status = ntlmssp_set_password(es->s.ntlmssp_state, pass))) {
		goto fail;
	}

	do {
		status = ntlmssp_update(es->s.ntlmssp_state, blob_in, &blob_out);
		data_blob_free(&blob_in);
		data_blob_free(&param_out);
		if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED) || NT_STATUS_IS_OK(status)) {
			NTSTATUS trans_status = enc_blob_send_receive(cli,
									&blob_out,
									&blob_in,
									&param_out);
			if (!NT_STATUS_EQUAL(trans_status,
					NT_STATUS_MORE_PROCESSING_REQUIRED) &&
					!NT_STATUS_IS_OK(trans_status)) {
				status = trans_status;
			} else {
				if (param_out.length == 2) {
					es->enc_ctx_num = SVAL(param_out.data, 0);
				}
			}
		}
		data_blob_free(&blob_out);
	} while (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED));

	data_blob_free(&blob_in);

	if (NT_STATUS_IS_OK(status)) {
		/* Replace the old state, if any. */
		if (cli->trans_enc_state) {
			common_free_encryption_state(&cli->trans_enc_state);
		}
		cli->trans_enc_state = es;
		cli->trans_enc_state->enc_on = True;
		es = NULL;
	}

  fail:

	common_free_encryption_state(&es);
	return status;
}

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)

#ifndef SMB_GSS_REQUIRED_FLAGS
#define SMB_GSS_REQUIRED_FLAGS (GSS_C_CONF_FLAG|GSS_C_INTEG_FLAG|GSS_C_MUTUAL_FLAG|GSS_C_REPLAY_FLAG|GSS_C_SEQUENCE_FLAG)
#endif

/******************************************************************************
 Get client gss blob to send to a server.
******************************************************************************/

static NTSTATUS make_cli_gss_blob(struct smb_trans_enc_state *es,
				const char *service,
				const char *host,
				NTSTATUS status_in,
				DATA_BLOB spnego_blob_in,
				DATA_BLOB *p_blob_out)
{
	const char *krb_mechs[] = {OID_KERBEROS5, NULL};
	OM_uint32 ret;
	OM_uint32 min;
	gss_name_t srv_name;
	gss_buffer_desc input_name;
	gss_buffer_desc *p_tok_in;
	gss_buffer_desc tok_out, tok_in;
	DATA_BLOB blob_out = data_blob_null;
	DATA_BLOB blob_in = data_blob_null;
	char *host_princ_s = NULL;
	OM_uint32 ret_flags = 0;
	NTSTATUS status = NT_STATUS_OK;

	gss_OID_desc nt_hostbased_service =
	{10, CONST_DISCARD(char *,"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04")};

	memset(&tok_out, '\0', sizeof(tok_out));

	/* Get a ticket for the service@host */
	if (asprintf(&host_princ_s, "%s@%s", service, host) == -1) {
		return NT_STATUS_NO_MEMORY;
	}

	input_name.value = host_princ_s;
	input_name.length = strlen(host_princ_s) + 1;

	ret = gss_import_name(&min,
				&input_name,
				&nt_hostbased_service,
				&srv_name);

	if (ret != GSS_S_COMPLETE) {
		SAFE_FREE(host_princ_s);
		return map_nt_error_from_gss(ret, min);
	}

	if (spnego_blob_in.length == 0) {
		p_tok_in = GSS_C_NO_BUFFER;
	} else {
		/* Remove the SPNEGO wrapper */
		if (!spnego_parse_auth_response(spnego_blob_in, status_in, OID_KERBEROS5, &blob_in)) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto fail;
		}
		tok_in.value = blob_in.data;
		tok_in.length = blob_in.length;
		p_tok_in = &tok_in;
	}

	ret = gss_init_sec_context(&min,
				GSS_C_NO_CREDENTIAL, /* Use our default cred. */
				&es->s.gss_state->gss_ctx,
				srv_name,
				GSS_C_NO_OID, /* default OID. */
				GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_DELEG_FLAG,
				GSS_C_INDEFINITE,	/* requested ticket lifetime. */
				NULL,   /* no channel bindings */
				p_tok_in,
				NULL,   /* ignore mech type */
				&tok_out,
				&ret_flags,
				NULL);  /* ignore time_rec */

	status = map_nt_error_from_gss(ret, min);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status,NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		ADS_STATUS adss = ADS_ERROR_GSS(ret, min);
		DEBUG(10,("make_cli_gss_blob: gss_init_sec_context failed with %s\n",
			ads_errstr(adss)));
		goto fail;
	}

	if ((ret_flags & SMB_GSS_REQUIRED_FLAGS) != SMB_GSS_REQUIRED_FLAGS) {
		status = NT_STATUS_ACCESS_DENIED;
	}

	blob_out = data_blob(tok_out.value, tok_out.length);

	/* Wrap in an SPNEGO wrapper */
	*p_blob_out = gen_negTokenTarg(krb_mechs, blob_out);

  fail:

	data_blob_free(&blob_out);
	data_blob_free(&blob_in);
	SAFE_FREE(host_princ_s);
	gss_release_name(&min, &srv_name);
	if (tok_out.value) {
		gss_release_buffer(&min, &tok_out);
	}
	return status;
}

/******************************************************************************
 Start a SPNEGO gssapi encryption context.
******************************************************************************/

NTSTATUS cli_gss_smb_encryption_start(struct cli_state *cli)
{
	DATA_BLOB blob_recv = data_blob_null;
	DATA_BLOB blob_send = data_blob_null;
	DATA_BLOB param_out = data_blob_null;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	fstring fqdn;
	const char *servicename;
	struct smb_trans_enc_state *es = make_cli_enc_state(SMB_TRANS_ENC_GSS);

	if (!es) {
		return NT_STATUS_NO_MEMORY;
	}

	name_to_fqdn(fqdn, cli->desthost);
	strlower_m(fqdn);

	servicename = "cifs";
	status = make_cli_gss_blob(es, servicename, fqdn, NT_STATUS_OK, blob_recv, &blob_send);
	if (!NT_STATUS_EQUAL(status,NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		servicename = "host";
		status = make_cli_gss_blob(es, servicename, fqdn, NT_STATUS_OK, blob_recv, &blob_send);
		if (!NT_STATUS_EQUAL(status,NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			goto fail;
		}
	}

	do {
		data_blob_free(&blob_recv);
		status = enc_blob_send_receive(cli, &blob_send, &blob_recv, &param_out);
		if (param_out.length == 2) {
			es->enc_ctx_num = SVAL(param_out.data, 0);
		}
		data_blob_free(&blob_send);
		status = make_cli_gss_blob(es, servicename, fqdn, status, blob_recv, &blob_send);
	} while (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED));
	data_blob_free(&blob_recv);

	if (NT_STATUS_IS_OK(status)) {
		/* Replace the old state, if any. */
		if (cli->trans_enc_state) {
			common_free_encryption_state(&cli->trans_enc_state);
		}
		cli->trans_enc_state = es;
		cli->trans_enc_state->enc_on = True;
		es = NULL;
	}

  fail:

	common_free_encryption_state(&es);
	return status;
}
#else
NTSTATUS cli_gss_smb_encryption_start(struct cli_state *cli)
{
	return NT_STATUS_NOT_SUPPORTED;
}
#endif

/********************************************************************
 Ensure a connection is encrypted.
********************************************************************/

NTSTATUS cli_force_encryption(struct cli_state *c,
			const char *username,
			const char *password,
			const char *domain)
{
	uint16 major, minor;
	uint32 caplow, caphigh;

	if (!SERVER_HAS_UNIX_CIFS(c)) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (!cli_unix_extensions_version(c, &major, &minor, &caplow, &caphigh)) {
		return NT_STATUS_UNKNOWN_REVISION;
	}

	if (!(caplow & CIFS_UNIX_TRANSPORT_ENCRYPTION_CAP)) {
		return NT_STATUS_UNSUPPORTED_COMPRESSION;
	}

	if (c->use_kerberos) {
		return cli_gss_smb_encryption_start(c);
	}
	return cli_raw_ntlm_smb_encryption_start(c,
					username,
					password,
					domain);
}
