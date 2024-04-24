/*
   Unix SMB/CIFS implementation.
   ads tls wrapping code
   Copyright (C) Stefan Metzmacher 2024

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
#include "ads.h"
#include "lib/param/param.h"
#include "../source4/lib/tls/tls.h"

void ndr_print_ads_tlswrap_struct(struct ndr_print *ndr, const char *name, const struct ads_tlswrap *r)
{
	ndr_print_struct(ndr, name, "tlswrap");
	ndr->depth++;
	ndr_print_ptr(ndr, "mem_ctx", r->mem_ctx);
	ndr_print_timeval(ndr, "endtime", &r->endtime);
#ifdef HAVE_ADS
	ndr_print_ptr(ndr, "sbiod", r->sbiod);
	ndr_print_ptr(ndr, "tls_params", r->tls_params);
	ndr_print_ptr(ndr, "tls_sync", r->tls_sync);
#endif /* HAVE_ADS */
	ndr->depth--;
}

#ifdef HAVE_ADS

static int ads_tlswrap_setup(Sockbuf_IO_Desc *sbiod, void *arg)
{
	struct ads_tlswrap *wrap = (struct ads_tlswrap *)arg;

	wrap->sbiod = sbiod;

	sbiod->sbiod_pvt = wrap;

	return 0;
}

static int ads_tlswrap_remove(Sockbuf_IO_Desc *sbiod)
{
	struct ads_tlswrap *wrap =
			(struct ads_tlswrap *)sbiod->sbiod_pvt;

	wrap->sbiod = NULL;

	return 0;
}

static ssize_t ads_tlswrap_send_function(gnutls_transport_ptr_t ptr,
					 const uint8_t *buf, size_t size)
{
	struct ads_tlswrap *wrap = (struct ads_tlswrap *)ptr;

	if (wrap->endtime.tv_sec != 0) {
		if (timeval_expired(&wrap->endtime)) {
			errno = ECONNRESET;
			return -1;
		}
	}

	return LBER_SBIOD_WRITE_NEXT(wrap->sbiod, discard_const(buf), size);
}

static ssize_t ads_tlswrap_recv_function(gnutls_transport_ptr_t ptr,
					 uint8_t *buf, size_t size)
{
	struct ads_tlswrap *wrap = (struct ads_tlswrap *)ptr;

	if (wrap->endtime.tv_sec != 0) {
		if (timeval_expired(&wrap->endtime)) {
			errno = ECONNRESET;
			return -1;
		}
	}

	return LBER_SBIOD_READ_NEXT(wrap->sbiod, buf, size);
}

static ber_slen_t ads_tlswrap_read(Sockbuf_IO_Desc *sbiod,
				   void *buf, ber_len_t len)
{
	struct ads_tlswrap *wrap =
			(struct ads_tlswrap *)sbiod->sbiod_pvt;

	return tstream_tls_sync_read(wrap->tls_sync, buf, len);
}

static ber_slen_t ads_tlswrap_write(Sockbuf_IO_Desc *sbiod,
				    void *buf, ber_len_t len)
{
	struct ads_tlswrap *wrap =
			(struct ads_tlswrap *)sbiod->sbiod_pvt;

	return tstream_tls_sync_write(wrap->tls_sync, buf, len);
}

static int ads_tlswrap_ctrl(Sockbuf_IO_Desc *sbiod, int opt, void *arg)
{
	struct ads_tlswrap *wrap =
			(struct ads_tlswrap *)sbiod->sbiod_pvt;
	int ret;

	switch (opt) {
	case LBER_SB_OPT_DATA_READY:
		if (tstream_tls_sync_pending(wrap->tls_sync) > 0) {
			return 1;
		}

		ret = LBER_SBIOD_CTRL_NEXT(sbiod, opt, arg);
		break;
	default:
		ret = LBER_SBIOD_CTRL_NEXT(sbiod, opt, arg);
		break;
	}

	return ret;
}

static int ads_tlswrap_close(Sockbuf_IO_Desc *sbiod)
{
	struct ads_tlswrap *wrap =
			(struct ads_tlswrap *)sbiod->sbiod_pvt;

	TALLOC_FREE(wrap->tls_sync);
	TALLOC_FREE(wrap->tls_params);

	return 0;
}

static const Sockbuf_IO ads_tlswrap_sockbuf_io = {
	ads_tlswrap_setup,	/* sbi_setup */
	ads_tlswrap_remove,	/* sbi_remove */
	ads_tlswrap_ctrl,	/* sbi_ctrl */
	ads_tlswrap_read,	/* sbi_read */
	ads_tlswrap_write,	/* sbi_write */
	ads_tlswrap_close	/* sbi_close */
};

ADS_STATUS ads_setup_tls_wrapping(struct ads_tlswrap *wrap,
				  LDAP *ld,
				  const char *server_name)
{
	TALLOC_CTX *frame = talloc_stackframe();
	Sockbuf_IO *io = discard_const_p(Sockbuf_IO, &ads_tlswrap_sockbuf_io);
	Sockbuf *sb = NULL;
	struct loadparm_context *lp_ctx = NULL;
	ADS_STATUS status;
	NTSTATUS ntstatus;
	unsigned to;
	int rc;

	rc = ldap_get_option(ld, LDAP_OPT_SOCKBUF, &sb);
	status = ADS_ERROR_LDAP(rc);
	if (!ADS_ERR_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	lp_ctx = loadparm_init_s3(frame, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		TALLOC_FREE(frame);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	ntstatus = tstream_tls_params_client_lpcfg(wrap->mem_ctx,
						   lp_ctx,
						   server_name,
						   &wrap->tls_params);
	if (!NT_STATUS_IS_OK(ntstatus)) {
		TALLOC_FREE(frame);
		return ADS_ERROR_NT(ntstatus);
	}

	/* setup the real wrapping callbacks */
	rc = ber_sockbuf_add_io(sb, io, LBER_SBIOD_LEVEL_TRANSPORT, wrap);
	status = ADS_ERROR_LDAP(rc);
	if (!ADS_ERR_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	to = lpcfg_ldap_connection_timeout(lp_ctx);
	wrap->endtime = timeval_current_ofs(to, 0);
	ntstatus = tstream_tls_sync_setup(wrap->tls_params,
					  wrap,
					  ads_tlswrap_send_function,
					  ads_tlswrap_recv_function,
					  wrap->mem_ctx,
					  &wrap->tls_sync);
	wrap->endtime = timeval_zero();
	if (!NT_STATUS_IS_OK(ntstatus)) {
		ber_sockbuf_remove_io(sb, io, LBER_SBIOD_LEVEL_TRANSPORT);
		TALLOC_FREE(frame);
		return ADS_ERROR_NT(ntstatus);
	}

	TALLOC_FREE(frame);
	return ADS_SUCCESS;
}

const DATA_BLOB *ads_tls_channel_bindings(struct ads_tlswrap *wrap)
{
	if (wrap->tls_sync == NULL) {
		return NULL;
	}

	return tstream_tls_sync_channel_bindings(wrap->tls_sync);
}
#else
ADS_STATUS ads_setup_tls_wrapping(struct ads_tlswrap *wrap,
				  LDAP *ld,
				  const char *server_name)
{
	return ADS_ERROR_NT(NT_STATUS_NOT_SUPPORTED);
}
const DATA_BLOB *ads_tls_channel_bindings(struct ads_tlswrap *wrap)
{
	return NULL;
}
#endif /* HAVE_ADS */
