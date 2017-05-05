/* 
   Unix SMB/CIFS implementation.
   ads sasl wrapping code
   Copyright (C) Stefan Metzmacher 2007
   
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

void ndr_print_ads_saslwrap_struct(struct ndr_print *ndr, const char *name, const struct ads_saslwrap *r)
{
	ndr_print_struct(ndr, name, "saslwrap");
	ndr->depth++;
	ndr_print_uint16(ndr, "wrap_type", r->wrap_type);
#ifdef HAVE_LDAP_SASL_WRAPPING
	ndr_print_ptr(ndr, "sbiod", r->sbiod);
#endif /* HAVE_LDAP_SASL_WRAPPING */
	ndr_print_ptr(ndr, "mem_ctx", r->mem_ctx);
	ndr_print_ptr(ndr, "wrap_ops", r->wrap_ops);
	ndr_print_ptr(ndr, "wrap_private_data", r->wrap_private_data);
	ndr_print_struct(ndr, name, "in");
	ndr->depth++;
	ndr_print_uint32(ndr, "ofs", r->in.ofs);
	ndr_print_uint32(ndr, "needed", r->in.needed);
	ndr_print_uint32(ndr, "left", r->in.left);
	ndr_print_uint32(ndr, "max_wrapped", r->in.max_wrapped);
	ndr_print_uint32(ndr, "min_wrapped", r->in.min_wrapped);
	ndr_print_uint32(ndr, "size", r->in.size);
	ndr_print_array_uint8(ndr, "buf", r->in.buf, r->in.size);
	ndr->depth--;
	ndr_print_struct(ndr, name, "out");
	ndr->depth++;
	ndr_print_uint32(ndr, "ofs", r->out.ofs);
	ndr_print_uint32(ndr, "left", r->out.left);
	ndr_print_uint32(ndr, "max_unwrapped", r->out.max_unwrapped);
	ndr_print_uint32(ndr, "sig_size", r->out.sig_size);
	ndr_print_uint32(ndr, "size", r->out.size);
	ndr_print_array_uint8(ndr, "buf", r->out.buf, r->out.size);
	ndr->depth--;
}

#ifdef HAVE_LDAP_SASL_WRAPPING

static int ads_saslwrap_setup(Sockbuf_IO_Desc *sbiod, void *arg)
{
	struct ads_saslwrap *wrap = (struct ads_saslwrap *)arg;

	wrap->sbiod	= sbiod;

	sbiod->sbiod_pvt = wrap;

	return 0;
}

static int ads_saslwrap_remove(Sockbuf_IO_Desc *sbiod)
{
	return 0;
}

static ber_slen_t ads_saslwrap_prepare_inbuf(struct ads_saslwrap *wrap)
{
	wrap->in.ofs	= 0;
	wrap->in.needed	= 0;
	wrap->in.left	= 0;
	wrap->in.size	= 4 + wrap->in.min_wrapped;
	wrap->in.buf	= talloc_array(wrap->mem_ctx,
				       uint8_t, wrap->in.size);
	if (!wrap->in.buf) {
		return -1;
	}

	return 0;
}

static ber_slen_t ads_saslwrap_grow_inbuf(struct ads_saslwrap *wrap)
{
	if (wrap->in.size == (4 + wrap->in.needed)) {
		return 0;
	}

	wrap->in.size	= 4 + wrap->in.needed;
	wrap->in.buf	= talloc_realloc(wrap->mem_ctx,
					 wrap->in.buf,
					 uint8_t, wrap->in.size);
	if (!wrap->in.buf) {
		return -1;
	}

	return 0;
}

static void ads_saslwrap_shrink_inbuf(struct ads_saslwrap *wrap)
{
	talloc_free(wrap->in.buf);

	wrap->in.buf	= NULL;
	wrap->in.size	= 0;
	wrap->in.ofs	= 0;
	wrap->in.needed	= 0;
	wrap->in.left	= 0;
}

static ber_slen_t ads_saslwrap_read(Sockbuf_IO_Desc *sbiod,
				    void *buf, ber_len_t len)
{
	struct ads_saslwrap *wrap =
			(struct ads_saslwrap *)sbiod->sbiod_pvt;
	ber_slen_t ret;

	/* If ofs < 4 it means we don't have read the length header yet */
	if (wrap->in.ofs < 4) {
		ret = ads_saslwrap_prepare_inbuf(wrap);
		if (ret < 0) return ret;

		ret = LBER_SBIOD_READ_NEXT(sbiod,
					   wrap->in.buf + wrap->in.ofs,
					   4 - wrap->in.ofs);
		if (ret <= 0) return ret;
		wrap->in.ofs += ret;

		if (wrap->in.ofs < 4) goto eagain;

		wrap->in.needed = RIVAL(wrap->in.buf, 0);
		if (wrap->in.needed > wrap->in.max_wrapped) {
			errno = EINVAL;
			return -1;
		}
		if (wrap->in.needed < wrap->in.min_wrapped) {
			errno = EINVAL;
			return -1;
		}

		ret = ads_saslwrap_grow_inbuf(wrap);
		if (ret < 0) return ret;
	}

	/*
	 * if there's more data needed from the remote end,
	 * we need to read more
	 */
	if (wrap->in.needed > 0) {
		ret = LBER_SBIOD_READ_NEXT(sbiod,
					   wrap->in.buf + wrap->in.ofs,
					   wrap->in.needed);
		if (ret <= 0) return ret;
		wrap->in.ofs += ret;
		wrap->in.needed -= ret;

		if (wrap->in.needed > 0) goto eagain;
	}

	/*
	 * if we have a complete packet and have not yet unwrapped it
	 * we need to call the mech specific unwrap() hook
	 */
	if (wrap->in.needed == 0 && wrap->in.left == 0) {
		ADS_STATUS status;
		status = wrap->wrap_ops->unwrap(wrap);
		if (!ADS_ERR_OK(status)) {
			errno = EACCES;
			return -1;
		}
	}

	/*
	 * if we have unwrapped data give it to the caller
	 */
	if (wrap->in.left > 0) {
		ret = MIN(wrap->in.left, len);
		memcpy(buf, wrap->in.buf + wrap->in.ofs, ret);
		wrap->in.ofs += ret;
		wrap->in.left -= ret;

		/*
		 * if no more is left shrink the inbuf,
		 * this will trigger reading a new SASL packet
		 * from the remote stream in the next call
		 */
		if (wrap->in.left == 0) {
			ads_saslwrap_shrink_inbuf(wrap);
		}

		return ret;
	}

	/*
	 * if we don't have anything for the caller yet,
	 * tell him to ask again
	 */
eagain:
	errno = EAGAIN;
	return -1;
}

static ber_slen_t ads_saslwrap_prepare_outbuf(struct ads_saslwrap *wrap,
					      uint32_t len)
{
	wrap->out.ofs	= 0;
	wrap->out.left	= 0;
	wrap->out.size	= 4 + wrap->out.sig_size + len;
	wrap->out.buf	= talloc_array(wrap->mem_ctx,
					       uint8_t, wrap->out.size);
	if (!wrap->out.buf) {
		return -1;
	}

	return 0;
}

static void ads_saslwrap_shrink_outbuf(struct ads_saslwrap *wrap)
{
	talloc_free(wrap->out.buf);

	wrap->out.buf	= NULL;
	wrap->out.size	= 0;
	wrap->out.ofs	= 0;
	wrap->out.left	= 0;
}

static ber_slen_t ads_saslwrap_write(Sockbuf_IO_Desc *sbiod,
				     void *buf, ber_len_t len)
{
	struct ads_saslwrap *wrap =
			(struct ads_saslwrap *)sbiod->sbiod_pvt;
	ber_slen_t ret, rlen;

	/* if the buffer is empty, we need to wrap in incoming buffer */
	if (wrap->out.left == 0) {
		ADS_STATUS status;

		if (len == 0) {
			errno = EINVAL;
			return -1;
		}

		rlen = MIN(len, wrap->out.max_unwrapped);

		ret = ads_saslwrap_prepare_outbuf(wrap, rlen);
		if (ret < 0) return ret;
		
		status = wrap->wrap_ops->wrap(wrap, (uint8_t *)buf, rlen);
		if (!ADS_ERR_OK(status)) {
			errno = EACCES;
			return -1;
		}

		RSIVAL(wrap->out.buf, 0, wrap->out.left - 4);
	} else {
		rlen = -1;
	}

	ret = LBER_SBIOD_WRITE_NEXT(sbiod,
				    wrap->out.buf + wrap->out.ofs,
				    wrap->out.left);
	if (ret <= 0) return ret;
	wrap->out.ofs += ret;
	wrap->out.left -= ret;

	if (wrap->out.left == 0) {
		ads_saslwrap_shrink_outbuf(wrap);
	}

	if (rlen > 0) return rlen;

	errno = EAGAIN;
	return -1;
}

static int ads_saslwrap_ctrl(Sockbuf_IO_Desc *sbiod, int opt, void *arg)
{
	struct ads_saslwrap *wrap =
			(struct ads_saslwrap *)sbiod->sbiod_pvt;
	int ret;

	switch (opt) {
	case LBER_SB_OPT_DATA_READY:
		if (wrap->in.left > 0) {
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

static int ads_saslwrap_close(Sockbuf_IO_Desc *sbiod)
{
	return 0;
}

static const Sockbuf_IO ads_saslwrap_sockbuf_io = {
	ads_saslwrap_setup,	/* sbi_setup */
	ads_saslwrap_remove,	/* sbi_remove */
	ads_saslwrap_ctrl,	/* sbi_ctrl */
	ads_saslwrap_read,	/* sbi_read */
	ads_saslwrap_write,	/* sbi_write */
	ads_saslwrap_close	/* sbi_close */
};

ADS_STATUS ads_setup_sasl_wrapping(struct ads_saslwrap *wrap, LDAP *ld,
				   const struct ads_saslwrap_ops *ops,
				   void *private_data)
{
	ADS_STATUS status;
	Sockbuf *sb;
	Sockbuf_IO *io = discard_const_p(Sockbuf_IO, &ads_saslwrap_sockbuf_io);
	int rc;

	rc = ldap_get_option(ld, LDAP_OPT_SOCKBUF, &sb);
	status = ADS_ERROR_LDAP(rc);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	/* setup the real wrapping callbacks */
	rc = ber_sockbuf_add_io(sb, io, LBER_SBIOD_LEVEL_TRANSPORT, wrap);
	status = ADS_ERROR_LDAP(rc);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	wrap->wrap_ops		= ops;
	wrap->wrap_private_data	= private_data;

	return ADS_SUCCESS;
}
#else
ADS_STATUS ads_setup_sasl_wrapping(struct ads_saslwrap *wrap, LDAP *ld,
				   const struct ads_saslwrap_ops *ops,
				   void *private_data)
{
	return ADS_ERROR_NT(NT_STATUS_NOT_SUPPORTED);
}
#endif /* HAVE_LDAP_SASL_WRAPPING */
