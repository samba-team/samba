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

#ifdef HAVE_LDAP_SASL_WRAPPING

static int ads_saslwrap_setup(Sockbuf_IO_Desc *sbiod, void *arg)
{
	ADS_STRUCT *ads = (ADS_STRUCT *)arg;

	ads->ldap.sbiod	= sbiod;

	sbiod->sbiod_pvt = ads;

	return 0;
}

static int ads_saslwrap_remove(Sockbuf_IO_Desc *sbiod)
{
	return 0;
}

static ber_slen_t ads_saslwrap_read(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
	return LBER_SBIOD_READ_NEXT(sbiod, buf, len);
}

static ber_slen_t ads_saslwrap_write(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
	return LBER_SBIOD_WRITE_NEXT(sbiod, buf, len);
}


static int ads_saslwrap_ctrl(Sockbuf_IO_Desc *sbiod, int opt, void *arg)
{
	return LBER_SBIOD_CTRL_NEXT(sbiod, opt, arg);
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

ADS_STATUS ads_setup_sasl_wrapping(ADS_STRUCT *ads)
{
	ADS_STATUS status;
	Sockbuf *sb;
	Sockbuf_IO *io = discard_const_p(Sockbuf_IO, &ads_saslwrap_sockbuf_io);
	int rc;

	rc = ldap_get_option(ads->ldap.ld, LDAP_OPT_SOCKBUF, &sb);
	status = ADS_ERROR_LDAP(rc);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	/* debugging for the layer above SASL */
	rc = ber_sockbuf_add_io(sb, &ber_sockbuf_io_debug,
				LBER_SBIOD_LEVEL_TRANSPORT,
				(void *)"ads_sasl_wrapping_above");
	status = ADS_ERROR_LDAP(rc);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	/* setup the real wrapping callbacks */
	rc = ber_sockbuf_add_io(sb, io, LBER_SBIOD_LEVEL_TRANSPORT, ads);
	status = ADS_ERROR_LDAP(rc);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	/* debugging for the layer below SASL */
	rc = ber_sockbuf_add_io(sb, &ber_sockbuf_io_debug,
				LBER_SBIOD_LEVEL_TRANSPORT,
				(void *)"ads_sasl_wrapping_below");
	status = ADS_ERROR_LDAP(rc);
	if (!ADS_ERR_OK(status)) {
		return status;
	}

	return ADS_SUCCESS;
}

#endif /* HAVE_LDAP_SASL_WRAPPING */
