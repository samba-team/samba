/* 
   Unix SMB/CIFS implementation.
   Parameter loading functions
   Copyright (C) Karl Auer 1993-1998

   Largely re-written by Andrew Tridgell, September 1994

   Copyright (C) Simo Sorce 2001
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) Stefan (metze) Metzmacher 2002
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007

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
#include "lib/param/param.h"
#include "libcli/raw/libcliraw.h"
#include "librpc/ndr/libndr.h"

void lpcfg_smbcli_options(struct loadparm_context *lp_ctx,
			 struct smbcli_options *options)
{
	options->max_xmit = lpcfg_max_xmit(lp_ctx);
	options->max_mux = lpcfg_max_mux(lp_ctx);
	options->use_spnego = lpcfg_nt_status_support(lp_ctx) && lpcfg_use_spnego(lp_ctx);
	options->signing = lpcfg_client_signing(lp_ctx);
	options->request_timeout = SMB_REQUEST_TIMEOUT;
	options->ntstatus_support = lpcfg_nt_status_support(lp_ctx);
	options->max_protocol = lpcfg__client_max_protocol(lp_ctx);
	options->unicode = lpcfg_unicode(lp_ctx);
	options->use_oplocks = true;
	options->use_level2_oplocks = true;
	options->smb2_capabilities = SMB2_CAP_ALL;
	options->client_guid = GUID_random();
}

void lpcfg_smbcli_session_options(struct loadparm_context *lp_ctx,
				 struct smbcli_session_options *options)
{
	options->lanman_auth = lpcfg_client_lanman_auth(lp_ctx);
	options->ntlmv2_auth = lpcfg_client_ntlmv2_auth(lp_ctx);
	options->plaintext_auth = lpcfg_client_plaintext_auth(lp_ctx);
}

