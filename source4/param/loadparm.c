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
#include "libcli/smb/smb2_negotiate_context.h"

void lpcfg_smbcli_options(struct loadparm_context *lp_ctx,
			 struct smbcli_options *options)
{
	*options = (struct smbcli_options) {
		.max_xmit = lpcfg_max_xmit(lp_ctx),
		.max_mux = lpcfg_max_mux(lp_ctx),
		.use_spnego = lpcfg_nt_status_support(lp_ctx) && lpcfg_client_use_spnego(lp_ctx),
		.signing = lpcfg_client_signing(lp_ctx),
		.request_timeout = SMB_REQUEST_TIMEOUT,
		.ntstatus_support = lpcfg_nt_status_support(lp_ctx),
		.min_protocol = lpcfg_client_min_protocol(lp_ctx),
		.max_protocol = lpcfg__client_max_protocol(lp_ctx),
		.unicode = lpcfg_unicode(lp_ctx),
		.use_oplocks = true,
		.use_level2_oplocks = true,
		.smb2_capabilities = SMB2_CAP_ALL,
		.client_guid = GUID_random(),
		.max_credits = WINDOWS_CLIENT_PURE_SMB2_NEGPROT_INITIAL_CREDIT_ASK,
	};
}

void lpcfg_smbcli_session_options(struct loadparm_context *lp_ctx,
				 struct smbcli_session_options *options)
{
	*options = (struct smbcli_session_options) {
		.lanman_auth = lpcfg_client_lanman_auth(lp_ctx),
		.ntlmv2_auth = lpcfg_client_ntlmv2_auth(lp_ctx),
		.plaintext_auth = lpcfg_client_plaintext_auth(lp_ctx),
	};
}

