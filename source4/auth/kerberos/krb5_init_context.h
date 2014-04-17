/* 
   Unix SMB/CIFS implementation.
   simple kerberos5 routines for active directory
   Copyright (C) Andrew Bartlett 2005
   
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

#ifndef _KRB5_INIT_CONTEXT_H_
#define _KRB5_INIT_CONTEXT_H_

struct smb_krb5_context {
	krb5_context krb5_context;
	void *pvt_log_data;
	struct tevent_context *current_ev;
};

struct tevent_context;
struct loadparm_context;

krb5_error_code
smb_krb5_init_context_basic(TALLOC_CTX *tmp_ctx,
			    struct loadparm_context *lp_ctx,
			    krb5_context *_krb5_context);

krb5_error_code smb_krb5_init_context(void *parent_ctx,
				      struct loadparm_context *lp_ctx,
				      struct smb_krb5_context **smb_krb5_context); 

#ifdef SAMBA4_USES_HEIMDAL
krb5_error_code smb_krb5_send_and_recv_func(krb5_context context,
					    void *data,
					    krb5_krbhst_info *hi,
					    time_t timeout,
					    const krb5_data *send_buf,
					    krb5_data *recv_buf);
krb5_error_code smb_krb5_context_set_event_ctx(struct smb_krb5_context *smb_krb5_context,
					       struct tevent_context *ev,
					       struct tevent_context **previous_ev);
krb5_error_code smb_krb5_context_remove_event_ctx(struct smb_krb5_context *smb_krb5_context,
						  struct tevent_context *previous_ev,
						  struct tevent_context *ev);
#endif

#endif /* _KRB5_INIT_CONTEXT_H_ */
