/*
   Unix SMB/CIFS implementation.
   Headers for the async winbind client library
   Copyright (C) Kai Blin 2009

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

#ifndef _WBC_ASYNC_H_
#define _WBC_ASYNC_H_

#include "nsswitch/libwbclient/wbclient.h"

struct wb_context;

struct tevent_req *wb_trans_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct wb_context *wb_ctx, bool need_priv,
				 struct winbindd_request *wb_req);
wbcErr wb_trans_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		     struct winbindd_response **presponse);
struct wb_context *wb_context_init(TALLOC_CTX *mem_ctx);

/* Definitions from wb_reqtrans.c */
wbcErr map_wbc_err_from_errno(int error);

bool tevent_req_is_wbcerr(struct tevent_req *req, wbcErr *pwbc_err);
wbcErr tevent_req_simple_recv_wbcerr(struct tevent_req *req);

struct tevent_req *wb_req_read_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    int fd, size_t max_extra_data);
wbcErr wb_req_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			struct winbindd_request **preq);

struct tevent_req *wb_req_write_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct tevent_queue *queue, int fd,
				     struct winbindd_request *wb_req);
wbcErr wb_req_write_recv(struct tevent_req *req);

struct tevent_req *wb_resp_read_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev, int fd);
wbcErr wb_resp_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			 struct winbindd_response **presp);

struct tevent_req *wb_resp_write_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct tevent_queue *queue, int fd,
				      struct winbindd_response *wb_resp);
wbcErr wb_resp_write_recv(struct tevent_req *req);

#endif /*_WBC_ASYNC_H_*/
