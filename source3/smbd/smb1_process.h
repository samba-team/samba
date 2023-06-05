/*
   Unix SMB/CIFS implementation.
   process incoming packets - main loop
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Volker Lendecke 2005-2007

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

bool smb1_srv_send(struct smbXsrv_connection *xconn,
		   char *buffer,
		   bool do_signing,
		   uint32_t seqnum,
		   bool do_encrypt);
NTSTATUS allow_new_trans(struct trans_state *list, uint64_t mid);
void smb_request_done(struct smb_request *req);
const char *smb_fn_name(int type);
void add_to_common_flags2(uint32_t v);
void remove_from_common_flags2(uint32_t v);
bool smb1_is_chain(const uint8_t *buf);
bool smb1_walk_chain(const uint8_t *buf,
		     bool (*fn)(uint8_t cmd,
				uint8_t wct, const uint16_t *vwv,
				uint16_t num_bytes, const uint8_t *bytes,
				void *private_data),
		     void *private_data);
unsigned smb1_chain_length(const uint8_t *buf);
bool smb1_parse_chain(TALLOC_CTX *mem_ctx, const uint8_t *buf,
		      struct smbXsrv_connection *xconn,
		      bool encrypted, uint32_t seqnum,
		      struct smb_request ***reqs, unsigned *num_reqs);
bool req_is_in_chain(const struct smb_request *req);
bool fork_echo_handler(struct smbXsrv_connection *xconn);
NTSTATUS smb1_receive_talloc(TALLOC_CTX *mem_ctx,
			     struct smbXsrv_connection *xconn,
			     int sock,
			     char **buffer, unsigned int timeout,
			     size_t *p_unread, bool *p_encrypted,
			     size_t *p_len,
			     uint32_t *seqnum,
			     bool trusted_channel);
bool push_deferred_open_message_smb1(struct smb_request *req,
				     struct timeval timeout,
				     struct file_id id,
				     struct deferred_open_record *open_rec);
void process_smb1(struct smbXsrv_connection *xconn,
		  uint8_t *inbuf, size_t nread, size_t unread_bytes,
		  uint32_t seqnum, bool encrypted,
		  struct smb_perfcount_data *deferred_pcd);
void smbd_echo_init(struct smbXsrv_connection *xconn);
void construct_reply(struct smbXsrv_connection *xconn,
		     char *inbuf, int size, size_t unread_bytes,
		     uint32_t seqnum, bool encrypted,
		     struct smb_perfcount_data *deferred_pcd);
void smbd_smb1_server_connection_read_handler(struct smbXsrv_connection *xconn,
					      int fd);
bool keepalive_fn(const struct timeval *now, void *private_data);
