/*
   Unix SMB/CIFS implementation.
   Main SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett      2001
   Copyright (C) Jeremy Allison 1992-2007.
   Copyright (C) Volker Lendecke 2007

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

void reply_tcon(struct smb_request *req);
void reply_tcon_and_X(struct smb_request *req);
void reply_unknown_new(struct smb_request *req, uint8_t type);
void reply_ioctl(struct smb_request *req);
void reply_checkpath(struct smb_request *req);
void reply_getatr(struct smb_request *req);
void reply_setatr(struct smb_request *req);
void reply_dskattr(struct smb_request *req);
void reply_search(struct smb_request *req);
void reply_fclose(struct smb_request *req);
void reply_open(struct smb_request *req);
void reply_open_and_X(struct smb_request *req);
void reply_ulogoffX(struct smb_request *req);
void reply_mknew(struct smb_request *req);
void reply_ctemp(struct smb_request *req);
void reply_unlink(struct smb_request *req);
void reply_readbraw(struct smb_request *req);
void reply_lockread(struct smb_request *req);
size_t setup_readX_header(char *outbuf, size_t smb_maxcnt);
void reply_read(struct smb_request *req);
void reply_read_and_X(struct smb_request *req);
void error_to_writebrawerr(struct smb_request *req);
void reply_writebraw(struct smb_request *req);
void reply_writeunlock(struct smb_request *req);
void reply_write(struct smb_request *req);
bool is_valid_writeX_buffer(struct smbXsrv_connection *xconn,
			    const uint8_t *inbuf);
void reply_write_and_X(struct smb_request *req);
void reply_lseek(struct smb_request *req);
void reply_flush(struct smb_request *req);
void reply_exit(struct smb_request *req);
void reply_close(struct smb_request *req);
void reply_writeclose(struct smb_request *req);
void reply_lock(struct smb_request *req);
void reply_unlock(struct smb_request *req);
void reply_tdis(struct smb_request *req);
void reply_echo(struct smb_request *req);
void reply_printopen(struct smb_request *req);
void reply_printclose(struct smb_request *req);
void reply_printqueue(struct smb_request *req);
void reply_printwrite(struct smb_request *req);
void reply_mkdir(struct smb_request *req);
void reply_rmdir(struct smb_request *req);
void reply_mv(struct smb_request *req);
void reply_copy(struct smb_request *req);
uint64_t get_lock_pid(const uint8_t *data, int data_offset,
		    bool large_file_format);
uint64_t get_lock_count(const uint8_t *data, int data_offset,
			bool large_file_format);
void reply_lockingX(struct smb_request *req);
void reply_readbmpx(struct smb_request *req);
void reply_readbs(struct smb_request *req);
void reply_setattrE(struct smb_request *req);
void reply_writebmpx(struct smb_request *req);
void reply_writebs(struct smb_request *req);
void reply_getattrE(struct smb_request *req);
void reply_findclose(struct smb_request *req);
void reply_findnclose(struct smb_request *req);
