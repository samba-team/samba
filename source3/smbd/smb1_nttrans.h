/*
   Unix SMB/CIFS implementation.
   SMB NT transaction handling
   Copyright (C) Jeremy Allison			1994-2007
   Copyright (C) Stefan (metze) Metzmacher	2003

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

void reply_ntcreate_and_X(struct smb_request *req);
void reply_ntcancel(struct smb_request *req);
void reply_ntrename(struct smb_request *req);
void reply_nttrans(struct smb_request *req);
void reply_nttranss(struct smb_request *req);
