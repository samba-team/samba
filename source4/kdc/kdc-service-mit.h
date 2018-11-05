/*
   Unix SMB/CIFS implementation.

   Start MIT krb5kdc server within Samba AD

   Copyright (c) 2014      Andreas Schneider <asn@samba.org>

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

#ifndef _KDC_SERVICE_MIT_H
#define _KDC_SERVICE_MIT_H

NTSTATUS mitkdc_task_init(struct task_server *task);

#endif /* _KDC_SERVICE_MIT_H */
