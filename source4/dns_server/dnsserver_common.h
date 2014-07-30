/*
   Unix SMB/CIFS implementation.

   DNS server utils

   Copyright (C) 2014 Stefan Metzmacher

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

#ifndef __DNSSERVER_COMMON_H__
#define __DNSSERVER_COMMON_H__

uint8_t werr_to_dns_err(WERROR werr);
#define DNS_ERR(err_str) WERR_DNS_ERROR_RCODE_##err_str

#endif /* __DNSSERVER_COMMON_H__ */
