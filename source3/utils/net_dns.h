/*
   Samba Unix/Linux Dynamic DNS Update
   net ads commands

   Copyright (C) Krishna Ganugapati (krishnag@centeris.com)         2006
   Copyright (C) Gerald Carter                                      2006

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

#if defined(WITH_DNS_UPDATES)

#include "../lib/addns/dns.h"

DNS_ERROR DoDNSUpdate(char *pszServerName,
		      const char *pszDomainName, const char *pszHostName,
		      const struct sockaddr_storage *sslist,
		      size_t num_addrs );
DNS_ERROR do_gethostbyname(const char *server, const char *host);

#endif /* defined(WITH_DNS_UPDATES) */
