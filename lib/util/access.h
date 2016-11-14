/*
   This module is an adaption of code from the tcpd-1.4 package written
   by Wietse Venema, Eindhoven University of Technology, The Netherlands.

   The code is used here with permission.

   The code has been considerably changed from the original. Bug reports
   should be sent to samba-technical@lists.samba.org

   Updated for IPv6 by Jeremy Allison (C) 2007.
*/

#ifndef _UTIL_ACCESS_H_
#define _UTIL_ACCESS_H_

bool client_match(const char *tok, const void *item);
bool list_match(const char **list,const void *item,
		bool (*match_fn)(const char *, const void *));
bool allow_access_nolog(const char **deny_list,
		const char **allow_list,
		const char *cname,
		const char *caddr);
bool allow_access(const char **deny_list,
		const char **allow_list,
		const char *cname,
		const char *caddr);

#endif
