/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Andrew Tridgell              2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
  this header declares basic enumerated types
*/

/* protocol types. It assumes that higher protocols include lower protocols
   as subsets */
enum protocol_types {PROTOCOL_NONE,PROTOCOL_CORE,PROTOCOL_COREPLUS,PROTOCOL_LANMAN1,PROTOCOL_LANMAN2,PROTOCOL_NT1};

/* security levels */
enum security_types {SEC_SHARE,SEC_USER,SEC_SERVER,SEC_DOMAIN,SEC_ADS};

/* printing types */
enum printing_types {PRINT_BSD,PRINT_SYSV,PRINT_AIX,PRINT_HPUX,
		     PRINT_QNX,PRINT_PLP,PRINT_LPRNG,PRINT_SOFTQ,
		     PRINT_CUPS,PRINT_LPRNT,PRINT_LPROS2
#ifdef DEVELOPER
,PRINT_TEST,PRINT_VLP
#endif /* DEVELOPER */
};

/* LDAP schema types */
enum schema_types {SCHEMA_COMPAT, SCHEMA_AD, SCHEMA_SAMBA};

/* LDAP SSL options */
enum ldap_ssl_types {LDAP_SSL_ON, LDAP_SSL_OFF, LDAP_SSL_START_TLS};

/* LDAP PASSWD SYNC methods */
enum ldap_passwd_sync_types {LDAP_PASSWD_SYNC_ON, LDAP_PASSWD_SYNC_OFF, LDAP_PASSWD_SYNC_ONLY};

/* Remote architectures we know about. */
enum remote_arch_types {RA_UNKNOWN, RA_WFWG, RA_OS2, RA_WIN95, RA_WINNT, RA_WIN2K, RA_WINXP, RA_SAMBA};

/* case handling */
enum case_handling {CASE_LOWER,CASE_UPPER};

