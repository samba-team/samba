/*
   Unix SMB/CIFS implementation.
   ads (active directory) utility library
   Copyright (C) Guenther Deschner 2005-2007
   Copyright (C) Gerald (Jerry) Carter 2006

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

#ifndef _LIBADS_LDAP_SCHEMA_OIDS_H_
#define _LIBADS_LDAP_SCHEMA_OIDS_H_

/* ldap attribute oids (Services for Unix 3.0, 3.5) */
#define ADS_ATTR_SFU_UIDNUMBER_OID 	"1.2.840.113556.1.6.18.1.310"
#define ADS_ATTR_SFU_GIDNUMBER_OID 	"1.2.840.113556.1.6.18.1.311"
#define ADS_ATTR_SFU_HOMEDIR_OID 	"1.2.840.113556.1.6.18.1.344"
#define ADS_ATTR_SFU_SHELL_OID 		"1.2.840.113556.1.6.18.1.312"
#define ADS_ATTR_SFU_GECOS_OID 		"1.2.840.113556.1.6.18.1.337"
#define ADS_ATTR_SFU_UID_OID            "1.2.840.113556.1.6.18.1.309"

/* ldap attribute oids (Services for Unix 2.0) */
#define ADS_ATTR_SFU20_UIDNUMBER_OID	"1.2.840.113556.1.4.7000.187.70"
#define ADS_ATTR_SFU20_GIDNUMBER_OID	"1.2.840.113556.1.4.7000.187.71"
#define ADS_ATTR_SFU20_HOMEDIR_OID	"1.2.840.113556.1.4.7000.187.106"
#define ADS_ATTR_SFU20_SHELL_OID	"1.2.840.113556.1.4.7000.187.72"
#define ADS_ATTR_SFU20_GECOS_OID 	"1.2.840.113556.1.4.7000.187.97"
#define ADS_ATTR_SFU20_UID_OID          "1.2.840.113556.1.4.7000.187.102"


/* ldap attribute oids (RFC2307) */
#define ADS_ATTR_RFC2307_UIDNUMBER_OID	"1.3.6.1.1.1.1.0"
#define ADS_ATTR_RFC2307_GIDNUMBER_OID	"1.3.6.1.1.1.1.1"
#define ADS_ATTR_RFC2307_HOMEDIR_OID	"1.3.6.1.1.1.1.3"
#define ADS_ATTR_RFC2307_SHELL_OID	"1.3.6.1.1.1.1.4"
#define ADS_ATTR_RFC2307_GECOS_OID	"1.3.6.1.1.1.1.2"
#define ADS_ATTR_RFC2307_UID_OID        "0.9.2342.19200300.100.1.1"

#endif
