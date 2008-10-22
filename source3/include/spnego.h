/* 
   Unix SMB/CIFS implementation.

   RFC2478 Compliant SPNEGO implementation

   Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2003

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

#ifndef SAMBA_SPNEGO_H
#define SAMBA_SPNEGO_H

#define SPNEGO_DELEG_FLAG    0x01
#define SPNEGO_MUTUAL_FLAG   0x02
#define SPNEGO_REPLAY_FLAG   0x04
#define SPNEGO_SEQUENCE_FLAG 0x08
#define SPNEGO_ANON_FLAG     0x10
#define SPNEGO_CONF_FLAG     0x20
#define SPNEGO_INTEG_FLAG    0x40
#define SPNEGO_REQ_FLAG      0x80

#define SPNEGO_NEG_TOKEN_INIT 0
#define SPNEGO_NEG_TOKEN_TARG 1

/* some well known object IDs */
#define OID_SPNEGO "1.3.6.1.5.5.2"
#define OID_NTLMSSP "1.3.6.1.4.1.311.2.2.10"
#define OID_KERBEROS5_OLD "1.2.840.48018.1.2.2"
#define OID_KERBEROS5 "1.2.840.113554.1.2.2"

#define SPNEGO_NEG_RESULT_ACCEPT 0
#define SPNEGO_NEG_RESULT_INCOMPLETE 1
#define SPNEGO_NEG_RESULT_REJECT 2

/* not really ASN.1, but RFC 1964 */
#define TOK_ID_KRB_AP_REQ	(uchar*)"\x01\x00"
#define TOK_ID_KRB_AP_REP	(uchar*)"\x02\x00"
#define TOK_ID_KRB_ERROR	(uchar*)"\x03\x00"
#define TOK_ID_GSS_GETMIC	(uchar*)"\x01\x01"
#define TOK_ID_GSS_WRAP		(uchar*)"\x02\x01"

typedef enum _spnego_negResult {
	SPNEGO_ACCEPT_COMPLETED = 0,
	SPNEGO_ACCEPT_INCOMPLETE = 1,
	SPNEGO_REJECT = 2
} negResult_t;

typedef struct spnego_negTokenInit {
	const char **mechTypes;
	int reqFlags;
	DATA_BLOB mechToken;
	DATA_BLOB mechListMIC;
} negTokenInit_t;

typedef struct spnego_negTokenTarg {
	uint8 negResult;
	char *supportedMech;
	DATA_BLOB responseToken;
	DATA_BLOB mechListMIC;
} negTokenTarg_t;

typedef struct spnego_spnego {
	int type;
	negTokenInit_t negTokenInit;
	negTokenTarg_t negTokenTarg;
} SPNEGO_DATA;

#endif
