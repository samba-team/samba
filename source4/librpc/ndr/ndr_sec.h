/* 
   Unix SMB/CIFS implementation.

   definitions for marshalling/unmarshalling security descriptors
   and related structures

   Copyright (C) Andrew Tridgell 2003
   
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


/* a domain SID. Note that unlike Samba3 this contains a pointer,
   so you can't copy them using assignment */
struct dom_sid {
	uint8  sid_rev_num;             /**< SID revision number */
	uint8  num_auths;               /**< Number of sub-authorities */
	uint8  id_auth[6];              /**< Identifier Authority */
	uint32 *sub_auths;
};

/* use the same structure for dom_sid2 as dom_sid */
#define dom_sid2 dom_sid

/* an access control element */
struct security_ace {
	uint8 type;  /* xxxx_xxxx_ACE_TYPE - e.g allowed / denied etc */
	uint8 flags; /* xxxx_INHERIT_xxxx - e.g OBJECT_INHERIT_ACE */

	uint32 access_mask;

	/* the 'obj' part is present when type is XXXX_TYPE_XXXX_OBJECT */
	struct {
		uint32 flags;
		GUID object_guid;
		GUID inherit_guid;
	} *obj;

	struct dom_sid trustee;
};


/* a security ACL */
struct security_acl {
	uint16 revision;
	uint32 num_aces;

	struct security_ace *aces;
};


/* a security descriptor */
struct security_descriptor {
	uint8 revision;
	uint16 type;     /* SEC_DESC_xxxx flags */

	struct dom_sid *owner_sid; 
	struct dom_sid *group_sid;
	struct security_acl *sacl; /* system ACL */
	struct security_acl *dacl; /* user (discretionary) ACL */
};


/*
  a security descriptor encapsulated in a buffer.
  It is like this IDL:
  typedef struct {
       uint32 size;
       [size_is(size)] uint8 *buf;
  } sec_desc_buf;
*/
struct sec_desc_buf {
	uint32 size; /* the sd wire size - auto-generated */
	struct security_descriptor *sd;
};




/* query security descriptor */
struct smb_query_secdesc {
	struct {
		uint16 fnum;
		uint32 secinfo_flags;
	} in;
	struct {
		struct security_descriptor *sd;
	} out;
};

/* set security descriptor */
struct smb_set_secdesc {
	struct {
		uint16 fnum;
		uint32 secinfo_flags;
		struct security_descriptor *sd;
	} in;
};
