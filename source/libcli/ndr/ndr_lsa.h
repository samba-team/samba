/* 
   Unix SMB/CIFS implementation.

   definitions for marshalling/unmarshalling the lsa pipe

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

struct lsa_QosInfo {
	uint16 impersonation_level;
	uint8  context_mode;
	uint8  effective_only;
};

struct lsa_ObjectAttribute {
	const char *root_dir;
	const char *object_name;
	uint32 attributes;
	struct security_descriptor *sec_desc;
	struct lsa_QosInfo *sec_qos;
};

struct lsa_OpenPolicy {
	struct {
		const char *system_name;
		struct lsa_ObjectAttribute *attr;
		uint32 desired_access;
	} in;
	struct {
		struct policy_handle handle;
		NTSTATUS status;
	} out;
};
