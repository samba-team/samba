/* 
   Unix SMB/CIFS implementation.
   DCOM standard objects
   Copyright (C) Jelmer Vernooij					  2004.
   
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

#ifndef _DCOM_H /* _DCOM_H */
#define _DCOM_H 

struct dcom_class
{
	const char *name;
	const char *prog_id;
	struct GUID CLSID;

	/* List of IID's implemented */
	uint32 num_iids;
	struct GUID *IID;

	/* Pointers to functions this class implements */
	void **interfaces;
};

struct dcom_object 
{
	struct dcom_class *class;
	struct GUID oid;
	HYPER_T OXID;
	struct dcom_interface_pointer *interfaces;
	void *private_data;
};

struct dcom_interface_pointer
{
	struct dcom_object *object;
	struct dcerpc_interface_table *interface;
	struct GUID ipid;
};

#endif /* _DCOM_H */
