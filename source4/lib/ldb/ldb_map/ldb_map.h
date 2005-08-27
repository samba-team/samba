/* 
   ldb database library - map backend

   Copyright (C) Jelmer Vernooij 2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __LDB_MAP_H__
#define __LDB_MAP_H__

/* ldb_map is a skeleton LDB module that can be used for any other modules
 * that need to map attributes.
 *
 * The term 'remote' in this header refers to the connection where the 
 * original schema is used on while 'local' means the local connection 
 * that any upper layers will use.
 *
 * All local attributes will have to have a definition. Not all remote 
 * attributes need a definition as LDB is a lot less stricter then LDAP 
 * (in other words, sending unknown attributes to an LDAP server hurts us, 
 * returning too much attributes in ldb_search() doesn't)
 */

struct ldb_map_attribute 
{
	const char *local_name; /* local name */

	enum { 
		MAP_IGNORE, /* Ignore this local attribute. Doesn't exist remotely.  */
		MAP_KEEP,   /* Keep as is */
		MAP_RENAME, /* Simply rename the attribute. Name changes, data is the same */
		MAP_CONVERT, /* Rename + convert data */
		MAP_GENERATE /* Use generate function for generating new name/data. 
						Used for generating attributes based on 
						multiple remote attributes. */
	} type;
	
	/* if set, will be called for expressions that contain this attribute */
	struct ldb_parse_tree *(*convert_operator) (TALLOC_CTX *ctx, const struct ldb_parse_tree *);	

	union { 
		struct {
			const char *remote_name;
		} rename;
		
		struct {
			const char *remote_name;

			struct ldb_message_element *(*convert_local) (
				TALLOC_CTX *ctx, 
				const char *remote_attr,
				const struct ldb_message_element *);

			struct ldb_message_element *(*convert_remote) (
				TALLOC_CTX *ctx,
				const char *local_attr,
				const struct ldb_message_element *);
		} convert;
	
		struct {
			/* Generate the local attribute from remote message */
			struct ldb_message_element *(*generate_local) (
					TALLOC_CTX *ctx, 
					const char *attr, 
					const struct ldb_message *remote);

			/* Update remote message with information from local message */
			void (*generate_remote) (
					const char *local_attr,
					const struct ldb_message *local, 
					struct ldb_message *remote);

			/* Name(s) for this attribute on the remote server. This is an array since 
			 * one local attribute's data can be split up into several attributes 
			 * remotely */
#define LDB_MAP_MAX_REMOTE_NAMES 10
			const char *remote_names[LDB_MAP_MAX_REMOTE_NAMES];
		} generate;
	} u;
};

struct ldb_map_objectclass 
{
	const char *local_name;
	const char *remote_name;
};

#endif /* __LDB_MAP_H__ */
