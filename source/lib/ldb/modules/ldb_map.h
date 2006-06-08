/* 
   ldb database library - map backend

   Copyright (C) Jelmer Vernooij 2005
   	Development sponsored by the Google Summer of Code program

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
 * attributes need a definition as LDB is a lot less strict than LDAP 
 * (in other words, sending unknown attributes to an LDAP server hurts us, 
 * while returning too many attributes in ldb_search() doesn't)
 */

struct ldb_map_context;

struct ldb_map_attribute 
{
	const char *local_name; /* local name */

	enum ldb_map_attr_type { 
		MAP_IGNORE, /* Ignore this local attribute. Doesn't exist remotely.  */
		MAP_KEEP,   /* Keep as is. Same name locally and remotely. */
		MAP_RENAME, /* Simply rename the attribute. Name changes, data is the same */
		MAP_CONVERT, /* Rename + convert data */
		MAP_GENERATE /* Use generate function for generating new name/data. 
						Used for generating attributes based on 
						multiple remote attributes. */
	} type;
	
	/* if set, will be called for expressions that contain this attribute */
	struct ldb_parse_tree *(*convert_operator) (struct ldb_map_context *, TALLOC_CTX *ctx, const struct ldb_parse_tree *);	

	union { 
		struct {
			const char *remote_name;
		} rename;
		
		struct {
			const char *remote_name;
			struct ldb_val (*convert_local) (struct ldb_module *, TALLOC_CTX *, const struct ldb_val *);
			
			/* an entry can have convert_remote set to NULL, as long as there as an entry with the same local_name 
			 * that is non-NULL before it. */
			struct ldb_val (*convert_remote) (struct ldb_module *, TALLOC_CTX *, const struct ldb_val *);
		} convert;
	
		struct {
			/* Generate the local attribute from remote message */
			struct ldb_message_element *(*generate_local) (
					struct ldb_module *, 
					TALLOC_CTX *ctx, 
					const char *attr,
					const struct ldb_message *remote);

			/* Update remote message with information from local message */
			void (*generate_remote) (
					struct ldb_module *, 
					const char *local_attr,
					const struct ldb_message *local, 
					struct ldb_message *remote_mp,
					struct ldb_message *remote_fb);

			/* Name(s) for this attribute on the remote server. This is an array since 
			 * one local attribute's data can be split up into several attributes 
			 * remotely */
#define LDB_MAP_MAX_REMOTE_NAMES 10
			const char *remote_names[LDB_MAP_MAX_REMOTE_NAMES];
		} generate;
	} u;
};

#define LDB_MAP_MAX_SUBCLASSES 	10
#define LDB_MAP_MAX_MUSTS 		10
#define LDB_MAP_MAX_MAYS 		50
struct ldb_map_objectclass 
{
	const char *local_name;
	const char *remote_name;
	const char *base_classes[LDB_MAP_MAX_SUBCLASSES];
	const char *musts[LDB_MAP_MAX_MUSTS];
	const char *mays[LDB_MAP_MAX_MAYS];
};

struct ldb_map_context
{
	struct ldb_map_attribute *attribute_maps;
	/* NOTE: Always declare base classes first here */
	const struct ldb_map_objectclass *objectclass_maps;
	struct ldb_context *mapped_ldb;
};

#endif /* __LDB_MAP_H__ */
