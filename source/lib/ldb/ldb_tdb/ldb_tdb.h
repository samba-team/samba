
#ifdef _SAMBA_BUILD_
#include "system/filesys.h"
#include "lib/tdb/include/tdb.h"
#else
#include "tdb.h"
#endif

/* this private structure is used by the ltdb backend in the
   ldb_context */
struct ltdb_private {
	TDB_CONTEXT *tdb;
	unsigned int connect_flags;
	
	/* a double is used for portability and ease of string
	   handling. It has plenty of digits of precision */
	double sequence_number;

	struct ltdb_cache {
		struct ldb_message *baseinfo;
		struct ldb_message *indexlist;
		struct ldb_message *attributes;
		struct ldb_message *subclasses;

		struct {
			char *name;
			int flags;
		} last_attribute;
	} *cache;
};

/*
  the async local context
  holds also internal search state during a full db search
*/
struct ltdb_async_context {
	struct ldb_module *module;

	/* search stuff */
	struct ldb_parse_tree *tree;
	const struct ldb_dn *base;
	enum ldb_scope scope;
	const char * const *attrs;

	/* async stuff */
	void *context;
	int timeout;
	int (*callback)(struct ldb_context *, void *, struct ldb_async_result *);
};

/* special record types */
#define LTDB_INDEX      "@INDEX"
#define LTDB_INDEXLIST  "@INDEXLIST"
#define LTDB_IDX        "@IDX"
#define LTDB_IDXATTR    "@IDXATTR"
#define LTDB_BASEINFO   "@BASEINFO"
#define LTDB_ATTRIBUTES "@ATTRIBUTES"
#define LTDB_SUBCLASSES "@SUBCLASSES"

/* special attribute types */
#define LTDB_SEQUENCE_NUMBER "sequenceNumber"
#define LTDB_OBJECTCLASS "objectClass"

/* The following definitions come from lib/ldb/ldb_tdb/ldb_cache.c  */

int ltdb_cache_reload(struct ldb_module *module);
int ltdb_cache_load(struct ldb_module *module);
int ltdb_increase_sequence_number(struct ldb_module *module);
int ltdb_check_at_attributes_values(const struct ldb_val *value);

/* The following definitions come from lib/ldb/ldb_tdb/ldb_index.c  */

struct ldb_parse_tree;

int ltdb_search_indexed(struct ldb_async_handle *handle);
int ltdb_index_add(struct ldb_module *module, const struct ldb_message *msg);
int ltdb_index_del(struct ldb_module *module, const struct ldb_message *msg);
int ltdb_reindex(struct ldb_module *module);

/* The following definitions come from lib/ldb/ldb_tdb/ldb_pack.c  */

int ltdb_pack_data(struct ldb_module *module,
		   const struct ldb_message *message,
		   struct TDB_DATA *data);
void ltdb_unpack_data_free(struct ldb_module *module,
			   struct ldb_message *message);
int ltdb_unpack_data(struct ldb_module *module,
		     const struct TDB_DATA *data,
		     struct ldb_message *message);

/* The following definitions come from lib/ldb/ldb_tdb/ldb_search.c  */

int ltdb_has_wildcard(struct ldb_module *module, const char *attr_name, 
		      const struct ldb_val *val);
void ltdb_search_dn1_free(struct ldb_module *module, struct ldb_message *msg);
int ltdb_search_dn1(struct ldb_module *module, const struct ldb_dn *dn, struct ldb_message *msg);
int ltdb_add_attr_results(struct ldb_module *module,
 			  TALLOC_CTX *mem_ctx, 
			  struct ldb_message *msg,
			  const char * const attrs[], 
			  unsigned int *count, 
			  struct ldb_message ***res);
int ltdb_filter_attrs(struct ldb_message *msg, const char * const *attrs);
int ltdb_search_async(struct ldb_module *module, const struct ldb_dn *base,
		      enum ldb_scope scope, struct ldb_parse_tree *tree,
		      const char * const *attrs,
		      void *context,
		      int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
		      int timeout,
		      struct ldb_async_handle **handle);
int ltdb_search_bytree(struct ldb_module *module, const struct ldb_dn *base,
		       enum ldb_scope scope, struct ldb_parse_tree *tree,
		       const char * const attrs[], struct ldb_result **res);


/* The following definitions come from lib/ldb/ldb_tdb/ldb_tdb.c  */
struct ldb_async_handle *init_ltdb_handle(struct ltdb_private *ltdb, struct ldb_module *module,
					  void *context,
					  int (*callback)(struct ldb_context *, void *, struct ldb_async_result *),
					  int timeout);
struct TDB_DATA ltdb_key(struct ldb_module *module, const struct ldb_dn *dn);
int ltdb_store(struct ldb_module *module, const struct ldb_message *msg, int flgs);
int ltdb_delete_noindex(struct ldb_module *module, const struct ldb_dn *dn);
int ltdb_modify_internal(struct ldb_module *module, const struct ldb_message *msg);

int ltdb_index_del_value(struct ldb_module *module, const char *dn, 
			 struct ldb_message_element *el, int v_idx);

struct tdb_context *ltdb_wrap_open(TALLOC_CTX *mem_ctx,
				   const char *path, int hash_size, int tdb_flags,
				   int open_flags, mode_t mode);

