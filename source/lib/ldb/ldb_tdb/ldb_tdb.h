
#ifdef STANDALONE
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

	struct {
		struct ldb_message baseinfo;
		struct ldb_message indexlist;
		struct ldb_message attributes;
		struct ldb_message subclasses;

		struct {
			char *name;
			int flags;
		} last_attribute;
	} cache;

	/* error if an internal ldb+tdb error */
	const char *last_err_string;
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

/* well known attribute flags */
#define LTDB_FLAG_CASE_INSENSITIVE (1<<0)
#define LTDB_FLAG_INTEGER          (1<<1)
#define LTDB_FLAG_WILDCARD         (1<<2)
#define LTDB_FLAG_OBJECTCLASS      (1<<3)
#define LTDB_FLAG_HIDDEN           (1<<4)

/* The following definitions come from lib/ldb/ldb_tdb/ldb_cache.c  */

void ltdb_cache_free(struct ldb_module *module);
int ltdb_cache_load(struct ldb_module *module);
int ltdb_increase_sequence_number(struct ldb_module *module);
int ltdb_attribute_flags(struct ldb_module *module, const char *attr_name);

/* The following definitions come from lib/ldb/ldb_tdb/ldb_index.c  */

struct ldb_parse_tree;

int ltdb_search_indexed(struct ldb_module *module, 
			const char *base,
			enum ldb_scope scope,
			struct ldb_parse_tree *tree,
			const char * const attrs[], struct ldb_message ***res);
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
int ltdb_search_dn1(struct ldb_module *module, const char *dn, struct ldb_message *msg);
int ltdb_search_dn(struct ldb_module *module, char *dn,
		   const char * const attrs[], struct ldb_message ***res);
int ltdb_add_attr_results(struct ldb_module *module, struct ldb_message *msg,
			  const char * const attrs[], 
			  int *count, 
			  struct ldb_message ***res);
int ltdb_search_free(struct ldb_module *module, struct ldb_message **msgs);
int ltdb_search(struct ldb_module *module, const char *base,
		enum ldb_scope scope, const char *expression,
		const char * const attrs[], struct ldb_message ***res);

/* The following definitions come from lib/ldb/ldb_tdb/ldb_tdb.c  */
struct TDB_DATA ltdb_key(struct ldb_module *module, const char *dn);
int ltdb_store(struct ldb_module *module, const struct ldb_message *msg, int flgs);
int ltdb_delete_noindex(struct ldb_module *module, const char *dn);
int ltdb_modify_internal(struct ldb_module *module, const struct ldb_message *msg);

/* The following definitions come from lib/ldb/ldb_tdb/ldb_match.c  */
int ltdb_val_equal(struct ldb_module *module,
		  const char *attr_name,
		  const struct ldb_val *v1, const struct ldb_val *v2);
int ltdb_message_match(struct ldb_module *module, 
		      struct ldb_message *msg,
		      struct ldb_parse_tree *tree,
		      const char *base,
		      enum ldb_scope scope);

int ltdb_index_del_value(struct ldb_module *module, const char *dn, 
			 struct ldb_message_element *el, int v_idx);

