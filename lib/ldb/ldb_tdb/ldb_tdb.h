#include "replace.h"
#include "system/filesys.h"
#include "system/time.h"
#include "tdb.h"
#include "ldb_module.h"

struct ltdb_private;
typedef int (*ldb_kv_traverse_fn)(struct ltdb_private *ltdb,
				  struct ldb_val key, struct ldb_val data,
				  void *ctx);

struct kv_db_ops {
	int (*store)(struct ltdb_private *ltdb, TDB_DATA key, TDB_DATA data, int flags);
	int (*delete)(struct ltdb_private *ltdb, TDB_DATA key);
	int (*iterate)(struct ltdb_private *ltdb, ldb_kv_traverse_fn fn, void *ctx);
	int (*update_in_iterate)(struct ltdb_private *ltdb, TDB_DATA key,
				 TDB_DATA key2, TDB_DATA data, void *ctx);
	int (*fetch_and_parse)(struct ltdb_private *ltdb, TDB_DATA key,
                               int (*parser)(TDB_DATA key, TDB_DATA data,
                                             void *private_data),
                               void *ctx);
	int (*lock_read)(struct ldb_module *);
	int (*unlock_read)(struct ldb_module *);
	int (*begin_write)(struct ltdb_private *);
	int (*prepare_write)(struct ltdb_private *);
	int (*abort_write)(struct ltdb_private *);
	int (*finish_write)(struct ltdb_private *);
	int (*error)(struct ltdb_private *ltdb);
	const char * (*errorstr)(struct ltdb_private *ltdb);
	const char * (*name)(struct ltdb_private *ltdb);
	bool (*has_changed)(struct ltdb_private *ltdb);
};

/* this private structure is used by the ltdb backend in the
   ldb_context */
struct ltdb_private {
	const struct kv_db_ops *kv_ops;
	TDB_CONTEXT *tdb;
	unsigned int connect_flags;
	
	unsigned long long sequence_number;

	/* the low level tdb seqnum - used to avoid loading BASEINFO when
	   possible */
	int tdb_seqnum;

	struct ltdb_cache {
		struct ldb_message *indexlist;
		bool one_level_indexes;
		bool attribute_indexes;
		const char *GUID_index_attribute;
		const char *GUID_index_dn_component;
	} *cache;

	int in_transaction;

	bool check_base;
	bool disallow_dn_filter;
	struct ltdb_idxptr *idxptr;
	bool prepared_commit;
	int read_lock_count;

	bool warn_unindexed;
	bool warn_reindex;

	bool read_only;

	bool reindex_failed;

	const struct ldb_schema_syntax *GUID_index_syntax;

	/*
	 * Maximum index key length.  If non zero keys longer than this length
	 * will be truncated for non unique indexes. Keys for unique indexes
	 * greater than this length will be rejected.
	 */
	unsigned max_key_length;
};

struct ltdb_context {
	struct ldb_module *module;
	struct ldb_request *req;

	bool request_terminated;
	struct ltdb_req_spy *spy;

	/* search stuff */
	const struct ldb_parse_tree *tree;
	struct ldb_dn *base;
	enum ldb_scope scope;
	const char * const *attrs;
	struct tevent_timer *timeout_event;

	/* error handling */
	int error;
};

struct ltdb_reindex_context {
	struct ldb_module *module;
	int error;
	uint32_t count;
};


/* special record types */
#define LTDB_INDEX      "@INDEX"
#define LTDB_INDEXLIST  "@INDEXLIST"
#define LTDB_IDX        "@IDX"
#define LTDB_IDXVERSION "@IDXVERSION"
#define LTDB_IDXATTR    "@IDXATTR"
#define LTDB_IDXONE     "@IDXONE"
#define LTDB_IDXDN     "@IDXDN"
#define LTDB_IDXGUID    "@IDXGUID"
#define LTDB_IDX_DN_GUID "@IDX_DN_GUID"
#define LTDB_BASEINFO   "@BASEINFO"
#define LTDB_OPTIONS    "@OPTIONS"
#define LTDB_ATTRIBUTES "@ATTRIBUTES"

/* special attribute types */
#define LTDB_SEQUENCE_NUMBER "sequenceNumber"
#define LTDB_CHECK_BASE "checkBaseOnSearch"
#define LTDB_DISALLOW_DN_FILTER "disallowDNFilter"
#define LTDB_MOD_TIMESTAMP "whenChanged"
#define LTDB_OBJECTCLASS "objectClass"

/* DB keys */
#define LTDB_GUID_KEY_PREFIX "GUID="
#define LTDB_GUID_SIZE 16
#define LTDB_GUID_KEY_SIZE (LTDB_GUID_SIZE + sizeof(LTDB_GUID_KEY_PREFIX) - 1)

/* The following definitions come from lib/ldb/ldb_tdb/ldb_cache.c  */

int ltdb_cache_reload(struct ldb_module *module);
int ltdb_cache_load(struct ldb_module *module);
int ltdb_increase_sequence_number(struct ldb_module *module);
int ltdb_check_at_attributes_values(const struct ldb_val *value);

/* The following definitions come from lib/ldb/ldb_tdb/ldb_index.c  */

struct ldb_parse_tree;

int ltdb_search_indexed(struct ltdb_context *ctx, uint32_t *);
int ltdb_index_add_new(struct ldb_module *module,
		       struct ltdb_private *ltdb,
		       const struct ldb_message *msg);
int ltdb_index_delete(struct ldb_module *module, const struct ldb_message *msg);
int ltdb_index_del_element(struct ldb_module *module,
			   struct ltdb_private *ltdb,
			   const struct ldb_message *msg,
			   struct ldb_message_element *el);
int ltdb_index_add_element(struct ldb_module *module,
			   struct ltdb_private *ltdb,
			   const struct ldb_message *msg,
			   struct ldb_message_element *el);
int ltdb_index_del_value(struct ldb_module *module,
			 struct ltdb_private *ltdb,
			 const struct ldb_message *msg,
			 struct ldb_message_element *el, unsigned int v_idx);
int ltdb_reindex(struct ldb_module *module);
int ltdb_index_transaction_start(struct ldb_module *module);
int ltdb_index_transaction_commit(struct ldb_module *module);
int ltdb_index_transaction_cancel(struct ldb_module *module);
int ltdb_key_dn_from_idx(struct ldb_module *module,
			 struct ltdb_private *ltdb,
			 TALLOC_CTX *mem_ctx,
			 struct ldb_dn *dn,
			 TDB_DATA *tdb_key);

/* The following definitions come from lib/ldb/ldb_tdb/ldb_search.c  */

int ltdb_has_wildcard(struct ldb_module *module, const char *attr_name, 
		      const struct ldb_val *val);
void ltdb_search_dn1_free(struct ldb_module *module, struct ldb_message *msg);
int ltdb_search_dn1(struct ldb_module *module, struct ldb_dn *dn, struct ldb_message *msg,
		    unsigned int unpack_flags);
int ltdb_search_base(struct ldb_module *module,
		     TALLOC_CTX *mem_ctx,
		     struct ldb_dn *dn,
		     struct ldb_dn **ret_dn);
int ltdb_search_key(struct ldb_module *module, struct ltdb_private *ltdb,
		    struct TDB_DATA tdb_key,
		    struct ldb_message *msg,
		    unsigned int unpack_flags);
int ltdb_filter_attrs(TALLOC_CTX *mem_ctx,
		      const struct ldb_message *msg, const char * const *attrs,
		      struct ldb_message **filtered_msg);
int ltdb_search(struct ltdb_context *ctx);

/* The following definitions come from lib/ldb/ldb_tdb/ldb_tdb.c  */
/* 
 * Determine if this key could hold a record.  We allow the new GUID
 * index, the old DN index and a possible future ID=
 */
bool ltdb_key_is_record(TDB_DATA key);
TDB_DATA ltdb_key_dn(struct ldb_module *module, TALLOC_CTX *mem_ctx,
		     struct ldb_dn *dn);
TDB_DATA ltdb_key_msg(struct ldb_module *module, TALLOC_CTX *mem_ctx,
		      const struct ldb_message *msg);
int ltdb_guid_to_key(struct ldb_module *module,
		     struct ltdb_private *ltdb,
		     const struct ldb_val *GUID_val,
		     TDB_DATA *key);
int ltdb_idx_to_key(struct ldb_module *module,
		    struct ltdb_private *ltdb,
		    TALLOC_CTX *mem_ctx,
		    const struct ldb_val *idx_val,
		    TDB_DATA *key);
TDB_DATA ltdb_key(struct ldb_module *module, struct ldb_dn *dn);
int ltdb_store(struct ldb_module *module, const struct ldb_message *msg, int flgs);
int ltdb_modify_internal(struct ldb_module *module, const struct ldb_message *msg, struct ldb_request *req);
int ltdb_delete_noindex(struct ldb_module *module,
			const struct ldb_message *msg);
int ltdb_err_map(enum TDB_ERROR tdb_code);

struct tdb_context *ltdb_wrap_open(TALLOC_CTX *mem_ctx,
				   const char *path, int hash_size, int tdb_flags,
				   int open_flags, mode_t mode,
				   struct ldb_context *ldb);
int init_store(struct ltdb_private *ltdb, const char *name,
	       struct ldb_context *ldb, const char *options[],
	       struct ldb_module **_module);

int ltdb_connect(struct ldb_context *ldb, const char *url,
		 unsigned int flags, const char *options[],
		 struct ldb_module **_module);
