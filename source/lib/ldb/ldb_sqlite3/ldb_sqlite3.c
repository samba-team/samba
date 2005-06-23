/* 
   ldb database library
   
   Copyright (C) Derrell Lipman  2005
   
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

/*
 *  Name: ldb
 *
 *  Component: ldb sqlite3 backend
 *
 *  Description: core files for SQLITE3 backend
 *
 *  Author: Derrell Lipman (based on Andrew Tridgell's LDAP backend)
 */

#include <stdarg.h>
#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/include/ldb_explode_dn.h"
#include "ldb/ldb_sqlite3/ldb_sqlite3.h"

/*
 * Macros used throughout
 */

#ifndef FALSE
# define FALSE  (0)
# define TRUE   (! FALSE)
#endif

#define FILTER_ATTR_TABLE       "temp_filter_attrs"
#define RESULT_ATTR_TABLE       "temp_result_attrs"

//#define TEMPTAB                 /* for testing, create non-temporary table */
#define TEMPTAB                 "TEMPORARY"

//#define DEBUG_LOCKS

#ifndef DEBUG_LOCKS
# define LOCK_DB(mod, name)      lsqlite3_lock(mod, name)
# define UNLOCK_DB(mod, name)    lsqlite3_unlock(mod, name)
#else
# define LOCK_DB(mod, name)      lock_debug(mod, name, __FILE__, __LINE__)
# define UNLOCK_DB(mod, name)    unlock_debug(mod, name, __FILE__, __LINE__)
#endif

#define QUERY_NOROWS(lsqlite3, bRollbackOnError, sql...)                \
        do {                                                            \
                if (query_norows(lsqlite3, sql) != 0) {                 \
                        if (bRollbackOnError) {                         \
                                UNLOCK_DB(module, "rollback");          \
                        }                                               \
                        return -1;                                      \
                }                                                       \
        } while (0)

#define QUERY_INT(lsqlite3, result_var, bRollbackOnError, sql...)       \
        do {                                                            \
                if (query_int(lsqlite3, &result_var, sql) != 0) {       \
                        if (bRollbackOnError) {                         \
                                UNLOCK_DB(module, "rollback");          \
                        }                                               \
                        return -1;                                      \
                }                                                       \
        } while (0)


#define SQLITE3_DEBUG_QUERY     (1 << 0)
#define SQLITE3_DEBUG_INIT      (1 << 1)
#define SQLITE3_DEBUG_ADD       (1 << 2)
#define SQLITE3_DEBUG_NEWDN     (1 << 3)
#define SQLITE3_DEBUG_SEARCH    (1 << 4)

/*
 * Static variables
 */
static int      lsqlite3_debug = FALSE;

/*
 * Forward declarations
 */
static int
lsqlite3_rename(struct ldb_module * module,
                const char * olddn,
                const char * newdn);

static int
lsqlite3_delete(struct ldb_module *module,
                const char *dn);

static int
lsqlite3_search_bytree(struct ldb_module * module,
                       const char * pBaseDN,
                       enum ldb_scope scope,
                       struct ldb_parse_tree * pTree,
                       const char * const * attrs,
                       struct ldb_message *** pppRes);

static int
lsqlite3_search(struct ldb_module * module,
                const char * pBaseDN,
                enum ldb_scope scope,
                const char * pExpression,
                const char * const attrs[],
                struct ldb_message *** pppRes);

static int
lsqlite3_add(struct ldb_module *module,
             const struct ldb_message *msg);

static int
lsqlite3_modify(struct ldb_module *module,
                const struct ldb_message *msg);

static int
lsqlite3_lock(struct ldb_module *module,
              const char *lockname);

static int
lsqlite3_unlock(struct ldb_module *module,
                const char *lockname);

static const char *
lsqlite3_errstring(struct ldb_module *module);

static int
initialize(struct lsqlite3_private *lsqlite3,
           const char *url);

static int
destructor(void *p);

static int
query_norows(const struct lsqlite3_private *lsqlite3,
             const char *pSql,
             ...);

static int
query_int(const struct lsqlite3_private * lsqlite3,
          long long * pRet,
          const char * pSql,
          ...);

static int case_fold_attr_required(void * hUserData,
                                   char *attr);

static int
add_msg_attr(void * hTalloc,
             long long eid,
             const char * pDN,
             const char * pAttrName,
             const char * pAttrValue,
             long long prevEID,
             int * pAllocated,
             struct ldb_message *** pppRes);

static char *
parsetree_to_sql(struct ldb_module *module,
                 char * hTalloc,
                 const struct ldb_parse_tree *t);

static int
parsetree_to_attrlist(struct ldb_module *module,
                      const struct ldb_parse_tree * t);

#ifdef NEED_TABLE_LIST
static char *
build_attr_table_list(void * hTalloc,
                      struct lsqlite3_private * lsqlite3);
#endif

static int
msg_to_sql(struct ldb_module * module,
           const struct ldb_message * msg,
           long long eid,
           int use_flags);

static int
new_dn(struct ldb_module * module,
       char * pDN,
       long long * pEID);

static void
base160_sql(sqlite3_context * hContext,
            int argc,
            sqlite3_value ** argv);

static void
base160next_sql(sqlite3_context * hContext,
                int argc,
                sqlite3_value ** argv);

#ifdef DEBUG_LOCKS
static int lock_debug(struct ldb_module * module,
                      const char * lockname,
                      const char * pFileName,
                      int linenum);

static int unlock_debug(struct ldb_module * module,
                        const char * lockname,
                        const char * pFileName,
                        int linenum);
#endif


/*
 * Table of operations for the sqlite3 backend
 */
static const struct ldb_module_ops lsqlite3_ops = {
	.name          = "sqlite",
	.search        = lsqlite3_search,
	.search_bytree = lsqlite3_search_bytree,
	.add_record    = lsqlite3_add,
	.modify_record = lsqlite3_modify,
	.delete_record = lsqlite3_delete,
	.rename_record = lsqlite3_rename,
	.named_lock    = lsqlite3_lock,
	.named_unlock  = lsqlite3_unlock,
	.errstring     = lsqlite3_errstring
};




/*
 * Public functions
 */


/*
 * connect to the database
 */
int lsqlite3_connect(struct ldb_context *ldb,
		     const char *url, 
		     unsigned int flags, 
		     const char *options[])
{
	int                         i;
        int                         ret;
	struct lsqlite3_private *   lsqlite3 = NULL;
        
	lsqlite3 = talloc(ldb, struct lsqlite3_private);
	if (!lsqlite3) {
		goto failed;
	}
        
	lsqlite3->sqlite = NULL;
	lsqlite3->options = NULL;
        lsqlite3->lock_count = 0;
        
	ret = initialize(lsqlite3, url);
	if (ret != SQLITE_OK) {
		goto failed;
	}
        
	talloc_set_destructor(lsqlite3, destructor);
        
	ldb->modules = talloc(ldb, struct ldb_module);
	if (!ldb->modules) {
		goto failed;
	}
	ldb->modules->ldb = ldb;
	ldb->modules->prev = ldb->modules->next = NULL;
	ldb->modules->private_data = lsqlite3;
	ldb->modules->ops = &lsqlite3_ops;
        
	if (options) {
		/*
                 * take a copy of the options array, so we don't have to rely
                 * on the caller keeping it around (it might be dynamic)
                 */
		for (i=0;options[i];i++) ;
                
		lsqlite3->options = talloc_array(lsqlite3, char *, i+1);
		if (!lsqlite3->options) {
			goto failed;
		}
                
		for (i=0;options[i];i++) {
                        
			lsqlite3->options[i+1] = NULL;
			lsqlite3->options[i] =
                                talloc_strdup(lsqlite3->options, options[i]);
			if (!lsqlite3->options[i]) {
				goto failed;
			}
		}
	}
        
	return 0;
        
failed:
        if (lsqlite3->sqlite != NULL) {
                (void) sqlite3_close(lsqlite3->sqlite);
        }
	talloc_free(lsqlite3);
	return -1;
}


/*
 * Interface functions referenced by lsqlite3_ops
 */

/* rename a record */
static int
lsqlite3_rename(struct ldb_module * module,
                const char * pOldDN,
                const char * pNewDN)
{
        long long                   eid;
	struct lsqlite3_private *   lsqlite3 = module->private_data;

        /* ignore ltdb specials */
        if (*pOldDN == '@' || *pNewDN == '@') {
                return 0;
        }

        /* Case-fold each of the DNs */
        pOldDN = ldb_dn_fold(module->ldb, pOldDN,
                             module, case_fold_attr_required);
        pNewDN = ldb_dn_fold(module->ldb, pNewDN,
                             module, case_fold_attr_required);

        /* Begin a transaction */
        if (LOCK_DB(module, "transaction") < 0) {
                return -1;
        }

        /* Determine the eid of the DN being renamed */
        QUERY_INT(lsqlite3,
                  eid,
                  TRUE,
                  "SELECT eid\n"
                  "  FROM ldb_entry\n"
                  "  WHERE dn = %Q;",
                  pOldDN);
        
        QUERY_NOROWS(lsqlite3,
                     TRUE,
                     "UPDATE ldb_entry "
                     "  SET dn = %Q "
                     "  WHERE eid = %lld;",
                     pNewDN, eid);

        QUERY_NOROWS(lsqlite3,
                     TRUE,
                     "UPDATE ldb_attribute_values "
                     "  SET attr_value = %Q, "
                     "      attr_value_normalized = upper(%Q) "
                     "  WHERE eid = %lld "
                     "    AND attr_name = 'DN';",
                     pNewDN,
                     pNewDN,
                     eid);

        /* Commit the transaction */
        if (UNLOCK_DB(module, "transaction") < 0) {
                UNLOCK_DB(module, "rollback");
                return -1;
        }
        
        return 0;
}

/* delete a record */
static int
lsqlite3_delete(struct ldb_module * module,
                const char * pDN)
{
        long long                   eid;
	struct lsqlite3_private *   lsqlite3 = module->private_data;

        /* ignore ltdb specials */
        if (*pDN == '@') {
                return 0;
        }

        /* Begin a transaction */
        if (LOCK_DB(module, "transaction") < 0) {
                return -1;
        }

        /* Case-fold the DNs */
        pDN = ldb_dn_fold(module->ldb, pDN, module, case_fold_attr_required);

        /* Determine the eid of the DN being deleted */
        QUERY_INT(lsqlite3,
                  eid,
                  TRUE,
                  "SELECT eid\n"
                  "  FROM ldb_attribute_values\n"
                  "  WHERE attr_name = 'DN'\n"
                  "    AND attr_value_normalized = upper(%Q);",
                  pDN);
        
        /* Delete attribute/value table entries pertaining to this DN */
        QUERY_NOROWS(lsqlite3,
                     TRUE,
                     "DELETE FROM ldb_attribute_values "
                     "  WHERE eid = %lld;",
                     eid);

        /* Delete this entry */
        QUERY_NOROWS(lsqlite3,
                     TRUE,
                     "DELETE FROM ldb_entry "
                     "  WHERE eid = %lld;",
                     eid);

        /* Commit the transaction */
        if (UNLOCK_DB(module, "transaction") < 0) {
                UNLOCK_DB(module, "rollback");
                return -1;
        }
        
        return 0;
}

/* search for matching records, by tree */
static int
lsqlite3_search_bytree(struct ldb_module * module,
                       const char * pBaseDN,
                       enum ldb_scope scope,
                       struct ldb_parse_tree * pTree,
                       const char * const * attrs,
                       struct ldb_message *** pppRes)
{
        int                         ret;
        int                         allocated;
        int                         bLoop;
        long long                   eid = 0;
        long long                   prevEID;
        char *                      pSql = NULL;
	char *                      pSqlConstraints;
#ifdef NEED_TABLE_LIST
        char *                      pTableList;
#endif
        char *                      hTalloc = NULL;
        const char *                pDN;
        const char *                pAttrName;
        const char *                pAttrValue;
        const char *                pResultAttrList;
        const char * const *        pRequestedAttrs;
        sqlite3_stmt *              pStmt;
	struct lsqlite3_private *   lsqlite3 = module->private_data;
        
	if (pBaseDN == NULL) {
		pBaseDN = "";
	}
        
        /* Allocate a temporary talloc context */
	if ((hTalloc = talloc_new(module->ldb)) == NULL) {
                return -1;
        }
        
        /* Case-fold the base DN */
        if ((pBaseDN = ldb_dn_fold(hTalloc, pBaseDN,
                                   module, case_fold_attr_required)) == NULL) {
                talloc_free(hTalloc);
                return -1;
            }

        /* Begin a transaction */
        if (LOCK_DB(module, "transaction") < 0) {
                return -1;
        }
        
        /*
         * Obtain the eid of the base DN
         */
        if ((ret = query_int(lsqlite3,
                             &eid,
                             "SELECT eid\n"
                             "  FROM ldb_attribute_values\n"
                             "  WHERE attr_name = 'DN'\n"
                             "    AND attr_value_normalized = upper(%Q);",
                             pBaseDN)) == SQLITE_DONE) {
                UNLOCK_DB(module, "rollback");
                talloc_free(hTalloc);
                return 0;
        } else if (ret != SQLITE_OK) {
                UNLOCK_DB(module, "rollback");
                talloc_free(hTalloc);
                return -1;
        }
        
        /* Convert filter into a series of SQL conditions (constraints) */
	pSqlConstraints = parsetree_to_sql(module, hTalloc, pTree);
        
        /* Ensure we're starting with an empty result attribute table */
        QUERY_NOROWS(lsqlite3,
                     FALSE,
                     "DELETE FROM " RESULT_ATTR_TABLE "\n"
                     "  WHERE 1;");/* avoid a schema change with WHERE 1 */
        
        /* Initially, we don't know what the requested attributes are */
        pResultAttrList = NULL;

        /* Insert the list of requested attributes into this table */
        for (pRequestedAttrs = (const char * const *) attrs;
             pRequestedAttrs != NULL && *pRequestedAttrs != NULL;
             pRequestedAttrs++) {
                
                /* If any attribute in the list is "*" then... */
                if (strcmp(*pRequestedAttrs, "*") == 0) {
                        /* we want all attribute types */
                        pResultAttrList = "";
                        break;
                        
                } else {
                        /* otherwise, add this name to the resuult list */
                        QUERY_NOROWS(lsqlite3,
                                     FALSE,
                                     "INSERT OR IGNORE\n"
                                     "  INTO " RESULT_ATTR_TABLE "\n"
                                     "    (attr_name)\n"
                                     "  VALUES\n"
                                     "    (%Q);",
                                     *pRequestedAttrs);
                }
        }
        
        /* If we didn't get a "*" for all attributes in the result list... */
        if (pResultAttrList == NULL) {
                /* ... then we'll use the result attribute table */
                pResultAttrList =
                        "    AND upper(av.attr_name) IN\n"
                        "          (SELECT attr_name\n"
                        "             FROM " RESULT_ATTR_TABLE ") ";
        }

        /* Ensure we're starting with an empty filter attribute table */
        QUERY_NOROWS(lsqlite3,
                     FALSE,
                     "DELETE FROM " FILTER_ATTR_TABLE "\n"
                     "  WHERE 1;");/* avoid a schema change with WHERE 1 */
        
        /*
         * Create a table of unique attribute names for our extra table list
         */
        if ((ret = parsetree_to_attrlist(module, pTree)) != 0) {
                ret = -1;
                goto cleanup;
        }
        
#ifdef NEED_TABLE_LIST
        /*
         * Build the attribute table list from the list of unique names.
         */
        if ((pTableList = build_attr_table_list(hTalloc, lsqlite3)) == NULL) {
                ret = -1;
                goto cleanup;
        }
#endif
        
        switch(scope) {
        case LDB_SCOPE_DEFAULT:
        case LDB_SCOPE_SUBTREE:
                pSql = sqlite3_mprintf(
                        "SELECT entry.eid,\n"
                        "       entry.dn,\n"
                        "       av.attr_name,\n"
                        "       av.attr_value\n"
                        "  FROM ldb_entry AS entry\n"

                        "  LEFT OUTER JOIN ldb_attribute_values AS av\n"
                        "    ON av.eid = entry.eid\n"
                        "       %s\n"

                        "  WHERE entry.eid IN\n"
                        "    (SELECT DISTINCT ldb_entry.eid\n"
                        "       FROM ldb_entry\n"
                        "       WHERE ldb_entry.tree_key >=\n"
                        "               (SELECT tree_key\n"
                        "                  FROM ldb_entry\n"
                        "                  WHERE eid = %lld)\n"
                        "         AND ldb_entry.tree_key <\n"
                        "               (SELECT base160_next(tree_key)\n"
                        "                  FROM ldb_entry\n"
                        "                  WHERE eid = %lld)\n"
                        "         AND ldb_entry.eid IN\n(%s)\n"
                        "    )\n"
                        "  ORDER BY entry.tree_key DESC,\n"
                        "           COALESCE(av.attr_name, '');",
                        pResultAttrList,
                        eid,
                        eid,
                        pSqlConstraints);
                break;
                
        case LDB_SCOPE_BASE:
                pSql = sqlite3_mprintf(
                        "SELECT entry.eid,\n"
                        "       entry.dn,\n"
                        "       av.attr_name,\n"
                        "       av.attr_value\n"
                        "  FROM ldb_entry AS entry\n"

                        "  LEFT OUTER JOIN ldb_attribute_values AS av\n"
                        "    ON av.eid = entry.eid\n"
                        "       %s\n"

                        "  WHERE entry.eid IN\n"
                        "    (SELECT DISTINCT ldb_entry.eid\n"
                        "       FROM ldb_entry\n"
                        "       WHERE ldb_entry.eid = %lld\n"
                        "         AND ldb_entry.eid IN\n(%s)\n"
                        "    )\n"
                        "  ORDER BY entry.tree_key DESC,\n"
                        "           COALESCE(av.attr_name, '');",
                        pResultAttrList,
                        eid,
                        pSqlConstraints);
                break;
                
        case LDB_SCOPE_ONELEVEL:
                pSql = sqlite3_mprintf(
                        "SELECT entry.eid,\n"
                        "       entry.dn,\n"
                        "       av.attr_name,\n"
                        "       av.attr_value\n"
                        "  FROM ldb_entry AS entry\n"

                        "  LEFT OUTER JOIN ldb_attribute_values AS av\n"
                        "    ON av.eid = entry.eid\n"
                        "       %s\n"

                        "  WHERE entry.eid IN\n"
                        "    (SELECT DISTINCT ldb_entry.eid\n"
                        "       FROM ldb_entry\n"
                        "       WHERE ldb_entry.tree_key >=\n"
                        "               (SELECT tree_key\n"
                        "                  FROM ldb_entry\n"
                        "                  WHERE eid = %lld)\n"
                        "         AND ldb_entry.tree_key <\n"
                        "               (SELECT base160_next(tree_key)\n"
                        "                  FROM ldb_entry\n"
                        "                  WHERE eid = %lld)\n"
                        "         AND length(ldb_entry.tree_key) =\n"
                        "               (SELECT length(tree_key) + 4\n"
                        "                  FROM ldb_entry\n"
                        "                  WHERE eid = %lld)\n"
                        "         AND ldb_entry.eid IN\n(%s)\n"
                        "    )\n"

                        "  ORDER BY entry.tree_key DESC,\n"
                        "           COALESCE(av.attr_name, '');\n",
                        pResultAttrList,
                        eid,
                        eid,
                        eid,
                        pSqlConstraints);
                break;
        }
        
        if (pSql == NULL) {
                ret = -1;
                goto cleanup;
        }

        if (lsqlite3_debug & SQLITE3_DEBUG_SEARCH) {
                printf("%s\n", pSql);
        }

        /*
         * Prepare and execute the SQL statement.  Loop allows retrying on
         * certain errors, e.g. SQLITE_SCHEMA occurs if the schema changes,
         * requiring retrying the operation.
         */
        for (bLoop = TRUE; bLoop; ) {
                /* There are no allocate message structures yet */
                allocated = 0;
                if (pppRes != NULL) {
                        *pppRes = NULL;
                }
                
                /* Compile the SQL statement into sqlite virtual machine */
                if ((ret = sqlite3_prepare(lsqlite3->sqlite,
                                           pSql,
                                           -1,
                                           &pStmt,
                                           NULL)) == SQLITE_SCHEMA) {
                        if (pppRes != NULL && *pppRes != NULL) {
                                talloc_free(*pppRes);
                        }
                        continue;
                } else if (ret != SQLITE_OK) {
                        ret = -1;
                        break;
                }
                
                /* Initially, we have no previous eid */
                prevEID = -1;
                
                /* Loop through the returned rows */
                for (ret = SQLITE_ROW; ret == SQLITE_ROW; ) {
                        
                        /* Get the next row */
                        if ((ret = sqlite3_step(pStmt)) == SQLITE_ROW) {
                                
                                /* Get the values from this row */
                                eid = sqlite3_column_int64(pStmt, 0);
                                pDN = sqlite3_column_text(pStmt, 1);
                                pAttrName = sqlite3_column_text(pStmt, 2);
                                pAttrValue = sqlite3_column_text(pStmt, 3);
                                
                                /* Add this result to the result set */
                                if (add_msg_attr(hTalloc,
                                                 eid,
                                                 pDN,
                                                 pAttrName,
                                                 pAttrValue,
                                                 prevEID,
                                                 &allocated,
                                                 pppRes) != 0) {
                                        
                                        (void) sqlite3_finalize(pStmt);
                                        ret = -1;
                                        break;
                                }

                                /* Save the most recent EID */
                                prevEID = eid;
                        }
                }
                
                if (ret == SQLITE_SCHEMA) {
                        (void) sqlite3_finalize(pStmt);
                        if (pppRes != NULL && *pppRes != NULL) {
                                talloc_free(*pppRes);
                        }
                        continue;
                } else if (ret != SQLITE_DONE) {
                        (void) sqlite3_finalize(pStmt);
                        ret = -1;
                        break;
                }
                
                /* Free the virtual machine */
                if ((ret = sqlite3_finalize(pStmt)) == SQLITE_SCHEMA) {
                        (void) sqlite3_finalize(pStmt);
                        if (pppRes != NULL && *pppRes != NULL) {
                                talloc_free(*pppRes);
                        }
                        continue;
                } else if (ret != SQLITE_OK) {
                        (void) sqlite3_finalize(pStmt);
                        ret = -1;
                        break;
                }
                
                /*
                 * Normal condition is only one time through loop.  Loop is
                 * rerun in error conditions, via "continue", above.
                 */
                ret = 0;
                bLoop = FALSE;
        }
        
        /* We're alll done with this query */
        sqlite3_free(pSql);
        
        /* End the transaction */
        UNLOCK_DB(module, "rollback");
        
        /* Were there any results? */
        if (ret != 0 || allocated == 0) {
                /* Nope.  We can free the results. */
                if (pppRes != NULL && *pppRes != NULL) {
                        talloc_free(*pppRes);
                }
        }
        
cleanup:
        /* Clean up our temporary tables */
        QUERY_NOROWS(lsqlite3,
                     FALSE,
                     "DELETE FROM " RESULT_ATTR_TABLE "\n"
                     "  WHERE 1;");/* avoid a schema change with WHERE 1 */
        
        QUERY_NOROWS(lsqlite3,
                     FALSE,
                     "DELETE FROM " FILTER_ATTR_TABLE "\n"
                     "  WHERE 1;");/* avoid a schema change with WHERE 1 */
        
        
        if (hTalloc != NULL) {
                talloc_free(hTalloc);
        }
        
        /* If error, return error code; otherwise return number of results */
	return ret == 0 ? allocated : ret;
}

/* search for matching records, by expression */
static int
lsqlite3_search(struct ldb_module * module,
                const char * pBaseDN,
                enum ldb_scope scope,
                const char * pExpression,
                const char * const * attrs,
                struct ldb_message *** pppRes)
{
        int                     ret;
        struct ldb_parse_tree * pTree;
        
        /* Handle tdb specials */
        if (pBaseDN != NULL && *pBaseDN == '@') {
#warning "handle tdb specials"
                return 0;
        }

#if 0 
/* (|(objectclass=*)(dn=*)) is  passed by the command line tool now instead */
        /* Handle the special case of requesting all */
        if (pExpression != NULL && *pExpression == '\0') {
                pExpression = "dn=*";
        }
#endif

        /* Parse the filter expression into a tree we can work with */
	if ((pTree = ldb_parse_tree(module->ldb, pExpression)) == NULL) {
                return -1;
	}
        
        /* Now use the bytree function for the remainder of processing */
        ret = lsqlite3_search_bytree(module, pBaseDN, scope,
                                     pTree, attrs, pppRes);
        
        /* Free the parse tree */
	talloc_free(pTree);
        
        /* All done. */
        return ret;
}


/* add a record */
static int
lsqlite3_add(struct ldb_module *module,
             const struct ldb_message *msg)
{
        long long                   eid;
        
        /* See if this is an ltdb special */
        if (*msg->dn == '@') {
                /* Yup.  We handle a few of these and ignore others */
                if (strcmp(msg->dn, "@SUBCLASSES") == 0) {
#warning "insert subclasses into object class tree"
                }

                if (strcmp(msg->dn, "@INDEXLIST") == 0) {
                        /* explicitly ignored */
                        return 0;
                }

                /* Others are implicitly ignored */
                return 0;
        }

        /* Begin a transaction */
        if (LOCK_DB(module, "transaction") < 0) {
                return -1;
        }
        
        /*
         * Build any portions of the directory tree that don't exist.  If the
         * final component already exists, it's an error.
         */
        if (new_dn(module, msg->dn, &eid) != 0) {
                UNLOCK_DB(module, "rollback");
                return -1;
        }
        
        /* Add attributes to this new entry */
	if (msg_to_sql(module, msg, eid, FALSE) != 0) {
                UNLOCK_DB(module, "rollback");
                return -1;
        }
        
        /* Everything worked.  Commit it! */
        if (UNLOCK_DB(module, "transaction") < 0) {
                UNLOCK_DB(module, "rollback");
                return -1;
        }
        return 0;
}


/* modify a record */
static int
lsqlite3_modify(struct ldb_module * module,
                const struct ldb_message * msg)
{
        char *                      pDN;
        long long                   eid;
	struct lsqlite3_private *   lsqlite3 = module->private_data;
        
        /* ignore ltdb specials */
        if (*msg->dn == '@') {
                return 0;
        }

        /* Begin a transaction */
        if (LOCK_DB(module, "transaction") < 0) {
                return -1;
        }
        
        /* Case-fold the DN so we can compare it to what's in the database */
        pDN = ldb_dn_fold(module->ldb, msg->dn,
                          module, case_fold_attr_required);

        /* Determine the eid of the DN being deleted */
        QUERY_INT(lsqlite3,
                  eid,
                  TRUE,
                  "SELECT eid\n"
                  "  FROM ldb_entry\n"
                  "  WHERE dn = %Q;",
                  pDN);
        
        /* Apply the message attributes */
	if (msg_to_sql(module, msg, eid, TRUE) != 0) {
                UNLOCK_DB(module, "rollback");
                return -1;
        }
        

        /* Everything worked.  Commit it! */
        if (UNLOCK_DB(module, "transaction") < 0) {
                UNLOCK_DB(module, "rollback");
                return -1;
        }
        return 0 ;
}

/* obtain a named lock */
static int
lsqlite3_lock(struct ldb_module * module,
              const char * lockname)
{
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	if (lockname == NULL) {
		return -1;
	}
        
        if (strcmp(lockname, "transaction") == 0) {
                if (lsqlite3->lock_count == 0) {
                        if (query_norows(lsqlite3, "BEGIN EXCLUSIVE;") != 0) {
                                return -1;
                        }
                }
                ++lsqlite3->lock_count;
        }
        
	return 0;
}

/* release a named lock */
static int
lsqlite3_unlock(struct ldb_module *module,
                const char *lockname)
{
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	if (lockname == NULL) {
		return -1;
	}
        
        if (strcmp(lockname, "transaction") == 0) {
                if (lsqlite3->lock_count == 1) {
                        if (query_norows(lsqlite3, "COMMIT;") != 0) {
                                query_norows(lsqlite3, "ROLLBACK;");
                        }
                } else if (lsqlite3->lock_count > 0) {
                        --lsqlite3->lock_count;
                }
        } else if (strcmp(lockname, "rollback") == 0) {
                query_norows(lsqlite3, "ROLLBACK;");
        }
        
        return 0;
}

/* return extended error information */
static const char *
lsqlite3_errstring(struct ldb_module *module)
{
	struct lsqlite3_private *   lsqlite3 = module->private_data;
        
	return sqlite3_errmsg(lsqlite3->sqlite);
}




/*
 * Static functions
 */

static int
initialize(struct lsqlite3_private *lsqlite3,
           const char *url)
{
        int             ret;
        long long       queryInt;
        const char *    pTail;
        sqlite3_stmt *  stmt;
        const char *    schema =       
                
                
                "CREATE TABLE ldb_info AS "
                "  SELECT 'LDB' AS database_type,"
                "         '1.0' AS version;"
                
                /*
                 * The entry table holds the information about an entry. 
                 * This table is used to obtain the EID of the entry and to 
                 * support scope=one and scope=base.  The parent and child
                 * table is included in the entry table since all the other
                 * attributes are dependent on EID.
                 */
                "CREATE TABLE ldb_entry "
                "("
                "  eid                   INTEGER PRIMARY KEY,"
                "  peid                  INTEGER REFERENCES ldb_entry,"
                "  dn                    TEXT UNIQUE NOT NULL,"
                "  tree_key              TEXT UNIQUE,"
                "  max_child_num         INTEGER DEFAULT 0,"
                "  create_timestamp      INTEGER,"
                "  modify_timestamp      INTEGER"
                ");"
                

                "CREATE TABLE ldb_object_classes"
                "("
                "  class_name            TEXT PRIMARY KEY,"
                "  parent_class_name     TEXT,"
                "  tree_key              TEXT UNIQUE,"
                "  max_child_num         INTEGER DEFAULT 0"
                ");"
                
                /*
                 * We keep a full listing of attribute/value pairs here
                 */
                "CREATE TABLE ldb_attribute_values"
                "("
                "  eid                   INTEGER REFERENCES ldb_entry,"
                "  attr_name             TEXT,"
                "  attr_value            TEXT,"
                "  attr_value_normalized TEXT "
                ");"
                
               
                /*
                 * Indexes
                 */
                "CREATE INDEX ldb_entry_tree_key_idx "
                "  ON ldb_entry (tree_key);"

                "CREATE INDEX ldb_attribute_values_eid_idx "
                "  ON ldb_attribute_values (eid);"
                
                

                /*
                 * Triggers
                 */
                
                "CREATE TRIGGER ldb_entry_insert_tr"
                "  AFTER INSERT"
                "  ON ldb_entry"
                "  FOR EACH ROW"
                "    BEGIN"

                "      UPDATE ldb_entry"
                "        SET create_timestamp = strftime('%s', 'now'),"
                "            modify_timestamp = strftime('%s', 'now')"
                "           ,"
                "            tree_key = COALESCE(tree_key, "
                "              ("
                "                SELECT tree_key || "
                "                       (SELECT base160(max_child_num + 1)"
                "                                FROM ldb_entry"
                "                                WHERE eid = new.peid)"
                "                  FROM ldb_entry "
                "                  WHERE eid = new.peid "
                "              ));"
                "      UPDATE ldb_entry "
                "        SET max_child_num = max_child_num + 1"
                "        WHERE eid = new.peid;"
                "    END;"
                
                "CREATE TRIGGER ldb_entry_update_tr"
                "  AFTER UPDATE"
                "  ON ldb_entry"
                "  FOR EACH ROW"
                "    BEGIN"
                "      UPDATE ldb_entry"
                "        SET modify_timestamp = strftime('%s', 'now')"
                "        WHERE eid = old.eid;"
                "    END;"
                
                "CREATE TRIGGER ldb_object_classes_insert_tr"
                "  AFTER INSERT"
                "  ON ldb_object_classes"
                "  FOR EACH ROW"
                "    BEGIN"
                "      UPDATE ldb_object_classes"
                "        SET tree_key = COALESCE(tree_key, "
                "              ("
                "                SELECT tree_key || "
                "                       (SELECT base160(max_child_num + 1)"
                "                                FROM ldb_object_classes"
                "                                WHERE class_name = "
                "                                      new.parent_class_name)"
                "                  FROM ldb_object_classes "
                "                  WHERE class_name = new.parent_class_name "
                "              ));"
                "      UPDATE ldb_object_classes "
                "        SET max_child_num = max_child_num + 1"
                "        WHERE class_name = new.parent_class_name;"
                "    END;"
                
                /*
                 * Table initialization
                 */

                /* The root node */
                "INSERT INTO ldb_entry "
                "    (eid, peid, dn, tree_key) "
                "  VALUES "
                "    (0, NULL, '', '0001');"

                /* And the root node "dn" attribute */
                "INSERT INTO ldb_attribute_values "
                "    (eid, attr_name, attr_value, attr_value_normalized) "
                "  VALUES "
                "    (0, 'DN', '', '');"

                "INSERT INTO ldb_object_classes "
                "    (class_name, tree_key) "
                "  VALUES "
                "    ('TOP', '0001');"

                ;
        
        /* Skip protocol indicator of url  */
        if (strncmp(url, "sqlite://", 9) != 0) {
                return SQLITE_MISUSE;
        }
        
        /* Update pointer to just after the protocol indicator */
        url += 9;
        
        /* Try to open the (possibly empty/non-existent) database */
        if ((ret = sqlite3_open(url, &lsqlite3->sqlite)) != SQLITE_OK) {
                return ret;
        }
        
        /* In case this is a new database, enable auto_vacuum */
        if (query_norows(lsqlite3, "PRAGMA auto_vacuum=1;") != 0) {
                        return -1;
        }
        
        /* Establish a busy timeout of 30 seconds */
        if ((ret = sqlite3_busy_timeout(lsqlite3->sqlite,
                                        30000)) != SQLITE_OK) {
                return ret;
        }

        /* Create a function, callable from sql, to increment a tree_key */
        if ((ret =
             sqlite3_create_function(lsqlite3->sqlite,/* handle */
                                     "base160_next",  /* function name */
                                     1,               /* number of args */
                                     SQLITE_ANY,      /* preferred text type */
                                     NULL,            /* user data */
                                     base160next_sql, /* called func */
                                     NULL,            /* step func */
                                     NULL             /* final func */
                     )) != SQLITE_OK) {
                return ret;
        }

        /* Create a function, callable from sql, to convert int to base160 */
        if ((ret =
             sqlite3_create_function(lsqlite3->sqlite,/* handle */
                                     "base160",       /* function name */
                                     1,               /* number of args */
                                     SQLITE_ANY,      /* preferred text type */
                                     NULL,            /* user data */
                                     base160_sql,     /* called func */
                                     NULL,            /* step func */
                                     NULL             /* final func */
                     )) != SQLITE_OK) {
                return ret;
        }

        /* Begin a transaction */
        if ((ret = query_norows(lsqlite3, "BEGIN EXCLUSIVE;")) != 0) {
                        return ret;
        }
        
        /* Determine if this is a new database.  No tables means it is. */
        if (query_int(lsqlite3,
                      &queryInt,
                      "SELECT COUNT(*)\n"
                      "  FROM sqlite_master\n"
                      "  WHERE type = 'table';") != 0) {
                query_norows(lsqlite3, "ROLLBACK;");
                return -1;
        }
        
        if (queryInt == 0) {
                /*
                 * Create the database schema
                 */
                for (pTail = discard_const_p(char, schema);
                     pTail != NULL && *pTail != '\0';
                        ) {
                        
                        if (lsqlite3_debug & SQLITE3_DEBUG_INIT) {
                                printf("Execute first query in:\n%s\n", pTail);
                        }
                        
                        if ((ret = sqlite3_prepare(
                                     lsqlite3->sqlite,
                                     pTail,
                                     -1,
                                     &stmt,
                                     &pTail)) != SQLITE_OK ||
                            (ret = sqlite3_step(stmt)) != SQLITE_DONE ||
                            (ret = sqlite3_finalize(stmt)) != SQLITE_OK) {
                                
                                if (lsqlite3_debug & SQLITE3_DEBUG_INIT) {
                                        printf("%s\n",
                                               sqlite3_errmsg(lsqlite3->sqlite));
                                        printf("pTail = [%s]\n", pTail);
                                }
                                        
                                query_norows(lsqlite3, "ROLLBACK;");
                                (void) sqlite3_close(lsqlite3->sqlite);
                                return ret;
                        }
                }
        } else {
                /*
                 * Ensure that the database we opened is one of ours
                 */
                if (query_int(lsqlite3,
                              &queryInt,
                              "SELECT "
                              "  (SELECT COUNT(*) = 2"
                              "     FROM sqlite_master "
                              "     WHERE type = 'table' "
                              "       AND name IN "
                              "         ("
                              "           'ldb_entry', "
                              "           'ldb_object_classes' "
                              "         ) "
                              "  ) "
                              "  AND "
                              "  (SELECT 1 "
                              "     FROM ldb_info "
                              "     WHERE database_type = 'LDB' "
                              "       AND version = '1.0'"
                              "  );") != 0 ||
                    queryInt != 1) {
                        
                        /* It's not one that we created.  See ya! */
                        query_norows(lsqlite3, "ROLLBACK;");
                        (void) sqlite3_close(lsqlite3->sqlite);
                        return SQLITE_MISUSE;
                }
        }
        
        /*
         * Create a temporary table to hold attributes requested in the result
         * set of a search.
         */
        query_norows(lsqlite3, "DROP TABLE " RESULT_ATTR_TABLE ";\n");
        if ((ret =
             query_norows(lsqlite3,
                          "CREATE " TEMPTAB " TABLE " RESULT_ATTR_TABLE "\n"
                          " (\n"
                          "  attr_name TEXT PRIMARY KEY\n"
                          " );")) != 0) {
                query_norows(lsqlite3, "ROLLBACK;");
                return ret;
        }

        /*
         * Create a temporary table to hold the attributes used by filters
         * during a search.
         */
        query_norows(lsqlite3, "DROP TABLE " FILTER_ATTR_TABLE ";\n");
        if ((ret =
             query_norows(lsqlite3,
                          "CREATE " TEMPTAB " TABLE " FILTER_ATTR_TABLE "\n"
                          " (\n"
                          "  attr_name TEXT PRIMARY KEY\n"
                          " );")) != 0) {
                query_norows(lsqlite3, "ROLLBACK;");
                return ret;
        }

        /* Commit the transaction */
        if ((ret = query_norows(lsqlite3, "COMMIT;")) != 0) {
                query_norows(lsqlite3, "ROLLBACK;");
                return ret;
        }
        
        return SQLITE_OK;
}

static int
destructor(void *p)
{
	struct lsqlite3_private *   lsqlite3 = p;
        
	if (lsqlite3->sqlite) {
		sqlite3_close(lsqlite3->sqlite);
	}
	return 0;
}


/*
 * query_norows()
 *
 * This function is used for queries that are not expected to return any rows,
 * e.g. BEGIN, COMMIT, ROLLBACK, CREATE TABLE, INSERT, UPDATE, DELETE, etc.
 * There are no provisions here for returning data from rows in a table, so do
 * not pass SELECT queries to this function.
 */
static int
query_norows(const struct lsqlite3_private *lsqlite3,
             const char *pSql,
             ...)
{
        int             ret;
        int             bLoop;
        char *          p;
        sqlite3_stmt *  pStmt;
        va_list         args;
        double          t0;
        double          t1;
        struct timeval  tv;
        struct timezone tz;
        
        gettimeofday(&tv, &tz);
        t0 = (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0);

        /* Begin access to variable argument list */
        va_start(args, pSql);
        
        /* Format the query */
        if ((p = sqlite3_vmprintf(pSql, args)) == NULL) {
                return -1;
        }
        
        /*
         * Prepare and execute the SQL statement.  Loop allows retrying on
         * certain errors, e.g. SQLITE_SCHEMA occurs if the schema changes,
         * requiring retrying the operation.
         */
        for (bLoop = TRUE; bLoop; ) {
                
                /* Compile the SQL statement into sqlite virtual machine */
                if ((ret = sqlite3_prepare(lsqlite3->sqlite,
                                           p,
                                           -1,
                                           &pStmt,
                                           NULL)) == SQLITE_SCHEMA) {
                        continue;
                } else if (ret != SQLITE_OK) {
                        ret = -1;
                        break;
                }
                
                /* No rows expected, so just step through machine code once */
                if ((ret = sqlite3_step(pStmt)) == SQLITE_SCHEMA) {
                        (void) sqlite3_finalize(pStmt);
                        continue;
                } else if (ret != SQLITE_DONE) {
                        (void) sqlite3_finalize(pStmt);
                        ret = -1;
                        break;
                }
                
                /* Free the virtual machine */
                if ((ret = sqlite3_finalize(pStmt)) == SQLITE_SCHEMA) {
                        (void) sqlite3_finalize(pStmt);
                        continue;
                } else if (ret != SQLITE_OK) {
                        (void) sqlite3_finalize(pStmt);
                        ret = -1;
                        break;
                }
                
                /*
                 * Normal condition is only one time through loop.  Loop is
                 * rerun in error conditions, via "continue", above.
                 */
                ret = 0;
                bLoop = FALSE;
        }
        
        /* All done with variable argument list */
        va_end(args);
        
        gettimeofday(&tv, NULL);
        t1 = (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0);

        if (lsqlite3_debug & SQLITE3_DEBUG_QUERY) {
                printf("%1.6lf %s\n%s\n\n", t1 - t0,
                       ret == 0 ? "SUCCESS" : "FAIL",
                       p);
        }

        /* Free the memory we allocated for our query string */
        sqlite3_free(p);
        
        return ret;
}


/*
 * query_int()
 *
 * This function is used for the common case of queries that return a single
 * integer value.
 *
 * NOTE: If more than one value is returned by the query, all but the first
 * one will be ignored.
 */
static int
query_int(const struct lsqlite3_private * lsqlite3,
          long long * pRet,
          const char * pSql,
          ...)
{
        int             ret;
        int             bLoop;
        char *          p;
        sqlite3_stmt *  pStmt;
        va_list         args;
        double          t0;
        double          t1;
        struct timeval  tv;
        struct timezone tz;
        
        gettimeofday(&tv, &tz);
        t0 = (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0);

        /* Begin access to variable argument list */
        va_start(args, pSql);
        
        /* Format the query */
        if ((p = sqlite3_vmprintf(pSql, args)) == NULL) {
                return SQLITE_NOMEM;
        }
        
        if (lsqlite3_debug & SQLITE3_DEBUG_QUERY) {
                printf("%s\n", p);
        }

        /*
         * Prepare and execute the SQL statement.  Loop allows retrying on
         * certain errors, e.g. SQLITE_SCHEMA occurs if the schema changes,
         * requiring retrying the operation.
         */
        for (bLoop = TRUE; bLoop; ) {
                
                /* Compile the SQL statement into sqlite virtual machine */
                if ((ret = sqlite3_prepare(lsqlite3->sqlite,
                                           p,
                                           -1,
                                           &pStmt,
                                           NULL)) == SQLITE_SCHEMA) {
                        continue;
                } else if (ret != SQLITE_OK) {
                        break;
                }
                
                /* One row expected */
                if ((ret = sqlite3_step(pStmt)) == SQLITE_SCHEMA) {
                        (void) sqlite3_finalize(pStmt);
                        continue;
                } else if (ret != SQLITE_ROW) {
                        (void) sqlite3_finalize(pStmt);
                        break;
                }
                
                /* Get the value to be returned */
                *pRet = sqlite3_column_int64(pStmt, 0);
                
                /* Free the virtual machine */
                if ((ret = sqlite3_finalize(pStmt)) == SQLITE_SCHEMA) {
                        (void) sqlite3_finalize(pStmt);
                        continue;
                } else if (ret != SQLITE_OK) {
                        (void) sqlite3_finalize(pStmt);
                        break;
                }
                
                /*
                 * Normal condition is only one time through loop.  Loop is
                 * rerun in error conditions, via "continue", above.
                 */
                bLoop = FALSE;
        }
        
        /* All done with variable argument list */
        va_end(args);
        
        gettimeofday(&tv, NULL);
        t1 = (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0);

        if (lsqlite3_debug & SQLITE3_DEBUG_QUERY) {
                printf("%1.6lf %s\n%s\n\n", t1 - t0,
                       ret == 0 ? "SUCCESS" : "FAIL",
                       p);
        }

        /* Free the memory we allocated for our query string */
        sqlite3_free(p);
        
        return ret;
}


/*
  callback function used in call to ldb_dn_fold() for determining whether an
  attribute type requires case folding.
*/
static int
case_fold_attr_required(void * hUserData,
                        char *attr)
{
//        struct ldb_module * module = hUserData;
        
#warning "currently, all attributes require case folding"
        return TRUE;
}


/*
 * add a single set of ldap message values to a ldb_message
 */

static int
add_msg_attr(void * hTalloc,
             long long eid,
             const char * pDN,
             const char * pAttrName,
             const char * pAttrValue,
             long long prevEID,
             int * pAllocated,
             struct ldb_message *** pppRes)
{
        void *                       x;
        struct ldb_message *         msg;
	struct ldb_message_element * el;
        
        /* Is this a different EID than the previous one? */
        if (eid != prevEID) {
                /* Yup.  Add another result to the result array */
                if ((x = talloc_realloc(hTalloc,
                                        *pAllocated == 0 ? NULL : *pppRes,
                                        struct ldb_message *,
                                        *pAllocated + 1)) == NULL) {
                        
                        return -1;
                }
                
                /* Save the new result list */
                *pppRes = x;

                /* Allocate a new result structure */
                if ((x = talloc(*pppRes, struct ldb_message)) == NULL) {
                        return -1;
                }

                /* Save the new result */
                (*pppRes)[*pAllocated] = x;

                /* Steal the initial result and put it in its own context */
                talloc_steal(NULL, *pppRes);

                /* We've allocated one more result */
                ++*pAllocated;
                
                /* Ensure that the message is initialized */
                msg = x;
                if ((msg->dn = talloc_strdup(msg, pDN)) == NULL) {
                        return -1;
                }
                msg->num_elements = 0;
                msg->elements = NULL;
                msg->private_data = NULL;
        } else {
                /* Same EID.  Point to the previous most-recent message */
                msg = (*pppRes)[*pAllocated - 1];
        }
        
        if (pAttrName != NULL && pAttrValue != NULL) {
            /*
             * Point to the most recent previous element.  (If there are none,
             * this will point to non-allocated memory, but the pointer will
             * never be dereferenced.)
             */
            el = &msg->elements[msg->num_elements - 1];
        
            /*
             * See if the most recent previous element has the same attr_name
             */
            if (msg->num_elements == 0 || strcmp(el->name, pAttrName) != 0) {
                
                /* It's a new attr_name.  Allocate another message element */
                if ((el = talloc_realloc(msg,
                                         msg->elements,
                                         struct ldb_message_element, 
                                         msg->num_elements + 1)) == NULL) {
                    return -1;
                }
                
                /* Save the new element */
                msg->elements = el;
                
                /* Save the attribute name */
                if ((el->name =
                     talloc_strdup(msg->elements, pAttrName)) == NULL) {
                        
                    return -1;
                }
                
                /* There's now one additional element */
                msg->num_elements++;
                
                /* No flags */
                el->flags = 0;
                
                /* Initialize number of attribute values for this type */
                el->num_values = 0;
                el->values = NULL;
            }
        
            /* Increase the value array size by 1 */
            if ((el->values =
                 talloc_realloc(el,
                                el->num_values == 0 ? NULL : el->values,
                                struct ldb_val,
                                el->num_values + 1)) == NULL) {
                return -1;
            }
        
            /* Save the new attribute value length */
            el->values[el->num_values].length = strlen(pAttrValue);
        
            /* Copy the new attribute value */
            if ((el->values[el->num_values].data =
                 talloc_memdup(el->values,
                               pAttrValue,
                               el->values[el->num_values].length)) == NULL) {
                return -1;
            }
        
            /* We now have one additional value of this type */
            el->num_values++;
        }
        
	return 0;
}

static char *
parsetree_to_sql(struct ldb_module *module,
                 char * hTalloc,
                 const struct ldb_parse_tree *t)
{
	int                     i;
        char *                  pDN;
	char *                  child;
        char *                  p;
	char *                  ret = NULL;
        char *                  pAttrName;
        
        
	switch(t->operation) {
        case LDB_OP_SIMPLE:
                break;
                
        case LDB_OP_EXTENDED:
#warning  "work out how to handle bitops"
                return NULL;

        case LDB_OP_AND:
                ret = parsetree_to_sql(module,
                                       hTalloc,
                                       t->u.list.elements[0]);
                
                for (i = 1; i < t->u.list.num_elements; i++) {
                        child =
                                parsetree_to_sql(
                                        module,
                                        hTalloc,
                                        t->u.list.elements[i]);
                        ret = talloc_asprintf_append(ret,
                                                     "INTERSECT\n"
                                                     "%s\n",
                                                     child);
                        talloc_free(child);
                }
                
                child = ret;
                ret = talloc_asprintf(hTalloc,
                                      "SELECT * FROM (\n"
                                      "%s\n"
                                      ")\n",
                                      child);
                talloc_free(child);
                return ret;
                
        case LDB_OP_OR:
                ret = parsetree_to_sql(module,
                                       hTalloc,
                                       t->u.list.elements[0]);
                
                for (i = 1; i < t->u.list.num_elements; i++) {
                        child =
                                parsetree_to_sql(
                                        module,
                                        hTalloc,
                                        t->u.list.elements[i]);
                        ret = talloc_asprintf_append(ret,
                                                     "UNION\n"
                                                     "%s\n",
                                                     child);
                        talloc_free(child);
                }
                child = ret;
                ret = talloc_asprintf(hTalloc,
                                      "SELECT * FROM (\n"
                                      "%s\n"
                                      ")\n",
                                      child);
                talloc_free(child);
                return ret;
                
        case LDB_OP_NOT:
                child =
                        parsetree_to_sql(
                                module,
                                hTalloc,
                                t->u.not.child);
                ret = talloc_asprintf(hTalloc,
                                      "  SELECT eid\n"
                                      "    FROM ldb_entry\n"
                                      "    WHERE eid NOT IN (%s)\n",
                                      child);
                talloc_free(child);
                return ret;
                
        default:
                /* should never occur */
                abort();
	};
        
        /* Get a case-folded copy of the attribute name */
        pAttrName = ldb_casefold((struct ldb_context *) module,
                                 t->u.simple.attr);
        
        /*
         * For simple searches, we want to retrieve the list of EIDs that
         * match the criteria.
         */
        if (t->u.simple.value.length == 1 &&
            (*(const char *) t->u.simple.value.data) == '*') {
		/*
                 * Special case for "attr_name=*".  In this case, we want the
                 * eid corresponding to all values in the specified attribute
                 * table.
                 */
                if ((p = sqlite3_mprintf("  SELECT eid\n"
                                         "    FROM ldb_attribute_values\n"
                                         "    WHERE attr_name = %Q",
                                     pAttrName)) == NULL) {
                        return NULL;
                }
                
                if (lsqlite3_debug & SQLITE3_DEBUG_QUERY) {
                        printf("%s\n", p);
                }

                ret = talloc_strdup(hTalloc, p);
                sqlite3_free(p);

	} else if (strcasecmp(t->u.simple.attr, "objectclass") == 0) {
		/*
                 * For object classes, we want to search for all objectclasses
                 * that are subclasses as well.
                 */
                if ((p = sqlite3_mprintf(
                             "  SELECT eid\n"
                             "    FROM ldb_attribute_values\n"
                             "    WHERE attr_name = 'OBJECTCLASS' "
                             "      AND attr_value_normalized IN\n"
                             "      (SELECT class_name\n"
                             "         FROM ldb_object_classes\n"
                             "         WHERE tree_key GLOB\n"
                             "           (SELECT tree_key\n"
                             "              FROM ldb_object_classes\n"
                             "              WHERE class_name = upper(%Q)) "
                             "           || '*')\n",
                             t->u.simple.value.data)) == NULL) {
                        return NULL;
                }
                
                if (lsqlite3_debug & SQLITE3_DEBUG_QUERY) {
                        printf("%s\n", p);
                }

                ret = talloc_strdup(hTalloc, p);
                sqlite3_free(p);
                
        } else if (strcasecmp(t->u.simple.attr, "dn") == 0) {
                pDN = ldb_dn_fold(module->ldb, t->u.simple.value.data,
                                  module, case_fold_attr_required);
                if ((p = sqlite3_mprintf(
                             "  SELECT eid\n"
                             "    FROM ldb_attribute_values\n"
                             "    WHERE attr_name = %Q\n"
                             "      AND attr_value_normalized = upper(%Q)\n",
                             pAttrName,
                             pDN)) == NULL) {
                        return NULL;
                }
                
                if (lsqlite3_debug & SQLITE3_DEBUG_QUERY) {
                        printf("%s\n", p);
                }

                ret = talloc_strdup(hTalloc, p);
                sqlite3_free(p);
	} else {
                /* A normal query. */
                if ((p = sqlite3_mprintf(
                             "  SELECT eid\n"
                             "    FROM ldb_attribute_values\n"
                             "    WHERE attr_name = %Q\n"
                             "      AND attr_value_normalized = upper(%Q)\n",
                             pAttrName,
                             t->u.simple.value.data)) == NULL) {
                        return NULL;
                }
                
                if (lsqlite3_debug & SQLITE3_DEBUG_QUERY) {
                        printf("%s\n", p);
                }

                ret = talloc_strdup(hTalloc, p);
                sqlite3_free(p);
	}

	return ret;
}


static int
parsetree_to_attrlist(struct ldb_module *module,
                      const struct ldb_parse_tree * t)
{
	int                         i;
        struct lsqlite3_private *   lsqlite3 = module->private_data;
        
	switch(t->operation) {
        case LDB_OP_SIMPLE:
                break;
                
        case LDB_OP_EXTENDED:
#warning  "work out how to handle bitops"
                return -1;

        case LDB_OP_AND:
                if (parsetree_to_attrlist(
                            module,
                            t->u.list.elements[0]) != 0) {
                        return -1;
                }
                
                for (i = 1; i < t->u.list.num_elements; i++) {
                        if (parsetree_to_attrlist(
                                    module,
                                    t->u.list.elements[i]) != 0) {
                                return -1;
                        }
                }
                
                return 0;
                
        case LDB_OP_OR:
                if (parsetree_to_attrlist(
                            module,
                            t->u.list.elements[0]) != 0) {
                        return -1;
                }
                
                for (i = 1; i < t->u.list.num_elements; i++) {
                        if (parsetree_to_attrlist(
                                    module,
                                    t->u.list.elements[i]) != 0) {
                                return -1;
                        }
                }
                
                return 0;
                
        case LDB_OP_NOT:
                if (parsetree_to_attrlist(module,
                                          t->u.not.child) != 0) {
                        return -1;
                }
                
                return 0;
                
        default:
                /* should never occur */
                abort();
	};
        
        QUERY_NOROWS(lsqlite3,
                     FALSE,
                     "INSERT OR IGNORE INTO " FILTER_ATTR_TABLE "\n"
                     "    (attr_name)\n"
                     "  VALUES\n"
                     "    (%Q);",
                     t->u.simple.attr);
	return 0;
}


/*
 * Issue a series of SQL statements to implement the ADD/MODIFY/DELETE
 * requests in the ldb_message
 */
static int
msg_to_sql(struct ldb_module * module,
           const struct ldb_message * msg,
           long long eid,
           int use_flags)
{
        int                         flags;
        char *                      pAttrName;
	unsigned int                i;
        unsigned int                j;
	struct lsqlite3_private *   lsqlite3 = module->private_data;
        
	for (i = 0; i < msg->num_elements; i++) {
		const struct ldb_message_element *el = &msg->elements[i];
                
                if (! use_flags) {
                        flags = LDB_FLAG_MOD_ADD;
                } else {
                        flags = el->flags & LDB_FLAG_MOD_MASK;
                }
                
                /* Get a case-folded copy of the attribute name */
                pAttrName = ldb_casefold((struct ldb_context *) module,
                                         el->name);
                
                /* For each value of the specified attribute name... */
		for (j = 0; j < el->num_values; j++) {
                        
                        /* ... bind the attribute value, if necessary */
                        switch (flags) {
                        case LDB_FLAG_MOD_ADD:
                                QUERY_NOROWS(
                                        lsqlite3,
                                        FALSE,
                                        "INSERT INTO ldb_attribute_values\n"
                                        "    (eid,\n"
                                        "     attr_name,\n"
                                        "     attr_value,\n"
                                        "     attr_value_normalized)\n"
                                        "  VALUES\n"
                                        "    (%lld, %Q, %Q, upper(%Q));",
                                        eid,
                                        pAttrName,
                                        el->values[j].data, /* FIX ME */
                                        el->values[j].data);

                                /* Is this a special "objectclass"? */
                                if (strcasecmp(pAttrName,
                                               "objectclass") != 0) {
                                        /* Nope. */
                                        break;
                                }

                                /* Handle special "objectclass" type */
                                QUERY_NOROWS(lsqlite3,
                                             FALSE,
                                             "INSERT OR IGNORE "
                                             "  INTO ldb_object_classes "
                                             "    (class_name, "
                                             "     parent_class_name) "
                                             "  VALUES "
                                             "    (upper(%Q), 'TOP');",
                                             ldb_casefold(module,
                                                          el->values[j].data));
                                break;
                                
                        case LDB_FLAG_MOD_REPLACE:
                                QUERY_NOROWS(
                                        lsqlite3,
                                        FALSE,
                                        "UPDATE ldb_attribute_values\n"
                                        "  SET attr_value = %Q,\n"
                                        "      attr_value_normalized =\n"
                                        "          upper(%Q)\n"
                                        "  WHERE eid = %lld\n"
                                        "    AND attr_name = %Q;",
                                        el->values[j].data, /* FIX ME */
                                        el->values[j].data,
                                        eid,
                                        pAttrName);
                                break;
                                
                        case LDB_FLAG_MOD_DELETE:
                                /* No additional parameters to this query */
                                QUERY_NOROWS(
                                        lsqlite3,
                                        FALSE,
                                        "DELETE FROM ldb_attribute_values"
                                        "  WHERE eid = %lld "
                                        "    AND attr_name = %Q "
                                        "    AND attr_value_normalized =\n"
                                        "            upper(%Q);",
                                        eid,
                                        el->name,
                                        el->values[j].data);
                                break;
                        }
		}
	}
        
	return 0;
}



static int
new_dn(struct ldb_module * module,
       char * pDN,
       long long * pEID)
{
        int                         nComponent;
        int                         bFirst;
        char *                      p;
        char *                      pPartialDN;
        long long                   eid;
        long long                   peid;
        double                      t0 = 0;
        double                      t1 = 0;
        struct timeval              tv;
        struct timezone             tz;
        struct ldb_dn *             pExplodedDN;
        struct ldb_dn_component *   pComponent;
	struct ldb_context *        ldb = module->ldb;
	struct lsqlite3_private *   lsqlite3 = module->private_data;
        
        if (lsqlite3_debug & SQLITE3_DEBUG_NEWDN) {
                gettimeofday(&tv, &tz);
                t0 = (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0);
        }

        /* Explode and normalize the DN */
        if ((pExplodedDN =
             ldb_explode_dn(ldb,
                            pDN,
                            ldb,
                            case_fold_attr_required)) == NULL) {
                return -1;
        }
        
        if (lsqlite3_debug & SQLITE3_DEBUG_NEWDN) {
                gettimeofday(&tv, NULL);
                t1 = (double) tv.tv_sec + ((double) tv.tv_usec / 1000000.0);
                printf("%1.6lf loc 1\n", t1 - t0);
                t0 = t1;
        }

        /* Allocate a string to hold the partial DN of each component */
        if ((pPartialDN = talloc_strdup(ldb, "")) == NULL) {
                return -1;
        }
        
        /* For each component of the DN (starting with the last one)... */
#warning "convert this loop to recursive, and search backwards instead"
        eid = 0;

        for (nComponent = pExplodedDN->comp_num - 1, bFirst = TRUE;
             nComponent >= 0;
             nComponent--, bFirst = FALSE) {
                
                if (lsqlite3_debug & SQLITE3_DEBUG_NEWDN) {
                        gettimeofday(&tv, NULL);
                        t1 = ((double) tv.tv_sec +
                              ((double) tv.tv_usec / 1000000.0));
                        printf("%1.6lf loc 2\n", t1 - t0);
                        t0 = t1;
                }
                
                /* Point to the component */
                pComponent = pExplodedDN->components[nComponent];
                
                /* Add this component on to the partial DN to date */
                if ((p = talloc_asprintf(ldb,
                                         "%s%s%s",
                                         pComponent->component,
                                         bFirst ? "" : ",",
                                         pPartialDN)) == NULL) {
                        return -1;
                }
                
                if (lsqlite3_debug & SQLITE3_DEBUG_NEWDN) {
                        gettimeofday(&tv, NULL);
                        t1 = ((double) tv.tv_sec +
                              ((double) tv.tv_usec / 1000000.0));
                        printf("%1.6lf loc 3\n", t1 - t0);
                        t0 = t1;
                }
                
                /* No need for the old partial DN any more */
                talloc_free(pPartialDN);
                
                /* Save the new partial DN */
                pPartialDN = p;
                
                if (lsqlite3_debug & SQLITE3_DEBUG_NEWDN) {
                        gettimeofday(&tv, NULL);
                        t1 = ((double) tv.tv_sec +
                              ((double) tv.tv_usec / 1000000.0));
                        printf("%1.6lf loc 4\n", t1 - t0);
                        t0 = t1;
                }
                
                /*
                 * Ensure that an entry is in the ldb_entry table for this
                 * component.  Any component other than the last one
                 * (component 0) may already exist.  It is an error if
                 * component 0 (the full DN requested to be be inserted)
                 * already exists.
                 */
                QUERY_NOROWS(lsqlite3,
                             FALSE,
                             "INSERT %s INTO ldb_entry\n"
                             "    (peid, dn)\n"
                             "  VALUES\n"
                             "    (%lld, %Q);",
                             nComponent == 0 ? "" : "OR IGNORE",
                             eid, pPartialDN);
                
                /* Save the parent EID */
                peid = eid;
                
                if (lsqlite3_debug & SQLITE3_DEBUG_NEWDN) {
                        gettimeofday(&tv, NULL);
                        t1 = ((double) tv.tv_sec +
                              ((double) tv.tv_usec / 1000000.0));
                        printf("%1.6lf loc 5\n", t1 - t0);
                        t0 = t1;
                }
                
                /* Get the EID of the just inserted row */
                QUERY_INT(lsqlite3,
                          eid,
                          FALSE,
                          "SELECT eid "
                          "  FROM ldb_entry "
                          "  WHERE dn = %Q;",
                          pPartialDN);

                if (lsqlite3_debug & SQLITE3_DEBUG_NEWDN) {
                        gettimeofday(&tv, NULL);
                        t1 = ((double) tv.tv_sec +
                              ((double) tv.tv_usec / 1000000.0));
                        printf("%1.6lf loc 8\n", t1 - t0);
                        t0 = t1;
                }
                
                /* Also add DN attribute */
                QUERY_NOROWS(lsqlite3,
                             FALSE,
                             "INSERT %s INTO ldb_attribute_values\n"
                             "    (eid,\n"
                             "     attr_name,\n"
                             "     attr_value,\n"
                             "     attr_value_normalized) "
                             "  VALUES "
                             "    (%lld, 'DN', %Q, upper(%Q));",
                             nComponent == 0 ? "" : "OR IGNORE",
                             eid,
                             pPartialDN, /* FIX ME */
                             pPartialDN);
        }
        
        if (lsqlite3_debug & SQLITE3_DEBUG_NEWDN) {
                gettimeofday(&tv, NULL);
                t1 = ((double) tv.tv_sec +
                      ((double) tv.tv_usec / 1000000.0));
                printf("%1.6lf loc 9\n", t1 - t0);
                t0 = t1;
        }
                
        /* Give 'em what they came for! */
        *pEID = eid;
        
        return 0;
}


static unsigned char        base160tab[161] = {
        48 ,49 ,50 ,51 ,52 ,53 ,54 ,55 ,56 ,57 , /* 0-9 */
        58 ,59 ,65 ,66 ,67 ,68 ,69 ,70 ,71 ,72 , /* : ; A-H */
        73 ,74 ,75 ,76 ,77 ,78 ,79 ,80 ,81 ,82 , /* I-R */
        83 ,84 ,85 ,86 ,87 ,88 ,89 ,90 ,97 ,98 , /* S-Z , a-b */
        99 ,100,101,102,103,104,105,106,107,108, /* c-l */
        109,110,111,112,113,114,115,116,117,118, /* m-v */
        119,120,121,122,160,161,162,163,164,165, /* w-z, latin1 */
        166,167,168,169,170,171,172,173,174,175, /* latin1 */
        176,177,178,179,180,181,182,183,184,185, /* latin1 */
        186,187,188,189,190,191,192,193,194,195, /* latin1 */
        196,197,198,199,200,201,202,203,204,205, /* latin1 */
        206,207,208,209,210,211,212,213,214,215, /* latin1 */
        216,217,218,219,220,221,222,223,224,225, /* latin1 */
        226,227,228,229,230,231,232,233,234,235, /* latin1 */
        236,237,238,239,240,241,242,243,244,245, /* latin1 */
        246,247,248,249,250,251,252,253,254,255, /* latin1 */
        '\0'
};


/*
 * base160()
 *
 * Convert an unsigned long integer into a base160 representation of the
 * number.
 *
 * Parameters:
 *   val --
 *     value to be converted
 *
 *   result --
 *     character array, 5 bytes long, into which the base160 representation
 *     will be placed.  The result will be a four-digit representation of the
 *     number (with leading zeros prepended as necessary), and null
 *     terminated.
 *
 * Returns:
 *   Nothing
 */
static void
base160_sql(sqlite3_context * hContext,
            int argc,
            sqlite3_value ** argv)
{
    int             i;
    long long       val;
    char            result[5];

    val = sqlite3_value_int64(argv[0]);

    for (i = 3; i >= 0; i--) {
        
        result[i] = base160tab[val % 160];
        val /= 160;
    }

    result[4] = '\0';

    sqlite3_result_text(hContext, result, -1, SQLITE_TRANSIENT);
}


/*
 * base160next_sql()
 *
 * This function enhances sqlite by adding a "base160_next()" function which is
 * accessible via queries.
 *
 * Retrieve the next-greater number in the base160 sequence for the terminal
 * tree node (the last four digits).  Only one tree level (four digits) is
 * operated on.
 *
 * Input:
 *   A character string: either an empty string (in which case no operation is
 *   performed), or a string of base160 digits with a length of a multiple of
 *   four digits.
 *
 * Output:
 *   Upon return, the trailing four digits (one tree level) will have been
 *   incremented by 1.
 */
static void
base160next_sql(sqlite3_context * hContext,
                int argc,
                sqlite3_value ** argv)
{
        int                         i;
        int                         len;
        unsigned char *             pTab;
        unsigned char *             pBase160 =
                strdup(sqlite3_value_text(argv[0]));
        unsigned char *             pStart = pBase160;

        /*
         * We need a minimum of four digits, and we will always get a multiple
         * of four digits.
         */
        if (pBase160 != NULL &&
            (len = strlen(pBase160)) >= 4 &&
            len % 4 == 0) {

                if (pBase160 == NULL) {

                        sqlite3_result_null(hContext);
                        return;
                }

                pBase160 += strlen(pBase160) - 1;

                /* We only carry through four digits: one level in the tree */
                for (i = 0; i < 4; i++) {

                        /* What base160 value does this digit have? */
                        pTab = strchr(base160tab, *pBase160);

                        /* Is there a carry? */
                        if (pTab < base160tab + sizeof(base160tab) - 1) {

                                /*
                                 * Nope.  Just increment this value and we're
                                 * done.
                                 */
                                *pBase160 = *++pTab;
                                break;
                        } else {

                                /*
                                 * There's a carry.  This value gets
                                 * base160tab[0], we decrement the buffer
                                 * pointer to get the next higher-order digit,
                                 * and continue in the loop.
                                 */
                                *pBase160-- = base160tab[0];
                        }
                }

                sqlite3_result_text(hContext,
                                    pStart,
                                    strlen(pStart),
                                    free);
        } else {
                sqlite3_result_value(hContext, argv[0]);
                if (pBase160 != NULL) {
                        free(pBase160);
                }
        }
}


#ifdef DEBUG_LOCKS
static int lock_debug(struct ldb_module * module,
                      const char * lockname,
                      const char * pFileName,
                      int linenum)
{
        int                         ret;
        struct lsqlite3_private *   lsqlite3 = module->private_data;

        printf("%s(%d): LOCK (%d) ",
               pFileName, linenum, lsqlite3->lock_count);
        ret = lsqlite3_lock(module, lockname);
        printf("got %d\n", ret);

        return ret;
}
                      

static int unlock_debug(struct ldb_module * module,
                        const char * lockname,
                        const char * pFileName,
                        int linenum)
{
        int                         ret;
        struct lsqlite3_private *   lsqlite3 = module->private_data;

        ret = lsqlite3_unlock(module, lockname);
        printf("%s(%d): UNLOCK (%d) got %d\n",
               pFileName, linenum, lsqlite3->lock_count, ret);

        return ret;
}
#endif                      
