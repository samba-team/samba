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

#define QUERY_NOROWS(lsqlite3, bRollbackOnError, sql...)        \
        do {                                                    \
                if (query_norows(lsqlite3, sql) != 0) {         \
                        if (bRollbackOnError) {                 \
                                query_norows(lsqlite3,          \
                                             "ROLLBACK;");      \
                        }                                       \
                        return -1;                              \
                }                                               \
        } while (0)

#define QUERY_INT(lsqlite3, result_var, bRollbackOnError, sql...)       \
        do {                                                            \
                if (query_int(lsqlite3, &result_var, sql) != 0) {       \
                        if (bRollbackOnError) {                         \
                                query_norows(lsqlite3,                  \
                                             "ROLLBACK;");              \
                        }                                               \
                        return -1;                                      \
                }                                                       \
        } while (0)


/*
 * Static variables
 */
static int      lsqlite3_debug = TRUE;


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
parsetree_to_attrlist(struct lsqlite3_private * lsqlite3,
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

static int
new_attr(struct ldb_module * module,
         char * pAttrName);


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
struct ldb_context *
lsqlite3_connect(const char *url, 
                 unsigned int flags, 
                 const char *options[])
{
	int                         i;
        int                         ret;
	struct ldb_context *        ldb = NULL;
	struct lsqlite3_private *   lsqlite3 = NULL;
        
	ldb = talloc(NULL, struct ldb_context);
	if (!ldb) {
		goto failed;
	}
        
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
        
	return ldb;
        
failed:
        if (lsqlite3->sqlite != NULL) {
                (void) sqlite3_close(lsqlite3->sqlite);
        }
	talloc_free(ldb);
	return NULL;
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
	struct lsqlite3_private *   lsqlite3 = module->private_data;

        /* Case-fold each of the DNs */
        pOldDN = ldb_dn_fold(module->ldb, pOldDN,
                             module, case_fold_attr_required);
        pNewDN = ldb_dn_fold(module->ldb, pNewDN,
                             module, case_fold_attr_required);

        QUERY_NOROWS(lsqlite3,
                     FALSE,
                     "UPDATE ldb_entry "
                     "  SET dn = %Q "
                     "  WHERE dn = %Q;",
                     pNewDN, pOldDN);

        return 0;
}

/* delete a record */
static int
lsqlite3_delete(struct ldb_module * module,
                const char * pDN)
{
        int                         ret;
        int                         bLoop;
        long long                   eid;
        char *                      pSql;
        const char *                pAttrName;
        sqlite3_stmt *              pStmt;
	struct lsqlite3_private *   lsqlite3 = module->private_data;

        /* Begin a transaction */
        QUERY_NOROWS(lsqlite3, FALSE, "BEGIN EXCLUSIVE;");

        /* Determine the eid of the DN being deleted */
        QUERY_INT(lsqlite3,
                  eid,
                  TRUE,
                  "SELECT eid\n"
                  "  FROM ldb_entry\n"
                  "  WHERE dn = %Q;",
                  pDN);
        
        /* Obtain the list of attribute names in use by this DN */
        if ((pSql = talloc_asprintf(module->ldb,
                                    "SELECT attr_name "
                                    "  FROM ldb_attribute_values "
                                    "  WHERE eid = %lld;",
                                    eid)) == NULL) {
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
                                           pSql,
                                           -1,
                                           &pStmt,
                                           NULL)) == SQLITE_SCHEMA) {
                        continue;
                } else if (ret != SQLITE_OK) {
                        ret = -1;
                        break;
                }
                
                /* Loop through the returned rows */
                for (ret = SQLITE_ROW; ret == SQLITE_ROW; ) {
                        
                        /* Get the next row */
                        if ((ret = sqlite3_step(pStmt)) == SQLITE_ROW) {
                                
                                /* Get the values from this row */
                                pAttrName = sqlite3_column_text(pStmt, 0);
                                
                                /*
                                 * Delete any entries from the specified
                                 * attribute table that pertain to this eid.
                                 */
                                QUERY_NOROWS(lsqlite3,
                                             TRUE,
                                             "DELETE FROM ldb_attr_%q "
                                             "  WHERE eid = %lld;",
                                             pAttrName, eid);
                        }
                }
                
                if (ret == SQLITE_SCHEMA) {
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
        
        /* Delete the descendants records */
        QUERY_NOROWS(lsqlite3,
                     TRUE,
                     "DELETE FROM ldb_descendants "
                     "  WHERE deid = %lld;",
                     eid);

        /* Delete attribute/value table entries pertaining to this DN */
        QUERY_NOROWS(lsqlite3,
                     TRUE,
                     "DELETE FROM ldb_attribute_value "
                     "  WHERE eid = %lld;",
                     eid);

        /* Commit the transaction */
        QUERY_NOROWS(lsqlite3, TRUE, "COMMIT;");
        
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
        QUERY_NOROWS(lsqlite3, FALSE, "BEGIN IMMEDIATE;");
        
        /*
         * Obtain the eid of the base DN
         */
        if ((ret = query_int(lsqlite3,
                             &eid,
                             "SELECT eid\n"
                             "  FROM ldb_attr_DN\n"
                             "  WHERE attr_value = %Q;",
                             pBaseDN)) == SQLITE_DONE) {
                QUERY_NOROWS(lsqlite3, FALSE, "ROLLBACK;");
                talloc_free(hTalloc);
                return 0;
        } else if (ret != SQLITE_OK) {
                QUERY_NOROWS(lsqlite3, FALSE, "ROLLBACK;");
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
        if (attrs == NULL) {
                /* but they didn't give us any so we'll retrieve all of 'em */
                pResultAttrList = "";
        } else {
                /* Discover the list of attributes */
                pResultAttrList = NULL;
        }

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
                        "    AND av.attr_name IN\n"
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
        if ((ret = parsetree_to_attrlist(lsqlite3, pTree)) != 0) {
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
                        "  FROM ldb_entry AS entry,\n"
                        "       ldb_attribute_values AS av\n"
                        "  WHERE entry.eid IN\n"
                        "    (SELECT DISTINCT ldb_entry.eid\n"
                        "       FROM ldb_entry,\n"
                        "            ldb_descendants\n"
                        "       WHERE ldb_descendants.aeid = %lld\n"
                        "         AND ldb_entry.eid = ldb_descendants.deid\n"
                        "         AND ldb_entry.eid IN\n%s\n"
                        "    )\n"
                        "    AND av.eid = entry.eid\n"
                        "    %s\n"
                        "  ORDER BY av.eid, av.attr_name;",
                        eid,
                        pSqlConstraints,
                        pResultAttrList);
                break;
                
        case LDB_SCOPE_BASE:
                pSql = sqlite3_mprintf(
                        "SELECT entry.eid,\n"
                        "       entry.dn,\n"
                        "       av.attr_name,\n"
                        "       av.attr_value\n"
                        "  FROM ldb_entry AS entry,\n"
                        "       ldb_attribute_values AS av\n"
                        "  WHERE entry.eid IN\n"
                        "    (SELECT DISTINCT ldb_entry.eid\n"
                        "       FROM ldb_entry\n"
                        "       WHERE ldb_entry.eid = %lld\n"
                        "         AND ldb_entry.eid IN\n%s\n"
                        "    )\n"
                        "    AND av.eid = entry.eid\n"
                        "    %s\n"
                        "  ORDER BY av.eid, av.attr_name;",
                        eid,
                        pSqlConstraints,
                        pResultAttrList);
                break;
                
        case LDB_SCOPE_ONELEVEL:
                pSql = sqlite3_mprintf(
                        "SELECT entry.eid,\n"
                        "       entry.dn,\n"
                        "       av.attr_name,\n"
                        "       av.attr_value\n"
                        "  FROM ldb_entry AS entry,\n"
                        "       ldb_attribute_values AS av\n"
                        "  WHERE entry.eid IN\n"
                        "    (SELECT DISTINCT ldb_entry.eid\n"
                        "       FROM ldb_entry AS pchild\n"
                        "       WHERE ldb_entry.eid = pchild.eid\n"
                        "         AND pchild.peid = %lld\n"
                        "         AND ldb_entry.eid IN\n%s\n"
                        "    )\n"
                        "    AND av.eid = entry.eid\n"
                        "    %s\n"
                        "  ORDER BY av.eid, av.attr_name;\n",
                        eid,
                        pSqlConstraints,
                        pResultAttrList);
                break;
        }
        
        if (pSql == NULL) {
                ret = -1;
                goto cleanup;
        }

        if (lsqlite3_debug) {
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
                                if ((ret = add_msg_attr(hTalloc,
                                                        eid,
                                                        pDN,
                                                        pAttrName,
                                                        pAttrValue,
                                                        prevEID,
                                                        &allocated,
                                                        pppRes)) != 0) {
                                        
                                        (void) sqlite3_finalize(pStmt);
                                        ret = -1;
                                        break;
                                }
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
        QUERY_NOROWS(lsqlite3, FALSE, "END TRANSACTION;");
        
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
	struct lsqlite3_private *   lsqlite3 = module->private_data;
        
	/* ignore ltdb specials */
	if (msg->dn[0] == '@') {
		return 0;
	}
        
        /* Begin a transaction */
        QUERY_NOROWS(lsqlite3, FALSE, "BEGIN EXCLUSIVE;");
        
        /*
         * Build any portions of the directory tree that don't exist.  If the
         * final component already exists, it's an error.
         */
        if (new_dn(module, msg->dn, &eid) != 0) {
                QUERY_NOROWS(lsqlite3, FALSE, "ROLLBACK;");
                return -1;
        }
        
        /* Add attributes to this new entry */
	if (msg_to_sql(module, msg, eid, FALSE) != 0) {
                QUERY_NOROWS(lsqlite3, FALSE, "ROLLBACK;");
                return -1;
        }
        
        /* Everything worked.  Commit it! */
        QUERY_NOROWS(lsqlite3, TRUE, "COMMIT;");
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
	if (msg->dn[0] == '@') {
		return 0;
	}
        
        /* Begin a transaction */
        QUERY_NOROWS(lsqlite3, FALSE, "BEGIN EXCLUSIVE;");
        
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
                QUERY_NOROWS(lsqlite3, FALSE, "ROLLBACK;");
                return -1;
        }
        

        /* Everything worked.  Commit it! */
        QUERY_NOROWS(lsqlite3, TRUE, "COMMIT;");
        return 0 ;
}

/* obtain a named lock */
static int
lsqlite3_lock(struct ldb_module *module,
              const char *lockname)
{
	if (lockname == NULL) {
		return -1;
	}
        
	/* TODO implement a local locking mechanism here */
        
	return 0;
}

/* release a named lock */
static int
lsqlite3_unlock(struct ldb_module *module,
                const char *lockname)
{
	if (lockname == NULL) {
		return -1;
	}
        
	/* TODO implement a local locking mechanism here */
        
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
                "  dn                    TEXT UNIQUE,"
                "  create_timestamp      INTEGER,"
                "  modify_timestamp      INTEGER"
                ");"
                

                /*
                 * The purpose of the descendant table is to support the
                 * subtree search feature.  For each LDB entry with a unique
                 * ID (AEID), this table contains the unique identifiers
                 * (DEID) of the descendant entries.
                 *
                 * For evern entry in the directory, a row exists in this
                 * table for each of its ancestors including itself.  The 
                 * size of the table depends on the depth of each entry.  In 
                 * the worst case, if all the entries were at the same 
                 * depth, the number of rows in the table is O(nm) where 
                 * n is the number of nodes in the directory and m is the 
                 * depth of the tree. 
                 */
                "CREATE TABLE ldb_descendants "
                "( "
                "  aeid                  INTEGER REFERENCES ldb_entry,"
                "  deid                  INTEGER REFERENCES ldb_entry"
                ");"
                
                
                "CREATE TABLE ldb_object_classes"
                "("
                "  class_name            TEXT PRIMARY KEY,"
                "  tree_key              TEXT UNIQUE"
                ");"
                
                /*
                 * We keep a full listing of attribute/value pairs here
                 */
                "CREATE TABLE ldb_attribute_values"
                "("
                "  eid                   INTEGER REFERENCES ldb_entry,"
                "  attr_name             TEXT,"
                "  attr_value            TEXT"
                ");"
                
                /*
                 * There is one attribute table per searchable attribute.
                 */
                /*
                "CREATE TABLE ldb_attr_ATTRIBUTE_NAME"
                "("
                "  eid                   INTEGER REFERENCES ldb_entry,"
                "  attr_value            TEXT"
                ");"
                */
                
                /*
                 * We pre-create the dn attribute table
                 */
                "CREATE TABLE ldb_attr_DN"
                "("
                "  eid                   INTEGER REFERENCES ldb_entry,"
                "  attr_value            TEXT"
                ");"

                
                /*
                 * We pre-create the objectclass attribute table
                 */
                "CREATE TABLE ldb_attr_OBJECTCLASS"
                "("
                "  eid                   INTEGER REFERENCES ldb_entry,"
                "  attr_value            TEXT"
                ");"

                
                /*
                 * Indexes
                 */
                
                
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
                "        WHERE eid = new.eid;"
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
                
                /*
                 * Table initialization
                 */

                /* The root node */
                "INSERT INTO ldb_entry "
                "    (eid, peid, dn) "
                "  VALUES "
                "    (0, NULL, '');"

                /* And the root node "dn" attribute */
                "INSERT INTO ldb_attr_DN "
                "    (eid, attr_value) "
                "  VALUES "
                "    (0, '');"

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
        QUERY_NOROWS(lsqlite3, FALSE, "PRAGMA auto_vacuum=1;");
        
        /* Begin a transaction */
        QUERY_NOROWS(lsqlite3, FALSE, "BEGIN EXCLUSIVE;");
        
        /* Determine if this is a new database.  No tables means it is. */
        QUERY_INT(lsqlite3,
                  queryInt,
                  TRUE,
                  "SELECT COUNT(*)\n"
                  "  FROM sqlite_master\n"
                  "  WHERE type = 'table';");
        
        if (queryInt == 0) {
                /*
                 * Create the database schema
                 */
                for (pTail = discard_const_p(char, schema);
                     pTail != NULL && *pTail != '\0';
                        ) {
                        
                        if (lsqlite3_debug) {
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
                                
                                QUERY_NOROWS(lsqlite3, FALSE, "ROLLBACK;");
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
                              "  (SELECT COUNT(*) = 3"
                              "     FROM sqlite_master "
                              "     WHERE type = 'table' "
                              "       AND name IN "
                              "         ("
                              "           'ldb_entry', "
                              "           'ldb_descendants', "
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
                        QUERY_NOROWS(lsqlite3, FALSE, "ROLLBACK;");
                        (void) sqlite3_close(lsqlite3->sqlite);
                        return SQLITE_MISUSE;
                }
        }
        
        /*
         * Create a temporary table to hold attributes requested in the result
         * set of a search.
         */
        QUERY_NOROWS(lsqlite3,
                     FALSE,
                     "CREATE TEMPORARY TABLE " RESULT_ATTR_TABLE "\n"
                     " (\n"
                     "  attr_name TEXT PRIMARY KEY\n"
                     " );");
        
        /*
         * Create a temporary table to hold the attributes used by filters
         * during a search.
         */
        QUERY_NOROWS(lsqlite3,
                     FALSE,
                     "CREATE TEMPORARY TABLE " FILTER_ATTR_TABLE "\n"
                     " (\n"
                     "  attr_name TEXT PRIMARY KEY\n"
                     " );");
        
        /* Commit the transaction */
        QUERY_NOROWS(lsqlite3, FALSE, "COMMIT;");
        
        return SQLITE_OK;
}

static int
destructor(void *p)
{
	struct lsqlite3_private *   lsqlite3 = p;
        
        (void) sqlite3_close(lsqlite3->sqlite);
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
        
        /* Begin access to variable argument list */
        va_start(args, pSql);
        
        /* Format the query */
        if ((p = sqlite3_vmprintf(pSql, args)) == NULL) {
                return -1;
        }
        
        if (lsqlite3_debug) {
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
        
        /* Begin access to variable argument list */
        va_start(args, pSql);
        
        /* Format the query */
        if ((p = sqlite3_vmprintf(pSql, args)) == NULL) {
                return SQLITE_NOMEM;
        }
        
        if (lsqlite3_debug) {
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
                                        *pAllocated == 0 ? NULL : pppRes,
                                        struct ldb_message *,
                                        *pAllocated + 1)) == NULL) {
                        
                        return -1;
                }
                
                /* Save the new result list */
                *pppRes = x;
                
                /* We've allocated one more result */
                *pAllocated++;
                
                /* Ensure that the message is initialized */
                msg = x;
                msg->dn = NULL;
                msg->num_elements = 0;
                msg->elements = NULL;
                msg->private_data = NULL;
        } else {
                /* Same EID.  Point to the previous most-recent message */
                msg = *pppRes[*pAllocated - 1];
        }
        
        /*
         * Point to the most recent previous element.  (If there are none,
         * this will point to non-allocated memory, but the pointer will never
         * be dereferenced.)
         */
        el = &msg->elements[msg->num_elements - 1];
        
        /* See if the most recent previous element has the same attr_name */
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
                
                /* There's now one additional element */
                msg->num_elements++;
                
                /* Save the attribute name */
                if ((el->name =
                     talloc_strdup(msg->elements, pAttrName)) == NULL) {
                        
                        return -1;
                }
                
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
                            el->num_values)) == NULL) {
                return -1;
        }
        
        /* Save the new attribute value length */
        el->values[el->num_values].length = strlen(pAttrValue) + 1;
        
        /* Copy the new attribute value */
        if (talloc_memdup(el->values[el->num_values].data,
                          pAttrValue,
                          el->values[el->num_values].length) == NULL) {
                return -1;
        }
        
        /* We now have one additional value of this type */
        el->num_values++;
        
	return 0;
}

static char *
parsetree_to_sql(struct ldb_module *module,
                 char * hTalloc,
                 const struct ldb_parse_tree *t)
{
	int                     i;
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
                                      "(\n"
                                      "%s\n"
                                      ")\n",
                                      child);
                talloc_free(child);
                return ret;
                
        case LDB_OP_OR:
                child =
                        parsetree_to_sql(
                                module,
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
                                      "(\n"
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
                                      "(\n"
                                      "  SELECT eid\n"
                                      "    FROM ldb_entry\n"
                                      "    WHERE eid NOT IN %s\n"
                                      ")\n",
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
         * match the criteria.  We accomplish this by searching the
         * appropriate table, ldb_attr_<attributeName>, for the eid
         * corresponding to all matching values.
         */
        if (t->u.simple.value.length == 1 &&
            (*(const char *) t->u.simple.value.data) == '*') {
		/*
                 * Special case for "attr_name=*".  In this case, we want the
                 * eid corresponding to all values in the specified attribute
                 * table.
                 */
                if ((p = sqlite3_mprintf("(\n"
                                         "  SELECT eid\n"
                                         "    FROM ldb_attr_%q\n"
                                         ")\n",
                                         pAttrName)) == NULL) {
                        return NULL;
                }
                
                if (lsqlite3_debug) {
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
                             "(\n"
                             "  SELECT eid\n"
                             "    FROM ldb_attr_OBJECTCLASS\n"
                             "    WHERE attr_name IN\n"
                             "      (SELECT class_name\n"
                             "         FROM ldb_objectclasses\n"
                             "         WHERE tree_key GLOB\n"
                             "           (SELECT tree_key\n"
                             "              FROM ldb_objectclasses\n"
                             "              WHERE class_name = %Q) || '*')\n"
                             ")\n",
                             t->u.simple.value.data)) == NULL) {
                        return NULL;
                }
                
                if (lsqlite3_debug) {
                        printf("%s\n", p);
                }

                ret = talloc_strdup(hTalloc, p);
                sqlite3_free(p);
                
	} else {
                /* A normal query. */
                if ((p = sqlite3_mprintf("(\n"
                                         "  SELECT eid\n"
                                         "    FROM ldb_attr_%q\n"
                                         "    WHERE attr_value = %Q\n"
                                         ")\n",
                                         pAttrName,
                                         t->u.simple.value.data)) == NULL) {
                        return NULL;
                }
                
                if (lsqlite3_debug) {
                        printf("%s\n", p);
                }

                ret = talloc_strdup(hTalloc, p);
                sqlite3_free(p);
	}

	return ret;
}


static int
parsetree_to_attrlist(struct lsqlite3_private * lsqlite3,
                      const struct ldb_parse_tree * t)
{
	int                         i;
        
	switch(t->operation) {
        case LDB_OP_SIMPLE:
                break;
                
        case LDB_OP_EXTENDED:
#warning  "work out how to handle bitops"
                return -1;

        case LDB_OP_AND:
                if (parsetree_to_attrlist(
                            lsqlite3,
                            t->u.list.elements[0]) != 0) {
                        return -1;
                }
                
                for (i = 1; i < t->u.list.num_elements; i++) {
                        if (parsetree_to_attrlist(
                                    lsqlite3,
                                    t->u.list.elements[i]) != 0) {
                                return -1;
                        }
                }
                
                return 0;
                
        case LDB_OP_OR:
                if (parsetree_to_attrlist(
                            lsqlite3,
                            t->u.list.elements[0]) != 0) {
                        return -1;
                }
                
                for (i = 1; i < t->u.list.num_elements; i++) {
                        if (parsetree_to_attrlist(
                                    lsqlite3,
                                    t->u.list.elements[i]) != 0) {
                                return -1;
                        }
                }
                
                return 0;
                
        case LDB_OP_NOT:
                if (parsetree_to_attrlist(lsqlite3,
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


#ifdef NEED_TABLE_LIST
/*
 * Use the already-generated FILTER_ATTR_TABLE to create a list of attribute
 * table names that will be used in search queries.
 */
static char *
build_attr_table_list(void * hTalloc,
                      struct lsqlite3_private * lsqlite3)
{
        int             ret;
        int             bLoop;
        char *          p;
        char *          pAttrName;
        char *          pTableList;
        sqlite3_stmt *  pStmt;
        
        /*
         * Prepare and execute the SQL statement.  Loop allows retrying on
         * certain errors, e.g. SQLITE_SCHEMA occurs if the schema changes,
         * requiring retrying the operation.
         */
        for (bLoop = TRUE; bLoop; ) {
                /* Initialize a string to which we'll append each table name */
                if ((pTableList = talloc_strdup(hTalloc, "")) == NULL) {
                        return NULL;
                }
                
                /* Compile the SQL statement into sqlite virtual machine */
                if ((ret = sqlite3_prepare(lsqlite3->sqlite,
                                           "SELECT attr_name "
                                           "  FROM " FILTER_ATTR_TABLE ";",
                                           -1,
                                           &pStmt,
                                           NULL)) == SQLITE_SCHEMA) {
                        continue;
                } else if (ret != SQLITE_OK) {
                        ret = -1;
                        break;
                }
                
                /* Loop through the returned rows */
                for (ret = SQLITE_ROW; ret == SQLITE_ROW; ) {
                        
                        /* Get the next row */
                        if ((ret = sqlite3_step(pStmt)) == SQLITE_ROW) {
                                
                                /*
                                 * Get value from this row and append to table
                                 * list
                                 */
                                p = discard_const_p(char,
                                                    sqlite3_column_text(pStmt,
                                                                        0));
                                
                                pAttrName =
                                        ldb_casefold(
                                                hTalloc,
                                                sqlite3_column_text(pStmt, 0));

                                /* Append it to the table list */
                                if ((p = talloc_asprintf(
                                             hTalloc,
                                             "%sldb_attr_%s",
                                             *pTableList == '\0' ? "" : ",",
                                             pAttrName)) == NULL) {
                                        
                                        talloc_free(pTableList);
                                        return NULL;
                                }
                                
                                /* We have a new table list */
                                talloc_free(pTableList);
                                pTableList = p;
                        }
                }
                
                if (ret == SQLITE_SCHEMA) {
                        talloc_free(pTableList);
                        continue;
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

        if (ret != 0) {
                talloc_free(pTableList);
                pTableList = NULL;
        }

        return pTableList;
}
#endif


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
                
                if (flags == LDB_FLAG_MOD_ADD) {
                        /* Create the attribute table if it doesn't exist */
                        if (new_attr(module, pAttrName) != 0) {
                                return -1;
                        }
                }
                
                /* For each value of the specified attribute name... */
		for (j = 0; j < el->num_values; j++) {
                        
                        /* ... bind the attribute value, if necessary */
                        switch (flags) {
                        case LDB_FLAG_MOD_ADD:
                                QUERY_NOROWS(lsqlite3,
                                             FALSE,
                                             "INSERT INTO ldb_attr_%q\n"
                                             "    (eid, attr_value)\n"
                                             "  VALUES\n"
                                             "    (%lld, %Q);",
                                             pAttrName,
                                             eid, el->values[j].data);
                                QUERY_NOROWS(lsqlite3,
                                             FALSE,
                                             "INSERT INTO ldb_attribute_values"
                                             "    (eid, attr_name, attr_value)"
                                             "  VALUES "
                                             "    (%lld, %Q, %Q);",
                                             eid,
                                             el->name,
                                             el->values[j].data);
                                
                                break;
                                
                        case LDB_FLAG_MOD_REPLACE:
                                QUERY_NOROWS(lsqlite3,
                                             FALSE,
                                             "UPDATE ldb_attr_%q\n"
                                             "  SET attr_value = %Q\n"
                                             "  WHERE eid = %lld;",
                                             pAttrName,
                                             el->values[j].data,
                                             eid);
                                QUERY_NOROWS(lsqlite3,
                                             FALSE,
                                             "UPDATE ldb_attribute_values "
                                             "  SET attr_value = %Q "
                                             "  WHERE eid = %lld "
                                             "    AND attr_name = %Q;",
                                             el->values[j].data,
                                             eid,
                                             el->name);
                                break;
                                
                        case LDB_FLAG_MOD_DELETE:
                                /* No additional parameters to this query */
                                QUERY_NOROWS(lsqlite3,
                                             FALSE,
                                             "DELETE FROM ldb_attr_%q\n"
                                             "  WHERE eid = %lld\n"
                                             "    AND attr_value = %Q;",
                                             pAttrName,
                                             eid,
                                             el->values[j].data);
                                QUERY_NOROWS(lsqlite3,
                                             FALSE,
                                             "DELETE FROM ldb_attribute_values"
                                             "  WHERE eid = %lld "
                                             "    AND attr_name = %Q "
                                             "    AND attr_value = %Q;",
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
        struct ldb_dn *             pExplodedDN;
        struct ldb_dn_component *   pComponent;
	struct ldb_context *        ldb = module->ldb;
	struct lsqlite3_private *   lsqlite3 = module->private_data;
        
        /* Explode and normalize the DN */
        if ((pExplodedDN =
             ldb_explode_dn(ldb,
                            pDN,
                            ldb,
                            case_fold_attr_required)) == NULL) {
                return -1;
        }
        
        /* Allocate a string to hold the partial DN of each component */
        if ((pPartialDN = talloc_strdup(ldb, "")) == NULL) {
                return -1;
        }
        
        /* For each component of the DN (starting with the last one)... */
        eid = 0;
        for (nComponent = pExplodedDN->comp_num - 1, bFirst = TRUE;
             nComponent >= 0;
             nComponent--, bFirst = FALSE) {
                
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
                
                /* No need for the old partial DN any more */
                talloc_free(pPartialDN);
                
                /* Save the new partial DN */
                pPartialDN = p;
                
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
                
                /* Get the EID of the just inserted row */
                eid = sqlite3_last_insert_rowid(lsqlite3->sqlite);

                /*
                 * Popoulate the descendant table
                 */

                /* This table has an entry for itself as well as descendants */
                QUERY_NOROWS(lsqlite3,
                             FALSE,
                             "INSERT INTO ldb_descendants "
                             "    (aeid, deid) "
                             "  VALUES "
                             "    (%lld, %lld);",
                             eid, eid);
                
                /* Now insert rows for all of our ancestors */
                QUERY_NOROWS(lsqlite3,
                             FALSE,
                             "INSERT INTO ldb_descendants "
                             "    (aeid, deid) "
                             "  SELECT aeid, %lld "
                             "    FROM ldb_descendants "
                             "    WHERE aeid = %lld;",
                             eid, peid);

                /* If this is the final component, also add DN attribute */
                if (nComponent == 0) {
                        QUERY_NOROWS(lsqlite3,
                                     FALSE,
                                     "INSERT %s INTO ldb_attr_DN\n"
                                     "    (eid, attr_value) "
                                     "  VALUES "
                                     "    (%lld, %Q);",
                                     nComponent == 0 ? "" : "OR IGNORE",
                                     eid, pPartialDN);
                }
        }
        
        /* Give 'em what they came for! */
        *pEID = eid;
        
        return 0;
}


static int
new_attr(struct ldb_module * module,
         char * pAttrName)
{
        long long                   bExists;
	struct lsqlite3_private *   lsqlite3 = module->private_data;
        
        /*
         * NOTE:
         *   pAttrName is assumed to already be case-folded here!
         */
        
        /* See if the table already exists */
        QUERY_INT(lsqlite3,
                  bExists,
                  FALSE,
                  "SELECT COUNT(*) <> 0\n"
                  "  FROM sqlite_master\n"
                  "  WHERE type = 'table'\n"
                  "    AND tbl_name = 'ldb_attr_%q';",
                  pAttrName);
        
        /* Did it exist? */
        if (! bExists) {
                /* Nope.  Create the table */
                QUERY_NOROWS(lsqlite3,
                             FALSE,
                             "CREATE TABLE ldb_attr_%q\n"
                             "(\n"
                             "  eid        INTEGER REFERENCES ldb_entry,\n"
                             "  attr_value TEXT\n"
                             ");",
                             pAttrName);
        }
        
        return 0;
}


