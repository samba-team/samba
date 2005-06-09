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
#include "ldb/include/ldb_parse.h"
#include "ldb/include/ldb_explode_dn.h"
#include "ldb/ldb_sqlite3/ldb_sqlite3.h"

/*
 * Macros used throughout
 */

#ifndef FALSE
# define FALSE  (0)
# define TRUE   (! FALSE)
#endif

#define QUERY_NOROWS(lsqlite3, bRollbackOnError, sql...)        \
    do {                                                        \
            if (query_norows(lsqlite3, sql) != 0) {             \
                if (bRollbackOnError) {                         \
                        query_norows(lsqlite3,                  \
                                       "ROLLBACK;");            \
                }                                               \
                return -1;                                      \
        }                                                       \
    } while (0)

#define QUERY_INT(lsqlite3, result_var, bRollbackOnError, sql...)       \
    do {                                                                \
            if (query_int(lsqlite3, &result_var, sql) != 0) {           \
                    if (bRollbackOnError) {                             \
                            query_norows(lsqlite3,                      \
                                                  "ROLLBACK;");         \
                    }                                                   \
                    return -1;                                          \
            }                                                           \
    } while (0)


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
lsqlite3_search(struct ldb_module * module,
                const char * pBaseDN,
                enum ldb_scope scope,
                const char * pExpression,
                const char * const attrs[],
                struct ldb_message *** res);

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

static char *
parsetree_to_sql(struct ldb_module *module,
                          char * hTalloc,
                 const struct ldb_parse_tree *t);

static char *
parsetree_to_tablelist(struct ldb_module *module,
                       char * hTalloc,
                       const struct ldb_parse_tree *t);

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
	"sqlite",
	lsqlite3_search,
	lsqlite3_add,
	lsqlite3_modify,
	lsqlite3_delete,
	lsqlite3_rename,
	lsqlite3_lock,
	lsqlite3_unlock,
	lsqlite3_errstring
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
		errno = ENOMEM;
		goto failed;
	}

	lsqlite3 = talloc(ldb, struct lsqlite3_private);
	if (!lsqlite3) {
		errno = ENOMEM;
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
		errno = ENOMEM;
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
                const char * olddn,
                const char * newdn)
{
	/* ignore ltdb specials */
	if (olddn[0] == '@' ||newdn[0] == '@') {
		return 0;
	}

#warning "lsqlite3_rename() is not yet supported"
        return -1;
}

/* delete a record */
static int
lsqlite3_delete(struct ldb_module *module,
                const char *dn)
{
	/* ignore ltdb specials */
	if (dn[0] == '@') {
		return 0;
	}
	
        return -1;
}

/* search for matching records */
static int
lsqlite3_search(struct ldb_module * module,
                const char * pBaseDN,
                enum ldb_scope scope,
                const char * pExpression,
                const char * const attrs[],
                struct ldb_message *** res)
{
        long long                   eid = 0;
        char *                      sql;
	char *                      sql_constraints;
        char *                      table_list;
        char *                      hTalloc;
	struct ldb_parse_tree *     pTree;
	struct lsqlite3_private *   lsqlite3 = module->private_data;
	
	if (pBaseDN == NULL) {
		pBaseDN = "";
	}

        /* Begin a transaction */
        QUERY_NOROWS(lsqlite3, FALSE, "BEGIN IMMEDIATE;");

        /*
         * Obtain the eid of the base DN
         */
        QUERY_INT(lsqlite3,
                  eid,
                  TRUE,
                  "SELECT eid "
                  "  FROM ldb_attr_dn "
                  "  WHERE attr_value = %Q;",
                  pBaseDN);

        /* Parse the filter expression into a tree we can work with */
	if ((pTree = ldb_parse_tree(module->ldb, pExpression)) == NULL) {
		return -1;
	}
	
        /* Allocate a temporary talloc context */
	hTalloc = talloc_new(module->ldb);

        /* Move the parse tree to our temporary context */
	talloc_steal(hTalloc, pTree);
	
        /* Convert filter into a series of SQL statements (constraints) */
	sql_constraints = parsetree_to_sql(module, hTalloc, pTree);
	
        /* Get the list of attribute names to use as our extra table list */
        table_list = parsetree_to_tablelist(module, hTalloc, pTree);

        switch(scope) {
        case LDB_SCOPE_DEFAULT:
        case LDB_SCOPE_SUBTREE:
                sql = sqlite3_mprintf(
                        "SELECT entry.entry_data\n"
                        "  FROM ldb_entry AS entry\n"
                        "  WHERE entry.eid IN\n"
                        "    (SELECT DISTINCT ldb_entry.eid\n"
                        "       FROM ldb_entry,\n"
                        "            ldb_descendants,\n"
                        "            %q\n"
                        "       WHERE ldb_descendants.aeid = %lld\n"
                        "         AND ldb_entry.eid = ldb_descendants.deid\n"
                        "         AND ldap_entry.eid IN\n"
                        "%s"
                        ");",
                        table_list,
                        eid,
                        sql_constraints);
                break;

        case LDB_SCOPE_BASE:
                sql = sqlite3_mprintf(
                        "SELECT entry.entry_data\n"
                        "  FROM ldb_entry AS entry\n"
                        "  WHERE entry.eid IN\n"
                        "    (SELECT DISTINCT ldb_entry.eid\n"
                        "       FROM %q\n"
                        "       WHERE ldb_entry.eid = %lld\n"
                        "         AND ldb_entry.eid IN\n"
                        "%s"
                        ");",
                        table_list,
                        eid,
                        sql_constraints);
                break;

        case LDB_SCOPE_ONELEVEL:
                sql = sqlite3_mprintf(
                        "SELECT entry.entry_data\n"
                        "  FROM ldb_entry AS entry\n"
                        "  WHERE entry.eid IN\n"
                        "    (SELECT DISTINCT ldb_entry.eid\n"
                        "       FROM ldb_entry AS pchild, "
                        "            %q\n"
                        "       WHERE ldb_entry.eid = pchild.eid "
                        "         AND pchild.peid = %lld "
                        "         AND ldb_entry.eid IN\n"
                        "%s"
                        ");",
                        table_list,
                        eid,
                        sql_constraints);
                break;
        }

#warning "retrieve and return the result set of the search here"

        /* End the transaction */
        QUERY_NOROWS(lsqlite3, FALSE, "END TRANSACTION;");

	return 0;
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
lsqlite3_modify(struct ldb_module *module,
                const struct ldb_message *msg)
{
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	/* ignore ltdb specials */
	if (msg->dn[0] == '@') {
		return 0;
	}

        /* Begin a transaction */
        QUERY_NOROWS(lsqlite3, FALSE, "BEGIN EXCLUSIVE;");

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
                "-- ------------------------------------------------------"

                "PRAGMA auto_vacuum=1;"

                "-- ------------------------------------------------------"

                "BEGIN EXCLUSIVE;"

                "-- ------------------------------------------------------"

                "CREATE TABLE ldb_info AS"
                "  SELECT 'LDB' AS database_type,"
                "         '1.0' AS version;"

                "-- ------------------------------------------------------"
                "-- Schema"

                "/*"
                " * The entry table holds the information about an entry. "
                " * This table is used to obtain the EID of the entry and to "
                " * support scope=one and scope=base.  The parent and child"
                " * table is included in the entry table since all the other"
                " * attributes are dependent on EID."
                " */"
                "CREATE TABLE ldb_entry"
                "("
                "  -- Unique identifier of this LDB entry"
                "  eid                   INTEGER PRIMARY KEY,"

                "  -- Unique identifier of the parent LDB entry"
                "  peid                  INTEGER REFERENCES ldb_entry,"

                "  -- Distinguished name of this entry"
                "  dn                    TEXT,"

                "  -- Time when the entry was created"
                "  create_timestamp      INTEGER,"

                "  -- Time when the entry was last modified"
                "  modify_timestamp      INTEGER,"

                "  -- Attributes of this entry, in the form"
                "  --   attr\1value\0[attr\1value\0]*\0"
                "  entry_data            TEXT"
                ");"


                "/*"
                " * The purpose of the descendant table is to support the"
                " * subtree search feature.  For each LDB entry with a unique"
                " * ID (AEID), this table contains the unique identifiers"
                " * (DEID) of the descendant entries."
                " *"
                " * For evern entry in the directory, a row exists in this"
                " * table for each of its ancestors including itself.  The "
                " * size of the table depends on the depth of each entry.  In "
                " * the worst case, if all the entries were at the same "
                " * depth, the number of rows in the table is O(nm) where "
                " * n is the number of nodes in the directory and m is the "
                " * depth of the tree. "
                " */"
                "CREATE TABLE ldb_descendants"
                "("
                "  -- The unique identifier of the ancestor LDB entry"
                "  aeid                  INTEGER REFERENCES ldb_entry,"

                "  -- The unique identifier of the descendant LDB entry"
                "  deid                  INTEGER REFERENCES ldb_entry"
                ");"


                "CREATE TABLE ldb_object_classes"
                "("
                "  -- Object classes are inserted into this table to track"
                "  -- their class hierarchy.  'top' is the top-level class"
                "  -- of which all other classes are subclasses."
                "  class_name            TEXT PRIMARY KEY,"

                "  -- tree_key tracks the position of the class in"
                "  -- the hierarchy"
                "  tree_key              TEXT UNIQUE"
                ");"

                "/*"
                " * There is one attribute table per searchable attribute."
                " */"
                "/*"
                "CREATE TABLE ldb_attr_ATTRIBUTE_NAME"
                "("
                "  -- The unique identifier of the LDB entry"
                "  eid                   INTEGER REFERENCES ldb_entry,"

                "  -- Normalized attribute value"
                "  attr_value            TEXT"
                ");"
                "*/"


                "-- ------------------------------------------------------"
                "-- Indexes"


                "-- ------------------------------------------------------"
                "-- Triggers"

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

                "-- ------------------------------------------------------"
                "-- Table initialization"

                "/* We need an implicit 'top' level object class */"
                "INSERT INTO ldb_attributes (attr_name,"
                "                            parent_tree_key)"
                "  SELECT 'top', '';"

                "-- ------------------------------------------------------"

                "COMMIT;"

                "-- ------------------------------------------------------"
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

        /* Begin a transaction */
        QUERY_NOROWS(lsqlite3, FALSE, "BEGIN EXCLUSIVE;");

        /* Determine if this is a new database.  No tables means it is. */
        QUERY_INT(lsqlite3,
                  queryInt,
                  TRUE,
                  "SELECT COUNT(*) "
                  "  FROM sqlite_master "
                  "  WHERE type = 'table';");

        if (queryInt == 0) {
                /*
                 * Create the database schema
                 */
                for (pTail = discard_const_p(char, schema); pTail != NULL; ) {

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
        const char *    pTail;
        sqlite3_stmt *  pStmt;
        va_list         args;
        
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
                                           pTail,
                                           -1,
                                           &pStmt,
                                           &pTail)) != SQLITE_OK) {
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
        const char *    pTail;
        sqlite3_stmt *  pStmt;
        va_list         args;
        
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
                                           pTail,
                                           -1,
                                           &pStmt,
                                           &pTail)) != SQLITE_OK) {
                        ret = -1;
                        break;
                }
                
                /* No rows expected, so just step through machine code once */
                if ((ret = sqlite3_step(pStmt)) == SQLITE_SCHEMA) {
                        (void) sqlite3_finalize(pStmt);
                        continue;
                } else if (ret != SQLITE_ROW) {
                        (void) sqlite3_finalize(pStmt);
                        ret = -1;
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

#warning "add_msg_attr() not yet implemented or used"
#if 0
static int
add_msg_attr(struct ldb_context *ldb,
                      struct ldb_message *msg, 
                      const char *attr,
                      struct berval **bval)
{
        int                          i;
	int                          count;
	struct ldb_message_element * el;

	count = ldap_count_values_len(bval);

	if (count <= 0) {
		return -1;
	}

	el = talloc_realloc(msg, msg->elements, struct ldb_message_element, 
			      msg->num_elements + 1);
	if (!el) {
		errno = ENOMEM;
		return -1;
	}

	msg->elements = el;

	el = &msg->elements[msg->num_elements];

	el->name = talloc_strdup(msg->elements, attr);
	if (!el->name) {
		errno = ENOMEM;
		return -1;
	}
	el->flags = 0;

	el->num_values = 0;
	el->values = talloc_array(msg->elements, struct ldb_val, count);
	if (!el->values) {
		errno = ENOMEM;
		return -1;
	}

	for (i=0;i<count;i++) {
		el->values[i].data = talloc_memdup(el->values, bval[i]->bv_val, bval[i]->bv_len);
		if (!el->values[i].data) {
			return -1;
		}
		el->values[i].length = bval[i]->bv_len;
		el->num_values++;
	}

	msg->num_elements++;

	return 0;
}
#endif

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
                        ret = talloc_asprintf("(\n"
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
                        ret = talloc_asprintf("(\n"
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
                             "    FROM ldb_attr_objectclass\n"
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

                ret = talloc_strdup(hTalloc, p);
                sqlite3_free(p);
	}
	return ret;
}


static char *
parsetree_to_tablelist(struct ldb_module *module,
                                char * hTalloc,
                                const struct ldb_parse_tree *t)
{
#warning "obtain talloc'ed array of attribute names for table list"
        return NULL;
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
                                             "INSERT INTO ldb_attr_%q "
                                             "    (eid, attr_value) "
                                             "  VALUES "
                                             "    (%lld, %Q);",
                                             pAttrName,
                                             eid, el->values[j].data);
                                QUERY_NOROWS(lsqlite3,
                                             FALSE,
                                             "UPDATE ldb_entry "
                                             "  SET entry_data = "
                                             "        add_attr(entry_data, "
                                             "                 %Q, %Q) "
                                             "  WHERE eid = %lld;",
                                             el->name, el->values[j].data,
                                             eid);
                                      
                                break;

                        case LDB_FLAG_MOD_REPLACE:
                                QUERY_NOROWS(lsqlite3,
                                             FALSE,
                                             "UPDATE ldb_attr_%q "
                                             "  SET attr_value = %Q "
                                             "  WHERE eid = %lld;",
                                             pAttrName,
                                             el->values[j].data,
                                             eid);
                                QUERY_NOROWS(lsqlite3,
                                             FALSE,
                                             "UPDATE ldb_entry "
                                             "  SET entry_data = "
                                             "        mod_attr(entry_data, "
                                             "                 %Q, %Q) "
                                             "  WHERE eid = %lld;",
                                             el->name, el->values[j].data,
                                             eid);
                                break;

                        case LDB_FLAG_MOD_DELETE:
                                /* No additional parameters to this query */
                                QUERY_NOROWS(lsqlite3,
                                             FALSE,
                                             "DELETE FROM ldb_attr_%q "
                                             "  WHERE eid = %lld "
                                             "    AND attr_value = %Q;",
                                             pAttrName,
                                             eid,
                                             el->values[j].data);
                                QUERY_NOROWS(lsqlite3,
                                             FALSE,
                                             "UPDATE ldb_entry "
                                             "  SET entry_data = "
                                             "        del_attr(entry_data, "
                                             "                 %Q, %Q) "
                                             "  WHERE eid = %lld;",
                                             el->name, el->values[j].data,
                                             eid);
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
        struct ldb_dn *             pExplodedDN;
	struct ldb_context *        ldb = module->ldb;
//	struct lsqlite3_private *   lsqlite3 = module->private_data;

        /* Explode and normalize the DN */
        if ((pExplodedDN =
             ldb_explode_dn(ldb,
                            pDN,
                            ldb,
                            case_fold_attr_required)) == NULL) {
                return -1;
        }

#warning "*** new_dn() not yet fully implemented ***"
        return -1;
}


static int
new_attr(struct ldb_module * module,
                  char * pAttrName)
{
	struct lsqlite3_private *   lsqlite3 = module->private_data;

        /* NOTE: pAttrName is assumed to already be case-folded here! */
        QUERY_NOROWS(lsqlite3,
                     FALSE,
                     "CREATE TABLE ldb_attr_%q "
                     "("
                     "  eid        INTEGER REFERENCES ldb_entry, "
                     "  attr_value TEXT"
                     ");",
                     pAttrName);

        return 0;
}

