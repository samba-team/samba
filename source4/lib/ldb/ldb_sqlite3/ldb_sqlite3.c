/* 
   ldb database library
   
   Copyright (C) Andrew Tridgell  2004
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
#include "system/filesys.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/ldb_sqlite3/ldb_sqlite3.h"

#ifndef False
# define False  (0)
# define True   (! False)
#endif

#define QUERY(lsqlite3, pppValues, pNumRows, bRollbackOnError, sql...)  \
    do                                                                  \
    {                                                                   \
            if (lsqlite3_query(lsqlite3,                                \
                               pppValues,                               \
                               pNumRows,                                \
                               sql) != 0) {                             \
                if (bRollbackOnError) {                                 \
                        lsqlite3_query(lsqlite3,                        \
                                       NULL,                            \
                                       NULL,                            \
                                       "ROLLBACK;");                    \
                }                                                       \
                return -1;                                              \
        }                                                               \
    } while (0)


static int
lsqlite3_query(const struct lsqlite3_private *lsqlite3,
               char ***pppValues,
               int *pNumRows,
               const char *pSql,
               ...)
{
//        int             i;
//        int             retval;
        int             numRows;
//        int             numColumns;
        int             bFreeTable = False;
//        char            errorBuf[4096];
        char *          p;
//        char *          pError = NULL;
        char **         ppValues;
        va_list         args;
        
        /* Begin access to variable argument list */
        va_start(args, pSql);

        /*
         * If they didn't give us a place to put returned values, use our own
         */
        if (pppValues == NULL)
        {
                pppValues = &ppValues;
                bFreeTable = True;
        }
        
        /* Similarly for number of rows in result set */
        if (pNumRows == NULL)
        {
                pNumRows = &numRows;
        }

        /* Format the query */
        if ((p = sqlite3_vmprintf(pSql, args)) == NULL) {
                return -1;
        }


#warning "*** FINISH QUERY FUNCTION.  Catch timeouts, schema changed, etc. ***"


        /* All done with variable argument list */
        va_end(args);

        /* Success! */
        return 0;
}

static int
lsqlite3_create_attr_table(struct ldb_module *module,
                           char * pAttr)
{
#warning "*** lsqlite3_create_attr_table() not yet written ***"
        return -1;
}


#if 0
/*
 * we don't need this right now, but will once we add some backend options
 *
 * find an option in an option list (a null terminated list of strings)
 *
 * this assumes the list is short. If it ever gets long then we really should
 * do this in some smarter way
 */
static const char *
lsqlite3_option_find(const struct lsqlite3_private *lsqlite3,
                     const char *name)
{
	int                 i;
	size_t              len = strlen(name);

	if (!lsqlite3->options) return NULL;

	for (i=0;lsqlite3->options[i];i++) {		
		if (strncmp(lsqlite3->options[i], name, len) == 0 &&
		    lsqlite3->options[i][len] == '=') {
			return &lsqlite3->options[i][len+1];
		}
	}

	return NULL;
}
#endif

/*
  callback function used in call to ldb_dn_fold() for determining whether an
  attribute type requires case folding.
*/
static int lsqlite3_case_fold_attr_required(struct ldb_module *module,
                                           char *attr)
{
#warning "currently, all attributes require case folding"
        return True;
}


/*
 * rename a record
 */
static int
lsqlite3_rename(struct ldb_module *module,
                const char *olddn,
                const char *newdn)
{
	/* ignore ltdb specials */
	if (olddn[0] == '@' ||newdn[0] == '@') {
		return 0;
	}

#warning "lsqlite3_rename() is not yet supported"
        return -1;
}

/*
 * delete a record
 */
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

#if 0 /* not currently used */
/*
 * free a search result
 */
static int
lsqlite3_search_free(struct ldb_module *module,
                     struct ldb_message **res)
{
	talloc_free(res);
	return 0;
}
#endif


/*
 * add a single set of ldap message values to a ldb_message
 */

/* get things to compile before we actually implement this function */
struct berval
{
        int x;
};

#warning "lsqlite3_add_msg_attr() not yet implemented or used"
#if 0
static int
lsqlite3_add_msg_attr(struct ldb_context *ldb,
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

/*
 * search for matching records
 */
static int
lsqlite3_search(struct ldb_module *module,
                const char *base,
                enum ldb_scope scope,
                const char *expression,
                const char * const attrs[],
                struct ldb_message ***res)
{
#warning "lsqlite3_search() not yet implemented"
#if 0
	int                       count;
        int                       msg_count;
	struct ldb_context *      ldb = module->ldb;
	struct lsqlite3_private * lsqlite3 = module->private_data;

	if (base == NULL) {
		base = "";
	}

	lsqlite3->last_rc = ldap_search_s(lsqlite3->ldap, base, (int)scope, 
				      expression, 
				      discard_const_p(char *, attrs), 
				      0, &ldapres);
	if (lsqlite3->last_rc != LDAP_SUCCESS) {
		return -1;
	}

	count = ldap_count_entries(lsqlite3->ldap, ldapres);
	if (count == -1 || count == 0) {
		ldap_msgfree(ldapres);
		return count;
	}

	(*res) = talloc_array(lsqlite3, struct ldb_message *, count+1);
	if (! *res) {
		ldap_msgfree(ldapres);
		errno = ENOMEM;
		return -1;
	}

	(*res)[0] = NULL;

	msg_count = 0;

	/* loop over all messages */
	for (msg=ldap_first_entry(lsqlite3->ldap, ldapres); 
	     msg; 
	     msg=ldap_next_entry(lsqlite3->ldap, msg)) {
		BerElement *berptr = NULL;
		char *attr, *dn;

		if (msg_count == count) {
			/* hmm, got too many? */
			ldb_debug(ldb, LDB_DEBUG_FATAL, "Fatal: ldap message count inconsistent\n");
			break;
		}

		(*res)[msg_count] = talloc(*res, struct ldb_message);
		if (!(*res)[msg_count]) {
			goto failed;
		}
		(*res)[msg_count+1] = NULL;

		dn = ldap_get_dn(lsqlite3->ldap, msg);
		if (!dn) {
			goto failed;
		}

		(*res)[msg_count]->dn = talloc_strdup((*res)[msg_count], dn);
		ldap_memfree(dn);
		if (!(*res)[msg_count]->dn) {
			goto failed;
		}


		(*res)[msg_count]->num_elements = 0;
		(*res)[msg_count]->elements = NULL;
		(*res)[msg_count]->private_data = NULL;

		/* loop over all attributes */
		for (attr=ldap_first_attribute(lsqlite3->ldap, msg, &berptr);
		     attr;
		     attr=ldap_next_attribute(lsqlite3->ldap, msg, berptr)) {
			struct berval **bval;
			bval = ldap_get_values_len(lsqlite3->ldap, msg, attr);

			if (bval) {
				lsqlite3_add_msg_attr(ldb, (*res)[msg_count], attr, bval);
				ldap_value_free_len(bval);
			}					  
			
			ldap_memfree(attr);
		}
		if (berptr) ber_free(berptr, 0);

		msg_count++;
	}

	ldap_msgfree(ldapres);

	return msg_count;

failed:
	if (*res) lsqlite3_search_free(module, *res);
	return -1;
#else
        return -1;
#endif
}


/*
 * Issue a series of SQL statements to implement the ADD/MODIFY/DELETE
 * requests in the ldb_message
 */
static int
lsqlite3_msg_to_sql(struct ldb_module *module,
                    const struct ldb_message *msg,
                    long long eid,
                    int use_flags)
{
        int                         flags;
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

                if (flags == LDB_FLAG_MOD_ADD) {
                        /* Create the attribute table if it doesn't exist */
                        if (lsqlite3_create_attr_table(module,
                                                       el->name) != 0) {
                                return -1;
                        }
                }

                /* For each value of the specified attribute name... */
		for (j = 0; j < el->num_values; j++) {

                        /* ... bind the attribute value, if necessary */
                        switch (flags) {
                        case LDB_FLAG_MOD_ADD:
                                QUERY(lsqlite3,
                                      NULL, NULL,
                                      False,
                                      "INSERT INTO ldb_attr_%q "
                                      "    (eid, attr_value) "
                                      "  VALUES "
                                      "    (%lld, %Q);",
                                      eid, el->values[j].data);
                                QUERY(lsqlite3,
                                      NULL, NULL,
                                      False,
                                      "UPDATE ldb_entry "
                                      "  SET entry_data = "
                                      "        add_attr(entry_data, %Q, %Q) "
                                      "  WHERE eid = %lld;",
                                      el->name, el->values[j].data, eid);
                                      
                                break;

                        case LDB_FLAG_MOD_REPLACE:
                                QUERY(lsqlite3,
                                      NULL, NULL,
                                      False,
                                      "UPDATE ldb_attr_%q "
                                      "  SET attr_value = %Q "
                                      "  WHERE eid = %lld;",
                                      el->values[j].data, eid);
                                QUERY(lsqlite3,
                                      NULL, NULL,
                                      False,
                                      "UPDATE ldb_entry "
                                      "  SET entry_data = "
                                      "        mod_attr(entry_data, %Q, %Q) "
                                      "  WHERE eid = %lld;",
                                      el->name, el->values[j].data, eid);
                                break;

                        case LDB_FLAG_MOD_DELETE:
                                /* No additional parameters to this query */
                                QUERY(lsqlite3,
                                      NULL, NULL,
                                      False,
                                      "DELETE FROM ldb_attr_%q "
                                      "  WHERE eid = %lld "
                                      "    AND attr_value = %Q;",
                                      eid, el->values[j].data);
                                QUERY(lsqlite3,
                                      NULL, NULL,
                                      False,
                                      "UPDATE ldb_entry "
                                      "  SET entry_data = "
                                      "        del_attr(entry_data, %Q, %Q) "
                                      "  WHERE eid = %lld;",
                                      el->name, el->values[j].data, eid);
                                break;
                        }
		}
	}

	return 0;
}


static int
lsqlite3_insert_dn(struct lsqlite3_private * lsqlite3,
                   char * pDN,
                   long long * pEID)
{
#warning "*** lsqlite3_insert_dn() not yet implemented ***"
        return -1;
}


/*
 * add a record
 */
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
        QUERY(lsqlite3, NULL, NULL, False, "BEGIN EXCLUSIVE;");

        /*
         * Build any portions of the directory tree that don't exist.  If the
         * final component already exists, it's an error.
         */
        if (lsqlite3_insert_dn(lsqlite3,
                               ldb_dn_fold(module,
                                           msg->dn,
                                           lsqlite3_case_fold_attr_required),
                                         &eid) != 0) {
                QUERY(lsqlite3, NULL, NULL, False, "ROLLBACK;");
                return -1;
        }

        /* Add attributes to this new entry */
	if (lsqlite3_msg_to_sql(module, msg, eid, False) != 0) {
                QUERY(lsqlite3, NULL, NULL, False, "ROLLBACK;");
                return -1;
        }

        /* Everything worked.  Commit it! */
        QUERY(lsqlite3, NULL, NULL, True, "COMMIT;");
        return 0;
}


/*
 * modify a record
 */
static int
lsqlite3_modify(struct ldb_module *module,
                const struct ldb_message *msg)
{
        int                         numRows;
        long long                   eid;
        char **                     ppValues;
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	/* ignore ltdb specials */
	if (msg->dn[0] == '@') {
		return 0;
	}

        /* Begin a transaction */
        QUERY(lsqlite3, NULL, NULL, False, "BEGIN EXCLUSIVE;");

        /* Get the id of this DN. */
        QUERY(lsqlite3,
              &ppValues,
              &numRows,
              True, 
              "SELECT eid "
              "  FROM ldb_entry "
              "  WHERE dn = %Q;",
              ldb_dn_fold(module,
                          msg->dn,
                          lsqlite3_case_fold_attr_required));

        /* Did it exist? */
        if (numRows != 1) {
                /* Nope.  See ya! */
                sqlite3_free_table(ppValues);
                return -1;
        }

        /* Retrieve the eid */
        eid = strtoll(ppValues[1], NULL, 10);

        /* Modify attributes as specified */
	if (lsqlite3_msg_to_sql(module, msg, eid, False) != 0) {
                QUERY(lsqlite3, NULL, NULL, False, "ROLLBACK;");
                return -1;
        }

        /* Everything worked.  Commit it! */
        QUERY(lsqlite3, NULL, NULL, True, "COMMIT;");
        return 0 ;
}

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

/*
 * return extended error information
 */
static const char *
lsqlite3_errstring(struct ldb_module *module)
{
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	return sqlite3_errmsg(lsqlite3->sqlite);
}


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


static int
lsqlite3_destructor(void *p)
{
	struct lsqlite3_private *   lsqlite3 = p;

        (void) sqlite3_close(lsqlite3->sqlite);
	return 0;
}

static int
lsqlite3_initialize(struct lsqlite3_private *lsqlite3,
                    const char *url)
{
        int             ret;
        int             bNewDatabase = False;
        char *          p;
        const char *    pTail;
        struct stat     statbuf;
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
        if ((p = strchr(url, ':')) == NULL) {
                return SQLITE_MISUSE;
        } else {
                ++p;
        }
                
        /*
         * See if we'll be creating a new database, or opening an existing one
         */
        if ((stat(p, &statbuf) < 0 && errno == ENOENT) ||
            statbuf.st_size == 0) {

                bNewDatabase = True;
        }

        /* Try to open the (possibly empty/non-existent) database */
        if ((ret = sqlite3_open(p, &lsqlite3->sqlite)) != SQLITE_OK) {
                return ret;
        }

        if (bNewDatabase) {
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

                                (void) sqlite3_close(lsqlite3->sqlite);
                                return ret;
                        }
                }
        } else {
                /*
                 * Ensure that the database we opened is one of ours
                 */
                if ((ret = sqlite3_prepare(
                             lsqlite3->sqlite,
                             "SELECT COUNT(*) "
                             "  FROM sqlite_master "
                             "  WHERE type = 'table' "
                             "    AND name IN "
                             "      ("
                             "        'ldb_entry', "
                             "        'ldb_descendants', "
                             "        'ldb_object_classes' "
                             "      );",
                             -1,
                             &stmt,
                             &pTail)) != SQLITE_OK ||
                    (ret = sqlite3_step(stmt)) != SQLITE_ROW ||
                    sqlite3_column_int(stmt, 0) != 3 ||
                    (ret = sqlite3_finalize(stmt)) != SQLITE_OK ||

                    (ret = sqlite3_prepare(
                             lsqlite3->sqlite,
                             "SELECT 1 "
                             "  FROM ldb_info "
                             "  WHERE database_type = 'LDB' "
                             "    AND version = '1.0';",
                             -1,
                             &stmt,
                             &pTail)) != SQLITE_OK ||
                    (ret = sqlite3_step(stmt)) != SQLITE_ROW ||
                    (ret = sqlite3_finalize(stmt)) != SQLITE_OK) {
                
                        /* It's not one that we created.  See ya! */
                        (void) sqlite3_close(lsqlite3->sqlite);
                        return SQLITE_MISUSE;
                }
        }

        return SQLITE_OK;
}

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

	ret = lsqlite3_initialize(lsqlite3, url);
	if (ret != SQLITE_OK) {
		goto failed;
	}

	talloc_set_destructor(lsqlite3, lsqlite3_destructor);

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

