/* 
   ldb database library
   
   Copyright (C) Andrew Tridgell  2004
   
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

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/ldb_sqlite3/ldb_sqlite3.h"

#undef SQL_EXEC                 /* just in case; not expected to be defined */
#define SQL_EXEC(lsqlite3, query, reset)                        \
        do {                                                    \
                lsqlite3->last_rc =                             \
                        sqlite3_step(lsqlite3->queries.query);  \
                if (lsqlite3->last_rc == SQLITE_BUSY || reset)  \
                        (void) sqlite3_reset(lsqlite3->queries.query);  \
        } while lsqlite3->last_rc == SQLITE_BUSY;



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
 * rename a record
 */
static int
lsqlite3_rename(struct ldb_module *module,
                const char *olddn,
                const char *newdn)
{
        int                         column;
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	/* ignore ltdb specials */
	if (olddn[0] == '@' ||newdn[0] == '@') {
		return 0;
	}

        /* Bind old distinguished names */
        column = sqlite3_bind_parameter_index(lsqlite3->queries.renameDN,
                                              ":oldDN");
        if (sqlite3_bind_text(lsqlite3->queries.renameDN, column,
                              olddn, strlen(olddn),
                              SQLITE_STATIC) != SQLITE_OK) {
                return -1;
        }

        /* Bind new distinguished names */
        column = sqlite3_bind_parameter_index(lsqlite3->queries.renameDN,
                                              ":newDN");
        if (sqlite3_bind_text(lsqlite3->queries.renameDN, column,
                              newdn, strlen(newdn),
                              SQLITE_STATIC) != SQLITE_OK) {
                return -1;
        }

        /* Execute the query.  This sets lsqlite3->last_rc */
        SQL_EXEC(lsqlite3, renameDN, TRUE);

	return lsqlite3->last_rc == 0 ? 0 : -1;
}

/*
 * delete a record
 */
static int
lsqlite3_delete(struct ldb_module *module,
                const char *dn)
{
	int                         ret = 0;
        int                         column;
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	/* ignore ltdb specials */
	if (dn[0] == '@') {
		return 0;
	}
	
        /* Bind distinguished names */
        column = sqlite3_bind_parameter_index(lsqlite3->queries.deleteDN,
                                              ":dn");
        if (sqlite3_bind_text(lsqlite3->queries.deleteDN, column,
                              dn, strlen(dn),
                              SQLITE_STATIC) != SQLITE_OK) {
                return -1;
        }

        /* Execute the query.  This sets lsqlite3->last_rc */
        SQL_EXEC(lsqlite3, deleteDN, TRUE);

	return lsqlite3->last_rc == 0 ? 0 : -1;
}

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


/*
 * add a single set of ldap message values to a ldb_message
 */
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

/*
 * search for matching records
 */
static int
lsqlite3_search(struct ldb_module *module,
                const char *base,
                enum ldb_scope scope,
                const char *expression,
                const char * const *attrs,
                struct ldb_message ***res)
{
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
}


/*
 * Issue a series of SQL statements to implement the ADD/MODIFY/DELETE
 * requests in the ldb_message
 */
static int
lsqlite3_msg_to_sql(struct ldb_context *ldb,
                    const struct ldb_message *msg,
                    long long dn_id,
                    int use_flags)
{
        int                         flags;
	unsigned int                i;
        unsigned int                j;
        sqlite3_stmt *              stmt = NULL;
	struct ldb_context *        ldb = module->ldb;
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	for (i = 0; i < msg->num_elements; i++) {
		const struct ldb_message_element *el = &msg->elements[i];

                if (! use_flags) {
                        flags = LDB_FLAG_MOD_ADD;
                } else {
                        flags = el->flags & LDB_FLAG_MOD_MASK;
                }

                /* Determine which query to use */
                switch (flags) {
                case LDB_FLAG_MOD_ADD:
                        stmt = lsqlite3->queries.addAttrValuePair;
                        break;
                        
                case LDB_FLAG_MOD_DELETE:
                        stmt = lsqlite3->queries.deleteAttrValuePairs;
                        break;

                case LDB_FLAG_MOD_REPLACE:
                        stmt = lsqlite3->queries.replaceAttrValuePairs;
                        break;
                }

                /*
                 * All queries use dn id and attribute name.  Bind them now.
                 */

                /* Bind distinguished name id */
                column =
                        sqlite3_bind_parameter_index(
                                stmt,
                                ":dn_id");
                if (sqlite3_bind_int64(stmt,
                                      column,
                                      dn_id) != SQLITE_OK) {

                        return -1;
                }

                /* Bind attribute name */
                column =
                        sqlite3_bind_parameter_index(
                                stmt,
                                ":attr_name");
                if (sqlite3_bind_text(lsqlite3->queries.deleteDN, column,
                                      el->name, strlen(el->name),
                                      SQLITE_STATIC) != SQLITE_OK) {

                        return -1;
                }


                /* For each value of the specified attribute name... */
		for (j = 0; j < el->num_values; j++) {

                        /* ... bind the attribute value, if necessary */
                        switch (flags) {
                        case LDB_FLAG_MOD_ADD:
                        case LDB_FLAG_MOD_REPLACE:
                                /* Bind attribute value */
                                column =
                                        sqlite3_bind_parameter_index(
                                                stmt,
                                                ":attr_value");
                                if (sqlite3_bind_text(
                                            stmt, column,
                                            el->values[j].data,
                                            el->values[j].length,
                                            SQLITE_STATIC) != SQLITE_OK) {

                                        return -1;
                                }

                                break;

                        case LDB_FLAG_MOD_DELETE:
                                /* No additional parameters to this query */
                                break;
                        }

                        /* Execute the query */
                        do {
                                lsqlite3->last_rc = sqlite3_step(stmt);
                                (void) sqlite3_reset(stmt);
                        } while lsqlite3->last_rc == SQLITE_BUSY;

                        /* Make sure we succeeded */
                        if (lsqlite3->last_rc != SQLITE_OK) {
                                return -1;
                        }
		}
	}

	return 0;
}


/*
 * add a record
 */
static int
lsqlite3_add(struct ldb_module *module,
             const struct ldb_message *msg)
{
	int                         ret;
	struct ldb_context *        ldb = module->ldb;
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	/* ignore ltdb specials */
	if (msg->dn[0] == '@') {
		return 0;
	}

        /* Begin a transaction */
        SQL_EXEC(lsqlite3, begin, TRUE);

        /* This is a new DN.  Bind new distinguished name */
        column = sqlite3_bind_parameter_index(lsqlite3->queries.newDN, ":dn");
        if (sqlite3_bind_text(lsqlite3->queries.newDN, column,
                              msg->dn, strlen(msg->dn),
                              SQLITE_STATIC) != SQLITE_OK) {
                return -1;
        }
        
        /* Add this new DN.  This sets lsqlite3->last_rc */
        SQL_EXEC(lsqlite3, newDN, TRUE);
        
        if (lsqlite3->last_rc != SQLITE_DONE) {
                return -1;
        }
        
        /* Get the id of the just-added DN */
        dn_id = sqlite3_last_insert_rowid(lsqlite3->sqlite3);
        
	ret = lsqlite3_msg_to_sql(ldb, msg, dn_id, FALSE);

        /* Did the attribute additions (if any) succeeded? */
        if (ret == 0)
        {
                /* Yup.  Commit the transaction */
                SQL_EXEC(lsqlite3, commit, TRUE);
        }
        else
        {
                /* Attribute addition failed.  Rollback the transaction */
                SQL_EXEC(lsqlite3, rollback, TRUE);
        }

        /* If everything succeeded, return success */
        return lsqlite3->last_rc == SQLITE_DONE && ret == 0 ? 0 : -1;
}


/*
 * modify a record
 */
static int
lsqlite3_modify(struct ldb_module *module,
                const struct ldb_message *msg)
{
	int                         ret = 0;
	struct ldb_context *        ldb = module->ldb;
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	/* ignore ltdb specials */
	if (msg->dn[0] == '@') {
		return 0;
	}

        /* Begin a transaction */
        SQL_EXEC(lsqlite3, begin, TRUE);

        /* Get the dn_id for the specified DN */
        column =
                sqlite3_bind_parameter_index(
                        lsqlite3->queries.getDNID,
                        ":dn");
        if (sqlite3_bind_text(lsqlite3->queries.getDNID,
                              column,
                              msg->dn, strlen(msg->dn),
                              SQLITE_STATIC) != SQLITE_OK) {
                return -1;
        }

        /* Get the id of this DN.  This sets lsqlite3->last_rc */
        SQL_EXEC(lsqlite3, getDNID, FALSE);
                        
        if (lsqlite3->last_rc != SQLITE_ROW) {
                return -1;
        }

        dn_id = sqlite3_column_int64(lsqlite3->queries.getDNID,
                                     column);
        (void) sqlite3_reset(lsqlite3->queries.getDNID);

	ret = lsqlite3_msg_to_sql(ldb, msg, dn_id, FALSE);

        /* Did the attribute additions (if any) succeeded? */
        if (ret == 0)
        {
                /* Yup.  Commit the transaction */
                SQL_EXEC(lsqlite3, commit, TRUE);
        }
        else
        {
                /* Attribute addition failed.  Rollback the transaction */
                SQL_EXEC(lsqlite3, rollback, TRUE);
        }

        /* If everything succeeded, return success */
        return lsqlite3->last_rc == SQLITE_DONE && ret == 0 ? 0 : -1;
}

static int
lsqlite3_lock(struct ldb_module *module,
              const char *lockname)
{
	int                         ret = 0;
	struct ldb_context *        ldb = module->ldb;
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	if (lockname == NULL) {
		return -1;
	}

        /* If we're already locked, just update lock count */
        if (++lsqlite3->lock_count > 1) {
                return -1;
        }
            
        /* Write-lock (but not read-lock) the database */
        SQL_EXEC(lsqlite3, begin, TRUE);

	return lsqlite3->last_rc == 0 ? 0 : -1;
}

static int
lsqlite3_unlock(struct ldb_module *module,
                const char *lockname)
{
	int                         ret = 0;
	struct ldb_context *        ldb = module->ldb;
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	if (lockname == NULL) {
		return -1;
	}

        /* If we're not already locked, there's nothing to do */
        if (lsqlite3->lock_count == 0) {
                return 0;
        }

        /* Decrement lock count */
        if (--lsqlite3->lock_count == 0) {
        
                /* Final unlock.  Unlock the database */
                SQL_EXEC(lsqlite3, commit, TRUE);
        }

	return lsqlite3->last_rc == 0 ? 0 : -1;
}

/*
 * return extended error information
 */
static const char *
lsqlite3_errstring(struct ldb_module *module)
{
	struct lsqlite3_private *   lsqlite3 = module->private_data;

	return sqlite3_errmsg(lsqlite3->sqlite3);
}


static const struct ldb_module_ops lsqlite3_ops = {
	"sqlite",
	lsqlite3_search,
	lsqlite3_search_free,
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

        (void) sqlite3_close(lsqlite3->sqlite3);
	return 0;
}

static int
lsqlite3_initialize(lsqlite3_private *lsqlite3,
                    const char *url)
{
        int             bNewDatabase = False;
        char *          p;
        char *          pTail;
        struct stat     statbuf;
        sqlite3_stmt *  stmt;
        const char *    schema =       
                "
                -- ------------------------------------------------------

                PRAGMA auto_vacuum=1;

                -- ------------------------------------------------------

                BEGIN EXCLUSIVE;

                -- ------------------------------------------------------

                CREATE TABLE ldb_info AS 
                  SELECT 'LDB' AS database_type, 
                         '1.0' AS version;

                CREATE TABLE ldb_distinguished_names 
                (
                  dn_id         INTEGER PRIMARY KEY AUTOINCREMENT, 
                  dn            TEXT UNIQUE
                );

                CREATE TABLE ldb_object_classes 
                (
                  class_name    TEXT PRIMARY KEY,
                  tree_key      TEXT,
                  max_child_num INTEGER
                );

                CREATE TABLE ldb_dn_object_classes 
                (
                  dn_id         INTEGER REFERENCES ldb_distinguished_names, 
                  class_name    TEXT REFERENCES ldb_object_classes 
                );

                CREATE TABLE ldb_attributes
                (
                  attr_name             TEXT PRIMARY KEY,
                  case_insensitive_p    BOOLEAN DEFAULT FALSE,
                  wildcard_p            BOOLEAN DEFAULT FALSE,
                  hidden_p              BOOLEAN DEFAULT FALSE,
                  integer_p             BOOLEAN DEFAULT FALSE
                );

                CREATE TABLE ldb_attr_value_pairs 
                (
                  dn_id         INTEGER REFERENCES ldb_distinguished_names, 
                  attr_name     TEXT, -- optionally REFERENCES ldb_attributes
                  attr_value    TEXT,

                  UNIQUE (dn_id, attr_name, attr_value)
                );

                -- ------------------------------------------------------

                CREATE TRIGGER ldb_distinguished_names_delete_tr
                  AFTER DELETE
                  ON ldb_distinguished_names
                  FOR EACH ROW
                    BEGIN
                      DELETE FROM ldb_attr_value_pairs
                        WHERE dn_id = old.dn_id;
                      DELETE FROM ldb_dn_object_classes
                        WHERE dn_id = old.dn_id;
                    END;

                CREATE TRIGGER ldb_attr_value_pairs_insert_tr
                  BEFORE INSERT
                  ON ldb_attr_value_pairs
                  FOR EACH ROW
                    BEGIN
                      INSERT OR IGNORE INTO ldb_attributes
                          (attr_name)
                        VALUES
                          (new.attr_name);
                    END;

                CREATE TRIGGER ldb_attr_value_pairs_delete_tr
                  AFTER DELETE
                  ON ldb_attr_value_pairs
                  FOR EACH ROW
                    BEGIN
                      DELETE FROM ldb_attributes
                        WHERE (SELECT COUNT(*)
                                 FROM ldb_attr_value_pairs
                                 WHERE attr_name = old.attr_name) = 0
                          AND attr_name = old.attr_name;
                    END;

                -- ------------------------------------------------------

                CREATE INDEX ldb_distinguished_names_dn_idx
                  ON ldb_distinguished_names (dn);

                CREATE INDEX ldb_object_classes_tree_key_idx
                  ON ldb_object_classes (tree_key);


                CREATE INDEX ldb_dn_object_classes_dn_id_idx
                  ON ldb_dn_object_classes (dn_id);

                CREATE INDEX ldb_dn_object_classes_class_name_idx
                  ON ldb_dn_object_classes (class_name);


                CREATE INDEX ldb_attr_value_pairs_dn_id_name_case_idx
                  ON ldb_attr_value_pairs (dn_id, attr_name);

                CREATE INDEX ldb_attr_value_pairs_dn_id_name_nocase_idx
                  ON ldb_attr_value_pairs (dn_id, attr_name COLLATE NOCASE);

                -- ------------------------------------------------------

                /* all defaults for dn, initially */
                INSERT INTO ldb_attributes (attr_name)
                  VALUES ('dn');

                /* We need an implicit 'top' level object class */
                INSERT INTO ldb_object_classes (class_name, tree_key)
                  SELECT 'top', /* next_tree_key(NULL) */ '0001';

                -- ------------------------------------------------------

                COMMIT;

                -- ------------------------------------------------------
                ";

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
        if ((lsqlite3->last_rc = sqlite3_open(p, &lsqlite3->sqlite3)) != SQLITE_SUCCESS) {
                return ret;
        }

        if (bNewDatabase) {
                /*
                 * Create the database schema
                 */
                for (pTail = schema; pTail != NULL; ) {

                        if ((lsqlite3->last_rc = sqlite3_prepare(
                                     lsqlite3->sqlite3,
                                     pTail,
                                     -1,
                                     &stmt,
                                     &pTail)) != SQLITE_SUCCESS ||
                            (lsqlite3->last_rc = sqlite3_step(stmt)) != SQLITE_DONE ||
                            (lsqlite3->last_rc = sqlite_finalize(stmt)) != SQLITE_SUCCESS) {

                                (void) sqlite3_close(lsqlite3->sqlite3);
                                return ret;
                        }
                }
        } else {
                /*
                 * Ensure that the database we opened is one of ours
                 */
                if ((lsqlite3->last_rc = sqlite3_prepare(
                             lsqlite3->sqlite3,
                             "SELECT COUNT(*) "
                             "  FROM sqlite_master "
                             "  WHERE type = 'table' "
                             "    AND name IN "
                             "      ("
                             "        'ldb_info', "
                             "        'ldb_distinguished_names', "
                             "        'ldb_object_classes', "
                             "        'ldb_dn_object_classes', "
                             "        'ldb_attributes', "
                             "        'ldb_attr_value_pairs' "
                             "      );",
                             -1,
                             &stmt,
                             &pTail)) != SQLITE_SUCCESS ||
                    (lsqlite3->last_rc = sqlite3_step(stmt)) != SQLITE_ROW ||
                    sqlite3_column_int(stmt, 0) != 6 ||
                    (lsqlite3->last_rc = sqlite_finalize(stmt)) != SQLITE_SUCCESS ||

                    (lsqlite3->last_rc = sqlite3_prepare(
                             lsqlite3->sqlite3,
                             "SELECT 1 "
                             "  FROM ldb_info "
                             "  WHERE database_type = 'LDB' "
                             "    AND version = '1.0';",
                             -1,
                             &stmt,
                             &pTail)) != SQLITE_SUCCESS ||
                    (lsqlite3->last_rc = sqlite3_step(stmt)) != SQLITE_ROW ||
                    (lsqlite3->last_rc = sqlite_finalize(stmt)) != SQLITE_SUCCESS) {
                
                        /* It's not one that we created.  See ya! */
                        (void) sqlite3_close(lsqlite3->sqlite3);
                        return SQLITE_MISUSE;
                }
        }

        /*
         * Pre-compile each of the queries we'll be using.
         */

        if ((lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "BEGIN IMMEDIATE;",
                     -1,
                     &lsqlite3->queries.begin,
                     &pTail)) != SQLITE_SUCCESS ||

            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "COMMIT;",
                     -1,
                     &lsqlite3->queries.commit,
                     &pTail)) != SQLITE_SUCCESS ||

            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "ROLLBACK;",
                     -1,
                     &lsqlite3->queries.rollback,
                     &pTail)) != SQLITE_SUCCESS ||

            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "INSERT INTO ldb_distinguished_names (dn_id, dn) "
                     "  VALUES (:dn_id, :dn);",
                     -1,
                     &lsqlite3->queries.newDN,
                     &pTail)) != SQLITE_SUCCESS ||

            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "UPDATE ldb_distinguished_names "
                     "  SET dn = :newDN "
                     "  WHERE dn = :oldDN;",
                     -1,
                     &lsqlite3->queries.renameDN,
                     &pTail)) != SQLITE_SUCCESS ||

            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "DELETE FROM ldb_distinguished_names "
                     "  WHERE dn = :dn;",
                     -1,
                     &lsqlite3->queries.deleteDN,
                     &pTail)) != SQLITE_SUCCESS ||

            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "INSERT OR IGNORE INTO ldb_object_classes "
                     "    (class_name, tree_key)"
                     "  SELECT :class_name, next_tree_key(NULL);",
                     -1,
                     &lsqlite3->queries.newObjectClass,
                     &pTail)) != SQLITE_SUCCESS ||
            
            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "INSERT OR REPLACE INTO ldb_dn_object_classes "
                     "    (dn_id, class_name) "
                     "  VALUES (:dn_id, :class_name);",
                     -1,
                     &lsqlite3->queries.assignObjectClass,
                     &pTail)) != SQLITE_SUCCESS ||
            
            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "INSERT OR IGNORE INTO ldb_attributes (name) "
                     "  VALUES (:name);",
                     -1,
                     &lsqlite3->queries.newAttributeUseDefaults,
                     &pTail)) != SQLITE_SUCCESS ||
            
            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "INSERT OR REPLACE INTO ldb_attributes "
                     "    (name, "
                     "     case_insensitive_p, "
                     "     wildcard_p, "
                     "     hidden_p, "
                     "     integer_p) "
                     "  VALUES (:name, "
                     "          :case_insensitive_p, "
                     "          :wildcard_p, "
                     "          :hidden_p, "
                     "          :integer_p);",
                     -1,
                     &lsqlite3->queries.newAttribute,
                     &pTail)) != SQLITE_SUCCESS ||
            
            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "INSERT INTO ldb_attr_value_pairs "
                     "    (dn_id, attr_name, attr_value) "
                     "  VALUES (:dn_id, :attr_name, :attr_value);",
                     -1,
                     &lsqlite3->queries.addAttrValuePair,
                     &pTail)) != SQLITE_SUCCESS ||
            
            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "UPDATE ldb_attr_value_pairs "
                     "  SET attr_value = :attr_value "
                     "  WHERE dn_id = :dn_id "
                     "    AND attr_name = :attr_name;",
                     -1,
                     &lsqlite3->queries.addAttrValuePair,
                     &pTail)) != SQLITE_SUCCESS ||
            
            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "DELETE FROM ldb_attr_value_pairs "
                     "  WHERE dn_id = :dn_id "
                     "    AND attr_name = :attr_name;"
                     -1,
                     &lsqlite3->queries.deleteAttrValuePair,
                     &pTail)) != SQLITE_SUCCESS ||
            
            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "INSERT OR REPLACE INTO ldb_object_classes "
                     "    (class_name, tree_key) "
                     "  SELECT :child_class, next_tree_key(:parent_class);"
                     -1,
                     &lsqlite3->queries.insertSubclass,
                     &pTail)) != SQLITE_SUCCESS ||

            (lsqlite3->last_rc = sqlite3_prepare(
                     lsqlite3->sqlite3,
                     "SELECT dn_id "
                     "  FROM ldb_distinguished_names "
                     "  WHERE dn = :dn;"
                     -1,
                     &lsqlite3->queries.getDNID,
                     &pTail)) != SQLITE_SUCCESS) {

                (void) sqlite3_close(lsqlite3->sqlite3);
                return ret;
        }

        return SQLITE_SUCCESS;
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

	lsqlite3->sqlite3 = NULL;
	lsqlite3->options = NULL;
        lsqlite3->lock_count = 0;

	lsqlite3->last_rc = lsqlite3_initialize(&lsqlite3->sqlite3, url);
	if (lsqlite3->last_rc != SQLITE_SUCCESS) {
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
        if (lsqlite3->sqlite3 != NULL) {
                (void) sqlite3_close(lsqlite3->sqlite3);
        }
	talloc_free(ldb);
	return NULL;
}

