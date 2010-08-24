#include "utils.h"
#include "log.h"
#include "tui.h"
#include "ctdb-test.h"
#include <ctdb.h>
#include <tdb.h>
#include <talloc.h>
#include <dlinklist.h>
#include <errno.h>

static unsigned int db_num;
static struct db *dbs;

struct db {
	struct db *next, *prev;
	struct ctdb_db *db;
	const char *name;
	unsigned int num;
	bool persistent;
	uint32_t tdb_flags;
};

struct ctdb_db *find_db_by_id(unsigned int id)
{
	struct db *db;

	for (db = dbs; db; db = db->next) {
		if (db->num == id)
			return db->db;
	}
	return NULL;
}

static void attachdb_help(int agc, char **argv)
{
#include "generated-attachdb-help:attachdb"
/*** XML Help:
    <section id="c:attachdb">
     <title><command>attachdb</command></title>
     <para>Attach to a ctdb database</para>
     <cmdsynopsis>
      <command>attachdb</command>
      <arg choice="req"><replaceable>name</replaceable></arg>
      <arg choice="req"><replaceable>persistent</replaceable></arg>
      <arg choice="opt"><replaceable>tdb-flags</replaceable></arg>
     </cmdsynopsis>
     <para>Attach to the database of the given <replaceable>name</replaceable>.
	<replaceable>persistent</replaceable> is 'true' or 'false', an

	<replaceable>tdb-flags</replaceable> an optional one or more
	comma-separated values:</para>
     <variablelist>
      <varlistentry>
       <term>SEQNUM</term>
       <listitem>
        <para>Use sequence numbers on the tdb</para>
       </listitem>
      </varlistentry>
     </variablelist>

     <para>It uses a consecutive number for each attached db to
     identify it for other ctdb-test commands, starting with 1.</para>

     <para>Without any options, the <command>attachdb</command>
      command lists all databases attached.</para>
     </section>
*/
}

static void detachdb_help(int agc, char **argv)
{
#include "generated-attachdb-help:detachdb"
/*** XML Help:
    <section id="c:detachdb">
     <title><command>detachdb</command></title>
     <para>Detach from a ctdb database</para>
     <cmdsynopsis>
      <command>detachdb</command>
      <arg choice="req"><replaceable>number</replaceable></arg>
     </cmdsynopsis>
     <para>Detach from the database returned by <command>attachdb</command>.
     </para>
     </section>
*/
}
static int db_destructor(struct db *db)
{
	ctdb_detachdb(get_ctdb(), db->db);
	DLIST_REMOVE(dbs, db);
	return 0;
}

static bool detachdb(int argc, char **argv)
{
	struct db *db;

	if (argc != 2) {
		log_line(LOG_ALWAYS, "Need database number");
		return false;
	}

	for (db = dbs; db; db = db->next) {
		if (db->num == atoi(argv[1]))
			break;
	}
	if (!db) {
		log_line(LOG_ALWAYS, "Unknown db number %s", argv[1]);
		return false;
	}
	talloc_free(db);
	return true;
}

static bool attachdb(int argc, char **argv)
{
	struct db *db;

	if (!get_ctdb()) {
		log_line(LOG_ALWAYS, "No ctdb connection");
		return false;
	}

	if (argc == 1) {
		log_line(LOG_UI, "Databases currently attached:");
		for (db = dbs; db; db = db->next) {
			log_line(LOG_ALWAYS, "  %i: %s: %s %u",
				 db->num, db->name,
				 db->persistent
				 ? "persistent" : "not persistent",
				 db->tdb_flags);
		}
		return true;
	}
	if (argc != 3 && argc != 4) {
		log_line(LOG_ALWAYS, "Need 2 or 3 args");
		return false;
	}
	db = talloc(working, struct db);
	db->name = talloc_strdup(db, argv[1]);
	if (strcasecmp(argv[2], "true") == 0)
		db->persistent = true;
	else if (strcasecmp(argv[2], "false") == 0)
		db->persistent = false;
	else {
		log_line(LOG_ALWAYS, "persistent should be true or false");
		talloc_free(db);
		return false;
	}
	db->tdb_flags = 0;
	if (argc == 4) {
		if (strcasecmp(argv[3], "seqnum") == 0)
			db->tdb_flags |= TDB_SEQNUM;
		else {
			log_line(LOG_ALWAYS, "invalid tdb-flags");
			talloc_free(db);
			return false;
		}
	}
	db->db = ctdb_attachdb(get_ctdb(), db->name, db->persistent,
			       db->tdb_flags);
	if (!db->db) {
		log_line(LOG_UI, "ctdb_attachdb: %s", strerror(errno));
		return false;
	}
	db->num = ++db_num;
	DLIST_ADD(dbs, db);
	talloc_set_destructor(db, db_destructor);
	log_line(LOG_UI, "attached: %u", db->num);
	return true;
}

static void attachdb_init(void)
{
	tui_register_command("attachdb", attachdb, attachdb_help);
	tui_register_command("detachdb", detachdb, detachdb_help);
}
init_call(attachdb_init);
