#include "utils.h"
#include "log.h"
#include "tui.h"
#include "ctdb-test.h"
#include <ctdb.h>
#include <tdb.h>
#include <talloc.h>
#include <dlinklist.h>
#include <errno.h>

struct lock {
	struct lock *next, *prev;
	struct ctdb_db *db;
	struct ctdb_lock *lock;
	unsigned int id;
};

static unsigned int lock_id;
static struct lock *locks;

static void readrecordlock_help(int argc, char **argv)
{
#include "generated-readrecordlock-help:readrecordlock"
/*** XML Help:
    <section id="c:readrecordlock">
     <title><command>readrecordlock</command></title>
     <para>Read and lock a record in a ctdb database</para>
     <cmdsynopsis>
      <command>readrecordlock</command>
      <arg choice="req"><replaceable>db-id</replaceable></arg>
      <arg choice="req"><replaceable>key</replaceable></arg>
     </cmdsynopsis>

     <para>Read and lock a record.  Prints the record, and a 1-based
     sequential handle on success, which should be handed to
     <command>releaselock</command>
     </para>
     </section>
*/
}

static void releaselock_help(int argc, char **argv)
{
#include "generated-readrecordlock-help:releaselock"
/*** XML Help:
    <section id="c:releaselock">
     <title><command>releaselock</command></title>
     <para>Unlock a record in a ctdb database</para>
     <cmdsynopsis>
      <command>releaselock</command>
      <arg choice="req"><replaceable>db-id</replaceable></arg>
      <arg choice="req"><replaceable>lock-id</replaceable></arg>
     </cmdsynopsis>

     <para>Unlock a record successfully locked by
     <command>readrecordlock</command>.  </para>

     </section>
*/
}

static void writerecord_help(int argc, char **argv)
{
#include "generated-readrecordlock-help:writerecord"
/*** XML Help:
    <section id="c:writerecord">
     <title><command>writerecord</command></title>
     <para>Write to a locked record in a ctdb database</para>
     <cmdsynopsis>
      <command>writerecord</command>
      <arg choice="req"><replaceable>db-id</replaceable></arg>
      <arg choice="req"><replaceable>lock-id</replaceable></arg>
      <arg choice="req"><replaceable>data</replaceable></arg>
     </cmdsynopsis>

     <para>Once a record is locked with
     <command>readrecordlock</command>, you can write to it. </para>
     </section>
*/
}

static int lock_destructor(struct lock *lock)
{
	ctdb_release_lock(lock->db, lock->lock);
	DLIST_REMOVE(locks, lock);
	return 0;
}

static bool releaselock(int argc, char **argv)
{
	struct ctdb_db *db;
	struct lock *lock;

	if (argc != 3) {
		log_line(LOG_ALWAYS, "Need database number and lock number");
		return false;
	}

	db = find_db_by_id(atoi(argv[1]));
	if (!db) {
		log_line(LOG_ALWAYS, "Unknown db number %s", argv[1]);
		return false;
	}

	for (lock = locks; lock; lock = lock->next) {
		if (lock->id == atoi(argv[2]))
			break;
	}
	if (!lock) {
		log_line(LOG_ALWAYS, "Unknown lock number %s", argv[2]);
		return false;
	}
	talloc_free(lock);
	return true;
}

static bool writerecord(int argc, char **argv)
{
	struct ctdb_db *db;
	struct lock *lock;
	TDB_DATA data;

	if (argc != 4) {
		log_line(LOG_ALWAYS, "Need db-id, lock-id and data");
		return false;
	}

	db = find_db_by_id(atoi(argv[1]));
	if (!db) {
		log_line(LOG_ALWAYS, "Unknown db number %s", argv[1]);
		return false;
	}

	for (lock = locks; lock; lock = lock->next) {
		if (lock->id == atoi(argv[2]))
			break;
	}
	if (!lock) {
		log_line(LOG_ALWAYS, "Unknown lock number %s", argv[2]);
		return false;
	}

	data.dptr = (unsigned char *)argv[3];
	data.dsize = strlen(argv[3]);

	if (!ctdb_writerecord(db, lock->lock, data)) {
		log_line(LOG_UI, "writerecordlock: failed %s", strerror(errno));
		return false;
	}
	return true;
}

static bool readrecordlock(int argc, char **argv)
{
	struct lock *lock = talloc(working, struct lock);
	TDB_DATA key, data;

	if (!get_ctdb()) {
		log_line(LOG_ALWAYS, "No ctdb connection");
		return false;
	}
	if (argc != 3) {
		log_line(LOG_ALWAYS, "Need db-id and key");
		return false;
	}

	lock->db = find_db_by_id(atoi(argv[1]));
	if (!lock->db) {
		log_line(LOG_ALWAYS, "Unknown db number %s", argv[1]);
		return false;
	}

	key.dptr = (unsigned char *)argv[2];
	key.dsize = strlen(argv[2]);

	lock->lock = ctdb_readrecordlock(get_ctdb(), lock->db, key, &data);
	if (!lock->lock) {
		log_line(LOG_UI, "readrecordlock: failed %s", strerror(errno));
		return false;
	}
	lock->id = ++lock_id;
	DLIST_ADD(locks, lock);
	talloc_set_destructor(lock, lock_destructor);

	log_line(LOG_UI, "lock %u: data '%.*s'",
		 lock->id, data.dsize, (char *)data.dptr);
	return true;
}

static void readrecordlock_init(void)
{
	tui_register_command("readrecordlock",
			     readrecordlock, readrecordlock_help);
	tui_register_command("releaselock", releaselock, releaselock_help);
	tui_register_command("writerecord", writerecord, writerecord_help);
}
init_call(readrecordlock_init);
