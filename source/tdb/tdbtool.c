#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <ctype.h>
#include "tdb.h"

/* a tdb tool for manipulating a tdb database */

#define FSTRING_LEN 128
typedef char fstring[FSTRING_LEN];

typedef struct connections_key {
	pid_t pid;
	int cnum;
	fstring name;
} connections_key;

typedef struct connections_data {
	int magic;
	pid_t pid;
	int cnum;
	uid_t uid;
	gid_t gid;
	char name[24];
	char addr[24];
	char machine[128];
	time_t start;
} connections_data;

static TDB_CONTEXT *tdb;
static TDB_CONTEXT *tdb_dest;

static int print_rec(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state);

static void print_asc(unsigned char *buf,int len)
{
	int i;
	for (i=0;i<len;i++)
		printf("%c",isprint(buf[i])?buf[i]:'.');
}

static void print_data(unsigned char *buf,int len)
{
	int i=0;
	if (len<=0) return;
	printf("[%03X] ",i);
	for (i=0;i<len;) {
		printf("%02X ",(int)buf[i]);
		i++;
		if (i%8 == 0) printf(" ");
		if (i%16 == 0) {      
			print_asc(&buf[i-16],8); printf(" ");
			print_asc(&buf[i-8],8); printf("\n");
			if (i<len) printf("[%03X] ",i);
		}
	}
	if (i%16) {
		int n;
		
		n = 16 - (i%16);
		printf(" ");
		if (n>8) printf(" ");
		while (n--) printf("   ");
		
		n = i%16;
		if (n > 8) n = 8;
		print_asc(&buf[i-(i%16)],n); printf(" ");
		n = (i%16) - n;
		if (n>0) print_asc(&buf[i-n],n); 
		printf("\n");    
	}
}

static long fingerprint(TDB_DATA *key)
{
	u32 value;	/* Used to compute the hash value.  */
	u32   i;	/* Used to cycle through random values. */

	/* Set the initial value from the key size. */
	for (value = 0x238F13AF * key->dsize, i=0; i < key->dsize; i++)
		value = (value + (key->dptr[i] << (i*5 % 24)));

	return (1103515243 * value + 12345);  
}

static void help(void)
{
	printf("
tdbtool [tdb_src [tdb_dest]]

Interactive commands:
  copy      dbname     : copy an existing database to dbname
  create    dbname     : create a database
  delete    key        : delete a record by key
  dump                 : dump the database as strings
  erase                : erase the database
  free                 : print the database freelist
  help | h             : print help text
  info                 : display tdb stats
  insert    key,data   : insert a record (note the ',' separator)
  open      dbname     : open an existing database
  quit | q             : quit
  remove    partialkey : remove all keys matching partialkey
  store     key,data   : store/replace a record (note the ',' separator)
  show      key        : show a record by key
  !shellcmd            : execute the shell command shellcmd

  1 | first            : print the first record
  n | next             : print the next record
  \\n                   : repeat 'next' command

Examples:
    tdbtool                   # enter interactive mode
    tdbtool tdb_src           # tdb_src is opened, enter interactive mode
    tdbtool tdb_src > file    # tdb_src is opened, all key,values printed to stdout
    tdbtool tdb_src tdb_dest  # tdb_src is opened, all key,values copied to tdb_dest
\n");
}

static void terror(char *why)
{
	printf("%s\n", why);
}

static void create_tdb(void)
{
	char *tok = strtok(NULL, ",");
	if (!tok) {
		help();
		return;
	}
	if (tdb) tdb_close(tdb);
	tdb = tdb_open(tok, 0, TDB_CLEAR_IF_FIRST,
		       O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (!tdb) {
		printf("Could not create %s: %s\n", tok, strerror(errno));
	}
}

static void open_tdb(void)
{
	char *tok = strtok(NULL, ",");
	if (!tok) {
		help();
		return;
	}
	if (tdb) tdb_close(tdb);
	tdb = tdb_open(tok, 0, 0, O_RDWR, 0600);
	if (!tdb) {
		printf("Could not open %s: %s\n", tok, strerror(errno));
	}
}

static void insert_tdb(void)
{
	char *k = strtok(NULL, ",");
	char *d = strtok(NULL, ",");
	TDB_DATA key, dbuf;

	if (!k || !d) {
		help();
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k);
	dbuf.dptr = d;
	dbuf.dsize = strlen(d);

	if (tdb_store(tdb, key, dbuf, TDB_INSERT) == -1) {
		terror("insert failed");
	}
}

static void store_tdb(void)
{
	char *k = strtok(NULL, ",");
	char *d = strtok(NULL, ",");
	TDB_DATA key, dbuf;

	if (!k || !d) {
		help();
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k);
	dbuf.dptr = d;
	dbuf.dsize = strlen(d);

	if (tdb_store(tdb, key, dbuf, TDB_REPLACE) == -1) {
		terror("store failed");
	}
}

static int traverse_copy_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	if (tdb_store(tdb_dest, key, dbuf, TDB_REPLACE) == -1) return -1;
	return 0;
}

static void copy_tdb(void)
{
	int count;
	char *tok = strtok(NULL, ",");
	if (!tok) {
		help();
		return;
	}

	tdb_dest = tdb_open(tok, 0, TDB_CLEAR_IF_FIRST, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (!tdb_dest)
		printf("Could not open %s: %s\n", tok, strerror(errno));
	else { 
		if ((count = tdb_traverse(tdb, traverse_copy_fn, NULL)) == -1)
			printf("Error = %s\n", tdb_errorstr(tdb));
		else
			printf("Success: %d records copied to %s\n", count, tok);
		tdb_close(tdb_dest);
	}
}


static void show_tdb(void)
{
	char *k = strtok(NULL, ",");
	TDB_DATA key, dbuf;

	if (!k) {
		help();
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k)+1;

	dbuf = tdb_fetch(tdb, key);
	if (!dbuf.dptr) terror("fetch failed");
	/* printf("%s : %*.*s\n", k, (int)dbuf.dsize, (int)dbuf.dsize, dbuf.dptr); */
	print_rec(tdb, key, dbuf, NULL);
}

static void delete_tdb(void)
{
	char *k = strtok(NULL, ",");
	TDB_DATA key;

	if (!k) {
		help();
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k);

	if (tdb_delete(tdb, key) != 0) {
		terror("delete failed");
	}
}

static int print_conn_key(TDB_DATA key)
{
	printf( "pid    =%5d   ", ((connections_key*)key.dptr)->pid);
	printf( "cnum   =%10d  ", ((connections_key*)key.dptr)->cnum);
	printf( "name   =[%s]\n", ((connections_key*)key.dptr)->name);
	return 0;
}

static int print_conn_data(TDB_DATA dbuf)
{
	printf( "pid    =%5d   ", ((connections_data*)dbuf.dptr)->pid);
	printf( "cnum   =%10d  ", ((connections_data*)dbuf.dptr)->cnum);
	printf( "name   =[%s]\n", ((connections_data*)dbuf.dptr)->name);
	
	printf( "uid    =%5d   ",  ((connections_data*)dbuf.dptr)->uid);
	printf( "addr   =[%s]\n", ((connections_data*)dbuf.dptr)->addr);
	printf( "gid    =%5d   ",  ((connections_data*)dbuf.dptr)->gid);
	printf( "machine=[%s]\n", ((connections_data*)dbuf.dptr)->machine);
	printf( "start  = %s\n",   ctime(&((connections_data*)dbuf.dptr)->start));
	return 0;
}

static int print_rec(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
#if 0
	print_conn_key(key);
	print_conn_data(dbuf);
	return 0;
#else
	printf("\nkey %d bytes [%08x]\n", key.dsize, fingerprint(&key));
	print_data(key.dptr, key.dsize);
	printf("data %d bytes [%08x]\n", dbuf.dsize, fingerprint(&dbuf));
	print_data(dbuf.dptr, dbuf.dsize);
	return 0;
#endif
}


static char *remove_str;
static int remove_count;

static int traverse_remove_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	if (strncmp(remove_str,key.dptr,strlen(remove_str)) == 0) {
		if (tdb_delete(tdb, key) != 0)
			terror("delete failed");
		else
			remove_count++;
	}
	return 0;
}

static void remove_tdb(void)
{
	int count;

	remove_str = strtok(NULL, ",");
	if (remove_str) {
		remove_count = 0;
		if ((count = tdb_traverse(tdb, traverse_remove_fn, NULL)) == -1)
			printf("Error = %s\n", tdb_errorstr(tdb));
		else
			printf("%d records removed from %d records\n", remove_count, count);
	}
}

static int total_bytes;

static int traverse_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	total_bytes += dbuf.dsize;
	return 0;
}

static void info_tdb(void)
{
	int count;
	total_bytes = 0;
	if ((count = tdb_traverse(tdb, traverse_fn, NULL)) == -1)
		printf("Error = %s\n", tdb_errorstr(tdb));
	else
		printf("%d records totalling %d bytes\n", count, total_bytes);
}

static char *getline(char *prompt)
{
	static char line[1024];
	char *p;
	fputs(prompt, stdout);
	line[0] = 0;
	p = fgets(line, sizeof(line)-1, stdin);
	if (p) p = strchr(p, '\n');
	if (p) *p = 0;
	return p?line:NULL;
}

static int do_delete_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf,
                     void *state)
{
    return tdb_delete(tdb, key);
}

static void first_record(TDB_CONTEXT *tdb, TDB_DATA *pkey)
{
	TDB_DATA dbuf;
	*pkey = tdb_firstkey(tdb);
	
	dbuf = tdb_fetch(tdb, *pkey);
	if (!dbuf.dptr) terror("fetch failed");
	/* printf("%s : %*.*s\n", k, (int)dbuf.dsize, (int)dbuf.dsize, dbuf.dptr); */
	print_rec(tdb, *pkey, dbuf, NULL);
}

static void next_record(TDB_CONTEXT *tdb, TDB_DATA *pkey)
{
	TDB_DATA dbuf;
	*pkey = tdb_nextkey(tdb, *pkey);
	
	dbuf = tdb_fetch(tdb, *pkey);
	if (!dbuf.dptr) 
		terror("fetch failed");
	else
		/* printf("%s : %*.*s\n", k, (int)dbuf.dsize, (int)dbuf.dsize, dbuf.dptr); */
		print_rec(tdb, *pkey, dbuf, NULL);
}

int main(int argc, char *argv[])
{
    int bIterate = 0;
    char *line;
    char *tok;
	TDB_DATA iterate_kbuf;

    if (argc>1) {
        if (argv[1]) {
            static char tmp[1024];
    
            sprintf(tmp, "open %s", argv[1]);
            tok=strtok(tmp," ");
            open_tdb();
    
            if (argc==3) {
                if (tdb) {
                    sprintf(tmp, "copy %s", argv[2]);
                    tok=strtok(tmp," ");
                    copy_tdb();
                    tdb_close(tdb);
                }
                exit(0);
            }
            
            if (!isatty(1)) {
                if (tdb) {
                    tdb_traverse(tdb, print_rec, NULL);
                    tdb_close(tdb);
                }
                exit(0);
            }
        }
    }

    while ((line = getline("tdb> "))) {

        /* Shell command */
        
        if (line[0] == '!') {
            system(line + 1);
            continue;
        }
        
        if ((tok = strtok(line," "))==NULL) {
           if (bIterate)
              next_record(tdb, &iterate_kbuf);
           continue;
        }
        if (strcmp(tok,"create") == 0) {
            bIterate = 0;
            create_tdb();
            continue;
        } else if (strcmp(tok,"open") == 0) {
            open_tdb();
            continue;
        } else if ((strcmp(tok, "h") == 0) ||
                   (strcmp(tok, "help") == 0)) {
            help();
            continue;
        } else if ((strcmp(tok, "q") == 0) ||
                   (strcmp(tok, "quit") == 0)) {
            exit(0);
        }
            
        /* all the rest require a open database */
        if (!tdb) {
            bIterate = 0;
            terror("database not open");
            help();
            continue;
        }
            
        if (strcmp(tok,"insert") == 0) {
            bIterate = 0;
            insert_tdb();
        } else if (strcmp(tok,"copy") == 0) {
            bIterate = 0;
            copy_tdb();
        } else if (strcmp(tok,"store") == 0) {
            bIterate = 0;
            store_tdb();
        } else if (strcmp(tok,"show") == 0) {
            bIterate = 0;
            show_tdb();
        } else if (strcmp(tok,"erase") == 0) {
            bIterate = 0;
            tdb_traverse(tdb, do_delete_fn, NULL);
        } else if (strcmp(tok,"remove") == 0) {
            bIterate = 0;
            remove_tdb();
        } else if (strcmp(tok,"delete") == 0) {
            bIterate = 0;
            delete_tdb();
        } else if (strcmp(tok,"dump") == 0) {
            bIterate = 0;
            tdb_traverse(tdb, print_rec, NULL);
        } else if (strcmp(tok,"list") == 0) {
            tdb_dump_all(tdb);
        } else if (strcmp(tok,"info") == 0) {
            info_tdb();
        } else if (strcmp(tok, "free") == 0) {
            tdb_printfreelist(tdb);
        } else if ( (strcmp(tok, "1") == 0) ||
                    (strcmp(tok, "first") == 0)) {
            bIterate = 1;
            first_record(tdb, &iterate_kbuf);
        } else if ((strcmp(tok, "n") == 0) ||
                   (strcmp(tok, "next") == 0)) {
            next_record(tdb, &iterate_kbuf);
        } else {
            help();
        }
    }

    if (tdb) tdb_close(tdb);

    return 0;
}
