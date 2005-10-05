
#include "includes.h"

#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_UTIL_EVENTLOG

Eventlog_entry ee;

int main( int argc, char **argv )
{
	FILE *f1;
	char linein[1024];

	/* fixed constants are bad bad bad  */
	char fname[1024];

	BOOL is_eor;
	int pret, i;
	int rcnum;
	int debug;
	const char **elogs;

	TDB_CONTEXT *the_tdb;

	debug = 1;		/* todo set this from getopts */

	lp_load( dyn_CONFIGFILE, True, False, False );

	if ( argc < 2 ) {
		printf( "Usage %s <Eventlog Name>\n", argv[0] );
		return -1;
	}

	/* f1 = fopen("foo.txt","r"); */
	f1 = stdin;
	if ( !f1 ) {
		printf( "Can't open STDIN\n" );
		return -1;
	}

	elogs = lp_eventlog_list(  );

	if ( debug ) {
		printf( "%s starting for [%s] ... valid eventlogs:\n",
			argv[0], argv[1] );
		for ( i = 0; elogs[i]; i++ ) {
			printf( "%s\n", elogs[i] );
		}
	}

	/* todo - check for the eventlog name being passed as being something that smb.conf
	   knows about -- and defer the open in case we have an chicken and egg issue */

	if ( mk_tdbfilename( ( char * ) &fname, argv[1], sizeof( fname ) ) ) {
		the_tdb = open_eventlog_tdb( lock_path( ( char * ) &fname ) );
	} else {
		printf( "can't open filename [%s]\n", fname );
		return -1;
	}

	if ( the_tdb == NULL ) {
		printf( "can't open the eventlog TDB\n" );
		return -1;
	}
	memset( &ee, 0, sizeof( Eventlog_entry ) );	/* MUST initialize between records */
	while ( !feof( f1 ) ) {
		fgets( linein, sizeof( linein ) - 1, f1 );
		linein[strlen( linein ) - 1] = 0;	/* whack the line delimiter */
		if ( debug )
			printf( "Read line [%s]\n", linein );

		is_eor = False;

		pret = parse_logentry( ( char * ) &linein, &ee, &is_eor );
		if ( is_eor ) {
			fixup_eventlog_entry( &ee );

			if ( debug )
				printf( "record number [%d], tg [%d] , tw [%d]\n", ee.record.record_number, ee.record.time_generated, ee.record.time_written );

			if ( ee.record.time_generated != 0 ) {
				/* printf("Writing to the event log\n"); */
				if ( !
				     ( rcnum =
				       write_eventlog_tdb( the_tdb,
							   &ee ) ) ) {
					printf( "Can't write to the event log\n" );
				} else {
					if ( debug )
						printf( "Wrote record %d\n",
							rcnum );
				}
			} else {
				if ( debug )
					printf( "<null record>\n" );
			}
			memset( &ee, 0, sizeof( Eventlog_entry ) );	/* MUST initialize between records */
		}
	}

	return 0;
}
