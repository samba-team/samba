/*
 * Samba Unix/Linux SMB client utility 
 * Write Eventlog records to a tdb
 *
 * Copyright (C) Brian Moran                2005.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"

#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_UTIL_EVENTLOG

Eventlog_entry ee;

extern int optind;
extern char *optarg;

int opt_debug = 0;

static void usage( char *s )
{
	printf( "\nUsage: %s [-d] [-h] <Eventlog Name>\n", s );
	printf( "\t-d\tturn debug on\n" );
	printf( "\t-h\tdisplay help\n\n" );
}

static void display_eventlog_names( void )
{
	const char **elogs;
	int i;

	elogs = lp_eventlog_list(  );
	printf( "Active eventlog names (from smb.conf):\n" );
	printf( "--------------------------------------\n" );
	for ( i = 0; elogs[i]; i++ ) {
		printf( "\t%s\n", elogs[i] );
	}
}

int main( int argc, char *argv[] )
{
	FILE *f1;

	/* fixed constants are bad bad bad  */
	pstring linein;
	BOOL is_eor;
	int pret, opt;
	int rcnum;
	char *argfname, *exename;
	char *tdbname;


	TDB_CONTEXT *elog_tdb;

	opt_debug = 0;		/* todo set this from getopts */


	lp_load( dyn_CONFIGFILE, True, False, False );

	exename = argv[0];

	while ( ( opt = getopt( argc, argv, "dh" ) ) != -1 ) {
		switch ( opt ) {
		case 'h':
			usage( argv[0] );
			display_eventlog_names(  );
			exit( 0 );
			break;

		case 'd':
			opt_debug = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if ( argc < 1 ) {
		usage( exename );
		exit( 1 );
	}



	f1 = stdin;

	if ( !f1 ) {
		printf( "Can't open STDIN\n" );
		return -1;
	}


	if ( opt_debug ) {
		printf( "Starting %s for eventlog [%s]\n", exename, argv[0] );
		display_eventlog_names(  );
	}

	argfname = argv[0];

	if ( !(elog_tdb = elog_open_tdb( argfname ) ) ) {
		printf( "can't open the eventlog TDB (%s)\n", tdbname );
		return -1;
	}

	ZERO_STRUCT( ee );	/* MUST initialize between records */

	while ( !feof( f1 ) ) {
		fgets( linein, sizeof( linein ) - 1, f1 );
		linein[strlen( linein ) - 1] = 0;	/* whack the line delimiter */

		if ( opt_debug )
			printf( "Read line [%s]\n", linein );

		is_eor = False;

		pret = parse_logentry( ( char * ) &linein, &ee, &is_eor );

		if ( is_eor ) {
			fixup_eventlog_entry( &ee );

			if ( opt_debug )
				printf( "record number [%d], tg [%d] , tw [%d]\n", 
					ee.record.record_number, 
					ee.record.time_generated, 
					ee.record.time_written );

			if ( ee.record.time_generated != 0 ) {

				/* printf("Writing to the event log\n"); */

				rcnum = write_eventlog_tdb( elog_tdb, &ee ); 
				if ( !rcnum ) {
					printf( "Can't write to the event log\n" );
				} else {
					if ( opt_debug )
						printf( "Wrote record %d\n",
							rcnum );
				}
			} else {
				if ( opt_debug )
					printf( "<null record>\n" );
			}
			ZERO_STRUCT( ee );	/* MUST initialize between records */
		}
	}

	tdb_close( elog_tdb );

	return 0;
}
