/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  Samba MYSQL SAM Database, by Benjamin Kuit.
 *  Copyright (C) Benjamin Kuit                     1999,
 *  Copyright (C) Andrew Tridgell              1992-1999,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if defined(WITH_MYSQL) || defined(WITH_MYSQLSAM)

#include "includes.h"
#include <mysql.h>

extern int DEBUGLEVEL;

#define UNIX_NAME(row)   ((*row)[0])
#define UNIX_UID(row)    ((*row)[1])
#define NT_NAME(row)     ((*row)[2])
#define RID(row)         ((*row)[3])
#define LM_HASH(row)     ((*row)[4])
#define NT_HASH(row)     ((*row)[5])
#define FLAGS(row)       ((*row)[6])
#define CHANGE_TIME(row) ((*row)[7])

void *mysql_fill_smb_passwd( MYSQL_ROW *row );

typedef void *(*mysql_fill_func)( MYSQL_ROW * );
#define FILL_SMB mysql_fill_smb_passwd

void *mysql_startpwent(BOOL update);
void mysql_endpwent(void *vp);
SMB_BIG_UINT mysql_getpwpos(void *vp);
BOOL mysql_setpwpos(void *vp, SMB_BIG_UINT pos);
void *mysql_fill_smb_passwd( MYSQL_ROW *row );
MYSQL_ROW *mysql_getpwent(void *vp);
void *mysql_fetch_passwd( mysql_fill_func filler, char *where );
void *mysql_getpwuid( mysql_fill_func filler, uid_t uid );
void *mysql_getpwnam( mysql_fill_func filler, char *field, const char *name );
int mysql_db_lock_connect( MYSQL *handle );
BOOL mysql_add_smb( MYSQL *handle, struct smb_passwd *smb );
BOOL mysql_mod_smb( MYSQL *handle, struct smb_passwd *smb, BOOL override );
BOOL mysql_del_smb( MYSQL *handle, char *unix_name );

static fstring mysql_table = { 0 };

struct mysql_struct {
	MYSQL handle;
	MYSQL_RES *result;
	uint current_row;
};
typedef struct mysql_struct mysql_ctrl;

static char *mysql_retrieve_password(char *passfile) {
	static fstring pass;
	static time_t last_checked = (time_t)0;
	static char pass_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_-+=|~`\\{}[]:;\"'?/>.<,";
	fstring temppass;
	FILE *filep;
	int length;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	if ( passfile == NULL ) {
		pass[0]=0;
		return pass;
	}

	if ( time(NULL) - last_checked <= 60 ) {
		return pass;
	}

	if ( file_modtime(passfile) < last_checked ) {
		return pass;
	}

	filep = sys_fopen(passfile,"r");

	if ( filep == NULL ) {
		return pass;
	}

	memset(temppass,0,sizeof(temppass));

	if ( fgets( temppass, sizeof(temppass)-1, filep) == NULL ) {
		fclose(filep);
		return pass;
	}

	fclose(filep);

	length = strspn( temppass, pass_chars );
	temppass[length<sizeof(temppass)-1?length:sizeof(temppass)-1] = '\0';

	fstrcpy( pass, temppass );

	last_checked = time(NULL);

	return pass;
}

static int mysql_db_connect( MYSQL *handle ) {
	char *password;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	password = mysql_retrieve_password(lp_mysql_passfile());

	if ( !mysql_connect(handle, lp_mysql_host(), lp_mysql_user(), password) ) {
		DEBUG(0,("mysql_connect: %s\n",mysql_error(handle)));
		return -1;
	}

	if ( mysql_select_db( handle, lp_mysql_db()) ) {
		DEBUG(0,("mysql_connect: %s\n",mysql_error(handle)));
		mysql_close(handle);
		return -1;
	}

	fstrcpy(mysql_table,lp_mysql_table());

	return 0;
}

static int mysql_lock_table( MYSQL *handle, BOOL write_access ) {
	fstring query;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	slprintf( query, sizeof(query), "lock tables %s %s", mysql_table, write_access==True?"write":"read");

	if ( mysql_query( handle, query ) ) {
		DEBUG(0,("Cannot get lock: %s: %s\n",query,mysql_error(handle) ));
		return -1;
	}

	return 0;
}

int mysql_db_lock_connect( MYSQL *handle ) {

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	if ( mysql_db_connect( handle ) ) {
		return -1;
	}
	
	if ( mysql_lock_table( handle, True ) ) {
		mysql_close( handle );
		return -1;
	}

	return 0;
}

static MYSQL_RES *mysql_select_results( MYSQL *handle, char *selection ) {
	MYSQL_RES *result;
	pstring query;
	int query_length;
	char select[] = "select ";
	char where[] = " where ";
	char from[] = " from ";
	char mysql_query_string[] = "unix_name, unix_uid, nt_name, user_rid, smb_passwd, smb_nt_passwd, acct_ctrl, pass_last_set_time";

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	query_length = sizeof( select ) + sizeof( mysql_query_string ) + sizeof(from ) + strlen( mysql_table );

	if ( selection != NULL && *selection != '\0' ) {
		query_length += sizeof( where ) + strlen( selection );
	}

	if ( query_length >= sizeof( query ) ) {
		DEBUG(0,("Query string too long\n"));
		return NULL;
	}

	pstrcpy( query, select);
	pstrcat( query, mysql_query_string );
	pstrcat( query, from );
	pstrcat( query, mysql_table );

	if ( selection != NULL && *selection != '\0' ) {
		pstrcat( query, where );
		pstrcat( query, selection );
	}

	DEBUG(5,("mysql> %s\n",query));
	if ( mysql_query( handle, query ) ) {
		DEBUG(0,("%s: %s\n", query, mysql_error(handle) ));
		return NULL;
	}

	result = mysql_store_result( handle );

	if ( mysql_num_fields( result ) != 8 ) {
		DEBUG(0,("mysql_num_result = %d (!=8)\n",mysql_num_fields( result )));
		return NULL;
	}

	if ( result == NULL ) {
		DEBUG(0,("mysql_store_result: %s\n",mysql_error(handle)));
		return NULL;
	}

	return result;
}

void *mysql_startpwent( BOOL update ) {
	mysql_ctrl *mysql;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	mysql = (mysql_ctrl *)malloc( sizeof(mysql_ctrl) );
	if ( mysql == NULL ) {
		DEBUG(0,("malloc: Out of memory\n"));
		return NULL;
	}

	memset( mysql, 0, sizeof(mysql_ctrl) );

	if ( mysql_db_connect( &mysql->handle ) ) {
		return NULL;
	}

	if ( mysql_lock_table( &mysql->handle, update ) ) {
		mysql_close( &mysql->handle );
		return NULL;
	}

	mysql->result = mysql_select_results( &mysql->handle, NULL );

	if ( mysql->result == NULL ) {
		mysql_close( &mysql->handle );
		return NULL;
	}

	mysql->current_row = 0;

	return (void*)mysql;
}

void mysql_endpwent( void *ptr ) {
	mysql_ctrl *handle;

	DEBUG(5,("%s\n",FUNCTION_MACRO));
	handle = (mysql_ctrl *)ptr;

	mysql_free_result( handle->result );

	mysql_close( &handle->handle );

	free( handle );
}

SMB_BIG_UINT mysql_getpwpos(void *vp) {

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	return ((mysql_ctrl *)vp)->current_row;
}

BOOL mysql_setpwpos(void *vp, SMB_BIG_UINT pos) {

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	mysql_data_seek( ((mysql_ctrl*)vp)->result, (uint)pos );
((mysql_ctrl *)vp)->current_row=(uint)pos;

	return True;
}

static void quote_hash( char *target, unsigned char *passwd ) {
        char hex[] = "0123456789ABCDEF";
	int i;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	if ( passwd == NULL ) {
		fstrcpy(target,"NULL");
	}
	else {
		target[0]='\'';
		for (i=0;i<32;i++) {
			target[i+1] = hex[(passwd[i>>1]>>(((~i)&1)<<2))&15];
		}
		target[33] = '\'';
		target[34] = '\0';
	}
}

static unsigned char *decode_hash( char *hash, unsigned char *buffer ) {
	char hex[] = "0123456789ABCDEF";
	int pos, v1, v2;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	if ( hash == NULL ) {
		return NULL;
	}

	for (pos=0;pos<16;pos++) {
		for( v1 = 0; v1 < sizeof(hex) && hash[0] != hex[v1]; v1++ );
		for( v2 = 0; v2 < sizeof(hex) && hash[1] != hex[v2]; v2++ );

		if ( v1 == sizeof(hex) || v2 == sizeof(hex) ) {
			return NULL;
		}

		buffer[pos] = (v1<<4)|v2;
		hash += 2;
	}

	return buffer;
}

void *mysql_fill_smb_passwd( MYSQL_ROW *row ) {
	static struct smb_passwd pw_buf;
	static fstring unix_name;
	static fstring nt_name;
	static unsigned char smbpwd[16];
	static unsigned char smbntpwd[16];

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	pwdb_init_smb(&pw_buf);

	fstrcpy( unix_name, UNIX_NAME(row) );
	pw_buf.unix_name = unix_name;
	pw_buf.unix_uid = get_number( UNIX_UID(row) );

	if ( NT_NAME(row) != NULL ) {
		fstrcpy( nt_name, NT_NAME(row) );
		pw_buf.nt_name = nt_name;
	}

	if ( RID(row) != NULL ) {
		pw_buf.user_rid = get_number( RID(row) );
	}

	pw_buf.smb_passwd = decode_hash( LM_HASH(row), smbpwd );
	if ( !pw_buf.smb_passwd ) {
		DEBUG(4, ("entry invalidated for unix user %s\n", unix_name ));
		return NULL;
	}

	pw_buf.smb_nt_passwd = decode_hash( NT_HASH(row), smbntpwd );

	if ( FLAGS(row) != NULL ) {
		pw_buf.acct_ctrl = get_number( FLAGS(row) );
	}

	if ( pw_buf.acct_ctrl == 0 ) {
		pw_buf.acct_ctrl = ACB_NORMAL;
	}

	pw_buf.pass_last_set_time = get_number( CHANGE_TIME(row) );

	return (void*)&pw_buf;
}

MYSQL_ROW *mysql_getpwent(void *vp) {
	mysql_ctrl *mysql;
	static MYSQL_ROW row;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	mysql = (mysql_ctrl*)vp;
	row = mysql_fetch_row( mysql->result );

	if ( row == NULL ) {
		return NULL;
	}

	mysql->current_row++;

	return &row;
}

struct smb_passwd *mysql_getsmbpwent(void *vp) {

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	return (struct smb_passwd*)mysql_fill_smb_passwd( mysql_getpwent(vp) );
}

void *mysql_fetch_passwd( mysql_fill_func filler, char *where ) {
	void *retval;
	MYSQL handle;
	MYSQL_RES *result;
	MYSQL_ROW row;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	if ( filler == NULL ) {
		return NULL;
	}

	if ( where == NULL || *where == '\0' ) {
		DEBUG(0,("Null or empty query\n"));
		return NULL;
	}

	if ( mysql_db_connect( &handle ) ) {
		return NULL;
	}

	result = mysql_select_results( &handle, where );
	if ( result == NULL ) {
		mysql_close( &handle );
		return NULL;
	}

	row = mysql_fetch_row ( result );
	if ( row == NULL ) {
		mysql_free_result( result );
		mysql_close( &handle );
		return NULL;
	}

	if ( DEBUGLEVEL >= 7 ) {
		int field;
		for (field=0; field< mysql_num_fields( result ); field++ ) {
			DEBUG(7,(" row[%d] = \"%s\"\n",field,row[field]?row[field]:"NULL"));
		}
	}

	retval = (*filler)( &row );

	mysql_free_result( result );
	mysql_close( &handle );

	return retval;
}

void *mysql_getpwuid(mysql_fill_func filler, uid_t uid) {
	fstring where;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	slprintf( where, sizeof(where), "unix_uid=%lu", uid);

	return mysql_fetch_passwd(filler,where);
}

struct smb_passwd *mysql_getsmbpwuid(uid_t uid) {

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	return (struct smb_passwd *)mysql_getpwuid( FILL_SMB, uid );
}

void *mysql_getpwnam(mysql_fill_func filler, char *field, const char *name) {
	fstring where;
	char format[] = "%s='%s'";

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	if ( filler == NULL ) {
		DEBUG(0,("Empty fill opteration\n"));
		return NULL;
	}

	if ( field == NULL || *field == '\0' ) {
		DEBUG(0,("Empty or NULL field name\n"));
		return NULL;
	}

	if ( name == NULL || *name == '\0' ) {
		DEBUG(0,("Empty or NULL query\n"));
		return NULL;
	}

	if ( sizeof(format) + strlen(name) + strlen(field) > sizeof(where) ) {
		DEBUG(0,("Query string too long\n"));
		return NULL;
	}

	slprintf(where, sizeof( where ), format, field, name );

	return mysql_fetch_passwd( filler, where );
}

struct smb_passwd *mysql_getsmbpwnam(const char *unix_name) {
	DEBUG(5,("%s\n",FUNCTION_MACRO));

	return mysql_getpwnam( FILL_SMB, "unix_name", unix_name );
}

static void quote_string(char *target, char *string) {
	DEBUG(5,("%s\n",FUNCTION_MACRO));

	if ( string == NULL ) {
		fstrcpy( target, "NULL" );
	}
	else {
		target[0] = '\'';
		safe_strcpy(&target[1],string,sizeof(fstring)-2);
		safe_strcpy(&target[strlen(target)],"'",2);
	}
}

BOOL mysql_del_smb( MYSQL *handle, char *unix_name ) {
	pstring query;
	char format[] = "delete from %s where unix_name='%s'";

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	if (strlen( format ) + strlen(mysql_table) + strlen(unix_name)) {
		return False;
	}

	slprintf( query, sizeof(query), format, mysql_table, unix_name);

	if ( mysql_query( handle, query ) ) {
		DEBUG(0,("%s: %s\n", query, mysql_error(handle) ));
		return False;
	}

	return True;
}

BOOL mysql_add_smb( MYSQL *handle, struct smb_passwd *smb ) {
	pstring query;
	char format[] = "insert into %s (unix_name, unix_uid) values ( '%s', %lu )";

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	if ( strlen(format) + strlen(mysql_table) + strlen(smb->unix_name) + 10 > sizeof(query) ) {
		DEBUG(0,("Query too long\n"));
		return False;
	}
	
	slprintf( query, sizeof(query), "insert into %s (unix_name,unix_uid) values ('%s', %lu)", mysql_table, smb->unix_name, smb->unix_uid);

	if ( mysql_query( handle, query ) ) {
		DEBUG(0,("%s: %s\n",query,mysql_error(handle) ));
		return False;
	}

	return True;
}

BOOL mysql_mod_smb( MYSQL *handle, struct smb_passwd *smb, BOOL override ) {
	pstring query;
	fstring smb_passwd;
	fstring smb_nt_passwd;
	fstring nt_name;

	char format[] = "update %s set nt_name=%s, user_rid=%lu, smb_passwd=%s, smb_nt_passwd=%s, acct_ctrl=%u, pass_last_set_time=unix_timestamp() where unix_name='%s'";
	char extra[] = " and not ISNULL(smb_passwd)";

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	if ( strlen(format) + 2*20 + 3*10 + 2*32 + strlen(mysql_table) >= sizeof( query ) + strlen( extra ) ) {
		DEBUG(0,("Query string too long\n"));
		return False;
	}
	
	quote_hash(smb_passwd, smb->smb_passwd);
	quote_hash(smb_nt_passwd, smb->smb_nt_passwd);

	quote_string(nt_name, smb->nt_name);

	slprintf( query, sizeof(query), format, mysql_table, nt_name, (long unsigned)smb->user_rid, smb_passwd, smb_nt_passwd, smb->acct_ctrl, smb->unix_name);

	if ( override != True ) {
		pstrcat( query, extra );
	}

	if ( mysql_query( handle, query ) ) {
		DEBUG(0,("%s: %s\n",query,mysql_error(handle) ));
		return False;
	}

	if ( mysql_affected_rows( handle ) < 1 ) {
		DEBUG(3,("No entries changed\n"));
		return False;
	}

	return True;
}

BOOL mysql_add_smbpwd_entry(struct smb_passwd *smb) {
	MYSQL handle;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	if ( smb == NULL ) {
		return False;
	}

	if ( mysql_db_lock_connect( &handle ) ) {
		return False;
	}

	if ( !mysql_add_smb( &handle, smb ) ) {
		mysql_close( &handle );
		return False;
	}

	if ( !mysql_mod_smb( &handle, smb, True ) ) {
		mysql_del_smb( &handle, smb->unix_name );
		mysql_close( &handle );
		return False;
	}

	mysql_close(&handle);
	return True;
}

BOOL mysql_mod_smbpwd_entry(struct smb_passwd *smb, BOOL override) {
	MYSQL handle;

	DEBUG(5,("%s\n",FUNCTION_MACRO));

	if ( smb == NULL ) {
		return False;
	}

	if ( mysql_db_lock_connect( &handle ) ) {
		return False;
	}

	if ( !mysql_mod_smb( &handle, smb, override ) ) {
		mysql_close(&handle);
		return False;
	}

	mysql_close(&handle);
	return True;
}

static struct smb_passdb_ops mysql_ops = {
	mysql_startpwent,
	mysql_endpwent,
	mysql_getpwpos,
	mysql_setpwpos,
	mysql_getsmbpwnam,
	mysql_getsmbpwuid,
	mysql_getsmbpwent,
	mysql_add_smbpwd_entry,
	mysql_mod_smbpwd_entry
};

struct smb_passdb_ops *mysql_initialise_password_db(void)
{
	(void*)mysql_retrieve_password(NULL);
	return &mysql_ops;
}

#else
	void mysql_dummy_smb_function(void) { }
#endif
