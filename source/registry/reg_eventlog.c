/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Marcin Krzysztof Porwit    2005.
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
 
#include "includes.h"

/**********************************************************************
 handle enumeration of values AT KEY_EVENTLOG
 *********************************************************************/
 
static int eventlog_topkey_values( char *key, REGVAL_CTR *val )
{
    int 		num_values = 0;
    char		*keystr, *key2 = NULL;
    char		*base, *new_path;
    fstring		evtlogname; 
    UNISTR2		data;
    int             iDisplayNameId;
    int             iMaxSize;
    
    /* 
     *  TODO - callout to get these values...
     */
    
    if ( key ) 
    {
	key2 = SMB_STRDUP( key );
	keystr = key2;
	reg_split_path( keystr, &base, &new_path );
	
	iDisplayNameId = 0x00000100;
	iMaxSize=        0x00080000;
	
	fstrcpy( evtlogname, base );
	DEBUG(10,("eventlog_topkey_values: subkey root=> [%s] subkey path=>[%s]\n", base,new_path));
	
	if ( !new_path ) 
	{
	    iDisplayNameId = 0x01;
	    regval_ctr_addvalue( val, "ErrorControl",    REG_DWORD, (char*)&iDisplayNameId,       sizeof(int) ); 
	    
	    init_unistr2( &data, "EventLog", UNI_STR_TERMINATE);
	    regval_ctr_addvalue( val, "DisplayName",             REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	    
	    num_values = regval_ctr_numvals( val );	
	    
	    
	    num_values = 0;
	}
    }
    
    SAFE_FREE( key2 ); 
    return num_values;
}

/**********************************************************************
 handle enumeration of values below KEY_EVENTLOG\<Eventlog>
 *********************************************************************/
 
static int eventlog_subkey_values( char *key, REGVAL_CTR *val )
{
    int 	num_values = 0;
    char     	*keystr, *key2 = NULL;
    char	*base, *new_path;
    fstring    	evtlogname; 
    UNISTR2    	data;
    int         iDisplayNameId;
    int         iMaxSize;
    int         iRetention;
    
    /* 
     *  TODO - callout to get these values...
     */
    
    if ( !key ) 
	return num_values;
    
    key2 = SMB_STRDUP( key );
    keystr = key2;
    reg_split_path( keystr, &base, &new_path );
    
    iDisplayNameId = 0x00000100;
    /* MaxSize is limited to 0xFFFF0000 (UINT_MAX - USHRT_MAX) as per MSDN documentation */
    iMaxSize=        0xFFFF0000;
    /* records in the samba log are not overwritten */
    iRetention =     0xFFFFFFFF;
    
    fstrcpy( evtlogname, base );
    DEBUG(10,("eventlog_subpath_values_printer: eventlogname [%s]\n", base));
    DEBUG(10,("eventlog_subpath_values_printer: new_path [%s]\n", new_path));
    if ( !new_path ) 
    {
#if 0
	regval_ctr_addvalue( val, "DisplayNameId",    REG_DWORD, (char*)&iDisplayNameId,       sizeof(int) ); 
	
	init_unistr2( &data, "%SystemRoot%\\system32\\els.dll", UNI_STR_TERMINATE);
	regval_ctr_addvalue( val, "DisplayNameFile",             REG_EXPAND_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
#endif
	regval_ctr_addvalue( val, "MaxSize",          REG_DWORD, (char*)&iMaxSize, sizeof(int));
	regval_ctr_addvalue( val, "Retention",  REG_DWORD, (char *)&iRetention, sizeof(int));
#if 0
	init_unistr2( &data, lp_logfile(), UNI_STR_TERMINATE);
	regval_ctr_addvalue( val, "File",             REG_EXPAND_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
#endif
	init_unistr2( &data, base, UNI_STR_TERMINATE);
	regval_ctr_addvalue( val, "PrimaryModule",         REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
	init_unistr2( &data, base, UNI_STR_TERMINATE);
	regval_ctr_addvalue( val, "Sources",          REG_MULTI_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
	num_values = regval_ctr_numvals( val );	
	
    } 
    else
    {
	iDisplayNameId = 0x07;
	regval_ctr_addvalue( val, "CategoryCount",    REG_DWORD, (char*)&iDisplayNameId,       sizeof(int) ); 
	
	init_unistr2( &data, "%SystemRoot%\\system32\\eventlog.dll", UNI_STR_TERMINATE);
	regval_ctr_addvalue( val, "CategoryMessageFile", REG_EXPAND_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
	num_values = regval_ctr_numvals( val );	
	
	num_values = 0;
    }
    
    SAFE_FREE( key2 ); 
    return num_values;
}


/**********************************************************************
 It is safe to assume that every registry path passed into on of 
 the exported functions here begins with KEY_EVENTLOG else
 these functions would have never been called.  This is a small utility
 function to strip the beginning of the path and make a copy that the 
 caller can modify.  Note that the caller is responsible for releasing
 the memory allocated here.
 **********************************************************************/

static char* trim_eventlog_reg_path( const char *path )
{
	const char *p;
	uint16 key_len = strlen(KEY_EVENTLOG);
	
	/* 
	 * sanity check...this really should never be True.
	 * It is only here to prevent us from accessing outside
	 * the path buffer in the extreme case.
	 */
	
	if ( strlen(path) < key_len ) {
		DEBUG(0,("trim_reg_path: Registry path too short! [%s]\n", path));
		DEBUG(0,("trim_reg_path: KEY_EVENTLOG => [%s]!\n", KEY_EVENTLOG));
		return NULL;
	}
	
	
	p = path + strlen( KEY_EVENTLOG );
	
	if ( *p == '\\' )
		p++;
	
	if ( *p )
		return SMB_STRDUP(p);
	else
		return NULL;
}
/**********************************************************************
 Enumerate registry subkey names given a registry path.  
 Caller is responsible for freeing memory to **subkeys
 *********************************************************************/
static int eventlog_subkey_info( const char *key, REGSUBKEY_CTR *subkey_ctr )
{
    char 	*path;
    BOOL       	top_level = False;
    int		num_subkeys = 0;
    const char        **evtlog_list;
    
    path = trim_eventlog_reg_path( key );
    DEBUG(10,("eventlog_subkey_info: entire key=>[%s] SUBkey=>[%s]\n", key,path));	
    
    /* check to see if we are dealing with the top level key */
    num_subkeys = 0;
    
    if ( !path )
	top_level = True;
    
    num_subkeys = 0;
    if ( !(evtlog_list = lp_eventlog_list()) ) {
	SAFE_FREE(path);
	return num_subkeys;
    }

    
    if ( top_level )
    { 
        /* todo - get the eventlog subkey values from the smb.conf file
	   for ( num_subkeys=0; num_subkeys<MAX_TOP_LEVEL_KEYS; num_subkeys++ )
	   regsubkey_ctr_addkey( subkey_ctr, top_level_keys[num_subkeys] ); */
	DEBUG(10,("eventlog_subkey_info: Adding eventlog subkeys from globals\n"));	
	/* TODO - make this  from the globals.szEventLogs list */
	
	while (*evtlog_list) 
	{
   	    DEBUG(10,("eventlog_subkey_info: Adding subkey =>[%s]\n",*evtlog_list));	
	    regsubkey_ctr_addkey( subkey_ctr, *evtlog_list);
	    evtlog_list++;
	    num_subkeys++;
	}
    }
    else 
    {
	while (*evtlog_list && (0==num_subkeys) ) 
	{
	    if (0 == StrCaseCmp(path,*evtlog_list)) 
	    {
		DEBUG(10,("eventlog_subkey_info: Adding subkey [%s] for key =>[%s]\n",path,*evtlog_list));	
		regsubkey_ctr_addkey( subkey_ctr, *evtlog_list);
		num_subkeys = 1;
	    }
	    evtlog_list++;
	}
	
	if (0==num_subkeys) 
	    DEBUG(10,("eventlog_subkey_info: No match on SUBkey=>[%s]\n", path));
    }
    
    SAFE_FREE( path );
    return num_subkeys;
}

/**********************************************************************
 Enumerate registry values given a registry path.  
 Caller is responsible for freeing memory 
 *********************************************************************/

static int eventlog_value_info( const char *key, REGVAL_CTR *val )
{
	char 		*path;
	BOOL		top_level = False;
	int		num_values = 0;
	
	DEBUG(10,("eventlog_value_info: key=>[%s]\n", key));
	
	path = trim_eventlog_reg_path( key );
	
	/* check to see if we are dealing with the top level key */
	
	if ( !path )
	    top_level = True;
	if ( top_level )
	    num_values = eventlog_topkey_values(path,val);
	else 
	{
	    DEBUG(10,("eventlog_value_info: SUBkey=>[%s]\n", path));
	    num_values = eventlog_subkey_values(path,val);
	}
	return num_values;
}

/**********************************************************************
 Stub function which always returns failure since we don't want
 people storing eventlog information directly via registry calls
 (for now at least)
 *********************************************************************/
static BOOL eventlog_store_subkey( const char *key, REGSUBKEY_CTR *subkeys )
{
	return False;
}

/**********************************************************************
 Stub function which always returns failure since we don't want
 people storing eventlog information directly via registry calls
 (for now at least)
 *********************************************************************/
static BOOL eventlog_store_value( const char *key, REGVAL_CTR *val )
{
	return False;
}

/* 
 * Table of function pointers for accessing eventlog data
 */
REGISTRY_OPS eventlog_ops = {
	eventlog_subkey_info,
	eventlog_value_info,
	eventlog_store_subkey,
	eventlog_store_value,
	NULL
};
