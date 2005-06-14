/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald (Jerry) Carter             2005,
 *  Copyright (C) Marcin Krzysztof Porwit           2005.
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

/* TODO - Do the OpenService service name matching case-independently, or at least make it an option. */


#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

#define SERVICEDB_VERSION_V1 1 /* Will there be more? */
#define INTERNAL_SERVICES_LIST "NETLOGON Spooler"

/*                                                                                                                     */
/* scripts will execute from the following libdir, if they are in the enable svcctl=<list of scripts>                  */
/* these should likely be symbolic links. Note that information about them will be extracted from the files themselves */
/* using the LSB standard keynames for various information                                                             */

#define SVCCTL_SCRIPT_DIR  "/svcctl/"

/*
 * sertup the \PIPE\svcctl db API
 */
 
#define SCVCTL_DATABASE_VERSION_V1 1
TALLOC_CTX    *svcdb=NULL;
static TDB_CONTEXT *service_tdb; /* used for services tdb file */

/* there are two types of services -- internal, and external.
   Internal services are "built-in" to samba -- there may be 
   functions that exist to provide the control and enumeration 
   functions.  There certainly is information returned to be 
   displayed in the typical management console.

   External services are those that can be specified in the smb.conf 
   file -- and they conform to the LSB specification as to having 
   particular keywords in the scripts. Note that these "scripts" are 
   located in the lib directory, and are likely links to LSB-compliant 
   init.d scripts, such as those that might come with Suse. Note 
   that the spec is located  http://www.linuxbase.org/spec/ */



/* Expand this to include what can and can't be done 
   with a particular internal service. Expand as necessary 
   to add other infromation like what can be controlled, 
   etc. */

typedef struct Internal_service_struct
{
	const char *filename;		/* internal name "index" */
	const char *displayname;
	const char *description;
	const uint32 statustype;
	void *status_fn; 
	void *control_fn;
} Internal_service_description;


static const Internal_service_description ISD[] = {
	{ "NETLOGON",	"Net Logon",	"Provides logon and authentication service to the network", 	0x110,	NULL, NULL},
	{ "Spooler",	"Spooler",	"Printing Services", 						0x0020, NULL, NULL},
	{ NULL, NULL, NULL, 0, NULL, NULL}
};


/********************************************************************
 TODOs
 (a) get and set security descriptors on services
 (b) read and write QUERY_SERVICE_CONFIG structures (both kinds, country and western)
 (c) create default secdesc objects for services and SCM
 (d) check access control masks with se_access_check()
********************************************************************/

/*********************************************************************
 given a service nice name, find the underlying service name
*********************************************************************/

BOOL  _svcctl_service_nicename_to_servicename(TDB_CONTEXT *stdb,pstring service_nicename, pstring servicename,int szsvcname) 
{
	pstring keystring;
	TDB_DATA key_data;

	if ((stdb == NULL) || (service_nicename==NULL) || (servicename == NULL)) 
		return False;

	pstr_sprintf(keystring,"SERVICE_NICENAME/%s", servicename);

	DEBUG(5, ("_svcctl_service_nicename_to_servicename: Looking for service name [%s], key [%s]\n", 
		service_nicename, keystring));

	key_data = tdb_fetch_bystring(stdb,keystring);

	if (key_data.dsize == 0) {
		DEBUG(5, ("_svcctl_service_nicename_to_servicename: [%s] Not found, tried key [%s]\n",service_nicename,keystring));
		return False; 
	}

	strncpy(servicename,key_data.dptr,szsvcname);
	servicename[(key_data.dsize > szsvcname ? szsvcname : key_data.dsize)] = 0;
	DEBUG(5, ("_svcctl_service_nicename_to_servicename: Found service name [%s], name is  [%s]\n",
		service_nicename,servicename));

	return True;
}

/*********************************************************************
*********************************************************************/

static BOOL  write_si_to_service_tdb(TDB_CONTEXT *stdb,char *service_name, Service_info *si) 
{
	pstring keystring;

	/* Note -- when we write to the tdb, we "index" on the filename 
	   field, not the nice name. when a service is "opened", it is 
	   opened by the nice (SERVICENAME) name, not the file name. 
	   So there needs to be a mapping from nice name back to the file name. */

	if ((stdb == NULL) || (si == NULL) || (service_name==NULL) || (*service_name == 0)) 
		return False;


	/* Store the nicename */

	pstr_sprintf(keystring,"SERVICE_NICENAME/%s", si->servicename);
	tdb_store_bystring(stdb,keystring,string_tdb_data(service_name),TDB_REPLACE);

	pstr_sprintf(keystring,"SERVICE/%s/TYPE", service_name);
	tdb_store_bystring(stdb,keystring,string_tdb_data(si->servicetype),TDB_REPLACE);

	pstr_sprintf(keystring,"SERVICE/%s/FILENAME", service_name);
	tdb_store_bystring(stdb,keystring,string_tdb_data(si->filename),TDB_REPLACE);

	pstr_sprintf(keystring,"SERVICE/%s/PROVIDES", service_name);
	tdb_store_bystring(stdb,keystring,string_tdb_data(si->provides),TDB_REPLACE);

	pstr_sprintf(keystring,"SERVICE/%s/SERVICENAME", service_name);
	tdb_store_bystring(stdb,keystring,string_tdb_data(si->servicename),TDB_REPLACE);

	pstr_sprintf(keystring,"SERVICE/%s/DEPENDENCIES", service_name);
	tdb_store_bystring(stdb,keystring,string_tdb_data(si->dependencies),TDB_REPLACE);

	pstr_sprintf(keystring,"SERVICE/%s/SHOULDSTART", service_name);
	tdb_store_bystring(stdb,keystring,string_tdb_data(si->shouldstart),TDB_REPLACE);

	pstr_sprintf(keystring,"SERVICE/%s/SHOULDSTOP", service_name);
	tdb_store_bystring(stdb,keystring,string_tdb_data(si->shouldstop),TDB_REPLACE);

	pstr_sprintf(keystring,"SERVICE/%s/REQUIREDSTART", service_name);
	tdb_store_bystring(stdb,keystring,string_tdb_data(si->requiredstart),TDB_REPLACE);

	pstr_sprintf(keystring,"SERVICE/%s/REQUIREDSTOP", service_name);
	tdb_store_bystring(stdb,keystring,string_tdb_data(si->requiredstop),TDB_REPLACE);

	pstr_sprintf(keystring,"SERVICE/%s/DESCRIPTION", service_name);
	tdb_store_bystring(stdb,keystring,string_tdb_data(si->description),TDB_REPLACE);

	pstr_sprintf(keystring,"SERVICE/%s/SHORTDESC", service_name);
	tdb_lock_bystring(stdb, keystring, 0);
	if (si->shortdescription && *si->shortdescription) 
		tdb_store_bystring(stdb,keystring,string_tdb_data(si->shortdescription),TDB_REPLACE);
	else
	      	tdb_store_bystring(stdb,keystring,string_tdb_data(si->description),TDB_REPLACE);

	return True;
}


/*******************************************************************************
 Get the INTERNAL services information for the given service name. 
*******************************************************************************/

static BOOL _svcctl_get_internal_service_data(const Internal_service_description *isd, Service_info *si)
{
	ZERO_STRUCTP( si );
#if 0
	
	pstrcpy( si->servicename, isd->displayname);
	pstrcpy( si->servicetype, "INTERNAL");
	pstrcpy( si->filename, isd->filename);
	pstrcpy( si->provides, isd->displayname);
	pstrcpy( si->description, isd->description);
	pstrcpy( si->shortdescription, isd->description);
#endif
	
	return True;
}


/*******************************************************************************
 Get the services information  by reading and parsing the shell scripts. These 
 are symbolically linked into the  SVCCTL_SCRIPT_DIR  directory.

 Get the names of the services/scripts to read from the smb.conf file.
*******************************************************************************/

static BOOL _svcctl_get_LSB_data(char *fname,Service_info *si )
{
	pstring initdfile;
	char mybuffer[256];
	const char *tokenptr;
	char **qlines;
	int fd = -1;
	int nlines, *numlines,i,in_section,in_description;
	
	pstrcpy(si->servicename,"");
	pstrcpy(si->servicetype,"EXTERNAL");
	pstrcpy(si->filename,fname);
	pstrcpy(si->provides,"");
	pstrcpy(si->dependencies,"");
	pstrcpy(si->shouldstart,"");
	pstrcpy(si->shouldstop,"");
	pstrcpy(si->requiredstart,"");
	pstrcpy(si->requiredstop,"");
	pstrcpy(si->description,"");
	pstrcpy(si->shortdescription,"");

	numlines = &nlines;
	in_section = 0;
	in_description = 0;

   
	if( !fname || !*fname ) {
		DEBUG(0, ("Must define an \"LSB-style init file\" to read.\n"));
		return False;
	}
	pstrcpy(initdfile,dyn_LIBDIR);
	pstrcat(initdfile,SVCCTL_SCRIPT_DIR);
	pstrcat(initdfile,fname);

	/* TODO  - should check to see if the file that we're trying to open is 
	   actually a script. If it's NOT, we should do something like warn, 
	   and not continue to try to find info we're looking for */

	DEBUG(10, ("Opening [%s]\n", initdfile));
	fd = -1;
	fd = open(initdfile,O_RDONLY);
	*numlines = 0;

	if (fd == -1) {
		DEBUG(10, ("Couldn't open [%s]\n", initdfile));
		return False;
	}

	qlines = fd_lines_load(fd, numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", *numlines));
	close(fd);
    

	if (*numlines) {
	
		for(i = 0; i < *numlines; i++) {

			DEBUGADD(10, ("Line[%d] = %s\n", i, qlines[i]));
			if (!in_section && (0==strwicmp("### BEGIN INIT INFO", qlines[i]))) {
				/* we now can look for params */
				DEBUGADD(10, ("Configuration information starts on line = [%d]\n", i));
				in_section = 1;

			} else if (in_section && (0==strwicmp("### END INIT INFO", qlines[i]))) {
				DEBUGADD(10, ("Configuration information ends on line = [%d]\n", i));
				DEBUGADD(10, ("Description is [%s]\n", si->description));
				in_description = 0;
				in_section = 0;
				break;
			} else if (in_section) {
				tokenptr = qlines[i];
				if (in_description) {
					DEBUGADD(10, ("Processing DESCRIPTION [%d]\n", *tokenptr));
					if (tokenptr && (*tokenptr=='#') && (*(tokenptr+1)=='\t')) {
						DEBUGADD(10, ("Adding to DESCRIPTION [%d]\n", *tokenptr));
						pstrcat(si->description," ");
						pstrcat(si->description,tokenptr+2);
						continue;
					}
					in_description = 0;
					DEBUGADD(10, ("Not a description!\n"));
				}
				if (!next_token(&tokenptr,mybuffer," \t",sizeof(mybuffer))) {
					DEBUGADD(10, ("Invalid line [%d]\n", i));
					break; /* bad line? */
				}
				if (0 != strncmp(mybuffer,"#",1)) {
					DEBUGADD(10, ("Invalid line [%d], is %s\n", i,mybuffer));
					break;
				}
				if (!next_token(&tokenptr,mybuffer," \t",sizeof(mybuffer))) {
					DEBUGADD(10, ("Invalid token on line [%d]\n", i));
					break; /* bad line? */
				}	      
				DEBUGADD(10, ("Keyword is  [%s]\n", mybuffer));
				if (0==strwicmp(mybuffer,"Description:")) {
					while (tokenptr && *tokenptr && (strchr(" \t",*tokenptr))) { 
						tokenptr++; 
					}
					pstrcpy(si->description,tokenptr);
					DEBUGADD(10, ("FOUND DESCRIPTION! Data is [%s]\n", tokenptr));
					in_description = 1;
				} else {
					while (tokenptr && *tokenptr && (strchr(" \t",*tokenptr))) { 
						tokenptr++; 
					}
					DEBUGADD(10, ("Data is [%s]\n", tokenptr));
					in_description = 0;

					/* save certain keywords, don't save others */
					if (0==strwicmp(mybuffer, "Provides:")) {
						pstrcpy(si->provides,tokenptr);
						pstrcpy(si->servicename,tokenptr);
					}

					if (0==strwicmp(mybuffer, "Short-Description:")) {
						pstrcpy(si->shortdescription,tokenptr);
					}

					if (0==strwicmp(mybuffer, "Required-start:")) {
						pstrcpy(si->requiredstart,tokenptr);
						pstrcpy(si->dependencies,tokenptr);
					}

					if (0==strwicmp(mybuffer, "Should-start:")) {
						pstrcpy(si->shouldstart,tokenptr);
					}
				}
			}
		}

		file_lines_free(qlines);
			return True;
	}

	return False;
}

/****************************************************************************
 Create/Open the service control manager tdb. This code a clone of init_group_mapping.
****************************************************************************/

BOOL init_svcctl_db(void)
{
	const char *vstring = "INFO/version";
	uint32 vers_id;
	char **svc_list;
	char **svcname;
	pstring keystring;
	pstring external_service_list;
	pstring internal_service_list;
	Service_info si;
	const Internal_service_description *isd_ptr;
	/* svc_list = str_list_make( "etc/init.d/skeleton  etc/init.d/syslog", NULL ); */
	svc_list=(char **)lp_enable_svcctl(); 

	if (service_tdb)
		return True;

	pstrcpy(external_service_list,"");

	service_tdb = tdb_open_log(lock_path("services.tdb"), 0, TDB_DEFAULT, O_RDWR, 0600);
	if (!service_tdb) {
		DEBUG(0,("Failed to open service db\n"));
		service_tdb = tdb_open_log(lock_path("services.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
		if (!service_tdb) return False;
		DEBUG(0,("Created new services db\n"));
	}

	if ((-1 == tdb_fetch_uint32(service_tdb, vstring,&vers_id)) || (vers_id != SERVICEDB_VERSION_V1)) {
	  /* wrong version of DB, or db was just created */
	  tdb_traverse(service_tdb, tdb_traverse_delete_fn, NULL);
	  tdb_store_uint32(service_tdb, vstring, SERVICEDB_VERSION_V1);
	}
	tdb_unlock_bystring(service_tdb, vstring);

	DEBUG(0,("Initializing services db\n"));
	
	svcname = svc_list;

	/* Get the EXTERNAL services as mentioned by line in smb.conf */

	while (*svcname) {
		DEBUG(10,("Reading information on service %s\n",*svcname));
		if (_svcctl_get_LSB_data(*svcname,&si));{
			/* write the information to the TDB */
			write_si_to_service_tdb(service_tdb,*svcname,&si);
			/* definitely not efficient to do it this way. */
			pstrcat(external_service_list,"\"");
			pstrcat(external_service_list,*svcname);
			pstrcat(external_service_list,"\" ");
		}
		svcname++;
	}
	pstrcpy(keystring,"EXTERNAL_SERVICES");
        tdb_lock_bystring(service_tdb, keystring, 0);
	DEBUG(8,("Storing external service list [%s]\n",external_service_list));
        tdb_store_bystring(service_tdb,keystring,string_tdb_data(external_service_list),TDB_REPLACE);
        tdb_unlock_bystring(service_tdb,keystring);

	/* Get the INTERNAL services */
	
	pstrcpy(internal_service_list,"");
	isd_ptr = ISD; 

	while (isd_ptr && (isd_ptr->filename)) {
		DEBUG(10,("Reading information on service %s\n",isd_ptr->filename));
		if (_svcctl_get_internal_service_data(isd_ptr,&si)){
			/* write the information to the TDB */
			write_si_to_service_tdb(service_tdb,(char *)isd_ptr->filename,&si);
			/* definitely not efficient to do it this way. */
			pstrcat(internal_service_list,"\"");
			pstrcat(internal_service_list,isd_ptr->filename);
			pstrcat(internal_service_list,"\" ");

		}
		isd_ptr++;
	}
	pstrcpy(keystring,"INTERNAL_SERVICES");
        tdb_lock_bystring(service_tdb, keystring, 0);
	DEBUG(8,("Storing internal service list [%s]\n",internal_service_list));
        tdb_store_bystring(service_tdb,keystring,string_tdb_data(internal_service_list),TDB_REPLACE);
        tdb_unlock_bystring(service_tdb,keystring);

	return True;
}

/********************************************************************
********************************************************************/

static BOOL read_service_tdb_to_si(TDB_CONTEXT *stdb,char *service_name, Service_info *si) 
{

	pstring keystring;
	TDB_DATA  key_data;

	if ((stdb == NULL) || (si == NULL) || (service_name==NULL) || (*service_name == 0)) 
		return False;

	/* TODO  - error handling -- what if the service isn't in the DB? */
    
	pstr_sprintf(keystring,"SERVICE/%s/TYPE", service_name);
	key_data = tdb_fetch_bystring(stdb,keystring);
	strncpy(si->servicetype,key_data.dptr,key_data.dsize);
	si->servicetype[key_data.dsize] = 0;

	/* crude check to see if the service exists... */
  	DEBUG(3,("Size of the TYPE field is %d\n",key_data.dsize));
	if (key_data.dsize == 0) 
		return False;

	pstr_sprintf(keystring,"SERVICE/%s/FILENAME", service_name);
	key_data = tdb_fetch_bystring(stdb,keystring);
	strncpy(si->filename,key_data.dptr,key_data.dsize);
	si->filename[key_data.dsize] = 0;

	pstr_sprintf(keystring,"SERVICE/%s/PROVIDES", service_name);
	key_data = tdb_fetch_bystring(stdb,keystring);
	strncpy(si->provides,key_data.dptr,key_data.dsize);
	si->provides[key_data.dsize] = 0;
	strncpy(si->servicename,key_data.dptr,key_data.dsize);
	si->servicename[key_data.dsize] = 0;

	    
	pstr_sprintf(keystring,"SERVICE/%s/DEPENDENCIES", service_name);
	key_data = tdb_fetch_bystring(stdb,keystring);
	strncpy(si->dependencies,key_data.dptr,key_data.dsize);
	si->dependencies[key_data.dsize] = 0;

	pstr_sprintf(keystring,"SERVICE/%s/SHOULDSTART", service_name);
	key_data = tdb_fetch_bystring(stdb,keystring);
	strncpy(si->shouldstart,key_data.dptr,key_data.dsize);
	si->shouldstart[key_data.dsize] = 0;

	pstr_sprintf(keystring,"SERVICE/%s/SHOULD_STOP", service_name);
	key_data = tdb_fetch_bystring(stdb,keystring);
	strncpy(si->shouldstop,key_data.dptr,key_data.dsize);
	si->shouldstop[key_data.dsize] = 0;

	pstr_sprintf(keystring,"SERVICE/%s/REQUIREDSTART", service_name);
	key_data = tdb_fetch_bystring(stdb,keystring);
	strncpy(si->requiredstart,key_data.dptr,key_data.dsize);
	si->requiredstart[key_data.dsize] = 0;

	pstr_sprintf(keystring,"SERVICE/%s/REQUIREDSTOP", service_name);
	key_data = tdb_fetch_bystring(stdb,keystring);
	strncpy(si->requiredstop,key_data.dptr,key_data.dsize);
	si->requiredstop[key_data.dsize] = 0;

	pstr_sprintf(keystring,"SERVICE/%s/DESCRIPTION", service_name);
	key_data = tdb_fetch_bystring(stdb,keystring);
	strncpy(si->description,key_data.dptr,key_data.dsize);
	si->description[key_data.dsize] = 0;

	pstr_sprintf(keystring,"SERVICE/%s/SHORTDESC", service_name);
	key_data = tdb_fetch_bystring(stdb,keystring);
	strncpy(si->shortdescription,key_data.dptr,key_data.dsize);
	si->shortdescription[key_data.dsize] = 0;

	return True;
}

/******************************************************************
 free() function for REGISTRY_KEY
 *****************************************************************/
 
static void free_service_handle_info(void *ptr)
{
	SERVICE_INFO *info = (SERVICE_INFO*)ptr;
	
	SAFE_FREE(info->name);
	SAFE_FREE(info);
}

/******************************************************************
 Find a registry key handle and return a SERVICE_INFO
 *****************************************************************/

static SERVICE_INFO *find_service_info_by_hnd(pipes_struct *p, POLICY_HND *hnd)
{
	SERVICE_INFO *service_info = NULL;

	if( !find_policy_by_hnd( p, hnd, (void **)&service_info) ) {
		DEBUG(2,("find_service_info_by_hnd: handle not found"));
		return NULL;
	}

	return service_info;
}

/******************************************************************
 *****************************************************************/
 
WERROR create_open_service_handle( pipes_struct *p, POLICY_HND *handle, const char *service )
{
	SERVICE_INFO *info = NULL;
	
	if ( !(info = SMB_MALLOC_P( SERVICE_INFO )) )
		return WERR_NOMEM;
		
	/* the Service Manager has a NULL name */
	
	if ( !service ) {
		info->type = SVC_HANDLE_IS_SCM;
	} else {
		info->type = SVC_HANDLE_IS_SERVICE;
		
		if ( !(info->name  = SMB_STRDUP( service )) ) {
			free_service_handle_info( info );
			WERR_NOMEM;
		}
		
#if 0
		/* lookup the SERVICE_CONTROL_OPS */

		for ( i=0; svcctl_ops[i].name; i++ ) {
			;;
		}
#endif
	}

	/* store the SERVICE_INFO and create an open handle */
	
	if ( !create_policy_hnd( p, handle, free_service_handle_info, info ) ) {
		free_service_handle_info( info );
		return WERR_ACCESS_DENIED;
	}
		
	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_open_scmanager(pipes_struct *p, SVCCTL_Q_OPEN_SCMANAGER *q_u, SVCCTL_R_OPEN_SCMANAGER *r_u)
{
	/* perform access checks */
	

	/* open the handle and return */
	
	return create_open_service_handle( p, &r_u->handle, NULL );

}

/********************************************************************
********************************************************************/

WERROR _svcctl_open_service(pipes_struct *p, SVCCTL_Q_OPEN_SERVICE *q_u, SVCCTL_R_OPEN_SERVICE *r_u)
{
	pstring service;

	rpcstr_pull(service, q_u->servicename.buffer, sizeof(service), q_u->servicename.uni_str_len*2, 0);
	
  	DEBUG(5, ("_svcctl_open_service: Attempting to open Service [%s], \n", service));
	
	if ( !service_tdb ) {
		DEBUG(1, ("_svcctl_open_service: service database is not open\n!"));
		return WERR_ACCESS_DENIED;
	}
	
	/* check the access granted on the SCM handle */
	
	/* check the access requested on this service */
	
       
#if 0	/* FIXME!!! */
	if ( ! read_service_tdb_to_si(service_tdb,service, info) ) {
		return WERR_NO_SUCH_SERVICE;
#endif
	
	return create_open_service_handle( p, &r_u->handle, service );
}

/********************************************************************
********************************************************************/

WERROR _svcctl_close_service(pipes_struct *p, SVCCTL_Q_CLOSE_SERVICE *q_u, SVCCTL_R_CLOSE_SERVICE *r_u)
{
	return close_policy_hnd( p, &q_u->handle ) ? WERR_OK : WERR_BADFID;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_get_display_name(pipes_struct *p, SVCCTL_Q_GET_DISPLAY_NAME *q_u, SVCCTL_R_GET_DISPLAY_NAME *r_u)
{
	fstring service;
	fstring displayname;

	SERVICE_INFO *service_info;
	POLICY_HND *handle;

	rpcstr_pull(service, q_u->servicename.buffer, sizeof(service), q_u->servicename.uni_str_len*2, 0);

	handle = &(q_u->handle);

	service_info = find_service_info_by_hnd(p, handle);

	if (!service_info) {
 		DEBUG(10, ("_svcctl_get_display_name : Can't find the service for the handle\n"));
		return WERR_ACCESS_DENIED;
	}

	DEBUG(10,("_svcctl_get_display_name: Found service [%s]\n", service_info->name ));

	fstrcpy( displayname, "FIX ME!" );

	init_svcctl_r_get_display_name( r_u, displayname );

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_query_status(pipes_struct *p, SVCCTL_Q_QUERY_STATUS *q_u, SVCCTL_R_QUERY_STATUS *r_u)
{
	r_u->svc_status.type = 0x0020;
	r_u->svc_status.state = 0x0004;
	r_u->svc_status.controls_accepted = 0x0005;

	return WERR_OK;
}

/* allocate an array of external services and return them. Null return is okay, make sure &added is also zero! */

int _svcctl_num_external_services(void)
{
	int num_services;
	char **svc_list;
	pstring keystring, external_services_string;
	TDB_DATA key_data;


	if (!service_tdb) {
		DEBUG(8,("enum_external_services: service database is not open!!!\n"));
		num_services = 0;
	} else {
		pstrcpy(keystring,"EXTERNAL_SERVICES");
		tdb_lock_bystring(service_tdb, keystring, 0);
		key_data = tdb_fetch_bystring(service_tdb, keystring);

		if ((key_data.dptr != NULL) && (key_data.dsize != 0)) {
			strncpy(external_services_string,key_data.dptr,key_data.dsize);
			external_services_string[key_data.dsize] = 0;
			DEBUG(8,("enum_external_services: services list is %s, size is %d\n",external_services_string,key_data.dsize));
		}
		tdb_unlock_bystring(service_tdb, keystring);
	} 
	svc_list = str_list_make(external_services_string,NULL);
 
	num_services = str_list_count( (const char **)svc_list);

	return num_services;
}



/********************************************************************
  Gather information on the "external services". These are services 
  listed in the smb.conf file, and found to exist through checks in 
  this code. Note that added will be incremented on the basis of the 
  number of services added.  svc_ptr should have enough memory allocated 
  to accommodate all of the services that exist. 

  Typically _svcctl_num_external_services is used to "size" the amount of
  memory allocated, but does little/no work. 

  enum_external_services() actually examines each of the specified 
  external services, populates the memory structures, and returns.

  ** note that 'added' may end up with less than the number of services 
  found in _num_external_services, such as the case when a service is
  called out, but the actual service doesn't exist or the file can't be 
  read for the service information.
********************************************************************/

WERROR enum_external_services(TALLOC_CTX *tcx,ENUM_SERVICES_STATUS **svc_ptr, int existing_services,int *added) 
{
	/* *svc_ptr must have pre-allocated memory */
	int num_services = 0;
	int i = 0;
	ENUM_SERVICES_STATUS *services=NULL;
	char **svc_list,**svcname;
	pstring command, keystring, external_services_string;
	int ret;
	int fd = -1;
	Service_info *si;
	TDB_DATA key_data;

	*added = num_services;

	if (!service_tdb) {
		DEBUG(8,("enum_external_services: service database is not open!!!\n"));
	} else {
		pstrcpy(keystring,"EXTERNAL_SERVICES");
		tdb_lock_bystring(service_tdb, keystring, 0);
		key_data = tdb_fetch_bystring(service_tdb, keystring);
		if ((key_data.dptr != NULL) && (key_data.dsize != 0)) {
			strncpy(external_services_string,key_data.dptr,key_data.dsize);
			external_services_string[key_data.dsize] = 0;
			DEBUG(8,("enum_external_services: services list is %s, size is %d\n",external_services_string,key_data.dsize));
		}
		tdb_unlock_bystring(service_tdb, keystring);
	} 
	svc_list = str_list_make(external_services_string,NULL);
 
	num_services = str_list_count( (const char **)svc_list);

	if (0 == num_services) {
		DEBUG(8,("enum_external_services: there are no external services\n"));
		*added = num_services;
		return WERR_OK;
	}
	DEBUG(8,("enum_external_services: there are [%d] external services\n",num_services));
	si=TALLOC_ARRAY( tcx, Service_info, 1 );
	if (si == NULL) { 
		DEBUG(8,("enum_external_services: Failed to alloc si\n"));
		return WERR_NOMEM;
	}

#if 0
/* *svc_ptr has the pointer to the array if there is one already. NULL if not. */
	if ((existing_services>0) && svc_ptr && *svc_ptr) { /* reallocate vs. allocate */
		DEBUG(8,("enum_external_services: REALLOCing %x to %d services\n", *svc_ptr, existing_services+num_services));

		services=TALLOC_REALLOC_ARRAY(tcx,*svc_ptr,ENUM_SERVICES_STATUS,existing_services+num_services);
		DEBUG(8,("enum_external_services: REALLOCed to %x services\n", services));

		if (!services) return WERR_NOMEM;
			*svc_ptr = services;
	} else {
		if ( !(services = TALLOC_ARRAY( tcx, ENUM_SERVICES_STATUS, num_services )) )
			return WERR_NOMEM;
	}
#endif

	if (!svc_ptr || !(*svc_ptr)) 
		return WERR_NOMEM;
	services = *svc_ptr;
	if (existing_services > 0) {
		i+=existing_services;
	}

	svcname = svc_list;
	DEBUG(8,("enum_external_services: enumerating %d external services starting at index %d\n", num_services,existing_services));

	while (*svcname) {
		DEBUG(10,("enum_external_services: Reading information on service %s, index %d\n",*svcname,i));
		/* _svcctl_get_LSB_data(*svcname,si);  */
		if (!read_service_tdb_to_si(service_tdb,*svcname, si)) {
			DEBUG(1,("enum_external_services: CAN'T FIND INFO FOR SERVICE %s in the services DB\n",*svcname));
		}

		if ((si->filename == NULL) || (*si->filename == 0)) {
			init_unistr(&services[i].servicename, *svcname );
		} else {
			init_unistr( &services[i].servicename, si->filename );    
			/* init_unistr( &services[i].servicename, si->servicename ); */
		}

		if ((si->provides == NULL) || (*si->provides == 0)) {
			init_unistr(&services[i].displayname, *svcname );
		} else {
			init_unistr( &services[i].displayname, si->provides );
		}

		/* TODO - we could keep the following info in the DB, too... */

		DEBUG(8,("enum_external_services: Service name [%s] displayname [%s]\n",
		si->filename, si->provides)); 
		services[i].status.type               = SVCCTL_WIN32_OWN_PROC; 
		services[i].status.win32_exit_code    = 0x0;
		services[i].status.service_exit_code  = 0x0;
		services[i].status.check_point        = 0x0;
		services[i].status.wait_hint          = 0x0;

		/* TODO - do callout here to get the status */

		memset(command, 0, sizeof(command));
		slprintf(command, sizeof(command)-1, "%s%s%s %s", dyn_LIBDIR, SVCCTL_SCRIPT_DIR, *svcname, "status");

		DEBUG(10, ("enum_external_services: status command is [%s]\n", command));

		/* TODO  - wrap in privilege check */

		ret = smbrun(command, &fd);
		DEBUGADD(10, ("returned [%d]\n", ret));
		close(fd);
		if(ret != 0)
			DEBUG(10, ("enum_external_services: Command returned  [%d]\n", ret));
		services[i].status.state              = SVCCTL_STOPPED;
		if (ret == 0) {
			services[i].status.state              = SVCCTL_RUNNING;
			services[i].status.controls_accepted  = SVCCTL_CONTROL_SHUTDOWN | SVCCTL_CONTROL_STOP;
		} else {
			services[i].status.state              = SVCCTL_STOPPED;
			services[i].status.controls_accepted  = 0;
		}
		svcname++; 
		i++;
	} 

	DEBUG(10,("enum_external_services: Read services %d\n",num_services));
	*added = num_services;

	return WERR_OK;
}

int _svcctl_num_internal_services(void)
{
	int num_services;
	char **svc_list;
	pstring keystring, internal_services_string;
	TDB_DATA key_data;

	if (!service_tdb) {
		DEBUG(8,("_svcctl_enum_internal_services: service database is not open!!!\n"));
		num_services = 0;
	} else {
		pstrcpy(keystring,"INTERNAL_SERVICES");
		tdb_lock_bystring(service_tdb, keystring, 0);
		key_data = tdb_fetch_bystring(service_tdb, keystring);

		if ((key_data.dptr != NULL) && (key_data.dsize != 0)) {
			strncpy(internal_services_string,key_data.dptr,key_data.dsize);
			internal_services_string[key_data.dsize] = 0;
			DEBUG(8,("_svcctl_enum_internal_services: services list is %s, size is %d\n",internal_services_string,key_data.dsize));
		}
		tdb_unlock_bystring(service_tdb, keystring);
	} 
	svc_list = str_list_make(internal_services_string,NULL);
 
	num_services = str_list_count( (const char **)svc_list);

	return num_services;
}

#if 0

int _svcctl_num_internal_services(void)
{
	return 2;
}
#endif

/* TODO - for internal services, do similar to external services, except we have to call the right status routine... */

WERROR _svcctl_enum_internal_services(TALLOC_CTX *tcx,ENUM_SERVICES_STATUS **svc_ptr, int existing_services, int *added) 
{
	int num_services = 2;
	int i = 0;
	ENUM_SERVICES_STATUS *services=NULL;

	if (!svc_ptr || !(*svc_ptr)) 
		return WERR_NOMEM;

	services = *svc_ptr;

#if 0
	/* *svc_ptr has the pointer to the array if there is one already. NULL if not. */
	if ((existing_services>0) && svc_ptr && *svc_ptr) { /* reallocate vs. allocate */
		DEBUG(8,("_svcctl_enum_internal_services: REALLOCing %d services\n", num_services));
		services = TALLOC_REALLOC_ARRAY(tcx,*svc_ptr,ENUM_SERVICES_STATUS,existing_services+num_services);
		if (!rsvcs) 
			return WERR_NOMEM;
		*svc_ptr = services;
	} else {
		if ( !(services = TALLOC_ARRAY( tcx, ENUM_SERVICES_STATUS, num_services )) )
			return WERR_NOMEM;
	}
#endif

	if (existing_services > 0) {
		i += existing_services;
	}
	DEBUG(8,("_svcctl_enum_internal_services: Creating %d services, starting index %d\n", num_services,existing_services));
				
	init_unistr( &services[i].servicename, "Spooler" );
	init_unistr( &services[i].displayname, "Print Spooler" );
	
	services[i].status.type               = 0x110;
	services[i].status.controls_accepted  = 0x0;
	services[i].status.win32_exit_code    = 0x0;
	services[i].status.service_exit_code  = 0x0;
	services[i].status.check_point        = 0x0;
	services[i].status.wait_hint          = 0x0;
	if ( !lp_disable_spoolss() ) 
		services[i].status.state              = SVCCTL_RUNNING;
	else
		services[i].status.state              = SVCCTL_STOPPED;

	i++;		
	
	init_unistr( &services[i].servicename, "NETLOGON" );
	init_unistr( &services[i].displayname, "Net Logon" );
	
	services[i].status.type               = 0x20;	
	services[i].status.controls_accepted  = 0x0;
	services[i].status.win32_exit_code    = 0x0;
	services[i].status.service_exit_code  = 0x0;
	services[i].status.check_point        = 0x0;
	services[i].status.wait_hint          = 0x0;
	if ( lp_servicenumber("NETLOGON") != -1 ) 
		services[i].status.state              = SVCCTL_RUNNING;
	else
		services[i].status.state              = SVCCTL_STOPPED;

	*added = num_services;

	return WERR_OK;
}

WERROR _init_svcdb(void) 
{
	if (svcdb) {
		talloc_destroy(svcdb);
	}
	svcdb = talloc_init("services DB");

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_enum_services_status(pipes_struct *p, SVCCTL_Q_ENUM_SERVICES_STATUS *q_u, SVCCTL_R_ENUM_SERVICES_STATUS *r_u)
{
	ENUM_SERVICES_STATUS *services = NULL;
 
	uint32 num_int_services = 0;
	uint32 num_ext_services = 0;
	int i = 0;
	size_t buffer_size;
	WERROR result = WERR_OK;
	WERROR ext_result = WERR_OK;		

	/* num_services = str_list_count( lp_enable_svcctl() ); */

	/* here's where we'll read the db of external services */
	/* _svcctl_read_LSB_data(NULL,NULL); */
	/* init_svcctl_db(); */
	
	num_int_services = 0;

	num_int_services = _svcctl_num_internal_services();

	num_ext_services =  _svcctl_num_external_services();

	if ( !(services = TALLOC_ARRAY(p->mem_ctx, ENUM_SERVICES_STATUS, num_int_services+num_ext_services )) )
          return WERR_NOMEM;

        result = _svcctl_enum_internal_services(p->mem_ctx, &services, 0, &num_int_services);

	if (W_ERROR_IS_OK(result)) {
		DEBUG(8,("_svcctl_enum_services_status: Got %d internal services\n", num_int_services));
	} 

	ext_result=enum_external_services(p->mem_ctx, &services, num_int_services, &num_ext_services);

	if (W_ERROR_IS_OK(ext_result)) {
		DEBUG(8,("_svcctl_enum_services_status: Got %d external services\n", num_ext_services));
	} 

        DEBUG(8,("_svcctl_enum_services_status: total of %d services\n", num_int_services+num_ext_services));

	buffer_size = 0;
        for (i=0;i<num_int_services+num_ext_services;i++) {
	  buffer_size += svcctl_sizeof_enum_services_status(&services[i]);
	}

	/* */
	buffer_size += buffer_size % 4;
	DEBUG(8,("_svcctl_enum_services_status: buffer size passed %d, we need %d\n",
		 q_u->buffer_size, buffer_size));

	if (buffer_size > q_u->buffer_size ) {
		num_int_services = 0;
		num_ext_services = 0;
		result = WERR_MORE_DATA;
	}

	rpcbuf_init(&r_u->buffer, q_u->buffer_size, p->mem_ctx);

	if ( W_ERROR_IS_OK(result) ) {
		for ( i=0; i<num_int_services+num_ext_services; i++ )
			svcctl_io_enum_services_status( "", &services[i], &r_u->buffer, 0 );
	}

	r_u->needed      = (buffer_size > q_u->buffer_size) ? buffer_size : q_u->buffer_size;
	r_u->returned    = num_int_services+num_ext_services;

	if ( !(r_u->resume = TALLOC_P( p->mem_ctx, uint32 )) )
		return WERR_NOMEM;

	*r_u->resume = 0x0;

	return result;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_start_service(pipes_struct *p, SVCCTL_Q_START_SERVICE *q_u, SVCCTL_R_START_SERVICE *r_u)
{
	return WERR_ACCESS_DENIED;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_control_service(pipes_struct *p, SVCCTL_Q_CONTROL_SERVICE *q_u, SVCCTL_R_CONTROL_SERVICE *r_u)
{
#if 0
	SERVICE_INFO *service_info;
	POLICY_HND   *handle;
	pstring      command;
	SERVICE_STATUS *service_status;
	int          ret,fd;

	/* need to find the service name by the handle that is open */
	handle = &(q_u->handle);

	service_info = find_service_info_by_hnd(p, handle);

	if (!service_info) {
 		DEBUG(10, ("_svcctl_control_service : Can't find the service for the handle\n"));
		return WERR_BADFID; 
	}

	/* we return a SERVICE_STATUS structure if there's an error. */
	if ( !(service_status = TALLOC_ARRAY(p->mem_ctx, SERVICE_STATUS, 1 ))  )
		return WERR_NOMEM;

	DEBUG(10, ("_svcctl_control_service: Found service [%s], [%s]\n",
		service_info->servicename, service_info->filename));

	/* TODO  - call the service config function here... */
	memset(command, 0, sizeof(command));
	if (q_u->control == SVCCTL_CONTROL_STOP) {
		slprintf(command, sizeof(command)-1, "%s%s%s %s", dyn_LIBDIR, SVCCTL_SCRIPT_DIR,
			service_info->filename, "stop");
	}

	if (q_u->control == SVCCTL_CONTROL_PAUSE) {
		slprintf(command, sizeof(command)-1, "%s%s%s %s", dyn_LIBDIR, SVCCTL_SCRIPT_DIR,
			service_info->filename, "stop");
	}

	if (q_u->control == SVCCTL_CONTROL_CONTINUE) {
		slprintf(command, sizeof(command)-1, "%s%s%s %s", dyn_LIBDIR, SVCCTL_SCRIPT_DIR,
			service_info->filename, "restart");
	}

        DEBUG(10, ("_svcctl_control_service: status command is [%s]\n", command));

	/* TODO  - wrap in privilege check */

	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));
        close(fd);

	if(ret != 0)
        	DEBUG(10, ("enum_external_services: Command returned  [%d]\n", ret));

	/* SET all service_stats bits here...*/
	if (ret == 0) {
		service_status->state              = SVCCTL_RUNNING;
	  	service_status->controls_accepted  = SVCCTL_CONTROL_SHUTDOWN | SVCCTL_CONTROL_STOP;
	} else {
		service_status->state              = SVCCTL_STOPPED;
 	 	service_status->controls_accepted  = 0;
	}

	DEBUG(10, ("_svcctl_query_service_config: Should call the commFound service [%s], [%s]\n",service_info->servicename,service_info->filename));

#endif

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_enum_dependent_services( pipes_struct *p, SVCCTL_Q_ENUM_DEPENDENT_SERVICES *q_u, SVCCTL_R_ENUM_DEPENDENT_SERVICES *r_u )
{
	
	/* we have to set the outgoing buffer size to the same as the 
	   incoming buffer size (even in the case of failure */

	rpcbuf_init( &r_u->buffer, q_u->buffer_size, p->mem_ctx );
				
	r_u->needed      = q_u->buffer_size;
	
	/* no dependent services...basically a stub function */
	r_u->returned    = 0;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_query_service_status_ex( pipes_struct *p, SVCCTL_Q_QUERY_SERVICE_STATUSEX *q_u, SVCCTL_R_QUERY_SERVICE_STATUSEX *r_u )
{
        SERVICE_STATUS_PROCESS ssp;
	POLICY_HND *handle;
	SERVICE_INFO *service_info;
	pstring     command;

	/* we have to set the outgoing buffer size to the same as the 
	   incoming buffer size (even in the case of failure */

	r_u->needed      = q_u->buffer_size;

        /* need to find the service name by the handle that is open */
	handle = &(q_u->handle);


	/* get rid of the easy errors */

	if (q_u->info_level != SVC_STATUS_PROCESS_INFO) {
 		DEBUG(10, ("_svcctl_query_service_status_ex :  Invalid information level specified\n"));
		return WERR_UNKNOWN_LEVEL; 
	}

	service_info = find_service_info_by_hnd(p, handle);

	if (!service_info) {
 		DEBUG(10, ("_svcctl_query_service_status_ex : Can't find the service for the handle\n"));
		return WERR_BADFID; 
	}
	
	if (r_u->needed < (sizeof(SERVICE_STATUS_PROCESS)+sizeof(uint32)+sizeof(uint32))) {
 		DEBUG(10, ("_svcctl_query_service_status_ex : buffer size of [%d] is too small.\n",r_u->needed));
		return WERR_INSUFFICIENT_BUFFER;
	}

  	ZERO_STRUCT(ssp); 
	    
#if 0
        if (!strwicmp(service_info->servicetype,"EXTERNAL")) 
		ssp.type = SVCCTL_WIN32_OWN_PROC;
	else 
		ssp.type = SVCCTL_WIN32_SHARED_PROC;
#endif

	/* Get the status of the service.. */

        memset(command, 0, sizeof(command));

#if 0
	slprintf(command, sizeof(command)-1, "%s%s%s %s", dyn_LIBDIR, SVCCTL_SCRIPT_DIR, service_info->filename, "status");

        DEBUG(10, ("_svcctl_query_service_status_ex: status command is [%s]\n", command));

	/* TODO  - wrap in privilege check */

	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));
        close(fd);
	if(ret != 0)
		DEBUG(10, ("_svcctl_query_service_status_ex: Command returned  [%d]\n", ret));

	/* SET all service_stats bits here... */
	if (ret == 0) {
		ssp.state              = SVCCTL_RUNNING;
		ssp.controls_accepted  = SVCCTL_CONTROL_SHUTDOWN | SVCCTL_CONTROL_STOP;
	} else {
		ssp.state              = SVCCTL_STOPPED;
		ssp.controls_accepted  = 0;
	}
#endif

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_query_service_config( pipes_struct *p, SVCCTL_Q_QUERY_SERVICE_CONFIG *q_u, SVCCTL_R_QUERY_SERVICE_CONFIG *r_u )
{
	POLICY_HND *handle;
	SERVICE_INFO *service_info;
        uint32      needed_size;

	/* we have to set the outgoing buffer size to the same as the 
	   incoming buffer size (even in the case of failure */

	r_u->needed      = q_u->buffer_size;

        /* need to find the service name by the handle that is open */
	handle = &(q_u->handle);

	service_info = find_service_info_by_hnd(p, handle);

#if 0
	if (q_u->buffer_size < sizeof(Service_info)) {
		/* have to report need more... */
		/* TODO worst case -- should actualy calc what we need here. */
		r_u->needed = sizeof(Service_info)+sizeof(pstring)*5; 
		DEBUG(10, ("_svcctl_query_service_config: NOT ENOUGH BUFFER ALLOCATED FOR RETURN DATA -- provided %d wanted %d\n",
		q_u->buffer_size,r_u->needed));

		return WERR_INSUFFICIENT_BUFFER;
	}
#endif
	if (!service_info) {
 		DEBUG(10, ("_svcctl_query_service_config : Can't find the service for the handle\n"));
		return WERR_BADFID; 
	}

#if 0
	if ( !(service_config = (SERVICE_CONFIG *)TALLOC_ZERO_P(p->mem_ctx, SERVICE_CONFIG)) )
        	return WERR_NOMEM;
#endif

	r_u->config.service_type       = SVCCTL_WIN32_OWN_PROC;
	r_u->config.start_type         = SVCCTL_DEMAND_START;
	r_u->config.error_control      = SVCCTL_SVC_ERROR_IGNORE;
	r_u->config.tag_id = 0x00000000;

	/* Init the strings */

	r_u->config.executablepath = TALLOC_ZERO_P(p->mem_ctx,  UNISTR2);
	r_u->config.loadordergroup = TALLOC_ZERO_P(p->mem_ctx,  UNISTR2);
	r_u->config.dependencies = TALLOC_ZERO_P(p->mem_ctx,  UNISTR2);
	r_u->config.startname = TALLOC_ZERO_P(p->mem_ctx,  UNISTR2);
	r_u->config.displayname = TALLOC_ZERO_P(p->mem_ctx,  UNISTR2);

#if 0
	pstrcpy(fullpathinfo,dyn_LIBDIR);
	pstrcat(fullpathinfo,SVCCTL_SCRIPT_DIR);
	pstrcat(fullpathinfo,service_info->filename);
	/* Get and calculate the size of the fields. Note that we're still building the fields in the "too-small buffer case"
	   even though we throw it away. */
	
	DEBUG(10, ("_svcctl_query_service_config: fullpath info [%s]\n",fullpathinfo));
	init_unistr2(r_u->config.executablepath,fullpathinfo,UNI_STR_TERMINATE);
	init_unistr2(r_u->config.loadordergroup,"",UNI_STR_TERMINATE);
	init_unistr2(r_u->config.dependencies,service_info->dependencies,UNI_STR_TERMINATE);

	/* TODO - if someone really cares, perhaps "LocalSystem" should be changed to something else here... */

	init_unistr2(r_u->config.startname,"LocalSystem",UNI_STR_TERMINATE);
	init_unistr2(r_u->config.displayname,service_info->servicename,UNI_STR_TERMINATE);
#endif

	needed_size = 0x04 + sizeof(SERVICE_CONFIG)+ 2*(
	              r_u->config.executablepath->uni_str_len +
	              r_u->config.loadordergroup->uni_str_len + 
	              r_u->config.dependencies->uni_str_len + 
                      r_u->config.startname->uni_str_len + 
                      r_u->config.displayname->uni_str_len);
	
       	DEBUG(10, ("_svcctl_query_service_config: ****** need to have a buffer of [%d], [%d] for struct \n",needed_size,
		   sizeof(SERVICE_CONFIG)));
	DEBUG(10, ("\tsize of executable path : %d\n",r_u->config.executablepath->uni_str_len));
	DEBUG(10, ("\tsize of loadordergroup  : %d\n", r_u->config.loadordergroup->uni_str_len)); 
	DEBUG(10, ("\tsize of dependencies    : %d\n", r_u->config.dependencies->uni_str_len)); 
	DEBUG(10, ("\tsize of startname       : %d\n", r_u->config.startname->uni_str_len));
	DEBUG(10, ("\tsize of displayname     : %d\n", r_u->config.displayname->uni_str_len));

	if (q_u->buffer_size < needed_size) {
		/* have to report need more...*/
		r_u->needed = needed_size;
       		DEBUG(10, ("_svcctl_query_service_config: ****** zeroing strings for return\n"));
		memset(&r_u->config,0,sizeof(SERVICE_CONFIG));
		DEBUG(10, ("_svcctl_query_service_config: Not enouh buffer provided for return -- provided %d wanted %d\n",
			q_u->buffer_size,needed_size));
		return WERR_INSUFFICIENT_BUFFER;
	}

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _svcctl_query_service_config2( pipes_struct *p, SVCCTL_Q_QUERY_SERVICE_CONFIG2 *q_u, SVCCTL_R_QUERY_SERVICE_CONFIG2 *r_u )
{
	POLICY_HND *handle;
	SERVICE_INFO *service_info;
        uint32   level;
 
	/* we have to set the outgoing buffer size to the same as the 
	   incoming buffer size (even in the case of failure */

	r_u->needed      = q_u->buffer_size;
	r_u->description = NULL;               
	r_u->returned = q_u->buffer_size;
	r_u->offset = 4;                       

	handle = &(q_u->handle);

	service_info = find_service_info_by_hnd(p, handle);

	if (!service_info) {
 		DEBUG(10, ("_svcctl_query_service_config2 : Can't find the service for the handle\n"));
		return WERR_BADFID; 
	}
	
	/* 
	   TODO - perhaps move the RPC_DATA_BLOB into the R_QUERY_SERVICE_CONFIG structure, and to the processing in here, vs
           in the *r_query_config2 marshalling routine...
	*/

	level = q_u->info_level;

#if 0
	if (SERVICE_CONFIG_DESCRIPTION == level) {
		if (service_info && service_info->shortdescription) {
			/* length of the string, plus the terminator... */
			string_buffer_size = strlen(service_info->shortdescription)+1; 
			DEBUG(10, ("_svcctl_query_service_config: copying the description [%s] length [%d]\n",
			service_info->shortdescription,string_buffer_size));
	    
			if (q_u->buffer_size >= ((string_buffer_size)*2+4)) {
				r_u->description = TALLOC_ZERO_P(p->mem_ctx,  UNISTR2);
				if (!r_u->description) return WERR_NOMEM;
					init_unistr2(r_u->description,service_info->shortdescription,UNI_STR_TERMINATE);
			}
		}
		else { 
			string_buffer_size = 0;
		}
		DEBUG(10, ("_svcctl_query_service_config2: buffer needed is [%x], return buffer size is [%x]\n",
			string_buffer_size,q_u->buffer_size));
		if (((string_buffer_size)*2+4) > q_u->buffer_size) {
			r_u->needed = (string_buffer_size+1)*2+4;
			DEBUG(10, ("_svcctl_query_service_config2: INSUFFICIENT BUFFER\n"));
			return WERR_INSUFFICIENT_BUFFER;
		}
		DEBUG(10, ("_svcctl_query_service_config2: returning ok, needed is [%x], buffer size is [%x]\n",
		r_u->needed,q_u->buffer_size));

	   	return WERR_OK;    
	} 
#endif

	return WERR_ACCESS_DENIED;
}
