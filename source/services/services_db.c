/* 
 *  Unix SMB/CIFS implementation.
 *  Service Control API Implementation
 *  Copyright (C) Gerald Carter                   2005.
 *  Copyright (C) Marcin Krzysztof Porwit         2005.
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

#if 0

/* backend database routines for services.tdb */

#define SERVICEDB_VERSION_V1 1 /* Will there be more? */
#define INTERNAL_SERVICES_LIST "NETLOGON Spooler"

/*                                                                                                                     */
/* scripts will execute from the following libdir, if they are in the enable svcctl=<list of scripts>                  */
/* these should likely be symbolic links. Note that information about them will be extracted from the files themselves */
/* using the LSB standard keynames for various information                                                             */

#define SCVCTL_DATABASE_VERSION_V1 1
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
 allocate an array of external services and return them. Null return 
 is okay, make sure &added is also zero! 
********************************************************************/

int num_external_services(void)
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
		key_data = tdb_fetch_bystring(service_tdb, keystring);

		if ((key_data.dptr != NULL) && (key_data.dsize != 0)) {
			strncpy(external_services_string,key_data.dptr,key_data.dsize);
			external_services_string[key_data.dsize] = 0;
			DEBUG(8,("enum_external_services: services list is %s, size is %d\n",external_services_string,key_data.dsize));
		}
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

  Typically num_external_services is used to "size" the amount of
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
		key_data = tdb_fetch_bystring(service_tdb, keystring);
		if ((key_data.dptr != NULL) && (key_data.dsize != 0)) {
			strncpy(external_services_string,key_data.dptr,key_data.dsize);
			external_services_string[key_data.dsize] = 0;
			DEBUG(8,("enum_external_services: services list is %s, size is %d\n",external_services_string,key_data.dsize));
		}
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
		/* get_LSB_data(*svcname,si);  */
		if (!get_service_info(service_tdb,*svcname, si)) {
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

/********************************************************************
********************************************************************/

int num_internal_services(void)
{
	int num_services;
	char **svc_list;
	pstring keystring, internal_services_string;
	TDB_DATA key_data;

	if (!service_tdb) {
		DEBUG(8,("enum_internal_services: service database is not open!!!\n"));
		num_services = 0;
	} else {
		pstrcpy(keystring,"INTERNAL_SERVICES");
		key_data = tdb_fetch_bystring(service_tdb, keystring);

		if ((key_data.dptr != NULL) && (key_data.dsize != 0)) {
			strncpy(internal_services_string,key_data.dptr,key_data.dsize);
			internal_services_string[key_data.dsize] = 0;
			DEBUG(8,("enum_internal_services: services list is %s, size is %d\n",internal_services_string,key_data.dsize));
		}
	} 
	svc_list = str_list_make(internal_services_string,NULL);
 
	num_services = str_list_count( (const char **)svc_list);

	return num_services;
}

#if 0 
/*********************************************************************
 given a service nice name, find the underlying service name
*********************************************************************/

static BOOL convert_service_displayname(TDB_CONTEXT *stdb,pstring service_nicename, pstring servicename,int szsvcname) 
{
	pstring keystring;
	TDB_DATA key_data;

	if ((stdb == NULL) || (service_nicename==NULL) || (servicename == NULL)) 
		return False;

	pstr_sprintf(keystring,"SERVICE_NICENAME/%s", servicename);

	DEBUG(5, ("convert_service_displayname: Looking for service name [%s], key [%s]\n", 
		service_nicename, keystring));

	key_data = tdb_fetch_bystring(stdb,keystring);

	if (key_data.dsize == 0) {
		DEBUG(5, ("convert_service_displayname: [%s] Not found, tried key [%s]\n",service_nicename,keystring));
		return False; 
	}

	strncpy(servicename,key_data.dptr,szsvcname);
	servicename[(key_data.dsize > szsvcname ? szsvcname : key_data.dsize)] = 0;
	DEBUG(5, ("convert_service_displayname: Found service name [%s], name is  [%s]\n",
		service_nicename,servicename));

	return True;
}
#endif

/*******************************************************************************
 Get the INTERNAL services information for the given service name. 
*******************************************************************************/

static BOOL get_internal_service_data(const Internal_service_description *isd, Service_info *si)
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

/********************************************************************
********************************************************************/

BOOL get_service_info(TDB_CONTEXT *stdb,char *service_name, Service_info *si) 
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

/*********************************************************************
*********************************************************************/

BOOL store_service_info(TDB_CONTEXT *stdb,char *service_name, Service_info *si) 
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
	if (si->shortdescription && *si->shortdescription) 
		tdb_store_bystring(stdb,keystring,string_tdb_data(si->shortdescription),TDB_REPLACE);
	else
	      	tdb_store_bystring(stdb,keystring,string_tdb_data(si->description),TDB_REPLACE);

	return True;
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
		if (get_LSB_data(*svcname,&si));{
			/* write the information to the TDB */
			store_service_info(service_tdb,*svcname,&si);
			/* definitely not efficient to do it this way. */
			pstrcat(external_service_list,"\"");
			pstrcat(external_service_list,*svcname);
			pstrcat(external_service_list,"\" ");
		}
		svcname++;
	}
	pstrcpy(keystring,"EXTERNAL_SERVICES");
	DEBUG(8,("Storing external service list [%s]\n",external_service_list));
        tdb_store_bystring(service_tdb,keystring,string_tdb_data(external_service_list),TDB_REPLACE);

	/* Get the INTERNAL services */
	
	pstrcpy(internal_service_list,"");
	isd_ptr = ISD; 

	while (isd_ptr && (isd_ptr->filename)) {
		DEBUG(10,("Reading information on service %s\n",isd_ptr->filename));
		if (get_internal_service_data(isd_ptr,&si)){
			/* write the information to the TDB */
			store_service_info(service_tdb,(char *)isd_ptr->filename,&si);
			/* definitely not efficient to do it this way. */
			pstrcat(internal_service_list,"\"");
			pstrcat(internal_service_list,isd_ptr->filename);
			pstrcat(internal_service_list,"\" ");

		}
		isd_ptr++;
	}
	pstrcpy(keystring,"INTERNAL_SERVICES");
	DEBUG(8,("Storing internal service list [%s]\n",internal_service_list));
        tdb_store_bystring(service_tdb,keystring,string_tdb_data(internal_service_list),TDB_REPLACE);

	return True;
}
#endif
