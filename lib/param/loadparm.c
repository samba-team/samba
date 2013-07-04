/* 
   Unix SMB/CIFS implementation.
   Parameter loading functions
   Copyright (C) Karl Auer 1993-1998

   Largely re-written by Andrew Tridgell, September 1994

   Copyright (C) Simo Sorce 2001
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) Stefan (metze) Metzmacher 2002
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   Copyright (C) Andrew Bartlett 2011-2012

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Load parameters.
 *
 *  This module provides suitable callback functions for the params
 *  module. It builds the internal table of service details which is
 *  then used by the rest of the server.
 *
 * To add a parameter:
 *
 * 1) add it to the global or service structure definition
 * 2) add it to the parm_table
 * 3) add it to the list of available functions (eg: using FN_GLOBAL_STRING())
 * 4) If it's a global then initialise it in init_globals. If a local
 *    (ie. service) parameter then initialise it in the sDefault structure
 *
 *
 * Notes:
 *   The configuration file is processed sequentially for speed. It is NOT
 *   accessed randomly as happens in 'real' Windows. For this reason, there
 *   is a fair bit of sequence-dependent code here - ie., code which assumes
 *   that certain things happen before others. In particular, the code which
 *   happens at the boundary between sections is delicately poised, so be
 *   careful!
 *
 */

#include "includes.h"
#include "version.h"
#include "dynconfig/dynconfig.h"
#include "system/time.h"
#include "system/locale.h"
#include "system/network.h" /* needed for TCP_NODELAY */
#include "../lib/util/dlinklist.h"
#include "lib/param/param.h"
#include "lib/param/loadparm.h"
#include "auth/gensec/gensec.h"
#include "lib/param/s3_param.h"
#include "lib/util/bitmap.h"
#include "libcli/smb/smb_constants.h"

#define standard_sub_basic talloc_strdup

static bool do_parameter(const char *, const char *, void *);
static bool defaults_saved = false;

#define LOADPARM_EXTRA_GLOBALS \
	struct parmlist_entry *param_opt;				\
	char *szRealm;							\
	char *szConfigFile;						\
	int iminreceivefile;						\
	char *szPrintcapname;						\
	int CupsEncrypt;						\
	int  iPreferredMaster;						\
	char *szLdapMachineSuffix;					\
	char *szLdapUserSuffix;						\
	char *szLdapIdmapSuffix;					\
	char *szLdapGroupSuffix;					\
	char *szUsershareTemplateShare;					\
	char *szIdmapUID;						\
	char *szIdmapGID;						\
	int winbindMaxDomainConnections;				\
	int ismb2_max_credits;						\
	char *tls_keyfile;						\
	char *tls_certfile;						\
	char *tls_cafile;						\
	char *tls_crlfile;						\
	char *tls_dhpfile;						\
	char *loglevel;							\
	char *panic_action;						

#include "lib/param/param_global.h"

#define NUMPARAMETERS (sizeof(parm_table) / sizeof(struct parm_struct))

/* we don't need a special handler for "dos charset" and "unix charset" */
#define handle_dos_charset NULL
#define handle_charset NULL

/* these are parameter handlers which are not needed in the
 * non-source3 code
 */
#define handle_netbios_aliases NULL
#define handle_printing NULL
#define handle_ldap_debug_level NULL
#define handle_idmap_backend NULL
#define handle_idmap_uid NULL
#define handle_idmap_gid NULL

#ifndef N_
#define N_(x) x
#endif

/* prototypes for the special type handlers */
static bool handle_include(struct loadparm_context *lp_ctx, int unused,
			   const char *pszParmValue, char **ptr);
static bool handle_realm(struct loadparm_context *lp_ctx, int unused,
			 const char *pszParmValue, char **ptr);
static bool handle_copy(struct loadparm_context *lp_ctx, int unused,
			const char *pszParmValue, char **ptr);
static bool handle_debug_list(struct loadparm_context *lp_ctx, int unused,
			      const char *pszParmValue, char **ptr);
static bool handle_logfile(struct loadparm_context *lp_ctx, int unused,
			   const char *pszParmValue, char **ptr);

#include "lib/param/param_table.c"

/* local variables */
struct loadparm_context {
	const char *szConfigFile;
	struct loadparm_global *globals;
	struct loadparm_service **services;
	struct loadparm_service *sDefault;
	struct smb_iconv_handle *iconv_handle;
	int iNumServices;
	struct loadparm_service *currentService;
	bool bInGlobalSection;
	struct file_lists {
		struct file_lists *next;
		char *name;
		char *subfname;
		time_t modtime;
	} *file_lists;
	unsigned int flags[NUMPARAMETERS];
	bool loaded;
	bool refuse_free;
	bool global; /* Is this the global context, which may set
		      * global variables such as debug level etc? */
	const struct loadparm_s3_helpers *s3_fns;
};


struct loadparm_service *lpcfg_default_service(struct loadparm_context *lp_ctx)
{
	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_default_loadparm_service();
	}
	return lp_ctx->sDefault;
}

/**
 * Convenience routine to grab string parameters into temporary memory
 * and run standard_sub_basic on them.
 *
 * The buffers can be written to by
 * callers without affecting the source string.
 */

static const char *lp_string(const char *s)
{
#if 0  /* until REWRITE done to make thread-safe */
	size_t len = s ? strlen(s) : 0;
	char *ret;
#endif

	/* The follow debug is useful for tracking down memory problems
	   especially if you have an inner loop that is calling a lp_*()
	   function that returns a string.  Perhaps this debug should be
	   present all the time? */

#if 0
	DEBUG(10, ("lp_string(%s)\n", s));
#endif

#if 0  /* until REWRITE done to make thread-safe */
	if (!lp_talloc)
		lp_talloc = talloc_init("lp_talloc");

	ret = talloc_array(lp_talloc, char, len + 100);	/* leave room for substitution */

	if (!ret)
		return NULL;

	if (!s)
		*ret = 0;
	else
		strlcpy(ret, s, len);

	if (trim_string(ret, "\"", "\"")) {
		if (strchr(ret,'"') != NULL)
			strlcpy(ret, s, len);
	}

	standard_sub_basic(ret,len+100);
	return (ret);
#endif
	return s;
}

/*
   In this section all the functions that are used to access the
   parameters from the rest of the program are defined
*/

/*
 * the creation of separate lpcfg_*() and lp_*() functions is to allow
 * for code compatibility between existing Samba4 and Samba3 code.
 */

/* this global context supports the lp_*() function varients */
static struct loadparm_context *global_loadparm_context;

#define lpcfg_default_service global_loadparm_context->sDefault
#define lpcfg_global_service(i) global_loadparm_context->services[i]

#define FN_GLOBAL_STRING(fn_name,var_name)				\
 _PUBLIC_ const char *lpcfg_ ## fn_name(struct loadparm_context *lp_ctx) { \
	if (lp_ctx == NULL) return NULL;				\
	if (lp_ctx->s3_fns) {						\
		SMB_ASSERT(lp_ctx->s3_fns->fn_name);			\
		return lp_ctx->s3_fns->fn_name();			\
	}								\
	return lp_ctx->globals->var_name ? lp_string(lp_ctx->globals->var_name) : ""; \
}

#define FN_GLOBAL_CONST_STRING(fn_name,var_name) \
 _PUBLIC_ const char *lpcfg_ ## fn_name(struct loadparm_context *lp_ctx) {\
	 if (lp_ctx == NULL) return NULL;				\
	 if (lp_ctx->s3_fns) {						\
		 SMB_ASSERT(lp_ctx->s3_fns->fn_name);			\
		 return lp_ctx->s3_fns->fn_name();			\
	 }								\
	 return lp_ctx->globals->var_name ? lp_string(lp_ctx->globals->var_name) : ""; \
 }

#define FN_GLOBAL_LIST(fn_name,var_name)				\
 _PUBLIC_ const char **lpcfg_ ## fn_name(struct loadparm_context *lp_ctx) { \
	 if (lp_ctx == NULL) return NULL;				\
	 if (lp_ctx->s3_fns) {						\
		 SMB_ASSERT(lp_ctx->s3_fns->fn_name);			\
		 return lp_ctx->s3_fns->fn_name();			\
	 }								\
	 return lp_ctx->globals->var_name;				\
 }

#define FN_GLOBAL_BOOL(fn_name,var_name) \
 _PUBLIC_ bool lpcfg_ ## fn_name(struct loadparm_context *lp_ctx) {\
	 if (lp_ctx == NULL) return false;				\
	 if (lp_ctx->s3_fns) {						\
		 SMB_ASSERT(lp_ctx->s3_fns->fn_name);			\
		 return lp_ctx->s3_fns->fn_name();			\
	 }								\
	 return lp_ctx->globals->var_name;				\
}

#define FN_GLOBAL_INTEGER(fn_name,var_name) \
 _PUBLIC_ int lpcfg_ ## fn_name(struct loadparm_context *lp_ctx) { \
	 if (lp_ctx->s3_fns) {						\
		 SMB_ASSERT(lp_ctx->s3_fns->fn_name);			\
		 return lp_ctx->s3_fns->fn_name();			\
	 }								\
	 return lp_ctx->globals->var_name;				\
 }

/* Local parameters don't need the ->s3_fns because the struct
 * loadparm_service is shared and lpcfg_service() checks the ->s3_fns
 * hook */
#define FN_LOCAL_STRING(fn_name,val) \
 _PUBLIC_ const char *lpcfg_ ## fn_name(struct loadparm_service *service, \
					struct loadparm_service *sDefault) { \
	 return(lp_string((const char *)((service != NULL && service->val != NULL) ? service->val : sDefault->val))); \
 }

#define FN_LOCAL_CONST_STRING(fn_name,val) FN_LOCAL_STRING(fn_name, val)

#define FN_LOCAL_LIST(fn_name,val) \
 _PUBLIC_ const char **lpcfg_ ## fn_name(struct loadparm_service *service, \
					 struct loadparm_service *sDefault) {\
	 return(const char **)(service != NULL && service->val != NULL? service->val : sDefault->val); \
 }

#define FN_LOCAL_PARM_BOOL(fn_name, val) FN_LOCAL_BOOL(fn_name, val)

#define FN_LOCAL_BOOL(fn_name,val) \
 _PUBLIC_ bool lpcfg_ ## fn_name(struct loadparm_service *service, \
				 struct loadparm_service *sDefault) {	\
	 return((service != NULL)? service->val : sDefault->val); \
 }

#define FN_LOCAL_INTEGER(fn_name,val) \
 _PUBLIC_ int lpcfg_ ## fn_name(struct loadparm_service *service, \
				struct loadparm_service *sDefault) {	\
	 return((service != NULL)? service->val : sDefault->val); \
 }

#define FN_LOCAL_PARM_INTEGER(fn_name, val) FN_LOCAL_INTEGER(fn_name, val)

#define FN_LOCAL_CHAR(fn_name,val) \
 _PUBLIC_ char lpcfg_ ## fn_name(struct loadparm_service *service, \
				struct loadparm_service *sDefault) {	\
	 return((service != NULL)? service->val : sDefault->val); \
 }

#include "lib/param/param_functions.c"

/* These functions remain only in lib/param for now */
FN_GLOBAL_BOOL(readraw, bReadRaw)
FN_GLOBAL_BOOL(writeraw, bWriteRaw)
FN_GLOBAL_CONST_STRING(cachedir, szCacheDir)
FN_GLOBAL_CONST_STRING(statedir, szStateDir)

/* local prototypes */
static int map_parameter(const char *pszParmName);
static struct loadparm_service *getservicebyname(struct loadparm_context *lp_ctx,
					const char *pszServiceName);
static void copy_service(struct loadparm_service *pserviceDest,
			 struct loadparm_service *pserviceSource,
			 struct bitmap *pcopymapDest);
static bool lpcfg_service_ok(struct loadparm_service *service);
static bool do_section(const char *pszSectionName, void *);
static void init_copymap(struct loadparm_service *pservice);

/* This is a helper function for parametrical options support. */
/* It returns a pointer to parametrical option value if it exists or NULL otherwise */
/* Actual parametrical functions are quite simple */
const char *lpcfg_get_parametric(struct loadparm_context *lp_ctx,
			      struct loadparm_service *service,
			      const char *type, const char *option)
{
	char *vfskey_tmp = NULL;
	char *vfskey = NULL;
	struct parmlist_entry *data;

	if (lp_ctx == NULL)
		return NULL;

	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_parametric(service, type, option);
	}

	data = (service == NULL ? lp_ctx->globals->param_opt : service->param_opt);

	vfskey_tmp = talloc_asprintf(NULL, "%s:%s", type, option);
	if (vfskey_tmp == NULL) return NULL;
	vfskey = strlower_talloc(NULL, vfskey_tmp);
	talloc_free(vfskey_tmp);

	while (data) {
		if (strcmp(data->key, vfskey) == 0) {
			talloc_free(vfskey);
			return data->value;
		}
		data = data->next;
	}

	if (service != NULL) {
		/* Try to fetch the same option but from globals */
		/* but only if we are not already working with globals */
		for (data = lp_ctx->globals->param_opt; data;
		     data = data->next) {
			if (strcmp(data->key, vfskey) == 0) {
				talloc_free(vfskey);
				return data->value;
			}
		}
	}

	talloc_free(vfskey);

	return NULL;
}


/**
 * convenience routine to return int parameters.
 */
static int lp_int(const char *s)
{

	if (!s) {
		DEBUG(0,("lp_int(%s): is called with NULL!\n",s));
		return -1;
	}

	return strtol(s, NULL, 0);
}

/**
 * convenience routine to return unsigned long parameters.
 */
static unsigned long lp_ulong(const char *s)
{

	if (!s) {
		DEBUG(0,("lp_ulong(%s): is called with NULL!\n",s));
		return -1;
	}

	return strtoul(s, NULL, 0);
}

/**
 * convenience routine to return unsigned long parameters.
 */
static long lp_long(const char *s)
{

	if (!s) {
		DEBUG(0,("lp_long(%s): is called with NULL!\n",s));
		return -1;
	}

	return strtol(s, NULL, 0);
}

/**
 * convenience routine to return unsigned long parameters.
 */
static double lp_double(const char *s)
{

	if (!s) {
		DEBUG(0,("lp_double(%s): is called with NULL!\n",s));
		return -1;
	}

	return strtod(s, NULL);
}

/**
 * convenience routine to return boolean parameters.
 */
static bool lp_bool(const char *s)
{
	bool ret = false;

	if (!s) {
		DEBUG(0,("lp_bool(%s): is called with NULL!\n",s));
		return false;
	}

	if (!set_boolean(s, &ret)) {
		DEBUG(0,("lp_bool(%s): value is not boolean!\n",s));
		return false;
	}

	return ret;
}


/**
 * Return parametric option from a given service. Type is a part of option before ':'
 * Parametric option has following syntax: 'Type: option = value'
 * Returned value is allocated in 'lp_talloc' context
 */

const char *lpcfg_parm_string(struct loadparm_context *lp_ctx,
			      struct loadparm_service *service, const char *type,
			      const char *option)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value)
		return lp_string(value);

	return NULL;
}

/**
 * Return parametric option from a given service. Type is a part of option before ':'
 * Parametric option has following syntax: 'Type: option = value'
 * Returned value is allocated in 'lp_talloc' context
 */

const char **lpcfg_parm_string_list(TALLOC_CTX *mem_ctx,
				    struct loadparm_context *lp_ctx,
				    struct loadparm_service *service,
				    const char *type,
				    const char *option, const char *separator)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value != NULL)
		return (const char **)str_list_make(mem_ctx, value, separator);

	return NULL;
}

/**
 * Return parametric option from a given service. Type is a part of option before ':'
 * Parametric option has following syntax: 'Type: option = value'
 */

int lpcfg_parm_int(struct loadparm_context *lp_ctx,
		   struct loadparm_service *service, const char *type,
		   const char *option, int default_v)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value)
		return lp_int(value);

	return default_v;
}

/**
 * Return parametric option from a given service. Type is a part of
 * option before ':'.
 * Parametric option has following syntax: 'Type: option = value'.
 */

int lpcfg_parm_bytes(struct loadparm_context *lp_ctx,
		  struct loadparm_service *service, const char *type,
		  const char *option, int default_v)
{
	uint64_t bval;

	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value && conv_str_size_error(value, &bval)) {
		if (bval <= INT_MAX) {
			return (int)bval;
		}
	}

	return default_v;
}

/**
 * Return parametric option from a given service.
 * Type is a part of option before ':'
 * Parametric option has following syntax: 'Type: option = value'
 */
unsigned long lpcfg_parm_ulong(struct loadparm_context *lp_ctx,
			    struct loadparm_service *service, const char *type,
			    const char *option, unsigned long default_v)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value)
		return lp_ulong(value);

	return default_v;
}

long lpcfg_parm_long(struct loadparm_context *lp_ctx,
		     struct loadparm_service *service, const char *type,
		     const char *option, long default_v)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value)
		return lp_long(value);

	return default_v;
}

double lpcfg_parm_double(struct loadparm_context *lp_ctx,
		      struct loadparm_service *service, const char *type,
		      const char *option, double default_v)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value != NULL)
		return lp_double(value);

	return default_v;
}

/**
 * Return parametric option from a given service. Type is a part of option before ':'
 * Parametric option has following syntax: 'Type: option = value'
 */

bool lpcfg_parm_bool(struct loadparm_context *lp_ctx,
		     struct loadparm_service *service, const char *type,
		     const char *option, bool default_v)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value != NULL)
		return lp_bool(value);

	return default_v;
}


/**
 * Initialise a service to the defaults.
 */

static struct loadparm_service *init_service(TALLOC_CTX *mem_ctx, struct loadparm_service *sDefault)
{
	struct loadparm_service *pservice =
		talloc_zero(mem_ctx, struct loadparm_service);
	copy_service(pservice, sDefault, NULL);
	return pservice;
}

/**
 * Set a string value, deallocating any existing space, and allocing the space
 * for the string
 */
static bool lpcfg_string_set(TALLOC_CTX *mem_ctx, char **dest, const char *src)
{
	talloc_free(*dest);

	if (src == NULL)
		src = "";

	*dest = talloc_strdup(mem_ctx, src);
	if ((*dest) == NULL) {
		DEBUG(0,("Out of memory in string_set\n"));
		return false;
	}

	return true;
}

/**
 * Set a string value, deallocating any existing space, and allocing the space
 * for the string
 */
static bool lpcfg_string_set_upper(TALLOC_CTX *mem_ctx, char **dest, const char *src)
{
	talloc_free(*dest);

	if (src == NULL)
		src = "";

	*dest = strupper_talloc(mem_ctx, src);
	if ((*dest) == NULL) {
		DEBUG(0,("Out of memory in string_set_upper\n"));
		return false;
	}

	return true;
}



/**
 * Add a new service to the services array initialising it with the given
 * service.
 */

struct loadparm_service *lpcfg_add_service(struct loadparm_context *lp_ctx,
					   const struct loadparm_service *pservice,
					   const char *name)
{
	int i;
	struct loadparm_service tservice;
	int num_to_alloc = lp_ctx->iNumServices + 1;
	struct parmlist_entry *data, *pdata;

	if (pservice == NULL) {
		pservice = lp_ctx->sDefault;
	}

	tservice = *pservice;

	/* it might already exist */
	if (name) {
		struct loadparm_service *service = getservicebyname(lp_ctx,
								    name);
		if (service != NULL) {
			/* Clean all parametric options for service */
			/* They will be added during parsing again */
			data = service->param_opt;
			while (data) {
				pdata = data->next;
				talloc_free(data);
				data = pdata;
			}
			service->param_opt = NULL;
			return service;
		}
	}

	/* find an invalid one */
	for (i = 0; i < lp_ctx->iNumServices; i++)
		if (lp_ctx->services[i] == NULL)
			break;

	/* if not, then create one */
	if (i == lp_ctx->iNumServices) {
		struct loadparm_service **tsp;

		tsp = talloc_realloc(lp_ctx, lp_ctx->services, struct loadparm_service *, num_to_alloc);

		if (!tsp) {
			DEBUG(0,("lpcfg_add_service: failed to enlarge services!\n"));
			return NULL;
		} else {
			lp_ctx->services = tsp;
			lp_ctx->services[lp_ctx->iNumServices] = NULL;
		}

		lp_ctx->iNumServices++;
	}

	lp_ctx->services[i] = init_service(lp_ctx->services, lp_ctx->sDefault);
	if (lp_ctx->services[i] == NULL) {
		DEBUG(0,("lpcfg_add_service: out of memory!\n"));
		return NULL;
	}
	copy_service(lp_ctx->services[i], &tservice, NULL);
	if (name != NULL)
		lpcfg_string_set(lp_ctx->services[i], &lp_ctx->services[i]->szService, name);
	return lp_ctx->services[i];
}

/**
 * Add a new home service, with the specified home directory, defaults coming
 * from service ifrom.
 */

bool lpcfg_add_home(struct loadparm_context *lp_ctx,
		 const char *pszHomename,
		 struct loadparm_service *default_service,
		 const char *user, const char *pszHomedir)
{
	struct loadparm_service *service;

	service = lpcfg_add_service(lp_ctx, default_service, pszHomename);

	if (service == NULL)
		return false;

	if (!(*(default_service->szPath))
	    || strequal(default_service->szPath, lp_ctx->sDefault->szPath)) {
		service->szPath = talloc_strdup(service, pszHomedir);
	} else {
		service->szPath = string_sub_talloc(service, lpcfg_pathname(default_service, lp_ctx->sDefault), "%H", pszHomedir);
	}

	if (!(*(service->comment))) {
		service->comment = talloc_asprintf(service, "Home directory of %s", user);
	}
	service->bAvailable = default_service->bAvailable;
	service->bBrowseable = default_service->bBrowseable;

	DEBUG(3, ("adding home's share [%s] for user '%s' at '%s'\n",
		  pszHomename, user, service->szPath));

	return true;
}

/**
 * Add a new printer service, with defaults coming from service iFrom.
 */

bool lpcfg_add_printer(struct loadparm_context *lp_ctx,
		       const char *pszPrintername,
		       struct loadparm_service *default_service)
{
	const char *comment = "From Printcap";
	struct loadparm_service *service;
	service = lpcfg_add_service(lp_ctx, default_service, pszPrintername);

	if (service == NULL)
		return false;

	/* note that we do NOT default the availability flag to True - */
	/* we take it from the default service passed. This allows all */
	/* dynamic printers to be disabled by disabling the [printers] */
	/* entry (if/when the 'available' keyword is implemented!).    */

	/* the printer name is set to the service name. */
	lpcfg_string_set(service, &service->szPrintername, pszPrintername);
	lpcfg_string_set(service, &service->comment, comment);
	service->bBrowseable = default_service->bBrowseable;
	/* Printers cannot be read_only. */
	service->bRead_only = false;
	/* Printer services must be printable. */
	service->bPrint_ok = true;

	DEBUG(3, ("adding printer service %s\n", pszPrintername));

	return true;
}

/**
 * Map a parameter's string representation to something we can use.
 * Returns False if the parameter string is not recognised, else TRUE.
 */

static int map_parameter(const char *pszParmName)
{
	int iIndex;

	if (*pszParmName == '-')
		return -1;

	for (iIndex = 0; parm_table[iIndex].label; iIndex++)
		if (strwicmp(parm_table[iIndex].label, pszParmName) == 0)
			return iIndex;

	/* Warn only if it isn't parametric option */
	if (strchr(pszParmName, ':') == NULL)
		DEBUG(0, ("Unknown parameter encountered: \"%s\"\n", pszParmName));
	/* We do return 'fail' for parametric options as well because they are
	   stored in different storage
	 */
	return -1;
}


/**
  return the parameter structure for a parameter
*/
struct parm_struct *lpcfg_parm_struct(struct loadparm_context *lp_ctx, const char *name)
{
	int parmnum;

	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_parm_struct(name);
	}

	parmnum = map_parameter(name);
	if (parmnum == -1) return NULL;
	return &parm_table[parmnum];
}

/**
  return the parameter pointer for a parameter
*/
void *lpcfg_parm_ptr(struct loadparm_context *lp_ctx,
		  struct loadparm_service *service, struct parm_struct *parm)
{
	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_parm_ptr(service, parm);
	}

	if (service == NULL) {
		if (parm->p_class == P_LOCAL)
			return ((char *)lp_ctx->sDefault)+parm->offset;
		else if (parm->p_class == P_GLOBAL)
			return ((char *)lp_ctx->globals)+parm->offset;
		else return NULL;
	} else {
		return ((char *)service) + parm->offset;
	}
}

/**
  return the parameter pointer for a parameter
*/
bool lpcfg_parm_is_cmdline(struct loadparm_context *lp_ctx, const char *name)
{
	int parmnum;

	if (lp_ctx->s3_fns) {
		struct parm_struct *parm = lp_ctx->s3_fns->get_parm_struct(name);
		if (parm) {
			return parm->flags & FLAG_CMDLINE;
		}
		return false;
	}

	parmnum = map_parameter(name);
	if (parmnum == -1) return false;

	return lp_ctx->flags[parmnum] & FLAG_CMDLINE;
}

/**
 * Find a service by name. Otherwise works like get_service.
 */

static struct loadparm_service *getservicebyname(struct loadparm_context *lp_ctx,
					const char *pszServiceName)
{
	int iService;

	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_service(pszServiceName);
	}

	for (iService = lp_ctx->iNumServices - 1; iService >= 0; iService--)
		if (lp_ctx->services[iService] != NULL &&
		    strwicmp(lp_ctx->services[iService]->szService, pszServiceName) == 0) {
			return lp_ctx->services[iService];
		}

	return NULL;
}

/**
 * Copy a service structure to another.
 * If pcopymapDest is NULL then copy all fields
 */

static void copy_service(struct loadparm_service *pserviceDest,
			 struct loadparm_service *pserviceSource,
			 struct bitmap *pcopymapDest)
{
	int i;
	bool bcopyall = (pcopymapDest == NULL);
	struct parmlist_entry *data, *pdata, *paramo;
	bool not_added;

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].p_class == P_LOCAL &&
		    (bcopyall || bitmap_query(pcopymapDest, i))) {
			void *src_ptr =
				((char *)pserviceSource) + parm_table[i].offset;
			void *dest_ptr =
				((char *)pserviceDest) + parm_table[i].offset;

			switch (parm_table[i].type) {
				case P_BOOL:
					*(bool *)dest_ptr = *(bool *)src_ptr;
					break;

				case P_INTEGER:
				case P_BYTES:
				case P_OCTAL:
				case P_ENUM:
					*(int *)dest_ptr = *(int *)src_ptr;
					break;

				case P_STRING:
					lpcfg_string_set(pserviceDest,
						   (char **)dest_ptr,
						   *(char **)src_ptr);
					break;

				case P_USTRING:
					lpcfg_string_set_upper(pserviceDest,
							 (char **)dest_ptr,
							 *(char **)src_ptr);
					break;
				case P_LIST:
					*(const char ***)dest_ptr = (const char **)str_list_copy(pserviceDest, 
										  *(const char ***)src_ptr);
					break;
				default:
					break;
			}
		}

	if (bcopyall) {
		init_copymap(pserviceDest);
		if (pserviceSource->copymap)
			bitmap_copy(pserviceDest->copymap,
				    pserviceSource->copymap);
	}

	data = pserviceSource->param_opt;
	while (data) {
		not_added = true;
		pdata = pserviceDest->param_opt;
		/* Traverse destination */
		while (pdata) {
			/* If we already have same option, override it */
			if (strcmp(pdata->key, data->key) == 0) {
				talloc_free(pdata->value);
				pdata->value = talloc_strdup(pdata,
							     data->value);
				not_added = false;
				break;
			}
			pdata = pdata->next;
		}
		if (not_added) {
			paramo = talloc_zero(pserviceDest, struct parmlist_entry);
			if (paramo == NULL)
				smb_panic("OOM");
			paramo->key = talloc_strdup(paramo, data->key);
			paramo->value = talloc_strdup(paramo, data->value);
			DLIST_ADD(pserviceDest->param_opt, paramo);
		}
		data = data->next;
	}
}

/**
 * Check a service for consistency. Return False if the service is in any way
 * incomplete or faulty, else True.
 */
static bool lpcfg_service_ok(struct loadparm_service *service)
{
	bool bRetval;

	bRetval = true;
	if (service->szService[0] == '\0') {
		DEBUG(0, ("The following message indicates an internal error:\n"));
		DEBUG(0, ("No service name in service entry.\n"));
		bRetval = false;
	}

	/* The [printers] entry MUST be printable. I'm all for flexibility, but */
	/* I can't see why you'd want a non-printable printer service...        */
	if (strwicmp(service->szService, PRINTERS_NAME) == 0) {
		if (!service->bPrint_ok) {
			DEBUG(0, ("WARNING: [%s] service MUST be printable!\n",
			       service->szService));
			service->bPrint_ok = true;
		}
		/* [printers] service must also be non-browsable. */
		if (service->bBrowseable)
			service->bBrowseable = false;
	}

	/* If a service is flagged unavailable, log the fact at level 0. */
	if (!service->bAvailable)
		DEBUG(1, ("NOTE: Service %s is flagged unavailable.\n",
			  service->szService));

	return bRetval;
}


/*******************************************************************
 Keep a linked list of all config files so we know when one has changed
 it's date and needs to be reloaded.
********************************************************************/

static void add_to_file_list(struct loadparm_context *lp_ctx,
			     const char *fname, const char *subfname)
{
	struct file_lists *f = lp_ctx->file_lists;

	while (f) {
		if (f->name && !strcmp(f->name, fname))
			break;
		f = f->next;
	}

	if (!f) {
		f = talloc(lp_ctx, struct file_lists);
		if (!f)
			return;
		f->next = lp_ctx->file_lists;
		f->name = talloc_strdup(f, fname);
		if (!f->name) {
			talloc_free(f);
			return;
		}
		f->subfname = talloc_strdup(f, subfname);
		if (!f->subfname) {
			talloc_free(f);
			return;
		}
		lp_ctx->file_lists = f;
		f->modtime = file_modtime(subfname);
	} else {
		time_t t = file_modtime(subfname);
		if (t)
			f->modtime = t;
	}
}

/*******************************************************************
 Check if a config file has changed date.
********************************************************************/
bool lpcfg_file_list_changed(struct loadparm_context *lp_ctx)
{
	struct file_lists *f;
	DEBUG(6, ("lp_file_list_changed()\n"));

	for (f = lp_ctx->file_lists; f != NULL; f = f->next) {
		char *n2;
		time_t mod_time;

		n2 = standard_sub_basic(lp_ctx, f->name);

		DEBUGADD(6, ("file %s -> %s  last mod_time: %s\n",
			     f->name, n2, ctime(&f->modtime)));

		mod_time = file_modtime(n2);

		if (mod_time && ((f->modtime != mod_time) || (f->subfname == NULL) || (strcmp(n2, f->subfname) != 0))) {
			DEBUGADD(6, ("file %s modified: %s\n", n2,
				  ctime(&mod_time)));
			f->modtime = mod_time;
			talloc_free(f->subfname);
			f->subfname = talloc_strdup(f, n2);
			return true;
		}
	}
	return false;
}

/***************************************************************************
 Handle the "realm" parameter
***************************************************************************/

static bool handle_realm(struct loadparm_context *lp_ctx, int unused,
			 const char *pszParmValue, char **ptr)
{
	lpcfg_string_set(lp_ctx, ptr, pszParmValue);

	talloc_free(lp_ctx->globals->szRealm_upper);
	talloc_free(lp_ctx->globals->szRealm_lower);

	lp_ctx->globals->szRealm_upper = strupper_talloc(lp_ctx, pszParmValue);
	lp_ctx->globals->szRealm_lower = strlower_talloc(lp_ctx, pszParmValue);

	return true;
}

/***************************************************************************
 Handle the include operation.
***************************************************************************/

static bool handle_include(struct loadparm_context *lp_ctx, int unused,
			   const char *pszParmValue, char **ptr)
{
	char *fname = standard_sub_basic(lp_ctx, pszParmValue);

	add_to_file_list(lp_ctx, pszParmValue, fname);

	lpcfg_string_set(lp_ctx, ptr, fname);

	if (file_exist(fname))
		return pm_process(fname, do_section, do_parameter, lp_ctx);

	DEBUG(2, ("Can't find include file %s\n", fname));

	return false;
}

/***************************************************************************
 Handle the interpretation of the copy parameter.
***************************************************************************/

static bool handle_copy(struct loadparm_context *lp_ctx, int unused,
			const char *pszParmValue, char **ptr)
{
	bool bRetval;
	struct loadparm_service *serviceTemp;

	lpcfg_string_set(lp_ctx, ptr, pszParmValue);

	bRetval = false;

	DEBUG(3, ("Copying service from service %s\n", pszParmValue));

	if ((serviceTemp = getservicebyname(lp_ctx, pszParmValue)) != NULL) {
		if (serviceTemp == lp_ctx->currentService) {
			DEBUG(0, ("Can't copy service %s - unable to copy self!\n", pszParmValue));
		} else {
			copy_service(lp_ctx->currentService,
				     serviceTemp,
				     lp_ctx->currentService->copymap);
			bRetval = true;
		}
	} else {
		DEBUG(0, ("Unable to copy service - source not found: %s\n",
			  pszParmValue));
		bRetval = false;
	}

	return bRetval;
}

static bool handle_debug_list(struct loadparm_context *lp_ctx, int unused,
			const char *pszParmValue, char **ptr)
{

	lpcfg_string_set(lp_ctx, ptr, pszParmValue);
	if (lp_ctx->global) {
		return debug_parse_levels(pszParmValue);
	}
	return true;
}

static bool handle_logfile(struct loadparm_context *lp_ctx, int unused,
			const char *pszParmValue, char **ptr)
{
	debug_set_logfile(pszParmValue);
	if (lp_ctx->global) {
		lpcfg_string_set(lp_ctx, ptr, pszParmValue);
	}
	return true;
}

/***************************************************************************
 Initialise a copymap.
***************************************************************************/

static void init_copymap(struct loadparm_service *pservice)
{
	int i;

	TALLOC_FREE(pservice->copymap);

	pservice->copymap = bitmap_talloc(NULL, NUMPARAMETERS);
	if (!pservice->copymap)
		DEBUG(0,
		      ("Couldn't allocate copymap!! (size %d)\n",
		       (int)NUMPARAMETERS));
	else
		for (i = 0; i < NUMPARAMETERS; i++)
			bitmap_set(pservice->copymap, i);
}

/**
 * Process a parametric option
 */
static bool lp_do_parameter_parametric(struct loadparm_context *lp_ctx,
				       struct loadparm_service *service,
				       const char *pszParmName,
				       const char *pszParmValue, int flags)
{
	struct parmlist_entry *paramo, *data;
	char *name;
	TALLOC_CTX *mem_ctx;

	while (isspace((unsigned char)*pszParmName)) {
		pszParmName++;
	}

	name = strlower_talloc(lp_ctx, pszParmName);
	if (!name) return false;

	if (service == NULL) {
		data = lp_ctx->globals->param_opt;
		mem_ctx = lp_ctx->globals;
	} else {
		data = service->param_opt;
		mem_ctx = service;
	}

	/* Traverse destination */
	for (paramo=data; paramo; paramo=paramo->next) {
		/* If we already have the option set, override it unless
		   it was a command line option and the new one isn't */
		if (strcmp(paramo->key, name) == 0) {
			if ((paramo->priority & FLAG_CMDLINE) &&
			    !(flags & FLAG_CMDLINE)) {
				talloc_free(name);
				return true;
			}

			talloc_free(paramo->value);
			paramo->value = talloc_strdup(paramo, pszParmValue);
			paramo->priority = flags;
			talloc_free(name);
			return true;
		}
	}

	paramo = talloc_zero(mem_ctx, struct parmlist_entry);
	if (!paramo)
		smb_panic("OOM");
	paramo->key = talloc_strdup(paramo, name);
	paramo->value = talloc_strdup(paramo, pszParmValue);
	paramo->priority = flags;
	if (service == NULL) {
		DLIST_ADD(lp_ctx->globals->param_opt, paramo);
	} else {
		DLIST_ADD(service->param_opt, paramo);
	}

	talloc_free(name);

	return true;
}

static bool set_variable(TALLOC_CTX *mem_ctx, int parmnum, void *parm_ptr,
			 const char *pszParmName, const char *pszParmValue,
			 struct loadparm_context *lp_ctx, bool on_globals)
{
	int i;
	/* if it is a special case then go ahead */
	if (parm_table[parmnum].special) {
		bool ret;
		ret = parm_table[parmnum].special(lp_ctx, -1, pszParmValue,
						  (char **)parm_ptr);
		if (!ret) {
			return false;
		}
		goto mark_non_default;
	}

	/* now switch on the type of variable it is */
	switch (parm_table[parmnum].type)
	{
		case P_BOOL: {
			bool b;
			if (!set_boolean(pszParmValue, &b)) {
				DEBUG(0,("lp_do_parameter(%s): value is not boolean!\n", pszParmValue));
				return false;
			}
			*(bool *)parm_ptr = b;
			}
			break;

		case P_BOOLREV: {
			bool b;
			if (!set_boolean(pszParmValue, &b)) {
				DEBUG(0,("lp_do_parameter(%s): value is not boolean!\n", pszParmValue));
				return false;
			}
			*(bool *)parm_ptr = !b;
			}
			break;

		case P_INTEGER:
			*(int *)parm_ptr = atoi(pszParmValue);
			break;

		case P_CHAR:
			*(char *)parm_ptr = *pszParmValue;
			break;

		case P_OCTAL:
			*(int *)parm_ptr = strtol(pszParmValue, NULL, 8);
			break;

		case P_BYTES:
		{
			uint64_t val;
			if (conv_str_size_error(pszParmValue, &val)) {
				if (val <= INT_MAX) {
					*(int *)parm_ptr = (int)val;
					break;
				}
			}

			DEBUG(0,("lp_do_parameter(%s): value is not "
			    "a valid size specifier!\n", pszParmValue));
			return false;
		}

		case P_CMDLIST:
			*(const char ***)parm_ptr = (const char **)str_list_make(mem_ctx,
								  pszParmValue, NULL);
			break;
		case P_LIST:
		{
			char **new_list = str_list_make(mem_ctx,
							pszParmValue, NULL);
			for (i=0; new_list[i]; i++) {
				if (*(const char ***)parm_ptr != NULL &&
				    new_list[i][0] == '+' &&
				    new_list[i][1])
				{
					if (!str_list_check(*(const char ***)parm_ptr,
							    &new_list[i][1])) {
						*(const char ***)parm_ptr = str_list_add(*(const char ***)parm_ptr,
											 &new_list[i][1]);
					}
				} else if (*(const char ***)parm_ptr != NULL &&
					   new_list[i][0] == '-' &&
					   new_list[i][1])
				{
					str_list_remove(*(const char ***)parm_ptr,
							&new_list[i][1]);
				} else {
					if (i != 0) {
						DEBUG(0, ("Unsupported list syntax for: %s = %s\n",
							  pszParmName, pszParmValue));
						return false;
					}
					*(const char ***)parm_ptr = (const char **) new_list;
					break;
				}
			}
			break;
		}
		case P_STRING:
			lpcfg_string_set(mem_ctx, (char **)parm_ptr, pszParmValue);
			break;

		case P_USTRING:
			lpcfg_string_set_upper(mem_ctx, (char **)parm_ptr, pszParmValue);
			break;

		case P_ENUM:
			for (i = 0; parm_table[parmnum].enum_list[i].name; i++) {
				if (strequal
				    (pszParmValue,
				     parm_table[parmnum].enum_list[i].name)) {
					*(int *)parm_ptr =
						parm_table[parmnum].
						enum_list[i].value;
					break;
				}
			}
			if (!parm_table[parmnum].enum_list[i].name) {
				DEBUG(0,("Unknown enumerated value '%s' for '%s'\n", 
					 pszParmValue, pszParmName));
				return false;
			}
			break;

		case P_SEP:
			break;
	}

mark_non_default:
	if (on_globals && (lp_ctx->flags[parmnum] & FLAG_DEFAULT)) {
		lp_ctx->flags[parmnum] &= ~FLAG_DEFAULT;
		/* we have to also unset FLAG_DEFAULT on aliases */
		for (i=parmnum-1;i>=0 && parm_table[i].offset == parm_table[parmnum].offset;i--) {
			lp_ctx->flags[i] &= ~FLAG_DEFAULT;
		}
		for (i=parmnum+1;i<NUMPARAMETERS && parm_table[i].offset == parm_table[parmnum].offset;i++) {
			lp_ctx->flags[i] &= ~FLAG_DEFAULT;
		}
	}
	return true;
}


bool lpcfg_do_global_parameter(struct loadparm_context *lp_ctx,
			       const char *pszParmName, const char *pszParmValue)
{
	int parmnum = map_parameter(pszParmName);
	void *parm_ptr;

	if (parmnum < 0) {
		if (strchr(pszParmName, ':')) {
			return lp_do_parameter_parametric(lp_ctx, NULL, pszParmName, pszParmValue, 0);
		}
		DEBUG(0, ("Ignoring unknown parameter \"%s\"\n", pszParmName));
		return true;
	}

	/* if the flag has been set on the command line, then don't allow override,
	   but don't report an error */
	if (lp_ctx->flags[parmnum] & FLAG_CMDLINE) {
		return true;
	}

	parm_ptr = lpcfg_parm_ptr(lp_ctx, NULL, &parm_table[parmnum]);

	return set_variable(lp_ctx->globals, parmnum, parm_ptr,
			    pszParmName, pszParmValue, lp_ctx, true);
}

bool lpcfg_do_service_parameter(struct loadparm_context *lp_ctx,
				struct loadparm_service *service,
				const char *pszParmName, const char *pszParmValue)
{
	void *parm_ptr;
	int i;
	int parmnum = map_parameter(pszParmName);

	if (parmnum < 0) {
		if (strchr(pszParmName, ':')) {
			return lp_do_parameter_parametric(lp_ctx, service, pszParmName, pszParmValue, 0);
		}
		DEBUG(0, ("Ignoring unknown parameter \"%s\"\n", pszParmName));
		return true;
	}

	/* if the flag has been set on the command line, then don't allow override,
	   but don't report an error */
	if (lp_ctx->flags[parmnum] & FLAG_CMDLINE) {
		return true;
	}

	if (parm_table[parmnum].p_class == P_GLOBAL) {
		DEBUG(0,
		      ("Global parameter %s found in service section!\n",
		       pszParmName));
		return true;
	}
	parm_ptr = ((char *)service) + parm_table[parmnum].offset;

	if (!service->copymap)
		init_copymap(service);

	/* this handles the aliases - set the copymap for other
	 * entries with the same data pointer */
	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].offset == parm_table[parmnum].offset &&
		    parm_table[i].p_class == parm_table[parmnum].p_class)
			bitmap_clear(service->copymap, i);

	return set_variable(service, parmnum, parm_ptr, pszParmName,
			    pszParmValue, lp_ctx, false);
}

/**
 * Process a parameter.
 */

static bool do_parameter(const char *pszParmName, const char *pszParmValue,
			 void *userdata)
{
	struct loadparm_context *lp_ctx = (struct loadparm_context *)userdata;

	if (lp_ctx->bInGlobalSection)
		return lpcfg_do_global_parameter(lp_ctx, pszParmName,
					      pszParmValue);
	else
		return lpcfg_do_service_parameter(lp_ctx, lp_ctx->currentService,
						  pszParmName, pszParmValue);
}

/*
  variable argument do parameter
*/
bool lpcfg_do_global_parameter_var(struct loadparm_context *lp_ctx, const char *pszParmName, const char *fmt, ...) PRINTF_ATTRIBUTE(3, 4);
bool lpcfg_do_global_parameter_var(struct loadparm_context *lp_ctx,
				const char *pszParmName, const char *fmt, ...)
{
	char *s;
	bool ret;
	va_list ap;

	va_start(ap, fmt);
	s = talloc_vasprintf(NULL, fmt, ap);
	va_end(ap);
	ret = lpcfg_do_global_parameter(lp_ctx, pszParmName, s);
	talloc_free(s);
	return ret;
}


/*
  set a parameter from the commandline - this is called from command line parameter
  parsing code. It sets the parameter then marks the parameter as unable to be modified
  by smb.conf processing
*/
bool lpcfg_set_cmdline(struct loadparm_context *lp_ctx, const char *pszParmName,
		       const char *pszParmValue)
{
	int parmnum;
	int i;

	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->set_cmdline(pszParmName, pszParmValue);
	}

	parmnum = map_parameter(pszParmName);

	while (isspace((unsigned char)*pszParmValue)) pszParmValue++;


	if (parmnum < 0 && strchr(pszParmName, ':')) {
		/* set a parametric option */
		return lp_do_parameter_parametric(lp_ctx, NULL, pszParmName,
						  pszParmValue, FLAG_CMDLINE);
	}

	if (parmnum < 0) {
		DEBUG(0,("Unknown option '%s'\n", pszParmName));
		return false;
	}

	/* reset the CMDLINE flag in case this has been called before */
	lp_ctx->flags[parmnum] &= ~FLAG_CMDLINE;

	if (!lpcfg_do_global_parameter(lp_ctx, pszParmName, pszParmValue)) {
		return false;
	}

	lp_ctx->flags[parmnum] |= FLAG_CMDLINE;

	/* we have to also set FLAG_CMDLINE on aliases */
	for (i=parmnum-1;i>=0 && parm_table[i].offset == parm_table[parmnum].offset;i--) {
		lp_ctx->flags[i] |= FLAG_CMDLINE;
	}
	for (i=parmnum+1;i<NUMPARAMETERS && parm_table[i].offset == parm_table[parmnum].offset;i++) {
		lp_ctx->flags[i] |= FLAG_CMDLINE;
	}

	return true;
}

/*
  set a option from the commandline in 'a=b' format. Use to support --option
*/
bool lpcfg_set_option(struct loadparm_context *lp_ctx, const char *option)
{
	char *p, *s;
	bool ret;

	s = talloc_strdup(NULL, option);
	if (!s) {
		return false;
	}

	p = strchr(s, '=');
	if (!p) {
		talloc_free(s);
		return false;
	}

	*p = 0;

	ret = lpcfg_set_cmdline(lp_ctx, s, p+1);
	talloc_free(s);
	return ret;
}


#define BOOLSTR(b) ((b) ? "Yes" : "No")

/**
 * Print a parameter of the specified type.
 */

static void print_parameter(struct parm_struct *p, void *ptr, FILE * f)
{
	/* For the seperation of lists values that we print below */
	const char *list_sep = ", ";
	int i;
	switch (p->type)
	{
		case P_ENUM:
			for (i = 0; p->enum_list[i].name; i++) {
				if (*(int *)ptr == p->enum_list[i].value) {
					fprintf(f, "%s",
						p->enum_list[i].name);
					break;
				}
			}
			break;

		case P_BOOL:
			fprintf(f, "%s", BOOLSTR(*(bool *)ptr));
			break;

		case P_BOOLREV:
			fprintf(f, "%s", BOOLSTR(!*(bool *)ptr));
			break;

		case P_INTEGER:
		case P_BYTES:
			fprintf(f, "%d", *(int *)ptr);
			break;

		case P_CHAR:
			fprintf(f, "%c", *(char *)ptr);
			break;

		case P_OCTAL: {
			int val = *(int *)ptr; 
			if (val == -1) {
				fprintf(f, "-1");
			} else {
				fprintf(f, "0%o", val);
			}
			break;
		}

		case P_CMDLIST:
			list_sep = " ";
			/* fall through */
		case P_LIST:
			if ((char ***)ptr && *(char ***)ptr) {
				char **list = *(char ***)ptr;
				for (; *list; list++) {
					/* surround strings with whitespace in double quotes */
					if (*(list+1) == NULL) {
						/* last item, no extra separator */
						list_sep = "";
					}
					if ( strchr_m( *list, ' ' ) ) {
						fprintf(f, "\"%s\"%s", *list, list_sep);
					} else {
						fprintf(f, "%s%s", *list, list_sep);
					}
				}
			}
			break;

		case P_STRING:
		case P_USTRING:
			if (*(char **)ptr) {
				fprintf(f, "%s", *(char **)ptr);
			}
			break;
		case P_SEP:
			break;
	}
}

/**
 * Check if two parameters are equal.
 */

static bool equal_parameter(parm_type type, void *ptr1, void *ptr2)
{
	switch (type) {
		case P_BOOL:
		case P_BOOLREV:
			return (*((bool *)ptr1) == *((bool *)ptr2));

		case P_INTEGER:
		case P_ENUM:
		case P_OCTAL:
		case P_BYTES:
			return (*((int *)ptr1) == *((int *)ptr2));

		case P_CHAR:
			return (*((char *)ptr1) == *((char *)ptr2));

		case P_LIST:
		case P_CMDLIST:
			return str_list_equal(*(const char ***)ptr1, *(const char ***)ptr2);

		case P_STRING:
		case P_USTRING:
		{
			char *p1 = *(char **)ptr1, *p2 = *(char **)ptr2;
			if (p1 && !*p1)
				p1 = NULL;
			if (p2 && !*p2)
				p2 = NULL;
			return (p1 == p2 || strequal(p1, p2));
		}
		case P_SEP:
			break;
	}
	return false;
}

/**
 * Process a new section (service).
 *
 * At this stage all sections are services.
 * Later we'll have special sections that permit server parameters to be set.
 * Returns True on success, False on failure.
 */

static bool do_section(const char *pszSectionName, void *userdata)
{
	struct loadparm_context *lp_ctx = (struct loadparm_context *)userdata;
	bool bRetval;
	bool isglobal = ((strwicmp(pszSectionName, GLOBAL_NAME) == 0) ||
			 (strwicmp(pszSectionName, GLOBAL_NAME2) == 0));
	bRetval = false;

	/* if we've just struck a global section, note the fact. */
	lp_ctx->bInGlobalSection = isglobal;

	/* check for multiple global sections */
	if (lp_ctx->bInGlobalSection) {
		DEBUG(4, ("Processing section \"[%s]\"\n", pszSectionName));
		return true;
	}

	/* if we have a current service, tidy it up before moving on */
	bRetval = true;

	if (lp_ctx->currentService != NULL)
		bRetval = lpcfg_service_ok(lp_ctx->currentService);

	/* if all is still well, move to the next record in the services array */
	if (bRetval) {
		/* We put this here to avoid an odd message order if messages are */
		/* issued by the post-processing of a previous section. */
		DEBUG(4, ("Processing section \"[%s]\"\n", pszSectionName));

		if ((lp_ctx->currentService = lpcfg_add_service(lp_ctx, lp_ctx->sDefault,
								   pszSectionName))
		    == NULL) {
			DEBUG(0, ("Failed to add a new service\n"));
			return false;
		}
	}

	return bRetval;
}


/**
 * Determine if a particular base parameter is currently set to the default value.
 */

static bool is_default(struct loadparm_service *sDefault, int i)
{
	void *def_ptr = ((char *)sDefault) + parm_table[i].offset;
	if (!defaults_saved)
		return false;
	switch (parm_table[i].type) {
		case P_CMDLIST:
		case P_LIST:
			return str_list_equal((const char **)parm_table[i].def.lvalue, 
					      (const char **)def_ptr);
		case P_STRING:
		case P_USTRING:
			return strequal(parm_table[i].def.svalue,
					*(char **)def_ptr);
		case P_BOOL:
		case P_BOOLREV:
			return parm_table[i].def.bvalue ==
				*(bool *)def_ptr;
		case P_INTEGER:
		case P_CHAR:
		case P_OCTAL:
		case P_BYTES:
		case P_ENUM:
			return parm_table[i].def.ivalue ==
				*(int *)def_ptr;
		case P_SEP:
			break;
	}
	return false;
}

/**
 *Display the contents of the global structure.
 */

static void dump_globals(struct loadparm_context *lp_ctx, FILE *f,
			 bool show_defaults)
{
	int i;
	struct parmlist_entry *data;

	fprintf(f, "# Global parameters\n[global]\n");

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].p_class == P_GLOBAL &&
		    (i == 0 || (parm_table[i].offset != parm_table[i - 1].offset))) {
			if (!show_defaults && (lp_ctx->flags[i] & FLAG_DEFAULT))
				continue;
			fprintf(f, "\t%s = ", parm_table[i].label);
			print_parameter(&parm_table[i], lpcfg_parm_ptr(lp_ctx, NULL, &parm_table[i]), f);
			fprintf(f, "\n");
	}
	if (lp_ctx->globals->param_opt != NULL) {
		for (data = lp_ctx->globals->param_opt; data;
		     data = data->next) {
			if (!show_defaults && (data->priority & FLAG_DEFAULT)) {
				continue;
			}
			fprintf(f, "\t%s = %s\n", data->key, data->value);
		}
        }

}

/**
 * Display the contents of a single services record.
 */

static void dump_a_service(struct loadparm_service * pService, struct loadparm_service *sDefault, FILE * f,
			   unsigned int *flags)
{
	int i;
	struct parmlist_entry *data;

	if (pService != sDefault)
		fprintf(f, "\n[%s]\n", pService->szService);

	for (i = 0; parm_table[i].label; i++) {
		if (parm_table[i].p_class == P_LOCAL &&
		    (*parm_table[i].label != '-') &&
		    (i == 0 || (parm_table[i].offset != parm_table[i - 1].offset)))
		{
			if (pService == sDefault) {
				if (flags && (flags[i] & FLAG_DEFAULT)) {
					continue;
				}
				if (defaults_saved) {
					if (is_default(sDefault, i)) {
						continue;
					}
				}
			} else {
				if (equal_parameter(parm_table[i].type,
						    ((char *)pService) +
						    parm_table[i].offset,
						    ((char *)sDefault) +
						    parm_table[i].offset))
					continue;
			}

			fprintf(f, "\t%s = ", parm_table[i].label);
			print_parameter(&parm_table[i],
					((char *)pService) + parm_table[i].offset, f);
			fprintf(f, "\n");
		}
	}
	if (pService->param_opt != NULL) {
		for (data = pService->param_opt; data; data = data->next) {
			fprintf(f, "\t%s = %s\n", data->key, data->value);
		}
        }
}

bool lpcfg_dump_a_parameter(struct loadparm_context *lp_ctx,
			    struct loadparm_service *service,
			    const char *parm_name, FILE * f)
{
	struct parm_struct *parm;
	void *ptr;

	parm = lpcfg_parm_struct(lp_ctx, parm_name);
	if (!parm) {
		return false;
	}

	ptr = lpcfg_parm_ptr(lp_ctx, service,parm);

	print_parameter(parm, ptr, f);
	fprintf(f, "\n");
	return true;
}

/**
 * Return info about the next parameter in a service.
 * snum==-1 gives the globals.
 * Return NULL when out of parameters.
 */


struct parm_struct *lpcfg_next_parameter(struct loadparm_context *lp_ctx, int snum, int *i,
					 int allparameters)
{
	if (snum == -1) {
		/* do the globals */
		for (; parm_table[*i].label; (*i)++) {
			if ((*parm_table[*i].label == '-'))
				continue;

			if ((*i) > 0
			    && (parm_table[*i].offset ==
				parm_table[(*i) - 1].offset)
			    && (parm_table[*i].p_class ==
				parm_table[(*i) - 1].p_class))
				continue;

			return &parm_table[(*i)++];
		}
	} else {
		struct loadparm_service *pService = lp_ctx->services[snum];

		for (; parm_table[*i].label; (*i)++) {
			if (parm_table[*i].p_class == P_LOCAL &&
			    (*parm_table[*i].label != '-') &&
			    ((*i) == 0 ||
			     (parm_table[*i].offset !=
			      parm_table[(*i) - 1].offset)))
			{
				if (allparameters ||
				    !equal_parameter(parm_table[*i].type,
						     ((char *)pService) +
						     parm_table[*i].offset,
						     ((char *)lp_ctx->sDefault) +
						     parm_table[*i].offset))
				{
					return &parm_table[(*i)++];
				}
			}
		}
	}

	return NULL;
}


/**
 * Auto-load some home services.
 */
static void lpcfg_add_auto_services(struct loadparm_context *lp_ctx,
				    const char *str)
{
	return;
}


/**
 * Unload unused services.
 */

void lpcfg_killunused(struct loadparm_context *lp_ctx,
		   struct smbsrv_connection *smb,
		   bool (*snumused) (struct smbsrv_connection *, int))
{
	int i;
	for (i = 0; i < lp_ctx->iNumServices; i++) {
		if (lp_ctx->services[i] == NULL)
			continue;

		if (!snumused || !snumused(smb, i)) {
			talloc_free(lp_ctx->services[i]);
			lp_ctx->services[i] = NULL;
		}
	}
}


static int lpcfg_destructor(struct loadparm_context *lp_ctx)
{
	struct parmlist_entry *data;

	if (lp_ctx->refuse_free) {
		/* someone is trying to free the
		   global_loadparm_context.
		   We can't allow that. */
		return -1;
	}

	if (lp_ctx->globals->param_opt != NULL) {
		struct parmlist_entry *next;
		for (data = lp_ctx->globals->param_opt; data; data=next) {
			next = data->next;
			if (data->priority & FLAG_CMDLINE) continue;
			DLIST_REMOVE(lp_ctx->globals->param_opt, data);
			talloc_free(data);
		}
	}

	return 0;
}

/**
 * Initialise the global parameter structure.
 *
 * Note that most callers should use loadparm_init_global() instead
 */
struct loadparm_context *loadparm_init(TALLOC_CTX *mem_ctx)
{
	int i;
	char *myname;
	struct loadparm_context *lp_ctx;
	struct parmlist_entry *parm;
	char *logfile;

	lp_ctx = talloc_zero(mem_ctx, struct loadparm_context);
	if (lp_ctx == NULL)
		return NULL;

	talloc_set_destructor(lp_ctx, lpcfg_destructor);
	lp_ctx->bInGlobalSection = true;
	lp_ctx->globals = talloc_zero(lp_ctx, struct loadparm_global);
	lp_ctx->sDefault = talloc_zero(lp_ctx, struct loadparm_service);

	lp_ctx->sDefault->iMaxPrintJobs = 1000;
	lp_ctx->sDefault->bAvailable = true;
	lp_ctx->sDefault->bBrowseable = true;
	lp_ctx->sDefault->bRead_only = true;
	lp_ctx->sDefault->bMap_archive = true;
	lp_ctx->sDefault->iStrictLocking = true;
	lp_ctx->sDefault->bOpLocks = true;
	lp_ctx->sDefault->iCreate_mask = 0744;
	lp_ctx->sDefault->iCreate_force_mode = 0000;
	lp_ctx->sDefault->iDir_mask = 0755;
	lp_ctx->sDefault->iDir_force_mode = 0000;

	DEBUG(3, ("Initialising global parameters\n"));

	for (i = 0; parm_table[i].label; i++) {
		if ((parm_table[i].type == P_STRING ||
		     parm_table[i].type == P_USTRING) &&
		    !(lp_ctx->flags[i] & FLAG_CMDLINE)) {
			char **r;
			if (parm_table[i].p_class == P_LOCAL) {
				r = (char **)(((char *)lp_ctx->sDefault) + parm_table[i].offset);
			} else {
				r = (char **)(((char *)lp_ctx->globals) + parm_table[i].offset);
			}
			*r = talloc_strdup(lp_ctx, "");
		}
	}

	logfile = talloc_asprintf(lp_ctx, "%s/log.samba", dyn_LOGFILEBASE);
	lpcfg_do_global_parameter(lp_ctx, "log file", logfile);
	talloc_free(logfile);

	lpcfg_do_global_parameter(lp_ctx, "log level", "0");

	lpcfg_do_global_parameter(lp_ctx, "syslog", "1");
	lpcfg_do_global_parameter(lp_ctx, "syslog only", "No");
	lpcfg_do_global_parameter(lp_ctx, "debug timestamp", "Yes");
	lpcfg_do_global_parameter(lp_ctx, "debug prefix timestamp", "No");
	lpcfg_do_global_parameter(lp_ctx, "debug hires timestamp", "Yes");
	lpcfg_do_global_parameter(lp_ctx, "debug pid", "No");
	lpcfg_do_global_parameter(lp_ctx, "debug uid", "No");
	lpcfg_do_global_parameter(lp_ctx, "debug class", "No");

	lpcfg_do_global_parameter(lp_ctx, "share backend", "classic");

	lpcfg_do_global_parameter(lp_ctx, "server role", "auto");
	lpcfg_do_global_parameter(lp_ctx, "domain logons", "No");
	lpcfg_do_global_parameter(lp_ctx, "domain master", "Auto");

	/* options that can be set on the command line must be initialised via
	   the slower lpcfg_do_global_parameter() to ensure that FLAG_CMDLINE is obeyed */
#ifdef TCP_NODELAY
	lpcfg_do_global_parameter(lp_ctx, "socket options", "TCP_NODELAY");
#endif
	lpcfg_do_global_parameter(lp_ctx, "workgroup", DEFAULT_WORKGROUP);
	myname = get_myname(lp_ctx);
	lpcfg_do_global_parameter(lp_ctx, "netbios name", myname);
	talloc_free(myname);
	lpcfg_do_global_parameter(lp_ctx, "name resolve order", "wins host bcast");

	lpcfg_do_global_parameter(lp_ctx, "fstype", "NTFS");

	lpcfg_do_global_parameter(lp_ctx, "ntvfs handler", "unixuid default");
	lpcfg_do_global_parameter(lp_ctx, "max connections", "-1");

	lpcfg_do_global_parameter(lp_ctx, "dcerpc endpoint servers", "epmapper wkssvc rpcecho samr netlogon lsarpc spoolss drsuapi dssetup unixinfo browser eventlog6 backupkey dnsserver");
	lpcfg_do_global_parameter(lp_ctx, "server services", "s3fs rpc nbt wrepl ldap cldap kdc drepl winbind ntp_signd kcc dnsupdate dns");
	/* the winbind method for domain controllers is for both RODC
	   auth forwarding and for trusted domains */
	lpcfg_do_global_parameter(lp_ctx, "private dir", dyn_PRIVATE_DIR);
	lpcfg_do_global_parameter(lp_ctx, "registry:HKEY_LOCAL_MACHINE", "hklm.ldb");

	/* This hive should be dynamically generated by Samba using
	   data from the sam, but for the moment leave it in a tdb to
	   keep regedt32 from popping up an annoying dialog. */
	lpcfg_do_global_parameter(lp_ctx, "registry:HKEY_USERS", "hku.ldb");

	/* using UTF8 by default allows us to support all chars */
	lpcfg_do_global_parameter(lp_ctx, "unix charset", "UTF8");

	/* Use codepage 850 as a default for the dos character set */
	lpcfg_do_global_parameter(lp_ctx, "dos charset", "CP850");

	/*
	 * Allow the default PASSWD_CHAT to be overridden in local.h.
	 */
	lpcfg_do_global_parameter(lp_ctx, "passwd chat", DEFAULT_PASSWD_CHAT);

	lpcfg_do_global_parameter(lp_ctx, "pid directory", dyn_PIDDIR);
	lpcfg_do_global_parameter(lp_ctx, "lock dir", dyn_LOCKDIR);
	lpcfg_do_global_parameter(lp_ctx, "state directory", dyn_STATEDIR);
	lpcfg_do_global_parameter(lp_ctx, "cache directory", dyn_CACHEDIR);
	lpcfg_do_global_parameter(lp_ctx, "ncalrpc dir", dyn_NCALRPCDIR);

	lpcfg_do_global_parameter(lp_ctx, "nbt client socket address", "");
	lpcfg_do_global_parameter_var(lp_ctx, "server string",
				   "Samba %s", SAMBA_VERSION_STRING);

	lpcfg_do_global_parameter(lp_ctx, "password server", "*");

	lpcfg_do_global_parameter(lp_ctx, "max mux", "50");
	lpcfg_do_global_parameter(lp_ctx, "max xmit", "12288");
	lpcfg_do_global_parameter(lp_ctx, "host msdfs", "true");

	lpcfg_do_global_parameter(lp_ctx, "password level", "0");
	lpcfg_do_global_parameter(lp_ctx, "LargeReadwrite", "True");
	lpcfg_do_global_parameter(lp_ctx, "server min protocol", "CORE");
	lpcfg_do_global_parameter(lp_ctx, "server max protocol", "NT1");
	lpcfg_do_global_parameter(lp_ctx, "client min protocol", "CORE");
	lpcfg_do_global_parameter(lp_ctx, "client max protocol", "NT1");
	lpcfg_do_global_parameter(lp_ctx, "security", "AUTO");
	lpcfg_do_global_parameter(lp_ctx, "EncryptPasswords", "True");
	lpcfg_do_global_parameter(lp_ctx, "ReadRaw", "True");
	lpcfg_do_global_parameter(lp_ctx, "WriteRaw", "True");
	lpcfg_do_global_parameter(lp_ctx, "NullPasswords", "False");
	lpcfg_do_global_parameter(lp_ctx, "ObeyPamRestrictions", "False");

	lpcfg_do_global_parameter(lp_ctx, "TimeServer", "False");
	lpcfg_do_global_parameter(lp_ctx, "BindInterfacesOnly", "False");
	lpcfg_do_global_parameter(lp_ctx, "Unicode", "True");
	lpcfg_do_global_parameter(lp_ctx, "ClientLanManAuth", "False");
	lpcfg_do_global_parameter(lp_ctx, "ClientNTLMv2Auth", "True");
	lpcfg_do_global_parameter(lp_ctx, "LanmanAuth", "False");
	lpcfg_do_global_parameter(lp_ctx, "NTLMAuth", "True");
	lpcfg_do_global_parameter(lp_ctx, "client use spnego principal", "False");

	lpcfg_do_global_parameter(lp_ctx, "UnixExtensions", "False");

	lpcfg_do_global_parameter(lp_ctx, "PreferredMaster", "Auto");
	lpcfg_do_global_parameter(lp_ctx, "LocalMaster", "True");

	lpcfg_do_global_parameter(lp_ctx, "wins support", "False");
	lpcfg_do_global_parameter(lp_ctx, "dns proxy", "True");

	lpcfg_do_global_parameter(lp_ctx, "winbind separator", "\\");
	lpcfg_do_global_parameter(lp_ctx, "winbind sealed pipes", "True");
	lpcfg_do_global_parameter(lp_ctx, "winbindd socket directory", dyn_WINBINDD_SOCKET_DIR);
#if _SAMBA_BUILD_ >= 4
	lpcfg_do_global_parameter(lp_ctx, "winbindd privileged socket directory", dyn_WINBINDD_PRIVILEGED_SOCKET_DIR);
	lpcfg_do_global_parameter(lp_ctx, "ntp signd socket directory", dyn_NTP_SIGND_SOCKET_DIR);
	lpcfg_do_global_parameter_var(lp_ctx, "dns update command", "%s/samba_dnsupdate", dyn_SCRIPTSBINDIR);
	lpcfg_do_global_parameter_var(lp_ctx, "spn update command", "%s/samba_spnupdate", dyn_SCRIPTSBINDIR);
	lpcfg_do_global_parameter_var(lp_ctx, "samba kcc command",
					"%s/samba_kcc", dyn_SCRIPTSBINDIR);
#endif
	lpcfg_do_global_parameter(lp_ctx, "template shell", "/bin/false");
	lpcfg_do_global_parameter(lp_ctx, "template homedir", "/home/%WORKGROUP%/%ACCOUNTNAME%");

	lpcfg_do_global_parameter(lp_ctx, "client signing", "default");
	lpcfg_do_global_parameter(lp_ctx, "server signing", "default");

	lpcfg_do_global_parameter(lp_ctx, "use spnego", "True");

	lpcfg_do_global_parameter(lp_ctx, "use mmap", "True");

	lpcfg_do_global_parameter(lp_ctx, "smb ports", "445 139");
	lpcfg_do_global_parameter(lp_ctx, "nbt port", "137");
	lpcfg_do_global_parameter(lp_ctx, "dgram port", "138");
	lpcfg_do_global_parameter(lp_ctx, "cldap port", "389");
	lpcfg_do_global_parameter(lp_ctx, "krb5 port", "88");
	lpcfg_do_global_parameter(lp_ctx, "kpasswd port", "464");
	lpcfg_do_global_parameter(lp_ctx, "web port", "901");

	lpcfg_do_global_parameter(lp_ctx, "nt status support", "True");

	lpcfg_do_global_parameter(lp_ctx, "max wins ttl", "518400"); /* 6 days */
	lpcfg_do_global_parameter(lp_ctx, "min wins ttl", "10");

	lpcfg_do_global_parameter(lp_ctx, "tls enabled", "True");
	lpcfg_do_global_parameter(lp_ctx, "tls keyfile", "tls/key.pem");
	lpcfg_do_global_parameter(lp_ctx, "tls certfile", "tls/cert.pem");
	lpcfg_do_global_parameter(lp_ctx, "tls cafile", "tls/ca.pem");
	lpcfg_do_global_parameter(lp_ctx, "prefork children:smb", "4");

	lpcfg_do_global_parameter(lp_ctx, "rndc command", "/usr/sbin/rndc");
	lpcfg_do_global_parameter(lp_ctx, "nsupdate command", "/usr/bin/nsupdate -g");

        lpcfg_do_global_parameter(lp_ctx, "allow dns updates", "secure only");
        lpcfg_do_global_parameter(lp_ctx, "dns forwarder", "");

	for (i = 0; parm_table[i].label; i++) {
		if (!(lp_ctx->flags[i] & FLAG_CMDLINE)) {
			lp_ctx->flags[i] |= FLAG_DEFAULT;
		}
	}

	for (parm=lp_ctx->globals->param_opt; parm; parm=parm->next) {
		if (!(parm->priority & FLAG_CMDLINE)) {
			parm->priority |= FLAG_DEFAULT;
		}
	}

	return lp_ctx;
}

/**
 * Initialise the global parameter structure.
 */
struct loadparm_context *loadparm_init_global(bool load_default)
{
	if (global_loadparm_context == NULL) {
		global_loadparm_context = loadparm_init(NULL);
	}
	if (global_loadparm_context == NULL) {
		return NULL;
	}
	global_loadparm_context->global = true;
	if (load_default && !global_loadparm_context->loaded) {
		lpcfg_load_default(global_loadparm_context);
	}
	global_loadparm_context->refuse_free = true;
	return global_loadparm_context;
}

/**
 * Initialise the global parameter structure.
 */
struct loadparm_context *loadparm_init_s3(TALLOC_CTX *mem_ctx, 
					  const struct loadparm_s3_helpers *s3_fns)
{
	struct loadparm_context *loadparm_context = talloc_zero(mem_ctx, struct loadparm_context);
	if (!loadparm_context) {
		return NULL;
	}
	loadparm_context->s3_fns = s3_fns;
	return loadparm_context;
}

const char *lpcfg_configfile(struct loadparm_context *lp_ctx)
{
	return lp_ctx->szConfigFile;
}

const char *lp_default_path(void)
{
    if (getenv("SMB_CONF_PATH"))
        return getenv("SMB_CONF_PATH");
    else
        return dyn_CONFIGFILE;
}

/**
 * Update the internal state of a loadparm context after settings 
 * have changed.
 */
static bool lpcfg_update(struct loadparm_context *lp_ctx)
{
	struct debug_settings settings;
	lpcfg_add_auto_services(lp_ctx, lpcfg_auto_services(lp_ctx));

	if (!lp_ctx->globals->szWINSservers && lp_ctx->globals->bWINSsupport) {
		lpcfg_do_global_parameter(lp_ctx, "wins server", "127.0.0.1");
	}

	if (!lp_ctx->global) {
		return true;
	}

	panic_action = lp_ctx->globals->szPanicAction;

	reload_charcnv(lp_ctx);

	ZERO_STRUCT(settings);
	/* Add any more debug-related smb.conf parameters created in
	 * future here */
	settings.syslog = lp_ctx->globals->syslog;
	settings.syslog_only = lp_ctx->globals->bSyslogOnly;
	settings.timestamp_logs = lp_ctx->globals->bTimestampLogs;
	settings.debug_prefix_timestamp = lp_ctx->globals->bDebugPrefixTimestamp;
	settings.debug_hires_timestamp = lp_ctx->globals->bDebugHiresTimestamp;
	settings.debug_pid = lp_ctx->globals->bDebugPid;
	settings.debug_uid = lp_ctx->globals->bDebugUid;
	settings.debug_class = lp_ctx->globals->bDebugClass;
	debug_set_settings(&settings);

	/* FIXME: This is a bit of a hack, but we can't use a global, since 
	 * not everything that uses lp also uses the socket library */
	if (lpcfg_parm_bool(lp_ctx, NULL, "socket", "testnonblock", false)) {
		setenv("SOCKET_TESTNONBLOCK", "1", 1);
	} else {
		unsetenv("SOCKET_TESTNONBLOCK");
	}

	return true;
}

bool lpcfg_load_default(struct loadparm_context *lp_ctx)
{
    const char *path;

    path = lp_default_path();

    if (!file_exist(path)) {
	    /* We allow the default smb.conf file to not exist, 
	     * basically the equivalent of an empty file. */
	    return lpcfg_update(lp_ctx);
    }

    return lpcfg_load(lp_ctx, path);
}

/**
 * Load the services array from the services file.
 *
 * Return True on success, False on failure.
 */
bool lpcfg_load(struct loadparm_context *lp_ctx, const char *filename)
{
	char *n2;
	bool bRetval;

	filename = talloc_strdup(lp_ctx, filename);

	lp_ctx->szConfigFile = filename;

	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->load(filename);
	}

	lp_ctx->bInGlobalSection = true;
	n2 = standard_sub_basic(lp_ctx, lp_ctx->szConfigFile);
	DEBUG(2, ("lpcfg_load: refreshing parameters from %s\n", n2));

	add_to_file_list(lp_ctx, lp_ctx->szConfigFile, n2);

	/* We get sections first, so have to start 'behind' to make up */
	lp_ctx->currentService = NULL;
	bRetval = pm_process(n2, do_section, do_parameter, lp_ctx);

	/* finish up the last section */
	DEBUG(4, ("pm_process() returned %s\n", BOOLSTR(bRetval)));
	if (bRetval)
		if (lp_ctx->currentService != NULL)
			bRetval = lpcfg_service_ok(lp_ctx->currentService);

	bRetval = bRetval && lpcfg_update(lp_ctx);

	/* we do this unconditionally, so that it happens even
	   for a missing smb.conf */
	reload_charcnv(lp_ctx);

	if (bRetval == true) {
		/* set this up so that any child python tasks will
		   find the right smb.conf */
		setenv("SMB_CONF_PATH", filename, 1);

		/* set the context used by the lp_*() function
		   varients */
		global_loadparm_context = lp_ctx;
		lp_ctx->loaded = true;
	}

	return bRetval;
}

/**
 * Return the max number of services.
 */

int lpcfg_numservices(struct loadparm_context *lp_ctx)
{
	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_numservices();
	}

	return lp_ctx->iNumServices;
}

/**
 * Display the contents of the services array in human-readable form.
 */

void lpcfg_dump(struct loadparm_context *lp_ctx, FILE *f, bool show_defaults,
	     int maxtoprint)
{
	int iService;

	if (lp_ctx->s3_fns) {
		lp_ctx->s3_fns->dump(f, show_defaults, maxtoprint);
		return;
	}

	defaults_saved = !show_defaults;

	dump_globals(lp_ctx, f, show_defaults);

	dump_a_service(lp_ctx->sDefault, lp_ctx->sDefault, f, lp_ctx->flags);

	for (iService = 0; iService < maxtoprint; iService++)
		lpcfg_dump_one(f, show_defaults, lp_ctx->services[iService], lp_ctx->sDefault);
}

/**
 * Display the contents of one service in human-readable form.
 */
void lpcfg_dump_one(FILE *f, bool show_defaults, struct loadparm_service *service, struct loadparm_service *sDefault)
{
	if (service != NULL) {
		if (service->szService[0] == '\0')
			return;
		dump_a_service(service, sDefault, f, NULL);
	}
}

struct loadparm_service *lpcfg_servicebynum(struct loadparm_context *lp_ctx,
					    int snum)
{
	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_servicebynum(snum);
	}

	return lp_ctx->services[snum];
}

struct loadparm_service *lpcfg_service(struct loadparm_context *lp_ctx,
				    const char *service_name)
{
	int iService;
        char *serviceName;

	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_service(service_name);
	}

	for (iService = lp_ctx->iNumServices - 1; iService >= 0; iService--) {
		if (lp_ctx->services[iService] &&
		    lp_ctx->services[iService]->szService) {
			/*
			 * The substitution here is used to support %U is
			 * service names
			 */
			serviceName = standard_sub_basic(
					lp_ctx->services[iService],
					lp_ctx->services[iService]->szService);
			if (strequal(serviceName, service_name)) {
				talloc_free(serviceName);
				return lp_ctx->services[iService];
			}
			talloc_free(serviceName);
		}
	}

	DEBUG(7,("lpcfg_servicenumber: couldn't find %s\n", service_name));
	return NULL;
}

const char *lpcfg_servicename(const struct loadparm_service *service)
{
	return lp_string((const char *)service->szService);
}

/**
 * A useful volume label function.
 */
const char *lpcfg_volume_label(struct loadparm_service *service, struct loadparm_service *sDefault)
{
	const char *ret;
	ret = lp_string((const char *)((service != NULL && service->volume != NULL) ?
				       service->volume : sDefault->volume));
	if (!*ret)
		return lpcfg_servicename(service);
	return ret;
}

/**
 * If we are PDC then prefer us as DMB
 */
const char *lpcfg_printername(struct loadparm_service *service, struct loadparm_service *sDefault)
{
	const char *ret;
	ret = lp_string((const char *)((service != NULL && service->szPrintername != NULL) ?
				       service->szPrintername : sDefault->szPrintername));
	if (ret == NULL || (ret != NULL && *ret == '\0'))
		ret = lpcfg_servicename(service);

	return ret;
}


/**
 * Return the max print jobs per queue.
 */
int lpcfg_maxprintjobs(struct loadparm_service *service, struct loadparm_service *sDefault)
{
	int maxjobs = (service != NULL) ? service->iMaxPrintJobs : sDefault->iMaxPrintJobs;
	if (maxjobs <= 0 || maxjobs >= PRINT_MAX_JOBID)
		maxjobs = PRINT_MAX_JOBID - 1;

	return maxjobs;
}

struct smb_iconv_handle *lpcfg_iconv_handle(struct loadparm_context *lp_ctx)
{
	if (lp_ctx == NULL) {
		return get_iconv_handle();
	}
	return lp_ctx->iconv_handle;
}

_PUBLIC_ void reload_charcnv(struct loadparm_context *lp_ctx)
{
	struct smb_iconv_handle *old_ic = lp_ctx->iconv_handle;
	if (!lp_ctx->global) {
		return;
	}

	if (old_ic == NULL) {
		old_ic = global_iconv_handle;
	}
	lp_ctx->iconv_handle = smb_iconv_handle_reinit_lp(lp_ctx, lp_ctx, old_ic);
	global_iconv_handle = lp_ctx->iconv_handle;
}

_PUBLIC_ char *lpcfg_tls_keyfile(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	return lpcfg_private_path(mem_ctx, lp_ctx, lp_ctx->globals->tls_keyfile);
}

_PUBLIC_ char *lpcfg_tls_certfile(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	return lpcfg_private_path(mem_ctx, lp_ctx, lp_ctx->globals->tls_certfile);
}

_PUBLIC_ char *lpcfg_tls_cafile(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	return lpcfg_private_path(mem_ctx, lp_ctx, lp_ctx->globals->tls_cafile);
}

_PUBLIC_ char *lpcfg_tls_crlfile(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	return lpcfg_private_path(mem_ctx, lp_ctx, lp_ctx->globals->tls_crlfile);
}

_PUBLIC_ char *lpcfg_tls_dhpfile(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	return lpcfg_private_path(mem_ctx, lp_ctx, lp_ctx->globals->tls_dhpfile);
}

struct gensec_settings *lpcfg_gensec_settings(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	struct gensec_settings *settings = talloc_zero(mem_ctx, struct gensec_settings);
	if (settings == NULL)
		return NULL;
	SMB_ASSERT(lp_ctx != NULL);
	settings->lp_ctx = talloc_reference(settings, lp_ctx);
	settings->target_hostname = lpcfg_parm_string(lp_ctx, NULL, "gensec", "target_hostname");
	return settings;
}

int lpcfg_server_role(struct loadparm_context *lp_ctx)
{
	int domain_master = lpcfg__domain_master(lp_ctx);

	return lp_find_server_role(lpcfg__server_role(lp_ctx),
				   lpcfg__security(lp_ctx),
				   lpcfg__domain_logons(lp_ctx),
				   (domain_master == true) ||
				   (domain_master == Auto));
}

int lpcfg_security(struct loadparm_context *lp_ctx)
{
	return lp_find_security(lpcfg__server_role(lp_ctx),
				lpcfg__security(lp_ctx));
}
