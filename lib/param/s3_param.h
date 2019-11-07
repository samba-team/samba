#ifndef __S3_PARAM_H__
#define __S3_PARAM_H__

struct loadparm_s3_helpers
{
	void * (*get_parm_ptr)(struct loadparm_service *service, struct parm_struct *parm);
	struct loadparm_service * (*get_service)(const char *service_name);
	struct loadparm_service * (*get_servicebynum)(int snum);
	int (*getservicebyname)(const char *, struct loadparm_service *);
	int (*get_numservices)(void);
	bool (*load)(const char *filename);
	bool (*store_cmdline)(const char *pszParmName, const char *pszParmValue);
	void (*dump)(FILE *f, bool show_defaults, int maxtoprint);
	bool (*lp_include)(struct loadparm_context*, struct loadparm_service *,
		       	const char *, char **);
	void (*init_ldap_debugging)(void);
	bool (*set_netbios_aliases)(const char **);
	bool (*do_section)(const char *pszSectionName, void *userdata);
	struct loadparm_global *globals;
	unsigned int *flags;
};

#endif /* __S3_PARAM_H__ */
