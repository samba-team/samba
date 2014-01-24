#ifndef __S3_PARAM_H__
#define __S3_PARAM_H__

struct loadparm_s3_helpers
{
	const char * (*get_parametric)(struct loadparm_service *, const char *type, const char *option);
	struct parm_struct * (*get_parm_struct)(const char *param_name);
	void * (*get_parm_ptr)(struct loadparm_service *service, struct parm_struct *parm);
	struct loadparm_service * (*get_service)(const char *service_name);
	struct loadparm_service * (*get_default_loadparm_service)(void);
	struct loadparm_service * (*get_servicebynum)(int snum);
	int (*get_numservices)(void);
	bool (*load)(const char *filename);
	bool (*set_cmdline)(const char *pszParmName, const char *pszParmValue);
	void (*dump)(FILE *f, bool show_defaults, int maxtoprint);
	const char * (*dnsdomain)(void);
	char * (*lp_string)(TALLOC_CTX *ctx, const char *in);
	struct loadparm_global *globals;
};

#endif /* __S3_PARAM_H__ */
