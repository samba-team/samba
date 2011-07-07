#define LOADPARM_EXTRA_LOCALS				\
	struct parmlist_entry *param_opt;		\
	char *szService;				\
	char *szCopy;					\
	char *szInclude;				\
	char *szPrintername;				\
	int bAvailable;					\
	int iMaxPrintJobs;				\
	char *volume;					\
	struct bitmap *copymap;				\
	char dummy[3];		/* for alignment */

#include "param_local.h"
