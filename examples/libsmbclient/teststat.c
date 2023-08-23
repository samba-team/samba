#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <libsmbclient.h>
#include "get_auth_data_fn.h"


int main(int argc, char * argv[])
{
	SMBCCTX *ctx = NULL;
	int             debug = 0;
	char            m_time[32];
	char            c_time[32];
	char            a_time[32];
	const char *          pSmbPath = NULL;
	const char *          pLocalPath = NULL;
	struct stat     st;
	int ret;

	if (argc == 1) {
		pSmbPath = "smb://RANDOM/Public/small";
		pLocalPath = "/random/home/samba/small";
	}
	else if (argc == 2) {
		pSmbPath = argv[1];
		pLocalPath = NULL;
	}
	else if (argc == 3) {
		pSmbPath = argv[1];
		pLocalPath = argv[2];
	} else {
		printf("usage: %s [ smb://path/to/file "
		       "[ /nfs/or/local/path/to/file ] ]\n",
		       argv[0]);
		return 1;
	}

	ctx = smbc_new_context();
	if (ctx == NULL) {
		perror("smbc_new_context failed");
		return 1;
	}

	smbc_setOptionDebugToStderr(ctx, 1);
	smbc_setDebug(ctx, debug);
	smbc_init_context(ctx);
	smbc_setFunctionAuthData(ctx, get_auth_data_fn);

	ret = smbc_getFunctionStat(ctx)(ctx, pSmbPath, &st);
	if (ret < 0) {
		perror("smbc_stat");
		return 1;
	}

	printf("\nSAMBA\n mtime:%lld/%s ctime:%lld/%s atime:%lld/%s\n",
	       (long long)st.st_mtime, ctime_r(&st.st_mtime, m_time),
	       (long long)st.st_ctime, ctime_r(&st.st_ctime, c_time),
	       (long long)st.st_atime, ctime_r(&st.st_atime, a_time));

	if (pLocalPath != NULL) {
		ret = stat(pLocalPath, &st);
		if (ret < 0) {
			perror("stat");
			return 1;
		}

		printf("LOCAL\n mtime:%lld/%s ctime:%lld/%s atime:%lld/%s\n",
		       (long long)st.st_mtime, ctime_r(&st.st_mtime, m_time),
		       (long long)st.st_ctime, ctime_r(&st.st_ctime, c_time),
		       (long long)st.st_atime, ctime_r(&st.st_atime, a_time));
	}

	return 0;
}
