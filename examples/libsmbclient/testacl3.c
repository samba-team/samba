#include <sys/types.h>
#include <stdio.h> 
#include <unistd.h>
#include <string.h> 
#include <time.h> 
#include <errno.h>
#include <libsmbclient.h> 
#include "get_auth_data_fn.h"


int main(int argc, char * argv[]) 
{ 
    int             ret;
    int             debug = 0;
    char            value[2048]; 
    char            path[2048];
    char *          the_acl;
    char *          p;
    SMBCCTX *       context;
    
    smbc_init(get_auth_data_fn, debug); 
    
    context = smbc_set_context(NULL);
    smbc_setOptionFullTimeNames(context, 1);
    
    for (;;)
    {
        fprintf(stdout, "Path: ");
        *path = '\0';
        p = fgets(path, sizeof(path) - 1, stdin);
	if (p == NULL) {
		printf("Error reading from stdin\n");
		return 1;
	}
        if (strlen(path) == 0)
        {
            return 0;
        }

        p = path + strlen(path) - 1;
        if (*p == '\n')
        {
            *p = '\0';
        }
    
        the_acl = strdup("system.nt_sec_desc.*+");
        ret = smbc_getxattr(path, the_acl, value, sizeof(value));
        if (ret < 0)
        {
            printf("Could not get attributes for [%s] %d: %s\n",
                   path, errno, strerror(errno));
            return 1;
        }
    
        printf("Attributes for [%s] are:\n%s\n", path, value);
    }

    return 0; 
}
