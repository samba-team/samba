#include <stdio.h> 
#include <unistd.h>
#include <string.h> 
#include <time.h> 
#include <libsmbclient.h> 
#include "get_auth_data_fn.h"


int main(int argc, char * argv[]) 
{ 
    int             ret;
    int             debug = 0;
    int             mode = 0666;
    char            buffer[16384]; 
    char            mtime[32];
    char            ctime[32];
    char            atime[32];
    char *          pSmbPath = NULL;
    struct tm       tm;
    struct stat     st;
    struct utimbuf  utimbuf;
    
    if (argc == 1)
    {
        pSmbPath = "smb://RANDOM/Public/small";
    }
    else if (argc == 2)
    {
        pSmbPath = argv[1];
    }
    else if (argc == 3)
    {
        pSmbPath = argv[1];
        mode = (int) strtol(argv[2], NULL, 8);
    }
    else
    {
        printf("usage: "
               "%s [ smb://path/to/file [ octal_mode ] ]\n",
               argv[0]);
        return 1;
    }

    smbc_init(get_auth_data_fn, debug); 
    
    if (smbc_stat(pSmbPath, &st) < 0)
    {
        perror("smbc_stat");
        return 1;
    }
    
    printf("Before\n mtime:%lu/%s ctime:%lu/%s atime:%lu/%s\n",
           st.st_mtime, ctime_r(&st.st_mtime, mtime),
           st.st_ctime, ctime_r(&st.st_ctime, ctime),
           st.st_atime, ctime_r(&st.st_atime, atime)); 
    
    utimbuf.actime = st.st_atime - 120;  /* unchangable (wont change) */
    utimbuf.modtime = st.st_mtime - 120; /* this one should succeed */
    if (smbc_utime(pSmbPath, &utimbuf) < 0)
    {
        perror("smbc_utime");
        return 1;
    }

    if (smbc_stat(pSmbPath, &st) < 0)
    {
        perror("smbc_stat");
        return 1;
    }
    
    printf("After\n mtime:%lu/%s ctime:%lu/%s atime:%lu/%s\n",
           st.st_mtime, ctime_r(&st.st_mtime, mtime),
           st.st_ctime, ctime_r(&st.st_ctime, ctime),
           st.st_atime, ctime_r(&st.st_atime, atime)); 
    
    return 0; 
}
