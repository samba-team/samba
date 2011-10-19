#include "config.h"
#include <stdio.h> 
#include <unistd.h>
#include <string.h> 
#include <time.h> 
#include <libsmbclient.h> 
#include "get_auth_data_fn.h"


int main(int argc, char * argv[]) 
{ 
    int             debug = 0;
    char            m_time[32];
    char            c_time[32];
    char            a_time[32];
    const char *          pSmbPath = NULL;
    time_t          t = time(NULL);
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
        t = (time_t) strtol(argv[2], NULL, 10);
    }
    else
    {
        printf("usage: "
               "%s [ smb://path/to/file [ mtime ] ]\n",
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
           st.st_mtime, ctime_r(&st.st_mtime, m_time),
           st.st_ctime, ctime_r(&st.st_ctime, c_time),
           st.st_atime, ctime_r(&st.st_atime, a_time)); 
    
    utimbuf.actime = t;         /* unchangable (wont change) */
    utimbuf.modtime = t;        /* this one should succeed */
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
           st.st_mtime, ctime_r(&st.st_mtime, m_time),
           st.st_ctime, ctime_r(&st.st_ctime, c_time),
           st.st_atime, ctime_r(&st.st_atime, a_time)); 
    
    return 0; 
}
