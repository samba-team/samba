/* 
 * This file is only used with AIX 
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include <sys/types.h>
#include "kafs.h"
#include "afssysdefs.h"

int
aix_pioctl(char *a_path,
	   int o_opcode,
	   struct ViceIoctl *a_paramsP,
	   int a_followSymlinks)
{
    return lpioctl(a_path, o_opcode, a_paramsP, a_followSymlinks);
}

int
aix_setpag(void)
{
    return lsetpag();
}
