/* $Id$ */

#ifndef __KAFS_H
#define __KAFS_H

#include <sys/bitypes.h>
#include <sys/cdefs.h>
/* sys/ioctl.h must be included manually before kafs.h */

/*
 */
#define AFSCALL_PIOCTL 20
#define AFSCALL_SETPAG 21

#ifndef _VICEIOCTL
#define _VICEIOCTL(id)  ((unsigned int ) _IOW('V', id, struct ViceIoctl))
#endif /* _VICEIOCTL */

#define VIOCSETTOK _VICEIOCTL(3)
#define VIOCUNLOG  _VICEIOCTL(9)

#define VIOC_FILE_CELL_NAME _VICEIOCTL(30)

struct ViceIoctl {
  caddr_t in, out;
  short in_size;
  short out_size;
};

struct ClearToken {
  int32_t AuthHandle;
  char HandShakeKey[8];
  int32_t ViceId;
  int32_t BeginTimestamp;
  int32_t EndTimestamp;
};

/* Use k_hasafs() to probe if the machine supports AFS syscalls.
   The other functions will generate a SIGSYS if AFS is not supported */

int k_hasafs __P((void));

int k_afsklog __P((char *cell, char *realm));
int k_pioctl __P((char *a_path,
		  int o_opcode,
		  struct ViceIoctl *a_paramsP,
		  int a_followSymlinks));
int k_unlog __P((void));
int k_setpag __P((void));

#define _PATH_VICE		"/usr/vice/etc/"
#define _PATH_THISCELL 		_PATH_VICE "ThisCell"
#define _PATH_CELLSERVDB 	_PATH_VICE "CellServDB"
#define _PATH_THESECELLS	_PATH_VICE "TheseCells"

#endif /* __KAFS_H */
