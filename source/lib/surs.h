#ifndef _SURS_H_
#define _SURS_H_

typedef enum 
{
	SURS_POSIX_UID_AS_USR,
	SURS_POSIX_GID_AS_GRP,
	SURS_POSIX_GID_AS_ALS
} posix_type;

typedef struct _surs_posix_id
{
	uint32 id;
	posix_type type;
}
POSIX_ID;

#endif /* _SURS_H_ */
