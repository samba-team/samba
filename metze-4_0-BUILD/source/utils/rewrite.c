#include "includes.h"

/*

 this is a set of temporary stub functions used during the samba4 rewrite.
 This file will need to go away before the rewrite is complete.
*/

BOOL become_user_permanently(uid_t uid, gid_t gid)
{ return True; }

BOOL is_setuid_root(void)
{ return False; }

 int share_mode_forall(SHAREMODE_FN(fn))
{ return 0; }

#define BRLOCK_FN(fn) \
	void (*fn)(SMB_DEV_T dev, SMB_INO_T ino, int pid, \
				 enum brl_type lock_type, \
				 br_off start, br_off size)
 int brl_forall(BRLOCK_FN(fn))
{ return 0; }

BOOL locking_end(void)
{ return True; }

BOOL locking_init(int read_only)
{ return True; }

uid_t sec_initial_gid(void)
{ return 0; }
