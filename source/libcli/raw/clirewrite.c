#include "includes.h"

/*

 this is a set of temporary stub functions used during the libsmb rewrite.
 This file will need to go away before the rewrite is complete.
*/

void become_root(void)
{}

void unbecome_root(void)
{}

BOOL become_user_permanently(uid_t uid, gid_t gid)
{ return True; }

void set_effective_uid(uid_t uid)
{}

uid_t sec_initial_uid(void)
{ return 0; }
