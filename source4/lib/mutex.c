/* 
   Unix SMB/CIFS implementation.
   Samba mutex/lock functions
   Copyright (C) Andrew Tridgell 2003
   Copyright (C) James J Myers 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
#include "includes.h"
	 
static smb_mutex_t mutex_list[MUTEX_MAX];

/* the registered mutex handlers */
static struct {
	const char *name;
	struct mutex_ops ops;
} mutex_handlers;

int mutex_lock_by_id(enum mutex_id id, const char *name)
{
	return mutex_lock(&mutex_list[id], name);
}

int mutex_unlock_by_id(enum mutex_id id, const char *name)
{
	return mutex_unlock(&mutex_list[id], name);
}

int mutex_init(smb_mutex_t *mutex, const char *name)
{
	if (mutex_handlers.ops.mutex_init) {
		return mutex_handlers.ops.mutex_init(mutex, name);
	}
	return 0;
}

int mutex_destroy(smb_mutex_t *mutex, const char *name)
{
	if (mutex_handlers.ops.mutex_destroy) {
		return mutex_handlers.ops.mutex_destroy(mutex, name);
	}
	return 0;
}

int mutex_lock(smb_mutex_t *mutex, const char *name)
{
	if (mutex_handlers.ops.mutex_lock) {
		return mutex_handlers.ops.mutex_lock(mutex, name);
	}
	return 0;
}

int mutex_unlock(smb_mutex_t *mutex, const char *name)
{
	if (mutex_handlers.ops.mutex_unlock) {
		return mutex_handlers.ops.mutex_unlock(mutex, name);
	}
	return 0;
}

/* read/write lock routines */

int rwlock_init(smb_rwlock_t *rwlock, const char *name)
{
	if (mutex_handlers.ops.rwlock_init) {
		return mutex_handlers.ops.rwlock_init(rwlock, name);
	}
	return 0;
}

int rwlock_destroy(smb_rwlock_t *rwlock, const char *name)
{
	if (mutex_handlers.ops.rwlock_destroy) {
		return mutex_handlers.ops.rwlock_destroy(rwlock, name);
	}
	return 0;
}

int rwlock_lock_write(smb_rwlock_t *rwlock, const char *name)
{
	if (mutex_handlers.ops.rwlock_lock_write) {
		return mutex_handlers.ops.rwlock_lock_write(rwlock, name);
	}
	return 0;
}

int rwlock_lock_read(smb_rwlock_t *rwlock, const char *name)
{
	if (mutex_handlers.ops.rwlock_lock_read) {
		return mutex_handlers.ops.rwlock_lock_read(rwlock, name);
	}
	return 0;
}

int rwlock_unlock(smb_rwlock_t *rwlock, const char *name)
{
	if (mutex_handlers.ops.rwlock_unlock) {
		return mutex_handlers.ops.rwlock_unlock(rwlock, name);
	}
	return 0;
}


/*
  register a set of mutex/rwlock handlers. 
  Should only be called once in the execution of smbd.
*/
BOOL register_mutex_handlers(const char *name, struct mutex_ops *ops)
{
	if (mutex_handlers.name != NULL) {
		/* it's already registered! */
		DEBUG(2,("mutex handler '%s' already registered - failed '%s'\n", 
			 mutex_handlers.name, name));
		return False;
	}

	mutex_handlers.name = name;
	mutex_handlers.ops = *ops;

	if (mutex_handlers.ops.mutex_init) {
		enum mutex_id id;
		for (id=0; id < MUTEX_MAX; id++) {
			mutex_handlers.ops.mutex_init(&mutex_list[id], "mutex_list");
		}
	}

	DEBUG(2,("mutex handler '%s' registered\n", name));
	return True;
}

