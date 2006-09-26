/**
 *	@file 	mprThread.c
 *	@brief 	Mbedthis Portable Runtime Base Thread Locking Support
 */

/*
 *	@copy	default
 *
 *	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
 *	
 *	This software is distributed under commercial and open source licenses.
 *	You may use the GPL open source license described below or you may acquire 
 *	a commercial license from Mbedthis Software. You agree to be fully bound 
 *	by the terms of either license. Consult the LICENSE.TXT distributed with 
 *	this software for full details.
 *	
 *	This software is open source; you can redistribute it and/or modify it 
 *	under the terms of the GNU General Public License as published by the 
 *	Free Software Foundation; either version 2 of the License, or (at your 
 *	option) any later version. See the GNU General Public License for more 
 *	details at: http://www.mbedthis.com/downloads/gplLicense.html
 *	
 *	This program is distributed WITHOUT ANY WARRANTY; without even the 
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 *	
 *	This GPL license does NOT permit incorporating this software into 
 *	proprietary programs. If you are unable to comply with the GPL, you must
 *	acquire a commercial license to use this software. Commercial licenses 
 *	for this software and support services are available from Mbedthis 
 *	Software at http://www.mbedthis.com 
 *	
 *	@end
 */

#include	"mpr.h"

#if BLD_FEATURE_MULTITHREAD
/************************************ Code ************************************/

void mprInitThreads(MprApp *app)
{
	mprAssert(app);

	if (app->globalLock == 0) {
		app->globalLock = mprCreateLock(app);
		app->allocLock = mprCreateLock(app);
	}
}

/******************************************************************************/

void mprTermThreads(MprApp *app)
{
	mprAssert(app);

	if (app->globalLock) {
		mprDestroyLock(app->globalLock);
		app->globalLock = 0;
	}
	if (app->allocLock) {
		MprLock *lock = app->allocLock;
		app->allocLock = 0;
		mprDestroyLock(lock);
	}
}

/******************************************************************************/

MprLock *mprCreateLock(MprCtx ctx)
{
	MprLock	*lock;

	mprAssert(ctx);

	lock = mprAllocType(ctx, MprLock);

#if BLD_HOST_UNIX
	pthread_mutexattr_t	attr;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
	pthread_mutex_init(&lock->cs, &attr);
	pthread_mutexattr_destroy(&attr);
#elif WIN
	InitializeCriticalSectionAndSpinCount(&lock->cs, 5000);
#elif VXWORKS
	lock->cs = semMCreate(SEM_Q_PRIORITY | SEM_DELETE_SAFE | 
		SEM_INVERSION_SAFE);
	if (lock->cs == 0) {
		mprAssert(0);
		mprFree(lock);
		return 0;
	}
#endif
	return lock;
}

/******************************************************************************/
/*
 *	Destroy a lock. Must be locked on entrance.
 */ 

void mprDestroyLock(MprLock *lock)
{
	mprAssert(lock);
	if (lock == 0) {
		return;
	}

#if BLD_HOST_UNIX
	pthread_mutex_unlock(&lock->cs);
	pthread_mutex_destroy(&lock->cs);
#elif WIN
	DeleteCriticalSection(&lock->cs);
#elif VXWORKS
	semDelete(lock->cs);
#endif
	mprFree(lock);
}

/******************************************************************************/
/*
 *	Lock a mutex
 */ 

void mprLock(MprLock *lock)
{
	/*
	 *	OPT -- Do this just so we can allocate MprApp before we have created its
	 *	lock. Should remove this test here and in mprUnlock.
	 */
	if (lock == 0) {
		return;
	}

#if BLD_HOST_UNIX
	pthread_mutex_lock(&lock->cs);
#elif WIN
	EnterCriticalSection(&lock->cs);
#elif VXWORKS
	semTake(lock->cs, WAIT_FOREVER);
#endif
}

/******************************************************************************/
/*
 *	Try to attain a lock. Do not block!
 */ 

int mprTryLock(MprLock *lock)
{
	mprAssert(lock);

#if BLD_HOST_UNIX
	{
		int		err;

		if ((err = pthread_mutex_trylock(&lock->cs)) != 0) {
			if (err == EBUSY) {
				return MPR_ERR_BUSY;
			} else {
				return MPR_ERR_CANT_ACCESS;
			}
		}
		return 0;
	}
#elif WIN
	if (TryEnterCriticalSection(&lock->cs) == 0) {
		return MPR_ERR_BUSY;
	}
#elif VXWORKS
	{
		int		rc;

		rc = semTake(cs, NO_WAIT);
		if (rc == -1) {
			mprAssert(0);
		}
		if (rc == S_objLib_OBJ_UNAVAILABLE) {
			return MPR_ERR_BUSY;
		} else {
			return MPR_ERR_CANT_ACCESS;
		}
		/* Success */
		return 0;
	}
#endif
	return 0;
}

/******************************************************************************/
/*
 *	Unlock.
 */ 

void mprUnlock(MprLock *lock)
{
	if (lock == 0) {
		return;
	}

#if BLD_HOST_UNIX
	pthread_mutex_unlock(&lock->cs);
#elif WIN
	LeaveCriticalSection(&lock->cs);
#elif VXWORKS
	semGive(lock->cs);
#endif
}

/******************************************************************************/
/*
 *	Big global lock. Avoid using this.
 */

void mprGlobalLock(MprCtx ctx)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	mprAssert(app);

	if (app && app->globalLock) {
		mprLock(app->globalLock);
	}
}

/******************************************************************************/

void mprGlobalUnlock(MprCtx ctx)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	mprAssert(app);

	if (app && app->globalLock) {
		mprUnlock(app->globalLock);
	}
}

/******************************************************************************/

int mprGetCurrentThreadID()
{
#if BLD_HOST_UNIX
	return (int) pthread_self();
#elif WIN
	return GetCurrentThreadId();
#elif VXWORKS
	return (int) pthread_self();
#endif
}

/******************************************************************************/
#endif /* BLD_FEATURE_MULTITHREAD */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
