/**
 *	@file mprAlloc.c 
 *	@brief Memory Allocation
 *	@overview 
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

/********************************* Includes ***********************************/

#define 	UNSAFE_FUNCTIONS_OK 1

#include	"mpr.h"

/******************************* Local Defines ********************************/
/*
 *	Set to 1 to disable slab based allocations
 */
#define NO_SLAB 				0

/*
 *	Validation mode is quite slow
 */
#define VALIDATE_ALLOC			0
#if VALIDATE_ALLOC
#define VALIDATE_BLOCK(ptr)		mprValidateBlock(ptr)
#else
#define VALIDATE_BLOCK(ptr) 			
#endif

/*
 *	Align on 4 bytes if squeeze, Otherwize on 16 bytes.
 */
#define HDR_SIZE 				MPR_BLK_HDR_SIZE

#define APP_MAGIC 				0xa571cb80
#define ALLOC_MAGIC 			0xe814ecc0

/*
 *	This must be at least one word to ensure that the smallest allocation is
 *	4 bytes. Slab allocations need at least one word to store their next ptr.
 */
#define ALLOC_ALIGN(x) 			(((x)+3)&~3)
#define GET_HDR(ptr) 			((MprBlk*) (((char*) (ptr)) - HDR_SIZE))
#define GET_PTR(bp) 			((void*) (((char*) (bp)) + HDR_SIZE))
#define VALID_HDR(bp) 			(((bp)->flags & ~0x3F) == ALLOC_MAGIC)
#define VALID_BLK(ptr) 			(VALID_HDR(GET_HDR(ptr)))

/*
 *	In production releases, mprAssert will compile out (not be included)
 *	but CHECK_HDR will remain even in production builds.
 */
#define CHECK_HDR(bp) \
	if (1) { if (! VALID_HDR(bp)) { mprAllocAbort(); } } else

/*
 *	Chunk the slabs into 32 byte increments.
 *	This allows for allocations up to 512 bytes via slabs and maximizes
 *	sharing of slab allocations.
 *
 *	Index map:
 *	 	 0 ==  32  bytes
 *		 1 ==  64  bytes
 *		 2 ==  96  bytes
 *		 3 ==  128 bytes
 *		 4 ==  160 bytes
 *		 5 ==  192 bytes
 *		 6 ==  224 bytes
 *		 7 ==  256 bytes
 *		 8 ==  288 bytes
 *		 9 ==  320 bytes
 *		10 ==  352 bytes
 *		11 ==  384 bytes
 *		12 ==  416 bytes
 *		13 ==  448 bytes
 *		14 ==  480 bytes
 *		15 ==  512 bytes
 */
#define SLAB_ALIGN(size) 		((size + 31) & ~31)
#define GET_SLAB(size)			(size >> 6)

/*
 *	Block flags
 */
#define ALLOC_FLAGS_FREE			0x1		/* Block is free */
#define ALLOC_FLAGS_FREEING			0x2		/* Block is being freed */
#define ALLOC_FLAGS_SLAB_BLOCK		0x4		/* Block was allocated from slab */
#define ALLOC_FLAGS_REQUIRED		0x8		/* Block is required by alloc */
#define ALLOC_FLAGS_KEEP			0x10	/* Keep block - don't mprFree */
#define ALLOC_FLAGS_DONT_OS_FREE	0x20	/* Don't return mem to O/S */
#define ALLOC_FLAGS_IS_SLAB			0x40	/* Block is a slab */

#if BLD_DEBUG && !BREW
/*
 *	Set this address to break when this address is allocated or freed. This is
 *	a block address (not a user ptr).
 */
static MprBlk *stopAlloc;
#endif

#if !BREW
static MprCtx rootCtx;						/* Root context if none supplied */
#endif

/***************************** Forward Declarations ***************************/

static int mprAllocException(MPR_LOC_DEC(ptr, loc), uint size, bool granted);
static void slabFree(MprBlk *bp);
static int	growSlab(MPR_LOC_DEC(ctx, loc), MprSlab *slab, uint size, uint inc);

/******************************************************************************/
/*
 *	Put first in file so it is easy to locate in a debugger
 */

void mprBreakpoint(const char *loc, const char *msg)
{
}

/******************************************************************************/
#if (WIN || BREW_SIMULATOR) && BLD_DEBUG

int crtReportHook(int type, char *msg, int *retval)
{
	printf("%s\n", msg);
	*retval = 0;
	return TRUE;
}

#endif
/******************************************************************************/
/*
 *	Initialize the memory subsystem
 */

MprApp *mprAllocInit(MprAllocCback cback)
{
	MprAllocStats	*stats;
	MprApp			*app;
	MprSlab			*slab;
	MprBlk			*bp, *sp;
	int				i;

	bp = malloc(sizeof(MprApp) + HDR_SIZE);
	mprAssert(bp);
	if (bp == 0) {
		if (cback) {
			(*cback)(0, sizeof(MprApp), 0, 0);
		}
		return 0;
	}
	memset(bp, 0, sizeof(MprApp) + HDR_SIZE);

	bp->parent = bp;
	bp->size = sizeof(MprApp);
	bp->flags = ALLOC_MAGIC;
	bp->next = bp->prev = bp;

#if BLD_FEATURE_ALLOC_LEAK_TRACK
	bp->location = MPR_LOC;
#endif

	app = (MprApp*) GET_PTR(bp);
	app->magic = APP_MAGIC;

	app->alloc.cback = cback;
	app->stackStart = (void*) &app;

	bp->app = app;

	app->alloc.slabs = mprAllocZeroedBlock(MPR_LOC_PASS(app, MPR_LOC), 
		sizeof(MprSlab) * MPR_MAX_SLAB);
	if (app->alloc.slabs == 0) {
		mprFree(app);
		return 0;
	}

	/*
	 *	The slab control structures must not be freed. Set keep to safeguard
	 *	against accidents.
	 */
	sp = GET_HDR(app->alloc.slabs);
	sp->flags |= ALLOC_FLAGS_KEEP;

	for (i = 0; i < MPR_MAX_SLAB; i++) {
		/*
		 *	This is overriden by requestors calling slabAlloc
		 */
		slab = &app->alloc.slabs[i];
		slab->preAllocateIncr = MPR_SLAB_DEFAULT_INC;
	}

	/*
	 *	Keep aggregated stats even in production code
	 */
	stats = &app->alloc.stats;
	stats->bytesAllocated += sizeof(MprApp);
	if (stats->bytesAllocated > stats->peakAllocated) {
		stats->peakAllocated = stats->bytesAllocated;
	}
	stats->allocCount++;

#if !BREW
	rootCtx = app;
#endif
#if (WIN || BREW_SIMULATOR) && BLD_DEBUG
	_CrtSetReportHook(crtReportHook);
#endif
	return app;
}

/******************************************************************************/
/*
 *	Terminate the alloc module
 */

void mprAllocTerm(MprApp *app)
{
	MprSlab		*slabs;
	MprBlk		*appBlk, *slabBlk;

	/*
 	 *	Must do a carefully ordered cleanup. Need to free all children blocks
	 *	before freeing the slab memory. Save a local pointer to the slabs.
	 */
	slabs = app->alloc.slabs;

	/*
	 *	Free the app and all children. Set DONT_OS_FREE to prevent free() being
	 *	called on app itself. We need that so we can free the slabs below.
	 */
	appBlk = GET_HDR(app);
	appBlk->flags |= ALLOC_FLAGS_DONT_OS_FREE;
	mprFree(app);

	/*
	 *	Slabs are initially marked don't free. We must preserve them while all
	 *	other blocks are freed. Then we clear the don't free flag and free.
 	 *	Now we don't have an app structure which is used by mprFree. We must
	 *	fake it.
	 */
	slabBlk = GET_HDR(slabs);
	slabBlk->flags &= ~ALLOC_FLAGS_KEEP;
	mprFree(slabs);

	/*
	 *	Now we can finally free the memory for the app structure
	 */
	free(appBlk);
}

/******************************************************************************/
/*
 *	Allocate a block
 */

void *mprAllocBlock(MPR_LOC_DEC(ctx, loc), uint size)
{
	MprAllocStats	*stats;
	MprBlk			*bp, *parent;
	MprApp			*app;
	int				diff;

	mprAssert(size > 0);

	if (ctx == 0) {
#if BREW
		mprAssert(ctx);
		return 0;
#else
		ctx = rootCtx;
#endif
	}
	if (size == 0) {
		size = 1;
	}

	mprAssert(VALID_BLK(ctx));
	parent = GET_HDR(ctx);
	mprAssert(VALID_HDR(parent));

	CHECK_HDR(parent);

	size = ALLOC_ALIGN(size);

	app = parent->app;

	stats = &app->alloc.stats;

	mprLock(app->allocLock);

	stats->bytesAllocated += size + HDR_SIZE;
	if (stats->bytesAllocated > stats->peakAllocated) {
		stats->peakAllocated = stats->bytesAllocated;
	}

	/*
	 *	Prevent allocation if over the maximum
 	 */
	if (stats->maxMemory && stats->bytesAllocated > stats->maxMemory) {
		stats->bytesAllocated -= (size + HDR_SIZE);
		mprUnlock(app->allocLock);
		if (mprAllocException(MPR_LOC_PASS(ctx, loc), size, 0) < 0) {
			return 0;
		}
		mprLock(app->allocLock);
	}

	if ((bp = malloc(size + HDR_SIZE)) == 0) {
		mprAssert(bp);
		stats->errors++;
		mprUnlock(app->allocLock);
		mprAllocException(MPR_LOC_PASS(ctx, loc), size, 0);
		return 0;
	}

#if BLD_DEBUG
	memset(bp, 0xf7, size + HDR_SIZE);
#endif

#if BLD_DEBUG && !BREW
	if (bp == stopAlloc) {
		mprBreakpoint(MPR_LOC, "breakOnAddr");
	}
#endif

	/*
	 *	Warn if allocation puts us over the red line
 	 */
	if (stats->redLine && stats->bytesAllocated > stats->redLine) {
		mprUnlock(app->allocLock);
		if (mprAllocException(MPR_LOC_PASS(ctx, loc), size, 1) < 0) {
			return 0;
		}
		mprLock(app->allocLock);
	}

	bp->size = size;
	bp->flags = ALLOC_MAGIC;
	bp->destructor = 0;

	bp->parent = parent;

	if (parent->children == 0) {
		parent->children = bp;
		bp->next = bp->prev = bp;

	} else {
		/*
		 *	Append to the end of the list. Preserve alloc order
		 */
		bp->next = parent->children;
		bp->prev = parent->children->prev;
		parent->children->prev->next = bp;
		parent->children->prev = bp;
	}

	bp->children = 0;

#if BLD_FEATURE_ALLOC_LEAK_TRACK
	bp->location = loc;
#endif

	bp->app = parent->app;

	VALIDATE_BLOCK(GET_PTR(bp));

	stats->allocCount++;

	/*
 	 *	Monitor stack usage
 	 */
	diff = (int) bp->app->stackStart - (int) &stats;
	if (diff < 0) {
		app->maxStack -= diff;
		app->stackStart = (void*) &stats;
		diff = 0;
	}

	if ((uint) diff > app->maxStack) {
		app->maxStack = diff;
	}
	mprUnlock(app->allocLock);

	return GET_PTR(bp);
}

/******************************************************************************/
/*
 *	Allocate and zero a block
 */

void *mprAllocZeroedBlock(MPR_LOC_DEC(ctx, loc), uint size)
{
	void	*newBlock;

	MprBlk	*bp;

	bp = GET_HDR(ctx);
	mprAssert(VALID_BLK(ctx));

	newBlock = mprAllocBlock(MPR_LOC_PASS(ctx, loc), size);
	if (newBlock) {
		memset(newBlock, 0, size);
	}
	return newBlock;
}

/******************************************************************************/
/*
 *	Free a block of memory. Free all children recursively.
 */

int mprFree(void *ptr)
{
	MprAllocStats	*stats;
	MprBlk			*bp, *parent, *cp, *firstChild, *prev;
	MprApp			*app;

	if (ptr == 0) {
		return 0;
	}

	mprAssert(VALID_BLK(ptr));
	VALIDATE_BLOCK(ptr);

	bp = GET_HDR(ptr);

#if BLD_DEBUG && !BREW
	if (bp == stopAlloc) {
		mprBreakpoint(MPR_LOC, "breakOnAddr");
	}
#endif

	mprAssert(bp);
	mprAssert(VALID_HDR(bp));

	CHECK_HDR(bp);

	/*
 	 *	Test if already freed
 	 */
	mprAssert(! (bp->flags & ALLOC_FLAGS_FREE));
	if (bp->flags & ALLOC_FLAGS_FREE) {
		return 0;
	}

	/*
	 *	Return if recursive freeing or this is a permanent block
	 */
	app = bp->app;
	mprLock(app->allocLock);
	if (bp->flags & (ALLOC_FLAGS_FREEING | ALLOC_FLAGS_KEEP)) {
		mprUnlock(app->allocLock);
		return 0;
	}
	bp->flags |= ALLOC_FLAGS_FREEING;


	/*
 	 *	Call any destructors
	 */
	if (bp->destructor) {
		mprUnlock(app->allocLock);
		if ((bp->destructor)(ptr) < 0) {
			return -1;
		}
		mprLock(app->allocLock);
		bp->destructor = 0;
	}

	/*
	 *	Free the children. Free in reverse order so firstChild is preserved
 	 *	during the list scan as an end of list marker.
	 */
	if ((firstChild = bp->children) != 0) {
		cp = firstChild->prev;
		while (cp != firstChild) {

			mprAssert(VALID_HDR(cp));
			VALIDATE_BLOCK(GET_PTR(cp));

			prev = cp->prev;

			/*
			 *	FUTURE - OPT. Make this inline 
			 */
			mprFree(GET_PTR(cp));

			cp = prev;
		}

		mprFree(GET_PTR(firstChild));

		/*
		 *	Just for clarity
		 */
		bp->children = 0;
	}

	parent = bp->parent;

	mprAssert(VALID_HDR(parent));

	/*
	 *	Unlink from the parent
	 */
	if (parent->children == bp) {
		if (bp->next == bp) {
			parent->children = 0;
		} else {
			parent->children = bp->next;
		}
	}

	/*
	 *	Remove from the sibling chain
	 */
	bp->prev->next = bp->next;
	bp->next->prev = bp->prev;

	bp->flags |= ALLOC_FLAGS_FREE;

	/*
	 *	Release the memory. If from a slab, return to the slab. Otherwise, 
	 *	return to the O/S.
	 */
	if (bp->flags & ALLOC_FLAGS_SLAB_BLOCK) {
		slabFree(bp);

	} else {
		mprAssert(bp);

		/*
		 *	Update the stats
		 */
		stats = &bp->app->alloc.stats;
		stats->bytesAllocated -= (bp->size + HDR_SIZE);
		mprAssert(stats->bytesAllocated >= 0);

		stats->allocCount--;
		mprAssert(stats->allocCount >= 0);

#if BLD_DEBUG && !BREW
		if (bp == stopAlloc) {
			mprBreakpoint(MPR_LOC, "breakOnAddr");
		}
#endif

		/*
		 *	Return to the O/S
		 */
		if (! (bp->flags & ALLOC_FLAGS_DONT_OS_FREE)) {
			free(bp);
		}
	}
	/* OPT */
	if (app != ptr) {
		mprUnlock(app->allocLock);
	}

	return 0;
}

/******************************************************************************/
/*
 *	Rallocate a block
 */

void *mprReallocBlock(MPR_LOC_DEC(ctx, loc), void *ptr, uint size)
{
	MprBlk	*bp, *newbp, *firstChild, *cp;
	MprApp	*app;
	void	*newPtr;

	mprAssert(VALID_BLK(ctx));
	mprAssert(size > 0);

	if (ptr == 0) {
		return mprAllocBlock(MPR_LOC_PASS(ctx, loc), size);
	}
	
	mprAssert(VALID_BLK(ptr));
	bp = GET_HDR(ptr);
	mprAssert(bp);
	mprAssert(VALID_HDR(bp));

	CHECK_HDR(bp);

	if (size < bp->size) {
		return ptr;
	}

	newPtr = mprAllocBlock(MPR_LOC_PASS(ctx, loc), size);
	if (newPtr == 0) {
		bp->flags &= ~ALLOC_FLAGS_FREE;
		free(bp);
		return 0;
	}

	newbp = GET_HDR(newPtr);
	mprAssert(newbp->size >= size);
	memcpy((char*) newbp + HDR_SIZE, (char*) bp + HDR_SIZE, bp->size);
	mprAssert(newbp->size >= size);

	/* 
	 *	Fix the next / prev pointers
 	 */
	app = bp->app;
	mprLock(app->allocLock);
	newbp->next->prev = newbp;
	newbp->prev->next = newbp;

	/*
	 *	Need to fix the parent pointer of all children
 	 */
	if ((firstChild = newbp->children) != 0) {
		cp = firstChild;
		do {
			cp->parent = newbp;
			cp = cp->next;
		} while (cp != firstChild);
	}

	/*
	 *	May need to set the children pointer of our parent
 	 */
	if (newbp->parent->children == bp) {
		newbp->parent->children = newbp;
	}

	/*
 	 *	Free the original block
	 */
	mprFree(ptr);

	mprUnlock(app->allocLock);

	return GET_PTR(newbp);
}

/******************************************************************************/
/*
 *	Allocate a block from a slab
 */

void *mprSlabAllocBlock(MPR_LOC_DEC(ctx, loc), uint size, uint inc)
{

#if NO_SLAB
	return mprAllocBlock(MPR_LOC_PASS(ctx, loc), size);
#else

	MprBlk			*parent, *bp;
	MprSlabBlock	*sb;
	MprApp			*app;
	MprSlab			*slab;
	int				slabIndex;

	if (ctx == 0) {
		mprAssert(ctx);
		return 0;
	}

	mprAssert(size > 0);
	mprAssert(VALID_BLK(ctx));

	parent = GET_HDR(ctx);
	mprAssert(VALID_HDR(parent));

	CHECK_HDR(parent);

	size = SLAB_ALIGN(size);

	app = parent->app;
	mprAssert(app);

	slabIndex = GET_SLAB(size);

	if (slabIndex < 0 || slabIndex >= MPR_MAX_SLAB) {
		return mprAllocBlock(MPR_LOC_PASS(ctx, loc), size);
	}

	/*
 	 *	Dequeue a block from the slab. "sb" will point to the user data
	 *	portion of the block (i.e. after the MprBlk header). Slabs must be 
	 *	allocated off the "slabs" context to ensure they don't get freed 
	 *	until after all other blocks are freed.
	 */
	mprLock(app->allocLock);
	slab = &app->alloc.slabs[slabIndex];
	if ((sb = slab->next) == 0) {
		if (growSlab(MPR_LOC_ARGS(parent->app->alloc.slabs), 
				slab, size, inc) < 0) {
			mprUnlock(app->allocLock);
			return 0;
		}
		sb = slab->next;
	}
	mprAssert(sb);

	/*
 	 *	Dequeue the block
	 */
	slab->next = sb->next;

#if BLD_FEATURE_ALLOC_STATS
{
	MprSlabStats	*slabStats;
	/*
	 *	Update the slab stats
	 */
	slabStats = &slab->stats;
	slabStats->totalAllocCount++;
	slabStats->freeCount--;
	slabStats->allocCount++;
	if (slabStats->allocCount > slabStats->peakAllocCount) {
		slabStats->peakAllocCount = slabStats->allocCount;
	}
}
#endif /* BLD_FEATURE_ALLOC_STATS */

	bp = GET_HDR(sb);

#if BLD_DEBUG && !BREW
	if (bp == stopAlloc) {
		mprBreakpoint(MPR_LOC, "breakOnAddr");
	}
#endif

	bp->size = size;
	bp->flags = ALLOC_MAGIC | ALLOC_FLAGS_SLAB_BLOCK;
	bp->destructor = 0;

	bp->parent = parent;

	if (parent->children == 0) {
		parent->children = bp;
		bp->next = bp->prev = bp;

	} else {
		/*
		 *	Append to the end of the list. Preserve alloc order
		 */
		bp->next = parent->children;
		bp->prev = parent->children->prev;
		parent->children->prev->next = bp;
		parent->children->prev = bp;
	}

	bp->children = 0;

	bp->app = app;

#if BLD_FEATURE_ALLOC_LEAK_TRACK
	bp->location = loc;
#endif
	mprUnlock(app->allocLock);

	return GET_PTR(bp);
#endif
}

/******************************************************************************/
/*
 *	Return a block back to its slab
 */

static void slabFree(MprBlk *bp)
{
	MprSlab			*slab;
	MprApp			*app;
	void			*ptr;
	int				slabIndex;

	mprAssert(VALID_HDR(bp));

	slabIndex = GET_SLAB(bp->size);
	mprAssert(0 <= slabIndex && slabIndex < MPR_MAX_SLAB);

	if (0 <= slabIndex && slabIndex < MPR_MAX_SLAB) {
		mprLock(bp->app->allocLock);
		slab = &bp->app->alloc.slabs[slabIndex];
		app = bp->app;

#if BLD_DEBUG
		memset(bp, 0xfc, bp->size + HDR_SIZE);
#endif

		ptr = GET_PTR(bp);
		((MprSlabBlock*) ptr)->next = slab->next;
		slab->next = ((MprSlabBlock*) ptr);

#if BLD_FEATURE_ALLOC_STATS
{
		MprSlabStats	*slabStats;
		slabStats = &slab->stats;

		slabStats->freeCount++;
		slabStats->allocCount--;

		if (slabStats->freeCount >= slabStats->peakFreeCount) {
			slabStats->peakFreeCount = slabStats->freeCount;
		}
}
#endif
		mprUnlock(app->allocLock);
	}
}

/******************************************************************************/
/*
 *	Grow the slab and return the next free block
 *	Must be called locked.
 */

static int growSlab(MPR_LOC_DEC(ctx, loc), MprSlab *slab, uint size, uint inc)
{
	MprBlk			*bp;
	MprSlabBlock	*sb;
	int				i, chunkSize, len;

	mprAssert(VALID_BLK(ctx));
	mprAssert(slab);
	mprAssert(size > 0);

	/*
 	 *	Take the maximum requested by anyone
	 */
	slab->preAllocateIncr = max(slab->preAllocateIncr, inc);

	/*
	 *	We allocate an array of blocks each of user "size" bytes.
	 */
	chunkSize = HDR_SIZE + size;
	len = chunkSize * slab->preAllocateIncr;
	bp = mprAllocBlock(MPR_LOC_PASS(ctx, loc), len);

#if BLD_DEBUG
	memset(bp, 0xf1, len);
#endif

	if (bp == 0) {
		mprAssert(0);
		return MPR_ERR_MEMORY;
	}
	bp->flags |= ALLOC_FLAGS_IS_SLAB;

	/*
 	 *	We store the slab information in the user data portion
	 */
	sb = (MprSlabBlock*) GET_PTR(bp);


	sb = (MprSlabBlock*) ((char*) sb + len - chunkSize);
	for (i = slab->preAllocateIncr - 1; i >= 0; i--) {
		sb->next = slab->next;
		slab->next = sb;
		sb = (MprSlabBlock*) ((char*) sb - chunkSize);
	}

#if BLD_FEATURE_ALLOC_STATS
{
	MprSlabStats	*stats;
	stats = &slab->stats;
	stats->freeCount += slab->preAllocateIncr;
	if (stats->freeCount > stats->peakFreeCount) {
		stats->peakFreeCount = stats->freeCount;
	}
}
#endif

	return 0;
}

/******************************************************************************/
/*
 *	Set the pre-allocate amount
 */

int mprSetSlabPreAllocate(MprCtx ctx, int slabIndex, int preAllocateIncr)
{
	MprApp		*app;
	MprSlab		*slab;

	mprAssert(VALID_BLK(ctx));
	mprAssert(0 <= slabIndex && slabIndex < MPR_MAX_SLAB);
	mprAssert(preAllocateIncr > 0);

	if (0 <= slabIndex && slabIndex < MPR_MAX_SLAB) {
		app = mprGetApp(ctx);
		slab = &app->alloc.slabs[slabIndex];
		slab->preAllocateIncr = preAllocateIncr;
	} else {
		return MPR_ERR_BAD_ARGS;
	}
	return 0;
}

/******************************************************************************/

void *mprSlabAllocZeroedBlock(MPR_LOC_DEC(ctx, loc), uint size, uint inc)
{
	void	*newBlock;

	mprAssert(VALID_BLK(ctx));
	mprAssert(size > 0);

	newBlock = mprSlabAllocBlock(MPR_LOC_PASS(ctx, loc), size, inc);
	if (newBlock) {
		memset(newBlock, 0, size);
	}
	return newBlock;
}

/******************************************************************************/
/*
 *	Internal strdup function. Will use the slab allocator for small strings
 */

char *mprStrdupInternal(MPR_LOC_DEC(ctx, loc), const char *str)
{
	char	*newp;
	int		len;

	mprAssert(VALID_BLK(ctx));

	if (str == 0) {
		str = "";
	}

	len = strlen(str) + 1;

	if (len < MPR_SLAB_STR_MAX) {
		newp = mprSlabAllocBlock(MPR_LOC_PASS(ctx, loc), MPR_SLAB_STR_MAX,
			MPR_SLAB_STR_INC);
	} else {
		newp = mprAllocBlock(MPR_LOC_PASS(ctx, loc), len);
	}

	if (newp) {
		memcpy(newp, str, len);
	}

	return newp;
}

/******************************************************************************/
/*
 *	Internal strndup function. Will use the slab allocator for small strings
 */

char *mprStrndupInternal(MPR_LOC_DEC(ctx, loc), const char *str, uint size)
{
	char	*newp;
	uint	len;

	mprAssert(VALID_BLK(ctx));

	if (str == 0) {
		str = "";
	}
	len = strlen(str) + 1;
	len = min(len, size);

	if (len < MPR_SLAB_STR_MAX) {
		newp = mprSlabAllocBlock(MPR_LOC_PASS(ctx, loc), MPR_SLAB_STR_MAX,
			MPR_SLAB_STR_INC);
	} else {
		newp = mprAllocBlock(MPR_LOC_PASS(ctx, loc), len);
	}

	if (newp) {
		memcpy(newp, str, len);
	}

	return newp;
}

/******************************************************************************/
/*
 *	Internal memcpy function. Will use the slab allocator for small strings
 */

void *mprMemdupInternal(MPR_LOC_DEC(ctx, loc), const void *ptr, uint size)
{
	char	*newp;

	mprAssert(VALID_BLK(ctx));

	if (size < MPR_SLAB_STR_MAX) {
		newp = mprSlabAllocBlock(MPR_LOC_PASS(ctx, loc), MPR_SLAB_STR_MAX,
			MPR_SLAB_STR_INC);
	} else {
		newp = mprAllocBlock(MPR_LOC_PASS(ctx, loc), size);
	}

	if (newp) {
		memcpy(newp, ptr, size);
	}

	return newp;
}

/******************************************************************************/
/*
 *	Steal a block from one context and insert in another
 */

int mprStealAllocBlock(MPR_LOC_DEC(ctx, loc), const void *ptr)
{
	MprBlk		*bp, *parent;

	if (ptr == 0) {
		return 0;
	}

	mprAssert(VALID_BLK(ctx));
	mprAssert(VALID_BLK(ptr));

	bp = GET_HDR(ptr);

#if BLD_DEBUG && !BREW
	if (bp == stopAlloc) {
		mprBreakpoint(MPR_LOC, "breakOnAddr");
	}
#endif

	mprAssert(bp);
	mprAssert(VALID_HDR(bp));
	mprAssert(ptr != mprGetAllocParent(ptr));

	CHECK_HDR(bp);

	mprAssert(bp->prev);
	mprAssert(bp->prev->next);
	mprAssert(bp->next);
	mprAssert(bp->next->prev);

	parent = bp->parent;
	mprAssert(VALID_HDR(parent));

	mprLock(bp->app->allocLock);
	if (parent->children == bp) {
		if (bp->next == bp) {
			parent->children = 0;
		} else {
			parent->children = bp->next;
		}
	}

	bp->prev->next = bp->next;
	bp->next->prev = bp->prev;

	parent = GET_HDR(ctx);
	mprAssert(VALID_HDR(parent));
	bp->parent = parent;

	if (parent->children == 0) {
		parent->children = bp;
		bp->next = bp->prev = bp;

	} else {
		bp->next = parent->children;
		bp->prev = parent->children->prev;
		parent->children->prev->next = bp;
		parent->children->prev = bp;
	}

#if BLD_FEATURE_ALLOC_LEAK_TRACK
	bp->location = loc;
#endif

	VALIDATE_BLOCK(GET_PTR(bp));

	mprUnlock(bp->app->allocLock);

	return 0;
}

/******************************************************************************/

void mprSetRequiredAlloc(MprCtx ptr, bool recurse)
{
	MprBlk	*bp, *firstChild, *cp;

	bp = GET_HDR(ptr);

	bp->flags |= ALLOC_FLAGS_REQUIRED;

	if (recurse && (firstChild = bp->children) != 0) {
		cp = firstChild;
		do {
			mprSetRequiredAlloc(GET_PTR(cp), recurse);
			cp = cp->next;
		} while (cp != firstChild);
	}
}

/******************************************************************************/
/*
 *	Monitor stack usage. Return true if the stack has grown
 */

int mprStackCheck(MprCtx ptr)
{
	MprApp *app;
	int 	size;

	mprAssert(VALID_BLK(ptr));

	app = mprGetApp(ptr);

	size = (int) app->stackStart - (int) &app;
	if (size < 0) {
		app->maxStack -= size;
		app->stackStart = (void*) &app;
		size = 0;
	}
	if ((uint) size > app->maxStack) {
		app->maxStack = size;
		return 1;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Return the stack size
 */

int mprStackSize(MprCtx ptr)
{
	MprApp *app;

	mprAssert(VALID_BLK(ptr));

	app = mprGetApp(ptr);
	return app->maxStack;
}

/******************************************************************************/

static int mprAllocException(MPR_LOC_DEC(ctx, loc), uint size, bool granted)
{
	MprApp		*app;
	MprAlloc	*alloc;
	int			rc;

	mprAssert(VALID_BLK(ctx));

	app = mprGetApp(ctx);
	alloc = &app->alloc;

	if (alloc->cback == 0) {
		return 0;
	}

	mprLock(app->allocLock);
	if (alloc->inAllocException == 0) {
		alloc->inAllocException = 1;
		mprUnlock(app->allocLock);

		rc = (alloc->cback)(app, size, alloc->stats.bytesAllocated, granted);

		mprLock(app->allocLock);
		app->alloc.inAllocException = 0;
		mprUnlock(app->allocLock);

		return rc;
	}
	return 0;
}

/******************************************************************************/

void mprSetAllocLimits(MprApp *app, uint redLine, uint maxMemory)
{
	app->alloc.stats.redLine = redLine;
	app->alloc.stats.maxMemory = maxMemory;
}

/******************************************************************************/

MprAllocCback mprSetAllocCallback(MprApp *app, MprAllocCback cback)
{
	MprAllocCback	old;

	mprAssert(app);
	mprAssert(VALID_BLK(app));

	old = app->alloc.cback;
	app->alloc.cback = cback;
	return old;
}

/******************************************************************************/

uint mprGetAllocBlockSize(MprCtx ptr)
{
	MprBlk	*bp;

	mprAssert(VALID_BLK(ptr));

	if (ptr == 0) {
		return 0;
	}

	bp = GET_HDR(ptr);
	mprAssert(VALID_HDR(bp));

	CHECK_HDR(bp);

	return bp->size;
}

/******************************************************************************/
/* 
 *	Return the total block count used by a block including all children
 */

uint mprGetAllocBlockCount(MprCtx ptr)
{
	MprBlk	*bp, *firstChild, *cp;
	uint	count;

	mprAssert(VALID_BLK(ptr));

	if (ptr == 0) {
		return 0;
	}

	bp = GET_HDR(ptr);
	mprAssert(VALID_HDR(bp));

	/*
	 *	Add one for itself
	 */
	count = 1;
	if ((firstChild = bp->children) != 0) {
		cp = firstChild;
		do {
			count += mprGetAllocBlockCount(GET_PTR(cp));
			cp = cp->next;
		} while (cp != firstChild);
	}
	return count;
}

/******************************************************************************/
/*
 *	Return the total of all memory allocated including slabs
 */

uint mprGetAllocBlockMemory(MprCtx ptr)
{
	MprBlk	*bp, *firstChild, *cp;
	uint	count;

	mprAssert(VALID_BLK(ptr));

	if (ptr == 0) {
		return 0;
	}

	bp = GET_HDR(ptr);
	mprAssert(VALID_HDR(bp));

	count = bp->size + HDR_SIZE;
	if ((firstChild = bp->children) != 0) {
		cp = firstChild;
		do {
			count += mprGetAllocBlockMemory(GET_PTR(cp));
			cp = cp->next;
		} while (cp != firstChild);
	}
	return count;
}

/******************************************************************************/
#if BLD_FEATURE_ALLOC_LEAK_TRACK

const char *mprGetAllocLocation(MprCtx ptr)
{
	MprBlk	*bp;

	if (ptr == 0) {
		return 0;
	}
	mprAssert(VALID_BLK(ptr));

	bp = GET_HDR(ptr);
	mprAssert(VALID_HDR(bp));
	return bp->location;
}

#endif
/******************************************************************************/

void *mprGetAllocParent(MprCtx ptr)
{
	MprBlk	*bp;

	mprAssert(VALID_BLK(ptr));

	if (ptr == 0) {
		return 0;
	}

	bp = GET_HDR(ptr);
	mprAssert(VALID_HDR(bp));

	CHECK_HDR(bp);

	return GET_PTR(bp->parent);
}

/******************************************************************************/

MprAllocStats *mprGetAllocStats(MprApp *app)
{
	mprAssert(VALID_BLK(app));

	return &app->alloc.stats;
}

/******************************************************************************/
#if BLD_FEATURE_ALLOC_STATS

MprSlabStats *mprGetSlabAllocStats(MprApp *app, int slabIndex)
{
	MprSlab		*slab;

	mprAssert(VALID_BLK(app));

	if (0 <= slabIndex && slabIndex < MPR_MAX_SLAB) {
		slab = &app->alloc.slabs[slabIndex];
		return &slab->stats;
	}

	mprAssert(0 <= slabIndex && slabIndex < MPR_MAX_SLAB);
	return 0;
}

#endif /* BLD_FEATURE_ALLOC_STATS */
/******************************************************************************/
#if BLD_DEBUG

int mprPrintAllocBlocks(MprCtx ptr, int indent)
{
	MprBlk		*bp, *firstChild, *cp;
	const char	*location;
	int			subTotal, size, indentSpaces, code;

	subTotal = 0;

	bp = GET_HDR(ptr);

	if (! (bp->flags & ALLOC_FLAGS_REQUIRED)) {
		size = bp->size + HDR_SIZE;

		/*
		 *	Take one level off because we don't trace app
	 	 */
		indentSpaces = indent;

		if (bp->flags & ALLOC_FLAGS_REQUIRED) {
			code = 'R';
		} else if (bp->flags & ALLOC_FLAGS_IS_SLAB) {
			code = 'S';
		} else {
			code = ' ';
		}

#if BLD_FEATURE_ALLOC_LEAK_TRACK
		location = bp->location;
#else
		location = "";
#endif
		mprLog(bp->app, 0, 
			"%c %.*s %-16s %.*s size %5d has %3d deps, total %6d", code,
			indentSpaces, "                   ",
			mprGetBaseName(location),
			8 - indent, "          ",
			size, 
			mprGetAllocBlockCount(GET_PTR(bp)), 
			mprGetAllocBlockMemory(GET_PTR(bp))
			/* (uint) bp */
			);

		subTotal += size;
	}
		
	if ((firstChild = bp->children) != 0) {
		cp = firstChild;
		do {
			subTotal += mprPrintAllocBlocks(GET_PTR(cp), indent + 2);
			cp = cp->next;
		} while (cp != firstChild);
	}

	return subTotal;
}

#endif
/******************************************************************************/
#if BLD_FEATURE_ALLOC_STATS
/*
 *	Print a memory allocation report that includes a list of allocated blocks
 *	and a statistics summary
 */

void mprPrintAllocReport(MprApp *app, bool printBlocks, const char *msg)
{
	MprSlabStats	*stats;
	uint			total;
	int				i, size;
	
	mprAssert(VALID_BLK(app));

	if (msg) {
		mprLog(app, 0, " ");
		mprLog(app, 0, "%s", msg);
	}

#if BLD_DEBUG
	/*
	 *	Do block stats
	 */
	if (printBlocks) {
		int	sum;
		mprLog(app, 0, " ");
		sum = mprPrintAllocBlocks(app, 0);
		if (sum) {
			mprLog(app, 0, "  Sum of blocks %d", sum);
		} else {
			mprLog(app, 0, "  None");
		}
	}
#endif

	/*
	 *	Do Slab stats
	 */
	mprLog(app, 0, " ");
	mprLog(app, 0, "MPR Slab Memory Stats");
	mprLog(app, 0, " ");

	mprLog(app, 0, 
	"  Index Size    Total Allocated   Free PeakAlloc PeakFree TotalAlloc");

	total = 0;
	for (i = 0; i < MPR_MAX_SLAB; i++) {
		stats = &app->alloc.slabs[i].stats;
		size = 1 << (i + 5);
		if (stats->totalAllocCount > 0) {
			mprLog(app, 0, "   %2d %6d %8d %9d %6d %9d %8d %10d", 
				i, size, size * (stats->allocCount + stats->freeCount),
				stats->allocCount, stats->freeCount, 
				stats->peakAllocCount, stats->peakFreeCount, 
				stats->totalAllocCount); 
			total += size * (stats->allocCount + stats->freeCount);
		}
	}
	mprLog(app, 0, " ");
	mprLog(app, 0, "MPR Total Allocated Slab RAM: %10d", total);
	mprLog(app, 0, "MPR Total Allocated RAM:      %10d", 
		mprGetAllocatedMemory(app));
	mprLog(app, 0, "MPR Peak Allocated RAM:       %10d", 
		mprGetPeakAllocatedMemory(app));
	mprLog(app, 0, " ");
}

/******************************************************************************/
/*
 *	Return the total memory allocated.
 */

uint mprGetAllocatedMemory(MprCtx ctx)
{
	MprApp			*app;

	app = mprGetApp(ctx);

	return app->alloc.stats.bytesAllocated;
}

/******************************************************************************/
/*
 *	Return the peak memory allocated.
 */

uint mprGetPeakAllocatedMemory(MprCtx ctx)
{
	MprApp			*app;

	app = mprGetApp(ctx);

	return app->alloc.stats.peakAllocated;
}

/******************************************************************************/
/*
 *	Return memory in the MPR slab. This excludes the EJS slabs
 */

uint mprGetAllocatedSlabMemory(MprCtx ctx)
{
	MprApp			*app;
	MprSlabStats	*stats;
	uint			total;
	int				i, size;

	app = mprGetApp(ctx);

	total = 0;
	for (i = 0; i < MPR_MAX_SLAB; i++) {
		stats = &app->alloc.slabs[i].stats;
		size = 1 << (i + 5);
		if (stats->totalAllocCount > 0) {
			total += size * (stats->allocCount + stats->freeCount);
		}
	}
	return total;
}

#endif /* BLD_FEATURE_ALLOC_STATS */
/******************************************************************************/

MprDestructor mprSetDestructor(MprCtx ptr, MprDestructor destructor)
{
	MprDestructor	old;
	MprBlk			*bp;

	mprAssert(VALID_BLK(ptr));

	if (ptr == 0) {
		return 0;
	}

	bp = GET_HDR(ptr);

	mprAssert(bp);
	mprAssert(VALID_HDR(bp));
	mprAssert(ptr != mprGetAllocParent(ptr));

	CHECK_HDR(bp);

	old = bp->destructor;
	bp->destructor = destructor;

	return old;
}

/******************************************************************************/

int mprIsAllocBlockValid(MprCtx ptr)
{
	MprBlk	*bp;

	bp = GET_HDR(ptr);
	return (bp && VALID_HDR(bp));
}

/******************************************************************************/
#if VALIDATE_ALLOC
/*
 *	Exhaustive validation of the block and its children. Does not go recursive
 *	as it would be too slow.
 */

int mprValidateBlock(MprCtx ptr)
{
	MprBlk			*bp, *parent, *cp, *firstChild;
	int				count;

	mprAssert(ptr);
	mprAssert(VALID_BLK(ptr));

	bp = GET_HDR(ptr);

	mprAssert(bp);
	mprAssert(VALID_HDR(bp));
	mprAssert(VALID_HDR(bp->parent));

	if (ptr != bp->app) {
		mprAssert(bp != bp->parent);
	}
	mprAssert(! (bp->flags & ALLOC_FLAGS_FREE));
	mprAssert(! (bp->flags & ALLOC_FLAGS_FREEING));

	/*
	 *	
	 */
	count = 0;
	parent = bp->parent;

	if ((firstChild = bp->children) != 0) {
		cp = firstChild;
		mprAssert((int) cp != 0xfeefee);
		do {
			mprAssert(bp->next->prev == bp);
			mprAssert(bp->prev->next == bp);
			mprAssert(bp->prev->parent == parent);
			mprAssert(bp->next->parent == parent);

			count++;
			cp = cp->next;

			if (bp->next == bp) {
				mprAssert(bp->prev == bp);
				if (ptr != bp->app) {
					mprAssert(parent->children == bp);
				}
			}
			if (bp->prev == bp) {
				mprAssert(bp->next == bp);
				if (ptr != bp->app) {
					mprAssert(parent->children == bp);
				}
			}
		} while (cp != firstChild);
	}

	return 0;
}

#endif
/******************************************************************************/
/*
 *	Validate a block and all children
 */

int mprValidateAllocTree(MprCtx ptr)
{
#if VALIDATE_ALLOC
	MprBlk			*bp, *cp, *firstChild;

	mprAssert(ptr);
	mprAssert(VALID_BLK(ptr));

	bp = GET_HDR(ptr);

	mprValidateBlock(GET_PTR(bp));

	if ((firstChild = bp->children) != 0) {
		cp = firstChild;
		do {
			mprValidateAllocTree(GET_PTR(cp));
			cp = cp->next;
		} while (cp != firstChild);
	}

#endif
	return 0;
}

/******************************************************************************/
#if UNUSED && FUTURE
/*
 *	Exhaustive validation of the block and its children. Does not go recursive
 *	as it would be too slow.
 */

int mprValidateSlabs(MprApp *app)
{
	MprSlab			*slab;
	MprSlabStats	*slabStats;
	MprSlabBlock	*sp;
	int				count, i;

	for (i = 0; i < MPR_MAX_SLAB; i++) {
		slab = &app->alloc.slabs[i];
		slabStats = &slab->stats;

		count = 0;
		for (sp = slab->next; sp; sp = sp->next) {
			count++;
		}
		mprAssert(count == (int) slabStats->freeCount);
	}
	return 0;
}

#endif
/******************************************************************************/

void mprAllocAbort()
{
#if BREW
	printf("Bad block header");
#else
	exit(255);
#endif
}

/******************************************************************************/
#undef mprGetApp
/*
 *	Get the root parent from any block (which is the MprApp structure)
 */

MprApp *mprGetApp(MprCtx ptr)
{
	MprBlk	*bp;

	mprAssert(ptr);

	bp = GET_HDR(ptr);
	mprAssert(VALID_HDR(bp));

	CHECK_HDR(bp);

	mprAssert(bp->app->magic == APP_MAGIC);

	return bp->app;
}

/******************************************************************************/

int mprGetAllocErrors(MprCtx ctx)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	return app->alloc.stats.errors;
}

/******************************************************************************/

void mprClearAllocErrors(MprCtx ctx)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	app->alloc.stats.errors = 0;
}

/******************************************************************************/
/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
