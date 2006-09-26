/*
 *	@file 	ejsGarbage.c
 *	@brief 	EJS Garbage collector.
 *	@overview This implements a generational mark and sweep collection scheme.
 */
/********************************* Copyright **********************************/
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
/********************************** Includes **********************************/

#include	"ejs.h"

#if BLD_FEATURE_EJS

/****************************** Forward Declarations **************************/

static void 	mark(Ejs *ep);
static void		markObjByVar(Ejs *ep, EjsVar *op);
static void 	markObj(EjsObj *obj);
static void 	markPerm(Ejs *ep, uint gen);
static int		sweep(Ejs *ep, uint gen);
static EjsGCLink *ejsAlloc(EJS_LOC_DEC(ep, loc), int slabIndex);
static void 	ejsGracefulDegrade(Ejs *ep);
static void 	resetMarks(Ejs *ep, EjsSlab *slab);

#if FUTURE
static void 	ageGenerations(Ejs *ep);
#endif

#if BLD_DEBUG && (!BREW || BREW_SIMULATOR)
uint breakAddr;
#endif

/************************************* Code ***********************************/

void ejsGCInit(Ejs *ep, int objInc, int propInc, int varInc, int strInc)
{
	EjsSlab		*slab;

	if (ep->service && ep->service->globalClass) {
		ep->service->globalClass->objectState->gcMarked = 1;
	}

	slab = &ep->slabs[EJS_SLAB_OBJ];
	slab->allocIncrement = objInc;
	slab->size = EJS_ALLOC_ALIGN(sizeof(EjsObj));

	slab = &ep->slabs[EJS_SLAB_PROPERTY];
	slab->allocIncrement = propInc;
	slab->size = EJS_ALLOC_ALIGN(sizeof(EjsProperty));

	slab = &ep->slabs[EJS_SLAB_VAR];
	slab->allocIncrement = varInc;
	slab->size = EJS_ALLOC_ALIGN(sizeof(EjsVar));

	/*
 	 *	Initialize GC.
	 *	Enable GC both idle and demand collections.
	 *	Set no limits and garbage collect if the slabs are
	 *	empty and we have used more than the THRESHOLD of ram.
	 */
	ep->gc.debugLevel = 0;
	ep->gc.enable = 1;
	ep->gc.enableIdleCollect = 1;
	ep->gc.enableDemandCollect = 1;
	ep->gc.workQuota = EJS_GC_WORK_QUOTA;
	ep->gc.maxMemory = 0;
}


/******************************************************************************/
#if BLD_FEATURE_ALLOC_STATS

void ejsPrintAllocReport(Ejs *ep, bool printLeakReport)
{
	EjsSlab		*slab;
	char		*name;
	int			slabIndex, isObj;
	
	for (slabIndex = 0; slabIndex < EJS_SLAB_MAX; slabIndex++) {
		slab = &ep->slabs[slabIndex];
		if (slabIndex == EJS_SLAB_VAR) {
			name = "var";
		} else if (slabIndex == EJS_SLAB_PROPERTY) {
			name = "prop";
		} else {
			name = "obj";
		}
		mprLog(ep, 0, " ");
		mprLog(ep, 0, "  GC \"%s\" local slab", name);
		mprLog(ep, 0, "  Total blocks           %14d", 
			slab->allocCount + slab->freeCount);
		mprLog(ep, 0, "  Block size             %14d", slab->size);
		mprLog(ep, 0, "  Slab RAM allocated     %14d", 
			(slab->allocCount + slab->freeCount) * slab->size);
		mprLog(ep, 0, "  Slab RAM in use        %14d", 
			slab->allocCount * slab->size);
		mprLog(ep, 0, "  Blocks in use          %14d", slab->allocCount);
		mprLog(ep, 0, "  Free blocks            %14d", slab->freeCount);
		mprLog(ep, 0, "  Peak allocated         %14d", slab->peakAllocated);
		mprLog(ep, 0, "  Peak free              %14d", slab->peakFree);
		mprLog(ep, 0, "  Total allocations      %14d", slab->totalAlloc);
		mprLog(ep, 0, "  Total blocks reclaimed %14d", slab->totalReclaimed);
		mprLog(ep, 0, "  Total sweeps           %14d", slab->totalSweeps);
		mprLog(ep, 0, "  Allocation inc         %14d", slab->allocIncrement);
	}

	mprLog(ep, 0, " ");
	mprLog(ep, 0, "  Total EJS memory in use    %10d", ejsGetUsedMemory(ep));
	mprLog(ep, 0, "  Total EJS memory allocated %10d", 
		ejsGetAllocatedMemory(ep));

	if (printLeakReport) {
		mprLog(ep, 0, " ");
		for (slabIndex = 0; slabIndex < EJS_SLAB_MAX; slabIndex++) {
			int		size;

			slab = &ep->slabs[slabIndex];

			isObj = 0;
			mprLog(ep, 0, " ");
			if (slabIndex == EJS_SLAB_VAR) {
				name = "var";
				size = sizeof(EjsVar);
			} else if (slabIndex == EJS_SLAB_PROPERTY) {
				name = "prop";
				size = sizeof(EjsProperty);
			} else {
				name = "obj";
				size = sizeof(EjsObj);
				isObj++;
			}
#if BLD_FEATURE_ALLOC_LEAK_TRACK
{
			EjsGCLink	*lp;
			EjsObj		*obj;
			int			count;

			mprLog(ep, 0, "EJS Leak Report for \"%s\"", name);
			count = 0;

			for (lp = slab->allocList[0].next; lp; lp = lp->next) {
				mprLog(ep, 0, "  %-20s           %10d", lp->allocatedBy, size);
				if (isObj) {
					obj = (EjsObj*) lp;
					mprLog(ep, 0, "  %-20s           %10d %s %s", 
						lp->allocatedBy, size,
						obj->permanent ? "permanent" : "", 
						obj->alive ? "alive" : ""
					);
				} else {
					mprLog(ep, 0, "  %-20s           %10d", lp->allocatedBy, 
						size);
				}
				count++;
			}
			mprLog(ep, 0, "  Total blocks               %14d", count);
}
#endif
		}
		mprLog(ep, 0, " ");
	}
}

#endif
/******************************************************************************/
/*
 *	Slab allocator
 */

static EjsGCLink *ejsAlloc(EJS_LOC_DEC(ep, loc), int slabIndex)
{
	EjsSlab		*slab;
	EjsGCLink	*block;
	EjsGC		*gc;
	uint		allocatedMemory;
	int			i;

	mprStackCheck(ep);

	if (slabIndex < 0 || slabIndex >= EJS_SLAB_MAX) {
		mprAssert(0);
		return 0;
	}

	/*
 	 *	See if the slab has some free blocks
 	 */
	slab = &ep->slabs[slabIndex];
	if ((block = slab->freeList.next) == 0) {

		allocatedMemory = ejsGetAllocatedMemory(ep);
		gc = &ep->gc;

		/*
		 *	No blocks available. If demand collection is enabled, try
		 *	to garbage collect first. We collect if we have done a good 
		 *	work quota or we are over the max memory limit.
		 */
		if (slabIndex != EJS_SLAB_VAR && 
				ep->gc.enable && ep->gc.enableDemandCollect) {
			if ((ep->gc.workDone > ep->gc.workQuota) || 
			   (gc->maxMemory > 0 && allocatedMemory > gc->maxMemory)) {

#if DEBUG_USE_ONLY
				if (ep->gc.debugLevel > 0) {
					mprLog(ep, 0, "Need GC, EJS RAM %d, MPR RAM %d\n",
						allocatedMemory, mprGetAllocatedMemory(ep));
					if (ep->gc.debugLevel > 4) {
						ejsPrintAllocReport(ep, 0);
					}
				}
#endif
				if (ejsCollectGarbage(ep, slabIndex) == 0) {
					block = slab->freeList.next;
				}
			}
		}

		if (block == 0) {
			if (gc->maxMemory > 0 && allocatedMemory > gc->maxMemory) {
				/*
				 *	We are above the max memory limit. We will fail this
				 *	memory allocation, but allow subsequent allocations to 
				 *	permit error recovery. We gracefully degrade by setting 
				 *	slab chunk sizes to 1. This minimizes real memory
				 *	consumption. This allows us to create 
				 *	an exception block to be created by upper layers.
				 */
				if (! gc->degraded) {
					ejsGracefulDegrade(ep);
					return 0;
				}
			}

			/*
			 *	Still non available, so allocate more memory for a set of blocks
			 *	OPT -- should bypass mprAlloc. Need mprMalloc.
			 */
			block = mprAlloc(ep->slabAllocContext, 
				slab->size * slab->allocIncrement);
			if (block == 0) {
				/*
				 *	Now we're in trouble. We should really never get here
				 *	as the graceful degrade will have signaled a memory 
				 *	allocation failure.
				 */
				mprAssert(block != 0);
				return 0;
			}

			/*
			 *	Chain all the blocks together onto the slab free list
			 */
			for (i = slab->allocIncrement - 1; i >= 0; i--) {
				block->next = slab->freeList.next;
#if BLD_DEBUG
				block->magic = EJS_MAGIC_FREE;
#endif
				slab->freeList.next = block;
				block = (EjsGCLink*) ((char*) block + slab->size);
			}

			block = slab->freeList.next;

#if BLD_FEATURE_ALLOC_STATS
			slab->freeCount += slab->allocIncrement;
			if (slab->freeCount > slab->peakFree) {
				slab->peakFree = slab->freeCount;
			}
#endif
		}
	}

	/*
	 *	We use block to point to the user data in the block. We only
	 *	store the magic number (if debug). No other data is stored in the
	 *	user block.
	 */
#if BLD_DEBUG
	mprAssert(block->magic == EJS_MAGIC_FREE);
#endif

	/*
	 *	Remove from the free list
	 */
	slab->freeList.next = block->next;

	/*
	 *	Zero block
	 */
	memset(block, 0, slab->size);

#if BLD_DEBUG
	block->magic = EJS_MAGIC;
#endif

#if BLD_FEATURE_ALLOC_STATS
	slab->totalAlloc++;
	if (++slab->allocCount > slab->peakAllocated) {
		slab->peakAllocated = slab->allocCount;
	}
	slab->freeCount--;
#endif

#if BLD_DEBUG && (!BREW || BREW_SIMULATOR)
	if ((uint) block == breakAddr) {
		mprBreakpoint(MPR_LOC, "Watched Block");
	}
#endif
	return block;
}


/******************************************************************************/

EjsObj *ejsAllocObj(EJS_LOC_DEC(ep, loc))
{
	EjsObj		*obj;
	EjsSlab		*slab;

	obj = (EjsObj*) ejsAlloc(EJS_LOC_PASS(ep, loc), EJS_SLAB_OBJ);

	/*
 	 *	Add to the allocated block list for the New generation.
	 */
	if (obj) {
		slab = &ep->slabs[EJS_SLAB_OBJ];
		obj->gc.next = slab->allocList[EJS_GEN_NEW].next;

#if BLD_FEATURE_ALLOC_LEAK_TRACK
		obj->gc.allocatedBy = loc;
#endif

		obj->ejs = ep;
		slab->allocList[EJS_GEN_NEW].next = (EjsGCLink*) obj;

		ep->gc.workDone++;
	}

	return obj;
}


/******************************************************************************/

EjsProperty *ejsAllocProperty(EJS_LOC_DEC(ep, loc))
{
	EjsProperty		*prop;

	prop = (EjsProperty*) ejsAlloc(EJS_LOC_PASS(ep, loc), EJS_SLAB_PROPERTY);
	mprAssert(prop);

	if (prop) {
		prop->var.type = EJS_TYPE_NULL;
		prop->var.isProperty = 1;
#if BLD_FEATURE_ALLOC_LEAK_TRACK
		prop->var.gc.allocatedBy = loc;
#endif
	}
	return prop;
}


/******************************************************************************/

EjsVar *ejsAllocVar(EJS_LOC_DEC(ep, loc))
{
	EjsVar	*vp;

	vp = (EjsVar*) ejsAlloc(EJS_LOC_PASS(ep, loc), EJS_SLAB_VAR);
	mprAssert(vp);

	if (vp) {
#if BLD_FEATURE_ALLOC_LEAK_TRACK
		EjsSlab	*slab;
		vp->gc.allocatedBy = loc;
		slab = &ep->slabs[EJS_SLAB_VAR];
		vp->gc.next = slab->allocList[EJS_GEN_NEW].next;
		slab->allocList[EJS_GEN_NEW].next = (EjsGCLink*) vp;
#endif
#if BLD_DEBUG
		vp->propertyName = 0;
#endif
	}
	return vp;
}


/******************************************************************************/
/*
 *	Return the block back to the relevant slab
 */

void ejsFree(Ejs *ep, void *ptr, int slabIndex)
{
	EjsSlab		*slab;
	EjsGCLink	*block;

	mprAssert(ep);
	mprAssert(ptr);

	if (slabIndex < 0 || slabIndex >= EJS_SLAB_MAX) {
		mprAssert(slabIndex >= 0 && slabIndex < EJS_SLAB_MAX);
		return;
	}
	slab = &ep->slabs[slabIndex];

#if BLD_FEATURE_ALLOC_LEAK_TRACK
	if (slabIndex == EJS_SLAB_VAR) {
		EjsVar		*vp, *np, *prev;

		/*
		 *	Remove the block rom the alloc list. WARNING: this is slow
		 *	and should not be used in production code.
		 */
		vp = (EjsVar*) ptr;
		prev = 0;
		for (np = (EjsVar*) slab->allocList[0].next; np; 
				np = (EjsVar*) np->gc.next) {
			if (vp == np) {
				if (prev) {
					prev->gc.next = (EjsGCLink*) np->gc.next;
				} else {
					slab->allocList[0].next = (EjsGCLink*) np->gc.next;
				}
				break;
			}
			prev = np;
		}
		if (np == 0) {
			mprAssert(0);
		}
	}
#endif

	/*
 	 *	Insert into the free list. Only use the next ptr
	 */
	block = (EjsGCLink*) ptr;

#if BLD_DEBUG
#if !BREW || BREW_SIMULATOR
	if ((uint) block == breakAddr) {
		mprBreakpoint(MPR_LOC, "Watched Block");
	}
#endif
	mprAssert(block->magic == EJS_MAGIC);
	block->magic = EJS_MAGIC_FREE;
#endif

	block->next = slab->freeList.next;
	slab->freeList.next = block;

#if BLD_FEATURE_ALLOC_STATS
	slab->allocCount--;
	if (++slab->freeCount >= slab->peakFree) {
		slab->peakFree = slab->freeCount;
	}
	slab->totalReclaimed++;
	if (slabIndex != 2) {
		slabIndex = slabIndex;
	}
#endif
}

/******************************************************************************/
/*
 *	Mark an object as being in-use. Traverse all properties for referenced 
 *	objects and base classes.
 */

static void markObjByVar(Ejs *ep, EjsVar *obj)
{
	EjsProperty		*pp;
	EjsVar			*vp, *baseClass;

	mprAssert(ep);
	mprAssert(obj);

	obj->objectState->gcMarked = 1;

#if BLD_DEBUG
	if (ep->gc.debugLevel >= 3) {
		int indent = min(ep->gc.gcIndent * 2, 32);
		mprLog(ep, 0, "%.*s %-24s %.*s 0x%08X", 
			indent, "                                 ",
			obj->propertyName,
			32 - indent, "................................ ",
			(uint) obj->objectState);
		ep->gc.gcIndent++;
	}
	ep->gc.objectsInUse++;
#endif

	/*
 	 *	Traverse all referenced objects
	 *	OPT -- optimize by directly accessing the object links and not using
	 *	ejsGetFirst/NextProperty. Then just examine objects
	 *	OPT -- first property in global is global. Should optimize this.
	 */
	pp = ejsGetFirstProperty(obj, EJS_ENUM_ALL);
	while (pp) {
		vp = ejsGetVarPtr(pp);
		if (vp->type == EJS_TYPE_OBJECT) {
			if (!vp->objectState->gcMarked) {
#if FUTURE
				/*
				 * 	OPT -- we can use the dirty bit on objects to avoid 
				 *	visiting permanent objects that are clean. If so, don't
				 *	forget the else case below.
				 */
				obj = vp->objectState;
				if ((!obj->alive && !obj->permanent) || obj->dirty)
#endif
				markObjByVar(ep, vp);
			}

		} else {
#if BLD_DEBUG
			if (ep->gc.debugLevel >= 3) {
				int indent = min(ep->gc.gcIndent * 2, 32);
				mprLog(ep, 0, "%.*s %-24s %.*s %s", 
					indent, "                                 ",
					vp->propertyName,
					32 - indent, "................................ ",
					ejsGetVarTypeAsString(vp));
			}
			ep->gc.propertiesInUse++;
#endif
		}
		pp = ejsGetNextProperty(pp, EJS_ENUM_ALL);
	}

	/*
 	 *	Traverse the base class
	 */
	baseClass = obj->objectState->baseClass;
	if (baseClass) {
		mprAssert(baseClass->type == EJS_TYPE_OBJECT);
		mprAssert(baseClass->objectState);
		if (baseClass->objectState) {
			if (! baseClass->objectState->gcMarked) {
				markObjByVar(ep, baseClass);
			}
		}
	}
#if BLD_DEBUG
	if (ep->gc.debugLevel >= 3) {
		ep->gc.gcIndent--;
	}
#endif
}


/******************************************************************************/
/*
 *	Mark phase. Examine all variable frames and the return result.
 */

static void mark(Ejs *ep)
{
	EjsVar	*vp;
	int		i;

#if BLD_DEBUG
	if (ep->gc.debugLevel >= 3) {
		mprLog(ep, 0, " ");
		mprLog(ep, 0, "GC: Marked Blocks:");
	}
#endif

	if (ep->frames) {
		for (i = 0; i < mprGetItemCount(ep->frames); i++) {

			vp = (EjsVar*) mprGetItem(ep->frames, i);
			mprAssert(vp->type == EJS_TYPE_OBJECT);

			if (! vp->objectState->gcMarked) {
				markObjByVar(ep, vp);
			}
		}
	}

	vp = ep->result;
	if (vp && vp->type == EJS_TYPE_OBJECT && ! vp->objectState->gcMarked) {
		markObjByVar(ep, vp);
	}

	vp = ep->currentObj;
	if (vp && vp->type == EJS_TYPE_OBJECT && ! vp->objectState->gcMarked) {
		markObjByVar(ep, vp);
	}

	vp = ejsGetVarPtr(ep->currentProperty);
	if (vp && vp->type == EJS_TYPE_OBJECT && ! vp->objectState->gcMarked) {
		markObjByVar(ep, vp);
	}

	/*
	 *	OPT -- we could mark master as "mark permanent" somehow and
	 *	then we would not need to walk the master objects.
 	 */
	if (ep->slabAllocContext == ep->service->master) {
		if (ep->service->master->global) {
			markObjByVar(ep, ep->service->master->global);
		}
	}

#if BLD_DEBUG
	if (ep->gc.debugLevel >= 3) {
		mprLog(ep, 0, " ");
	}
#endif
}


/******************************************************************************/
#if UNUSED

static void resetMark(EjsVar *obj)
{
	EjsProperty		*pp;
	EjsVar			*vp, *baseClass;

	obj->objectState->gcMarked = 0;
	obj->objectState->visited = 1;

	pp = ejsGetFirstProperty(obj, EJS_ENUM_ALL);
	while (pp) {
		vp = ejsGetVarPtr(pp);
		if (vp->type == EJS_TYPE_OBJECT && !vp->objectState->visited) {
			resetMark(vp);			
		}
		pp = ejsGetNextProperty(pp, EJS_ENUM_ALL);
	}

	baseClass = obj->objectState->baseClass;
	if (baseClass) {
		mprAssert(baseClass->type == EJS_TYPE_OBJECT);
		mprAssert(baseClass->objectState);
		if (baseClass->objectState) {
			if (! baseClass->objectState->visited) {
				resetMark(baseClass);
			}
		}
	}
	obj->objectState->visited = 0;
}

/******************************************************************************/
/*
 *	Mark phase. Examine all variable frames and the return result.
 */

static void resetAllMarks(Ejs *ep)
{
	EjsVar	*vp;
	int		i;

	for (i = 0; i < mprGetItemCount(ep->frames); i++) {
		vp = (EjsVar*) mprGetItem(ep->frames, i);
		resetMark(vp);
	}

	if (ep->result && ep->result->type == EJS_TYPE_OBJECT &&
			! ep->result->objectState->gcMarked) {
		resetMark(ep->result);
	}
}

#endif
/******************************************************************************/
/*
 *	Sweep up the garbage
 */

static void resetMarks(Ejs *ep, EjsSlab *slab)
{
	EjsVar		*vp;
	EjsObj		*obj;
	int			gen, i;

	for (gen = EJS_GEN_NEW; gen < EJS_GEN_MAX; gen++) {
		obj = (EjsObj*) slab->allocList[gen].next;
		for (; obj; obj = (EjsObj*) obj->gc.next) {
			obj->gcMarked = 0;
			obj->visited = 0;
		}
	}

	if (ep->frames) {
		for (i = 0; i < mprGetItemCount(ep->frames); i++) {

			vp = (EjsVar*) mprGetItem(ep->frames, i);
			mprAssert(vp->type == EJS_TYPE_OBJECT);

			vp->objectState->gcMarked = 0;
			vp->objectState->visited = 0;
		}
	}

	if (ep->result && ep->result->type == EJS_TYPE_OBJECT) {
		ep->result->objectState->gcMarked = 0;
	}
}

/******************************************************************************/
/*
 *	Mark all permanent and non-alive objects
 */

static void markPerm(Ejs *ep, uint gen)
{
	EjsSlab		*slab;
	EjsObj		*obj;

	slab = &ep->slabs[EJS_SLAB_OBJ];

	for (obj = (EjsObj*) slab->allocList[gen].next; obj; ) {

		if (! obj->gcMarked) {
			if (!obj->alive || obj->permanent) {
				markObj(obj);
			}
		}
		obj = (EjsObj*) obj->gc.next;

	}
}

/******************************************************************************/

static void markObj(EjsObj *obj)
{
	EjsProperty		*pp;
	EjsPropLink		*lp, *head;
	EjsObj			*op;

	mprAssert(obj);

	obj->gcMarked = 1;

	head = &obj->link;
	for (lp = head->next; lp != head; lp = lp->next) {

		pp = ejsGetPropertyFromLink(lp);

		if (pp->var.type == EJS_TYPE_OBJECT) {
			op = pp->var.objectState;
			if (op != 0 && !op->gcMarked) {
				markObj(op);
			}
		}
	}
}

/******************************************************************************/
/*
 *	Sweep up the garbage. Return the number of objects freed.
 */

static int sweep(Ejs *ep, uint gen)
{
	EjsSlab		*slab;
	EjsObj		*obj, *next, *prev;
	int			count;

	slab = &ep->slabs[EJS_SLAB_OBJ];

	/*
	 *	Examine allocated objects in the specified generation (only).
	 *	NOTE: we only sweep object allocated to this interpreter and so
	 *	we do not sweep any permanent objects in the default interpreter.
	 */
	prev = 0;
	count = 0;
	for (obj = (EjsObj*) slab->allocList[gen].next; obj; obj = next) {

		next = (EjsObj*) obj->gc.next;

#if BLD_DEBUG && (!BREW || BREW_SIMULATOR)
		if ((uint) obj == breakAddr) {
			mprBreakpoint(MPR_LOC, "Watched Block");
		}
#endif

		/*
		 *	If object has not been marked inuse and is not a permanent
		 *	object, then free it.
		 */
		if (! obj->gcMarked && obj->alive && !obj->permanent) {

#if BLD_DEBUG
			if (ep->gc.debugLevel >= 2) {
				if (obj->objName) {
					mprLog(ep, 0, "GC: destroy %-18s   %10d, %8X", 
						obj->objName, (uint) obj, (uint) obj);
				} else {
					mprLog(ep, 0, "GC: destroy UNKNOWN %x", (uint) obj);
				}
			}
#endif
			if (ejsDestroyObj(ep, obj) < 0) {
				prev = obj;
				obj->gcMarked = 0;
				continue;
			}

			if (prev) {
				prev->gc.next = (EjsGCLink*) next;
			} else {
				slab->allocList[gen].next = (EjsGCLink*) next;
			}
			count++;

		} else {
			prev = obj;
			/* Reset for next time */
			obj->gcMarked = 0;
		} 
	}

	if (gen == (EJS_GEN_OLD - 1)) {
		slab->lastRecentBlock = prev;
	}
#if BLD_FEATURE_ALLOC_STATS
	slab->totalSweeps++;
#endif
#if BLD_DEBUG
	if (ep->gc.debugLevel > 0) {
		mprLog(ep, 0, "GC: Sweep freed %d objects", count);
	}
#endif
	return count;
}

/******************************************************************************/
/*
 *	Sweep all variables
 */

void ejsSweepAll(Ejs *ep)
{
	EjsSlab		*slab;
	EjsObj		*obj, *next, *prev;
	int			gen;

	slab = &ep->slabs[EJS_SLAB_OBJ];

	for (gen = EJS_GEN_NEW; gen < EJS_GEN_MAX; gen++) {
		prev = 0;
		for (obj = (EjsObj*) slab->allocList[gen].next; obj; obj = next) {
			next = (EjsObj*) obj->gc.next;
			ejsDestroyObj(ep, obj);
		}
		break;
	}
}

/******************************************************************************/

bool ejsObjIsCollectable(EjsVar *vp)
{
	if (vp == 0 || !ejsVarIsObject(vp)) {
		return 0;
	}
	return (vp->objectState->alive && !vp->objectState->permanent);
}

/******************************************************************************/
#if FUTURE

static void ageGenerations(Ejs *ep)
{
	EjsSlab		*slab;
	EjsGCLink	*oldList;
	int			gen;

	slab = &ep->slabs[EJS_SLAB_OBJ];

	/*
	 *	Age all blocks. First append all (old - 1) blocks onto the old 
 	 *	alloc list 
 	 */
	oldList = &slab->allocList[EJS_GEN_OLD];

	if (slab->lastRecentBlock) {
		slab->lastRecentBlock->gc.next = oldList->next;
		oldList->next = (EjsGCLink*) slab->lastRecentBlock;
	}

	/*
 	 *	Now simply copy all allocation lists up one generation
	 */
	for (gen = EJS_GEN_OLD - 1; gen > 0; gen--) {
		slab->allocList[gen] = slab->allocList[gen - 1];
	}
	slab->allocList[0].next = 0;
}

#endif
/******************************************************************************/
/*
 *	Collect the garbage. This is a mark and sweep over all possible objects.
 *	If an object is not referenced, it and all contained properties will be
 *	freed. If a slabIndex is provided, the collection halts when a block is 
 *	available for allocation on that slab.
 *
 *	Return 0 if memory is now available after collecting garbage. Otherwise,
 *	return MPR_ERR_MEMORY.
 */

int ejsCollectGarbage(Ejs *ep, int slabIndex)
{
	EjsGeneration	gen;
	
	if (ep->flags & EJS_FLAGS_DONT_GC) {
		return -1;
	}

	/*
	 *	Prevent destructors invoking the garbage collector
	 */
	if (ep->gc.collecting) {
		return 0;
	}
	ep->gc.collecting = 1;

	resetMarks(ep, &ep->slabs[EJS_SLAB_OBJ]);

	/*
	 *	Examine each generation of objects starting with the most recent 
	 *	generation. Stop scanning when we have a free block to use.
	 */
	for (gen = EJS_GEN_NEW; gen < EJS_GEN_MAX; gen++) {

		if (slabIndex >= 0 && ep->slabs[slabIndex].freeList.next) {
			break;
		}

		/*
		 *	FUTURE OPT. Should mark objects in new generation and those 
		 *	with a dirty bit set in older generations. Don't need to mark
		 *	entire heap. But how to keep list of dirty objects. 
		 */
		mark(ep);
		markPerm(ep, gen);
		sweep(ep, gen);

		/* FUTURE - not using generations yet */
		break;
	}

	/*
	 *	FUTURE -- not using generations yet.  
	 *
 	 * 		ageGenerations(ep);
	 */

	ep->gc.workDone = 0;
	ep->gc.collecting = 0;

	return (gen < EJS_GEN_MAX) ? 0 : MPR_ERR_MEMORY;
}
 

/******************************************************************************/
/*
 *	Should be called when the app has been idle for a little while and when it
 *	is likely to be idle a bit longer. Call ejsIsTimeForGC to see if this is
 *	true. Return the count of objects collected .
 */

int ejsIncrementalCollectGarbage(Ejs *ep)
{
	int		count;

	if (ep->gc.collecting) {
		return 0;
	}

	ep->gc.collecting = 1;

	resetMarks(ep, &ep->slabs[EJS_SLAB_OBJ]);
	mark(ep);

	/* Not generational yet */
	count = sweep(ep, EJS_GEN_NEW);

	ep->gc.collecting = 0;
	ep->gc.workDone = 0;

	return count;
}

/******************************************************************************/
#if BLD_DEBUG

void ejsDumpObjects(Ejs *ep)
{
	int		oldDebugLevel;

	mprLog(ep, 0, "Dump of objects in use\n");

	oldDebugLevel = ep->gc.debugLevel;

	ep->gc.debugLevel = 3;
	ep->gc.objectsInUse = 0;
	ep->gc.propertiesInUse = 0;
	ep->gc.collecting = 1;

	resetMarks(ep, &ep->slabs[EJS_SLAB_OBJ]);
	mark(ep);

	ep->gc.collecting = 0;
	ep->gc.debugLevel = oldDebugLevel;

	mprLog(ep, 0, "%d objects and %d properties in use",
		ep->gc.objectsInUse, ep->gc.propertiesInUse);
	mprLog(ep, 0, "%d object bytes, %d property bytes and %d total",
		(int) (ep->gc.objectsInUse * sizeof(EjsObj)),
		(int) (ep->gc.propertiesInUse * sizeof(EjsProperty)),
		(int) ((ep->gc.objectsInUse * sizeof(EjsObj) +
		 		ep->gc.propertiesInUse * sizeof(EjsProperty))));
}

#endif
/******************************************************************************/
/*
 *	Return true if there is time to do a garbage collection and if we will
 *	benefit from it.
 */

int ejsIsTimeForGC(Ejs *ep, int timeTillNextEvent)
{
	EjsGC		*gc;

	if (timeTillNextEvent < EJS_MIN_TIME_FOR_GC) {
		/*
		 *	Not enough time to complete a collection
		 */
		return 0;
	}

	gc = &ep->gc;

	/*
	 *	Return if we haven't done enough work to warrant a collection
 	 *	Trigger a little short of the work quota to try to run GC before
	 *	a demand allocation requires it.
	 */
	if (!gc->enable || !gc->enableIdleCollect || 
			(gc->workDone < (gc->workQuota - EJS_GC_MIN_WORK_QUOTA))) {
		return 0;
	}

#if UNUSED
	mprLog(ep, 0, "Time for GC. Work done %d, time till next event %d",
		gc->workDone, timeTillNextEvent);
#endif
	return 1;
}

/******************************************************************************/
/*
 *	Return the amount of memory in use by EJS
 */

uint ejsGetUsedMemory(Ejs *ep)
{
#if BLD_FEATURE_ALLOC_STATS
	EjsSlab		*slab;
	int			i, totalMemory, slabMemory;

	totalMemory = 0;
	for (i = 0; i < EJS_SLAB_MAX; i++) {
		slab = &ep->slabs[i];
		slabMemory = slab->allocCount * slab->size;
		totalMemory += slabMemory;
	}
	return totalMemory;
#else
	return 0;
#endif
}

/******************************************************************************/
/*
 *	Return the amount of memory allocated by EJS
 */

uint ejsGetAllocatedMemory(Ejs *ep)
{
#if BLD_FEATURE_ALLOC_STATS
	EjsSlab		*slab;
	int			i, totalMemory, slabMemory;

	totalMemory = 0;
	for (i = 0; i < EJS_SLAB_MAX; i++) {
		slab = &ep->slabs[i];
		slabMemory = (slab->allocCount + slab->freeCount) * slab->size;
		totalMemory += slabMemory;
	}
	return totalMemory;
#else
	return 0;
#endif
}

/******************************************************************************/
/*
 *	On a memory allocation failure, go into graceful degrade mode. Set all
 *	slab allocation chunk increments to 1 so we can create an exception block 
 *	to throw.
 */

static void ejsGracefulDegrade(Ejs *ep)
{
	EjsSlab		*slab;
	int			i;

	mprLog(ep, 1, "WARNING: Memory almost depleted. In graceful degrade mode");
	for (i = 0; i < EJS_SLAB_MAX; i++) {
		slab = &ep->slabs[i];
		slab->allocIncrement = 8;
	}
	ep->gc.degraded = 1;
}

/******************************************************************************/

int ejsSetGCDebugLevel(Ejs *ep, int debugLevel)
{
	int		old;

	old = ep->gc.debugLevel;
	ep->gc.debugLevel = debugLevel;
	return old;
}

/******************************************************************************/

int ejsSetGCMaxMemory(Ejs *ep, uint maxMemory)
{
	int		old;

	old = ep->gc.maxMemory;
	ep->gc.maxMemory = maxMemory;

	return old;
}

/******************************************************************************/

bool ejsBlockInUseInt(EjsVar *vp)
{
	if (vp) {
#if BLD_DEBUG
		if (vp->gc.magic != EJS_MAGIC) {
			return 0;
		}
		if (vp->type == EJS_TYPE_OBJECT && vp->objectState && 
			vp->objectState->gc.magic != EJS_MAGIC) {
			return 0;
		}
#endif
		return 1;
	}
	return 1;
}

/******************************************************************************/
#else
void ejsGarbageDummy() {}

#endif /* BLD_FEATURE_EJS */

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
