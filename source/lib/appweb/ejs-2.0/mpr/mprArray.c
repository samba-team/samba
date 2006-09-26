/**
 *	@file 	mprArray.c
 *	@brief	Growable array structure
 *	@overview Simple growable array structure.
 *	@remarks Most routines in this file are not thread-safe. It is the callers 
 *		responsibility to perform all thread synchronization.
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

/********************************** Includes **********************************/

#include	"mpr.h"

/******************************************************************************/
/*
 *	Create a general growable array structure. Use mprFree to destroy.
 */

MprArray *mprCreateItemArrayInternal(MPR_LOC_DEC(ctx, loc), int initialSize, 
	int maxSize)
{
	MprArray	*array;
	int			size;

	mprAssert(initialSize <= maxSize);

	array = (MprArray*) mprSlabAllocZeroedBlock(MPR_LOC_PASS(ctx, loc), 
		sizeof(MprArray), 0);
	if (array == 0) {
		return 0;
	}

	if (initialSize == 0) {
		initialSize = MPR_ARRAY_INCR;
	}
	if (maxSize == 0) {
		maxSize = MAXINT;
	}
	size = initialSize * sizeof(void*);

	array->items = (void**) mprSlabAllocBlock(MPR_LOC_PASS(array, loc), 
		size, 0);

	if (array->items == 0) {
		mprFree(array);
		return 0;
	}

	array->capacity = initialSize;
	array->maxSize = maxSize;
	array->incr = min(initialSize * 2, (array->maxSize - array->length));
	array->length = 0;

	return array;
}

/******************************************************************************/
/*
 *	Add an item to the array
 */

int mprAddItem(MprArray *array, void *item)
{
	int		memsize, index, len;

	mprAssert(array);
	mprAssert(array->capacity >= 0);
	mprAssert(array->length >= 0);

	if (array->length < array->capacity) {
		/*
		 *	Room to fit in the current capacity
	 	 */
		index = array->length++;
		array->items[index] = item;
		return index;
	}
	mprAssert(array->length == array->capacity);

	/*
	 *	Need to grow the array
	 */
	if (array->capacity >= array->maxSize) {
		mprAssert(array->capacity < array->maxSize);
		return MPR_ERR_TOO_MANY;
	}

	len = array->capacity + array->incr;
	memsize = len * sizeof(void*);

	/*
	 *	Grow the array of items
	 */

	array->items = (void**) mprRealloc(array, array->items, memsize);

	/*
	 *	Zero the new portion
	 */
	memset(&array->items[array->capacity], 0, sizeof(void*) * array->incr);
	array->capacity = len;

	array->incr = min(array->incr * 2, (array->maxSize - array->length));

	index = array->length++;
	array->items[index] = item;

	return index;
}

/******************************************************************************/
/*
 *	Remove an item from the array
 */

int mprRemoveItem(MprArray *array, void *item)
{
	int		index;

	mprAssert(array);
	mprAssert(array->capacity > 0);
	mprAssert(array->length > 0);

	index = mprFindItem(array, item);
	if (index < 0) {
		return index;
	}

	return mprRemoveItemByIndex(array, index);
}

/******************************************************************************/
/*
 *	Remove an index from the array
 */

int mprRemoveItemByIndex(MprArray *array, int index)
{
	void	**items;
	int		i;

	mprAssert(array);
	mprAssert(array->capacity > 0);
	mprAssert(index >= 0 && index < array->capacity);
	mprAssert(array->items[index] != 0);
	mprAssert(array->length > 0);

	if (index < 0 || index >= array->length) {
		return MPR_ERR_NOT_FOUND;
	}

	/*
	 *	Copy down to compress
	 */
	items = array->items;
	for (i = index; i < (array->length - 1); i++) {
		items[i] = items[i + 1];
	}
	array->length--;

#if BLD_DEBUG
	if (array->length < array->capacity) {
		items[array->length] = 0;
	}
#endif
	return 0;
}

/******************************************************************************/

int mprRemoveRangeOfItems(MprArray *array, int start, int end)
{
	void	**items;
	int		i, count;

	mprAssert(array);
	mprAssert(array->capacity > 0);
	mprAssert(array->length > 0);
	mprAssert(start > end);

	if (start < 0 || start >= array->length) {
		return MPR_ERR_NOT_FOUND;
	}
	if (end < 0 || end >= array->length) {
		return MPR_ERR_NOT_FOUND;
	}
	if (start > end) {
		return MPR_ERR_BAD_ARGS;
	}

	/*
	 *	Copy down to compress
	 */
	items = array->items;
	count = end - start;
	for (i = start; i < (array->length - count); i++) {
		items[i] = items[i + count];
	}
	array->length -= count;

#if BLD_DEBUG
	if (array->length < array->capacity) {
		for (i = array->length; i < array->capacity; i++) {
			items[i] = 0;
		}
	}
#endif
	return 0;
}

/******************************************************************************/

void *mprGetItem(MprArray *array, int index)
{
	mprAssert(array);

	if (index < 0 || index >= array->length) {
		return 0;
	}
	return array->items[index];
}

/******************************************************************************/

void *mprGetFirstItem(MprArray *array, int *last)
{
	mprAssert(array);
	mprAssert(last);

	if (array == 0) {
		return 0;
	}

	*last = 0;

	if (array->length == 0) {
		return 0;
	}
	return array->items[0];
}

/******************************************************************************/

void *mprGetNextItem(MprArray *array, int *last)
{
	int		index;

	mprAssert(array);
	mprAssert(last);
	mprAssert(*last >= 0);

	index = *last;

	if (++index < array->length) {
		*last = index;
		return array->items[index];
	}
	return 0;
}

/******************************************************************************/

void *mprGetPrevItem(MprArray *array, int *last)
{
	int		index;

	mprAssert(array);
	mprAssert(last);
	mprAssert(*last >= 0);

	if (array == 0) {
		return 0;
	}

	index = *last;

	if (--index < array->length && index >= 0) {
		*last = index;
		return array->items[index];
	}
	return 0;
}

/******************************************************************************/

int mprGetItemCount(MprArray *array)
{
	mprAssert(array);

	if (array == 0) {
		return 0;
	}

	return array->length;
}

/******************************************************************************/

int mprGetItemCapacity(MprArray *array)
{
	mprAssert(array);

	if (array == 0) {
		return 0;
	}

	return array->capacity;
}

/******************************************************************************/

void mprClearAndFreeItems(MprArray *array)
{
	int		i;

	mprAssert(array);

	for (i = 0; i < array->length; i++) {
		mprFree(array->items[i]);
	}
}

/******************************************************************************/

void mprClearItems(MprArray *array)
{
	mprAssert(array);

	array->length = 0;
}

/******************************************************************************/

int mprFindItem(MprArray *array, void *item)
{
	int		i;

	mprAssert(array);
	
	for (i = 0; i < array->length; i++) {
		if (array->items[i] == item) {
			return i;
		}
	}
	return MPR_ERR_NOT_FOUND;
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
