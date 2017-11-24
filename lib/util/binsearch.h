/*
   Unix SMB/CIFS implementation.

   a generic binary search macro

   Copyright (C) Andrew Tridgell 2009

     ** NOTE! The following LGPL license applies to the binsearch.h
     ** header. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _BINSEARCH_H
#define _BINSEARCH_H

/* a binary array search, where the array is an array of pointers to structures,
   and we want to find a match for 'target' on 'field' in those structures.

   Inputs:
      array:          base pointer to an array of structures
      arrray_size:    number of elements in the array
      field:          the name of the field in the structure we are keying off
      target:         the field value we are looking for
      comparison_fn:  the comparison function
      result:         where the result of the search is put

   if the element is found, then 'result' is set to point to the found array element. If not,
   then 'result' is set to NULL.

   The array is assumed to be sorted by the same comparison_fn as the
   search (with, for example, qsort)
 */
#define BINARY_ARRAY_SEARCH_P(array, array_size, field, target, comparison_fn, result) do { \
	int32_t _b, _e; \
	(result) = NULL; \
	if (array_size) { for (_b = 0, _e = (array_size)-1; _b <= _e; ) { \
		int32_t _i = (_b+_e)/2; \
		int _r = comparison_fn(target, array[_i]->field); \
		if (_r == 0) { (result) = array[_i]; break; } \
		if (_r < 0) _e = _i - 1; else _b = _i + 1; \
	}} } while (0)

/*
  like BINARY_ARRAY_SEARCH_P, but assumes that the array is an array
  of structures, rather than pointers to structures

  result points to the found structure, or NULL
 */
#define BINARY_ARRAY_SEARCH(array, array_size, field, target, comparison_fn, result) do { \
	int32_t _b, _e; \
	(result) = NULL; \
	if (array_size) { for (_b = 0, _e = (array_size)-1; _b <= _e; ) {	\
		int32_t _i = (_b+_e)/2; \
		int _r = comparison_fn(target, array[_i].field); \
		if (_r == 0) { (result) = &array[_i]; break; } \
		if (_r < 0) _e = _i - 1; else _b = _i + 1; \
	}} } while (0)

/*
  like BINARY_ARRAY_SEARCH_P, but assumes that the array is an array
  of elements, rather than pointers to structures

  result points to the found structure, or NULL
 */
#define BINARY_ARRAY_SEARCH_V(array, array_size, target, comparison_fn, result) do { \
	int32_t _b, _e; \
	(result) = NULL; \
	if (array_size) { for (_b = 0, _e = (array_size)-1; _b <= _e; ) {	\
		int32_t _i = (_b+_e)/2; \
		int _r = comparison_fn(target, array[_i]); \
		if (_r == 0) { (result) = &array[_i]; break; } \
		if (_r < 0) _e = _i - 1; else _b = _i + 1; \
	}} } while (0)


/*
  like BINARY_ARRAY_SEARCH_V, but if an exact result is not found, the 'next'
  argument will point to the element after the place where the exact result
  would have been. If an exact result is found, 'next' will be NULL. If the
  target is beyond the end of the list, both 'exact' and 'next' will be NULL.
  Unlike other binsearch macros, where there are several elements that compare
  the same, the exact result will always point to the first one.

  If you don't care to distinguish between the 'greater than' and 'equals'
  cases, you can use the same pointer for both 'exact' and 'next'.

  As with all the binsearch macros, the comparison function is always called
  with the search term first.
 */
#define BINARY_ARRAY_SEARCH_GTE(array, array_size, target, comparison_fn, \
				exact, next) do {		\
	int32_t _b, _e;						\
	(exact) = NULL; (next) = NULL;			\
	if ((array_size) > 0) {					\
		for (_b = 0, _e = (array_size)-1; _b <= _e; ) {	\
			int32_t _i = (_b + _e) / 2;			\
			int _r = comparison_fn(target, &array[_i]); \
			if (_r == 0) {					\
				(exact) = &array[_i];			\
				_e = _i - 1;				\
			} else if (_r < 0) { _e = _i - 1;		\
			} else  { _b = _i + 1; }			\
		}							\
		if ((exact) == NULL &&_b < (array_size)) {		\
			(next) = &array[_b];				\
	} } } while (0)

#endif
