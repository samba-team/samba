/*
   Copyright (c) Ralph Boehme			2012-2014

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
  Typesafe, dynamic object store based on talloc

  Usage
  =====

  Define some types:

  A key/value store aka dictionary that supports retrieving elements
  by key:

    typedef dict_t DALLOC_CTX;

  An ordered set that can store different objects which can be
  retrieved by number:

    typedef set_t DALLOC_CTX;

  Create an dalloc object and add elementes of different type:

    TALLOC_CTX *mem_ctx = talloc_new(NULL);
    DALLOC_CTX *d = dalloc_new(mem_ctx);

  Store an int value in the object:

    uint64_t i = 1;
    dalloc_add_copy(d, &i, uint64_t);

  Store a string:

    dalloc_stradd(d, "hello world");

  Add a nested object:

    DALLOC_CTX *nested = dalloc_new(d);
    dalloc_add(d, nested, DALLOC_CTX);

  Add an int value to the nested object, this can be fetched:

    i = 2;
    dalloc_add_copy(nested, &i, uint64_t);

  Add a nested set:

    set_t *set = dalloc_zero(nested, set_t);
    dalloc_add(nested, set, set_t);

  Add an int value to the set:

    i = 3;
    dalloc_add_copy(set, &i, uint64_t);

  Add a dictionary (key/value store):

    dict_t *dict = dalloc_zero(nested, dict_t);
    dalloc_add(nested, dict, dict_t);

  Store a string as key in the dict:

    dalloc_stradd(dict, "key");

  Add a value for the key:

    i = 4;
    dalloc_add_copy(dict, &i, uint64_t);

  Fetching value references
  =========================

  You can fetch anything that is not a DALLOC_CTXs, because passing
  "DALLOC_CTXs" as type to the functions dalloc_get() and
  dalloc_value_for_key() tells the function to step into that object
  and expect more arguments that specify which element to fetch.

  Get reference to an objects element by position:

    uint64_t *p = dalloc_get(d, "uint64_t", 0);

  p now points to the first int with a value of 1.

  Get reference to the "hello world" string:

    str = dalloc_get(d, "char *", 1);

  You can't fetch a DALLOC_CTX itself:

    nested = dalloc_get(d, "DALLOC_CTX", 2);

  But you can fetch elements from the nested DALLOC_CTX:

    p = dalloc_get(d, "DALLOC_CTX", 2, "uint64_t", 0);

  p now points to the value 2.

  You can fetch types that are typedefd DALLOC_CTXs:

    set = dalloc_get(d, "DALLOC_CTX", 2, "set_t", 1);

  Fetch int from set, must use DALLOC_CTX as type for the set:

    p = dalloc_get(d, "DALLOC_CTX", 2, "DALLOC_CTX", 1, "uint64_t", 0);

  p points to 3.

  Fetch value by key from dictionary:

    p = dalloc_value_for_key(d, "DALLOC_CTX", 2, "DALLOC_CTX", 2, "key");

  p now points to 4.
*/

#ifndef DALLOC_H
#define DALLOC_H

#include <talloc.h>

struct dalloc_ctx;
typedef struct dalloc_ctx DALLOC_CTX;

#define dalloc_new(mem_ctx) (DALLOC_CTX *)_dalloc_new((mem_ctx), "DALLOC_CTX")
#define dalloc_zero(mem_ctx, type) (type *)_dalloc_new((mem_ctx), #type)

/**
 * talloc a chunk for obj of required size, copy the obj into the
 * chunk and add the chunk to the dalloc ctx
 **/
#define dalloc_add_copy(d, obj, type) _dalloc_add_talloc_chunk((d), (obj), #type, sizeof(type))

/**
 * Add a pointer to a talloced object to the dalloc ctx. The object
 * must be a talloc child of the dalloc ctx.
 **/
#define dalloc_add(d, obj, type) _dalloc_add_talloc_chunk((d), (obj), #type, 0)


extern void *dalloc_get(const DALLOC_CTX *d, ...);
extern void *dalloc_value_for_key(const DALLOC_CTX *d, ...);
extern size_t dalloc_size(const DALLOC_CTX *d);
extern void *dalloc_get_object(const DALLOC_CTX *d, int i);
extern const char *dalloc_get_name(const DALLOC_CTX *d, int i);
extern int dalloc_stradd(DALLOC_CTX *d, const char *string);

extern void *_dalloc_new(TALLOC_CTX *mem_ctx, const char *type);
extern int _dalloc_add_talloc_chunk(DALLOC_CTX *d, void *obj, const char *type, size_t size);

extern char *dalloc_dump(DALLOC_CTX *dd, int nestinglevel);

#endif  /* DALLOC_H */
