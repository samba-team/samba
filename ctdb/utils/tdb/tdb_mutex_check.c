/*
   Check the mutex lock information in tdb database

   Copyright (C) Amitay Isaacs 2015-2021

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>

#ifndef USE_TDB_MUTEX_LOCKING
#define USE_TDB_MUTEX_LOCKING  1
#endif

#include "lib/tdb/common/tdb_private.h"
#include "lib/tdb/common/mutex.c"

static uint8_t *hex_decode(const char *hex_in, size_t *plen)
{
	size_t i;
	int num;
	uint8_t *buffer;
	size_t len;

	len = strlen(hex_in) / 2;
	if (len == 0) {
		return NULL;
	}

	buffer = malloc(len);
	if (buffer == NULL) {
		return NULL;
	}

	for (i = 0; i < len; i++) {
		sscanf(&hex_in[i*2], "%02X", &num);
		buffer[i] = (uint8_t)num;
	}

	*plen = len;

	return buffer;
}

static int get_hash_chain(struct tdb_context *tdb, const char *hex_key)
{
	TDB_DATA key = {
		.dsize = 0,
	};
	unsigned int hash;

	key.dptr = hex_decode(hex_key, &key.dsize);
	if (key.dptr == NULL || key.dsize == 0) {
		return -1;
	}
	hash = tdb_jenkins_hash(&key);
	free(key.dptr);

	return hash % tdb_hash_size(tdb);
}

static void check_one(struct tdb_mutexes *mutexes, int chain)
{
	pthread_mutex_t *m;
	int ret;
	int pthread_mutex_consistent_np(pthread_mutex_t *);

	m = &mutexes->hashchains[chain+1];
	ret = pthread_mutex_trylock(m);
	if (ret == 0) {
		pthread_mutex_unlock(m);
		return;
	}
	if (ret == EOWNERDEAD) {
		ret = pthread_mutex_consistent_np(m);
		if (ret != 0) {
			printf("[%6d] consistent failed (%d)\n", chain, ret);
			return;
		}
		ret = pthread_mutex_unlock(m);
		if (ret != 0) {
			printf("[%6d] unlock failed (%d)\n", chain, ret);
			return;
		}
		printf("[%6d] cleaned\n", chain);
		return;
	}
	if (ret == EBUSY) {
		printf("[%6d] pid=%d\n", chain, m->__data.__owner);
		return;
	}
	printf("[%6d] trylock failed (%d)\n", chain, ret);
}

static void check_all(struct tdb_mutexes *mutexes, unsigned int hash_size)
{
	unsigned int i;

	for (i=0; i<hash_size; i++) {
		check_one(mutexes, i);
	}
}

int main(int argc, char **argv)
{
	const char *tdb_file;
	TDB_CONTEXT *tdb;
	uint32_t tdb_flags;
	int chain, i;

	if (argc < 2) {
		printf("Usage %s <tdb file> [<key1> <key2>]\n", argv[0]);
		exit(1);
	}

	tdb_file = argv[1];

	tdb_flags = TDB_MUTEX_LOCKING | TDB_INCOMPATIBLE_HASH |
		    TDB_CLEAR_IF_FIRST;
	tdb = tdb_open(tdb_file, 0, tdb_flags, O_RDWR, 0);
	if (tdb == NULL) {
		printf("Error opening %s\n", tdb_file);
		exit(1);
	}

	if (tdb->mutexes == NULL) {
		printf("Mutexes are not mmapped\n");
		exit(1);
	}

	if (argc == 2) {
		check_all(tdb->mutexes, tdb_hash_size(tdb));
	} else {
		for (i=2; i<argc; i++) {
			chain = get_hash_chain(tdb, argv[i]);
			if (chain == -1) {
				continue;
			}
			check_one(tdb->mutexes, chain);
		}
	}

	tdb_close(tdb);
	return 0;
}
