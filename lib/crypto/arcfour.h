#ifndef ARCFOUR_HEADER_H
#define ARCFOUR_HEADER_H

/*
   Unix SMB/CIFS implementation.

   (C) 2011 Samba Team.

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

#include "../lib/util/data_blob.h"

struct arcfour_state {
	uint8_t sbox[256];
	uint8_t index_i;
	uint8_t index_j;
};

void arcfour_init(struct arcfour_state *state, const DATA_BLOB *key);
void arcfour_crypt_sbox(struct arcfour_state *state, uint8_t *data, int len);
void arcfour_crypt_blob(uint8_t *data, int len, const DATA_BLOB *key);
void arcfour_crypt(uint8_t *data, const uint8_t keystr[16], int len);

#endif /* ARCFOUR_HEADER_H */
