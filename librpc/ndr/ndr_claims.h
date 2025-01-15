/*
   Unix SMB/CIFS implementation.

   routines for helping the compression in claims

   Copyright (C) Andrew Bartlett 2023

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

#ifndef _LIBRPC_NDR_NDR_CLAIMS_H
#define _LIBRPC_NDR_NDR_CLAIMS_H

enum ndr_compression_alg ndr_claims_compression_alg(enum CLAIMS_COMPRESSION_FORMAT wire_alg);
enum CLAIMS_COMPRESSION_FORMAT ndr_claims_actual_wire_compression_alg(enum CLAIMS_COMPRESSION_FORMAT specified_compression,
								      struct CLAIMS_SET_NDR *claims_set,
								      int flags);

size_t ndr_claims_compressed_size(struct CLAIMS_SET_NDR *claims_set,
				 enum CLAIMS_COMPRESSION_FORMAT wire_alg,
				 int flags);


#endif /* _LIBRPC_NDR_NDR_CLAIMS_H */
