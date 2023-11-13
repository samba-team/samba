/*
   Unix SMB/CIFS implementation.
   Group Key Distribution Protocol functions

   Copyright (C) Catalyst.Net Ltd 2023

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef LIB_CRYPTO_GKDI_H
#define LIB_CRYPTO_GKDI_H

#include <stdint.h>

static const int gkdi_l1_key_iteration = 32;
static const int gkdi_l2_key_iteration = 32;

static const int64_t gkdi_key_cycle_duration = 360000000000;
static const int64_t gkdi_max_clock_skew = 3000000000;

#endif /* LIB_CRYPTO_GKDI_H */
