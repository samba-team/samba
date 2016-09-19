/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling cab structures

   Copyright (C) Guenther Deschner 2016

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

uint32_t ndr_count_cfdata(const struct cab_file *r);
uint32_t ndr_cab_generate_checksum(const struct CFDATA *r);
enum cf_compress_type ndr_cab_get_compression(const struct cab_file *r);
