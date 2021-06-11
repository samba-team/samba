/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Stefan Metzmacher 2021

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

#ifndef _SAMBA_LIB_UTIL_MATCHING_H_
#define _SAMBA_LIB_UTIL_MATCHING_H_

struct samba_path_matching;

NTSTATUS samba_path_matching_mswild_create(TALLOC_CTX *mem_ctx,
					   bool case_sensitive,
					   const char *namelist_in,
					   struct samba_path_matching **ppm);

NTSTATUS samba_path_matching_regex_sub1_create(TALLOC_CTX *mem_ctx,
					       const char *namelist_in,
					       struct samba_path_matching **ppm);

NTSTATUS samba_path_matching_check_last_component(struct samba_path_matching *pm,
						  const char *name,
						  ssize_t *p_match_idx,
						  ssize_t *p_replace_start,
						  ssize_t *p_replace_end);

#endif /* _SAMBA_LIB_UTIL_MATCHING_H_ */
