/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *
 *  Copyright (C) Marcin Krzysztof Porwit    2005,
 *  Copyright (C) Gerald (Jerry) Carter      2005.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _REG_PERFCOUNT_H
#define _REG_PERFCOUNT_H

#include "reg_parse_prs.h"

uint32_t reg_perfcount_get_base_index(void);
uint32_t reg_perfcount_get_last_counter(uint32_t base_index);
uint32_t reg_perfcount_get_last_help(uint32_t last_counter);
uint32_t reg_perfcount_get_counter_help(uint32_t base_index, char **retbuf);
uint32_t reg_perfcount_get_counter_names(uint32_t base_index, char **retbuf);
WERROR reg_perfcount_get_hkpd(prs_struct *ps, uint32_t max_buf_size, uint32_t *outbuf_len, const char *object_ids);

#endif /* _REG_PERFCOUNT_H */
