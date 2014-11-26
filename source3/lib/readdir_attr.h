/*
 * Fetch filesystem metadata in readdir/marshall context
 *
 * Copyright (C) Ralph Boehme 2014
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _READDIR_ATTR_H
#define _READDIR_ATTR_H

enum readdir_attr_type {RDATTR_NONE, RDATTR_AAPL};

struct readdir_attr_data {
	enum readdir_attr_type type;
	union attr_data {
		struct aapl {
			uint64_t rfork_size;
			char finder_info[16];
			uint32_t max_access;
			mode_t unix_mode;
		} aapl;
	} attr_data;
};

#endif	/* _READDIR_ATTR_H */
