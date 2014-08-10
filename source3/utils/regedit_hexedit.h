/*
 * Samba Unix/Linux SMB client library
 * Registry Editor
 * Copyright (C) Christopher Davis 2012
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _HEXEDIT_H_
#define _HEXEDIT_H_

#include <ncurses.h>

enum {
	HE_CURSOR_UP = 0x1000,
	HE_CURSOR_DOWN = 0x1100,
	HE_CURSOR_LEFT = 0x1200,
	HE_CURSOR_RIGHT = 0x1300,
	HE_CURSOR_PGUP = 0x1400,
	HE_CURSOR_PGDN = 0x1500,
	HE_BACKSPACE = 0x1600,
	HE_DELETE = 0x1700,
};

#define LINE_WIDTH 44
struct hexedit;

struct hexedit *hexedit_new(TALLOC_CTX *ctx, WINDOW *parent, const void *data,
			    size_t sz);
WERROR hexedit_set_buf(struct hexedit *buf, const void *data, size_t sz);
const void *hexedit_get_buf(struct hexedit *buf);
size_t hexedit_get_buf_len(struct hexedit *buf);
void hexedit_set_cursor(struct hexedit *buf);
void hexedit_refresh(struct hexedit *buf);
void hexedit_driver(struct hexedit *buf, int c);
WERROR hexedit_resize_buffer(struct hexedit *buf, size_t newsz);

#endif
