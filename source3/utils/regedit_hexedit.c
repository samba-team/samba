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

#include "includes.h"
#include "regedit_hexedit.h"

static int max_rows(WINDOW *win)
{
	int maxy, maxx;

	getmaxyx(win, maxy, maxx);

	return maxy - 1;
}

static int hexedit_free(struct hexedit *buf)
{
	if (buf->status_line) {
		delwin(buf->status_line);
	}
	if (buf->win) {
		delwin(buf->win);
	}

	return 0;
}

struct hexedit *hexedit_new(TALLOC_CTX *ctx, WINDOW *parent, int nlines,
			    int y, int x, const void *data, size_t sz)
{
	struct hexedit *buf;

	buf = talloc_zero(ctx, struct hexedit);
	if (buf == NULL) {
		return NULL;
	}

	talloc_set_destructor(buf, hexedit_free);

	buf->data = talloc_zero_array(buf, uint8_t, sz);
	if (buf->data == NULL) {
		goto fail;
	}

	if (data) {
		memcpy(buf->data, data, sz);
	}

	buf->len = sz;
	buf->alloc_size = sz;
	buf->win = derwin(parent, nlines, LINE_WIDTH, y, x);
	if (buf->win == NULL) {
		goto fail;
	}
	buf->cursor_x = HEX_COL1;

	buf->status_line = derwin(buf->win, 1, LINE_WIDTH, max_rows(buf->win), 0);
	if (buf->status_line == NULL) {
		goto fail;
	}
	wattron(buf->status_line, A_REVERSE | A_STANDOUT);

	return buf;

fail:
	talloc_free(buf);

	return NULL;
}

static size_t bytes_per_screen(WINDOW *win)
{
	return max_rows(win) * BYTES_PER_LINE;
}

void hexedit_set_cursor(struct hexedit *buf)
{
	werase(buf->status_line);
	wprintw(buf->status_line, "Len:%lu Off:%lu Val:0x%X", buf->len,
		buf->cursor_offset, buf->data[buf->cursor_offset]);
	wmove(buf->win, buf->cursor_y, buf->cursor_x);
	wcursyncup(buf->win);
	wsyncup(buf->win);
	untouchwin(buf->win);
}

void hexedit_refresh(struct hexedit *buf)
{
	size_t end;
	size_t lineno;
	size_t off;

	werase(buf->win);

	end = buf->offset + bytes_per_screen(buf->win);
	if (end > buf->len) {
		end = buf->len;
	}

	for (off = buf->offset, lineno = 0; off < end; off += BYTES_PER_LINE, ++lineno) {
		uint8_t *line = buf->data + off;
		size_t i, endline;

		wmove(buf->win, lineno, 0);
		wprintw(buf->win, "%08X  ", off);

		endline = BYTES_PER_LINE;

		if (off + BYTES_PER_LINE > buf->len) {
			endline = buf->len - off;
		}

		for (i = 0; i < endline; ++i) {
			wprintw(buf->win, "%02X", line[i]);
			if (i + 1 < endline) {
				if (i == 3) {
					wprintw(buf->win, "  ");
				} else {
					wprintw(buf->win, " ");
				}
			}
		}

		wmove(buf->win, lineno, ASCII_COL);
		for (i = 0; i < endline; ++i) {
			if (isprint(line[i])) {
				waddch(buf->win, line[i]);
			} else {
				waddch(buf->win, '.');
			}
		}
	}
}

static void calc_cursor_offset(struct hexedit *buf)
{
	buf->cursor_offset = buf->offset + buf->cursor_y * BYTES_PER_LINE + buf->cursor_line_offset;
}

static int offset_to_hex_col(size_t pos)
{
	switch (pos) {
	case 0:
		return HEX_COL1;
	case 1:
		return HEX_COL1 + 3;
	case 2:
		return HEX_COL1 + 6;
	case 3:
		return HEX_COL1 + 9;

	case 4:
		return HEX_COL2;
	case 5:
		return HEX_COL2 + 3;
	case 6:
		return HEX_COL2 + 6;
	case 7:
		return HEX_COL2 + 9;
	}

	return -1;
}

static bool scroll_down(struct hexedit *buf)
{
	if (buf->offset + bytes_per_screen(buf->win) >= buf->len) {
		return false;
	}

	buf->offset += BYTES_PER_LINE;

	return true;
}

static bool scroll_up(struct hexedit *buf)
{
	if (buf->offset == 0) {
		return false;
	}

	buf->offset -= BYTES_PER_LINE;

	return true;
}

static void cursor_down(struct hexedit *buf)
{
	if (buf->cursor_y + 1 == max_rows(buf->win)) {
		if (scroll_down(buf)) {
			hexedit_refresh(buf);
		}
	} else {
		if (buf->cursor_offset + BYTES_PER_LINE >= buf->len) {
			return;
		}
		buf->cursor_y++;
	}

	calc_cursor_offset(buf);
}

static void cursor_up(struct hexedit *buf)
{
	if (buf->cursor_y == 0) {
		if (scroll_up(buf)) {
			hexedit_refresh(buf);
		}
	} else {
		buf->cursor_y--;
	}

	calc_cursor_offset(buf);
}

static bool is_over_gap(struct hexedit *buf)
{
	int col;

	if (buf->cursor_x < ASCII_COL) {
		if (buf->cursor_x >= HEX_COL2) {
			col = buf->cursor_x - HEX_COL2;
		} else {
			col = buf->cursor_x - HEX_COL1;
		}

		switch (col) {
		case 2:
		case 5:
		case 8:
			return true;
		}
	}

	return false;
}

static void cursor_left(struct hexedit *buf)
{
	if (buf->cursor_x == HEX_COL1) {
		return;
	}
	if (buf->cursor_x == HEX_COL2) {
		buf->cursor_x = HEX_COL1_END - 1;
		buf->cursor_line_offset = 3;
		buf->nibble = 1;
	} else if (buf->cursor_x == ASCII_COL) {
		size_t off = buf->offset + buf->cursor_y * BYTES_PER_LINE;
		if (off + 7 >= buf->len) {
			size_t lastpos = buf->len - off - 1;
			buf->cursor_x = offset_to_hex_col(lastpos) + 1;
			buf->cursor_line_offset = lastpos;
		} else {
			buf->cursor_x = HEX_COL2_END - 1;
			buf->cursor_line_offset = 7;
		}
		buf->nibble = 1;
	} else {
		if (buf->cursor_x > ASCII_COL || buf->nibble == 0) {
			buf->cursor_line_offset--;
		}
		buf->cursor_x--;
		buf->nibble = !buf->nibble;
	}

	if (is_over_gap(buf)) {
		buf->cursor_x--;
	}

	calc_cursor_offset(buf);
}

static void cursor_right(struct hexedit *buf)
{
	int new_x = buf->cursor_x + 1;

	if (new_x == ASCII_COL_END) {
		return;
	}
	if ((buf->cursor_x >= ASCII_COL || buf->nibble == 1) &&
	    buf->cursor_offset + 1 == buf->len) {
		if (buf->cursor_x < ASCII_COL) {
			new_x = ASCII_COL;
			buf->cursor_line_offset = 0;
			buf->nibble = 0;
		} else {
			return;
		}
	}
	if (new_x == HEX_COL1_END) {
		new_x = HEX_COL2;
		buf->cursor_line_offset = 4;
		buf->nibble = 0;
	} else if (new_x == HEX_COL2_END) {
		new_x = ASCII_COL;
		buf->cursor_line_offset = 0;
		buf->nibble = 0;
	} else {
		if (buf->cursor_x >= ASCII_COL || buf->nibble == 1) {
			buf->cursor_line_offset++;
		}
		buf->nibble = !buf->nibble;
	}

	buf->cursor_x = new_x;

	if (is_over_gap(buf)) {
		buf->cursor_x++;
	}

	calc_cursor_offset(buf);
}

static void do_edit(struct hexedit *buf, int c)
{
	uint8_t *byte;

	byte = buf->data + buf->cursor_offset;

	if (buf->cursor_x >= ASCII_COL) {
		*byte = (uint8_t)c;

		mvwprintw(buf->win, buf->cursor_y,
			  offset_to_hex_col(buf->cursor_line_offset), "%X", c);
		if (!isprint(c)) {
			c = '.';
		}
		mvwaddch(buf->win, buf->cursor_y, ASCII_COL + buf->cursor_line_offset, c);
		cursor_right(buf);
	} else {
		if (!isxdigit(c)) {
			return;
		}
		c = toupper(c);
		waddch(buf->win, c);

		if (isdigit(c)) {
			c = c - '0';
		} else {
			c = c - 'A' + 10;
		}
		if (buf->nibble == 0) {
			*byte = (*byte & 0x0f) | c << 4;
		} else {
			*byte = (*byte & 0xf0) | c;
		}

		c = *byte;
		if (!isprint(c)) {
			c = '.';
		}
		mvwaddch(buf->win, buf->cursor_y, ASCII_COL + buf->cursor_line_offset, c);

		if (buf->cursor_x + 1 != HEX_COL2_END) {
			cursor_right(buf);
		}
	}
}

void hexedit_driver(struct hexedit *buf, int c)
{
	switch (c) {
	case HE_CURSOR_UP:
		cursor_up(buf);
		break;
	case HE_CURSOR_DOWN:
		cursor_down(buf);
		break;
	case HE_CURSOR_LEFT:
		cursor_left(buf);
		break;
	case HE_CURSOR_RIGHT:
		cursor_right(buf);
		break;
	case HE_CURSOR_PGUP:
		break;
	case HE_CURSOR_PGDN:
		break;
	default:
		do_edit(buf, c & 0xff);
		break;
	}
}

WERROR hexedit_resize_buffer(struct hexedit *buf, size_t newsz)
{
	/* reset the cursor if it'll be out of bounds
	   after the resize */
	if (buf->cursor_offset >= newsz) {
		buf->cursor_y = 0;
		buf->cursor_x = HEX_COL1;
		buf->offset = 0;
		buf->cursor_offset = 0;
		buf->cursor_line_offset = 0;
		buf->nibble = 0;
	}

	if (newsz > buf->len) {
		if (newsz > buf->alloc_size) {
			uint8_t *d;
			d = talloc_realloc(buf, buf->data, uint8_t, newsz);
			if (d == NULL) {
				return WERR_NOMEM;
			}
			buf->data = d;
			buf->alloc_size = newsz;
		}
		memset(buf->data + buf->len, '\0', newsz - buf->len);
		buf->len = newsz;
	} else {
		buf->len = newsz;
	}

	return WERR_OK;
}
