#ifndef _HEXEDIT_H_
#define _HEXEDIT_H_

#include <ncurses.h>

enum {
	HE_CURSOR_UP = 0x1000,
	HE_CURSOR_DOWN = 0x1100,
	HE_CURSOR_LEFT = 0x1200,
	HE_CURSOR_RIGHT = 0x1300,
	HE_CURSOR_PGUP = 0x1400,
	HE_CURSOR_PGDN = 0x1500
};

/*
 offset    hex1         hex2         ascii
 00000000  FF FF FF FF  FF FF FF FF  ........
*/

#define LINE_WIDTH 44
#define HEX_COL1 10
#define HEX_COL1_END 21
#define HEX_COL2 23
#define HEX_COL2_END 34
#define ASCII_COL 36
#define ASCII_COL_END LINE_WIDTH
#define BYTES_PER_LINE 8

struct hexedit {
	size_t offset;
	size_t len;
	size_t alloc_size;
	int cursor_y;
	int cursor_x;
	size_t cursor_offset;
	size_t cursor_line_offset;
	int nibble;
	uint8_t *data;
	WINDOW *win;
	WINDOW *status_line;
};

struct hexedit *hexedit_new(TALLOC_CTX *ctx, WINDOW *parent, int nlines,
			    int y, int x, size_t sz);
void hexedit_set_cursor(struct hexedit *buf);
void hexedit_refresh(struct hexedit *buf);
void hexedit_driver(struct hexedit *buf, int c);
WERROR hexedit_resize_buffer(struct hexedit *buf, size_t newsz);

#endif
