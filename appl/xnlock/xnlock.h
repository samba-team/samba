/*
 * nlock.h -- "new"lockscreen, or, "nose"lockscreen
 *
 * Dan Heller
 */
#include <stdio.h>
#include <X11/Intrinsic.h>
#include <X11/StringDefs.h>
#include <X11/keysym.h>
#include <X11/Xos.h>

/* The program should be something that outputs a small amount of text */
#define DEFAULT_PROGRAM "fortune -s"

XtAppContext app;
Display *dpy;
unsigned short Width, Height;
#define win XtWindow(widget)
Widget widget;
GC gc;
XtIntervalId timeout_id;
#define font_height(font)	  	(font->ascent + font->descent)

#ifndef MAXPATHLEN
#define MAXPATHLEN BUFSIZ
#endif /* MAXPATHLEN */
char *ProgName, *words, *get_words();

int x, y;
extern int getwordsfrom;

Pixel Black, White;
XFontStruct *font;
extern Pixmap
    left0, left1, right0, right1, left_front, right_front, front, down;

extern void move();
