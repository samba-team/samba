/*
 * xnlock -- Dan Heller, 1990
 * "nlock" is a "new lockscreen" type program... something that prevents
 * screen burnout by making most of it "black" while providing something
 * of interest to be displayed in case anyone is watching.
 * "xnlock" is the X11 version of the program.
 * Original sunview version written by Dan Heller 1985 (not included here).
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#include <protos.h>
RCSID("$Id$");
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <X11/StringDefs.h>
#include <X11/Intrinsic.h>
#include <X11/keysym.h>
#include <X11/Shell.h>
#include <X11/Xos.h>
#include <ctype.h>
#include <pwd.h>

#include <krb.h>
#include <kafs.h>

char *crypt(const char *, const char *);

char inst[100];
char name[100];
char realm[REALM_SZ + 1];

#define font_height(font)	  	(font->ascent + font->descent)

char *SPACE_STRING = "                                                      ";
char STRING[] = "****************";

#define MAX_PASSWD_LENGTH (sizeof(STRING))

#ifndef MAXPATHLEN
#define MAXPATHLEN BUFSIZ
#endif /* MAXPATHLEN */

#define PROMPT	    "Password: "
#define FAIL_MSG    "Sorry, try again"
#define LEFT 	001
#define RIGHT 	002
#define DOWN 	004
#define UP 	010
#define FRONT	020
#define X_INCR 3
#define Y_INCR 2
#define XNLOCK_CTRL 1
#define XNLOCK_NOCTRL 0

XtAppContext	app;
Display        *dpy;
unsigned short	Width, Height;
Widget		widget;
GC		gc;
XtIntervalId	timeout_id;
char	       *ProgName, *words;
int		x, y;
Pixel		Black, White;
XFontStruct    *font;
struct passwd  *pw;
char		root_pw[16];
int		time_left, prompt_x, prompt_y, time_x, time_y;
unsigned long	interval;
Pixmap		left0, left1, right0, right1, left_front,
		right_front, front, down;

#define MAXLINES 40

#define IS_MOVING  1
#define GET_PASSWD 2
int state; /* indicates states: walking or getting passwd */

int ALLOW_LOGOUT = (60*10);	/* Allow logout after nn seconds */
char LOGOUT_PASSWD[] = "LOGOUT"; /* when given password "xx" */
time_t locked_at;

struct appres_t {
    Pixel bg;
    Pixel fg;
    XFontStruct *font;
    Boolean ignore_passwd;
    Boolean do_reverse;
    Boolean accept_root;
    char *text, *text_prog, *file;
    Boolean no_screensaver;
} appres;

static XtResource resources[] = {
    { XtNbackground, XtCBackground, XtRPixel, sizeof(Pixel), 
      XtOffsetOf(struct appres_t, bg), XtRString, "black" },

    { XtNforeground, XtCForeground, XtRPixel, sizeof(Pixel), 
      XtOffsetOf(struct appres_t, fg), XtRString, "white" },

    { XtNfont, XtCFont, XtRFontStruct, sizeof (XFontStruct *),
      XtOffsetOf(struct appres_t, font), 
      XtRString, "-*-new century schoolbook-*-*-*-18-*" },

    { "ignorePasswd", "IgnorePasswd", XtRBoolean, sizeof(Boolean),
      XtOffsetOf(struct appres_t,ignore_passwd),XtRImmediate,(XtPointer)False },

    { "acceptRootPasswd", "AcceptRootPasswd", XtRBoolean, sizeof(Boolean),
      XtOffsetOf(struct appres_t, accept_root), XtRImmediate, (XtPointer)True },

    { "text", "Text", XtRString, sizeof(String),
      XtOffsetOf(struct appres_t, text), XtRString, "I'm out running around." },
    
    { "program", "Program", XtRString, sizeof(String),
      XtOffsetOf(struct appres_t, text_prog), XtRImmediate, NULL },

    { "file", "File", XtRString, sizeof(String),
      XtOffsetOf(struct appres_t,file), XtRImmediate, NULL },

    { "noScreenSaver", "NoScreenSaver", XtRBoolean, sizeof(Boolean),
      XtOffsetOf(struct appres_t,no_screensaver), XtRImmediate, (XtPointer)False },
};

static XrmOptionDescRec options[] = {
    { "-fg", ".foreground", XrmoptionSepArg, NULL }, 
    { "-foreground", ".foreground", XrmoptionSepArg, NULL }, 
    { "-fn", ".font", XrmoptionSepArg, NULL }, 
    { "-font", ".font", XrmoptionSepArg, NULL }, 
    { "-ip", ".ignorePasswd", XrmoptionNoArg, "True" },
    { "-noip", ".ignorePasswd", XrmoptionNoArg, "False" },
    { "-ar",  ".acceptRootPasswd", XrmoptionNoArg, "True" },
    { "-noar", ".acceptRootPasswd", XrmoptionNoArg, "False" },
    { "-noscreensaver", ".noScreenSaver", XrmoptionNoArg, "True" },
};

static char*
get_words(void)
{
    FILE *pp = NULL;
    static char buf[BUFSIZ];

    if(appres.text_prog){
	pp = popen(appres.text_prog, "r");
	if(!pp){
	    perror(appres.text_prog);
	    return appres.text;
	}
	fread(buf, BUFSIZ, 1, pp);
	pclose(pp);
	return buf;
    }
    if(appres.file){
	pp = fopen(appres.file, "r");
	if(!pp){
	    perror(appres.file);
	    return appres.text;
	}
	fread(buf, BUFSIZ, 1, pp);
	fclose(pp);
	return buf;
    }

    return appres.text;
}

void usage(void)
{
    fprintf(stderr, "usage: %s [options] [message]\n", ProgName);
    fprintf(stderr, "-fg color     foreground color\n");
    fprintf(stderr, "-bg color     background color\n");
    fprintf(stderr, "-rv           reverse foreground/background colors\n");
    fprintf(stderr, "-nrv          no reverse video\n");
    fprintf(stderr, "-ip           ignore passwd\n");
    fprintf(stderr, "-nip          don't ignore passwd\n");
    fprintf(stderr, "-ar           accept root's passwd to unlock\n");
    fprintf(stderr, "-nar          don't accept root's passwd\n");
    fprintf(stderr, "-f [file]     message is read from file or ~/.msgfile\n");
    fprintf(stderr, "-prog program  text is gotten from executing `program'\n");
    exit(1);
}

static void
init_words (int argc, char **argv)
{
    char buf[BUFSIZ];
    int i = 0;

    while(argv[i]){
	if(strcmp(argv[i], "-p") == 0){
	    i++;
	    if(argv[i]){
		appres.text_prog = argv[i];
		i++;
	    }else{
		fprintf(stderr, "-p requires an argument\n");
		usage();
	    }
	}else if(strcmp(argv[i], "-f") == 0){
	    i++;
	    if(argv[i]){
		appres.file = argv[i];
		i++;
	    }else{
		sprintf(buf, "%s/.msgfile", getenv("HOME"));
		appres.file = strdup(buf);
	    }
	}else{
	    strcpy(buf, "");
	    while(argv[i]){
		strcat(buf, argv[i]);
		strcat(buf, " ");
		i++;
	    }
	    appres.text = strdup(buf);
	}
    }
}

static void
ScreenSaver(int save)
{
    static int timeout, interval, prefer_blank, allow_exp;
    if(!appres.no_screensaver){
	if (save) {
	    XGetScreenSaver(dpy, &timeout, &interval, 
			    &prefer_blank, &allow_exp);
	    XSetScreenSaver(dpy, 0, interval, prefer_blank, allow_exp);
	} else
	    /* restore state */
	    XSetScreenSaver(dpy, timeout, interval, prefer_blank, allow_exp);
    }
}

/* Forward decls necessary */
static void talk(int force_erase);
static unsigned long look(void);

static int
zrefresh()
{
  switch (fork()) {
  case -1:
      fprintf(stderr, "Warning %s: Failed to fork zrefresh\n", ProgName);
      return -1;
  case 0:
      /* Child */
      execlp("zrefresh", "zrefresh", 0);
      execl("/usr/athena/bin/zrefresh", "zrefresh", 0);
#if 0
      fprintf(stderr, "Warning %s: Failed to exec zrefresh\n", ProgName);
#endif
      return -1;
  default:
      /* Parent */
      break;
  }
  return 0;
}

static void
leave(void)
{
    XUngrabPointer(dpy, CurrentTime);
    XUngrabKeyboard(dpy, CurrentTime);
    ScreenSaver(0);
    zrefresh();
    exit(0);
}

static void
walk(int dir)
{
    register int incr = 0;
    static int lastdir;
    static int up = 1;
    static Pixmap frame;

    XSetForeground(dpy, gc, White);
    XSetBackground(dpy, gc, Black);
    if (dir & (LEFT|RIGHT)) { /* left/right movement (mabye up/down too) */
	up = -up; /* bouncing effect (even if hit a wall) */
	if (dir & LEFT) {
	    incr = X_INCR;
	    frame = (up < 0) ? left0 : left1;
	} else {
	    incr = -X_INCR;
	    frame = (up < 0) ? right0 : right1;
	}
	if ((lastdir == FRONT || lastdir == DOWN) && dir & UP) {
	    /* workaround silly bug that leaves screen dust when
	     * guy is facing forward or down and moves up-left/right.
	     */
	    XCopyPlane(dpy, frame, XtWindow(widget), gc, 0, 0, 64,64, x, y, 1L);
	    XFlush(dpy);
	}
	/* note that maybe neither UP nor DOWN is set! */
	if (dir & UP && y > Y_INCR)
	    y -= Y_INCR;
	else if (dir & DOWN && y < (int)Height - 64)
	    y += Y_INCR;
    }
    /* Explicit up/down movement only (no left/right) */
    else if (dir == UP)
	XCopyPlane(dpy, front, XtWindow(widget), gc,
	    0,0, 64,64, x, y -= Y_INCR, 1L);
    else if (dir == DOWN)
	XCopyPlane(dpy, down, XtWindow(widget), gc,
	    0,0, 64,64, x, y += Y_INCR, 1L);
    else if (dir == FRONT && frame != front) {
	if (up > 0)
	    up = -up;
	if (lastdir & LEFT)
	    frame = left_front;
	else if (lastdir & RIGHT)
	    frame = right_front;
	else
	    frame = front;
	XCopyPlane(dpy, frame, XtWindow(widget), gc, 0, 0, 64,64, x, y, 1L);
    }
    if (dir & LEFT)
	while(--incr >= 0) {
	    XCopyPlane(dpy, frame, XtWindow(widget), gc,
		0,0, 64,64, --x, y+up, 1L);
	    XFlush(dpy);
	}
    else if (dir & RIGHT)
	while(++incr <= 0) {
	    XCopyPlane(dpy, frame, XtWindow(widget), gc,
		0,0, 64,64, ++x, y+up, 1L);
	    XFlush(dpy);
	}
    lastdir = dir;
}

static int
think(void)
{
    if (rand() & 1)
	walk(FRONT);
    if (rand() & 1) {
	words = get_words();
	return 1;
    }
    return 0;
}

static void
move(XtPointer _p, XtIntervalId *_id)
{
    static int length, dir;

    if (!length) {
	register int tries = 0;
	dir = 0;
	if ((rand() & 1) && think()) {
	    talk(0); /* sets timeout to itself */
	    return;
	}
	if (!(rand() % 3) && (interval = look())) {
	    timeout_id = XtAppAddTimeOut(app, interval, move, NULL);
	    return;
	}
	interval = 20 + rand() % 100;
	do  {
	    if (!tries)
		length = Width/100 + rand() % 90, tries = 8;
	    else
		tries--;
	    switch (rand() % 8) {
		case 0:
		    if (x - X_INCR*length >= 5)
			dir = LEFT;
		case 1:
		    if (x + X_INCR*length <= (int)Width - 70)
			dir = RIGHT;
		case 2:
		    if (y - (Y_INCR*length) >= 5)
			dir = UP, interval = 40;
		case 3:
		    if (y + Y_INCR*length <= (int)Height - 70)
			dir = DOWN, interval = 20;
		case 4:
		    if (x - X_INCR*length >= 5 && y - (Y_INCR*length) >= 5)
			dir = (LEFT|UP);
		case 5:
		    if (x + X_INCR * length <= (int)Width - 70 &&
			y-Y_INCR * length >= 5)
			dir = (RIGHT|UP);
		case 6:
		    if (x - X_INCR * length >= 5 &&
			y + Y_INCR * length <= (int)Height - 70)
			dir = (LEFT|DOWN);
		case 7:
		    if (x + X_INCR*length <= (int)Width - 70 &&
			y + Y_INCR*length <= (int)Height - 70)
			dir = (RIGHT|DOWN);
	    }
	} while (!dir);
    }
    walk(dir);
    --length;
    timeout_id = XtAppAddTimeOut(app, interval, move, NULL);
}

static void
post_prompt_box(Window window)
{
    char s[64];
    int width = (Width / 3);
    int height = font_height(font) * 6;
    int box_x, box_y;

    /* make sure the entire nose icon fits in the box */
    if (height < 100)
	height = 100;

    if(width < 105 + font->max_bounds.width*MAX_PASSWD_LENGTH)
	width = 105 + font->max_bounds.width*MAX_PASSWD_LENGTH;
    box_x = (Width - width) / 2;
    time_x = prompt_x = box_x + 105;

    time_y = prompt_y = Height / 2;
    box_y = prompt_y - 3 * font_height(font);

    if (inst[0] == 0)
	sprintf (s, "User: %s@%s", name, realm);
    else
	sprintf (s, "User: %s.%s@%s", name, inst, realm);
    /* erase current guy -- text message may still exist */
    XSetForeground(dpy, gc, Black);
    XFillRectangle(dpy, window, gc, x, y, 64, 64);
    talk(1); /* forcefully erase message if one is being displayed */
    /* Clear area in middle of screen for prompt box */
    XSetForeground(dpy, gc, White);
    XFillRectangle(dpy, window, gc, box_x, box_y, width, height);

    /* make a box that's 5 pixels thick. Then add a thin box inside it */
    XSetForeground(dpy, gc, Black);
    XSetLineAttributes(dpy, gc, 5, 0, 0, 0);
    XDrawRectangle(dpy, window, gc, box_x+5, box_y+5, width-10, height-10);
    XSetLineAttributes(dpy, gc, 0, 0, 0, 0);
    XDrawRectangle(dpy, window, gc, box_x+12, box_y+12, width-23, height-23);

    XDrawString(dpy, window, gc,
	prompt_x, prompt_y-font_height(font), s, strlen(s));
    XDrawString(dpy, window, gc, prompt_x, prompt_y, PROMPT, strlen(PROMPT));
    /* set background for copyplane and DrawImageString; need reverse video */
    XSetBackground(dpy, gc, White);
    XCopyPlane(dpy, right0, window, gc, 0,0, 64,64,
	       box_x + 20, box_y + (height - 64)/2, 1L);
    prompt_x += XTextWidth(font, PROMPT, strlen(PROMPT));
    time_y += 2*font_height(font);
}

static void
RaiseWindow(Widget w, XEvent *ev, String *s, Cardinal *n)
{
  Widget x;
  if(!XtIsRealized(w))
    return;
  x = XtParent(w);
  XRaiseWindow(dpy, XtWindow(x));
}


static void
ClearWindow(Widget w, XEvent *_event, String *_s, Cardinal *_n)
{
    XExposeEvent *event = (XExposeEvent *)_event;
    if (!XtIsRealized(w))
	return;
    if (state == GET_PASSWD)
	post_prompt_box(XtWindow(w));
    if (timeout_id == 0 && event->count == 0) {
	timeout_id = XtAppAddTimeOut(app, 1000L, move, NULL);
	/* first grab the input focus */
	XSetInputFocus(dpy, XtWindow(w), RevertToPointerRoot, CurrentTime);
	/* now grab the pointer and keyboard and contrain to this window */
	XGrabPointer(dpy, XtWindow(w), TRUE, 0, GrabModeAsync,
	     GrabModeAsync, XtWindow(w), None, CurrentTime);
    }
}

static void
countdown(XtPointer _t, XtIntervalId *_d)
{
    int *timeout = (int *)_t;
    char buf[128];
    time_t seconds;

    if (--(*timeout) < 0) {
	XExposeEvent event;
	XtRemoveTimeOut(timeout_id);
	state = IS_MOVING;
	event.x = event.y = 0;
	event.width = Width, event.height = Height;
	ClearWindow(widget, (XEvent *)&event, 0, 0);
	timeout_id = XtAppAddTimeOut(app, 200L, move, NULL);
	return;
    }
    seconds = time(0) - locked_at;
    if (seconds >= 3600)
      (void) sprintf(buf, "Locked for %d:%02d:%02d    ",
                   (int)seconds/3600, (int)seconds/60%60, (int)seconds%60);
    else
      (void) sprintf(buf, "Locked for %2d:%02d    ",
		     (int)seconds/60, (int)seconds%60);
      
    XDrawImageString(dpy, XtWindow(widget), gc,
	time_x, time_y, buf, strlen(buf));
    XtAppAddTimeOut(app, 1000L, countdown, timeout);
    return;
}

static void
GetPasswd(Widget w, XEvent *_event, String *_s, Cardinal *_n)
{
    XKeyEvent *event = (XKeyEvent *)_event;
    static char passwd[MAX_PASSWD_LENGTH];
    static int cnt;
    static int is_ctrl = XNLOCK_NOCTRL;
    char c;
    KeySym keysym;

    if (event->type == ButtonPress) {
	x = event->x, y = event->y;
	return;
    }
    if (state == IS_MOVING) {
	/* guy is running around--change to post prompt box. */
	XtRemoveTimeOut(timeout_id);
	state = GET_PASSWD;
	if (appres.ignore_passwd || !strlen(pw->pw_passwd))
	    leave();
	post_prompt_box(XtWindow(w));
	cnt = 0;
	time_left = 30;
	countdown((XtPointer)&time_left, 0);
	return;
    }
    if (event->type == KeyRelease) {
      keysym = XLookupKeysym(event, 0);
      if (keysym == XK_Control_L || keysym == XK_Control_R) {
	is_ctrl = XNLOCK_NOCTRL;
      }
    }
    if (event->type != KeyPress)
	return;
    keysym = XLookupKeysym(event, 0);
    if (keysym == XK_Control_L || keysym == XK_Control_R) {
      is_ctrl = XNLOCK_CTRL;
      return;
    }
    if (!XLookupString(event, &c, 1, &keysym, 0))
	return;
    if (keysym == XK_Return || keysym == XK_Linefeed) {
	passwd[cnt] = 0;
	XtRemoveTimeOut(timeout_id);
	/*
	 * First try with root password, if allowed.
	 */
	if (appres.accept_root &&
	    (root_pw[0] == 0 && cnt == 0 ||
	     cnt && root_pw[0] && !strcmp(crypt(passwd, root_pw), root_pw)))
	    leave();
	/*
	 * Password that log out user
	 */
	if (    getuid() != 0
	    && geteuid() != 0
	    && (time(0) - locked_at) > ALLOW_LOGOUT
	    && strncmp(passwd, LOGOUT_PASSWD, sizeof(LOGOUT_PASSWD)) == 0)
	    {
		signal(SIGHUP, SIG_IGN);
		kill(-1, SIGHUP);
		sleep(5);
		/* If the X-server shut down then so will we, else
		 * continue */
		signal(SIGHUP, SIG_DFL);
	    }
	/*
	 * Try to verify as user with kerberos.
	 */
	if (realm[0] != 0)
	    {
		if (KSUCCESS == krb_get_pw_in_tkt(name,
						  inst,
						  realm,
						  "krbtgt",
						  realm,
						  DEFAULT_TKT_LIFE,
						  passwd))
		    {
			int code;
			if (k_hasafs())
			    {
				if ((code = k_afsklog(NULL, NULL)) != KSUCCESS
				    && code != KDC_PR_UNKNOWN)
				    fprintf(stderr,
					    "%s: Warning %s\n",
					    ProgName,
					    krb_get_err_text(code));
			    }
			leave();
		    }
	    }
	/*
	 * Try to verify as user.
	 */
	if (!strcmp(crypt(passwd, pw->pw_passwd), pw->pw_passwd))
	  leave();

	XDrawImageString(dpy, XtWindow(widget), gc,
	    time_x, time_y, FAIL_MSG, strlen(FAIL_MSG));
	time_left = 0;
	state = IS_MOVING;
	timeout_id = XtAppAddTimeOut(app, 2000L, countdown, &time_left);
	return;
    }
    if (keysym == XK_BackSpace || keysym == XK_Delete || keysym == XK_Left) {
	if (cnt)
	    passwd[cnt--] = ' ';
    } else if (keysym == XK_u && is_ctrl == XNLOCK_CTRL) {
      while (cnt) {
	passwd[cnt--] = ' ';
	XDrawImageString(dpy, XtWindow(w), gc,
		    prompt_x, prompt_y, STRING, cnt);
	XDrawImageString(dpy, XtWindow(w), gc,
			 prompt_x + XTextWidth(font, STRING, cnt),
			 prompt_y, SPACE_STRING, MAX_PASSWD_LENGTH - cnt + 1);
      }
    } else if (isprint(c))
	if ((cnt + 1) >= MAX_PASSWD_LENGTH)
	    XBell(dpy, 50);
	else
	    passwd[cnt++] = c;
    else
	return;
    XDrawImageString(dpy, XtWindow(w), gc,
	prompt_x, prompt_y, STRING, cnt);
    XDrawImageString(dpy, XtWindow(w), gc,
	prompt_x + XTextWidth(font, STRING, cnt),
	prompt_y, SPACE_STRING, MAX_PASSWD_LENGTH - cnt + 1);
}

#include "nose.0.left"
#include "nose.1.left"
#include "nose.0.right"
#include "nose.1.right"
#include "nose.left.front"
#include "nose.right.front"
#include "nose.front"
#include "nose.down"

static void
init_images(void)
{
    static Pixmap *images[] = {
	&left0, &left1, &right0, &right1,
	&left_front, &right_front, &front, &down 
    };
    static unsigned char *bits[] = {
	nose_0_left_bits, nose_1_left_bits, nose_0_right_bits,
	nose_1_right_bits, nose_left_front_bits, nose_right_front_bits,
	nose_front_bits, nose_down_bits
    };
    int i;

    for (i = 0; i < XtNumber(images); i++)
	if (!(*images[i] =
		XCreatePixmapFromBitmapData(dpy, DefaultRootWindow(dpy),
		    (char*)(bits[i]), 64, 64, 1, 0, 1)))
	    XtError("Can't load nose images");
}

static void
talk(int force_erase)
{
    int width = 0, height, Z, total = 0;
    static int X, Y, talking;
    static struct { int x, y, width, height; } s_rect;
    register char *p, *p2;
    char buf[BUFSIZ], args[MAXLINES][256];

    /* clear what we've written */
    if (talking || force_erase) {
	if (!talking)
	    return;
	if (talking == 2) {
	    XSetForeground(dpy, gc, Black);
	    XDrawString(dpy, XtWindow(widget), gc, X, Y, words, strlen(words));
	} else if (talking == 1) {
	    XSetForeground(dpy, gc, Black);
	    XFillRectangle(dpy, XtWindow(widget), gc, s_rect.x-5, s_rect.y-5,
			   s_rect.width+10, s_rect.height+10);
	}
	talking = 0;
	if (!force_erase)
	    timeout_id = XtAppAddTimeOut(app, 40L,
					 (XtTimerCallbackProc)move,
					 NULL);
	return;
    }
    XSetForeground(dpy, gc, White);
    talking = 1;
    walk(FRONT);
    p = strcpy(buf, words);

    /* possibly avoid a lot of work here
     * if no CR or only one, then just print the line
     */
    if (!(p2 = strchr(p, '\n')) || !p2[1]) {
	register int w;

	if (p2)
	    *p2 = 0;
	w = XTextWidth(font, words, strlen(words));
	X = x + 32 - w/2;
	Y = y - 5 - font_height(font);
	/* give us a nice 5 pixel margin */
	if (X < 5)
	    X = 5;
	else if (X + w + 15 > (int)Width + 5)
	    X = Width - w - 5;
	if (Y < 5)
	    Y = y + 64 + 5 + font_height(font);
	XDrawString(dpy, XtWindow(widget), gc, X, Y, words, strlen(words));
	timeout_id = XtAppAddTimeOut(app, 5000L, (XtTimerCallbackProc)talk, 
				     NULL);
	talking++;
	return;
    }

    /* p2 now points to the first '\n' */
    for (height = 0; p; height++) {
	int w;
	*p2 = 0;
	if ((w = XTextWidth(font, p, p2 - p)) > width)
	    width = w;
	total += p2 - p; /* total chars; count to determine reading time */
	strcpy(args[height], p);
	if (height == MAXLINES - 1) {
	    puts("Message too long!");
	    break;
	}
	p = p2+1;
	if (!(p2 = strchr(p, '\n')))
	    break;
    }
    height++;

    /* Figure out the height and width in pixels (height, width) extend
     * the new box by 15 pixels on the sides (30 total) top and bottom.
     */
    s_rect.width = width + 30;
    s_rect.height = height * font_height(font) + 30;
    if (x - s_rect.width - 10 < 5)
	s_rect.x = 5;
    else
	if ((s_rect.x = x+32-(s_rect.width+15)/2)
					 + s_rect.width+15 > (int)Width-5)
	    s_rect.x = Width - 15 - s_rect.width;
    if (y - s_rect.height - 10 < 5)
	s_rect.y = y + 64 + 5;
    else
	s_rect.y = y - 5 - s_rect.height;

    XSetForeground(dpy, gc, White);
    XFillRectangle(dpy, XtWindow(widget), gc,
       s_rect.x-5, s_rect.y-5, s_rect.width+10, s_rect.height+10);

    /* make a box that's 5 pixels thick. Then add a thin box inside it */
    XSetForeground(dpy, gc, Black);
    XSetLineAttributes(dpy, gc, 5, 0, 0, 0);
    XDrawRectangle(dpy, XtWindow(widget), gc,
		   s_rect.x, s_rect.y, s_rect.width-1, s_rect.height-1);
    XSetLineAttributes(dpy, gc, 0, 0, 0, 0);
    XDrawRectangle(dpy, XtWindow(widget), gc,
		   s_rect.x + 7, s_rect.y + 7, s_rect.width - 15, 
		   s_rect.height - 15);

    X = 15;
    Y = 15 + font_height(font);

    /* now print each string in reverse order (start at bottom of box) */
    for (Z = 0; Z < height; Z++) {
	XDrawString(dpy, XtWindow(widget), gc, s_rect.x+X, s_rect.y+Y,
	    args[Z], strlen(args[Z]));
	Y += font_height(font);
    }
    timeout_id = XtAppAddTimeOut(app, (total/15) * 1000, 
				 (XtTimerCallbackProc)talk, NULL);
}

static unsigned long
look(void)
{
    XSetForeground(dpy, gc, White);
    XSetBackground(dpy, gc, Black);
    if (rand() % 3) {
	XCopyPlane(dpy, (rand() & 1)? down : front, XtWindow(widget), gc,
	    0, 0, 64,64, x, y, 1L);
	return 1000L;
    }
    if (!(rand() % 5))
	return 0;
    if (rand() % 3) {
	XCopyPlane(dpy, (rand() & 1)? left_front : right_front,
	    XtWindow(widget), gc, 0, 0, 64,64, x, y, 1L);
	return 1000L;
    }
    if (!(rand() % 5))
	return 0;
    XCopyPlane(dpy, (rand() & 1)? left0 : right0, XtWindow(widget), gc,
	0, 0, 64,64, x, y, 1L);
    return 1000L;
}

int
main (int argc, char **argv)
{
    register int i;
    Widget override;
    XGCValues gcvalues;

    srand(getpid());
    for (i = 0; i < (sizeof(STRING)-2); i++)
	STRING[i] = ((unsigned long)rand() % ('~' - ' ')) + ' ';

    locked_at = time(0);

    if ((ProgName = strrchr(*argv, '/')) != 0)
	ProgName++;
    else
	ProgName = *argv;

    /* getpwuid() returns static pointer, so get root's passwd first */
    if (!(pw = getpwuid(0))){
	fprintf(stderr, "%s: can't get root's passwd!\n", ProgName);
	exit(1);
    }
    strcpy(root_pw, pw->pw_passwd);
    if (!(pw = getpwuid(getuid()))){
      fprintf(stderr, "%s: Can't get your password entry!\n", ProgName);
      exit(1);
    } 

    {
	int code = KSUCCESS;
	char *file;
	strcpy(name, pw->pw_name); /* Unix name is default name */
	if ((file =  getenv("KRBTKFILE")) == 0)
	    file = TKT_FILE;  
	code = tf_init(file, R_TKT_FIL);
	if (code == KSUCCESS)
	    {
		(void) tf_close();
		if ((code = krb_get_tf_realm(file, realm)) == KSUCCESS &&
		    (code = tf_init(file, R_TKT_FIL)) == KSUCCESS &&
		    (code = tf_get_pname(name)) == KSUCCESS &&
		    (code = tf_get_pinst(inst)) == KSUCCESS)
		    {
			(void) tf_close(); /* Alles gut */
		    }
	    }
	if (code != KSUCCESS)
	    {
		code = krb_get_lrealm(realm, 1);
		if (code != KSUCCESS)
		    realm[0] = 0; /* No kerberos today */
	    }
    }
    

    override = XtVaAppInitialize(&app, "XNlock", options, XtNumber(options),
				 &argc, argv, NULL, 
				 XtNoverrideRedirect, True, 
				 NULL);
    
    XtVaGetApplicationResources(override,(XtPointer)&appres,
				resources,XtNumber(resources),
				NULL);
    /* the background is black and the little guy is white */
    Black = appres.bg;
    White = appres.fg;

    dpy = XtDisplay(override);
    
    if (dpy == 0)
      {
	fprintf(stderr, "Error: Can't open display:\n");
	exit(1);
      }

    Width = DisplayWidth(dpy, DefaultScreen(dpy)) + 2;
    Height = DisplayHeight(dpy, DefaultScreen(dpy)) + 2;
    
    for(i = 0; i < ScreenCount(dpy); i++){
	Widget shell, core;

	struct xxx{
	    Pixel bg;
	}res;
	
	XtResource Res[] = {
	    { XtNbackground, XtCBackground, XtRPixel, sizeof(Pixel),
	      XtOffsetOf(struct xxx, bg), XtRString, "black" }
	};

	if(i == DefaultScreen(dpy))
	    continue;
      
	shell = XtVaAppCreateShell(NULL,NULL, applicationShellWidgetClass, dpy, 
				   XtNscreen, ScreenOfDisplay(dpy, i), 
				   XtNoverrideRedirect, True, 
				   XtNx, -1, 
				   XtNy, -1,
				   NULL);
      
	XtVaGetApplicationResources(shell, (XtPointer)&res, 
				    Res, XtNumber(Res),
				    NULL);

	core = XtVaCreateManagedWidget("_foo", widgetClass, shell,
				       XtNwidth, DisplayWidth(dpy, i),
				       XtNheight, DisplayHeight(dpy, i),
				       XtNbackground, res.bg, 
				       NULL);
	XtRealizeWidget(shell);
    }

    widget = XtVaCreateManagedWidget("_foo", widgetClass, override,
				     XtNwidth,	Width,
				     XtNheight,	Height,
				     XtNbackground, Black, 
				     NULL);

    init_words(--argc, ++argv);
    init_images();

    gcvalues.foreground = Black;
    gcvalues.background = White;


    font = appres.font;
    gcvalues.font = font->fid;
    gcvalues.graphics_exposures = False;
    gc = XCreateGC(dpy, DefaultRootWindow(dpy),
	GCForeground | GCBackground | GCGraphicsExposures | GCFont,
	&gcvalues);

    x = Width / 2;
    y = Height / 2;
    srand (time(0));
    state = IS_MOVING;

    {
	static XtActionsRec actions[] = {
	    { "ClearWindow",	ClearWindow  },
	    { "GetPasswd",	GetPasswd    },
	    { "RaiseWindow", 	RaiseWindow  },
	};
	XtAppAddActions(app, actions, XtNumber(actions));
	XtOverrideTranslations(widget,
	       XtParseTranslationTable(
				       "<Expose>:	ClearWindow()	\n"
				       "<BtnDown>:	GetPasswd()	\n"
				       "<Visible>: RaiseWindow() \n"
				       "<KeyRelease>:  GetPasswd()     \n"
				       "<KeyPress>:	GetPasswd()"));
    }

    XtRealizeWidget(override);
    XGrabPointer(dpy, XtWindow(widget), TRUE, 0, GrabModeAsync,
		 GrabModeAsync, XtWindow(widget), None, CurrentTime);
    XGrabKeyboard(dpy, XtWindow(widget), TRUE, GrabModeAsync,
		  GrabModeAsync, CurrentTime);
    ScreenSaver(1);
    XtAppMainLoop(app);
    exit(0);
}
