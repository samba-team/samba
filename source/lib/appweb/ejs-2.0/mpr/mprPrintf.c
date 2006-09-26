/**
 *	@file 	mprPrintf.c
 *	@brief	Printf routines safe for embedded programming
 *	@overview This module provides safe replacements for the standard 
 *		printf formatting routines.
 *	@remarks Most routines in this file are not thread-safe. It is the callers 
 *		responsibility to perform all thread synchronization.
 */

/*
 *	@copy	default
 *	
 *	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
 *	
 *	This software is distributed under commercial and open source licenses.
 *	You may use the GPL open source license described below or you may acquire 
 *	a commercial license from Mbedthis Software. You agree to be fully bound 
 *	by the terms of either license. Consult the LICENSE.TXT distributed with 
 *	this software for full details.
 *	
 *	This software is open source; you can redistribute it and/or modify it 
 *	under the terms of the GNU General Public License as published by the 
 *	Free Software Foundation; either version 2 of the License, or (at your 
 *	option) any later version. See the GNU General Public License for more 
 *	details at: http://www.mbedthis.com/downloads/gplLicense.html
 *	
 *	This program is distributed WITHOUT ANY WARRANTY; without even the 
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 *	
 *	This GPL license does NOT permit incorporating this software into 
 *	proprietary programs. If you are unable to comply with the GPL, you must
 *	acquire a commercial license to use this software. Commercial licenses 
 *	for this software and support services are available from Mbedthis 
 *	Software at http://www.mbedthis.com 
 *	
 *	@end
 */

/********************************** Includes **********************************/
/*
 *	We need to use the underlying str(cpy) routines to implement our safe
 *	alternatives
 */
#if !DOXYGEN
#define 	UNSAFE_FUNCTIONS_OK 1
#endif

#include	"mpr.h"

/*********************************** Defines **********************************/
/*
 *	Class definitions
 */
#define CLASS_NORMAL	0		/* [All other]		Normal characters */
#define CLASS_PERCENT	1		/* [%]				Begin format */
#define CLASS_MODIFIER	2		/* [-+ #,]			Modifiers */
#define CLASS_ZERO		3		/* [0]				Special modifier */
#define CLASS_STAR		4		/* [*]				Width supplied by arg */
#define CLASS_DIGIT		5		/* [1-9]			Field widths */
#define CLASS_DOT		6		/* [.]				Introduce precision */
#define CLASS_BITS		7		/* [hlL]			Length bits */
#define CLASS_TYPE		8		/* [cdfinopsSuxX]	Type specifiers */

#define STATE_NORMAL	0				/* Normal chars in format string */
#define STATE_PERCENT	1				/* "%" */
#define STATE_MODIFIER	2				/* Read flag */
#define STATE_WIDTH		3				/* Width spec */
#define STATE_DOT		4				/* "." */
#define STATE_PRECISION	5				/* Precision spec */
#define STATE_BITS		6				/* Size spec */
#define STATE_TYPE		7				/* Data type */
#define STATE_COUNT		8

/*
 *	Format:			%[modifier][width][precision][bits][type]
 *
 *	#define CLASS_MODIFIER	2		[-+ #,]			Modifiers
 *	#define CLASS_BITS		7		[hlL]			Length bits
 */


/*
 *	Flags
 */
#define SPRINTF_LEFT		0x1			/* Left align */
#define SPRINTF_SIGN		0x2			/* Always sign the result */
#define SPRINTF_LEAD_SPACE	0x4			/* put leading space for +ve numbers */
#define SPRINTF_ALTERNATE	0x8			/* Alternate format */
#define SPRINTF_LEAD_ZERO	0x10		/* Zero pad */
#define SPRINTF_SHORT		0x20		/* 16-bit */
#define SPRINTF_LONG		0x40		/* 32-bit */
#if BLD_FEATURE_INT64
#define SPRINTF_LONGLONG	0x80		/* 64-bit */
#endif
#define SPRINTF_COMMA		0x100		/* Thousand comma separators */
#define SPRINTF_UPPER_CASE	0x200		/* As the name says for numbers */

typedef struct Format {
	uchar	*buf;
	uchar	*endbuf;
	uchar	*start;
	uchar	*end;
	int		growBy;
	int		maxsize;

	int		precision;
	int		radix;
	int		width;
	int		flags;
	int		len;
} Format;

static int growBuf(MPR_LOC_DEC(ctx, loc), Format *fmt);

#define BPUT(ctx, loc, fmt, c) \
	if (1) { \
		/* Less one to allow room for the null */ \
		if ((fmt)->end >= ((fmt)->endbuf - sizeof(char))) { \
			if (growBuf(MPR_LOC_PASS(ctx, loc), fmt)) { \
				*(fmt)->end++ = (c); \
			} \
		} else { \
			*(fmt)->end++ = (c); \
		} \
	} else

#define BPUTNULL(ctx, loc, fmt) \
	if (1) { \
		if ((fmt)->end > (fmt)->endbuf) { \
			if (growBuf(MPR_LOC_PASS(ctx, loc), fmt)) { \
				*(fmt)->end = '\0'; \
			} \
		} else { \
			*(fmt)->end = '\0'; \
		} \
	} else 

/******************************************************************************/

#if BLD_FEATURE_INT64
#define unum 	uint64
#define num 	int64
#else
#define unum 	uint
#define num		int
#endif

/***************************** Forward Declarations ***************************/
#ifdef __cplusplus
extern "C" {
#endif

static int	getState(char c, int state);
static int	mprSprintfCore(MPR_LOC_DEC(ctx, loc), char **s, 
	int maxsize, const char *fmt, va_list arg);
static void	outNum(MPR_LOC_DEC(ctx, loc), Format *fmt, const char *prefix, 
	unum val);

#if BLD_FEATURE_FLOATING_POINT
static void outFloat(MPR_LOC_DEC(ctx, loc), Format *fmt, char specChar, 
	double value);
#endif

/******************************************************************************/

int mprPrintf(MprCtx ctx, const char *fmt, ...)
{
	va_list		ap;
	char		*buf;
	int			len;
	MprApp		*app;

	/* No asserts here as this is used as part of assert reporting */

	app = mprGetApp(ctx);

	va_start(ap, fmt);
	len = mprAllocVsprintf(MPR_LOC_ARGS(ctx), &buf, 0, fmt, ap);
	va_end(ap);
	if (len >= 0 && app->console) {
		len = mprWrite(app->console, buf, len);
	}
	mprFree(buf);

	return len;
}

/******************************************************************************/

int mprErrorPrintf(MprCtx ctx, const char *fmt, ...)
{
	va_list		ap;
	char		*buf;
	int			len;
	MprApp		*app;

	/* No asserts here as this is used as part of assert reporting */

	app = mprGetApp(ctx);

	va_start(ap, fmt);
	len = mprAllocVsprintf(MPR_LOC_ARGS(ctx), &buf, 0, fmt, ap);
	va_end(ap);
	if (len >= 0 && app->error) {
		len = mprWrite(app->error, buf, len);
	}
	mprFree(buf);

	return len;
}

/******************************************************************************/

int mprFprintf(MprFile *file, const char *fmt, ...)
{
	va_list		ap;
	char		*buf;
	int			len;

	if (file == 0) {
		return MPR_ERR_BAD_HANDLE;
	}

	va_start(ap, fmt);
	len = mprAllocVsprintf(MPR_LOC_ARGS(file), &buf, 0, fmt, ap);
	va_end(ap);

	if (len >= 0) {
		len = mprWrite(file, buf, len);
	}
	mprFree(buf);
	return len;
}

/******************************************************************************/
/*
 *	Printf with a static buffer. Used internally only. WILL NOT MALLOC.
 */

int mprStaticPrintf(MprCtx ctx, const char *fmt, ...)
{
	va_list		ap;
	char		buf[MPR_MAX_STRING];
	char		*bufp;
	int			len;
	MprApp		*app;

	app = mprGetApp(ctx);

	va_start(ap, fmt);
	bufp = buf;
	len = mprSprintfCore(MPR_LOC_ARGS(0), &bufp, MPR_MAX_STRING, fmt, ap);
	va_end(ap);
	if (len >= 0) {
		len = mprWrite(app->console, buf, len);
	}
	return len;
}

/******************************************************************************/

int mprSprintf(char *buf, int n, const char *fmt, ...)
{
	va_list		ap;
	int			result;

	mprAssert(buf);
	mprAssert(fmt);
	mprAssert(n > 0);

	va_start(ap, fmt);
	result = mprSprintfCore(MPR_LOC_ARGS(0), &buf, n, fmt, ap);
	va_end(ap);
	return result;
}

/******************************************************************************/

int mprVsprintf(char *buf, int n, const char *fmt, va_list arg)
{
	mprAssert(buf);
	mprAssert(fmt);
	mprAssert(n > 0);

	return mprSprintfCore(MPR_LOC_ARGS(0), &buf, n, fmt, arg);
}

/******************************************************************************/

int mprAllocSprintf(MPR_LOC_DEC(ctx, loc), char **buf, int maxSize, 
	const char *fmt, ...)
{
	va_list	ap;
	int		result;

	mprAssert(buf);
	mprAssert(fmt);

	*buf = 0;
	va_start(ap, fmt);
	result = mprSprintfCore(MPR_LOC_PASS(ctx, loc), buf, maxSize, fmt, ap);
	va_end(ap);
	return result;
}

/******************************************************************************/

int mprAllocVsprintf(MPR_LOC_DEC(ctx, loc), char **buf, int maxSize, 
	const char *fmt, va_list arg)
{
	mprAssert(buf);
	mprAssert(fmt);

	*buf = 0;
	return mprSprintfCore(MPR_LOC_PASS(ctx, loc), buf, maxSize, fmt, arg);
}

/******************************************************************************/

static int getState(char c, int state)
{
	/*
	 *	Declared here to remove all static / globals
	 *	FUTURE OPT -- need to measure this. Could be slow on BREW.
	 */

	char stateMap[] = {
	/*     STATES:  Normal Percent Modifier Width  Dot  Prec Bits Type */
	/* CLASS           0      1       2       3     4     5    6    7  */
	/* Normal   0 */   0,     0,      0,      0,    0,    0,   0,   0,
	/* Percent  1 */   1,     0,      1,      1,    1,    1,   1,   1,
	/* Modifier 2 */   0,     2,      2,      0,    0,    0,   0,   0,
	/* Zero     3 */   0,     2,      2,      3,    0,    5,   0,   0,
	/* Star     4 */   0,     3,      3,      0,    5,    0,   0,   0,
	/* Digit    5 */   0,     3,      3,      3,    5,    5,   0,   0,
	/* Dot      6 */   0,     4,      4,      4,    0,    0,   0,   0,
	/* Bits     7 */   0,     6,      6,      6,    6,    6,   6,   0,
	/* Types    8 */   0,     7,      7,      7,    7,    7,   7,   0,
	};

	/*
	 *	Format:			%[modifier][width][precision][bits][type]
	 */
	char classMap[] = {
		/*   0  ' '    !     "     #     $     %     &     ' */
				 2,    0,    0,    2,    0,    1,    0,    0,
		/*  07   (     )     *     +     ,     -     .     / */
				 0,    0,    4,    2,    2,    2,    6,    0,
		/*  10   0     1     2     3     4     5     6     7 */
				 3,    5,    5,    5,    5,    5,    5,    5,
		/*  17   8     9     :     ;     <     =     >     ? */
				 5,    5,    0,    0,    0,    0,    0,    0,
		/*  20   @     A     B     C     D     E     F     G */
				 0,    0,    0,    0,    0,    0,    0,    0,
		/*  27   H     I     J     K     L     M     N     O */
				 0,    0,    0,    0,    7,    0,    0,    0,
		/*  30   P     Q     R     S     T     U     V     W */
				 0,    0,    0,    8,    0,    0,    0,    0,
		/*  37   X     Y     Z     [     \     ]     ^     _ */
				 8,    0,    0,    0,    0,    0,    0,    0,
		/*  40   '     a     b     c     d     e     f     g */
				 0,    0,    0,    8,    8,    0,    8,    0,
		/*  47   h     i     j     k     l     m     n     o */
				 7,    8,    0,    0,    7,    0,    8,    8,
		/*  50   p     q     r     s     t     u     v     w */
				 8,    0,    0,    8,    0,    8,    0,    0,
		/*  57   x     y     z  */
				 8,    0,    0,
	};

	int		chrClass;

	if (c < ' ' || c > 'z') {
		chrClass = CLASS_NORMAL;
	} else {
		mprAssert((c - ' ') < (int) sizeof(classMap));
		chrClass = classMap[(c - ' ')];
	}
	mprAssert((chrClass * STATE_COUNT + state) < (int) sizeof(stateMap));
	state = stateMap[chrClass * STATE_COUNT + state];
	return state;
}

/******************************************************************************/

static int mprSprintfCore(MPR_LOC_DEC(ctx, loc), char **bufPtr, 
	int maxsize, const char *spec, va_list arg)
{
	Format		fmt;
	char		*cp;
	char		c;
	char		*sValue;
	num			iValue;
	unum		uValue;
	int			count, i, len, state;

	mprAssert(bufPtr);
	mprAssert(spec);

	if (*bufPtr != 0) {
		mprAssert(maxsize > 0);
		fmt.buf = (uchar*) *bufPtr;
		fmt.endbuf = &fmt.buf[maxsize];
		fmt.growBy = 0;
	} else {
		if (maxsize <= 0) {
			maxsize = MAXINT;
		}

		len = min(MPR_DEFAULT_ALLOC, maxsize);
		fmt.buf = (uchar*) mprAllocBlock(MPR_LOC_PASS(ctx, loc), len);
		fmt.endbuf = &fmt.buf[len];
		fmt.growBy = MPR_DEFAULT_ALLOC * 2;
	}

	fmt.maxsize = maxsize;
	fmt.start = fmt.buf;
	fmt.end = fmt.buf;
	fmt.len = 0;
	*fmt.start = '\0';

	state = STATE_NORMAL;

	while ((c = *spec++) != '\0') {
		state = getState(c, state);

		switch (state) {
		case STATE_NORMAL:
			BPUT(ctx, loc, &fmt, c);
			break;

		case STATE_PERCENT:
			fmt.precision = -1;
			fmt.width = 0;
			fmt.flags = 0;
			break;

		case STATE_MODIFIER:
			switch (c) {
			case '+':
				fmt.flags |= SPRINTF_SIGN;
				break;
			case '-':
				fmt.flags |= SPRINTF_LEFT;
				break;
			case '#':
				fmt.flags |= SPRINTF_ALTERNATE;
				break;
			case '0':
				fmt.flags |= SPRINTF_LEAD_ZERO;
				break;
			case ' ':
				fmt.flags |= SPRINTF_LEAD_SPACE;
				break;
			case ',':
				fmt.flags |= SPRINTF_COMMA;
				break;
			}
			break;

		case STATE_WIDTH:
			if (c == '*') {
				fmt.width = va_arg(arg, int);
				if (fmt.width < 0) {
					fmt.width = -fmt.width;
					fmt.flags |= SPRINTF_LEFT;
				}
			} else {
				while (isdigit((int)c)) {
					fmt.width = fmt.width * 10 + (c - '0');
					c = *spec++;
				}
				spec--;
			}
			break;

		case STATE_DOT:
			fmt.precision = 0;
			fmt.flags &= ~SPRINTF_LEAD_ZERO;
			break;

		case STATE_PRECISION:
			if (c == '*') {
				fmt.precision = va_arg(arg, int);
			} else {
				while (isdigit((int) c)) {
					fmt.precision = fmt.precision * 10 + (c - '0');
					c = *spec++;
				}
				spec--;
			}
			break;

		case STATE_BITS:
			switch (c) {
#if BLD_FEATURE_INT64
			case 'L':
				fmt.flags |= SPRINTF_LONGLONG;			/* 64 bit */
				break;
#endif

			case 'l':
				fmt.flags |= SPRINTF_LONG;
				break;

			case 'h':
				fmt.flags |= SPRINTF_SHORT;
				break;
			}
			break;

		case STATE_TYPE:
			switch (c) {
#if BLD_FEATURE_FLOATING_POINT
			case 'e':
			case 'g':
			case 'f':
				fmt.radix = 10;
				outFloat(MPR_LOC_PASS(ctx, loc), &fmt, c, 
					(double) va_arg(arg, double));
				break;
#endif
			case 'c':
				BPUT(ctx, loc, &fmt, (char) va_arg(arg, int));
				break;

			case 's':
			case 'S':
				sValue = va_arg(arg, char*);
				if (sValue == 0) {
					sValue = "null";
					len = strlen(sValue);
				} else if (fmt.flags & SPRINTF_ALTERNATE) {
					sValue++;
					len = (int) *sValue;
				} else if (fmt.precision >= 0) {
					/*
					 *	Can't use strlen(), the string may not have a null
					 */
					cp = sValue;
					for (len = 0; len < fmt.precision; len++) {
						if (*cp++ == '\0') {
							break;
						}
					}
				} else {
					len = strlen(sValue);
				}
				if (!(fmt.flags & SPRINTF_LEFT)) {
					for (i = len; i < fmt.width; i++) {
						BPUT(ctx, loc, &fmt, (char) ' ');
					}
				}
				for (i = 0; i < len && *sValue; i++) {
					BPUT(ctx, loc, &fmt, *sValue++);
				}
				if (fmt.flags & SPRINTF_LEFT) {
					for (i = len; i < fmt.width; i++) {
						BPUT(ctx, loc, &fmt, (char) ' ');
					}
				}
				break;

			case 'i':
				;
			case 'd':
				fmt.radix = 10;
				if (fmt.flags & SPRINTF_SHORT) {
					iValue = (short) va_arg(arg, int);
				} else if (fmt.flags & SPRINTF_LONG) {
					iValue = va_arg(arg, long);
#if BLD_FEATURE_INT64
				} else if (fmt.flags & SPRINTF_LONGLONG) {
					iValue = va_arg(arg, num);
#endif
				} else {
					iValue = va_arg(arg, int);
				}
				if (iValue >= 0) {
					if (fmt.flags & SPRINTF_LEAD_SPACE) {
						outNum(MPR_LOC_PASS(ctx, loc), &fmt, " ", iValue);
					} else if (fmt.flags & SPRINTF_SIGN) {
						outNum(MPR_LOC_PASS(ctx, loc), &fmt, "+", iValue);
					} else {
						outNum(MPR_LOC_PASS(ctx, loc), &fmt, 0, iValue);
					}
				} else {
					outNum(MPR_LOC_PASS(ctx, loc), &fmt, "-", -iValue);
				}
				break;

			case 'X':
				fmt.flags |= SPRINTF_UPPER_CASE;
				/*	Fall through  */
			case 'o':
			case 'x':
			case 'u':
				if (fmt.flags & SPRINTF_SHORT) {
					uValue = (ushort) va_arg(arg, uint);
				} else if (fmt.flags & SPRINTF_LONG) {
					uValue = va_arg(arg, ulong);
#if BLD_FEATURE_INT64
				} else if (fmt.flags & SPRINTF_LONGLONG) {
					uValue = va_arg(arg, unum);
#endif
				} else {
					uValue = va_arg(arg, uint);
				}
				if (c == 'u') {
					fmt.radix = 10;
					outNum(MPR_LOC_PASS(ctx, loc), &fmt, 0, uValue);
				} else if (c == 'o') {
					fmt.radix = 8;
					if (fmt.flags & SPRINTF_ALTERNATE && uValue != 0) {
						outNum(MPR_LOC_PASS(ctx, loc), &fmt, "0", uValue);
					} else {
						outNum(MPR_LOC_PASS(ctx, loc), &fmt, 0, uValue);
					}
				} else {
					fmt.radix = 16;
					if (fmt.flags & SPRINTF_ALTERNATE && uValue != 0) {
						if (c == 'X') {
							outNum(MPR_LOC_PASS(ctx, loc), &fmt, "0X", uValue);
						} else {
							outNum(MPR_LOC_PASS(ctx, loc), &fmt, "0x", uValue);
						}
					} else {
						outNum(MPR_LOC_PASS(ctx, loc), &fmt, 0, uValue);
					}
				}
				break;

			case 'n':		/* Count of chars seen thus far */
				if (fmt.flags & SPRINTF_SHORT) {
					short *count = va_arg(arg, short*);
					*count = fmt.end - fmt.start;
				} else if (fmt.flags & SPRINTF_LONG) {
					long *count = va_arg(arg, long*);
					*count = fmt.end - fmt.start;
				} else {
					int *count = va_arg(arg, int *);
					*count = fmt.end - fmt.start;
				}
				break;

			case 'p':		/* Pointer */
#if __WORDSIZE == 64 && BLD_FEATURE_INT64
				uValue = (unum) va_arg(arg, void*);
#else
				uValue = (uint) (int) va_arg(arg, void*);
#endif
				fmt.radix = 16;
				outNum(MPR_LOC_PASS(ctx, loc), &fmt, "0x", uValue);
				break;

			default:
				BPUT(ctx, loc, &fmt, c);
			}
		}
	}
	BPUTNULL(ctx, loc, &fmt);

	count = fmt.end - fmt.start;
	if (*bufPtr == 0) {
		*bufPtr = (char*) fmt.buf;
	}
	return count;
}

/******************************************************************************/
/*
 *	Output a number according to the given format. If BLD_FEATURE_INT64 is 
 *	defined, then uses 64 bits universally. Slower but smaller code.
 */

static void outNum(MPR_LOC_DEC(ctx, loc), Format *fmt, const char *prefix, 
	unum value)
{
	char	numBuf[64];
	char	*cp;
	char	*endp;
	char	c;
	int		letter, len, leadingZeros, i, fill;

	endp = &numBuf[sizeof(numBuf) - 1];
	*endp = '\0';
	cp = endp;

	/*
	 *	Convert to ascii
	 */
	if (fmt->radix == 16) {
		do {
			letter = (int) (value % fmt->radix);
			if (letter > 9) {
				if (fmt->flags & SPRINTF_UPPER_CASE) {
					letter = 'A' + letter - 10;
				} else {
					letter = 'a' + letter - 10;
				}
			} else {
				letter += '0';
			}
			*--cp = letter;
			value /= fmt->radix;
		} while (value > 0);

	} else if (fmt->flags & SPRINTF_COMMA) {
		i = 1;
		do {
			*--cp = '0' + (int) (value % fmt->radix);
			value /= fmt->radix;
			if ((i++ % 3) == 0 && value > 0) {
				*--cp = ',';
			}
		} while (value > 0);
	} else {
		do {
			*--cp = '0' + (int) (value % fmt->radix);
			value /= fmt->radix;
		} while (value > 0);
	}

	len = endp - cp;
	fill = fmt->width - len;

	if (prefix != 0) {
		fill -= strlen(prefix);
	}
	leadingZeros = (fmt->precision > len) ? fmt->precision - len : 0;
	fill -= leadingZeros;

	if (!(fmt->flags & SPRINTF_LEFT)) {
		c = (fmt->flags & SPRINTF_LEAD_ZERO) ? '0': ' ';
		for (i = 0; i < fill; i++) {
			BPUT(ctx, loc, fmt, c);
		}
	}
	if (prefix != 0) {
		while (*prefix) {
			BPUT(ctx, loc, fmt, *prefix++);
		}
	}
	for (i = 0; i < leadingZeros; i++) {
		BPUT(ctx, loc, fmt, '0');
	}
	while (*cp) {
		BPUT(ctx, loc, fmt, *cp);
		cp++;
	}
	if (fmt->flags & SPRINTF_LEFT) {
		for (i = 0; i < fill; i++) {
			BPUT(ctx, loc, fmt, ' ');
		}
	}
}

/******************************************************************************/
#if BLD_FEATURE_FLOATING_POINT
/*
 *	Output a floating point number
 */

static void outFloat(MPR_LOC_DEC(ctx, loc), Format *fmt, char specChar, 
	double value)
{
	char	*cp;
#if FUTURE
	char	numBuf[64];
	char	*endp;
	char	c;
	int		letter, len, leadingZeros, i, fill, width, precision;

	endp = &numBuf[sizeof(numBuf) - 1];
	*endp = '\0';

	precision = fmt->precision;
	if (precision < 0) {
		precision = 6;
	} else if (precision > (sizeof(numBuf) - 1)) {
		precision = (sizeof(numBuf) - 1);
	}
	width = min(fmt->width, sizeof(numBuf) - 1);

	if (__isnanl(value)) {
		"nan"
	} else if (__isinfl(value)) {
		"infinity"
	} else if (value < 0) {
		prefix = "-";
	} else if (fmt.flags & SPRINTF_LEAD_SPACE) {
		prefix = " ";
	} else if (fmt.flags & SPRINTF_SIGN) {
		prefix = "+";
	} 


	/*
	 *	Do the exponent part
	 */
	cp = &numBuf[sizeof(numBuf) - precision];
	for (i = 0; i < precision; i++) {
		*cp++ = '0' + (int) (value % fmt->radix);
		value /= fmt->radix;
	}

	/*
	 *	Do the decimal part
	 */
	if (fmt->flags & SPRINTF_COMMA) {
		i = 1;
		do {
			*--cp = '0' + (int) (value % fmt->radix);
			value /= fmt->radix;
			if ((i++ % 3) == 0 && value > 0) {
				*--cp = ',';
			}
		} while (value >= 1.0);

	} else {
		do {
			*--cp = '0' + (int) (value % fmt->radix);
			value /= fmt->radix;
		} while (value > 1.0);
	}

	len = endp - cp;
	fill = fmt->width - len;

	if (prefix != 0) {
		fill -= strlen(prefix);
	}

	leadingZeros = (fmt->precision > len) ? fmt->precision - len : 0;
	fill -= leadingZeros;

	if (!(fmt->flags & SPRINTF_LEFT)) {
		c = (fmt->flags & SPRINTF_LEAD_ZERO) ? '0': ' ';
		for (i = 0; i < fill; i++) {
			BPUT(ctx, loc, fmt, c);
		}
	}
	if (prefix != 0) {
		BPUT(ctx, loc, fmt, prefix);
	}
	for (i = 0; i < leadingZeros; i++) {
		BPUT(ctx, loc, fmt, '0');
	}
	BPUT(ctx, loc, fmt, cp);
	if (fmt->flags & SPRINTF_LEFT) {
		for (i = 0; i < fill; i++) {
			BPUT(ctx, loc, fmt, ' ');
		}
	}
#else
	char	numBuf[64];
	if (specChar == 'f') {
		sprintf(numBuf, "%*.*f", fmt->width, fmt->precision, value);
	} else if (specChar == 'g') {
		sprintf(numBuf, "%*.*g", fmt->width, fmt->precision, value);
	} else if (specChar == 'e') {
		sprintf(numBuf, "%*.*e", fmt->width, fmt->precision, value);
	}
	for (cp = numBuf; *cp; cp++) {
		BPUT(ctx, loc, fmt, *cp);
	}
#endif
}

#endif /* BLD_FEATURE_FLOATING_POINT */
/******************************************************************************/
/*
 *	Grow the buffer to fit new data. Return 1 if the buffer can grow. 
 *	Grow using the growBy size specified when creating the buffer. 
 */

static int growBuf(MPR_LOC_DEC(ctx, loc), Format *fmt)
{
	uchar	*newbuf;
	int		buflen;

	buflen = fmt->endbuf - fmt->buf;
	if (fmt->maxsize >= 0 && buflen >= fmt->maxsize) {
		return 0;
	}
	if (fmt->growBy < 0) {
		/*
		 *	User supplied buffer
		 */
		return 0;
	}

	newbuf = (uchar*) mprAlloc(ctx, buflen + fmt->growBy);
	if (fmt->buf) {
		memcpy(newbuf, fmt->buf, buflen);
		mprFree(fmt->buf);
	}

	buflen += fmt->growBy;
	fmt->end = newbuf + (fmt->end - fmt->buf);
	fmt->start = newbuf + (fmt->start - fmt->buf);
	fmt->buf = newbuf;
	fmt->endbuf = &fmt->buf[buflen];

	/*
	 *	Increase growBy to reduce overhead
	 */
	if ((buflen + (fmt->growBy * 2)) < fmt->maxsize) {
		fmt->growBy *= 2;
	}
	return 1;
}

/******************************************************************************/

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
