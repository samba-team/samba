/*
 *	exml.c -- A simple SAX style XML parser
 */

/********************************* Description ********************************/
/*
 *	This is a recursive descent parser for XML text files. It is a one-pass
 *	simple parser that invokes a user supplied callback for key tokens in the
 *	XML file. The user supplies a read function so that XML files can be parsed
 *	from disk or in-memory. 
 */
/********************************** Includes **********************************/

#include	"exml.h"

/****************************** Forward Declarations **************************/
/* MOB -- FIX */
#if BLD_FEATURE_EXML || 1

static int 		 parseNext(Exml *xp, int state);
static ExmlToken getToken(Exml *xp, int state);
static int 		 getNextChar(Exml *xp);
static int 		 scanFor(Exml *xp, char *str);
static int 		 putLastChar(Exml *xp, int c);
static void 	 error(Exml *xp, char *fmt, ...);
static void 	 trimToken(Exml *xp);

/************************************ Code ************************************/

Exml *exmlOpen(MprCtx ctx, int initialSize, int maxSize)
{
	Exml	*xp;

	xp = mprAllocTypeZeroed(ctx, Exml);
	
	xp->inBuf = mprCreateBuf(xp, EXML_BUFSIZE, EXML_BUFSIZE);
	xp->tokBuf = mprCreateBuf(xp, initialSize, maxSize);

	return xp;
}

/******************************************************************************/

void exmlClose(Exml *xp)
{
	mprAssert(xp);

	mprFree(xp);
}

/******************************************************************************/

void exmlSetParserHandler(Exml *xp, ExmlHandler h)
{
	mprAssert(xp);

	xp->handler = h;
}

/******************************************************************************/

void exmlSetInputStream(Exml *xp, ExmlInputStream s, void *arg)
{
	mprAssert(xp);

	xp->readFn = s;
	xp->inputArg = arg;
}

/******************************************************************************/
/*
 *	Set the parse arg
 */ 

void exmlSetParseArg(Exml *xp, void *parseArg)
{
	mprAssert(xp);

	xp->parseArg = parseArg;
}

/******************************************************************************/
/*
 *	Set the parse arg
 */ 

void *exmlGetParseArg(Exml *xp)
{
	mprAssert(xp);

	return xp->parseArg;
}

/******************************************************************************/
/*
 *	Parse an XML file. Return 0 for success, -1 for error.
 */ 

int	exmlParse(Exml *xp)
{
	mprAssert(xp);

	return parseNext(xp, EXML_BEGIN);
}

/******************************************************************************/
/*
 *	XML parser. This is a recursive descent parser. Return -1 for errors, 0 for
 *	EOF and 1 if there is still more data to parse.
 */

static int parseNext(Exml *xp, int state)
{
	ExmlHandler	handler;
	ExmlToken	token;
	MprBuf		*tokBuf;
	char		*tname, *aname;
	int			rc;

	mprAssert(state >= 0);

	tokBuf = xp->tokBuf;
	handler = xp->handler;
	tname = aname = 0;
	rc = 0;
	
	/*
	 *	In this parse loop, the state is never assigned EOF or ERR. In
	 *	such cases we always return EOF or ERR.
	 */
	while (1) {

		token = getToken(xp, state);

		if (token == TOKEN_TOO_BIG) {
			error(xp, "XML token is too big");
			goto err;
		}

		switch (state) {
		case EXML_BEGIN:		/* ------------------------------------------ */
			/*
			 *	Expect to get an element, comment or processing instruction 
			 */
			switch (token) {
			case TOKEN_EOF:
				goto exit;

			case TOKEN_LS:
				/*
				 *	Recurse to handle the new element, comment etc.
				 */
				rc = parseNext(xp, EXML_AFTER_LS);
				if (rc < 0) {
					goto exit;
				}
				break;

			default:
				error(xp, "Syntax error");
				goto err;
			}
			break;

		case EXML_AFTER_LS: /* ------------------------------------------ */
			switch (token) {
			case TOKEN_COMMENT:
				state = EXML_COMMENT;
				rc = (*handler)(xp, state, "!--", 0, mprGetBufStart(tokBuf));
				if (rc < 0) {
					goto err;
				}
				rc = 1;
				goto exit;

			case TOKEN_CDATA:
				state = EXML_CDATA;
				rc = (*handler)(xp, state, "!--", 0, mprGetBufStart(tokBuf));
				if (rc < 0) {
					goto err;
				}
				rc = 1;
				goto exit;

			case TOKEN_INSTRUCTIONS:
				/* Just ignore processing instructions */
				rc = 1;
				goto exit;

			case TOKEN_TEXT:
				state = EXML_NEW_ELT;
				tname = mprStrdup(xp, mprGetBufStart(tokBuf));
				if (tname == 0) {
					rc = MPR_ERR_MEMORY;
					goto exit;
				}
				rc = (*handler)(xp, state, tname, 0, 0);
				if (rc < 0) {
					goto err;
				}
				break;

			default:
				error(xp, "Syntax error");
				goto err;
			}
			break;

		case EXML_NEW_ELT: 	/* ------------------------------------------ */
			/*
			 *	We have seen the opening "<element" for a new element and have
 			 *	not yet seen the terminating ">" of the opening element.
			 */
			switch (token) {
			case TOKEN_TEXT:
				/*
				 *	Must be an attribute name
				 */
				aname = mprStrdup(xp, mprGetBufStart(tokBuf));
				token = getToken(xp, state);
				if (token != TOKEN_EQ) {
					error(xp, "Missing assignment for attribute \"%s\"", aname);
					goto err;
				}

				token = getToken(xp, state);
				if (token != TOKEN_TEXT) {
					error(xp, "Missing value for attribute \"%s\"", aname);
					goto err;
				}
				state = EXML_NEW_ATT;
				rc = (*handler)(xp, state, tname, aname,
						mprGetBufStart(tokBuf));
				if (rc < 0) {
					goto err;
				}
				state = EXML_NEW_ELT;
				break;

			case TOKEN_GR:
				/*
 				 *	This is ">" the termination of the opening element
				 */
				if (*tname == '\0') {
					error(xp, "Missing element name");
					goto err;
				}

				/*
				 *	Tell the user that the opening element is now complete
 				 */
				state = EXML_ELT_DEFINED;
				rc = (*handler)(xp, state, tname, 0, 0);
				if (rc < 0) {
					goto err;
				}
				state = EXML_ELT_DATA;
				break;

			case TOKEN_SLASH_GR:
				/*
				 *	If we see a "/>" then this is a solo element
 				 */
				if (*tname == '\0') {
					error(xp, "Missing element name");
					goto err;
				}
				state = EXML_SOLO_ELT_DEFINED;
				rc = (*handler)(xp, state, tname, 0, 0);
				if (rc < 0) {
					goto err;
				}
				rc = 1;
				goto exit;
	
			default:
				error(xp, "Syntax error");
				goto err;
			}
			break;

		case EXML_ELT_DATA:		/* -------------------------------------- */
			/*
			 *	We have seen the full opening element "<name ...>" and now 
			 *	await data or another element.
			 */
			if (token == TOKEN_LS) {
				/*
				 *	Recurse to handle the new element, comment etc.
				 */
				rc = parseNext(xp, EXML_AFTER_LS);
				if (rc < 0) {
					goto exit;
				}
				break;

			} else if (token == TOKEN_LS_SLASH) {
				state = EXML_END_ELT;
				break;

			} else if (token != TOKEN_TEXT) {
				goto err;
			}
			if (mprGetBufLength(tokBuf) > 0) {
				/*
				 *	Pass the data between the element to the user
				 */
				rc = (*handler)(xp, state, tname, 0, mprGetBufStart(tokBuf));
				if (rc < 0) {
					goto err;
				}
			}
			break;

		case EXML_END_ELT:			/* -------------------------------------- */
			if (token != TOKEN_TEXT) {
				error(xp, "Missing closing element name for \"%s\"", tname);
				goto err;
			}
			/*
			 *	The closing element name must match the opening element name 
			 */
			if (strcmp(tname, mprGetBufStart(tokBuf)) != 0) {
				error(xp, 
					"Closing element name \"%s\" does not match on line %d"
					"opening name \"%s\"",
					mprGetBufStart(tokBuf), xp->lineNumber, tname);
				goto err;
			}
			rc = (*handler)(xp, state, tname, 0, 0);
			if (rc < 0) {
				goto err;
			}
			if (getToken(xp, state) != TOKEN_GR) {
				error(xp, "Syntax error");
				goto err;
			}
			return 1;

		case EXML_EOF: 		/* ---------------------------------------------- */
			goto exit;

		case EXML_ERR:  	/* ---------------------------------------------- */
		default:
			goto err;
		}
	}
	mprAssert(0);

err:
	rc = -1;

exit:
	mprFree(tname);
	mprFree(aname);

	return rc;
}

/******************************************************************************/
/*
 *	Lexical analyser for XML. Return the next token reading input as required.
 *	It uses a one token look ahead and push back mechanism (LAR1 parser).
 *	Text token identifiers are left in the tokBuf parser buffer on exit.
 *	This Lex has special cases for the states EXML_ELT_DATA where we
 *	have an optimized read of element data, and EXML_AFTER_LS where we 
 *	distinguish between element names, processing instructions and comments. 
 */

static ExmlToken getToken(Exml *xp, int state)
{
	MprBuf		*tokBuf, *inBuf;
	uchar		*cp;
	int			c, rc;

	tokBuf = xp->tokBuf;
	inBuf = xp->inBuf;

	mprAssert(state >= 0);

	if ((c = getNextChar(xp)) < 0) {
		return TOKEN_EOF;
	}
	mprFlushBuf(tokBuf);

	/*
	 *	Special case parsing for names and for element data. We do this for
	 *	performance so we can return to the caller the largest token possible
	 */
	if (state == EXML_ELT_DATA) {
		/*
		 *	Read all the data up to the start of the closing element "<" or the
		 *	start of a sub-element.
 		 */
#if UNUSED
		while (isspace(c)) {
			if ((c = getNextChar(xp)) < 0) {
				return TOKEN_EOF;
			}
		}
#endif
		if (c == '<') {
			if ((c = getNextChar(xp)) < 0) {
				return TOKEN_EOF;
			}
			if (c == '/') {
				return TOKEN_LS_SLASH;
			}
			putLastChar(xp, c);
			return TOKEN_LS;
		}
		do {
			if (mprPutCharToBuf(tokBuf, c) < 0) {
				return TOKEN_TOO_BIG;
			}
			if ((c = getNextChar(xp)) < 0) {
				return TOKEN_EOF;
			}
		} while (c != '<');

		/*
		 *	Put back the last look-ahead character
		 */
		putLastChar(xp, c);

		/*
		 *	If all white space, then zero the token buffer
		 */
		for (cp = tokBuf->start; *cp; cp++) {
			if (!isspace(*cp)) {
				return TOKEN_TEXT;
			}
		}
		mprFlushBuf(tokBuf);
		return TOKEN_TEXT;
	}

	while (1) {
		switch (c) {
		case ' ':
		case '\n':
		case '\t':
		case '\r':
			break;

		case '<':
			if ((c = getNextChar(xp)) < 0) {
				return TOKEN_EOF;
			}
			if (c == '/') {
				return TOKEN_LS_SLASH;
			}
			putLastChar(xp, c);
			return TOKEN_LS;
	
		case '=':
			return TOKEN_EQ;

		case '>':
			return TOKEN_GR;

		case '/':
			if ((c = getNextChar(xp)) < 0) {
				return TOKEN_EOF;
			}
			if (c == '>') {
				return TOKEN_SLASH_GR;
			}
			return TOKEN_ERR;
		
		case '\"':
		case '\'':
			xp->quoteChar = c;
			/* Fall through */

		default:
			/*
 			 *	We handle element names, attribute names and attribute values 
			 *	here. We do NOT handle data between elements here. Read the 
			 *	token.  Stop on white space or a closing element ">"
			 */
			if (xp->quoteChar) {
				if ((c = getNextChar(xp)) < 0) {
					return TOKEN_EOF;
				}
				while (c != xp->quoteChar) {
					if (mprPutCharToBuf(tokBuf, c) < 0) {
						return TOKEN_TOO_BIG;
					}
					if ((c = getNextChar(xp)) < 0) {
						return TOKEN_EOF;
					}
				}
				xp->quoteChar = 0;

			} else {
				while (!isspace(c) && c != '>' && c != '/' && c != '=') {
					if (mprPutCharToBuf(tokBuf, c) < 0) {
						return TOKEN_TOO_BIG;
					}
					if ((c = getNextChar(xp)) < 0) {
						return TOKEN_EOF;
					}
				}
				putLastChar(xp, c);
			}
			if (mprGetBufLength(tokBuf) <= 0) {
				return TOKEN_ERR;
			}
			mprAddNullToBuf(tokBuf);

			if (state == EXML_AFTER_LS) {
				/*
				 *	If we are just inside an element "<", then analyze what we
				 *	have to see if we have an element name, instruction or
 				 *	comment. Tokbuf will hold "?" for instructions or "!--"
				 *	for comments.
				 */
				if (mprLookAtNextCharInBuf(tokBuf) == '?') {
					/*	Just ignore processing instructions */
					rc = scanFor(xp, "?>");
					if (rc < 0) {
						return TOKEN_TOO_BIG;
					} else if (rc == 0) {
						return TOKEN_ERR;
					}
					return TOKEN_INSTRUCTIONS;

				} else if (mprLookAtNextCharInBuf(tokBuf) == '!') {
					/*
					 *	First discard the comment leadin "!--" and eat leading 
					 *	white space.
					 */
					if (strcmp((char*) tokBuf->start, "![CDATA[") == 0) {
						mprFlushBuf(tokBuf);
#if UNUSED
						c = mprLookAtNextCharInBuf(inBuf);
						while (isspace(c)) {
							if ((c = getNextChar(xp)) < 0) {
								return TOKEN_EOF;
							}
							c = mprLookAtNextCharInBuf(inBuf);
						}
#endif
						rc = scanFor(xp, "]]>");
						if (rc < 0) {
							return TOKEN_TOO_BIG;
						} else if (rc == 0) {
							return TOKEN_ERR;
						}
						return TOKEN_CDATA;

					} else {
						mprFlushBuf(tokBuf);
#if UNUSED
						c = mprLookAtNextCharInBuf(inBuf);
						while (isspace(c)) {
							if ((c = getNextChar(xp)) < 0) {
								return TOKEN_EOF;
							}
							c = mprLookAtNextCharInBuf(inBuf);
						}
#endif
						rc = scanFor(xp, "-->");
						if (rc < 0) {
							return TOKEN_TOO_BIG;
						} else if (rc == 0) {
							return TOKEN_ERR;
						}
						return TOKEN_COMMENT;
					}
				}
			}
			trimToken(xp);
			return TOKEN_TEXT;
		}
		if ((c = getNextChar(xp)) < 0) {
			return TOKEN_EOF;
		}
	}

	/* Should never get here */
	mprAssert(0);
	return TOKEN_ERR;
}

/******************************************************************************/
/*
 *	Scan for a pattern. Eat and discard input up to the pattern. Return 1 if
 *	the pattern was found, return 0 if not found. Return < 0 on errors.
 */

static int scanFor(Exml *xp, char *str)
{
	MprBuf	*tokBuf;
	char	*cp;
	int		c;

	mprAssert(str);

	tokBuf = xp->tokBuf;

	while (1) {
		for (cp = str; *cp; cp++) {
			if ((c = getNextChar(xp)) < 0) {
				return 0;
			}
			if (tokBuf) {
				if (mprPutCharToBuf(tokBuf, c) < 0) {
					return -1;
				}
			}
			if (c != *cp) {
				break;
			}
		}
		if (*cp == '\0') {
			/*
			 *	Remove the pattern from the tokBuf
			 */
			if (tokBuf) {
				mprAdjustBufEnd(tokBuf, -(int) strlen(str));
				trimToken(xp);
			}
			return 1;
		}
	}
}

/******************************************************************************/
/*
 *	Get another character. We read and buffer blocks of data if we need more
 *	data to parse.
 */

static int getNextChar(Exml *xp)
{
	MprBuf	*inBuf;
	char	c;
	int		l;

	inBuf = xp->inBuf;
	if (mprGetBufLength(inBuf) <= 0) {
		/*
 		 *	Flush to reset the servp/endp pointers to the start of the buffer
		 *	so we can do a maximal read 
		 */
		mprFlushBuf(inBuf);
		l = (xp->readFn)(xp, xp->inputArg, mprGetBufStart(inBuf), 
			mprGetBufLinearSpace(inBuf));
		if (l <= 0) {
			return -1;
		}
		mprAdjustBufEnd(inBuf, l);
	}
	c = mprGetCharFromBuf(inBuf);

	if (c == '\n') {
		xp->lineNumber++;
	}
	return c;
}

/******************************************************************************/
/*
 *	Put back a character in the input buffer
 */

static int putLastChar(Exml *xp, int c)
{
	if (mprInsertCharToBuf(xp->inBuf, (char) c) < 0) {
		mprAssert(0);
		return -1;
	}
	if (c == '\n') {
		xp->lineNumber--;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Output a parse message
 */ 

static void error(Exml *xp, char *fmt, ...)
{
	va_list		args;
	char		*buf;

	mprAssert(fmt);

	va_start(args, fmt);
	mprAllocVsprintf(MPR_LOC_ARGS(xp), &buf, MPR_MAX_STRING, fmt, args);
	va_end(args);

	/*
	 *	MOB need to add the failing line text and a pointer to which column
	 */
	mprFree(xp->errMsg);
	mprAllocSprintf(MPR_LOC_ARGS(xp), &xp->errMsg, MPR_MAX_STRING, 
		"XML error: %s\nAt line %d\n", buf, xp->lineNumber);

	mprFree(buf);
}

/******************************************************************************/
/*
 *	Remove trailing whitespace in a token and ensure it is terminated with
 *	a NULL for easy parsing
 */

static void trimToken(Exml *xp)
{
	while (isspace(mprLookAtLastCharInBuf(xp->tokBuf))) {
		mprAdjustBufEnd(xp->tokBuf, -1);
	}
	mprAddNullToBuf(xp->tokBuf);
}

/******************************************************************************/

const char *exmlGetErrorMsg(Exml *xp)
{
	if (xp->errMsg == 0) {
		return "";
	}
	return xp->errMsg;
}

/******************************************************************************/

int exmlGetLineNumber(Exml *xp)
{
	return xp->lineNumber;
}

/******************************************************************************/
#else

void exmlParserDummy() {}
#endif /* BLD_FEATURE_EXML */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
