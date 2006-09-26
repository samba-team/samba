/*
 *	exml.h -- Embedded Xml Parser header
 *
 *	Copyright (c) Mbedthis Software, LLC, 2003-2003. All Rights Reserved. -- MOB
 */ 

#ifndef _h_EXML
#define _h_EXML 1

/******************************** Description *********************************/

#include	"mpr.h"

/********************************** Defines ***********************************/

#if BLD_FEATURE_SQUEEZE
	#define	EXML_BUFSIZE		512			/* Read buffer size */
#else
	#define	EXML_BUFSIZE		1024		/* Read buffer size */
#endif

/*
 *	XML parser states. The states that are passed to the user handler have
 *	"U" appended to the comment. The error states (ERR and EOF) must be 
 *	negative.
 */ 
#define EXML_ERR				-1			/* Error */
#define EXML_EOF				-2			/* End of input */
#define EXML_BEGIN				1			/* Before next tag 				 */
#define EXML_AFTER_LS			2			/* Seen "<" 					 */
#define EXML_COMMENT			3			/* Seen "<!--" (usr) 		U	 */
#define EXML_NEW_ELT			4			/* Seen "<tag" (usr) 		U	 */
#define EXML_ATT_NAME			5			/* Seen "<tag att" 				 */
#define EXML_ATT_EQ				6			/* Seen "<tag att" = 			 */
#define EXML_NEW_ATT			7			/* Seen "<tag att = "val" 	U	 */
#define EXML_SOLO_ELT_DEFINED	8			/* Seen "<tag../>" 			U	 */
#define EXML_ELT_DEFINED		9			/* Seen "<tag...>" 			U	 */
#define EXML_ELT_DATA			10			/* Seen "<tag>....<" 		U	 */
#define EXML_END_ELT			11			/* Seen "<tag>....</tag>"	U	 */
#define EXML_PI					12			/* Seen "<?processingInst" 	U	 */
#define EXML_CDATA				13			/* Seen "<![CDATA["  		U	 */

/*
 *	Lex tokens
 */ 
typedef enum ExmlToken {
	TOKEN_ERR,
	TOKEN_TOO_BIG,						/* Token is too big */
	TOKEN_CDATA,
	TOKEN_COMMENT,
	TOKEN_INSTRUCTIONS,
	TOKEN_LS,							/* "<" -- Opening a tag */
	TOKEN_LS_SLASH,						/* "</" -- Closing a tag */
	TOKEN_GR,							/* ">" -- End of an open tag */
	TOKEN_SLASH_GR,						/* "/>" -- End of a solo tag */
	TOKEN_TEXT,
	TOKEN_EQ,
	TOKEN_EOF,
	TOKEN_SPACE,
} ExmlToken;

struct Exml;
typedef int (*ExmlHandler)(struct Exml *xp, int state, 
	const char *tagName, const char* attName, const char* value);
typedef int (*ExmlInputStream)(struct Exml *xp, void *arg, char *buf, int size);

/*
 *	Per XML session structure
 */ 
typedef struct Exml {
	ExmlHandler		handler;		/* Callback function */
	ExmlInputStream	readFn;			/* Read data function */
	MprBuf			*inBuf;			/* Input data queue */
	MprBuf			*tokBuf;		/* Parsed token buffer */
	int				quoteChar;		/* XdbAtt quote char */
	int				lineNumber;		/* Current line no for debug */
	void 			*parseArg;		/* Arg passed to exmlParse() */
	void 			*inputArg;		/* Arg passed to exmlSetInputStream() */
	char			*errMsg;		/* Error message text */
} Exml;

extern Exml			*exmlOpen(MprCtx ctx, int initialSize, int maxSize);
extern void			exmlClose(Exml *xp);
extern void 		exmlSetParserHandler(Exml *xp, ExmlHandler h);
extern void 		exmlSetInputStream(Exml *xp, ExmlInputStream s, void *arg);
extern int 			exmlParse(Exml *xp);
extern void			exmlSetParseArg(Exml *xp, void *parseArg);
extern void			*exmlGetParseArg(Exml *xp);
extern const char	*exmlGetErrorMsg(Exml *xp);
extern int			exmlGetLineNumber(Exml *xp);

/******************************************************************************/

#endif /* _h_EXML */
