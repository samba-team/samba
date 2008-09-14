/*
 *	@file 	ejsParser.c
 *	@brief 	EJS Parser and Execution 
 */
/********************************* Copyright **********************************/
/*
 *	@copy	default.g
 *	
 *	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
 *	Portions Copyright (c) GoAhead Software, 1995-2000. All Rights Reserved.
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

#include	"ejs.h"

#if BLD_FEATURE_EJS

/****************************** Forward Declarations **************************/

static int 		createClass(Ejs *ep, EjsVar *parentClass, 
					const char *className, EjsVar *baseClass);
static int 		createProperty(Ejs *ep, EjsVar **obj, const char *id, 
					int state);
static int		evalCond(Ejs *ep, EjsVar *lhs, int rel, EjsVar *rhs);
static int		evalExpr(Ejs *ep, EjsVar *lhs, int rel, EjsVar *rhs);
#if BLD_FEATURE_FLOATING_POINT
static int 		evalFloatExpr(Ejs *ep, double l, int rel, double r);
#endif 
static int 		evalBoolExpr(Ejs *ep, int l, int rel, int r);
static int 		evalNumericExpr(Ejs *ep, EjsNum l, int rel, EjsNum r);
static int 		evalObjExpr(Ejs *ep, EjsVar *lhs, int rel, EjsVar *rhs) ;
static int 		evalStringExpr(Ejs *ep, EjsVar *lhs, int rel, EjsVar *rhs);
static int		evalMethod(Ejs *ep, EjsVar *obj, EjsProc *proc, int flags);
static EjsProperty *findProperty(Ejs *ep, EjsVar *op, const char *property, 
					int flags);
static EjsVar 	*pickSpace(Ejs *ep, int state, const char *property, int flags);
static void		freeProc(Ejs *ep, EjsProc *proc);
static int		parseArgs(Ejs *ep, int state, int flags);
static int 		parseArrayLiteral(Ejs *ep, int state, int flags, char *id);
static int		parseAssignment(Ejs *ep, int state, int flags, char *id);
static int 		parseClass(Ejs *ep, int state, int flags);
static int 		parseForInner(Ejs *ep, int state, int flags, 
					EjsInput *condScript, EjsInput *incrScript, 
					EjsInput *bodyScript, EjsInput *endScript);
static int		parseCond(Ejs *ep, int state, int flags);
static int		parseDeclaration(Ejs *ep, int state, int flags);
static int		parseExpr(Ejs *ep, int state, int flags);
static int 		parseFor(Ejs *ep, int state, int flags);
static int 		parseRegFor(Ejs *ep, int state, int flags);
static int 		parseForIn(Ejs *ep, int state, int flags, int each);
static int 		parseId(Ejs *ep, int state, int flags, char **id, int *done);
static int 		parseInc(Ejs *ep, int state, int flags);
static int 		parseIf(Ejs *ep, int state, int flags, int *done);
static int		parseFunction(Ejs *ep, int state, int flags);
static int		parseMethod(Ejs *ep, int state, int flags, char *id);
static int 		parseObjectLiteral(Ejs *ep, int state, int flags, char *id);
static int		parseStmt(Ejs *ep, int state, int flags);
static int 		parseThrow(Ejs *ep, int state, int flags);
static int 		parseTry(Ejs *ep, int state, int flags);
static void 	removeNewlines(Ejs *ep, int state);
static EjsProperty *searchSpacesForProperty(Ejs *ep, int state, EjsVar *obj, 
					char *property, int flags);
static int 		assignPropertyValue(Ejs *ep, char *id, int state, EjsVar *value,
					int flags);
static int 		updateProperty(Ejs *ep, EjsVar *obj, const char *id, int state,
					EjsVar *value);
static void 	updateResult(Ejs *ep, int state, int flags, EjsVar *vp);
static int 		getNextNonSpaceToken(Ejs *ep, int state);

static int 		callConstructor(Ejs *ep, EjsVar *thisObj, EjsVar *baseClass, 
					MprArray *args);
static int 		callCMethod(Ejs *ep, EjsVar *obj, EjsProc *proc,
					EjsVar *prototype);
static int 		callStringCMethod(Ejs *ep, EjsVar *obj, EjsProc *proc,
					EjsVar *prototype);
static int 		callMethod(Ejs *ep, EjsVar *obj, EjsProc *proc,
					EjsVar *prototype);
static int 		runMethod(Ejs *ep, EjsVar *thisObj, EjsVar *method, 
					const char *methodName, MprArray *args);

static EjsInput *getInputStruct(Ejs *ep);
static void 	freeInputStruct(Ejs *ep, EjsInput *input);

static void 	*pushFrame(Ejs *ep, int size);
static void 	*popFrame(Ejs *ep, int size);

/************************************* Code ***********************************/
/*
 *	Recursive descent parser for EJS
 */

int ejsParse(Ejs *ep, int state, int flags)
{
	mprAssert(ep);

#if MOB
	if (mprStackCheck(ep)) {
		char	*stack;
		stack = ejsFormatStack(ep);
		mprLog(ep, 0, "\nStack grew : MAX %d\n", mprStackSize(ep));
		mprLog(ep, 0, "Stack\n %s\n", stack);
		mprFree(stack);
	}
#endif

	if (ep->flags & EJS_FLAGS_EXIT) {
		return EJS_STATE_RET;
	}

	ep->inputMarker = ep->input->scriptServp;

	switch (state) {
	/*
	 *	Any statement, method arguments or conditional expressions
	 */
	case EJS_STATE_STMT:
		state = parseStmt(ep, state, flags);
		if (state != EJS_STATE_STMT_BLOCK_DONE && state != EJS_STATE_STMT_DONE){
			goto err;
		}
		break;

	case EJS_STATE_DEC:
		state = parseStmt(ep, state, flags);
		if (state != EJS_STATE_DEC_DONE) {
			goto err;
		}
		break;

	case EJS_STATE_EXPR:
		state = parseStmt(ep, state, flags);
		if (state != EJS_STATE_EXPR_DONE) {
			goto err;
		}
		break;

	/*
	 *	Variable declaration list
	 */
	case EJS_STATE_DEC_LIST:
		state = parseDeclaration(ep, state, flags);
		if (state != EJS_STATE_DEC_LIST_DONE) {
			goto err;
		}
		break;

	/*
	 *	Method argument string
	 */
	case EJS_STATE_ARG_LIST:
		state = parseArgs(ep, state, flags);
		if (state != EJS_STATE_ARG_LIST_DONE) {
			goto err;
		}
		break;

	/*
	 *	Logical condition list (relational operations separated by &&, ||)
	 */
	case EJS_STATE_COND:
		state = parseCond(ep, state, flags);
		if (state != EJS_STATE_COND_DONE) {
			goto err;
		}
		break;

	/*
	 *	Expression list
	 */
	case EJS_STATE_RELEXP:
		state = parseExpr(ep, state, flags);
		if (state != EJS_STATE_RELEXP_DONE) {
			goto err;
		}
		break;
	}

	/*
 	 *	Recursion protection
	 */
	if (ep->input->scriptServp == ep->inputMarker) {
		if (ep->recurseCount++ > 20) {
			ejsSyntaxError(ep, "Input syntax error");
			state = EJS_STATE_ERR;
		}
	} else {
		ep->recurseCount = 0;
	}

	if (state == EJS_STATE_RET || state == EJS_STATE_EOF) {
		return state;
	}

done:
	return state;

err:
	if (state == EJS_STATE_RET || state == EJS_STATE_EOF) {
		goto done;
	}
	if (state != EJS_STATE_ERR) {
		ejsSyntaxError(ep, 0);
	}
	state = EJS_STATE_ERR;
	goto done;
}

/******************************************************************************/
/*
 *	Local vars 
 */

typedef struct ParseStmt {
	EjsProc		*saveProc;
	EjsProperty	*pp;
	EjsVar		*saveObj, *exception;
	char		*str, *id;
	int			done, tid, rs, saveObjPerm, expectEndOfStmt;
} ParseStmt;

/*
 *	Parse expression (leftHandSide operator rightHandSide)
 */


static int parseStmt(Ejs *ep, int state, int flags)
{
	ParseStmt		*sp;

	mprAssert(ep);

	if ((sp = pushFrame(ep, sizeof(ParseStmt))) == 0) {
		return EJS_STATE_ERR;
	}

	sp->id = 0;
	sp->expectEndOfStmt = 0;
	sp->saveProc = NULL;

	ep->currentObj = 0;
	ep->currentProperty = 0;

	for (sp->done = 0; !sp->done && state != EJS_STATE_ERR; ) {
		sp->tid = ejsLexGetToken(ep, state);

#if (WIN || BREW_SIMULATOR) && BLD_DEBUG && DISABLED
		/* MOB -- make cross platform */
		_CrtCheckMemory();
#endif

		switch (sp->tid) {
		default:
			ejsLexPutbackToken(ep, sp->tid, ep->token);
			goto done;

		case EJS_TOK_EXPR:
			if (state == EJS_STATE_EXPR) {
				ejsLexPutbackToken(ep, EJS_TOK_EXPR, ep->token);
			}
			goto done;

		case EJS_TOK_LOGICAL:
			ejsLexPutbackToken(ep, sp->tid, ep->token);
			goto done;

		case EJS_TOK_ERR:
			if (state != EJS_STATE_ERR && !ep->gotException) {
				ejsSyntaxError(ep, 0);
			}
			state = EJS_STATE_ERR;
			goto done;

		case EJS_TOK_EOF:
			state = EJS_STATE_EOF;
			goto done;

		case EJS_TOK_NEWLINE:
			break;

		case EJS_TOK_SEMI:
			/*
			 *	This case is when we discover no statement and just a lone ';'
			 */
			if (state != EJS_STATE_STMT) {
				ejsLexPutbackToken(ep, sp->tid, ep->token);
			}
			goto done;

		case EJS_TOK_LBRACKET:
			if (flags & EJS_FLAGS_EXE) {
				ep->currentObj = &ep->currentProperty->var;
				if (ep->currentObj != 0 && ep->currentObj->type != 
						EJS_TYPE_OBJECT) {
					ejsError(ep, EJS_REFERENCE_ERROR,
						"Property reference to a non-object type \"%s\"\n", 
						sp->id);
					goto err;
				}
			}

			sp->saveObj = ep->currentObj;
			sp->saveObjPerm = ejsMakeObjPermanent(sp->saveObj, 1);

			sp->rs = ejsParse(ep, EJS_STATE_RELEXP, flags);

			ejsMakeObjPermanent(sp->saveObj, sp->saveObjPerm);
			ep->currentObj = sp->saveObj;

			if (sp->rs < 0) {
				state = sp->rs;
				goto done;
			}

			mprFree(sp->id);
			/* MOB rc */
			sp->str = ejsVarToString(ep, ep->result);
			sp->id = mprStrdup(ep, sp->str);

			if (sp->id[0] == '\0') {
				if (flags & EJS_FLAGS_EXE) {
					ejsError(ep, EJS_RANGE_ERROR,
						"[] expression evaluates to the empty string\n");
					goto err;
				}
			} else {
				sp->pp = searchSpacesForProperty(ep, state, ep->currentObj, 
					sp->id, flags);
				ep->currentProperty = sp->pp;
				updateResult(ep, state, flags, ejsGetVarPtr(sp->pp));
			}

			if ((sp->tid = ejsLexGetToken(ep, state)) != EJS_TOK_RBRACKET) {
				ejsSyntaxError(ep, "Missing ']'");
				goto err;
			}
			break;

		case EJS_TOK_PERIOD:
			if (flags & EJS_FLAGS_EXE) {
				if (ep->currentProperty == 0) {
					ejsError(ep, EJS_REFERENCE_ERROR,
						"Undefined object \"%s\"", sp->id);
					goto err;
				}
			}
			ep->currentObj = &ep->currentProperty->var;
			if (flags & EJS_FLAGS_EXE) {
				if (ep->currentObj != 0 && ep->currentObj->type != 
						EJS_TYPE_OBJECT) {
					ejsError(ep, EJS_REFERENCE_ERROR,
						"Property reference to a non-object type \"%s\"\n",
						sp->id);
					goto err;
				}
			}
			if ((sp->tid = ejsLexGetToken(ep, state)) != EJS_TOK_ID) {
				ejsError(ep, EJS_REFERENCE_ERROR, "Bad property after '.': %s", 
					ep->token);
				goto err;
			}
			/* Fall through */

		case EJS_TOK_ID:
			state = parseId(ep, state, flags, &sp->id, &sp->done);
			if (sp->done && state == EJS_STATE_STMT) {
				sp->expectEndOfStmt = 1;
			}
			break;

		case EJS_TOK_ASSIGNMENT:
			sp->tid = ejsLexGetToken(ep, state);
			if (sp->tid == EJS_TOK_LBRACE) {
				/* 
				 *	var = { name: value, name: value, ... } 
				 */
				if (parseObjectLiteral(ep, state, flags, sp->id) < 0) {
					ejsSyntaxError(ep, "Bad object literal");
					goto err;
				}

			} else if (sp->tid == EJS_TOK_LBRACKET) {
				/* 
				 *	var = [ array elements ] 
				 */
				if (parseArrayLiteral(ep, state, flags, sp->id) < 0) {
					ejsSyntaxError(ep, "Bad array literal");
					goto err;
				}

			} else if (sp->tid == EJS_TOK_EXPR && 
					(int) *ep->token == EJS_EXPR_LESS) {
				/* 
				 *	var = <xmlTag> .../</xmlTag>
				 */
				ejsSyntaxError(ep, "XML literals are not yet supported");
				goto err;

			} else {
				/* 
				 *	var = expression
				 */
				ejsLexPutbackToken(ep, sp->tid, ep->token);
				state = parseAssignment(ep, state, flags, sp->id);
				if (state == EJS_STATE_ERR) {
					if (ep->flags & EJS_FLAGS_EXIT) {
						state = EJS_STATE_RET;
						goto done;
					}
					if (!ep->gotException) {
						ejsSyntaxError(ep, 0);
					}
					goto err;
				}
			}

			if (flags & EJS_FLAGS_EXE) {
				if (assignPropertyValue(ep, sp->id, state, ep->result, 
							flags) < 0) {
					if (ep->gotException == 0) {
						ejsError(ep, EJS_EVAL_ERROR, "Can't set property %s", 
							sp->id);
					}
					goto err;
				}
			}

			if (state == EJS_STATE_STMT) {
				sp->expectEndOfStmt = 1;
				goto done;
			}
			break;

		case EJS_TOK_INC_DEC:
			state = parseInc(ep, state, flags);
			if (state == EJS_STATE_STMT) {
				sp->expectEndOfStmt = 1;
			}
			break;

		case EJS_TOK_NEW:
			/* MOB -- could we remove rs and just use state */
			sp->rs = ejsParse(ep, EJS_STATE_EXPR, flags | EJS_FLAGS_NEW);
			if (sp->rs < 0) {
				state = sp->rs;
				goto done;
			}
			break;

		case EJS_TOK_DELETE:
			sp->rs = ejsParse(ep, EJS_STATE_EXPR, flags | EJS_FLAGS_DELETE);
			if (sp->rs < 0) {
				state = sp->rs;
				goto done;
			}
			if (flags & EJS_FLAGS_EXE) {
				/* Single place where properties are deleted */
				if (ep->currentObj == 0 || ep->currentProperty == 0) {
					ejsError(ep, EJS_EVAL_ERROR, 
						"Can't find property to delete"); 
					goto err;
				}
				if (ep->currentObj->isArray) {
					ejsSetArrayLength(ep, ep->currentObj, 0, 
						ep->currentProperty->name, 0);
				}
				ejsDeleteProperty(ep, ep->currentObj, 
					ep->currentProperty->name);
				ep->currentProperty = 0;
			}
			goto done;

		case EJS_TOK_FUNCTION:
			/*
			 *	Parse a function declaration 
			 */
			state = parseFunction(ep, state, flags);
			goto done;

		case EJS_TOK_THROW:
			state = parseThrow(ep, state, flags);
			goto done;

		case EJS_TOK_TRY:
			state = parseTry(ep, state, flags);
			goto done;

		case EJS_TOK_CLASS:
		case EJS_TOK_MODULE:
			state = parseClass(ep, state, flags);
			goto done;

		case EJS_TOK_LITERAL:
			/*
			 *	Set the result to the string literal 
			 */
			if (flags & EJS_FLAGS_EXE) {
				ejsWriteVarAsString(ep, ep->result, ep->token);
				ejsSetVarName(ep, ep->result, "");
			}
			if (state == EJS_STATE_STMT) {
				sp->expectEndOfStmt = 1;
			}
			goto done;

		case EJS_TOK_NUMBER:
			/*
			 *	Set the result to the parsed number
			 */
			if (flags & EJS_FLAGS_EXE) {
				ejsWriteVar(ep, ep->result, &ep->tokenNumber, 0);
			}
			if (state == EJS_STATE_STMT) {
				sp->expectEndOfStmt = 1;
			}
			goto done;

		case EJS_TOK_METHOD_NAME:
			/*
			 *	parse a method() invocation
			 */
			mprAssert(ep->currentObj);
			state = parseMethod(ep, state, flags, sp->id);
			if (state == EJS_STATE_STMT) {
				sp->expectEndOfStmt = 1;
			}
			if (ep->flags & EJS_FLAGS_EXIT) {
				state = EJS_STATE_RET;
			}
			goto done;

		case EJS_TOK_IF:
			state = parseIf(ep, state, flags, &sp->done);
			if (state < 0) {
				goto done;
			}
			break;

		case EJS_TOK_FOR:
			state = parseFor(ep, state, flags);
			goto done;

		case EJS_TOK_VAR:
			if ((sp->rs = ejsParse(ep, EJS_STATE_DEC_LIST, flags)) < 0) {
				state = sp->rs;
				goto done;
			}
			goto done;

		case EJS_TOK_COMMA:
			ejsLexPutbackToken(ep, sp->tid, ep->token);
			goto done;

		case EJS_TOK_LPAREN:
			if (state == EJS_STATE_EXPR) {
				if ((sp->rs = ejsParse(ep, EJS_STATE_RELEXP, flags)) < 0) {
					state = sp->rs;
					goto done;
				}
				if (ejsLexGetToken(ep, state) != EJS_TOK_RPAREN) {
					ejsSyntaxError(ep, 0);
					goto err;
				}
				goto done;

			} else if (state == EJS_STATE_STMT) {
				ejsLexPutbackToken(ep, EJS_TOK_METHOD_NAME, ep->token);
			}
			break;

		case EJS_TOK_RPAREN:
			ejsLexPutbackToken(ep, sp->tid, ep->token);
			goto done;

		case EJS_TOK_EXTENDS:
			if (! (flags & EJS_FLAGS_CLASS_DEC)) {
				ejsSyntaxError(ep, 0);
				goto err;
			}
			sp->saveObj = ep->currentObj;
			sp->saveObjPerm = ejsMakeObjPermanent(sp->saveObj, 1);
			
			sp->rs = ejsParse(ep, EJS_STATE_STMT, flags);
			ejsMakeObjPermanent(sp->saveObj, sp->saveObjPerm);

			if (sp->rs < 0) {
				state = sp->rs;
				goto done;
			}

			if (flags & EJS_FLAGS_EXE) {
				if (createClass(ep, sp->saveObj, sp->id, 
						ejsGetVarPtr(ep->currentProperty)) < 0) {
					goto err;
				}
			}
			if (ejsLexGetToken(ep, state) != EJS_TOK_LBRACE) {
				ejsSyntaxError(ep, 0);
				goto err;
			}
			ejsLexPutbackToken(ep, ep->tid, ep->token);
			goto done;

		case EJS_TOK_LBRACE:
			if (flags & EJS_FLAGS_CLASS_DEC) {
				if (state == EJS_STATE_DEC) {
					if (flags & EJS_FLAGS_EXE) {
						if (createClass(ep, ep->currentObj, sp->id, 0) < 0) {
							goto err;
						}
					}
					ejsLexPutbackToken(ep, sp->tid, ep->token);

				} else if (state == EJS_STATE_STMT) {
					ejsLexPutbackToken(ep, sp->tid, ep->token);
				}
				goto done;
			}

			/*
			 *	This handles any code in braces except "if () {} else {}"
			 */
			if (state != EJS_STATE_STMT) {
				ejsSyntaxError(ep, 0);
				goto err;
			}

			/*
			 *	Parse will return EJS_STATE_STMT_BLOCK_DONE when the RBRACE 
			 *	is seen.
			 */
			sp->exception = 0;
			do {
				state = ejsParse(ep, EJS_STATE_STMT, flags);
				if (state == EJS_STATE_ERR) {
					/*
					 *	We need to keep parsing to get to the end of the block
					 */
					if (sp->exception == 0) {
						sp->exception = ejsDupVar(ep, ep->result, 
								EJS_SHALLOW_COPY);
						if (sp->exception == 0) {
							ejsMemoryError(ep);
							goto err;
						}
						if (sp->exception->type == EJS_TYPE_OBJECT) {
							ejsMakeObjLive(sp->exception, 0);
							mprAssert(sp->exception->objectState->alive == 0);
						}

						/*
						 *	If we're in a try block, we need to keep parsing
						 *	so we can find the end of the block and the start
						 *	of the catch block. Otherwise, we are done.
						 */
						if (!(flags & EJS_FLAGS_TRY)) {
							break;
						}
					}
					flags &= ~EJS_FLAGS_EXE;
					if (ep->recurseCount > 20) {
						break;
					}
					state = EJS_STATE_STMT_DONE;
					ep->gotException = 0;
				}

			} while (state == EJS_STATE_STMT_DONE);

			if (sp->exception) {
				ep->gotException = 1;
				ejsWriteVar(ep, ep->result, sp->exception, EJS_SHALLOW_COPY);

				/* Eat the closing brace */
				ejsLexGetToken(ep, state);
				ejsFreeVar(ep, sp->exception);

				goto err;
			}
			ejsFreeVar(ep, sp->exception);

			if (state < 0) {
				goto done;
			}

			if (ejsLexGetToken(ep, state) != EJS_TOK_RBRACE) {
				ejsSyntaxError(ep, 0);
				goto err;
			}
			state = EJS_STATE_STMT_DONE;
			goto done;

		case EJS_TOK_RBRACE:
			if (state == EJS_STATE_STMT) {
				ejsLexPutbackToken(ep, sp->tid, ep->token);
				state = EJS_STATE_STMT_BLOCK_DONE;
				
			} else if (state == EJS_STATE_EXPR) {
				ejsLexPutbackToken(ep, sp->tid, ep->token);
				state = EJS_STATE_EXPR;

			} else {
				ejsSyntaxError(ep, 0);
				state = EJS_STATE_ERR;
			}
			goto done;

		case EJS_TOK_RETURN:
			if ((sp->rs = ejsParse(ep, EJS_STATE_RELEXP, flags)) < 0) {
				state = sp->rs;
				goto done;
			}
			if (flags & EJS_FLAGS_EXE) {
				state = EJS_STATE_RET;
				goto done;
			}
			break;
		}
	}
done:
	mprFree(sp->id);

	if (sp->expectEndOfStmt && state >= 0) {
		sp->tid = ejsLexGetToken(ep, state);
		if (sp->tid == EJS_TOK_RBRACE) {
			ejsLexPutbackToken(ep, EJS_TOK_RBRACE, ep->token);

		} else if (sp->tid != EJS_TOK_SEMI && sp->tid != EJS_TOK_NEWLINE && 
				sp->tid != EJS_TOK_EOF) {
			ejsSyntaxError(ep, 0);
			state = EJS_STATE_ERR;

		} else {
			/*
			 *	Skip newlines after semi-colon
			 */
			removeNewlines(ep, state);
		}
	}

	/*
	 *	Advance the state
	 */
	switch (state) {
	case EJS_STATE_STMT:
	case EJS_STATE_STMT_DONE:
		state = EJS_STATE_STMT_DONE;
		break;

	case EJS_STATE_DEC:
	case EJS_STATE_DEC_DONE:
		state = EJS_STATE_DEC_DONE;
		break;

	case EJS_STATE_EXPR:
	case EJS_STATE_EXPR_DONE:
		state = EJS_STATE_EXPR_DONE;
		break;

	case EJS_STATE_STMT_BLOCK_DONE:
	case EJS_STATE_EOF:
	case EJS_STATE_RET:
		break;

	default:
		if (state != EJS_STATE_ERR) {
			ejsSyntaxError(ep, 0);
		}
		state = EJS_STATE_ERR;
	}
	popFrame(ep, sizeof(ParseStmt));
	return state;

err:
	state = EJS_STATE_ERR;
	goto done;
}

/******************************************************************************/
/*
 *	Local vars 
 */

typedef struct ParseFor {
	char		*initToken;
	int 		tid, foundVar, initId, each;
} ParseFor;

/*
 *	Parse method arguments
 */

static int parseFor(Ejs *ep, int state, int flags)
{
	ParseFor		*sp;

	if ((sp = pushFrame(ep, sizeof(ParseFor))) == 0) {
		return EJS_STATE_ERR;
	}

	mprAssert(ep);

	if (state != EJS_STATE_STMT) {
		ejsSyntaxError(ep, 0);
		goto err;
	}

	if ((sp->tid = ejsLexGetToken(ep, state)) == EJS_TOK_EACH) {
		sp->each = 1;
		sp->tid = ejsLexGetToken(ep, state);

	} else {
		sp->each = 0;
	}

	if (sp->tid != EJS_TOK_LPAREN) {
		ejsSyntaxError(ep, 0);
		goto err;
	}

	/*
	 *	Need to peek 2-3 tokens ahead and see if this is a 
	 *		for [each] ([var] x in set) 
	 *	or
	 *		for (init ; whileCond; incr)
	 */
	sp->initId = ejsLexGetToken(ep, EJS_STATE_EXPR);
	sp->foundVar = 0;
	if (sp->initId == EJS_TOK_ID && strcmp(ep->token, "var") == 0) {
		sp->foundVar = 1;
		sp->initId = ejsLexGetToken(ep, EJS_STATE_EXPR);
	}
	sp->initToken = mprStrdup(ep, ep->token);

	sp->tid = ejsLexGetToken(ep, EJS_STATE_EXPR);

	ejsLexPutbackToken(ep, sp->tid, ep->token);
	ejsLexPutbackToken(ep, sp->initId, sp->initToken);
	mprFree(sp->initToken);

	if (sp->foundVar) {
		ejsLexPutbackToken(ep, EJS_TOK_ID, "var");
	}

	if (sp->tid == EJS_TOK_IN) {
		state = parseForIn(ep, state, flags, sp->each);

	} else {
		state = parseRegFor(ep, state, flags);
	}

done:
	popFrame(ep, sizeof(ParseFor));
	return state;

err:
	state = EJS_STATE_ERR;
	goto done;
}

/******************************************************************************/
/*
 *	Parse method arguments
 */

static int parseArgs(Ejs *ep, int state, int flags)
{
	EjsVar		*vp;
	int			tid;

	mprAssert(ep);

	do {
		/*
		 *	Peek and see if there are no args
		 */
		tid = ejsLexGetToken(ep, state);
		ejsLexPutbackToken(ep, tid, ep->token);
		if (tid == EJS_TOK_RPAREN) {
			break;
		}

		/*
		 *	If this is part of a constructor, must run methods in args normally 
 		 */
		flags &= ~EJS_FLAGS_NEW;

		state = ejsParse(ep, EJS_STATE_RELEXP, flags);
		if (state < 0) {
			return state;
		}
		if (flags & EJS_FLAGS_EXE) {
			mprAssert(ep->proc->args);
			vp = ejsDupVar(ep, ep->result, EJS_SHALLOW_COPY);
			if (vp == 0) {
				ejsMemoryError(ep);
				return EJS_STATE_ERR;
			}
			/* MOB */
			if (vp->type == EJS_TYPE_OBJECT) {
				ejsMakeObjLive(vp, 0);
				mprAssert(vp->objectState->alive == 0);
			}

			/*
			 *	Propagate the name
			 */
			ejsSetVarName(ep, vp, ep->result->propertyName);

			mprAddItem(ep->proc->args, vp);

		}
		/*
		 *	Peek at the next token, continue if more args (ie. comma seen)
		 */
		tid = ejsLexGetToken(ep, state);
		if (tid != EJS_TOK_COMMA) {
			ejsLexPutbackToken(ep, tid, ep->token);
		}
	} while (tid == EJS_TOK_COMMA);

	if (tid != EJS_TOK_RPAREN && state != EJS_STATE_RELEXP_DONE) {
		ejsSyntaxError(ep, 0);
		return EJS_STATE_ERR;
	}
	return EJS_STATE_ARG_LIST_DONE;
}

/******************************************************************************/
/*
 *	Local vars 
 */

typedef struct ParseAssign {
	EjsProperty		*saveProperty;
	EjsVar			*saveObj;
	int				saveObjPerm, savePropPerm, rc;
} ParseAssign;

/*
 *	Parse an assignment statement
 */

static int parseAssignment(Ejs *ep, int state, int flags, char *id)
{
	ParseAssign		*sp;


	if (id == 0) {
		if (!ep->gotException) {
			ejsSyntaxError(ep, 0);
		}
		return EJS_STATE_ERR;
	}

	if ((sp = pushFrame(ep, sizeof(ParseAssign))) == 0) {
		return EJS_STATE_ERR;
	}

	mprAssert(ep->currentObj);

	/*
	 *	Parse the right hand side of the "="
	 */
	sp->saveObj = ep->currentObj;
	sp->saveProperty = ep->currentProperty;

	sp->saveObjPerm = ejsMakeObjPermanent(sp->saveObj, 1);
	sp->savePropPerm = ejsMakeObjPermanent(ejsGetVarPtr(sp->saveProperty), 1);

	sp->rc = ejsParse(ep, EJS_STATE_RELEXP, flags | EJS_FLAGS_ASSIGNMENT);
	
	ejsMakeObjPermanent(sp->saveObj, sp->saveObjPerm);
	ejsMakeObjPermanent(ejsGetVarPtr(sp->saveProperty), sp->savePropPerm);

	if (sp->rc < 0) {
		state = EJS_STATE_ERR;
	}

	ep->currentObj = sp->saveObj;
	ep->currentProperty = sp->saveProperty;

	popFrame(ep, sizeof(ParseAssign));

	if (! (flags & EJS_FLAGS_EXE)) {
		return state;
	}

	return state;
}

/******************************************************************************/

static int assignPropertyValue(Ejs *ep, char *id, int state, EjsVar *value, 
	int flags)
{
	EjsProperty		*saveProperty;
	EjsVar			*saveObj, *obj, *vp;
	char			*procName;
	int				saveObjPerm, savePropPerm, rc;

	mprAssert(flags & EJS_FLAGS_EXE);

	if (ep->currentProperty && 
			!ep->currentProperty->var.flags & EJS_GET_ACCESSOR) {
		obj = ep->currentObj;

	} else {
		/*
		 *	Handle any set accessors.
		 *	FUTURE OPT -- could be faster
		 * 	FUTURE OPT -- coming here even when doing just a set "x = value";
		 */
		procName = 0;
		if (mprAllocStrcat(MPR_LOC_ARGS(ep), &procName, EJS_MAX_ID + 5, 0, 
				"-set-", id, 0) > 0) {

			MprArray	*args;

			ep->currentProperty = searchSpacesForProperty(ep, state, 
				ep->currentObj, procName, flags);

			if (ep->currentProperty) {
				args = mprCreateItemArray(ep, EJS_INC_ARGS, EJS_MAX_ARGS);

				vp = ejsDupVar(ep, value, EJS_SHALLOW_COPY);
				mprAddItem(args, vp);
				mprAssert(! ejsObjIsCollectable(vp));

				saveObj = ep->currentObj;
				saveProperty = ep->currentProperty;

				saveObjPerm = ejsMakeObjPermanent(saveObj, 1);
				savePropPerm = ejsMakeObjPermanent(ejsGetVarPtr(saveProperty), 
					1);

				/*
				 *	Invoke the set accessor
			 	 */
				rc = ejsRunMethod(ep, ep->currentObj, procName, args);
				mprFree(procName);
				ejsFreeMethodArgs(ep, args);

				ejsMakeObjPermanent(saveObj, saveObjPerm);
				ejsMakeObjPermanent(ejsGetVarPtr(saveProperty), savePropPerm);

				ep->currentObj = saveObj;
				ep->currentProperty = saveProperty;

				if (rc < 0) {
					return EJS_STATE_ERR;
				}
				return state;
			}
			mprFree(procName);
		}

		if (ep->currentProperty == 0) {
			/*
			 *	MOB -- can we omit this as updateProperty below will create
			 */
			if (createProperty(ep, &obj, id, state) < 0) {
				return EJS_STATE_ERR;
			}
		}
	}

	if (updateProperty(ep, obj, id, state, value) < 0) {
		return EJS_STATE_ERR;
	}

	vp = ejsGetVarPtr(ep->currentProperty);
	if (vp->type == EJS_TYPE_OBJECT) {
		ejsMakeObjLive(vp, 1);
	}

	return state;
}

/******************************************************************************/

static int parseObjectLiteral(Ejs *ep, int state, int flags, char *id)
{
	EjsProperty		*saveProperty;
	EjsVar			*saveObj;
	EjsVar			*obj;
	char			*name;
	int				saveObjPerm, savePropPerm, tid;

	name = 0;

	saveObj = ep->currentObj;
	saveProperty = ep->currentProperty;

	saveObjPerm = ejsMakeObjPermanent(saveObj, 1);
	savePropPerm = ejsMakeObjPermanent(ejsGetVarPtr(saveProperty), 1);

	if (flags & EJS_FLAGS_EXE) {
		obj = ejsCreateSimpleObj(ep, "Object");
		if (obj == 0) {
			ejsMemoryError(ep);
			goto err;
		}
		mprAssert(! ejsObjIsCollectable(obj));

	} else {
		obj = 0;
	}

	do {
		tid = getNextNonSpaceToken(ep, state);
		if (tid != EJS_TOK_ID) {
			ejsSyntaxError(ep, 0);
			goto err;
		}
		name = mprStrdup(ep, ep->token);

		tid = getNextNonSpaceToken(ep, state);
		if (tid != EJS_TOK_COLON) {
			ejsSyntaxError(ep, 0);
			goto err;
		}

		if (flags & EJS_FLAGS_EXE) {
			/* FUTURE OPT -- can we optimize this. We are double accessing id 
				with the Put below. Should we be using this or ejsSetProperty
			 */
			if (ejsCreatePropertyMethod(ep, obj, name) == 0) {
				ejsMemoryError(ep);
				goto err;
			}
		}

		if (ejsParse(ep, EJS_STATE_RELEXP, flags) < 0) {
			goto err;
		}
		if (flags & EJS_FLAGS_EXE) {
			if (ejsSetPropertyMethod(ep, obj, name, ep->result) == 0) {
				ejsMemoryError(ep);
				goto err;
			}
		}
		mprFree(name);
		name = 0;

		tid = getNextNonSpaceToken(ep, state);

	} while (tid == EJS_TOK_COMMA);

	if (tid != EJS_TOK_RBRACE) {
		ejsSyntaxError(ep, 0);
		goto err;
	}

	if (flags & EJS_FLAGS_EXE) {
		ejsMakeObjLive(obj, 1);
		ejsWriteVar(ep, ep->result, obj, EJS_SHALLOW_COPY);
	}

done:
	ejsMakeObjPermanent(saveObj, saveObjPerm);
	ejsMakeObjPermanent(ejsGetVarPtr(saveProperty), savePropPerm);

	ep->currentObj = saveObj;
	ep->currentProperty = saveProperty;

	if (obj) {
		ejsFreeVar(ep, obj);
	}
	return state;

err:
	mprFree(name);
	state = EJS_STATE_ERR;
	goto done;
}

/******************************************************************************/

static int parseArrayLiteral(Ejs *ep, int state, int flags, char *id)
{
	EjsProperty		*saveProperty;
	EjsVar			*saveObj;
	EjsVar			*obj;
	int				saveObjPerm, savePropPerm, tid;

	saveObj = ep->currentObj;
	saveProperty = ep->currentProperty;

	saveObjPerm = ejsMakeObjPermanent(saveObj, 1);
	savePropPerm = ejsMakeObjPermanent(ejsGetVarPtr(saveProperty), 1);

	if (flags & EJS_FLAGS_EXE) {
		obj = ejsCreateArray(ep, 0);
		if (obj == 0) {
			ejsMemoryError(ep);
			goto err;
		}
		mprAssert(! ejsObjIsCollectable(obj));

	} else {
		obj = 0;
	}

	do {
		if (ejsParse(ep, EJS_STATE_RELEXP, flags) < 0) {
			goto err;
		}
		if (flags & EJS_FLAGS_EXE) {
			/* MOB _- should this be put[array.length] */
			if (ejsAddArrayElt(ep, obj, ep->result, EJS_SHALLOW_COPY) == 0) {
				goto err;
			}
		}

		tid = getNextNonSpaceToken(ep, state);

	} while (tid == EJS_TOK_COMMA);

	if (tid != EJS_TOK_RBRACKET) {
		ejsSyntaxError(ep, "Missing right bracket");
		goto err;
	}

	if (flags & EJS_FLAGS_EXE) {
		ejsMakeObjLive(obj, 1);
		ejsWriteVar(ep, ep->result, obj, EJS_SHALLOW_COPY);
	}

done:
	ejsMakeObjPermanent(saveObj, saveObjPerm);
	ejsMakeObjPermanent(ejsGetVarPtr(saveProperty), savePropPerm);

	ep->currentObj = saveObj;
	ep->currentProperty = saveProperty;

	ejsFreeVar(ep, obj);
	return state;

err:
	state = EJS_STATE_ERR;
	goto done;
}

/******************************************************************************/
/*
 *	Create a property. 
 */

/*
MOB -- simplify this. Enforce ep->currentObj to be always set.
Then we can delete this and just call 

	ejsCreatePropertyMethod(ep->currentObj, id);
*/
//XX
static int createProperty(Ejs *ep, EjsVar **objp, const char *id, int state)
{
	EjsVar	*obj, *vp;

	mprAssert(id && *id);
	mprAssert(objp);

	/*
	 *	Determine the variable scope to use for the property.
	 *	Standard says: "var x" means declare locally.
	 *	"x = 2" means declare globally if x is undefined.
	 */
	if (ep->currentObj) {
		if (ep->currentObj->type != EJS_TYPE_OBJECT) {
			ejsSyntaxError(ep, "Reference is not an object");
			return EJS_STATE_ERR;
		}
		obj = ep->currentObj;

	} else {
		/* MOB -- we should never be doing this here. ep->currentObj should
			always be set already */
		obj = (state == EJS_STATE_DEC) ? ep->local : ep->global;
	}
	mprAssert(obj);

	vp = ejsCreatePropertyMethod(ep, obj, id);
	if (vp == 0) {
		if (!ep->gotException) {
			ejsMemoryError(ep);
		}
		return EJS_STATE_ERR;
	}

	*objp = obj;
	return state;
}

/******************************************************************************/
/*
 *	Update a property. 
 *
 *	Return with ep->currentProperty updated to point to the property.
 */

static int updateProperty(Ejs *ep, EjsVar *obj, const char *id, int state,
	EjsVar *value)
{
	EjsVar	*vp;

	/* 
 	 *	MOB -- do ready-only check here
	 */
	vp = ejsSetPropertyMethod(ep, obj, id, value);
	if (vp == 0) {
		ejsMemoryError(ep);
		return EJS_STATE_ERR;
	}
	ep->currentProperty = ejsGetPropertyPtr(vp);

	obj->objectState->dirty = 1;

	return state;
}

/******************************************************************************/
/*
 *	Local vars 
 */

typedef struct ParseCond {
	EjsVar		lhs, rhs;
	int			tid, operator;
} ParseCond;

/*
 *	Parse conditional expression (relational ops separated by ||, &&)
 */

static int parseCond(Ejs *ep, int state, int flags)
{
	ParseCond		*sp;

	if ((sp = pushFrame(ep, sizeof(ParseCond))) == 0) {
		return EJS_STATE_ERR;
	}

	mprAssert(ep);

	if (flags & EJS_FLAGS_EXE) {
		ejsClearVar(ep, ep->result);
	}

	sp->lhs.type = sp->rhs.type = EJS_TYPE_UNDEFINED;
	sp->lhs.objectState = sp->rhs.objectState = 0;
	sp->lhs.allocatedData = sp->rhs.allocatedData = 0;

	ejsSetVarName(ep, &sp->lhs, "lhs");
	ejsSetVarName(ep, &sp->rhs, "rhs");

	sp->operator = 0;

	do {
		/*
		 *	Recurse to handle one side of a conditional. Accumulate the
		 *	left hand side and the final result in ep->result.
		 */
		state = ejsParse(ep, EJS_STATE_RELEXP, flags);
		if (state < 0) {
			break;
		}

		if (flags & EJS_FLAGS_EXE) {
			if (sp->operator > 0) {
				/*
				 * 	FUTURE -- does not do precedence
				 */ 
				ejsWriteVar(ep, &sp->rhs, ep->result, EJS_SHALLOW_COPY);
				if (evalCond(ep, &sp->lhs, sp->operator, &sp->rhs) < 0) {
					state = EJS_STATE_ERR;
					break;
				}
				/* Result left in ep->result */
				/* MOB */
				if (sp->lhs.type == EJS_TYPE_OBJECT) {
					mprAssert(sp->lhs.objectState->alive == 0);
				}
				if (sp->rhs.type == EJS_TYPE_OBJECT) {
					mprAssert(sp->rhs.objectState->alive == 0);
				}
			}
		}

		sp->tid = ejsLexGetToken(ep, state);
		if (sp->tid == EJS_TOK_LOGICAL) {
			sp->operator = (int) *ep->token;

		} else if (sp->tid == EJS_TOK_RPAREN || sp->tid == EJS_TOK_SEMI) {
			ejsLexPutbackToken(ep, sp->tid, ep->token);
			state = EJS_STATE_COND_DONE;
			break;

		} else {
			ejsLexPutbackToken(ep, sp->tid, ep->token);
		}

		if (flags & EJS_FLAGS_EXE) {
			ejsWriteVar(ep, &sp->lhs, ep->result, EJS_SHALLOW_COPY);
		}

	} while (state == EJS_STATE_RELEXP_DONE);

	ejsClearVar(ep, &sp->lhs);
	ejsClearVar(ep, &sp->rhs);

	popFrame(ep, sizeof(ParseCond));

	return state;
}

/******************************************************************************/
/*
 *	Parse variable declaration list. Declarations can be of the following forms:
 *		var x;
 *		var x, y, z;
 *		var x = 1 + 2 / 3, y = 2 + 4;
 *		var x = { property: value, property: value ... };
 *		var x = [ property: value, property: value ... ];
 *
 *	We set the variable to NULL if there is no associated assignment.
 */

static int parseDeclaration(Ejs *ep, int state, int flags)
{
	int		tid;

	mprAssert(ep);

	do {
		if ((tid = ejsLexGetToken(ep, state)) != EJS_TOK_ID) {
			ejsSyntaxError(ep, 0);
			return EJS_STATE_ERR;
		}
		ejsLexPutbackToken(ep, tid, ep->token);

		/*
		 *	Parse the entire assignment or simple identifier declaration
		 */
		if (ejsParse(ep, EJS_STATE_DEC, flags) != EJS_STATE_DEC_DONE) {
			return EJS_STATE_ERR;
		}

		/*
		 *	Peek at the next token, continue if comma seen
		 *	Stop on ";" or "in" which is used in a "for (var x in ..."
		 */
		tid = ejsLexGetToken(ep, state);

		if (tid == EJS_TOK_SEMI) {
			return EJS_STATE_DEC_LIST_DONE;

		} else if (tid == EJS_TOK_IN) {
			ejsLexPutbackToken(ep, tid, ep->token);
			return EJS_STATE_DEC_LIST_DONE;

		} else if (flags & EJS_FLAGS_CLASS_DEC && 
				(tid == EJS_TOK_LBRACE || tid == EJS_TOK_EXTENDS)) {
			ejsLexPutbackToken(ep, tid, ep->token);
			return EJS_STATE_DEC_LIST_DONE;

		} else if (tid == EJS_TOK_RPAREN && flags & EJS_FLAGS_CATCH) {
			ejsLexPutbackToken(ep, tid, ep->token);
			return EJS_STATE_DEC_LIST_DONE;

		} else if (tid != EJS_TOK_COMMA) {
			ejsSyntaxError(ep, 0);
			return EJS_STATE_ERR;
		}

	} while (tid == EJS_TOK_COMMA);

	if (tid != EJS_TOK_SEMI) {
		ejsSyntaxError(ep, 0);
		return EJS_STATE_ERR;
	}
	return EJS_STATE_DEC_LIST_DONE;
}

/******************************************************************************/
/*
 *	Local vars 
 */

typedef struct ParseExpr {
	EjsVar		lhs, rhs;
	int			rel, tid, unaryMinus;
} ParseExpr;

/*
 *	Parse expression (leftHandSide operator rightHandSide)
 */

static int parseExpr(Ejs *ep, int state, int flags)
{
	ParseExpr		*sp;

	mprAssert(ep);

	if ((sp = pushFrame(ep, sizeof(ParseExpr))) == 0) {
		return EJS_STATE_ERR;
	}

	if (flags & EJS_FLAGS_EXE) {
		ejsClearVar(ep, ep->result);
	}

	sp->lhs.type = sp->rhs.type = EJS_TYPE_UNDEFINED;
	sp->lhs.objectState = sp->rhs.objectState = 0;
	sp->lhs.allocatedData = sp->rhs.allocatedData = 0;

	ejsSetVarName(ep, &sp->lhs, "lhs");
	ejsSetVarName(ep, &sp->rhs, "rhs");

	sp->rel = 0;
	sp->tid = 0;
	sp->unaryMinus = 0;

	do {
		/*
		 *	This loop will handle an entire expression list. We call parse
		 *	to evalutate each term which returns the result in ep->result.
		 */
		if (sp->tid == EJS_TOK_LOGICAL) {
			state = ejsParse(ep, EJS_STATE_RELEXP, flags);
			if (state < 0) {
				break;
			}
		} else {
			sp->tid = ejsLexGetToken(ep, state);
			if (sp->tid == EJS_TOK_EXPR && (int) *ep->token == EJS_EXPR_MINUS) {
				sp->unaryMinus = 1;

			} else {
				ejsLexPutbackToken(ep, sp->tid, ep->token);
			}

			state = ejsParse(ep, EJS_STATE_EXPR, flags);
			if (state < 0) {
				break;
			}
		}

		if (flags & EJS_FLAGS_EXE) {
			if (sp->unaryMinus) {
				switch (ep->result->type) {
				default:
				case EJS_TYPE_UNDEFINED:
				case EJS_TYPE_NULL:
				case EJS_TYPE_STRING_CMETHOD:
				case EJS_TYPE_CMETHOD:
				case EJS_TYPE_METHOD:
				case EJS_TYPE_PTR:
				case EJS_TYPE_OBJECT:
				case EJS_TYPE_STRING:
				case EJS_TYPE_BOOL:
					ejsError(ep, EJS_SYNTAX_ERROR, "Invalid unary minus");
					state = EJS_STATE_ERR;
					break;

#if BLD_FEATURE_FLOATING_POINT
				case EJS_TYPE_FLOAT:
					ep->result->floating = - ep->result->floating;
					break;
#endif

				case EJS_TYPE_INT:
					ep->result->integer = - ep->result->integer;
					break;

#if BLD_FEATURE_INT64
				case EJS_TYPE_INT64:
					ep->result->integer64 = - ep->result->integer64;
					break;
#endif
				}
			}
			sp->unaryMinus = 0;

			if (sp->rel > 0) {
				ejsWriteVar(ep, &sp->rhs, ep->result, EJS_SHALLOW_COPY);
				if (sp->tid == EJS_TOK_LOGICAL) {
					if (evalCond(ep, &sp->lhs, sp->rel, &sp->rhs) < 0) {
						state = EJS_STATE_ERR;
						break;
					}
				} else {
					if (evalExpr(ep, &sp->lhs, sp->rel, &sp->rhs) < 0) {
						state = EJS_STATE_ERR;
						break;
					}
				}
			}
			/* MOB */
			if (sp->lhs.type == EJS_TYPE_OBJECT) {
				ejsMakeObjLive(&sp->lhs, 0);
				mprAssert(sp->lhs.objectState->alive == 0);
			}
			if (sp->rhs.type == EJS_TYPE_OBJECT) {
				ejsMakeObjLive(&sp->rhs, 0);
				mprAssert(sp->rhs.objectState->alive == 0);
			}
		}

		if ((sp->tid = ejsLexGetToken(ep, state)) == EJS_TOK_EXPR ||
			 sp->tid == EJS_TOK_INC_DEC || sp->tid == EJS_TOK_LOGICAL) {
			sp->rel = (int) *ep->token;
			ejsWriteVar(ep, &sp->lhs, ep->result, EJS_SHALLOW_COPY);

		} else {
			ejsLexPutbackToken(ep, sp->tid, ep->token);
			state = EJS_STATE_RELEXP_DONE;
		}

	} while (state == EJS_STATE_EXPR_DONE);

	ejsClearVar(ep, &sp->lhs);
	ejsClearVar(ep, &sp->rhs);

	popFrame(ep, sizeof(ParseExpr));

	return state;
}

/******************************************************************************/
/*
 *	Local vars
 */

typedef struct ParseForIn {
	EjsInput		*endScript, *bodyScript;
	EjsProperty		*pp, *nextp;
	EjsVar			*iteratorVar, *setVar, *vp;
	int				forFlags, tid;
} ParseForIn;

/*
 *	Parse the "for ... in" statement. Format for the statement is:
 *
 *		for [each] (var varName in expression) {
 *			body;
 *		}
 */

static int parseForIn(Ejs *ep, int state, int flags, int each)
{
	ParseForIn		*sp;

	mprAssert(ep);

	if ((sp = pushFrame(ep, sizeof(ParseForIn))) == 0) {
		return EJS_STATE_ERR;
	}

	sp->setVar = 0;
	sp->iteratorVar = 0;
	sp->bodyScript = 0;
	sp->endScript = 0;

	sp->tid = ejsLexGetToken(ep, state);
	if (sp->tid != EJS_TOK_ID && sp->tid != EJS_TOK_VAR) {
		ejsSyntaxError(ep, 0);
		goto err;
	}
	ejsLexPutbackToken(ep, sp->tid, ep->token);

	state = ejsParse(ep, EJS_STATE_EXPR, EJS_FLAGS_FORIN | flags);
	if (state < 0) {
		goto done;
	}
	if (flags & EJS_FLAGS_EXE) {
		if (ep->currentProperty == 0) {
			ejsSyntaxError(ep, 0);
			goto err;
		}
		sp->iteratorVar = &ep->currentProperty->var;
	} else {
		sp->iteratorVar = 0;
	}
	
	if (ejsLexGetToken(ep, state) != EJS_TOK_IN) {
		ejsSyntaxError(ep, 0);
		goto err;
	}

	/*
	 *	Get the set
	 */
	sp->tid = ejsLexGetToken(ep, state);
	if (sp->tid != EJS_TOK_ID) {
		ejsSyntaxError(ep, 0);
		goto err;
	}
	ejsLexPutbackToken(ep, sp->tid, ep->token);

	state = ejsParse(ep, EJS_STATE_EXPR, flags);
	if (state < 0) {
		goto done;
	}

	if ((flags & EJS_FLAGS_EXE) && 
			(ep->result == 0 || ep->result->type == EJS_TYPE_UNDEFINED)) {
		ejsError(ep, EJS_REFERENCE_ERROR, "Can't access array or object");
		goto err;
	}
	
	if (ejsLexGetToken(ep, state) != EJS_TOK_RPAREN) {
		ejsSyntaxError(ep, 0);
		goto err;
	}

	sp->setVar = ejsDupVar(ep, ep->result, EJS_SHALLOW_COPY);

	sp->bodyScript = getInputStruct(ep);

	/*
	 *	Parse the body and remember the end of the body script
	 */
	sp->forFlags = flags & ~EJS_FLAGS_EXE;
	ejsLexSaveInputState(ep, sp->bodyScript);

	state = ejsParse(ep, EJS_STATE_STMT, sp->forFlags);
	if (state < 0) {
		goto done;
	}

	sp->endScript = getInputStruct(ep);
	ejsInitInputState(sp->endScript);
	ejsLexSaveInputState(ep, sp->endScript);

	/*
	 *	Enumerate the properties
	 */
	if (flags & EJS_FLAGS_EXE) {
		if (sp->setVar->type == EJS_TYPE_OBJECT) {

			sp->setVar->objectState->preventDeleteProp = 1;

			sp->pp = ejsGetFirstProperty(sp->setVar, 0);
			while (sp->pp) {
				sp->nextp = ejsGetNextProperty(sp->pp, 0);
				if (! sp->pp->dontEnumerate && !sp->pp->delayedDelete) {
					if (each) {
						sp->vp = ejsWriteVar(ep, sp->iteratorVar,
							ejsGetVarPtr(sp->pp), EJS_SHALLOW_COPY);
					} else {
						sp->vp = ejsWriteVarAsString(ep, sp->iteratorVar, 
							sp->pp->name);
					}
					if (sp->vp == 0) {
						ejsError(ep, EJS_MEMORY_ERROR, 
							"Can't write to variable");
						goto err;
					}

					ejsLexRestoreInputState(ep, sp->bodyScript);

					state = ejsParse(ep, EJS_STATE_STMT, flags);

					if (state < 0) {
						if (sp->setVar->objectState) {
							sp->setVar->objectState->preventDeleteProp = 0;
						}
						goto done;
					}
				}
				sp->pp = sp->nextp;
			}

			/*
		     *	Process delayed deletes
			 */
			if (sp->setVar->objectState) {
				sp->setVar->objectState->preventDeleteProp = 0;
				if (sp->setVar->objectState->delayedDeleteProp) {
					sp->pp = ejsGetFirstProperty(sp->setVar, 0);
					while (sp->pp) {
						sp->nextp = ejsGetNextProperty(sp->pp, 0);
						if (sp->pp->delayedDelete) {
							ejsDeleteProperty(ep, sp->setVar, sp->pp->name);
						}
						sp->pp = sp->nextp;
					}
					sp->setVar->objectState->delayedDeleteProp = 0;
				}
			}

		} else {
			ejsError(ep, EJS_REFERENCE_ERROR,
				"Variable to iterate over is not an array or object");
			goto err;
		}
	}

	ejsLexRestoreInputState(ep, sp->endScript);

done:
	if (sp->endScript) {
		ejsLexFreeInputState(ep, sp->endScript);
		ejsLexFreeInputState(ep, sp->bodyScript);
	}

	if (sp->bodyScript) {
		freeInputStruct(ep, sp->bodyScript);
	}
	if (sp->endScript) {
		freeInputStruct(ep, sp->endScript);
	}

	if (sp->setVar) {
		ejsFreeVar(ep, sp->setVar);
	}

	popFrame(ep, sizeof(ParseForIn));

	return state;

err:
	state = EJS_STATE_ERR;
	goto done;
}

/******************************************************************************/
/*
 *	Parse the for statement. Format for the expression is:
 *
 *		for (initial; condition; incr) {
 *			body;
 *		}
 */

static int parseRegFor(Ejs *ep, int state, int flags)
{
	EjsInput	*condScript, *endScript, *bodyScript, *incrScript;

	endScript = getInputStruct(ep);
	bodyScript = getInputStruct(ep);
	incrScript = getInputStruct(ep);
	condScript = getInputStruct(ep);

	ejsInitInputState(endScript);
	ejsInitInputState(bodyScript);
	ejsInitInputState(incrScript);
	ejsInitInputState(condScript);

	state = parseForInner(ep, state, flags, 
		condScript, incrScript, bodyScript, endScript);

	ejsLexFreeInputState(ep, condScript);
	ejsLexFreeInputState(ep, incrScript);
	ejsLexFreeInputState(ep, endScript);
	ejsLexFreeInputState(ep, bodyScript);

	freeInputStruct(ep, condScript);
	freeInputStruct(ep, incrScript);
	freeInputStruct(ep, endScript);
	freeInputStruct(ep, bodyScript);

	return state;
}

/******************************************************************************/

static int parseForInner(Ejs *ep, int state, int flags, EjsInput *condScript,
	EjsInput *incrScript, EjsInput *bodyScript, EjsInput *endScript)
{
	int			forFlags, cond, rs;

	mprAssert(ep);

	/*
	 *	Evaluate the for loop initialization statement
	 */
	if ((state = ejsParse(ep, EJS_STATE_STMT, flags)) < 0) {
		return state;
	}

	/*
	 *	The first time through, we save the current input context just prior
	 *	to each step: prior to the conditional, the loop increment and 
 	 *	the loop body.
	 */
	ejsLexSaveInputState(ep, condScript);
	if ((rs = ejsParse(ep, EJS_STATE_COND, flags)) < 0) {
		return rs;
	}

	cond = (ep->result->boolean != 0);

	if (ejsLexGetToken(ep, state) != EJS_TOK_SEMI) {
		ejsSyntaxError(ep, 0);
		return EJS_STATE_ERR;
	}

	/*
	 *	Don't execute the loop increment statement or the body 
	 *	first time.
	 */
	forFlags = flags & ~EJS_FLAGS_EXE;
	ejsLexSaveInputState(ep, incrScript);
	if ((rs = ejsParse(ep, EJS_STATE_EXPR, forFlags)) < 0) {
		return rs;
	}

	if (ejsLexGetToken(ep, state) != EJS_TOK_RPAREN) {
		ejsSyntaxError(ep, 0);
		return EJS_STATE_ERR;
	}

	/*
	 *	Parse the body and remember the end of the body script
	 */
	ejsLexSaveInputState(ep, bodyScript);
	if ((rs = ejsParse(ep, EJS_STATE_STMT, forFlags)) < 0) {
		return rs;
	}
	ejsLexSaveInputState(ep, endScript);

	/*
	 *	Now actually do the for loop. Note loop has been rotated
	 */
	while (cond && (flags & EJS_FLAGS_EXE)) {
		/*
		 *	Evaluate the body
		 */
		ejsLexRestoreInputState(ep, bodyScript);

		if ((rs = ejsParse(ep, EJS_STATE_STMT, flags)) < 0) {
			return rs;
		}

		/*
		 *	Evaluate the increment script
		 */
		ejsLexRestoreInputState(ep, incrScript);
		if ((rs = ejsParse(ep, EJS_STATE_EXPR, flags)) < 0) {
			return rs;
		}
		/*
		 *	Evaluate the condition
		 */
		ejsLexRestoreInputState(ep, condScript);
		if ((rs = ejsParse(ep, EJS_STATE_COND, flags)) < 0) {
			return 0;
		}
		mprAssert(ep->result->type == EJS_TYPE_BOOL);
		cond = (ep->result->boolean != 0);
	}

	ejsLexRestoreInputState(ep, endScript);

	return state;
}

/******************************************************************************/
/*
 *	Create the bare class object
 */

static int createClass(Ejs *ep, EjsVar *obj, const char *className, 
	EjsVar *baseClass)
{
	EjsVar	*classObj, *existingClass;

	existingClass = ejsGetClass(ep, obj, className);
	if (existingClass) {
		/*
		 *	We allow partial clases and method redefinition
		 *	FUTURE -- should prevent this if the class is sealed.
		 *	DISABLED Error message and return OK.
		 */
		/* ejsError(ep, EJS_EVAL_ERROR, "Can't create class %s", className); */
		return 0;
	}

	if (baseClass == 0) {
		baseClass = ejsGetClass(ep, ep->service->globalClass, "Object");
		mprAssert(baseClass);
	}

	classObj = ejsCreateSimpleClass(ep, baseClass, className);
	if (classObj == 0) {
		ejsMemoryError(ep);
		return -1;
	}
	mprAssert(! ejsObjIsCollectable(classObj));

	ep->currentProperty = ejsSetPropertyAndFree(ep, obj, className, classObj);
	mprAssert(ep->currentProperty);

	if (ep->currentProperty == 0) {
		return -1;
	}

	return 0;
}

/******************************************************************************/
/*
 *	Local vars for parseTry
 */

typedef struct ParseTry {
	EjsVar		*exception;
	int			tid, caught, rs, catchFlags;
} ParseTry;

/*
 *	Parse try block
 *
 *		try {}
 */

static int parseTry(Ejs *ep, int state, int flags)
{
	ParseTry		*sp;

	if ((sp = pushFrame(ep, sizeof(ParseTry))) == 0) {
		return EJS_STATE_ERR;
	}

	mprAssert(ep);

	sp->caught = 0;
	sp->exception = 0;
	sp->catchFlags = flags;

	/*
	 *	Execute the code in the try block
	 */
	sp->rs = ejsParse(ep, EJS_STATE_STMT, flags | EJS_FLAGS_TRY);
	if (sp->rs < 0) {
		if (sp->rs == EJS_STATE_ERR) {
			sp->exception = ejsDupVar(ep, ep->result, EJS_SHALLOW_COPY);
			if (sp->exception == 0) {
				ejsMemoryError(ep);
				goto err;
			}
		} else {
			state = sp->rs;
			goto done;
		}

	} else {
		sp->catchFlags = flags & ~EJS_FLAGS_EXE;
	}

	/*
	 *	On success path or when an exception is caught, we must parse all
	 *	catch and finally blocks.
	 */
	sp->tid = getNextNonSpaceToken(ep, state);

	if (sp->tid == EJS_TOK_CATCH) {

		ep->gotException = 0;

		sp->tid = getNextNonSpaceToken(ep, state);

		if (sp->tid == EJS_TOK_LBRACE) {
			/*
			 *	Unqualified "catch "
			 */
			ejsLexPutbackToken(ep, sp->tid, ep->token);
			if (ejsParse(ep, EJS_STATE_STMT, sp->catchFlags) >= 0) {
				sp->caught++;
			}

		} else if (sp->tid == EJS_TOK_LPAREN) {

			/*
			 *	Qualified "catch (variable) "
			 */
			if ((sp->rs = ejsParse(ep, EJS_STATE_DEC_LIST, 
					sp->catchFlags | EJS_FLAGS_CATCH)) < 0) {
				ejsSyntaxError(ep, "Bad catch statement");
				state = sp->rs;
				goto done;
			}

			sp->tid = getNextNonSpaceToken(ep, state);
			if (sp->tid != EJS_TOK_RPAREN) {
				ejsSyntaxError(ep, 0);
				goto err;
			}

			if (sp->catchFlags & EJS_FLAGS_EXE) {
				if (ep->currentProperty == 0) {
					ejsError(ep, EJS_EVAL_ERROR, "Can't define catch variable");
					goto err;
				}

				/*
				 *	Set the catch variable
				 */
				if (ejsWriteVar(ep, 
						ejsGetVarPtr(ep->currentProperty), sp->exception, 
						EJS_SHALLOW_COPY) == 0) {
					ejsError(ep, EJS_EVAL_ERROR, "Can't update catch variable");
					goto err;
				}
			}

			/*
			 * 	Parse the catch block
			 */
			if ((sp->rs = ejsParse(ep, EJS_STATE_STMT, sp->catchFlags)) < 0) {
				state = sp->rs;
				goto done;
			}
			sp->caught++;
			ep->gotException = 0;
		}
		sp->tid = getNextNonSpaceToken(ep, state);
	}

	/*
	 *	Parse the finally block
	 */
	if (sp->tid == EJS_TOK_FINALLY) {
		if (ejsParse(ep, EJS_STATE_STMT, flags) < 0) {
			goto err;
		}
	} else {
		ejsLexPutbackToken(ep, sp->tid, ep->token);
	}

	/*
	 *	Set the exception value
	 */
	if (sp->exception && !sp->caught) {
		ejsWriteVar(ep, ep->result, sp->exception, EJS_SHALLOW_COPY);
		goto err;
	}
	
	state = EJS_STATE_STMT_DONE;

done:
	if (sp->exception) {
		ejsFreeVar(ep, sp->exception);
	}

	popFrame(ep, sizeof(ParseTry));
	return state;


err:
	state = EJS_STATE_ERR;
	goto done;
}

/******************************************************************************/
/*
 *	Parse throw statement
 *
 *		throw expression
 */

static int parseThrow(Ejs *ep, int state, int flags)
{
	int		rc;

	mprAssert(ep);

	if ((rc = ejsParse(ep, EJS_STATE_EXPR, flags)) < 0) {
		return rc;
	}


	if (flags & EJS_FLAGS_EXE) {
		/*
		 *	We have thrown the exception so set the state to ERR
 		 */
		ep->gotException = 1;
		return EJS_STATE_ERR;
	}
	return state;
}

/******************************************************************************/
/*
 *	Parse a class and module declaration
 *
 *		class <name> [extends baseClass] {
 *			[public | private | ... ] var declarations ...
 *			[constructor] function declarations ...
 *		}
 *
 *		Modules are identical except declared with a "module" instead of
 *		"class". Modules cannot be instantiated and are used for mixins.
 *	
 */

static int parseClass(Ejs *ep, int state, int flags)
{
	int			originalToken, tid, fid;

	mprAssert(ep);

	originalToken = ep->tid;

	/*
	 *	Parse "class Name [extends BaseClass]"
	 */
	if (ejsParse(ep, EJS_STATE_DEC_LIST, flags | EJS_FLAGS_CLASS_DEC) < 0) {
		return EJS_STATE_ERR;
	}

	tid = getNextNonSpaceToken(ep, state);

	if (tid != EJS_TOK_LBRACE) {
		return EJS_STATE_ERR;
	}

	/*
 	 *	After parsing the class body, ep->local will contain the actual 
	 *	class/module object. So, we save ep->local by creating a new block.
	 */
	if (flags & EJS_FLAGS_EXE) {
		fid = ejsSetBlock(ep, ejsGetVarPtr(ep->currentProperty));
		ejsSetVarName(ep, ep->local, ep->currentProperty->name);

	} else {
		fid = -1;
	}

	/* FUTURE -- should prevent modules from being instantiated */

	/*
	 *	Parse class body
	 */
	do {
		state = ejsParse(ep, EJS_STATE_STMT, flags);
		if (state < 0) {
			if (fid >= 0) {
				ejsCloseBlock(ep, fid);
			}
			return state;
		}
		tid = getNextNonSpaceToken(ep, state);
		if (tid == EJS_TOK_RBRACE) {
			break;
		}
		ejsLexPutbackToken(ep, tid, ep->token);

	} while (state >= 0);

	if (fid >= 0) {
		ejsCloseBlock(ep, fid);
	}

	if (tid != EJS_TOK_RBRACE) {
		ejsSyntaxError(ep, 0);
		state = EJS_STATE_ERR;
	}

	return state;
}

/******************************************************************************/
/*
 *	Parse a function declaration
 */

static int parseFunction(Ejs *ep, int state, int flags)
{
	EjsInput	*endScript, *bodyScript;
	EjsProperty	*pp;
	EjsVar		*func, *funcProp, *currentObj, *vp, *baseClass;
	char		*procName;
	int			varFlags, len, tid, bodyFlags, innerState;

	mprAssert(ep);

	func = 0;
	varFlags = 0;

	/*	
	 *	method <name>(arg, arg, arg) { body };
	 *	method name(arg, arg, arg) { body };
	 */

	tid = ejsLexGetToken(ep, state);

	if (tid == EJS_TOK_GET) {
		varFlags |= EJS_GET_ACCESSOR;
		tid = ejsLexGetToken(ep, state);

	} else if (tid == EJS_TOK_SET) {
		varFlags |= EJS_SET_ACCESSOR;
		tid = ejsLexGetToken(ep, state);
	} 

	if (tid == EJS_TOK_ID) {
		if (varFlags & EJS_SET_ACCESSOR) {

			if (mprAllocStrcat(MPR_LOC_ARGS(ep), &procName, EJS_MAX_ID + 5, 
					0, "-set-", ep->token, 0) < 0) {
				ejsError(ep, EJS_SYNTAX_ERROR, 
					"Name %s is too long", ep->token);
				return EJS_STATE_ERR;
			}

		} else {
			procName = mprStrdup(ep, ep->token);
		}

		tid = ejsLexGetToken(ep, state);

	}  else {
		procName = 0;
	}

	if (tid != EJS_TOK_LPAREN) {
		mprFree(procName);
		ejsSyntaxError(ep, 0);
		return EJS_STATE_ERR;
	}

	/*
 	 *	Hand craft the method value structure.
	 */
	if (flags & EJS_FLAGS_EXE) {
		func = ejsCreateMethodVar(ep, 0, 0, 0);
		if (func == 0) {
			mprFree(procName);
			ejsMemoryError(ep);
			return EJS_STATE_ERR;
		}
		func->flags = varFlags;
	}

	tid = ejsLexGetToken(ep, state);
	while (tid == EJS_TOK_ID) {
		if (flags & EJS_FLAGS_EXE) {
			mprAddItem(func->method.args, 
				mprStrdup(func->method.args, ep->token));
		}
		tid = ejsLexGetToken(ep, state);
		if (tid == EJS_TOK_RPAREN || tid != EJS_TOK_COMMA) {
			break;
		}
		tid = ejsLexGetToken(ep, state);
	}
	if (tid != EJS_TOK_RPAREN) {
		mprFree(procName);
		ejsFreeVar(ep, func);
		ejsSyntaxError(ep, 0);
		return EJS_STATE_ERR;
	}

	/* Allow new lines before opening brace */
	do {
		tid = ejsLexGetToken(ep, state);
	} while (tid == EJS_TOK_NEWLINE);

	if (tid != EJS_TOK_LBRACE) {
		mprFree(procName);
		ejsFreeVar(ep, func);
		ejsSyntaxError(ep, 0);
		return EJS_STATE_ERR;
	}
	
	/* 
	 *	Register the method name early to allow for recursive
	 *	method calls (see note in ECMA standard, page 71) 
	 */
	funcProp = 0;
	if (flags & EJS_FLAGS_EXE && procName) {
		currentObj = pickSpace(ep, 0, procName, flags | EJS_FLAGS_LOCAL);
		pp = ejsSetProperty(ep, currentObj, procName, func);
		if (pp == 0) {
			ejsFreeVar(ep, func);
			ejsMemoryError(ep);
			return EJS_STATE_ERR;
		}
		funcProp = ejsGetVarPtr(pp);
	}
	

	bodyScript = getInputStruct(ep);

	/*
	 *	Parse the method body. Turn execute off.
	 */
	bodyFlags = flags & ~EJS_FLAGS_EXE;
	ejsLexSaveInputState(ep, bodyScript);

	do {
		innerState = ejsParse(ep, EJS_STATE_STMT, bodyFlags);
	} while (innerState == EJS_STATE_STMT_DONE);

	tid = ejsLexGetToken(ep, state);

	if (innerState != EJS_STATE_STMT_BLOCK_DONE || tid != EJS_TOK_RBRACE) {
		mprFree(procName);
		ejsFreeVar(ep, func);
		ejsLexFreeInputState(ep, bodyScript);
		if (innerState != EJS_STATE_ERR) {
			ejsSyntaxError(ep, 0);
		}
		freeInputStruct(ep, bodyScript);
		return EJS_STATE_ERR;
	}

	if (flags & EJS_FLAGS_EXE) {
		endScript = getInputStruct(ep);
		ejsLexSaveInputState(ep, endScript);

		/*
		 *	Save the method body between the starting and ending parse 
		 *	positions. Overwrite the trailing '}' with a null.
		 */
		len = endScript->scriptServp - bodyScript->scriptServp;
		func->method.body = mprAlloc(ep, len + 1);
		memcpy(func->method.body, bodyScript->scriptServp, len);

		if (len <= 0) {
			func->method.body[0] = '\0';
		} else {
			func->method.body[len - 1] = '\0';
		}
		ejsLexFreeInputState(ep, bodyScript);
		ejsLexFreeInputState(ep, endScript);
		freeInputStruct(ep, endScript);

		/*
		 *	If we are in an assignment, don't register the method name, rather
		 *	return the method structure in the parser result.
		 */
		if (procName) {
			currentObj = pickSpace(ep, 0, procName, flags | EJS_FLAGS_LOCAL);
			pp = ejsSetProperty(ep, currentObj, procName, func);
			if (pp == 0) {
				ejsFreeVar(ep, func);
				ejsMemoryError(ep);
				return EJS_STATE_ERR;
			}

			if (currentObj->objectState->className &&
				strcmp(currentObj->objectState->className, procName) == 0) {
				baseClass = currentObj->objectState->baseClass;
				if (baseClass) {
					if (strstr(func->method.body, "super(") != 0) {
						funcProp->callsSuper = 1;
						/*
						 *	Define super() to point to the baseClass constructor
						 */
						vp = ejsGetPropertyAsVar(ep, baseClass, 
							baseClass->objectState->className);
						if (vp) {
							mprAssert(vp);
							if (ejsSetProperty(ep, currentObj, "super", 
									vp) == 0) {
								ejsFreeVar(ep, func);
								ejsMemoryError(ep);
								return EJS_STATE_ERR;
							}
						}
					}
				}
			}
		}
		/*
		 *	Always return the function. Try for all stmts to be expressions.
		 */
		/* MOB - rc */
		ejsWriteVar(ep, ep->result, func, EJS_SHALLOW_COPY);
	}
	freeInputStruct(ep, bodyScript);

	mprFree(procName);
	ejsFreeVar(ep, func);

	return state;
}

/******************************************************************************/
/*
 *	Local vars
 */

typedef struct ParseMethod {
	EjsProc		proc, *saveProc;
	EjsVar		*saveObj, *newObj;
	int			saveObjPerm, rc;

} ParseMethod;

/*
 *	Parse a method name and invoke the method. See parseFunction for 
 *	function declarations.
 */

static int parseMethod(Ejs *ep, int state, int flags, char *id)
{
	ParseMethod		*sp;

	if ((sp = pushFrame(ep, sizeof(ParseMethod))) == 0) {
		return EJS_STATE_ERR;
	}

	/*
	 *	Must save any current ep->proc value for the current stack frame
	 *	to allow for recursive method calls.
	 */
	sp->saveProc = (ep->proc) ? ep->proc: 0;

	memset(&sp->proc, 0, sizeof(EjsProc));
	sp->proc.procName = mprStrdup(ep, id);
	sp->proc.fn = &ep->currentProperty->var;
	sp->proc.args = mprCreateItemArray(ep, EJS_INC_ARGS, EJS_MAX_ARGS);
	ep->proc = &sp->proc;

#if BLD_DEBUG
	if (strcmp(sp->proc.procName, "printv") == 0) {
		flags |= EJS_FLAGS_TRACE_ARGS;
	}
#endif

	if (flags & EJS_FLAGS_EXE) {
		ejsClearVar(ep, ep->result);
	}

	if (! (flags & EJS_FLAGS_NO_ARGS)) {
		sp->saveObj = ep->currentObj;
		sp->saveObjPerm = ejsMakeObjPermanent(sp->saveObj, 1);
		sp->rc = ejsParse(ep, EJS_STATE_ARG_LIST, flags);
		ejsMakeObjPermanent(sp->saveObj, sp->saveObjPerm);
		if (sp->rc < 0) {
			goto err;
		}
		ep->currentObj = sp->saveObj;
	}

#if BLD_DEBUG
	flags &= ~EJS_FLAGS_TRACE_ARGS;
#endif

	/*
	 *	Evaluate the method if required
	 */
	if (flags & EJS_FLAGS_EXE) {
		if (flags & EJS_FLAGS_NEW) {
			sp->newObj = ejsCreateObjUsingArgv(ep, ep->currentObj, 
				sp->proc.procName, sp->proc.args);

			if (sp->newObj == 0) {
				state = EJS_STATE_ERR;

			} else {
				mprAssert(! ejsObjIsCollectable(sp->newObj));

				/*
				 *	Return the newly created object as the result of the 
				 *	command. NOTE: newObj may not be an object!
				 */
				/* MOB - rc */
				ejsWriteVar(ep, ep->result, sp->newObj, EJS_SHALLOW_COPY);
				if (ejsVarIsObject(sp->newObj)) {
					ejsMakeObjLive(sp->newObj, 1);
					mprAssert(ejsObjIsCollectable(sp->newObj));
					mprAssert(ejsBlockInUse(sp->newObj));
				}
				ejsFreeVar(ep, sp->newObj);
			}

		} else {

			if (evalMethod(ep, ep->currentObj, &sp->proc, flags) < 0) {
				/* Methods must call ejsError to set exceptions */
				state = EJS_STATE_ERR;
			}
		}
	}

	if (! (flags & EJS_FLAGS_NO_ARGS)) {
		if (ejsLexGetToken(ep, state) != EJS_TOK_RPAREN) {
			if (state != EJS_STATE_ERR) {
				ejsSyntaxError(ep, 0);
			}
			state = EJS_STATE_ERR;
		}
	}

done:
	freeProc(ep, &sp->proc);
	ep->proc = sp->saveProc;

	popFrame(ep, sizeof(ParseMethod));
	return state;

err:
	state = EJS_STATE_ERR;
	goto done;
}

/******************************************************************************/
/*
 *	Parse an identifier. This is a segment of a fully qualified variable.
 *	May come here for an initial identifier or for property names
 *	after a "." or "[...]".
 */

static int parseId(Ejs *ep, int state, int flags, char **id, int *done)
{
	EjsVar	*null;
	int		tid;

	mprFree(*id);
	*id = mprStrdup(ep, ep->token);

	if (ep->currentObj == 0) {
		/* First identifier segement */
		ep->currentObj = pickSpace(ep, state, *id, flags);
	}

	tid = ejsLexGetToken(ep, state);
	if (tid == EJS_TOK_ASSIGNMENT) {
		flags |= EJS_FLAGS_LHS;
	}

	/*
	 *	Find the referenced variable and store it in currentProperty.
	  */
	if (flags & EJS_FLAGS_EXE) {
		ep->currentProperty = searchSpacesForProperty(ep, state, 
			ep->currentObj, *id, flags);

		/*
		 *	Handle properties that have been deleted inside an enumeration
		 */
		if (ep->currentProperty && ep->currentProperty->delayedDelete) {
			ep->currentProperty = 0;
		}

		if (ep->currentProperty && 
				ejsVarIsMethod(&ep->currentProperty->var) && 
				tid != EJS_TOK_LPAREN) {
			if (ep->currentProperty->var.flags & EJS_GET_ACCESSOR) {
				ejsLexPutbackToken(ep, tid, ep->token);
				state = parseMethod(ep, state, flags | EJS_FLAGS_NO_ARGS, *id);
				if (ep->flags & EJS_FLAGS_EXIT) {
					state = EJS_STATE_RET;
				}
				if (state >= 0) {
					ejsSetVarName(ep, ep->result, ep->currentProperty->name);
				}
				return state;
			}
		}
		/*
		 *	OPT. We should not have to do this always
		 */
		updateResult(ep, state, flags, ejsGetVarPtr(ep->currentProperty));
	}

	flags &= ~EJS_FLAGS_LHS;

	if (tid == EJS_TOK_LPAREN) {
		if (ep->currentProperty == 0 && (flags & EJS_FLAGS_EXE)) {
			ejsError(ep, EJS_REFERENCE_ERROR,
				"Method name not defined \"%s\"", *id);
			return EJS_STATE_ERR;
		}
		ejsLexPutbackToken(ep, EJS_TOK_METHOD_NAME, ep->token);
		return state;
	}

	if (tid == EJS_TOK_PERIOD || tid == EJS_TOK_LBRACKET || 
			tid == EJS_TOK_ASSIGNMENT || tid == EJS_TOK_INC_DEC) {
		ejsLexPutbackToken(ep, tid, ep->token);
		return state;
	}

	if (flags & EJS_FLAGS_CLASS_DEC) {
		if (tid == EJS_TOK_LBRACE || tid == EJS_TOK_EXTENDS) {
			ejsLexPutbackToken(ep, tid, ep->token);
			return state;
		}
	}

	if (flags & EJS_FLAGS_DELETE) {
		if (tid == EJS_TOK_RBRACE) {
			ejsLexPutbackToken(ep, tid, ep->token);
		}
	}

	/*
	 *	Only come here for variable access and declarations.
	 *	Assignment handled elsewhere.
	 */
	if (flags & EJS_FLAGS_EXE) {
		if (state == EJS_STATE_DEC) {
			/*
 			 *	Declare a variable. Standard allows: var x ; var x ;
			 */
#if DISABLED
			if (ep->currentProperty != 0) {
				ejsError(ep, EJS_REFERENCE_ERROR,
					"Variable already defined \"%s\"", *id);
				return EJS_STATE_ERR;
			}
#endif
			/*
			 *	Create or overwrite if it already exists
			 *	Set newly declared variables to the null value.
			 */
			null = ejsCreateNullVar(ep);
			ep->currentProperty = ejsSetPropertyAndFree(ep, ep->currentObj, 
				*id, null);
			ejsClearVar(ep, ep->result);

		} else if (flags & EJS_FLAGS_FORIN) {
			/*
 			 *	This allows "for (x" when x has not yet been defined
			 */
			if (ep->currentProperty == 0) {
				/* MOB -- return code */
				ep->currentProperty = ejsCreateProperty(ep, 
					ep->currentObj, *id);
			}

		} else if (ep->currentProperty == 0) {

			if (ep->currentObj && ((ep->currentObj == ep->global || 
					(ep->currentObj == ep->local)))) {
				/* 
				 *	Test against currentObj and not currentObj->objectState
				 *	as we must allow "i = global.x" and not allow 
				 *	"i = x" where x does not exist.
				 */
				ejsError(ep, EJS_REFERENCE_ERROR,
					"Undefined variable \"%s\"", *id);
				return EJS_STATE_ERR;
			}

			if (flags & EJS_FLAGS_DELETE) {
				ejsError(ep, EJS_REFERENCE_ERROR,
					"Undefined variable \"%s\"", *id);
				return EJS_STATE_ERR;
			}
		}
	}
	ejsLexPutbackToken(ep, tid, ep->token);
	if (tid == EJS_TOK_RBRACKET || tid == EJS_TOK_COMMA || 
			tid == EJS_TOK_IN) {
		*done = 1;
	}
	return state;
}

/******************************************************************************/
/*
 *	Local vars 
 */

typedef struct ParseIf {
	int		ifResult, thenFlags, elseFlags, tid, rs;
} ParseIf;

/*
 *	Parse an "if" statement
 */

static int parseIf(Ejs *ep, int state, int flags, int *done)
{
	ParseIf		*sp;

	if ((sp = pushFrame(ep, sizeof(ParseIf))) == 0) {
		return EJS_STATE_ERR;
	}

	if (state != EJS_STATE_STMT) {
		goto err;
	}
	if (ejsLexGetToken(ep, state) != EJS_TOK_LPAREN) {
		goto err;
	}

	/*
	 *	Evaluate the entire condition list "(condition)"
	 */
	if (ejsParse(ep, EJS_STATE_COND, flags) < 0) {
		goto err;
	}
	if (ejsLexGetToken(ep, state) != EJS_TOK_RPAREN) {
		goto err;
	}

	/*
	 *	This is the "then" case. We need to always parse both cases and
	 *	execute only the relevant case.
	 */
	sp->ifResult = ejsVarToBoolean(ep->result);
	if (sp->ifResult) {
		sp->thenFlags = flags;
		sp->elseFlags = flags & ~EJS_FLAGS_EXE;
	} else {
		sp->thenFlags = flags & ~EJS_FLAGS_EXE;
		sp->elseFlags = flags;
	}

	/*
	 *	Process the "then" case.
	 */
	if ((sp->rs = ejsParse(ep, EJS_STATE_STMT, sp->thenFlags)) < 0) {
		if (! ep->gotException) {
			state = sp->rs;
			goto done;
		}
	}

	/*
	 *	Check to see if there is an "else" case
	 */
	removeNewlines(ep, state);
	sp->tid = ejsLexGetToken(ep, state);
	if (sp->tid != EJS_TOK_ELSE) {
		ejsLexPutbackToken(ep, sp->tid, ep->token);
		*done = 1;
		if (ep->gotException) {
			goto err;
		}
		goto done;
	}

	/*
	 *	Process the "else" case.
	 */
	state = ejsParse(ep, EJS_STATE_STMT, sp->elseFlags);

done:
	*done = 1;
	if (ep->gotException) {
		state = EJS_STATE_ERR;
	}
	popFrame(ep, sizeof(ParseIf));
	return state;


err:
	state = EJS_STATE_ERR;
	goto done;
}

/******************************************************************************/
/*
 *	Parse a postix "++" or "--" statement
 */

static int parseInc(Ejs *ep, int state, int flags)
{
	EjsVar	*one;

	if (! (flags & EJS_FLAGS_EXE)) {
		return state;
	}

	if (ep->currentProperty == 0) {
		ejsError(ep, EJS_REFERENCE_ERROR,
						"Undefined variable \"%s\"", ep->token);
		return EJS_STATE_ERR;
	}
	one = ejsCreateIntegerVar(ep, 1);
	if (evalExpr(ep, &ep->currentProperty->var, (int) *ep->token, one) < 0) {
		ejsFreeVar(ep, one);
		return EJS_STATE_ERR;
	}
	if (ejsWriteVar(ep, &ep->currentProperty->var, ep->result, 
			EJS_SHALLOW_COPY) < 0) {
		ejsError(ep, EJS_IO_ERROR, "Can't write to variable");
		ejsFreeVar(ep, one);
		return EJS_STATE_ERR;
	}
	ejsFreeVar(ep, one);
	return state;
}

/******************************************************************************/
/*
 *	Evaluate a condition. Implements &&, ||, !. Returns with a boolean result
 *	in ep->result. Returns EJS_STATE_ERR on errors, zero if successful.
 */

static int evalCond(Ejs *ep, EjsVar *lhs, int rel, EjsVar *rhs)
{
	int		l, r, lval;

	mprAssert(rel > 0);

	l = ejsVarToBoolean(lhs);
	r = ejsVarToBoolean(rhs);

	switch (rel) {
	case EJS_COND_AND:
		lval = l && r;
		break;
	case EJS_COND_OR:
		lval = l || r;
		break;
	default:
		ejsError(ep, EJS_SYNTAX_ERROR, "Bad operator %d", rel);
		return -1;
	}

	/* MOB - rc */
	ejsWriteVarAsBoolean(ep, ep->result, lval);
	return 0;
}


/******************************************************************************/
/*
 *	return true if this string is a valid number
 */

static int stringIsNumber(const char *s)
{
	char *endptr = NULL;

	if (s == NULL || *s == 0) {
		return 0;
	}
	/* MOB -- not ideal */
#if BREW
 	/* MOB this should check all digits and not just the first. */
	/* Does not support floating point - easy */

	if (isdigit(*s) || (*s == '-' && isdigit(s[1]))) {
		return 1;
	}
#else
	strtod(s, &endptr);
#endif
	if (endptr != NULL && *endptr == 0) {
		return 1;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Evaluate an operation. Returns with the result in ep->result. Returns -1
 *	on errors, otherwise zero is returned.
 */

static int evalExpr(Ejs *ep, EjsVar *lhs, int rel, EjsVar *rhs)
{
	EjsNum		lval;
	char		*str;
	int			rc;

	mprAssert(rel > 0);
	str = 0;
	lval = 0;

	/*
 	 *	Type conversion. This is tricky and must be according to the standard.
	 *	Only numbers (including floats) and strings can be compared. All other
	 *	types are first converted to numbers by preference and if that fails,
	 *	to strings.
	 *
	 *	MOB -- should we do "valueOf" here also.
	 */
	if (lhs->type == EJS_TYPE_OBJECT && 
		(rhs->type != EJS_TYPE_OBJECT && 
			(rhs->type != EJS_TYPE_UNDEFINED && rhs->type != EJS_TYPE_NULL))) {
		if (ejsVarIsNumber(rhs)) {
			if (ejsRunMethod(ep, lhs, "toValue", 0) == 0) {
				/* MOB - rc */
				ejsWriteVar(ep, lhs, ep->result, EJS_SHALLOW_COPY);
			} else {
				if (ejsRunMethod(ep, lhs, "toString", 0) == 0) {
					/* MOB - rc */
					ejsWriteVar(ep, lhs, ep->result, EJS_SHALLOW_COPY);
				}
			}

		} else {
			if (ejsRunMethod(ep, lhs, "toString", 0) == 0) {
				/* MOB - rc */
				ejsWriteVar(ep, lhs, ep->result, EJS_SHALLOW_COPY);
			} else {
				if (ejsRunMethod(ep, lhs, "toValue", 0) == 0) {
					/* MOB - rc */
					ejsWriteVar(ep, lhs, ep->result, EJS_SHALLOW_COPY);
				}
			}
		}
		/* Nothing more can be done */
	}

	if (rhs->type == EJS_TYPE_OBJECT && 
		(lhs->type != EJS_TYPE_OBJECT && 
			(lhs->type != EJS_TYPE_UNDEFINED && lhs->type != EJS_TYPE_NULL))) {
		if (ejsVarIsNumber(lhs)) {
			/* If LHS is number, then convert to a value first */
			if (ejsRunMethod(ep, rhs, "toValue", 0) == 0) {
				/* MOB - rc */
				ejsWriteVar(ep, rhs, ep->result, EJS_SHALLOW_COPY);
			} else {
				if (ejsRunMethod(ep, rhs, "toString", 0) == 0) {
					/* MOB - rc */
					ejsWriteVar(ep, rhs, ep->result, EJS_SHALLOW_COPY);
				}
			}

		} else {
			/* If LHS is not a number, then convert to a string first */
			if (ejsRunMethod(ep, rhs, "toString", 0) == 0) {
				/* MOB - rc */
				ejsWriteVar(ep, rhs, ep->result, EJS_SHALLOW_COPY);

			} else {
				if (ejsRunMethod(ep, rhs, "toValue", 0) == 0) {
					/* MOB - rc */
					ejsWriteVar(ep, rhs, ep->result, EJS_SHALLOW_COPY);
				}
			}
		}
		/* Nothing more can be done */
	}

	/* 
	 *	undefined and null are special, in that they don't get promoted when
	 *	comparing.
	 */
	if (rel == EJS_EXPR_EQ || rel == EJS_EXPR_NOTEQ) {
		if (lhs->type == EJS_TYPE_UNDEFINED || 
				rhs->type == EJS_TYPE_UNDEFINED) {
			return evalBoolExpr(ep, 
								lhs->type == EJS_TYPE_UNDEFINED, 
								rel, 
								rhs->type == EJS_TYPE_UNDEFINED);
		}

		if (lhs->type == EJS_TYPE_NULL || rhs->type == EJS_TYPE_NULL) {
			return evalBoolExpr(ep, 
								lhs->type == EJS_TYPE_NULL, 
								rel, 
								rhs->type == EJS_TYPE_NULL);
		}
	}

	/*
 	 *	From here on, lhs and rhs may contain allocated data (strings), so 
	 *	we must always destroy before overwriting.
	 */
	
	/*
	 *	Only allow a few bool operations. Otherwise convert to number.
 	 */
	if (lhs->type == EJS_TYPE_BOOL && rhs->type == EJS_TYPE_BOOL &&
			(rel != EJS_EXPR_EQ && rel != EJS_EXPR_NOTEQ &&
			rel != EJS_EXPR_BOOL_COMP)) {
		ejsWriteVarAsNumber(ep, lhs, ejsVarToNumber(lhs));
	}

	/*
 	 *	Types do not match, so try to coerce the right operand to match the left
 	 *	But first, try to convert a left operand that is a numeric stored as a
	 *	string, into a numeric.
	 */
	if (lhs->type != rhs->type) {
		if (lhs->type == EJS_TYPE_STRING) {
			if (stringIsNumber(lhs->string)) {
				ejsWriteVarAsNumber(ep, lhs, ejsVarToNumber(lhs));
				
				/* Examine further below */

			} else {
				/*
				 *	Convert the RHS to a string
				 *	MOB rc
				 */
				str = ejsVarToString(ep, rhs);
				ejsWriteVarAsString(ep, rhs, str);
			}

#if BLD_FEATURE_FLOATING_POINT
		} else if (lhs->type == EJS_TYPE_FLOAT) {
			/*
			 *	Convert rhs to floating
			 */
			ejsWriteVarAsFloat(ep, rhs, ejsVarToFloat(rhs));

#endif
#if BLD_FEATURE_INT64
		} else if (lhs->type == EJS_TYPE_INT64) {
			/*
			 *	Convert the rhs to 64 bit
			 */
			ejsWriteVarAsInteger64(ep, rhs, ejsVarToInteger64(rhs));
#endif
		} else if (lhs->type == EJS_TYPE_BOOL || lhs->type == EJS_TYPE_INT) {

			if (rhs->type == EJS_TYPE_STRING) {
				if (stringIsNumber(rhs->string)) {
					ejsWriteVarAsNumber(ep, rhs, ejsVarToNumber(rhs));
				} else {
					/*
					 *	Convert to lhs to a string
					 */
					str = ejsVarToString(ep, lhs);
					/* MOB -- rc */
					if (str) {
						ejsWriteVarAsString(ep, lhs, str);
					}
				}

#if BLD_FEATURE_FLOATING_POINT
			} else if (rhs->type == EJS_TYPE_FLOAT) {
				/*
				 *	Convert lhs to floating
				 */
				ejsWriteVarAsFloat(ep, lhs, ejsVarToFloat(lhs));
#endif

			} else {
				/*
				 *	Forcibly convert both operands to numbers
				 */
				ejsWriteVarAsNumber(ep, lhs, ejsVarToNumber(lhs));
				ejsWriteVarAsNumber(ep, rhs, ejsVarToNumber(rhs));
			}
		}
	}

	/*
 	 *	We have failed to coerce the types to be the same. Special case here
	 *	for undefined and null. We need to allow comparisions against these
	 *	special values.
	 */
	if (lhs->type == EJS_TYPE_UNDEFINED || lhs->type == EJS_TYPE_NULL) {
		switch (rel) {
		case EJS_EXPR_EQ:
			lval = lhs->type == rhs->type;
			break;
		case EJS_EXPR_NOTEQ:
			lval = lhs->type != rhs->type;
			break;
		case EJS_EXPR_BOOL_COMP:
			lval = ! ejsVarToBoolean(rhs);
			break;
		default:
			ejsWriteVar(ep, ep->result, rhs, EJS_SHALLOW_COPY);
			return 0;
		}
		ejsWriteVarAsBoolean(ep, ep->result, lval);
		return 0;
	}

	/*
	 *	Types are the same here
 	 */
	switch (lhs->type) {
	default:
	case EJS_TYPE_UNDEFINED:
	case EJS_TYPE_NULL:
		/* Should be handled above */
		mprAssert(0);
		return 0;

	case EJS_TYPE_STRING_CMETHOD:
	case EJS_TYPE_CMETHOD:
	case EJS_TYPE_METHOD:
	case EJS_TYPE_PTR:
		ejsWriteVarAsBoolean(ep, ep->result, 0);
		return 0;

	case EJS_TYPE_OBJECT:
		rc = evalObjExpr(ep, lhs, rel, rhs);
		break;

	case EJS_TYPE_BOOL:
		rc = evalBoolExpr(ep, lhs->boolean, rel, rhs->boolean);
		break;

#if BLD_FEATURE_FLOATING_POINT
	case EJS_TYPE_FLOAT:
		rc = evalFloatExpr(ep, lhs->floating, rel, rhs->floating);
		break;
#endif

	case EJS_TYPE_INT:
		rc = evalNumericExpr(ep, (EjsNum) lhs->integer, rel, 
			(EjsNum) rhs->integer);
		break;

#if BLD_FEATURE_INT64
	case EJS_TYPE_INT64:
		rc = evalNumericExpr(ep, (EjsNum) lhs->integer64, rel, 
			(EjsNum) rhs->integer64);
		break;
#endif

	case EJS_TYPE_STRING:
		rc = evalStringExpr(ep, lhs, rel, rhs);
	}

	/* MOB */
	if (lhs->type == EJS_TYPE_OBJECT) {
		ejsMakeObjLive(lhs, 0);
		mprAssert(lhs->objectState->alive == 0);
	}
	if (rhs->type == EJS_TYPE_OBJECT) {
		ejsMakeObjLive(rhs, 0);
		mprAssert(rhs->objectState->alive == 0);
	}

	return rc;
}

/******************************************************************************/
#if BLD_FEATURE_FLOATING_POINT
/*
 *	Expressions with floating operands
 */

static int evalFloatExpr(Ejs *ep, double l, int rel, double r) 
{
	double	lval;
	int		logical;

	lval = 0;
	logical = 0;

	switch (rel) {
	case EJS_EXPR_PLUS:
		lval = l + r;
		break;
	case EJS_EXPR_INC:
		lval = l + 1;
		break;
	case EJS_EXPR_MINUS:
		lval = l - r;
		break;
	case EJS_EXPR_DEC:
		lval = l - 1;
		break;
	case EJS_EXPR_MUL:
		lval = l * r;
		break;
	case EJS_EXPR_DIV:
		lval = l / r;
		break;
	default:
		logical++;
		break;
	}

	/*
	 *	Logical operators
	 */
	if (logical) {

		switch (rel) {
		case EJS_EXPR_EQ:
			lval = l == r;
			break;
		case EJS_EXPR_NOTEQ:
			lval = l != r;
			break;
		case EJS_EXPR_LESS:
			lval = (l < r) ? 1 : 0;
			break;
		case EJS_EXPR_LESSEQ:
			lval = (l <= r) ? 1 : 0;
			break;
		case EJS_EXPR_GREATER:
			lval = (l > r) ? 1 : 0;
			break;
		case EJS_EXPR_GREATEREQ:
			lval = (l >= r) ? 1 : 0;
			break;
		case EJS_EXPR_BOOL_COMP:
			lval = (r == 0) ? 1 : 0;
			break;
		default:
			ejsError(ep, EJS_SYNTAX_ERROR, "Bad operator %d", rel);
			return -1;
		}
		ejsWriteVarAsBoolean(ep, ep->result, lval != 0);

	} else {
		ejsWriteVarAsFloat(ep, ep->result, lval);
	}
	return 0;
}

#endif /* BLD_FEATURE_FLOATING_POINT */
/******************************************************************************/
/*
 *	Expressions with object operands
 */

static int evalObjExpr(Ejs *ep, EjsVar *lhs, int rel, EjsVar *rhs) 
{
	int		lval;

	switch (rel) {
	case EJS_EXPR_EQ:
		lval = lhs->objectState == rhs->objectState;
		break;
	case EJS_EXPR_NOTEQ:
		lval = lhs->objectState != rhs->objectState;
		break;
	default:
		ejsError(ep, EJS_SYNTAX_ERROR, "Bad operator %d", rel);
		return -1;
	}
	ejsWriteVarAsBoolean(ep, ep->result, lval);
	return 0;
}

/******************************************************************************/
/*
 *	Expressions with boolean operands
 */

static int evalBoolExpr(Ejs *ep, int l, int rel, int r) 
{
	int		lval;

	switch (rel) {
	case EJS_EXPR_EQ:
		lval = l == r;
		break;
	case EJS_EXPR_NOTEQ:
		lval = l != r;
		break;
	case EJS_EXPR_BOOL_COMP:
		lval = (r == 0) ? 1 : 0;
		break;
	default:
		ejsError(ep, EJS_SYNTAX_ERROR, "Bad operator %d", rel);
		return -1;
	}
	ejsWriteVarAsBoolean(ep, ep->result, lval);
	return 0;
}

/******************************************************************************/
/*
 *	Expressions with numeric operands
 */

static int evalNumericExpr(Ejs *ep, EjsNum l, int rel, EjsNum r) 
{
	EjsNum	lval;
	int		logical;

	lval = 0;
	logical = 0;

	switch (rel) {
	case EJS_EXPR_PLUS:
		lval = l + r;
		break;
	case EJS_EXPR_INC:
		lval = l + 1;
		break;
	case EJS_EXPR_MINUS:
		lval = l - r;
		break;
	case EJS_EXPR_DEC:
		lval = l - 1;
		break;
	case EJS_EXPR_MUL:
		lval = l * r;
		break;
	case EJS_EXPR_DIV:
		if (r != 0) {
			lval = l / r;
		} else {
			ejsError(ep, EJS_RANGE_ERROR, "Divide by zero");
			return -1;
		}
		break;
	case EJS_EXPR_MOD:
		if (r != 0) {
			lval = l % r;
		} else {
			ejsError(ep, EJS_RANGE_ERROR, "Modulo zero");
			return -1;
		}
		break;
	case EJS_EXPR_LSHIFT:
		lval = l << r;
		break;
	case EJS_EXPR_RSHIFT:
		lval = l >> r;
		break;

	default:
		logical++;
		break;
	}

	/*
	 *	Logical operators
	 */
	if (logical) {

		switch (rel) {
		case EJS_EXPR_EQ:
			lval = l == r;
			break;
		case EJS_EXPR_NOTEQ:
			lval = l != r;
			break;
		case EJS_EXPR_LESS:
			lval = (l < r) ? 1 : 0;
			break;
		case EJS_EXPR_LESSEQ:
			lval = (l <= r) ? 1 : 0;
			break;
		case EJS_EXPR_GREATER:
			lval = (l > r) ? 1 : 0;
			break;
		case EJS_EXPR_GREATEREQ:
			lval = (l >= r) ? 1 : 0;
			break;
		case EJS_EXPR_BOOL_COMP:
			lval = (r == 0) ? 1 : 0;
			break;
		default:
			ejsError(ep, EJS_SYNTAX_ERROR, "Bad operator %d", rel);
			return -1;
		}
		ejsWriteVarAsBoolean(ep, ep->result, lval != 0);

	} else {
		ejsWriteVarAsNumber(ep, ep->result, lval);
	}
	return 0;
}

/******************************************************************************/
/*
 *	Expressions with string operands
 */

static int evalStringExpr(Ejs *ep, EjsVar *lhs, int rel, EjsVar *rhs)
{
	int		lval;

	mprAssert(ep);
	mprAssert(lhs);
	mprAssert(rhs);

	switch (rel) {
	case EJS_EXPR_LESS:
		lval = strcmp(lhs->string, rhs->string) < 0;
		break;
	case EJS_EXPR_LESSEQ:
		lval = strcmp(lhs->string, rhs->string) <= 0;
		break;
	case EJS_EXPR_GREATER:
		lval = strcmp(lhs->string, rhs->string) > 0;
		break;
	case EJS_EXPR_GREATEREQ:
		lval = strcmp(lhs->string, rhs->string) >= 0;
		break;
	case EJS_EXPR_EQ:
		lval = strcmp(lhs->string, rhs->string) == 0;
		break;
	case EJS_EXPR_NOTEQ:
		lval = strcmp(lhs->string, rhs->string) != 0;
		break;
	case EJS_EXPR_PLUS:
		/*
 		 *	This differs from all the above operations. We append rhs to lhs.
		 */
		ejsClearVar(ep, ep->result);
		ejsStrcat(ep, ep->result, lhs);
		ejsStrcat(ep, ep->result, rhs);
		return 0;

	case EJS_EXPR_INC:
	case EJS_EXPR_DEC:
	case EJS_EXPR_MINUS:
	case EJS_EXPR_DIV:
	case EJS_EXPR_MOD:
	case EJS_EXPR_LSHIFT:
	case EJS_EXPR_RSHIFT:
	default:
		ejsSyntaxError(ep, "Bad operator");
		return -1;
	}

	ejsWriteVarAsBoolean(ep, ep->result, lval);
	return 0;
}

/******************************************************************************/
/*
 *	Evaluate a method. obj is set to the current object if a method is being
 *	run.
 */

static int evalMethod(Ejs *ep, EjsVar *obj, EjsProc *proc, int flags)
{
	EjsProperty		*pp;
	EjsVar			*saveThis, *prototype;
	int				saveThisPerm, rc, fid;

	mprAssert(ep); 

	rc = 0;
	fid = -1;
	saveThis = 0;
	saveThisPerm = 0;
	prototype = proc->fn;

	if (prototype == 0) {
		ejsError(ep, EJS_EVAL_ERROR, "Undefined method");
		return EJS_STATE_ERR;
	}

	if (prototype->type == EJS_TYPE_OBJECT) {
		prototype = ejsGetPropertyAsVar(ep, prototype, proc->procName);
	}

	if (prototype) {
		/*
		 *	Create a new variable stack frame. ie. new local variables.
		 *	Some C methods (eg. include) don't create a new local context.
		 */
		if (! (prototype->flags & EJS_NO_LOCAL)) {
			fid = ejsOpenBlock(ep);
			if (fid < 0) {
				return EJS_STATE_ERR;
			}
			mprAssert(ejsBlockInUse(ep->local));

			pp = ejsSetProperty(ep, ep->local, "this", obj);
			ejsMakePropertyEnumerable(pp, 0);

			/*
			 *	Optimization. Save "this" during this block.
			 */
			saveThis = ep->thisObject;
			ep->thisObject = ejsGetVarPtr(pp);
			saveThisPerm = ejsMakeObjPermanent(saveThis, 1);
		}

		switch (prototype->type) {
		default:
			mprAssert(0);
			break;

		case EJS_TYPE_STRING_CMETHOD:
			rc = callStringCMethod(ep, obj, proc, prototype);
			break;

		case EJS_TYPE_CMETHOD:
			rc = callCMethod(ep, obj, proc, prototype);
			break;

		case EJS_TYPE_METHOD:
			rc = callMethod(ep, obj, proc, prototype);
			break;
		}

		if (fid >= 0) {
			ejsMakeObjPermanent(saveThis, saveThisPerm);
			ep->thisObject = saveThis;
			mprAssert(ejsBlockInUse(ep->local));
			mprAssert(ejsBlockInUse(ep->thisObject));
			ejsCloseBlock(ep, fid);
		}
	}

	return rc;
}

/******************************************************************************/
/*
 *	Create a new object and call all required constructors.
 *	obj may be null in which case we look globally for className.
 */

EjsVar *ejsCreateObjUsingArgvInternal(EJS_LOC_DEC(ep, loc), EjsVar *obj, 
	const char *className, MprArray *args)
{
	EjsVar		*baseClass, *objectClass, *thisObj;
	int			rc;

	mprAssert(className && *className);

	/*
 	 *	Create a new object of the required class and pass it into the 
	 *	constructor as the "this" local variable. 
	 */
	baseClass = ejsGetClass(ep, obj, className);
	if (baseClass == 0) {

		if (obj && obj->objectState->className &&
			strcmp(obj->objectState->className, className) == 0) {
			/*
			 *	Handle case where we are calling the constructor inside
			 *	the class. In this case, obj == baseClass.
			 */
			thisObj = ejsCreateSimpleObjUsingClassInt(EJS_LOC_PASS(ep, loc), 
				obj);

		} else {

			/*
			 *	If the baseClass does not exist, try to create an Object
			 *	We do this for compatibility with JS 1.5 style new Function.
			 *	MOB -- but this masks an error if we really need className.
			 */
			objectClass = ejsGetClass(ep, 0, "Object");
			thisObj = ejsCreateSimpleObjUsingClassInt(EJS_LOC_PASS(ep, loc), 
				objectClass);
		}

	} else {
		thisObj = ejsCreateSimpleObjUsingClassInt(EJS_LOC_PASS(ep, loc), 
			baseClass);
	}

	if (thisObj == 0) {
		ejsMemoryError(ep);
		return 0;
	}

	/*
	 *	Make the object permanent. While currently not alive, the constructor 
	 *	below may make the object alive.
	 */
	ejsMakeObjPermanent(thisObj, 1);
	mprAssert(! ejsObjIsCollectable(thisObj));

	rc = 0;
	if (baseClass) {
		if (! baseClass->objectState->noConstructor) {
			rc = callConstructor(ep, thisObj, baseClass, args);
		}
	} else {
		/*
		 *	className is the function name when calling new on functions
		 */
		rc = ejsRunMethod(ep, thisObj, className, args); 
	}

	/*
	 *	Constructor may change the type to a non-object. 
	 *	Function() does this. Ensure object is not collectable yet.
	 */
	if (ejsVarIsObject(thisObj)) {
		ejsMakeObjPermanent(thisObj, 0);
		ejsMakeObjLive(thisObj, 0);
	}

	if (rc < 0) {
		if (rc == MPR_ERR_NOT_FOUND) {
			/* No constructor (default) */
			return thisObj;
		}
		if (! (ep->flags & EJS_FLAGS_EXIT)) {
			if (! ep->gotException) {
				ejsMemoryError(ep);
			}
		}
		ejsFreeVar(ep, thisObj);
		return 0;
	}

	mprAssert(ejsBlockInUse(thisObj));

	return thisObj;
}

/******************************************************************************/
/*
 *	Local vars 
 */

typedef struct CallCons {
	EjsVar		*subClassConstructor, *subClass, *method;
} CallCons;

/*
 *	Create a new object and call all required constructors.
 */

static int callConstructor(Ejs *ep, EjsVar *thisObj, EjsVar *baseClass, 
	MprArray *args)
{
	CallCons		*sp;
	int				state;

	if ((sp = pushFrame(ep, sizeof(CallCons))) == 0) {
		return EJS_STATE_ERR;
	}

	mprAssert(baseClass);
	mprAssert(baseClass->objectState);

	state = 0;

	/*
	 *	method will be null if there is no constructor for this class
	 */
	sp->method = ejsGetPropertyAsVar(ep, baseClass, 
		baseClass->objectState->className);

	if (sp->method == 0 || !ejsVarIsMethod(sp->method) || 
			!sp->method->callsSuper) {
		/*
		 * 	Invoke base class constructors in reverse order (RECURSIVE)
		 */
		sp->subClass = baseClass->objectState->baseClass;
		if (sp->subClass) {

			/*
			 *	Note that the Object class does not have a constructor for 
			 *	speed. Construction for the base Object is done via 
			 *	ejsCreateObj above. The code below will invoke constructors 
			 *	in the right order (bottom up) via recursion. MOB -- need to 
			 *	scan for super() MOB -- Bug. Fails poorly if no constructor. 
			 *	Should allows this and invoke a default constructor.
			 */
			sp->subClassConstructor = ejsGetPropertyAsVar(ep, sp->subClass, 
				sp->subClass->objectState->className);

			if (sp->subClassConstructor) {

				if (callConstructor(ep, thisObj, sp->subClass, 0) < 0) {
					if (! ep->gotException) {
						ejsMemoryError(ep);
					}
					goto err;
				}
			}
		}
	}

	if (sp->method) {
		/*
		 *	Finally, invoke the constructor for this class itself.
		 */
		state = runMethod(ep, thisObj, sp->method, 
			baseClass->objectState->className, args); 
	}

done:
	popFrame(ep, sizeof(CallCons));
	return state;

err:
	state = EJS_STATE_ERR;
	goto done;
}

/******************************************************************************/
/*
 *	Create a new object and call all required constructors using string args.
 *	MOB -- would be good to parse constructorArgs for "," and break into
 *	separate args.
 * 	Returned object is not yet collectable. Will have alive bit cleared.
 */

EjsVar *ejsCreateObj(Ejs *ep, EjsVar *obj, const char *className,
	 const char *constructorArgs)
{
	MprArray	*args;
	EjsVar		*newp, *vp;

	args = mprCreateItemArray(ep, 0, 0);
	if (args == 0) {
		return 0;
	}

	if (constructorArgs && *constructorArgs) {
		vp = ejsCreateStringVarInternal(EJS_LOC_ARGS(ep), constructorArgs);

		if (mprAddItem(args, vp) < 0) {
			mprFree(args);
			return 0;
		}
	}

	newp = ejsCreateObjUsingArgv(ep, obj, className, args);

	ejsFreeMethodArgs(ep, args);

	mprAssert(! ejsObjIsCollectable(newp));
	mprAssert(ejsBlockInUse(newp));

	return newp;
}

/******************************************************************************/

static int callStringCMethod(Ejs *ep, EjsVar *obj, EjsProc *proc,
	EjsVar *prototype)
{
	EjsVar 		**argValues;
	MprArray	*actualArgs;
	char		**argBuf, *str;
	int			i, rc;

	actualArgs = proc->args;
	argValues = (EjsVar**) actualArgs->items;

	if (actualArgs->length > 0) {
		argBuf = mprAlloc(ep, actualArgs->length * sizeof(char*));
		for (i = 0; i < actualArgs->length; i++) {
			str = ejsVarToString(ep, argValues[i]);
			/* MOB rc */
			argBuf[i] = mprStrdup(ep, str);
		}
	} else {
		argBuf = 0;
	}

	/*
	 *	Call the method depending on the various handle flags
	 */
	ep->userData = prototype->cMethodWithStrings.userData;
	if (prototype->flags & EJS_ALT_HANDLE) {
		/* 
		 *	Used by the AppWeb GaCompat module. The alt handle is set to the
		 *	web server request struct
		 */
		rc = ((EjsAltStringCMethod) 
			prototype->cMethodWithStrings.fn)
			(ep, ep->altHandle, obj, actualArgs->length, argBuf);

	} else if (prototype->flags & EJS_PRIMARY_HANDLE) {
		/* 
		 *	Used by ESP. The primary handle is set to the esp struct 
		 */
		rc = (prototype->cMethodWithStrings.fn)(ep->primaryHandle, 
			obj, actualArgs->length, argBuf);

	} else {
		/* 
		 *	Used EJS for the standard procs 
		 */
		rc = (prototype->cMethodWithStrings.fn)(ep, obj, actualArgs->length, 
			argBuf);
	}

	if (actualArgs->length > 0) {
		for (i = 0; i < actualArgs->length; i++) {
			mprFree(argBuf[i]);
		}
		mprFree(argBuf);
	}
	ep->userData = 0;

	return rc;
}

/******************************************************************************/

static int callCMethod(Ejs *ep, EjsVar *obj, EjsProc *proc, EjsVar *prototype)
{
	EjsVar 		**argValues;
	MprArray	*actualArgs;
	int			rc;

	actualArgs = proc->args;
	argValues = (EjsVar**) actualArgs->items;

	ep->userData = prototype->cMethod.userData;

	/*
	 *	Call the method depending on the various handle flags
	 *	Sometimes cMethod.fn is NULL if there is no constructor for
	 *	an object.
	 */
	if (prototype->flags & EJS_ALT_HANDLE) {
		/* 
		 *	Use by the GaCompat module. The alt handle is set to the
		 *	web server request struct
		 */
		rc = ((EjsAltCMethod) prototype->cMethod.fn)
			(ep, ep->altHandle, obj, actualArgs->length, argValues);

	} else if (prototype->flags & EJS_PRIMARY_HANDLE) {
		/* 
		 *	Used by ESP. The primary handle is set to the esp struct 
		 */
		rc = (prototype->cMethod.fn)
			(ep->primaryHandle, obj, actualArgs->length, argValues);

	} else {
		/* 
		 *	Used EJS for the standard procs 
		 */
		rc = (prototype->cMethod.fn)(ep, obj, actualArgs->length, argValues);
	}

	ep->userData = 0;

	return rc;
}

/******************************************************************************/
/*
 *	Local vars 
 */

typedef struct CallMethod {
	MprArray	*formalArgs, *actualArgs;
	EjsVar		*arguments, *callee, **argValues;
	char		**argNames, buf[16];
	int			i, argumentsObj;
} CallMethod;


static int callMethod(Ejs *ep, EjsVar *obj, EjsProc *proc, EjsVar *prototype)
{
	CallMethod		*sp;
	int				i;

	if ((sp = pushFrame(ep, sizeof(CallMethod))) == 0) {
		return EJS_STATE_ERR;
	}

	sp->arguments = 0;
	sp->callee = 0;

	sp->actualArgs = proc->args;
	sp->argValues = (EjsVar**) sp->actualArgs->items;
	sp->formalArgs = prototype->method.args;
	sp->argNames = (char**) sp->formalArgs->items;

	/*
	 *	Only create arguments and callee if the function actually uses them
	 */
	sp->argumentsObj = 0;
	if (strstr(prototype->method.body, "arguments") != 0) {
		sp->argumentsObj++;

		/*
		 *	Create the arguments and callee variables
		 *	MOB -- should we make real arrays here ? YES
		 */
		sp->arguments = ejsCreateSimpleObj(ep, "Object");
		ejsSetVarName(ep, sp->arguments, "arguments");
		mprAssert(! ejsObjIsCollectable(sp->arguments));

		sp->callee = ejsCreateSimpleObj(ep, "Object");
		ejsSetVarName(ep, sp->callee, "callee");
		mprAssert(! ejsObjIsCollectable(sp->callee));

		/*
		 *	Overwrite the length property
		 */
		ejsSetPropertyToInteger(ep, sp->arguments, "length", 
			sp->actualArgs->length);
		ejsSetPropertyToInteger(ep, sp->callee, "length", 
			sp->formalArgs->length);
	}

	/*
 	 *	Define all the agruments to be set to the actual parameters
	 */
	for (i = 0; i < sp->formalArgs->length; i++) {
		if (i >= sp->actualArgs->length) {
			/* MOB -- return code */
			ejsCreateProperty(ep, ep->local, sp->argNames[i]);

		} else {
			/* MOB -- return code */
			ejsSetProperty(ep, ep->local, sp->argNames[i], sp->argValues[i]);
		}
	}

	if (sp->argumentsObj) {
		for (i = 0; i < sp->actualArgs->length; i++) {
			mprItoa(sp->buf, sizeof(sp->buf), i);
			ejsSetProperty(ep, sp->arguments, sp->buf, sp->argValues[i]);
		}

		ejsSetPropertyAndFree(ep, sp->arguments, "callee", sp->callee);
		ejsSetPropertyAndFree(ep, ep->local, "arguments", sp->arguments);
	}

	/*
	 *	Actually run the method
 	 */

	i = ejsEvalScript(ep, prototype->method.body, 0);

	popFrame(ep, sizeof(CallMethod));
	return i;
}

/******************************************************************************/
/*
 *	Run a method. Obj is set to "this" object. MethodName must exist in it
 *	or in a sub class.
 */

int ejsRunMethod(Ejs *ep, EjsVar *obj, const char *methodName, MprArray *args)
{
	EjsProperty	*pp;
	EjsProc		proc, *saveProc;
	int			rc;

	mprAssert(obj);
	mprAssert(methodName && *methodName);

	pp = ejsGetProperty(ep, obj, methodName);
	if (pp == 0) {
		/* MOB -- this should be all in some common accessor routine */
		pp = ejsGetProperty(ep, ep->local, methodName);
		if (pp == 0) {
			pp = ejsGetProperty(ep, ep->global, methodName);
			if (pp == 0) {
				ejsError(ep, EJS_REFERENCE_ERROR,
					"Undefined method \"%s\"", methodName);
				return MPR_ERR_NOT_FOUND;
			}
		}
	}

	saveProc = ep->proc;
	ep->proc = &proc;

	memset(&proc, 0, sizeof(EjsProc));

	ejsClearVar(ep, ep->result);

	/* MOB -- if closures are going to work, we need to have proc be an 
	 	Object and let the GC look after it */

	proc.fn = &pp->var;
	if (proc.fn == 0 || proc.fn->type == EJS_TYPE_UNDEFINED) {
		ep->proc = saveProc;
		return MPR_ERR_NOT_FOUND;
	}

	proc.procName = mprStrdup(ep, methodName);
	if (args == 0) {
		proc.args = mprCreateItemArray(ep, EJS_INC_ARGS, EJS_MAX_ARGS);
	} else {
		proc.args = args;
	}

	rc = evalMethod(ep, obj, &proc, 0);

	if (args) {
		proc.args = 0;
	}
	freeProc(ep, &proc);

	ep->proc = saveProc;

	return rc;
}

/******************************************************************************/
/*
 *	Run a method. Obj is set to "this" object. MethodName must exist in it
 *	or in a sub class.
 */

int ejsRunMethodCmd(Ejs *ep, EjsVar *obj, const char *methodName, 
	const char *cmdFmt, ...)
{
	MprArray	*args;
	va_list		cmdArgs;
	char		*buf, *arg, *cp;
	int			rc;

	mprAssert(methodName && *methodName);
	mprAssert(cmdFmt && *cmdFmt);

	va_start(cmdArgs, cmdFmt);
	mprAllocVsprintf(MPR_LOC_ARGS(ep), &buf, 0, cmdFmt, cmdArgs);
	va_end(cmdArgs);

	args = mprCreateItemArray(ep, EJS_INC_ARGS, EJS_MAX_ARGS);

	for (arg = cp = buf; cp && *cp; cp++) {
		if (*cp == ',') {
			*cp = 0;
			mprAddItem(args, ejsParseVar(ep, arg, 0));
			arg = cp + 1;
		}
	}
	if (cp > arg) {
		mprAddItem(args, ejsParseVar(ep, arg, 0));
	}

	rc = ejsRunMethod(ep, obj, methodName, args);

	ejsFreeMethodArgs(ep, args);
	mprFree(buf);

	return rc;
}

/******************************************************************************/
/*
 *	Run a method. Obj is set to "this" object. 
 */

static int runMethod(Ejs *ep, EjsVar *thisObj, EjsVar *method, 
	const char *methodName, MprArray *args)
{
	EjsProc		proc, *saveProc;
	int			rc;

	mprAssert(thisObj);
	mprAssert(method);

	saveProc = ep->proc;
	ep->proc = &proc;

	memset(&proc, 0, sizeof(EjsProc));

	ejsClearVar(ep, ep->result);

	/* MOB -- if closures are going to work, we need to have proc be an 
	 	Object and let the GC look after it */

	proc.fn = method;
	if (proc.fn == 0 || proc.fn->type == EJS_TYPE_UNDEFINED) {
		ep->proc = saveProc;
		return MPR_ERR_NOT_FOUND;
	}

	proc.procName = mprStrdup(ep, methodName);
	if (args == 0) {
		proc.args = mprCreateItemArray(ep, EJS_INC_ARGS, EJS_MAX_ARGS);
	} else {
		proc.args = args;
	}

	rc = evalMethod(ep, thisObj, &proc, 0);

	if (args) {
		proc.args = 0;
	}
	freeProc(ep, &proc);

	ep->proc = saveProc;

	return rc;
}

/******************************************************************************/
/*
 *	Find which object contains the property given the current context.
 *	We call this when there is no explicit object and the object must be
 *	determined by the context.
 */

static EjsVar *pickSpace(Ejs *ep, int state, const char *property, int flags)
{
	EjsVar		*obj;

	mprAssert(ep);
	mprAssert(property && *property);

	/* MOB - this is ugly and the logic is confused */

	if (flags & EJS_FLAGS_GLOBAL) {
		obj = ep->global;

	} else if (state == EJS_STATE_DEC || flags & EJS_FLAGS_LOCAL) {
		obj = ep->local;

	} else {
		/* First look local, then this and finally global */

		if (ejsGetSimpleProperty(ep, ep->local, property)) {
			obj = ep->local;

		} else if (ep->thisObject && 
				findProperty(ep, ep->thisObject, property, flags)) {
			obj = ep->thisObject;

		} else {
#if EJS_ECMA_STND
			obj = ep->global;
#else
			if (flags & EJS_FLAGS_EXE && 
					!findProperty(ep, ep->global, property, flags)) {
				obj = ep->local;
			} else {
				obj = ep->global;
			}
#endif
		}
	}
	return obj;
}

/******************************************************************************/
/*
 *	Find an object property given a object and a property name. We
 *	intelligently look in the local and global namespaces depending on
 *	our state. If not found in local or global, try base classes for method
 *	names only. Returns the property or NULL.
 *	MOB -- need to rework this API.
 */

static EjsProperty *searchSpacesForProperty(Ejs *ep, int state, EjsVar *obj, 
	char *property, int flags)
{
	EjsProperty		*pp;

	if (obj) {
		return findProperty(ep, obj, property, flags);
	}

	/* MOB -- really should have a search stack */

	pp = findProperty(ep, ep->local, property, flags);
	if (pp == 0 && state != EJS_STATE_DEC) {

		if (ep->thisObject) {
			pp = findProperty(ep, ep->thisObject, property, flags);
		}
		if (pp == 0) {
			pp = findProperty(ep, ep->global, property, flags);
		}
	}
	return pp;
}

/******************************************************************************/
/*
 *	Search an object and its base classes to find an object given an object
 *	an a property name. If not an assignment (LHS), then follow base classes. 
 *	Otherwise, just look in the specified object.
 */

static EjsProperty *findProperty(Ejs *ep, EjsVar *op, const char *property, 
	int flags)
{
	/*	MOB -- NEW. Remove when EXE fixes are in. */
	if (! (flags & EJS_FLAGS_EXE) && op->type == EJS_TYPE_UNDEFINED) {
		return 0;
	}

	if (flags & EJS_FLAGS_LHS) {
		return ejsGetPropertyPtr(ejsGetSimpleProperty(ep, op, property));

	} else {
		/*
		 *	Follow base classes
		 */
		return ejsGetPropertyPtr(ejsGetProperty(ep, op, property));
	}
}

/******************************************************************************/
/*
 *	Update result
 */

static void updateResult(Ejs *ep, int state, int flags, EjsVar *vp)
{
	if (flags & EJS_FLAGS_EXE && state != EJS_STATE_DEC) {
		ejsClearVar(ep, ep->result);
		if (vp) {
			ejsWriteVar(ep, ep->result, vp, EJS_SHALLOW_COPY);
			ejsSetVarName(ep, ep->result, vp->propertyName);
		}
	}
}

/******************************************************************************/
/*
 *	Append to the pointer value
 */

int ejsStrcat(Ejs *ep, EjsVar *dest, EjsVar *src)
{
	char	*oldBuf, *buf, *str;
	int		oldLen, newLen, len;

	mprAssert(dest);
	mprAssert(ejsVarIsString(src));

	if (ejsVarIsValid(dest)) {

		if (! ejsVarIsString(dest)) {
			/* Bad type for dest */
			return -1;
		}

		if (! ejsVarIsString(src)) {
			str = ejsVarToString(ep, src);
			if (str == 0) {
				return -1;
			}
			len = strlen(str);

		} else {
			str = src->string;
			len = src->length;
		}

		oldBuf = dest->string;
		oldLen = dest->length;
		newLen = oldLen + len + 1;

		if (newLen < MPR_SLAB_STR_MAX) {
			buf = oldBuf;
		} else {
			buf = mprRealloc(ep, oldBuf, newLen);
			if (buf == 0) {
				return -1;
			}
			dest->string = buf;
		}
		memcpy(&buf[oldLen], str, len);
		dest->length += len;

	} else {
		ejsWriteVarAsString(ep, dest, src->string);
	}
	return 0;
}

/******************************************************************************/
/*
 *	Exit the script
 */

void ejsExit(Ejs *ep, int status)
{
	ep->scriptStatus = status;
	ep->flags |= EJS_FLAGS_EXIT;
}

/******************************************************************************/
/*
 *	Free an argument list
 */

static void freeProc(Ejs *ep, EjsProc *proc)
{
	if (proc->args) {
		ejsFreeMethodArgs(ep, proc->args);
	}

	if (proc->procName) {
		mprFree(proc->procName);
		proc->procName = NULL;
	}
}

/******************************************************************************/

void ejsFreeMethodArgs(Ejs *ep, MprArray *args)
{
	int		i;

	for (i = args->length - 1; i >= 0; i--) {
		ejsFreeVar(ep, args->items[i]);
		mprRemoveItemByIndex(args, i);
	}
	mprFree(args);
}

/******************************************************************************/
/*
 *	This method removes any new lines.  Used for else	cases, etc.
 */

static void removeNewlines(Ejs *ep, int state)
{
	int tid;

	do {
		tid = ejsLexGetToken(ep, state);
	} while (tid == EJS_TOK_NEWLINE);

	ejsLexPutbackToken(ep, tid, ep->token);
}

/******************************************************************************/

static int getNextNonSpaceToken(Ejs *ep, int state)
{
	int		tid;

	do {
		tid = ejsLexGetToken(ep, state);
	} while (tid == EJS_TOK_NEWLINE);
	return tid;
}

/******************************************************************************/

int ejsGetFlags(Ejs *ep)
{
	return ep->flags;
}

/******************************************************************************/

bool ejsIsExiting(Ejs *ep)
{
	return (ep->flags & EJS_FLAGS_EXIT) ? 1: 0;
}

/******************************************************************************/

void ejsClearExiting(Ejs *ep)
{
	ep->flags &= ~EJS_FLAGS_EXIT;
}

/******************************************************************************/

static EjsInput *getInputStruct(Ejs *ep)
{
	EjsInput	*input;

	if (ep->inputList) {
		input = ep->inputList;
		ep->inputList = input->nextInput;

	} else {
		input = mprAlloc(ep, sizeof(EjsInput));
	}
	return input;
}

/******************************************************************************/

static void freeInputStruct(Ejs *ep, EjsInput *input)
{
	input->nextInput = ep->inputList;
	ep->inputList = input;
}

/******************************************************************************/

static void *pushFrame(Ejs *ep, int size)
{
	/*
	 *	Grow down stack
	 */
	ep->stkPtr -= size;
	if (ep->stkPtr < ep->stack) {
		mprError(ep, MPR_LOC, "Exceeded parse stack");
		return 0;
	}
	return ep->stkPtr;
}

/******************************************************************************/

static void *popFrame(Ejs *ep, int size)
{
	ep->stkPtr += size;
	if (ep->stkPtr > &ep->stack[EJS_MAX_STACK]) {
		mprError(ep, MPR_LOC, "Over poped parse stack");
		return 0;
	}
	return ep->stkPtr;
}

/******************************************************************************/
#else
void ejsParserDummy() {}

/******************************************************************************/
#endif /* BLD_FEATURE_EJS */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
