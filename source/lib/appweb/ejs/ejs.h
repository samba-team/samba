/*
 *	@file 	ejs.h
 *	@brief 	Primary Embedded Javascript (ECMAScript) header.
 *	@overview This Embedded Javascript (EJS) header defines the 
 *		public API. This API should only be used by those directly 
 *		using EJS without using Embedded Server Pages (ESP). ESP 
 *		wraps all relevant APIs to expose a single consistent API.
 *		\n\n
 *		This API requires the mpr/var.h facilities to create and 
 *		manage objects and properties. 
 */
/********************************* Copyright **********************************/
/*
 *	@copy	default.g
 *	
 *	Copyright (c) Mbedthis Software LLC, 2003-2005. All Rights Reserved.
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

#ifndef _h_EJS
#define _h_EJS 1

#include	"lib/appweb/mpr/miniMpr.h"
#include	"lib/appweb/mpr/var.h"

#ifdef __cplusplus
extern "C" {
#endif

/********************************* Prototypes *********************************/

typedef MprVarHandle 	EjsId;
typedef MprVarHandle 	EjsHandle;

/*
 *	Multithreaded lock routines
 */
typedef void (*EjsLock)(void *lockData);
typedef void (*EjsUnlock)(void *lockData);

/********************************* Prototypes *********************************/
/*
 *	Module management
 */
extern int		ejsOpen(EjsLock lock, EjsUnlock unlock, void *lockData);
extern void 	ejsClose(void);
extern EjsId	ejsOpenEngine(EjsHandle primaryHandle, EjsHandle altHandle);
extern void		ejsCloseEngine(EjsId eid);

void *ejs_save_state(void);
void ejs_restore_state(void *ptr);

/*
 *	Evaluation functions
 */
extern int		ejsEvalFile(EjsId eid, char *path, MprVar *result, char **emsg);
extern int		ejsEvalScript(EjsId eid, char *script, MprVar *result,
					char **emsg);
extern int 		ejsRunFunction(int eid, MprVar *obj, const char *functionName, 
					MprArray *args);

/*
 *	Composite variable get / set routines. Can also use the MPR property
 *	routines on an object variable.
 */
extern MprVar	ejsCreateObj(const char *name, int hashSize);
extern MprVar	ejsCreateArray(const char *name, int hashSize);
extern bool		ejsDestroyVar(MprVar *obj);
extern int 		ejsCopyVar(EjsId eid, const char *var, MprVar *value, 
					bool copyRef);
extern int 		ejsReadVar(EjsId eid, const char *var, MprVar *value);
extern int	 	ejsWriteVar(EjsId eid, const char *var, MprVar *value);
extern int	 	ejsWriteVarValue(EjsId eid, const char *var, MprVar value);
extern int		ejsDeleteVar(EjsId eid, const char *var);

extern MprVar	*ejsGetLocalObject(EjsId eid);
extern MprVar	*ejsGetGlobalObject(EjsId eid);

/*
 *	Function routines
 */
extern void 	ejsDefineFunction(EjsId eid, const char *functionName, 
					char *args, char *body);
extern void 	ejsDefineCFunction(EjsId eid, const char *functionName, 
					MprCFunction fn, void *thisPtr, int flags);
extern void		ejsDefineStringCFunction(EjsId eid, const char *functionName, 
					MprStringCFunction fn, void *thisPtr, int flags);
extern void 	*ejsGetThisPtr(EjsId eid);
extern MprVar	*ejsGetReturnValue(EjsId eid);
extern int		ejsGetLineNumber(EjsId eid);
extern int 		ejsParseArgs(int argc, char **argv, char *fmt, ...);
extern void 	ejsSetErrorMsg(EjsId eid, const char* fmt, ...) 
					PRINTF_ATTRIBUTE(2,3);
extern void		ejsSetReturnValue(EjsId eid, MprVar value);
extern void		ejsSetReturnString(EjsId eid, const char *str);

#ifdef __cplusplus
}
#endif
#endif /* _h_EJS */

/*****************************************************************************/

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
