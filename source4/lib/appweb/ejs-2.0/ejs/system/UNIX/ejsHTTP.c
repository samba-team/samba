/*
 *	@file 	ejsHTTP.c
 *	@brief 	HTTP class for the EJ System Object Model
 */
/********************************** Copyright *********************************/
/*
 *	Copyright (c) Mbedthis Software LLC, 2005-2006. All Rights Reserved.
 */
/********************************** Includes **********************************/

#include	"ejs.h"

#if UNUSED
/*********************************** Defines **********************************/

#define EJS_WEB_PROPERTY 	"-web"
#define EJS_HTTP_PROPERTY 	"-http"

#define EJS_HTTP_DISPOSED	550

/*
 *	Control structure for one HTTP request structure
 */
typedef struct HTTPControl {
	Ejs				*ejs;
	IWebResp		*webResp;
	AEECallback		*callback;
	MprBuf			*buf;
	EjsVar			*thisObj;
	char			*url;
	MprTime			requestStarted;
	uint			timeout;
} HTTPControl;

/****************************** Forward Declarations **************************/

static void cleanup(HTTPControl *hp);
static int	createWeb(Ejs *ejs, EjsVar *thisObj);
static void brewCallback(HTTPControl *hp);
static int	httpDestructor(Ejs *ejs, EjsVar *vp);
static void httpCallback(HTTPControl *hp, int responseCode);
static int 	setCallback(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv);

/******************************************************************************/
/*
 *	Constructor
 */

int ejsHTTPConstructor(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc != 0 && argc != 2) {
		ejsError(ejs, EJS_ARG_ERROR, 
			"Bad usage: HTTP([obj = this, method = onComplete]);");
		return -1;
	}

	if (createWeb(ejs, thisObj) < 0) {
		return -1;
	}

	setCallback(ejs, thisObj, argc, argv);
	return 0;
}

/******************************************************************************/

static int createWeb(Ejs *ejs, EjsVar *thisObj)
{
	MprApp	*app;
	void	*web;

	app = mprGetApp(ejs);

	/*
	 *	Create one instance of IWeb for the entire application. Do it here
	 *	so only widgets that require HTTP incurr the overhead.
	 */
	web = mprGetKeyValue(ejs, "bpWeb");
	if (web == 0) {
		if (ISHELL_CreateInstance(app->shell, AEECLSID_WEB, &web) != SUCCESS) {
			ejsError(ejs, EJS_IO_ERROR, "Can't create IWEB");
			return -1;
		}
	}
	mprSetKeyValue(ejs, "bpWeb", web);
	return 0;
}

/******************************************************************************/
/************************************ Methods *********************************/
/******************************************************************************/
/*
 *	function setCallback(obj, methodString);
 */

static int setCallback(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc >= 1) {
		ejsSetProperty(ejs, thisObj, "obj", argv[0]);
	} else {
		ejsSetProperty(ejs, thisObj, "obj", thisObj);
	}

	if (argc >= 2) {
		ejsSetProperty(ejs, thisObj, "method", argv[1]);
	} else {
		ejsSetPropertyToString(ejs, thisObj, "method", "onComplete");
	}

	return 0;
}

/******************************************************************************/
/*
 *	function fetch();
 */

static int fetchProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	HTTPControl		*hp;
	EjsProperty 	*pp;
	MprApp			*app;
	IWeb			*web;

	if (argc != 1 || !ejsVarIsString(argv[0])) {
		ejsError(ejs, EJS_ARG_ERROR, "Bad usage: fetch(url)");
		return -1;
	}

	app = mprGetApp(ejs);
	web = (IWeb*) mprGetKeyValue(ejs, "bpWeb");

	/*
	 *	Web options
 	 *
	 *	WEBOPT_USERAGENT (char*)		sets user agent
	 *	WEBOPT_HANDLERDATA (void*)
	 *	WEBOPT_CONNECTTIMEOUT (uint)	msec
	 *	WEBOPT_CONTENTLENGTH (long)
	 *	WEBOPT_IDLECONNTIMEOUT (int)
	 *	WEBOPT_ACTIVEXACTIONST (uint)	Number of active requests
	 *
	 *	WEBREQUEST_REDIRECT				redirect transparently
	 *
	 */

	hp = mprAllocType(ejs, HTTPControl);
	if (hp == 0) {
		ejsMemoryError(ejs);
		return -1;
	}

	hp->ejs = ejs;
	hp->buf = mprCreateBuf(hp, MPR_BUF_INCR, MPR_MAX_BUF);
	if (hp->buf == 0) {
		mprFree(hp);
		ejsMemoryError(ejs);
		return -1;
	}

	/*
	 *	We copy thisObj because we need to preserve both the var and the object.
	 *	We pass the var to brewCallback and so it must persist. The call to
	 *	ejsMakeObjPermanent will stop the GC from collecting the object.
	 */
	hp->thisObj = ejsDupVar(ejs, thisObj, EJS_SHALLOW_COPY);
	ejsSetVarName(ejs, hp->thisObj, "internalHttp");

	/*
	 *	Must keep a reference to the http object
	 */
	ejsMakeObjPermanent(hp->thisObj, 1);

	/*
	 *	Make a property so we can access the HTTPControl structure from other
	 *	methods.
	 */
	pp = ejsSetPropertyToPtr(ejs, thisObj, EJS_HTTP_PROPERTY, hp, 0);
	ejsMakePropertyEnumerable(pp, 0);
	ejsSetObjDestructor(ejs, hp->thisObj, httpDestructor);

	hp->url = mprStrdup(hp, argv[0]->string);

	hp->timeout = ejsGetPropertyAsInteger(ejs, thisObj, "timeout");
	mprGetTime(hp, &hp->requestStarted);

	hp->callback = mprAllocTypeZeroed(hp, AEECallback);
	CALLBACK_Init(hp->callback, brewCallback, hp);

	hp->webResp = 0;
	IWEB_GetResponse(web, 
		(web, &hp->webResp, hp->callback, hp->url,
		WEBOPT_HANDLERDATA, hp, 
		WEBOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)", 
		WEBOPT_CONNECTTIMEOUT, hp->timeout,
		WEBOPT_COPYOPTS, TRUE,
		WEBOPT_CONTENTLENGTH, 0,
		WEBOPT_END));

	ejsSetPropertyToString(ejs, thisObj, "status", "active");

	return 0;
}

/******************************************************************************/
/*
 *	Called whenver the http object is deleted. 
 */

static int httpDestructor(Ejs *ejs, EjsVar *thisObj)
{
	HTTPControl		*hp;

	/*
	 *	If the httpCallback has run, then this property will not exist
 	 */
	hp = ejsGetPropertyAsPtr(ejs, thisObj, EJS_HTTP_PROPERTY);

	if (hp) {
		cleanup(hp);
	}

	return 0;
}

/******************************************************************************/
/*
 *	Stop the request immediately without calling the callback
 */

static int stopProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	HTTPControl		*hp;

	hp = ejsGetPropertyAsPtr(ejs, thisObj, EJS_HTTP_PROPERTY);

	if (hp) {
		cleanup(hp);
	}

	return 0;
}

/******************************************************************************/
/*
 *	Brew HTTP callback. Invoked for any return data.
 */

static void brewCallback(HTTPControl *hp)
{
	Ejs				*ejs;
	EjsVar			*thisObj;
	ISource			*source;
	WebRespInfo		*info;
	char 			data[MPR_BUF_INCR];
	int 			bytes;

	mprAssert(hp);
	mprAssert(hp->webResp);

	info = IWEBRESP_GetInfo(hp->webResp);

	if (info == 0) {
		mprAssert(info);
		/* should not happen */
		return;
	}

	ejs = hp->ejs;
	thisObj = hp->thisObj;

	if (! WEB_ERROR_SUCCEEDED(info->nCode)) {
		ejsSetPropertyToString(ejs, thisObj, "status", "error");
		httpCallback(hp, info->nCode);
		return;
	}

	if (hp->timeout) {
		if (mprGetTimeRemaining(hp, hp->requestStarted, hp->timeout) <= 0) {
			ejsSetPropertyToString(ejs, thisObj, "status", "timeout");
			httpCallback(hp, 504);
			return;
		}
	}

	/*
	 *	Normal success
	 */
	source = info->pisMessage;
	mprAssert(source);

	bytes = ISOURCE_Read(source, data, sizeof(data));

	switch (bytes) {
	case ISOURCE_WAIT:								// No data yet
		ISOURCE_Readable(source, hp->callback);
		break;

	case ISOURCE_ERROR:
		ejsSetPropertyToString(ejs, thisObj, "status", "error");
		httpCallback(hp, info->nCode);
		break;

	case ISOURCE_END:
		mprAddNullToBuf(hp->buf);
		ejsSetPropertyToString(ejs, thisObj, "status", "complete");
		httpCallback(hp, info->nCode);
		break;

	default:
		if (bytes > 0) {
			if (mprPutBlockToBuf(hp->buf, data, bytes) != bytes) {
				ejsSetPropertyToString(ejs, thisObj, "status", "partialData");
				httpCallback(hp, 500);
			}
		}
		ISOURCE_Readable(source, hp->callback);
		break;
	}
}

/******************************************************************************/
/*
 *	Invoke the HTTP completion method
 */

static void httpCallback(HTTPControl *hp, int responseCode)
{
	Ejs				*ejs;
	EjsVar			*thisObj, *callbackObj;
	MprArray		*args;
	char			*msg;
	const char		*callbackMethod;

	mprAssert(hp);
	mprAssert(hp->webResp);

	thisObj = hp->thisObj;
	ejs = hp->ejs;

	ejsSetPropertyToInteger(ejs, thisObj, "responseCode", responseCode);
	if (mprGetBufLength(hp->buf) > 0) {
		ejsSetPropertyToBinaryString(ejs, thisObj, "responseData", 
			mprGetBufStart(hp->buf), mprGetBufLength(hp->buf));
	}

	callbackObj = ejsGetPropertyAsVar(ejs, thisObj, "obj");
	callbackMethod = ejsGetPropertyAsString(ejs, thisObj, "method");

	if (callbackObj != 0 && callbackMethod != 0) {

		args = mprCreateItemArray(ejs, EJS_INC_ARGS, EJS_MAX_ARGS);
		mprAddItem(args, ejsDupVar(ejs, hp->thisObj, EJS_SHALLOW_COPY));

		if (ejsRunMethod(ejs, callbackObj, callbackMethod, args) < 0) {
			msg = ejsGetErrorMsg(ejs);
			mprError(ejs, MPR_LOC, "HTTP callback failed. Details: %s", msg);
		}
		ejsFreeMethodArgs(ejs, args);

	} else if (ejsRunMethod(ejs, thisObj, "onComplete", 0) < 0) {
		msg = ejsGetErrorMsg(ejs);
		mprError(ejs, MPR_LOC, "HTTP onComplete failed. Details: %s", msg);
	}

	cleanup(hp);
}

/******************************************************************************/
/*
 *	Cleanup
 */

static void cleanup(HTTPControl *hp)
{
	Ejs			*ejs;
	MprApp		*app;
	int			rc;

	mprAssert(hp);
	mprAssert(hp->webResp);

	ejs = hp->ejs;

	if (hp->webResp) {
		rc = IWEBRESP_Release(hp->webResp);
		// mprAssert(rc == 0);
		hp->webResp = 0;
	}

	if (hp->callback) {
		CALLBACK_Cancel(hp->callback);
		mprFree(hp->callback);
		hp->callback = 0;
	}		

	/*
	 *	Once the property is deleted, then if the destructor runs, it will
	 *	notice that the EJS_HTTP_PROPERTY is undefined.
	 */
	ejsDeleteProperty(ejs, hp->thisObj, EJS_HTTP_PROPERTY);

	/*
 	 *	Allow garbage collection to work on thisObj
	 */
	ejsMakeObjPermanent(hp->thisObj, 0);
	ejsFreeVar(ejs, hp->thisObj);

	mprFree(hp->buf);
	mprFree(hp->url);

	mprFree(hp);

	app = mprGetApp(ejs);


	ISHELL_SendEvent(app->shell, (AEECLSID) app->classId, EVT_USER, 0, 0);
}

/******************************************************************************/
/******************************** Initialization ******************************/
/******************************************************************************/

int ejsDefineHTTPClass(Ejs *ejs)
{
	EjsVar	*httpClass;

	httpClass =  
		ejsDefineClass(ejs, "HTTP", "Object", ejsHTTPConstructor);
	if (httpClass == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}

	/*
	 *	Define the methods
	 */
	ejsDefineCMethod(ejs, httpClass, "fetch", fetchProc, 0);
	ejsDefineCMethod(ejs, httpClass, "stop", stopProc, 0);
	ejsDefineCMethod(ejs, httpClass, "setCallback", setCallback, 0);

#if FUTURE
	ejsDefineCMethod(ejs, httpClass, "put", put, 0);
	ejsDefineCMethod(ejs, httpClass, "upload", upload, 0);
	ejsDefineCMethod(ejs, httpClass, "addUploadFile", addUploadFile, 0);
	ejsDefineCMethod(ejs, httpClass, "addPostData", addPostData, 0);
	ejsDefineCMethod(ejs, httpClass, "setUserPassword", setUserPassword, 0);
	ejsDefineCMethod(ejs, httpClass, "addCookie", addCookie, 0);
#endif

	/*
	 *	Define properties 
	 */
	ejsSetPropertyToString(ejs, httpClass, "status", "inactive");

	/*	This default should come from player.xml */

	ejsSetPropertyToInteger(ejs, httpClass, "timeout", 30 * 1000);
	ejsSetPropertyToInteger(ejs, httpClass, "responseCode", 0);

	return ejsObjHasErrors(httpClass) ? MPR_ERR_CANT_INITIALIZE: 0;
}

/******************************************************************************/

void ejsTermHTTPClass(Ejs *ejs)
{
	IWeb		*web;
	int			rc;

	web = (IWeb*) mprGetKeyValue(ejs, "bpWeb");
	if (web) {
		rc = IWEB_Release(web);
		mprAssert(rc == 0);
	}
}

#endif
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
