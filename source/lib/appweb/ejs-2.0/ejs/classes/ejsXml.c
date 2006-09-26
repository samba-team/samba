/*
 *	@file 	ejsXml.c
 *	@brief 	E4X XML support
 */
/********************************* Copyright **********************************/
/*
 *	@copy	default
 *	
 *	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
 *	Copyright (c) Michael O'Brien, 1994-1995. All Rights Reserved.
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
/************************************ Doc *************************************/
/*
 *	Javascript class definition
 *
 *	class XML {
 *		public XML();
 *		public XML(string xmlString);			// "<tag... "
 *		public XML(string file);				// "file"
 *
 *		public void load(string file);
 *		public void save(string file);
 *		public Array children();
 *		public Array attributes();
 *	}
 *
	[[Internal Properties / Methods]]
	- prototype				- Ptr to class prototype (base class)
	- class					- Type of class
		Object.prototype.toString
	- Value					- 
	- Get(name)				- Returns the value
	- Put(name, value)		- Sets the value
	- HasProperty(name)		- Bool if property exists
	- Delete(name)			- Delete property
	- DefaultValue(hint)	- Return default primitive (not obj) value
		toString, if result is obj, then call valueOf
		if hint is number, then call valueOf, then toString
	- Construct(arg list)	- Constructor
	- Call(arg list)		- Function call
	- HasInstance(value)	- ??
	- Scope					- Frame scope chain
	- Match(string, index)	- Regexp match

	- Example:
 		XML attribute @name
 		@*
 		*
		var node = new XML("<order/>");
		Operators:
			var prices = order..price;
			var urgentItems = order.item(@level == "rush");
			var itemAttrs = order.item[0].@*;			# @ for attributes
		XML Literals
			order.customer.address = 
				<address>.....
					<zip>{zipCode}</zip>			Where {var} is a JS var
					<tag attribute={prefix}> ...	Also for attributes
				</address>
		Omit namespaces
		Example:
			var html = <html/>;
			html.head.title = "My title";
			head.body@bgcolor = "#e4e4e4";
*/

/********************************** Includes **********************************/

#include	"ejs.h"
#include	"exml.h"

/************************************ Data ************************************/
#if BLD_FEATURE_EJS_E4X

/*
 *	Per tag state
 */
typedef struct XmlTagState {
	EjsVar	*obj;
	EjsVar	*attributes;
	EjsVar	*comments;
} XmlTagState;

/*
 *	Parser state
 */
typedef struct XmlState {
	Ejs			*ep;
	EjsVar		*xmlClass;
	EjsVar		*xmlListClass;
	XmlTagState	nodeStack[E4X_MAX_NODE_DEPTH];
	int			topOfStack;
	long		inputSize;
	long		inputPos;
	const char	*inputBuf;
	const char	*fileName;
} XmlState;

/****************************** Forward Declarations **************************/
/*
 *	XML methods
 */
static int 	text(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	name(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	load(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	save(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	toString(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	valueOf(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);

/* MOB -- temp */
static int 	getList(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int setText(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);

#if FUTURE
static int 	length(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	toXmlString(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);

static int 	appendChild(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	attributes(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	child(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	children(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	comments(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	decendants(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	elements(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	insertChildAfter(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	insertChildBefore(Ejs *ep, EjsVar *thisObj, int argc, 
				EjsVar **argv);
static int 	replace(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	setName(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
static int 	text(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv);
#endif

/*
 *	Internal methods
 */
static EjsVar	*createXmlProperty(Ejs *ep, EjsVar *obj, const char *property);
static int		deleteXmlProperty(Ejs *ep, EjsVar *obj, const char *property);
static EjsVar	*getXmlProperty(Ejs *ep, EjsVar *obj, const char *property);
static EjsVar	*setXmlProperty(Ejs *ep, EjsVar *obj, const char *property, 
					const EjsVar *value);
static int 		loadXmlString(Ejs *ep, EjsVar *thisObj, const char *xmlString);

/*
 *	XMLList methods
 */
static EjsVar	*createXmlListProperty(Ejs *ep, EjsVar *obj, 
					const char *property);
static int		deleteXmlListProperty(Ejs *ep, EjsVar *obj, 
					const char *property);
static EjsVar	*getXmlListProperty(Ejs *ep, EjsVar *obj, const char *property);
static EjsVar	*setXmlListProperty(Ejs *ep, EjsVar *obj, const char *property, 
					const EjsVar *value);

/*
 *	Misc
 */
static int 	readFileData(Exml *xp, void *data, char *buf, int size);
static int 	readStringData(Exml *xp, void *data, char *buf, int size);
static int	parserHandler(Exml *xp, int state, const char *tagName, 
				const char *attName, const char *value);
static void termParser(Exml *xp);
static Exml *initParser(Ejs *ep, EjsVar *thisObj, const char *fileName);
static int 	getNumElements(EjsVar *obj);
static int 	getText(MprBuf *buf, EjsVar *obj);
static int 	xmlToString(Ejs *ep, MprBuf *buf, EjsVar *obj, int indentLevel);
static void indent(MprBuf *bp, int level);
static char *cleanTagName(char *name);

/******************************************************************************/
/*
 *	Define the E4X classes (XML, XMLList)
 */

int ejsDefineXmlClasses(Ejs *ep)
{
	EjsMethods	*methods;
	EjsVar		*xmlClass, *xmlListClass;

	/*
	 *	Create the XML class
 	 */
	xmlClass = ejsDefineClass(ep, "XML", "Object", ejsXmlConstructor);
	if (xmlClass == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}

	/*
	 *	Define the XML class methods
	 */
	ejsDefineCMethod(ep, xmlClass, "text", text, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, xmlClass, "name", name, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, xmlClass, "load", load, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, xmlClass, "save", save, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, xmlClass, "toString", toString, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, xmlClass, "valueOf", valueOf, EJS_NO_LOCAL);

/*	MOB -- temporary only */
	ejsDefineCMethod(ep, xmlClass, "getList", getList, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, xmlClass, "setText", setText, EJS_NO_LOCAL);

	/*
	 *	Setup the XML internal methods. 
	 */
	methods = mprAllocTypeZeroed(ep, EjsMethods);
	xmlClass->objectState->methods = methods;

	methods->createProperty = createXmlProperty;
	methods->deleteProperty = deleteXmlProperty;
	methods->getProperty = getXmlProperty;
	methods->setProperty = setXmlProperty;

	/*
 	 *	Create the XMLList class
	 */
	xmlListClass = ejsDefineClass(ep, "XMLList", "Array", 
		ejsXmlListConstructor);

	/*
	 *	Define the XMLList class methods
	 */

	/*
	 *	Setup the XML internal methods. 
	 */
	methods = mprAllocTypeZeroed(ep, EjsMethods);
	xmlListClass->objectState->methods = methods;

	methods->createProperty = createXmlListProperty;
	methods->deleteProperty = deleteXmlListProperty;
	methods->getProperty = getXmlListProperty;
	methods->setProperty = setXmlListProperty;

	/* MOB -- need to complete xmlListClass */

	return (ejsObjHasErrors(xmlClass) || ejsObjHasErrors(xmlListClass))
		? MPR_ERR_CANT_INITIALIZE : 0;
	return 0;
}

/******************************************************************************/
/*
 *	Routine to create an XML object using a default constructor
 */

EjsVar *ejsCreateXml(Ejs *ep)
{
	EjsVar		*op;

	op = ejsCreateSimpleObj(ep, "XML");
	if (op == 0) {
		mprAssert(op);
		return op;
	}
	ejsSetVarName(ep, op, "xmlNode");

	/*
	 * 	Invoke class constructors manually (for speed and space)
	 */
	if (ejsXmlConstructor(ep, op, 0, 0) < 0) {
		mprFree(op);
		mprAssert(0);
		return 0;
	}
	return op;
}

/******************************************************************************/
/*
 *	XML constructor
 */

int ejsXmlConstructor(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	EjsVar		*vp;
	const char	*str;

	ejsSetVarFlags(thisObj, EJS_XML_FLAGS_ELEMENT);

	if (argc == 1) {
		vp = argv[0];

		if (ejsVarIsObject(vp)) {
			/* Convert DOM to XML. Not implemented */;

		} else if (ejsVarIsString(vp)) {
			str = vp->string;
			if (str == 0) {
				return 0;
			}
			if (*str == '<') {
				/* XML Literal */
				return loadXmlString(ep, thisObj, str);

			} else {
				/* Load from file */
				return load(ep, thisObj, argc, argv);
			}
		} else {
			ejsError(ep, EJS_TYPE_ERROR, "Bad type passed to XML constructor");
			return -1;
		}
	}
	return 0;
}

/******************************************************************************/
/*
 *	Routine to create an XMLList object
 */

EjsVar *ejsCreateXmlList(Ejs *ep)
{
	EjsVar		*op;

	/*	Sanity limit for size of hash table */

	op = ejsCreateSimpleObj(ep, "XMLList");
	if (op == 0) {
		mprAssert(0);
		return op;
	}
	if (ejsArrayConstructor(ep, op, 0, 0) < 0 ||
			ejsXmlConstructor(ep, op, 0, 0) < 0) {
		mprFree(op);
		mprAssert(0);
		return 0;
	}
	return op;
}

/******************************************************************************/
/*
 *	XMLList constructor
 */

int ejsXmlListConstructor(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	// ejsSetVarFlags(vp, EJS_XML_FLAGS_ELEMENT);
	return 0;
}

/******************************************************************************/
/******************************** Internal Methods ****************************/
/******************************************************************************/

static EjsVar *createXmlProperty(Ejs *ep, EjsVar *obj, const char *property)
{
	return ejsGetVarPtr(ejsCreateSimpleProperty(ep, obj, property));
}

/******************************************************************************/

static int deleteXmlProperty(Ejs *ep, EjsVar *obj, const char *property)
{
	return ejsDeleteProperty(ep, obj, property);
}

/******************************************************************************/
/*	MOB -- need ep as an arg */
static EjsVar *getXmlProperty(Ejs *ep, EjsVar *obj, const char *property)
{
#if NEW
	EjsVar	*lp;

	lp = ejsCreateXmlList(ep);
	if (isdigit(*property)) {
		/* MOB -- where do we store these. Do we need them ? */
		lp->targetObject = obj
		lp->targetProperty = property
		return getXmlListProperty(lp, property);
	}

	/*	What about a simple elment. Should it not return the text */

	if (*property == '@') {
		ap = ejsGetFirstProperty(obj, EJS_ENUM_ALL);
		while (ap) {
			vp = ejsGetVarPtr(ap);
			/*	MOB -- are attributes unique ? */
			if (vp->flags & EJS_XML_FLAGS_ATTRIBUTE &&
					strcmp(property, ap->name) == 0) {
				ejsAppendXml(lp, vp);
			}
			ap = ejsGetNexttProperty(ap, EJS_ENUM_ALL);
		}
	} else {
		while (ap) {
			vp = ejsGetVarPtr(ap);
			/*	MOB -- are attributes unique ? */
			if (vp->flags & EJS_XML_FLAGS_ELEMENT &&
					strcmp(property, ap->name) == 0) {
				ejsAppendXml(lp, vp);
			}
			ap = ejsGetNexttProperty(ap, EJS_ENUM_ALL);
		}
	}
	return l;

	//	Must always return XML or XMLList event for comments and attributes
#endif
	return ejsGetVarPtr(ejsGetSimpleProperty(ep, obj, property));
}

/******************************************************************************/

static EjsVar *setXmlProperty(Ejs *ep, EjsVar *obj, const char *property, 
	const EjsVar *value)
{
	EjsProperty		*pp;
	EjsVar			*vp;

	pp = ejsCreateSimpleProperty(ep, obj, property);
	if (pp == 0) {
		/* Should never happen */
		mprAssert(pp);
		return 0;
	}
	vp = ejsGetVarPtr(pp);
	if (ejsWriteVar(ep, vp, value, EJS_SHALLOW_COPY) < 0) {
		return 0;
	}
	return ejsGetVarPtr(pp);
}

/******************************************************************************/
/*
 NEW

static EjsVar *setXmlProperty(Ejs *ep, EjsVar *op, const char *property, 
	EjsVar *value)
{

	if ((value->objectState->baseClass != XML && 
			value->objectState->baseClass != XMLList) || 
			value->string[0] != '<') {
		ejsVarToString(luevalue.toString();
		ejsRunMethod(ep, value, "toString", 0);
		value = ejsDupVar(ep->result);

	} else {
		value = ejsDupVar(value);
	}

	if (isdigit(*property)) {
		//	ERROR -- reserved for future versions
		return 0;
	}

	if (*property == '@') {
		if (op->objectState->baseClass == XMLList) {
			if (op->obj.LENGTH_PROPERTY == 0) {
				c = "";
			} else {
				// Catenate all result of toString on all elts in list
			}
		} else {
			c = c.toString();
		}
		// Replace existing attribute of same name or insert
		return;
	}
	for (i = op->obj.LENGTH - 1; i >= 0; i--) {
		//	Delete item of same name
	}
	if (not Found) {
		Append new Xml object
			- set [[name]], [[class]] == "element"
	}

	mprFree(value);
}

 */
/******************************************************************************/
/************************************ Methods *********************************/
/******************************************************************************/

static int load(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	const char	*fileName;
	XmlState	*parser;
	Exml		*xp;
	MprFile		*file;

	if (argc != 1 || !ejsVarIsString(argv[0])) {
		ejsError(ep, EJS_ARG_ERROR, "Bad args. Usage: load(fileName);");
		return -1;
	}
	fileName = argv[0]->string;
	
	/* MOB -- not romable 
		Need rom code in MPR not MprServices
	*/
	file = mprOpen(ep, fileName, O_RDONLY, 0664);
	if (file == 0) {
		ejsError(ep, EJS_IO_ERROR, "Can't open: %s", fileName);
		return -1;
	}

	/* MOB -- should we empty thisObj of all existing properties ? */

	xp = initParser(ep, thisObj, fileName);
	parser = exmlGetParseArg(xp);

	exmlSetInputStream(xp, readFileData, (void*) file);

	if (exmlParse(xp) < 0) {
		if (! ejsGotException(ep)) {
			ejsError(ep, EJS_IO_ERROR, "Can't parse XML file: %s\nDetails %s", 
				fileName, exmlGetErrorMsg(xp));
		}
		termParser(xp);
		mprClose(file);
		return -1;
	}

	ejsSetReturnValue(ep, parser->nodeStack[0].obj);

	termParser(xp);
	mprClose(file);

	return 0;
}

/******************************************************************************/

static int loadXmlString(Ejs *ep, EjsVar *thisObj, const char *xmlString)
{
	XmlState	*parser;
	Exml		*xp;

	xp = initParser(ep, thisObj, "string");
	parser = exmlGetParseArg(xp);

	parser->inputBuf = xmlString;
	parser->inputSize = strlen(xmlString);

	exmlSetInputStream(xp, readStringData, (void*) 0);

	if (exmlParse(xp) < 0) {
		if (! ejsGotException(ep)) {
			ejsError(ep, EJS_IO_ERROR, "Can't parse XML string\nError %s", 
				exmlGetErrorMsg(xp));
		}
		termParser(xp);
		return -1;
	}

	ejsSetReturnValue(ep, parser->nodeStack[0].obj);

	termParser(xp);

	return 0;
}

/******************************************************************************/

static int text(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	EjsVar	*vp;

	vp = ejsGetVarPtr(ejsGetSimpleProperty(ep, thisObj, E4X_TEXT_PROPERTY));
	if (vp == 0) {
		ejsSetReturnValueToString(ep, "");
		return 0;
	}
	ejsSetReturnValue(ep, vp);
	return 0;
}

/******************************************************************************/
/*
 *	Return the tag name
 */

static int name(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	EjsVar	*vp;

	vp = ejsGetVarPtr(ejsGetSimpleProperty(ep, thisObj, E4X_TAG_NAME_PROPERTY));
	if (vp == 0) {
		ejsSetReturnValueToString(ep, "");
		return 0;
	}
	ejsSetReturnValue(ep, vp);
#if UNDEFINED
	char	*name;
	/* MOB -- not ideal as we can't guarantee thisObj is a property */
	name = ejsGetPropertyPtr(thisObj)->name; 
	if (name == 0) {
		name = "";
	}
	ejsSetReturnValueToString(ep, name); 
#endif
	return 0;
}

/******************************************************************************/
/* MOB -- temporary only  */

static int setText(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc != 1) {
		ejsArgError(ep, "usage: setText(string)");
	}

	ejsSetProperty(ep, thisObj, E4X_TEXT_PROPERTY, argv[0]);
	ejsSetReturnValue(ep, argv[0]);
	return 0;
}

/******************************************************************************/

static Exml *initParser(Ejs *ep, EjsVar *thisObj, const char *fileName)
{
	XmlState	*parser;
	Exml		*xp;

	xp = exmlOpen(ep, 512, E4X_BUF_MAX);
	mprAssert(xp);

	/*
	 *	Create the parser stack
	 */
	parser = mprAllocTypeZeroed(ep, XmlState);
	parser->ep = ep;
	parser->nodeStack[0].obj = thisObj;
	parser->xmlClass = ejsGetClass(ep, 0, "XML");
	parser->xmlListClass = ejsGetClass(ep, 0, "XMLList");
	parser->fileName = fileName;

	exmlSetParseArg(xp, parser);
	exmlSetParserHandler(xp, parserHandler);

	return xp;
}

/******************************************************************************/

static void termParser(Exml *xp)
{
	mprFree(exmlGetParseArg(xp));
	exmlClose(xp);
}

/******************************************************************************/
/*
 *	XML parsing callback. Called for each elt and attribute/value pair. 
 *	For speed, we handcraft the object model here rather than calling 
 *	putXmlProperty.
 *
 *	"<!-- txt -->"		parseHandler(efd, , EXML_COMMENT);
 *	"<elt"				parseHandler(efd, , EXML_NEW_ELT);
 *	"...att=value"		parseHandler(efd, , EXML_NEW_ATT);
 *	"<elt ...>"			parseHandler(efd, , EXML_ELT_DEFINED);
 *	"<elt/>"			parseHandler(efd, , EXML_SOLO_ELT_DEFINED);
 *	"<elt> ...<"		parseHandler(efd, , EXML_ELT_DATA);
 *	"...</elt>"			parseHandler(efd, , EXML_END_ELT);
 *
 *	Note: we recurse on every new nested elt.
 */

static int parserHandler(Exml *xp, int state, const char *tagName, 
	const char *attName, const char *value)
{
	XmlState		*parser;
	XmlTagState		*tos;
	EjsVar			*currentNode, *vp, *tagNode, *parent, *vpx;
	EjsProperty		*pp;
	Ejs				*ep;
	char			*name;

	parser = (XmlState*) xp->parseArg;
	ep = parser->ep;
	tos = &parser->nodeStack[parser->topOfStack];
	currentNode = tos->obj;

	mprAssert(state >= 0);
	mprAssert(tagName && *tagName);

	switch (state) {
	case EXML_PI:
		/*
		 *	By using a property name with a leading space, we can store
		 *	non-user-visible processing instructions as regular properties.
		 */
		pp = ejsCreateSimpleNonUniqueProperty(ep, currentNode, E4X_PI_PROPERTY);
		ejsMakePropertyEnumerable(pp, 1);
		vp = ejsGetVarPtr(pp);
		ejsWriteVarAsString(ep, vp, value);
		ejsSetVarFlags(vp, EJS_XML_FLAGS_PI);
		break;

	case EXML_COMMENT:
		/*
		 *	By using a property name with a leading space, we can store
		 *	non- user-visible comments as regular properties.
		 */
		pp = ejsCreateSimpleNonUniqueProperty(ep, currentNode, 
			E4X_COMMENT_PROPERTY);
		ejsMakePropertyEnumerable(pp, 1);
		vp = ejsGetVarPtr(pp);
		ejsWriteVarAsString(ep, vp, value);
		ejsSetVarFlags(vp, EJS_XML_FLAGS_COMMENT);
		break;

	case EXML_NEW_ELT:
		if (parser->topOfStack > E4X_MAX_NODE_DEPTH) {
			ejsError(ep, EJS_IO_ERROR, 
				"XML nodes nested too deeply in %s at line %d",
				parser->fileName, exmlGetLineNumber(xp));
			return MPR_ERR_BAD_SYNTAX;
		}

		name = mprStrdup(xp, tagName);
		if (name == 0) {
			return MPR_ERR_MEMORY;
		}

		if (cleanTagName(name) < 0) {
			ejsError(ep, EJS_TYPE_ERROR, "Bad XML tag name in %s at %d",
				parser->fileName, exmlGetLineNumber(xp));
			mprFree(name);
			return MPR_ERR_BAD_SYNTAX;
		}

		pp = ejsCreateSimpleNonUniqueProperty(ep, currentNode, name);
		ejsMakePropertyEnumerable(pp, 1);

		tagNode = ejsGetVarPtr(pp);

		/* MOB -- OPT */
		vpx = ejsCreateXml(ep);
		vp = ejsWriteVar(ep, tagNode, vpx, EJS_SHALLOW_COPY);
		ejsMakeObjLive(vp, 1);
		ejsFreeVar(ep, vpx);

		/* MOB -- return code */
		pp = ejsSetPropertyToString(ep, vp, E4X_TAG_NAME_PROPERTY, name);
		ejsMakePropertyEnumerable(pp, 0);

		ejsSetVarFlags(vp, EJS_XML_FLAGS_ELEMENT);
		ejsMakePropertyEnumerable(ejsGetPropertyPtr(vp), 1);

		tos = &parser->nodeStack[++(parser->topOfStack)];
		currentNode = tos->obj = vp;
		tos->attributes = 0;
		tos->comments = 0;
		mprFree(name);
		break;

	case EXML_NEW_ATT:
		if (mprAllocSprintf(MPR_LOC_ARGS(xp), &name, 0, "@%s", attName) < 0) {
			return MPR_ERR_MEMORY;
		}
		pp = ejsCreateProperty(ep, currentNode, name);
		ejsMakePropertyEnumerable(pp, 1);

		vp = ejsGetVarPtr(pp);
		ejsWriteVarAsString(ep, vp, value);
		ejsSetVarFlags(vp, EJS_XML_FLAGS_ATTRIBUTE);
		mprFree(name);
		break;

	case EXML_SOLO_ELT_DEFINED:
		parser->topOfStack--;
		mprAssert(parser->topOfStack >= 0);
		tos = &parser->nodeStack[parser->topOfStack];
		break;

	case EXML_ELT_DEFINED:
		if (parser->topOfStack > 0) {
			parent = parser->nodeStack[parser->topOfStack - 1].obj;
			ejsSetProperty(ep, currentNode, E4X_PARENT_PROPERTY, parent);
		}
		break;

	case EXML_ELT_DATA:
	case EXML_CDATA:
		pp = ejsCreateSimpleNonUniqueProperty(ep, currentNode, 
			E4X_TEXT_PROPERTY);
		ejsMakePropertyEnumerable(pp, 1);
		vp = ejsGetVarPtr(pp);
		ejsWriteVarAsString(ep, vp, value);
		ejsSetVarFlags(vp, EJS_XML_FLAGS_TEXT);
		break;

	case EXML_END_ELT:
		/*
 		 *	This is the closing element in a pair "<x>...</x>".
 		 *	Pop the stack frame off the elt stack
 		 */
		parser->topOfStack--;
		mprAssert(parser->topOfStack >= 0);
		tos = &parser->nodeStack[parser->topOfStack];
		break;

	default:
		ejsError(ep, EJS_IO_ERROR, "XML error in %s at %d\nDetails %s",
			parser->fileName, exmlGetLineNumber(xp), exmlGetErrorMsg(xp));
		mprAssert(0);
		return MPR_ERR_BAD_SYNTAX;
	}
	return 0;
}

/******************************************************************************/

static char *cleanTagName(char *name)
{
	char	*cp;

	for (cp = name; *cp; cp++) {
		if (*cp == ':') {
			*cp = '_';
		} else if (!isalnum(*cp) && *cp != '_' && *cp != '$' && *cp != '@') {
			return 0;
		}
	}
	return name;
}

/******************************************************************************/

static int readFileData(Exml *xp, void *data, char *buf, int size)
{
	mprAssert(xp);
	mprAssert(data);
	mprAssert(buf);
	mprAssert(size > 0);

	return mprRead((MprFile*) data, buf, size);
}

/******************************************************************************/

static int readStringData(Exml *xp, void *data, char *buf, int size)
{
	XmlState	*parser;
	int			rc, len;

	mprAssert(xp);
	mprAssert(buf);
	mprAssert(size > 0);

	parser = (XmlState*) xp->parseArg;

	if (parser->inputPos < parser->inputSize) {
		len = min(size, (parser->inputSize - parser->inputPos));
		rc = mprMemcpy(buf, size, &parser->inputBuf[parser->inputPos], len);
		parser->inputPos += len;
		return rc;
	}
	return 0;
}

/******************************************************************************/

static int save(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	const char	*fileName;
	MprBuf		*buf;
	MprFile		*file;
	int			bytes, len;

	if (argc != 1 || !ejsVarIsString(argv[0])) {
		ejsError(ep, EJS_ARG_ERROR, "Bad args. Usage: save(fileName);");
		return -1;
	}
	fileName = argv[0]->string;
	
	/* MOB -- not romable 
		Need rom code in MPR not MprServices
	*/

	/*
	 *	Convert to a string 
	 */
	buf = mprCreateBuf(ep, E4X_BUF_SIZE, E4X_BUF_MAX);
	if (xmlToString(ep, buf, thisObj, -1) < 0) {
		mprFree(buf);
		return -1;
	}

	file = mprOpen(ep, fileName, 
		O_CREAT | O_TRUNC | O_WRONLY | O_TEXT, 0664);
	if (file == 0) {
		ejsError(ep, EJS_IO_ERROR, "Can't open: %s, %d", fileName, 
			mprGetOsError());
		return -1;
	}

	len = mprGetBufLength(buf);
	bytes = mprWrite(file, buf->start, len);
	if (bytes != len) {
		ejsError(ep, EJS_IO_ERROR, "Can't write to: %s", fileName);
		mprClose(file);
		return -1;
	}
	mprWrite(file, "\n", 1);
	mprFree(buf);

	mprClose(file);

	return 0;
}

/******************************************************************************/

static int toString(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	MprBuf	*buf;

	buf = mprCreateBuf(ep, E4X_BUF_SIZE, E4X_BUF_MAX);

	if (xmlToString(ep, buf, thisObj, -1) < 0) {
		mprFree(buf);
		return -1;
	}
	ejsWriteVarAsString(ep, ep->result, (char*) buf->start);

	mprFree(buf);

	return 0;
}

/******************************************************************************/
/* MOB -- need to support XMLList */

static int xmlToString(Ejs *ep, MprBuf *buf, EjsVar *obj, int indentLevel)
{
	EjsProperty		*pp;
	EjsVar			*vp;
	char			*varBuf;
	int				endTag, sawElements;
	
	if (indentLevel < 0) {
		mprPutStringToBuf(buf, "<?xml version=\"1.0\"?>");
	}

	switch (obj->type) {
	case EJS_TYPE_STRING:
		if (obj->flags & EJS_XML_FLAGS_ATTRIBUTE) {
			mprPutFmtStringToBuf(buf, " %s=\"%s\"", 
				&ejsGetPropertyPtr(obj)->name[1], obj->string);
			/* No new line */

		} else if (obj->flags & EJS_XML_FLAGS_COMMENT) {
			mprPutCharToBuf(buf, '\n');
			indent(buf, indentLevel);
			mprPutFmtStringToBuf(buf, "<!-- %s -->", obj->string);

		} else if (obj->flags & EJS_XML_FLAGS_TEXT) {
			mprPutStringToBuf(buf, obj->string);

		} else {
//			indent(buf, indentLevel);
			mprPutStringToBuf(buf, obj->string);
//			mprPutCharToBuf(buf, '\n');
		}
		break;

	default:
		/* Primitive types come here */
		indent(buf, indentLevel);
		/* MOB -- rc */
		varBuf = ejsVarToString(ep, obj);
		mprPutStringToBuf(buf, varBuf); 
		break;

	case EJS_TYPE_OBJECT:
		if (obj->objectState->baseClass == ejsGetClass(ep, 0, "XML")) {
			if (!obj->objectState->visited) {
				obj->objectState->visited = 1;

				/* MOB -- opt. Flags would be quicker */
				if (strcmp(ejsGetPropertyPtr(obj)->name, 
						E4X_PARENT_PROPERTY) == 0) {
					return 0;
				}
				/* 
				 *	MOB -- short term fix for tags with no body but with 
				 *	attributes
				 */
				if (getNumElements(obj) == 0 && 0) {
					/*
					 *	XML element is simple with no elements, so return just 
					 *	the text.
					 */
					if (getText(buf, obj) < 0) {
						ejsError(ep, EJS_IO_ERROR, 
							"XML is to big to convert to a string");
						obj->objectState->visited = 0;
						return -1;
					}

				} else if (obj->flags & (EJS_XML_FLAGS_ELEMENT)) {
					/*
					 *	XML object is complex (has elements) so return full XML
					 *	content.
					 */
					mprPutCharToBuf(buf, '\n');
					indent(buf, indentLevel);

					/*
					 *	When called from toString, obj is not a property
					 */
					if (indentLevel >= 0) {
						mprPutFmtStringToBuf(buf, "<%s", 
							ejsGetPropertyPtr(obj)->name);
						endTag = 0;

					} else {
						endTag = 1;
					}

					sawElements = 0;
					pp = ejsGetFirstProperty(obj, 0);
					while (pp) {
						vp = ejsGetVarPtr(pp);

						if (! (vp->flags & EJS_XML_FLAGS_ATTRIBUTE)) {
							if (endTag == 0) {
								endTag++;
								mprPutStringToBuf(buf, ">"); 
							}
						} 
						if (vp->flags & EJS_XML_FLAGS_ELEMENT) {
							if (strcmp(ejsGetPropertyPtr(vp)->name, 
									E4X_PARENT_PROPERTY) != 0) {
								sawElements++;
							}
						}

						if (xmlToString(ep, buf, ejsGetVarPtr(pp), 
								indentLevel + 1) < 0){
							return -1;
						}

						pp = ejsGetNextProperty(pp, 0);
					}
					if (indentLevel >= 0) {
						if (sawElements) {
							mprPutCharToBuf(buf, '\n');
							indent(buf, indentLevel);
						}
						mprPutFmtStringToBuf(buf, "</%s>", 
							ejsGetPropertyPtr(obj)->name);
					}
				}
				obj->objectState->visited = 0;
			}
			return 0;
		}

		if (obj->objectState->baseClass == ejsGetClass(ep, 0, "XMLList")) {
			indent(buf, indentLevel);
			/* MOB -- TBD */
			return 0;
		}

		/* 
		 *	All other objects. Allow other objects to override toString 
		 */
		if (ejsRunMethod(ep, obj->objectState->baseClass, "toString", 
				0) < 0) {
			return -1;
		}
		if (ejsVarIsString(ep->result)) {
			indent(buf, indentLevel);
			mprPutStringToBuf(buf, obj->string); 
		}
		break;
	} 
	return 0;
}

/******************************************************************************/

static void indent(MprBuf *bp, int level)
{
	int		i;

	for (i = 0; i < level; i++) {
		mprPutCharToBuf(bp, '\t');
	}
}

/******************************************************************************/

static int valueOf(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc != 0) {
		mprAssert(0);
		return -1;
	}

	switch (thisObj->type) {
	default:
	case EJS_TYPE_UNDEFINED:
	case EJS_TYPE_NULL:
	case EJS_TYPE_CMETHOD:
	case EJS_TYPE_OBJECT:
	case EJS_TYPE_METHOD:
	case EJS_TYPE_STRING_CMETHOD:
		ejsWriteVar(ep, ep->result, thisObj, EJS_SHALLOW_COPY);
		break;

	case EJS_TYPE_STRING:
		ejsWriteVarAsInteger(ep, ep->result, atoi(thisObj->string));
		break;

	case EJS_TYPE_BOOL:
	case EJS_TYPE_INT:
#if BLD_FEATURE_INT64
	case EJS_TYPE_INT64:
#endif
#if BLD_FEATURE_FLOATING_POINT
	case EJS_TYPE_FLOAT:
#endif
		ejsWriteVar(ep, ep->result, thisObj, EJS_SHALLOW_COPY);
		break;
	} 
	return 0;
}

/******************************************************************************/

static int getList(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	const char 	*nodeName;
	EjsProperty	*pp;
	EjsVar		*list, *vp;

	if (argc != 1) {
		nodeName = 0;
	} else {
		nodeName = argv[0]->string;
	}

	list = ejsCreateArray(ep, 0);

	pp = ejsGetFirstProperty(thisObj, EJS_ENUM_ALL);
	while (pp) {
		vp = ejsGetVarPtr(pp);
		if (vp->type == EJS_TYPE_OBJECT) {
			if (strcmp(ejsGetPropertyPtr(vp)->name, E4X_PARENT_PROPERTY) != 0) {
				if (vp->flags & EJS_XML_FLAGS_ELEMENT &&
						(nodeName == 0 || strcmp(nodeName, pp->name) == 0)) {
					ejsAddArrayElt(ep, list, vp, EJS_SHALLOW_COPY);
				}
			}
		}
		pp = ejsGetNextProperty(pp, EJS_ENUM_ALL);
	}

	ejsSetReturnValueAndFree(ep, list);
	return 0;
}

/******************************************************************************/

static int getNumElements(EjsVar *obj)
{
	EjsProperty		*pp;
	int 			count;

	count = 0;
	pp = ejsGetFirstProperty(obj, EJS_ENUM_ALL);
	while (pp) {
		if (ejsGetVarPtr(pp)->flags & EJS_XML_FLAGS_ELEMENT) {
			count++;
		}
		pp = ejsGetNextProperty(pp, EJS_ENUM_ALL);
	}
	return count;
}

/******************************************************************************/
/* MOB - This needs to be a public method */

static int getText(MprBuf *buf, EjsVar *obj)
{
	EjsProperty		*pp;
	EjsVar			*vp;

	pp = ejsGetFirstProperty(obj, EJS_ENUM_ALL);
	while (pp) {
		vp = ejsGetVarPtr(pp);
		if (vp->flags & EJS_XML_FLAGS_TEXT) {
			/* MOB -- should test for overflow */
			mprPutStringToBuf(buf, vp->string);
		}
		pp = ejsGetNextProperty(pp, EJS_ENUM_ALL);
	}
	return 0;
}

/******************************************************************************/
/******************************************************************************/
/******************************** Internal Methods ****************************/
/******************************************************************************/

static EjsVar *createXmlListProperty(Ejs *ep, EjsVar *obj, const char *property)
{
	return ejsGetVarPtr(ejsCreateProperty(ep, obj, property));
}

/******************************************************************************/

static int deleteXmlListProperty(Ejs *ep, EjsVar *obj, const char *property)
{
	return ejsDeleteProperty(ep, obj, property);
}

/******************************************************************************/

static EjsVar *getXmlListProperty(Ejs *ep, EjsVar *obj, const char *property)
{
	//	Must always return XML or XMLList event for comments and attributes
	return ejsGetVarPtr(ejsGetSimpleProperty(ep, obj, property));
}

/******************************************************************************/

static EjsVar *setXmlListProperty(Ejs *ep, EjsVar *obj, const char *property, 
	const EjsVar *value)
{
	EjsProperty		*pp;
	EjsVar			*vp;

	pp = ejsGetSimpleProperty(ep, obj, property);
	if (pp == 0) {
		mprAssert(pp);
		return 0;
	}
	vp = ejsGetVarPtr(pp);
	if (ejsWriteVar(ep, vp, value, EJS_SHALLOW_COPY) < 0){
		mprAssert(0);
		return 0;
	}
	return ejsGetVarPtr(pp);
}

/******************************************************************************/
/*
 NEW

static EjsVar *putXmlListProperty(EjsVar *op, const char *property, 
	EjsVar *value)
{

	if ((value->objectState->baseClass != XML && 
			value->objectState->baseClass != XMLList) ||
			value->string[0] != '<') {
		c = value.toString();
	} else {
		value = ejsDupVar(value);
		??
	}
	if (isdigit(*property)) {
		//	ERROR
		return 0;
	}
	if (*property == '@') {
		if (op->objectState->baseClass == XMLList) {
			if (op->obj.LENGTH_PROPERTY == 0) {
				c = "";
			} else {
				// Catenate all result of toString on all elts in list
			}
		} else {
			c = c.toString();
		}
		// Replace existing attribute of same name or insert
		return;
	}
	for (i = op->obj.LENGTH - 1; i >= 0; i--) {
		//	Delete item of same name
	}
	if (not Found) {
		Append new Xml object
			- set [[name]], [[class]] == "element"
	}
}

 */

/******************************************************************************/
#else
void ejs4xDummy() {}

/******************************************************************************/
#endif /* BLD_FEATURE_EJS_E4X */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
