/*
 *	ejsVar.h -- EJS Universal Variable Type
 */

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

/*
 *	Variables can efficiently store primitive types and can hold references to
 *	objects. Objects can store properties which are themselves variables.
 *	Properties can be primitive data types, other objects or methods. 
 *	Properties are indexed by a character name. A variable may store one of 
 *	the following types: 
 *
 *		string, integer, integer-64bit, C method, C method with string args,
 *		 Javascript method, Floating point number, boolean value, Undefined 
 *		value and the Null value. 
 *
 *	Variables have names while objects may be referenced by multiple variables.
 *	Objects use reference counting for garbage collection.
 *
 *	This module is not thread safe for performance and compactness. It relies
 *	on upper modules to provide thread synchronization as required. The API
 *	provides primitives to get variable/object references or to get copies of 
 *	variables which will help minimize required lock times.
 */

#ifndef _h_EJS_VAR
#define _h_EJS_VAR 1

/********************************* Includes ***********************************/

#include	"mpr.h"

/********************************** Defines ***********************************/
#ifdef __cplusplus
extern "C" {
#endif

/*
 *	Defined in ejs.h
 */
typedef struct Ejs Ejs;

/*
 *	Constants
 */
#if BLD_FEATURE_SQUEEZE
 	/**
	 *	Maximum property or variable name size
	 */
	#define EJS_MAX_ID				64

	/*
	 *	EJS_VAR_HASH_SIZE must be less than the size of the bit field
	 * 	propertyIndex in EjsProperty.
	 */
	#define EJS_OBJ_HASH_SIZE		13

	/**
	 *	Maximum number of arguments per function call
	 */
	#define EJS_MAX_ARGS			32
	#define EJS_INC_ARGS			8				/* Frame stack increment */

#else
	#define EJS_MAX_ID				256
	#define EJS_OBJ_HASH_SIZE		29
	#define EJS_MAX_ARGS			64
	#define EJS_INC_ARGS			8
#endif

#define EJS_VAR_MAX_RECURSE	5						/* Max object loops */

#if !DOXYGEN
/*
 *	Forward declare types
 */
struct Ejs;
struct EjsObj;
struct EjsProperty;
struct EjsVar;
#endif

/**
 *	@overview EJ primitive variable type 
 *	@description EJ primitive variable values are stored in EjsVar structures.
 *		The type of the primitive data is described by an EjsType field. 
 *		EjsVar variable types. 
 *  @stability Prototype.
 *  @library libejs.
 *	@see EJS_TYPE_UNDEFINED, EJS_TYPE_NULL, EJS_TYPE_BOOL, EJS_TYPE_CMETHOD,
 *		EJS_TYPE_FLOAT, EJS_TYPE_INT, EJS_TYPE_INT64, EJS_TYPE_OBJECT,
 *		EJS_TYPE_METHOD, EJS_TYPE_STRING, EJS_TYPE_STRING_CMETHOD, EJS_TYPE_PTR,
 */
typedef uint EjsType;
#define EJS_TYPE_UNDEFINED 			0 	/**< Undefined. No value has been set */
#define EJS_TYPE_NULL 				1	/**< Value defined to be null. */
#define EJS_TYPE_BOOL 				2	/**< Boolean type. */
#define EJS_TYPE_CMETHOD 			3	/**< C method */
#define EJS_TYPE_FLOAT 				4	/**< Floating point number */
#define EJS_TYPE_INT 				5	/**< Integer number */
#define EJS_TYPE_INT64 				6	/**< 64-bit Integer number */
#define EJS_TYPE_OBJECT 			7	/**< Object reference */
#define EJS_TYPE_METHOD 			8	/**< JavaScript method */
#define EJS_TYPE_STRING 			9	/**< String (immutable) */
#define EJS_TYPE_STRING_CMETHOD 	10	/**< C method with string args */
#define EJS_TYPE_PTR	 			11	/**< Opaque pointer */

/*
 *	Create a type for the default number type
 *	Config.h will define the default number type. For example:
 *
 *		BLD_FEATURE_NUM_TYPE=int
 *		BLD_FEATURE_NUM_TYPE_ID=EJS_TYPE_INT
 */

/**
 *	Set to the type used for EJS numeric variables. Will equate to int, int64 
 *	or double. 
 */
typedef BLD_FEATURE_NUM_TYPE EjsNum;

/**
 *	Set to the EJS_TYPE used for EJS numeric variables. Will equate to 
 *	EJS_TYPE_INT, EJS_TYPE_INT64 or EJS_TYPE_FLOAT.
 */
#define EJS_NUM_VAR BLD_FEATURE_NUM_TYPE_ID
#define EJS_TYPE_NUM BLD_FEATURE_NUM_TYPE_ID

/*
 *	Return TRUE if a variable is a method type
 */
#define ejsVarIsMethod(vp) \
	((vp)->type == EJS_TYPE_METHOD || (vp)->type == EJS_TYPE_STRING_CMETHOD || \
	 (vp)->type == EJS_TYPE_CMETHOD)

/*
 *	Return TRUE if a variable is a numeric type
 */
#define ejsVarIsNumber(vp) \
	((vp)->type == EJS_TYPE_INT || (vp)->type == EJS_TYPE_INT64 || \
		(vp)->type == EJS_TYPE_FLOAT)

/*
 *	Return TRUE if a variable is a boolean
 */
#define ejsVarIsBoolean(vp) \
	((vp)->type == EJS_TYPE_BOOL)

/*
 *	Return TRUE if a variable is an integer type
 */
#define ejsVarIsInteger(vp) ((vp)->type == EJS_TYPE_INT)

/*
 *	Return TRUE if a variable is a string
 */
#define ejsVarIsString(vp) \
	((vp)->type == EJS_TYPE_STRING)

/*
 *	Return TRUE if a variable is an object 
 */
#define ejsVarIsObject(vp) \
	((vp)->type == EJS_TYPE_OBJECT)

/*
 *	Return TRUE if a variable is a floating number
 */
#define ejsVarIsFloating(vp) \
	((vp)->type == EJS_TYPE_FLOAT)

/*
 *	Return TRUE if a variable is undefined 
 */
#define ejsVarIsUndefined(var) \
	((var)->type == EJS_TYPE_UNDEFINED)

/*
 *	Return TRUE if a variable is null
 */
#define ejsVarIsNull(var) \
	((var)->type == EJS_TYPE_NULL)

/*
 *	Return TRUE if a variable is a valid type (not null or undefined)
 */
#define ejsVarIsValid(var) \
	(((var)->type != EJS_TYPE_NULL) && ((var)->type != EJS_TYPE_UNDEFINED))

/*
 *	Return TRUE if a variable is a ptr type 
 */
#define ejsVarIsPtr(vp) \
	((vp)->type == EJS_TYPE_PTR)

/*	MOB -- convert all ep to ejs */
/**
 *	@overview C Method signature
 *	@description This is the calling signature for C Methods.
 *	@param ejs Ejs reference returned from ejsCreateInterp
 *	@param thisObj Reference to the "this" object. (The object containing the
 *		method). 
 *	@param argc Number of arguments.
 *	@param argv Array of arguments. Each argument is held in an EjsVar type.
 *  @stability Prototype.
 *  @library libejs.
 * 	@see ejsCreateCMethodVar
 */
typedef int (*EjsCMethod)(struct Ejs *ejs, struct EjsVar *thisObj, 
	int argc, struct EjsVar **argv);

/**
 *	C Method with string arguments signature
 *	@overview C Method with string arguments signature
 *	@description This is the calling signature for C Methods.
 *	@param ejs Ejs reference returned from ejsCreateInterp
 *	@param thisObj Reference to the "this" object (object containing the
 *		method. 
 *	@param argc Number of arguments.
 *	@param argv Array of arguments. Each argument is held in an C string
 *		pointer.
 *  @stability Prototype.
 *  @library libejs.
 * 	@see ejsCreateStringCMethodVar
 */
typedef int (*EjsStringCMethod)(struct Ejs *ep, struct EjsVar *thisObj, 
	int argc, char **argv);

/**
 *	Flags for types: EJS_TYPE_CMETHOD, EJS_TYPE_STRING_CMETHOD
 * 	NOTE: flags == 0 means to use the EJS handle on method callbacks
 */
/* Use the primary handle on method callbacks */
#define EJS_PRIMARY_HANDLE		0x1

/* Use the alternate handle on method callbacks */
#define EJS_ALT_HANDLE			0x2

/** Method should not create a new local variable block */
#define EJS_NO_LOCAL			0x4

/* Method is a get accessor */
#define EJS_GET_ACCESSOR		0x8

/* Method is a set accessor */
#define EJS_SET_ACCESSOR		0x10

/*
 *	Flags for E4X (Xml type)
 */
/* Node is a text node */
#define EJS_XML_FLAGS_TEXT		0x1

/* Node is a processing instruction */
#define EJS_XML_FLAGS_PI		0x2

/* Node is a comment */
#define EJS_XML_FLAGS_COMMENT	0x4

/* Node is an attribute */
#define EJS_XML_FLAGS_ATTRIBUTE	0x8

/* Node is an element */
#define EJS_XML_FLAGS_ELEMENT	0x10

/**
 *	Copy depth
 *	@overview Specifies how an object should be copied
 *	@description The EjsCopyDepth type specifies how an object's properties
 *		should be copied. Several routines take EjsCopyDepth parameters to
 *		control how the properties of an object should be copied. It provides
 *		three copy options:
 *	@see ejsWriteVar
 */
typedef enum EjsCopyDepth {
	/**
	 *	During an object copy, object property references will be copied so
	 *	that the original object and the copy will share the same reference to
	 *	a property object. Properties containing primitive types including
	 *	strings will have their values copied and will not share references.
	 */
	EJS_SHALLOW_COPY, 			/** Copy strings. Copy object references. */
	/*
	 *	During an object copy, object properties will be replicated so that
	 *	the original object and the copy will not share references to the same
	 *	object properties. If the original object's properties are themselves
	 *	objects, their properties will not be copied. Only their references
	 *	will be copied. i.e. the deep copy is one level deep.
	 */
	EJS_DEEP_COPY, 				/** Copy strings and copy object contents. */
	/*
	 *	During an object copy, all object properties will be replicated so that
	 *	the original object and the copy will not share references to the same
	 *	object properties. If the original object's properties are themselves
	 *	objects, their properties will be copied. i.e. the copy is of infinite
	 *	depth.
	 */
	EJS_RECURSIVE_DEEP_COPY		/** Copy strings and copy object contents 
									recursively (complete copy). */
} EjsCopyDepth;


/*
 *	Enumeration flags
 */
/** Enumerate data properties */
#define EJS_ENUM_DATA			0x0

/** Enumerate sub classes */
#define EJS_ENUM_CLASSES		0x1

/** Enumerate non-enumerable properties */
#define EJS_ENUM_HIDDEN			0x2

/** Enumerate all properties */
#define EJS_ENUM_ALL			(0x3)

/** Magic number when allocated */
#define EJS_MAGIC				0xe801e2ec
#define EJS_MAGIC_FREE			0xe701e3ea


/*
 *	Garbage Collection Linkage. Free list only uses the next pointers.
 */
typedef struct EjsGCLink {
#if BLD_DEBUG
	uint				magic;					/* Magic number */
#endif
#if BLD_FEATURE_ALLOC_LEAK_TRACK
	const char			*allocatedBy;			/* Who allocated this */
#endif
	struct EjsGCLink	*next;					/* Next property */
} EjsGCLink;


/**
 *	@overview EJS Variable Type
 *	@description The EJ language supports an extensive set of primitive types.
 *	These variable types can efficiently store primitive data types such as
 *	integers, strings, binary string, booleans, floating point numbers, 
 *	pointer references, and objects. EjsVars are the universal type used by
 *	EJ to hold objects, classes and properties.
 *	\n\n
 *	An EjsVar may store one of the following types: 
 *	@li Boolean
 *	@li Floating point (if supported in this build)
 *	@li Integer
 *	@li 64 bit integer (if supported in this build)
 *	@li String
 *	@li Binary string
 *	@li C function or C++ method
 *	@li C function with string args
 *	@li Javascript method
 *	@li Object
 *	@li Null value. 
 *	@li Undefined value
 *	\n\n
 *	Objects can hold object properties which are themselves EJS variables.
 *	Properties are hash indexed by the property name and are stored in
 *	an ordered sequence. i.e. Order of properties is maintained. Objects may
 *	be referenced by multiple variables and they use garbage collection to
 *	reclaim memory no longer in use by objects and properties.
 *
 *	@warning This module is @e not thread safe for performance and
 *		compactness. It relies on upper modules to provide thread
 *		synchronization as required. The API provides primitives to get
 *		variable/object references or to get copies of variables which should
 *		help minimize required lock times.
 *	@stability Prototype.
 *	@library libejs
 *	@see Ejs, EjsProperty, ejsCreateStringVar, ejsFreeVar
 */

typedef struct EjsVar {							/* Size 12 bytes */
	/*
	 *	GC must be first
	 */
#if BLD_DEBUG || BLD_FEATURE_ALLOC_LEAK_TRACK
	EjsGCLink			gc;						/* Garbage collection links */
#endif

#if BLD_DEBUG
	const char			*propertyName;			/* Ptr to property name */
#endif

	/*
	 *	Union of primitive types. When debugging on Linux, don't use unions 
	 *	as the gdb debugger can't display them.
	 */
#if (!BLD_DEBUG && !VXWORKS) || WIN || BREW_SIMULATOR
	union {
#endif
		/* 
		 *	For debugging, we order the common types first
		 */
		struct EjsObj 	*objectState;			/* Object state information */
		int				integer;
		bool			boolean;

#if BLD_FEATURE_FLOATING_POINT
		double			floating;
#endif
#if BLD_FEATURE_INT64
		int64			integer64;
#endif

		struct {
			int			length;					/* String length (sans null) */
			/*
			 *	All strings always have a trailing null allocated
			 */
			union {
				char	*string;				/* String */
				uchar	*ustring;				/* Binary string */
			};
		};

		struct {								/* Javascript methods */
			MprArray	*args;					/* Null terminated */
			char		*body;
		} method;

		struct {								/* Method with EjsVar args */
			EjsCMethod fn;						/* Method pointer */
			void		*userData;				/* User data for method */
		} cMethod;

		struct {								/* Method with string args */
			EjsStringCMethod fn;				/* Method pointer */
			void		*userData;				/* User data for method */
		} cMethodWithStrings;

		struct {
			void		*userPtr;				/* Opaque pointer */
			int			(*destructor)(Ejs *ejs, struct EjsVar *vp);
		} ptr;

#if (!BLD_DEBUG && !VXWORKS) || WIN || BREW_SIMULATOR
	};
#endif

	/*
	 *	Packed bit field (32 bits)
	 */
	uint				flags			:  8;	/* Type specific flags */
	EjsType				type			:  4;	/* Selector into union */
	uint				stringLen		:  4;	/* Length of string if inline */
	uint				allocatedData	:  1;	/* Node needs freeing */
	uint				isArray			:  1;	/* Var is an array */
	uint				isArrayLength	:  1;	/* Var is array.length */
	uint				callsSuper		:  1;	/* Method calls super() */
	uint				isProperty		:  1;	/* Part of a property */
	uint				reserved		: 11;	/* Unused */

} EjsVar;


/*
 *	Linkage for the ordered list of properties
 */
typedef struct EjsPropLink {
	struct EjsPropLink	*next;						/* Next property */
	struct EjsPropLink	*prev;						/* Previous property */

	/*
	 *	To make debugging easier
	 */
#if BLD_DEBUG
	const char 			*propertyName;				/* Pointer to name */
	struct EjsProperty	*property;					/* Pointer to property */
	struct EjsPropLink	*head;						/* Dummy head of list */
#endif
} EjsPropLink;


/**
 *	@overview Object Property Type
 *	@description The EjsProperty type is used to store all object properties.
 *		It contains the property name, property linkage, propery attributes
 *		such as public/private, enumerable and readonly settings. It also
 *		contains an EjsVar to store the property data value.
 *	@stability Prototype.
 *	@library libejs
 *	@see Ejs, EjsVar
 */
typedef struct EjsProperty {					/* Size 96 bytes in squeeze */
	/*
	 *	EjsVar must be first. We often take the address of "var" and take
	 *	advantage of if an EjsProperty is null, then &prop->var will be null 
	 *	also. Be WARNED. External users should use ejsGetVarPtr and 
	 *	ejsGetPropertyPtr to convert between the two.
	 */
	EjsVar				var;					/* Property value */

	/* OPT change this to a pointer to the base class property */
	char				name[EJS_MAX_ID];		/* Name */

	uint				visited			: 1;	/* Has been traversed */
	uint				isPrivate		: 1;	/* Property is private */
	uint				isProtected		: 1;	/* Property is protected */
	uint				dontEnumerate	: 1;	/* Not enumerable */
	uint				dontDelete		: 1;	/* Prevent delete */
	uint				readonly		: 1;	/* Unmodifiable */
	uint				allowNonUnique	: 1;	/* Multiple of same name ok */
	uint				delayedDelete	: 1;
	uint				reserved		: 24;

	EjsPropLink			link;					/* Ordered linked list */
	struct EjsProperty	*hashNext;				/* Hash table linkage */

	/* MOB -- is this really required */
	struct EjsObj		*parentObj;				/* Pointer to parent object */

} EjsProperty;


#define EJS_OP_DOT		0x1
#define EJS_OP_INDEX	0x2
#define EJS_OP_PLUS		0x3
#define EJS_OP_MINUS	0x4
#define EJS_OP_MULTIPLY	0x5
#define EJS_OP_DIVIDE	0x6
#define EJS_OP_CALL		0x7

typedef struct EjsOp {
	int					opType;

} EjsOp;

/*
 *	Propety Access Methods. Used per class.
 *	MOB -- rename EjsHelpers
 */
typedef struct EjsMethods {
#if FUTURE
	int		(*create)(Ejs *ep, EjsVar *thisObj);
	int		(*deleteProperty)(Ejs *ep, EjsVar *thisObj, const char *prop);
	EjsVar	*(*getProperty)(Ejs *ep, EjsVar *thisObj, const char *prop);
	EjsVar	*(*setProperty)(Ejs *ep, EjsVar *thisObj, const char *prop);
	int		(*hasProperty)(Ejs *ep, EjsVar *thisObj, const char *prop);
	int		(*hasInstance)(Ejs *ep, EjsVar *thisObj, const char *prop);
	int		(*operate)(Ejs *ep, EjsVar *thisObj, EjsOp op, EjsVar *result,
				EjsVar *lhs, EjsVar *rhs, int *code);
#else

	EjsVar		*(*createProperty)(Ejs *ep, EjsVar *obj, const char *property);
	int			 (*deleteProperty)(Ejs *ep, EjsVar *obj, const char *property);
	EjsVar		*(*getProperty)(Ejs *ep, EjsVar *obj, const char *property);
	EjsVar		*(*setProperty)(Ejs *ep, EjsVar *obj, const char *property, 
					const EjsVar *value);
	/*
	 *	Other implemented internal properties in ECMA-262 are:
 	 *
	 * 		[[Construct]]		implemented via EjsVar methods
	 *		[[Prototype]]		implemented via EjsObj->baseClass 
	 *		[[Class]]			implemented via EjsObj->baseClass->name
	 *		[[Value]]			Implemented via EjsProperty + EjsVar + EjsObj
	 */

	/* 
 	 *	FUTURE -- not implemented 
	 */
	int			(*canPut)(Ejs *ep, EjsVar *obj, const char *property);
	int			(*defaultValue)(Ejs *ep, EjsVar *obj, const char *property, 
					const char *hint);
	int			(*hasProperty)(Ejs *ep, EjsVar *obj, const char *property);
	EjsVar		*(*call)(Ejs *ep, EjsVar *obj, const char *property, 
					EjsVar *args);
	int			(*hasInstance)(Ejs *ep, EjsVar *obj, const char *property);
	int			(*scope)(Ejs *ep, EjsVar *obj, const char *property);
	int			(*match)(Ejs *ep, EjsVar *obj, const char *property,
					const char *string, int index);
#endif
} EjsMethods;


/*
 *	Ejs Object Type
 */
typedef struct EjsObj {
	/* 
 	 *	GC must be first 
	 */
	EjsGCLink		gc;						/* Garbage collection links */

	union {
		char 		*objName;				/* Object name */
		char 		*className;				/* Class name */
	};

	struct EjsVar	*baseClass;				/* Pointer to base class object */

	EjsPropLink		link;					/* Ordered list of properties */

	/* OPT -- dynamically allocate this only if required */
	EjsProperty		*propertyHash[EJS_OBJ_HASH_SIZE]; /* Hash chains */

	/* 	OPT -- could save this and store off baseClass only */
	EjsMethods		*methods;				/* Property access methods */
	void			*nativeData;			/* Native object data */

	int				(*destructor)(Ejs *ejs, struct EjsVar *vp);

	uint			numProperties	  : 16;	/* Total count of items */
	uint			visited			  :  1;	/* Has been traversed */
	uint			gcMarked		  :  1;	/* Node marked in-use by GC */
	uint			permanent		  :  1;	/* Permanent object, dont GC */
	uint			alive			  :  1;	/* Only GC if alive */
	uint			noConstructor	  :  1;	/* Object has no constructor */
	uint			dirty	 		  :  1;	/* Object has been modified */
	uint			hasErrors		  :  1;	/* Update error */
	uint			preventDeleteProp :  1;	/* Don't allow prop deletion */
	uint			delayedDeleteProp :  1;	/* Delayed delete of props */
	uint			reserved		  :  7;	/* Unused */

	Ejs				*ejs;					/* Owning interp */

#if BLD_FEATURE_MULTITHREAD
	MprLock			*mutex;					/* Advisory mutex lock */
#endif
} EjsObj;


/*
 *	Define a field macro so code an use numbers in a "generic" fashion.
 */
#if EJS_NUM_VAR == EJS_TYPE_INT || DOXYGEN
/*
 *	Default numeric type 
 */
#define ejsNumber integer
#endif
#if EJS_NUM_VAR == EJS_TYPE_INT64
/*	Default numeric type */
#define ejsNumber integer64
#endif
#if EJS_NUM_VAR == EJS_TYPE_FLOAT
/*	Default numeric type */
#define ejsNumber floating
#endif

typedef BLD_FEATURE_NUM_TYPE EjsNumber;

/*
 *	Memory allocation slabs
 */
#define EJS_SLAB_OBJ		0
#define EJS_SLAB_PROPERTY	1
#define EJS_SLAB_VAR		2
#define EJS_SLAB_MAX		3

/**
 *	Object and pointer property destructory type
 */
typedef int		(*EjsDestructor)(Ejs *ejs, EjsVar *vp);

#if BLD_FEATURE_ALLOC_LEAK_TRACK || DOXYGEN
/*
 *	Line number information args and declarations for ejsAlloc.
 *		Use EJS_LOC_ARGS in normal user code.
 *		Use EJS_LOC_DEC  in declarations.
 *		Use EJS_LOC_PASS in layered APIs to pass original line info down.
 */
#define EJS_LOC_ARGS(ejs)		ejs, MPR_LOC
#define EJS_LOC_DEC(ejs, loc)	Ejs *ejs, const char *loc
#define EJS_LOC_PASS(ejs, loc)	ejs, loc
#else
#define EJS_LOC_ARGS(ejs)		ejs
#define EJS_LOC_DEC(ejs, loc)	Ejs *ejs 
#define EJS_LOC_PASS(ejs, loc)	ejs
#endif

/******************************* Internal Prototypes **************************/

#define ejsInitVar(vp, varType) \
	if (1) { 				 \
		(vp)->type = varType; 	 \
		(vp)->isArray = 0; 	 \
		(vp)->flags = 0; 		 \
	} else
extern void	 		ejsClearVar(Ejs *ep, EjsVar *vp);

extern int 		ejsDestroyObj(Ejs *ep, EjsObj *obj);
extern EjsVar 	*ejsCreatePropertyMethod(Ejs *ep, EjsVar *obj, 
					const char *name);
extern EjsVar 	*ejsSetPropertyMethod(Ejs *ep, EjsVar *obj, const char *name, 
					const EjsVar *value);
extern EjsVar 	*ejsGetPropertyMethod(Ejs *ep, EjsVar *obj, const char *name);
extern int	 	ejsDeletePropertyMethod(Ejs *ep, EjsVar *obj, 
					const char *name);
extern void 	ejsSetArrayLength(Ejs *ep, EjsVar *obj, const char *creating,
					const char *deleting, const EjsVar *setLength);

/*
 *	At the moment, these are the same routine
 */
extern void			ejsSetClassName(Ejs *ep, EjsVar *obj, const char *name);
#define ejsSetObjName ejsSetObjName

extern bool			ejsIsObjDirty(EjsVar *vp);			
extern void			ejsResetObjDirtyBit(EjsVar *vp);			

extern int			ejsObjHasErrors(EjsVar *vp);
extern void			ejsClearObjErrors(EjsVar *vp);

extern EjsVar		*ejsClearProperty(Ejs *ep, EjsVar *obj, const char *prop);

typedef int 		(*EjsSortFn)(Ejs *ep, EjsProperty *p1, EjsProperty *p2,
						const char *propertyName, int order);
extern void			ejsSortProperties(Ejs *ep, EjsVar *obj, EjsSortFn fn,
						const char *propertyName, int order);

#if BLD_DEBUG
#define 			ejsSetVarName(ep, vp, varName) \
						if (1) { \
							(vp)->propertyName = varName; \
							if ((vp)->type == EJS_TYPE_OBJECT && \
								(vp)->objectState && \
								((vp)->objectState->objName == 0)) { \
									(vp)->objectState->objName = \
										mprStrdup(ep, varName); \
							} \
						} else
#else
#define 			ejsSetVarName(ep, vp, varName) 
#endif

EjsVar 				*ejsFindProperty(Ejs *ep, EjsVar **obj, char **property, 
						EjsVar *global, EjsVar *local, const char *fullName, 
						int create);

extern EjsVar 		*ejsCopyProperties(Ejs *ep, EjsVar *dest, 
						const EjsVar *src, EjsCopyDepth copyDepth);

#define EJS_LINK_OFFSET ((uint) (&((EjsProperty*) 0)->link))
#define ejsGetPropertyFromLink(lp) \
		((EjsProperty*) ((char*) lp - EJS_LINK_OFFSET))

#define ejsGetObjPtr(vp) ((EjsObj*) vp->objectState)

extern void 		ejsMakePropertyPrivate(EjsProperty *pp, int isPrivate);
extern void 		ejsMakePropertyReadOnly(EjsProperty *pp, int readonly);
extern void 		ejsMakePropertyUndeleteable(EjsProperty *pp, int deletable);
extern int	 		ejsMakeObjLive(EjsVar *vp, bool alive);
extern void 		ejsMakeClassNoConstructor(EjsVar *vp);

extern bool			ejsBlockInUseInt(EjsVar *vp);
#if BLD_DEBUG
	#define ejsBlockInUse(vp) ejsBlockInUseInt(vp)
#else
	#define ejsBlockInUse(vp)
#endif

/********************************* Prototypes *********************************/

/*
 *	Variable constructors and destructors
 */
extern EjsVar		*ejsCreateBinaryStringVar(Ejs *ep, const uchar *value,
						int len);
extern EjsVar 		*ejsCreateBoolVar(Ejs *ep, int value);
extern EjsVar 		*ejsCreateCMethodVar(Ejs *ep, EjsCMethod fn, 
						void *userData, int flags);
#if BLD_FEATURE_FLOATING_POINT
extern EjsVar 		*ejsCreateFloatVar(Ejs *ep, double value);
#endif
extern EjsVar 		*ejsCreateIntegerVar(Ejs *ep, int value);
#if BLD_FEATURE_INT64
extern EjsVar 		*ejsCreateInteger64Var(Ejs *ep, int64 value);
#endif

extern EjsVar 		*ejsCreateMethodVar(Ejs *ep, const char *body, 
						MprArray *args, int flags);
extern EjsVar		*ejsCreateNullVar(Ejs *ep);
extern EjsVar 		*ejsCreateNumberVar(Ejs *ep, EjsNumber value);

#define ejsCreateObjVar(ep) \
					ejsCreateObjVarInternal(EJS_LOC_ARGS(ep))
extern EjsVar		*ejsCreateObjVarInternal(EJS_LOC_DEC(ep, loc));

extern EjsVar 		*ejsCreatePtrVar(Ejs *ep, void *ptr, EjsDestructor dest);

extern EjsVar 		*ejsCreateStringCMethodVar(Ejs *ep, EjsStringCMethod fn, 
						void *userData, int flags);

#define ejsCreateStringVar(ep, value) \
					ejsCreateStringVarInternal(EJS_LOC_ARGS(ep), value)
extern EjsVar		*ejsCreateStringVarInternal(EJS_LOC_DEC(ep, loc), 
						const char *value);

extern EjsVar		*ejsCreateUndefinedVar(Ejs *ep);

/* MOB -- naming. Should be Create/Destroy */
extern void	 		ejsFreeVar(Ejs *ep, EjsVar *vp);

/*
 *	Var support routines
 */
extern int			ejsGetVarFlags(EjsVar *vp);
extern void			ejsSetVarFlags(EjsVar *obj, int flags);

extern EjsType		ejsGetVarType(EjsVar *vp);
extern const char 	*ejsGetVarTypeAsString(EjsVar *vp);

extern void			*ejsGetCMethodUserData(EjsVar *obj);
extern void			ejsSetCMethodUserData(EjsVar *obj, void *userData);

extern void			*ejsGetVarUserPtr(EjsVar *vp);
extern void			ejsSetVarUserPtr(EjsVar *vp, void *data);


/*
 *	Variable access and manipulation. These work on standalone objects.
 */
#define ejsDupVar(ep, src, copyDepth) \
						ejsDupVarInternal(EJS_LOC_ARGS(ep), src, copyDepth)
extern EjsVar		*ejsDupVarInternal(EJS_LOC_DEC(ep, loc), EjsVar *src, 
						EjsCopyDepth copyDepth);
#define ejsWriteVar(ep, dest, src, copyDepth) \
					ejsWriteVarInternal(EJS_LOC_ARGS(ep), dest, src, copyDepth)
extern EjsVar		*ejsWriteVarInternal(EJS_LOC_DEC(ep, loc), EjsVar *dest, 
						const EjsVar *src, EjsCopyDepth copyDepth);
extern EjsVar 		*ejsWriteVarAsBinaryString(Ejs *ep, EjsVar *dest, 
						const uchar *value, int len);
extern EjsVar		*ejsWriteVarAsBoolean(Ejs *ep, EjsVar *dest, bool value);
extern EjsVar		*ejsWriteVarAsCMethod(Ejs *ep, EjsVar *dest, EjsCMethod fn, 
						void *userData, int flags);
#if BLD_FEATURE_FLOATING_POINT
extern EjsVar		*ejsWriteVarAsFloat(Ejs *ep, EjsVar *dest, double value);
#endif
extern EjsVar		*ejsWriteVarAsInteger(Ejs *ep, EjsVar *dest, int value);
#if BLD_FEATURE_INT64
extern EjsVar		*ejsWriteVarAsInteger64(Ejs *ep, EjsVar *dest, int64 value);
#endif
extern EjsVar		*ejsWriteVarAsMethod(Ejs *ep, EjsVar *dest, 
						const char *body, MprArray *args);
extern EjsVar		*ejsWriteVarAsNull(Ejs *ep, EjsVar *dest);
extern EjsVar		*ejsWriteVarAsNumber(Ejs *ep, EjsVar *dest, EjsNum value);
#define ejsWriteVarAsString(ep, dest, value) \
					ejsWriteVarAsStringInternal(EJS_LOC_ARGS(ep), dest, value)
extern EjsVar		*ejsWriteVarAsStringInternal(EJS_LOC_DEC(ep, loc), 
						EjsVar *dest, const char *value);
extern EjsVar		*ejsWriteVarAsStringCMethod(Ejs *ep, EjsVar *dest, 
						EjsStringCMethod fn, void *userData, int flags);
extern EjsVar		*ejsWriteVarAsUndefined(Ejs *ep, EjsVar *dest);

/*
 *	These routines do not convert types
 */
/* MOB -- make this a fn and pass back the length as an arg */
#define ejsReadVarAsBinaryString(vp) ((const uchar*) (vp->ustring));
#define ejsReadVarAsBoolean(vp) (vp->boolean);
#define ejsReadVarAsCMethod(vp) (vp->cMethod);
#if BLD_FEATURE_FLOATING_POINT
#define ejsReadVarAsFloat(vp) (vp->floating);
#endif
#define ejsReadVarAsInteger(vp) (vp->integer);
#if BLD_FEATURE_INT64
#define ejsReadVarAsInteger64(vp) (vp->int64);
#endif
#define ejsReadVarAsString(vp) ((const char*) (vp->string));
#define ejsReadVarAsStringCMethod(vp) (vp->cMethodWithStrings);
/* MOB -- remove this fn */
#define ejsReadVarStringLength(vp) (vp->length);

/*
 *	Object property creation routines
 */
extern EjsProperty	*ejsCreateProperty(Ejs *ep, EjsVar *obj, const char *prop);
extern EjsProperty	*ejsCreateSimpleProperty(Ejs *ep, EjsVar *obj, 
						const char *prop);
extern EjsProperty	*ejsCreateSimpleNonUniqueProperty(Ejs *ep, EjsVar *obj, 
						const char *prop);
/* MOB -- should be destroy */
extern int			ejsDeleteProperty(Ejs *ep, EjsVar *obj, const char *prop);


/*
 *	Get property routines
 */
extern EjsProperty 	*ejsGetProperty(Ejs *ep, EjsVar *obj, const char *prop);
extern EjsProperty 	*ejsGetSimpleProperty(Ejs *ep, EjsVar *obj, 
						const char *prop);

extern EjsVar		*ejsGetPropertyAsVar(Ejs *ep, EjsVar *obj, 
						const char *prop);
extern int			ejsGetPropertyCount(EjsVar *obj);

extern const uchar	*ejsGetPropertyAsBinaryString(Ejs *ep, EjsVar *obj, 
						const char *prop, int *length);
extern bool			ejsGetPropertyAsBoolean(Ejs *ep, EjsVar *obj, 
						const char *prop);
extern int			ejsGetPropertyAsInteger(Ejs *ep, EjsVar *obj, 
						const char *prop);
extern int64		ejsGetPropertyAsInteger64(Ejs *ep, EjsVar *obj, 
						const char *prop);
extern EjsNum 		ejsGetPropertyAsNumber(Ejs *ep, EjsVar *obj, 
						const char *prop);
extern void			*ejsGetPropertyAsPtr(Ejs *ep, EjsVar *obj, 
						const char *prop);
extern const char	*ejsGetPropertyAsString(Ejs *ep, EjsVar *obj, 
						const char *prop);

/* 
 *	Object property update routines 
 */
extern EjsProperty	*ejsSetBaseProperty(Ejs *ep, EjsVar *obj, const char *prop, 
						const EjsVar *value);
extern EjsProperty	*ejsSetProperty(Ejs *ep, EjsVar *obj, const char *prop, 
						const EjsVar *value);
extern EjsProperty	*ejsSetPropertyAndFree(Ejs *ep, EjsVar *obj, 
						const char *prop, EjsVar *value);
extern EjsProperty	*ejsSetPropertyToBinaryString(Ejs *ep, EjsVar *obj, 
						const char *prop, const uchar *value, int len);
extern EjsProperty	*ejsSetPropertyToBoolean(Ejs *ep, EjsVar *obj, 
						const char *prop, bool value);
extern EjsProperty	*ejsSetPropertyToCMethod(Ejs *ep, EjsVar *obj, 
						const char *prop, EjsCMethod fn, void *userData, 
						int flags);
#if BLD_FEATURE_FLOATING_POINT
extern EjsProperty	*ejsSetPropertyToFloat(Ejs *ep, EjsVar *obj, 
						const char *prop, double value);
#endif
extern EjsProperty	*ejsSetPropertyToInteger(Ejs *ep, EjsVar *obj, 
						const char *prop, int value);
#if BLD_FEATURE_INT64
extern EjsProperty	*ejsSetPropertyToInteger64(Ejs *ep, EjsVar *obj, 
						const char *prop, int64 value);
#endif
extern EjsProperty	*ejsSetPropertyToMethod(Ejs *ep, EjsVar *obj, 
						const char *prop, const char *body, MprArray *args,
						int flags);
extern EjsProperty	*ejsSetPropertyToNewObj(Ejs *ep, EjsVar *obj, 
						const char *prop, const char *className, 
						MprArray *args);
extern EjsProperty	*ejsSetPropertyToNull(Ejs *ep, EjsVar *obj, 
						const char *prop);
extern EjsProperty	*ejsSetPropertyToNumber(Ejs *ep, EjsVar *obj, 
						const char *prop, EjsNum value);
extern EjsProperty	*ejsSetPropertyToObj(Ejs *ep, EjsVar *obj, 
						const char *prop);
extern EjsProperty	*ejsSetPropertyToPtr(Ejs *ep, EjsVar *obj, 
						const char *prop, void *ptr, EjsDestructor destructor);

extern EjsProperty	*ejsSetPropertyToStringCMethod(Ejs *ep, EjsVar *obj, 
						const char *prop, EjsStringCMethod fn, 
						void *userData, int flags);
extern EjsProperty	*ejsSetPropertyToString(Ejs *ep, EjsVar *obj, 
						const char *prop, const char *value);
extern EjsProperty	*ejsSetPropertyToUndefined(Ejs *ep, EjsVar *obj, 
						const char *prop);


/* Convenience function */
extern EjsVar 		*ejsSetPropertyToObjAsVar(Ejs *ep, EjsVar *obj, 
						const char *prop);
extern void			ejsSetObjDestructor(Ejs *ep, EjsVar *obj, 
						EjsDestructor destructor);
extern void			ejsClearObjDestructor(Ejs *ep, EjsVar *obj);

/*
 *	Enumeration of properties
 *	MOB -- should these take an ejs parameter to be consistent
 */
extern EjsProperty 	*ejsGetFirstProperty(const EjsVar *obj, int flags);
extern EjsProperty 	*ejsGetNextProperty(EjsProperty *last, int flags);

/* 
 *	Method definition and control.
 */
extern EjsProperty	*ejsDefineMethod(Ejs *ep, EjsVar *obj, const char *prop, 
						const char *body, MprArray *args);
extern EjsProperty	*ejsDefineCMethod(Ejs *ep, EjsVar *obj, const char *prop, 
						EjsCMethod fn, int flags);

extern EjsProperty	*ejsDefineStringCMethod(Ejs *ep, EjsVar *obj, 
						const char *prop, EjsStringCMethod fn, int flags);

extern EjsProperty	*ejsDefineAccessors(Ejs *ep, EjsVar *obj, 
						const char *prop, const char *getBody, 
						const char *setBody);
extern EjsProperty	*ejsDefineCAccessors(Ejs *ep, EjsVar *obj, 
						const char *prop, EjsCMethod getFn, EjsCMethod setFn,
						 int flags);

/*
 *	Macro to get the variable value portion of a property
 */
#define ejsGetVarPtr(pp) (&((pp)->var))
#define ejsGetPropertyPtr(vp) ((EjsProperty*) vp)

/* MOB -- take ejs to be consistent */
extern int	 		ejsMakePropertyEnumerable(EjsProperty *pp, bool enumerable);
extern int	 		ejsMakeObjPermanent(EjsVar *vp, bool permanent);


/*
 *	Var conversion routines
 *	MOB -- should these take an Ejs as first arg for consistency
 */
extern bool	 	ejsVarToBoolean(EjsVar *vp);
#if BLD_FEATURE_FLOATING_POINT
extern double 	ejsVarToFloat(EjsVar *vp);
#endif
extern int	 	ejsVarToInteger(EjsVar *vp);
#if BLD_FEATURE_INT64
extern int64 	ejsVarToInteger64(EjsVar *vp);
#endif
extern EjsNum 	ejsVarToNumber(EjsVar *vp);
extern char		*ejsVarToString(Ejs *ep, EjsVar *vp);
extern char 	*ejsVarToStringEx(Ejs *ep, EjsVar *vp, bool *alloc);
extern char		*ejsFormatVar(Ejs *ep, const char *fmt, EjsVar *vp);

#if BLD_FEATURE_FLOATING_POINT
extern double 	ejsParseFloat(const char *str);
#endif
/*
 *	Parsing and type range checking routines
 */
extern bool	 	ejsParseBoolean(const char *str);
extern int	 	ejsParseInteger(const char *str);
#if BLD_FEATURE_INT64
extern int64 	ejsParseInteger64(const char *str);
#endif
extern EjsNum 	ejsParseNumber(const char *str);
extern EjsVar 	*ejsParseVar(Ejs *ep, const char *str, EjsType prefType);

#if BLD_FEATURE_FLOATING_POINT
extern bool	 	ejsIsInfinite(double f);
extern bool	 	ejsIsNan(double f);
#endif

/*
 *	Advisory locking support
 */
#if BLD_FEATURE_MULTITHREAD
extern void 	ejsLockObj(EjsVar *vp);
extern void 	ejsUnlockObj(EjsVar *vp);
#endif

/*
 *	Just for debugging
 */
extern bool 		ejsObjIsCollectable(EjsVar *vp);

#ifdef __cplusplus
}
#endif

/*****************************************************************************/
#endif /* _h_EJS_VAR */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
