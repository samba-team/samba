#define kw_ABSENT 257
#define kw_ABSTRACT_SYNTAX 258
#define kw_ALL 259
#define kw_APPLICATION 260
#define kw_AUTOMATIC 261
#define kw_BEGIN 262
#define kw_BIT 263
#define kw_BMPString 264
#define kw_BOOLEAN 265
#define kw_BY 266
#define kw_CHARACTER 267
#define kw_CHOICE 268
#define kw_CLASS 269
#define kw_COMPONENT 270
#define kw_COMPONENTS 271
#define kw_CONSTRAINED 272
#define kw_CONTAINING 273
#define kw_DEFAULT 274
#define kw_DEFINITIONS 275
#define kw_EMBEDDED 276
#define kw_ENCODED 277
#define kw_END 278
#define kw_ENUMERATED 279
#define kw_EXCEPT 280
#define kw_EXPLICIT 281
#define kw_EXPORTS 282
#define kw_EXTENSIBILITY 283
#define kw_EXTERNAL 284
#define kw_FALSE 285
#define kw_FROM 286
#define kw_GeneralString 287
#define kw_GeneralizedTime 288
#define kw_GraphicString 289
#define kw_IA5String 290
#define kw_IDENTIFIER 291
#define kw_IMPLICIT 292
#define kw_IMPLIED 293
#define kw_IMPORTS 294
#define kw_INCLUDES 295
#define kw_INSTANCE 296
#define kw_INTEGER 297
#define kw_INTERSECTION 298
#define kw_ISO646String 299
#define kw_MAX 300
#define kw_MIN 301
#define kw_MINUS_INFINITY 302
#define kw_NULL 303
#define kw_NumericString 304
#define kw_OBJECT 305
#define kw_OCTET 306
#define kw_OF 307
#define kw_OPTIONAL 308
#define kw_ObjectDescriptor 309
#define kw_PATTERN 310
#define kw_PDV 311
#define kw_PLUS_INFINITY 312
#define kw_PRESENT 313
#define kw_PRIVATE 314
#define kw_PrintableString 315
#define kw_REAL 316
#define kw_RELATIVE_OID 317
#define kw_SEQUENCE 318
#define kw_SET 319
#define kw_SIZE 320
#define kw_STRING 321
#define kw_SYNTAX 322
#define kw_T61String 323
#define kw_TAGS 324
#define kw_TRUE 325
#define kw_TYPE_IDENTIFIER 326
#define kw_TeletexString 327
#define kw_UNION 328
#define kw_UNIQUE 329
#define kw_UNIVERSAL 330
#define kw_UTCTime 331
#define kw_UTF8String 332
#define kw_UniversalString 333
#define kw_VideotexString 334
#define kw_VisibleString 335
#define kw_WITH 336
#define RANGE 337
#define EEQUAL 338
#define ELLIPSIS 339
#define IDENTIFIER 340
#define referencename 341
#define STRING 342
#define NUMBER 343
#ifdef YYSTYPE
#undef  YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
#endif
#ifndef YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
typedef union {
    int constant;
    struct value *value;
    struct range *range;
    char *name;
    Type *type;
    Member *member;
    struct objid *objid;
    char *defval;
    struct string_list *sl;
    struct tagtype tag;
    struct memhead *members;
    struct constraint_spec *constraint_spec;
} YYSTYPE;
#endif /* !YYSTYPE_IS_DECLARED */
extern YYSTYPE yylval;
