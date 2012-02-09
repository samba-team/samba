#define kw_TRUE 257
#define kw_FALSE 258
#define kw_AND 259
#define kw_OR 260
#define kw_IN 261
#define kw_TAILMATCH 262
#define NUMBER 263
#define STRING 264
#define IDENTIFIER 265
#ifdef YYSTYPE
#undef  YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
#endif
#ifndef YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
typedef union {
    char *string;
    struct hx_expr *expr;
} YYSTYPE;
#endif /* !YYSTYPE_IS_DECLARED */
extern YYSTYPE yylval;
