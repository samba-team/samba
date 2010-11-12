#define kw_TRUE 257
#define kw_FALSE 258
#define kw_AND 259
#define kw_OR 260
#define kw_IN 261
#define kw_TAILMATCH 262
#define NUMBER 263
#define STRING 264
#define IDENTIFIER 265
typedef union {
    char *string;
    struct hx_expr *expr;
} YYSTYPE;
extern YYSTYPE yylval;
