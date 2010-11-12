#define ET 257
#define INDEX 258
#define PREFIX 259
#define EC 260
#define ID 261
#define END 262
#define STRING 263
#define NUMBER 264
typedef union {
  char *string;
  int number;
} YYSTYPE;
extern YYSTYPE yylval;
