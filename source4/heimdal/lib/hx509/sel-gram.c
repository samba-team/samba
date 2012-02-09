#ifndef lint
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20101229

#define YYEMPTY        (-1)
#define yyclearin      (yychar = YYEMPTY)
#define yyerrok        (yyerrflag = 0)
#define YYRECOVERING() (yyerrflag != 0)

#define YYPREFIX "yy"

#define YYPURE 0

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <hx_locl.h>


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
/* compatibility with bison */
#ifdef YYPARSE_PARAM
/* compatibility with FreeBSD */
# ifdef YYPARSE_PARAM_TYPE
#  define YYPARSE_DECL() yyparse(YYPARSE_PARAM_TYPE YYPARSE_PARAM)
# else
#  define YYPARSE_DECL() yyparse(void *YYPARSE_PARAM)
# endif
#else
# define YYPARSE_DECL() yyparse(void)
#endif

/* Parameters sent to lex. */
#ifdef YYLEX_PARAM
# define YYLEX_DECL() yylex(void *YYLEX_PARAM)
# define YYLEX yylex(YYLEX_PARAM)
#else
# define YYLEX_DECL() yylex(void)
# define YYLEX yylex()
#endif

/* Parameters sent to yyerror. */
#define YYERROR_DECL() yyerror(const char *s)
#define YYERROR_CALL(msg) yyerror(msg)

extern int YYPARSE_DECL();

#define kw_TRUE 257
#define kw_FALSE 258
#define kw_AND 259
#define kw_OR 260
#define kw_IN 261
#define kw_TAILMATCH 262
#define NUMBER 263
#define STRING 264
#define IDENTIFIER 265
#define YYERRCODE 256
static const short yylhs[] = {                           -1,
    0,    1,    1,    1,    1,    1,    1,    1,    4,    4,
    2,    2,    2,    2,    2,    3,    3,    3,    3,    5,
    6,    7,    8,    9,    9,
};
static const short yylen[] = {                            2,
    1,    1,    1,    2,    3,    3,    3,    1,    1,    3,
    4,    4,    3,    5,    3,    1,    1,    1,    1,    1,
    1,    4,    4,    3,    1,
};
static const short yydefred[] = {                         0,
    2,    3,   20,   21,    0,    0,    0,    0,    0,    0,
    8,    0,   16,   17,   18,   19,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    7,    0,
    0,    0,    0,    0,   15,   13,    0,    0,    0,   22,
    0,   23,    0,   12,   11,   10,   24,   14,
};
static const short yydgoto[] = {                          9,
   10,   11,   12,   28,   13,   14,   15,   16,   31,
};
static const short yysindex[] = {                       -33,
    0,    0,    0,    0,  -23,  -33,  -33, -105,    0, -247,
    0,  -28,    0,    0,    0,    0,  -36, -247,  -39, -244,
  -33,  -33,  -26,  -36,  -38,  -37,  -22,  -16,    0,  -19,
  -97, -247, -247,  -36,    0,    0,  -36,  -36,  -36,    0,
 -244,    0,   -9,    0,    0,    0,    0,    0,
};
static const short yyrindex[] = {                         0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   36,
    0,    0,    0,    0,    0,    0,    0,    3,    0,    0,
    0,    0,    0,    0,    0,    0,   -4,    0,    0,  -87,
    0,    6,    8,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,
};
static const short yygindex[] = {                         0,
   13,    0,   -8,  -24,    0,    0,    0,   16,   -1,
};
#define YYTABLESIZE 234
static const short yytable[] = {                          6,
    8,   29,    4,    8,   25,    5,    7,    6,   27,   43,
    8,   21,   22,   34,   46,   36,   17,   20,   18,   19,
   30,   39,   37,   38,   40,   27,   41,   42,   44,   45,
   27,   48,   26,   32,   33,    1,    9,   25,   35,   47,
    0,    0,    0,    4,    0,    0,    5,    0,    6,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   21,
   22,    0,    0,    1,    2,    0,    3,    4,    5,    3,
    4,    5,   23,   24,
};
static const short yycheck[] = {                         33,
   37,   41,    0,   37,   33,    0,   40,    0,   17,   34,
   37,  259,  260,   40,   39,   24,   40,  123,    6,    7,
  265,   44,   61,   61,   41,   34,   46,  125,   37,   38,
   39,   41,   61,   21,   22,    0,   41,  125,   23,   41,
   -1,   -1,   -1,   41,   -1,   -1,   41,   -1,   41,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  259,
  260,   -1,   -1,  257,  258,   -1,  263,  264,  265,  263,
  264,  265,  261,  262,
};
#define YYFINAL 9
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 265
#if YYDEBUG
static const char *yyname[] = {

"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,"'%'",0,0,"'('","')'",0,0,"','",0,"'.'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'='",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,"kw_TRUE","kw_FALSE","kw_AND","kw_OR","kw_IN","kw_TAILMATCH","NUMBER",
"STRING","IDENTIFIER",
};
static const char *yyrule[] = {
"$accept : start",
"start : expr",
"expr : kw_TRUE",
"expr : kw_FALSE",
"expr : '!' expr",
"expr : expr kw_AND expr",
"expr : expr kw_OR expr",
"expr : '(' expr ')'",
"expr : comp",
"words : word",
"words : word ',' words",
"comp : word '=' '=' word",
"comp : word '!' '=' word",
"comp : word kw_TAILMATCH word",
"comp : word kw_IN '(' words ')'",
"comp : word kw_IN variable",
"word : number",
"word : string",
"word : function",
"word : variable",
"number : NUMBER",
"string : STRING",
"function : IDENTIFIER '(' words ')'",
"variable : '%' '{' variables '}'",
"variables : IDENTIFIER '.' variables",
"variables : IDENTIFIER",

};
#endif
/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 500
#define YYMAXDEPTH  500
#endif
#endif

#define YYINITSTACKSIZE 500

int      yydebug;
int      yynerrs;

typedef struct {
    unsigned stacksize;
    short    *s_base;
    short    *s_mark;
    short    *s_last;
    YYSTYPE  *l_base;
    YYSTYPE  *l_mark;
} YYSTACKDATA;
int      yyerrflag;
int      yychar;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* variables for the parser stack */
static YYSTACKDATA yystack;

#if YYDEBUG
#include <stdio.h>		/* needed for printf */
#endif

#include <stdlib.h>	/* needed for malloc, etc */
#include <string.h>	/* needed for memset */

/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(YYSTACKDATA *data)
{
    int i;
    unsigned newsize;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = data->stacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = data->s_mark - data->s_base;
    newss = (short *)realloc(data->s_base, newsize * sizeof(*newss));
    if (newss == 0)
        return -1;

    data->s_base = newss;
    data->s_mark = newss + i;

    newvs = (YYSTYPE *)realloc(data->l_base, newsize * sizeof(*newvs));
    if (newvs == 0)
        return -1;

    data->l_base = newvs;
    data->l_mark = newvs + i;

    data->stacksize = newsize;
    data->s_last = data->s_base + newsize - 1;
    return 0;
}

#if YYPURE || defined(YY_NO_LEAKS)
static void yyfreestack(YYSTACKDATA *data)
{
    free(data->s_base);
    free(data->l_base);
    memset(data, 0, sizeof(*data));
}
#else
#define yyfreestack(data) /* nothing */
#endif

#define YYABORT  goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR  goto yyerrlab

int
YYPARSE_DECL()
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;
    yystate = 0;

#if YYPURE
    memset(&yystack, 0, sizeof(yystack));
#endif

    if (yystack.s_base == NULL && yygrowstack(&yystack)) goto yyoverflow;
    yystack.s_mark = yystack.s_base;
    yystack.l_mark = yystack.l_base;
    yystate = 0;
    *yystack.s_mark = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = YYLEX) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
        {
            goto yyoverflow;
        }
        yystate = yytable[yyn];
        *++yystack.s_mark = yytable[yyn];
        *++yystack.l_mark = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;

    yyerror("syntax error");

    goto yyerrlab;

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yystack.s_mark]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yystack.s_mark, yytable[yyn]);
#endif
                if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
                {
                    goto yyoverflow;
                }
                yystate = yytable[yyn];
                *++yystack.s_mark = yytable[yyn];
                *++yystack.l_mark = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yystack.s_mark);
#endif
                if (yystack.s_mark <= yystack.s_base) goto yyabort;
                --yystack.s_mark;
                --yystack.l_mark;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yystack.l_mark[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 1:
	{ _hx509_expr_input.expr = yystack.l_mark[0].expr; }
break;
case 2:
	{ yyval.expr = _hx509_make_expr(op_TRUE, NULL, NULL); }
break;
case 3:
	{ yyval.expr = _hx509_make_expr(op_FALSE, NULL, NULL); }
break;
case 4:
	{ yyval.expr = _hx509_make_expr(op_NOT, yystack.l_mark[0].expr, NULL); }
break;
case 5:
	{ yyval.expr = _hx509_make_expr(op_AND, yystack.l_mark[-2].expr, yystack.l_mark[0].expr); }
break;
case 6:
	{ yyval.expr = _hx509_make_expr(op_OR, yystack.l_mark[-2].expr, yystack.l_mark[0].expr); }
break;
case 7:
	{ yyval.expr = yystack.l_mark[-1].expr; }
break;
case 8:
	{ yyval.expr = _hx509_make_expr(op_COMP, yystack.l_mark[0].expr, NULL); }
break;
case 9:
	{ yyval.expr = _hx509_make_expr(expr_WORDS, yystack.l_mark[0].expr, NULL); }
break;
case 10:
	{ yyval.expr = _hx509_make_expr(expr_WORDS, yystack.l_mark[-2].expr, yystack.l_mark[0].expr); }
break;
case 11:
	{ yyval.expr = _hx509_make_expr(comp_EQ, yystack.l_mark[-3].expr, yystack.l_mark[0].expr); }
break;
case 12:
	{ yyval.expr = _hx509_make_expr(comp_NE, yystack.l_mark[-3].expr, yystack.l_mark[0].expr); }
break;
case 13:
	{ yyval.expr = _hx509_make_expr(comp_TAILEQ, yystack.l_mark[-2].expr, yystack.l_mark[0].expr); }
break;
case 14:
	{ yyval.expr = _hx509_make_expr(comp_IN, yystack.l_mark[-4].expr, yystack.l_mark[-1].expr); }
break;
case 15:
	{ yyval.expr = _hx509_make_expr(comp_IN, yystack.l_mark[-2].expr, yystack.l_mark[0].expr); }
break;
case 16:
	{ yyval.expr = yystack.l_mark[0].expr; }
break;
case 17:
	{ yyval.expr = yystack.l_mark[0].expr; }
break;
case 18:
	{ yyval.expr = yystack.l_mark[0].expr; }
break;
case 19:
	{ yyval.expr = yystack.l_mark[0].expr; }
break;
case 20:
	{ yyval.expr = _hx509_make_expr(expr_NUMBER, yystack.l_mark[0].string, NULL); }
break;
case 21:
	{ yyval.expr = _hx509_make_expr(expr_STRING, yystack.l_mark[0].string, NULL); }
break;
case 22:
	{
			yyval.expr = _hx509_make_expr(expr_FUNCTION, yystack.l_mark[-3].string, yystack.l_mark[-1].expr); }
break;
case 23:
	{ yyval.expr = yystack.l_mark[-1].expr; }
break;
case 24:
	{
			yyval.expr = _hx509_make_expr(expr_VAR, yystack.l_mark[-2].string, yystack.l_mark[0].expr); }
break;
case 25:
	{
			yyval.expr = _hx509_make_expr(expr_VAR, yystack.l_mark[0].string, NULL); }
break;
    }
    yystack.s_mark -= yym;
    yystate = *yystack.s_mark;
    yystack.l_mark -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yystack.s_mark = YYFINAL;
        *++yystack.l_mark = yyval;
        if (yychar < 0)
        {
            if ((yychar = YYLEX) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yystack.s_mark, yystate);
#endif
    if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
    {
        goto yyoverflow;
    }
    *++yystack.s_mark = (short) yystate;
    *++yystack.l_mark = yyval;
    goto yyloop;

yyoverflow:
    yyerror("yacc stack overflow");

yyabort:
    yyfreestack(&yystack);
    return (1);

yyaccept:
    yyfreestack(&yystack);
    return (0);
}
