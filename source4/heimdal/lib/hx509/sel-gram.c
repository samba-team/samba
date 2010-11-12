#ifndef lint
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif

#include <stdlib.h>
#include <string.h>

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20070509

#define YYEMPTY (-1)
#define yyclearin    (yychar = YYEMPTY)
#define yyerrok      (yyerrflag = 0)
#define YYRECOVERING (yyerrflag != 0)

extern int yyparse(void);

static int yygrowstack(void);
#define YYPREFIX "yy"
#line 35 ""
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <hx_locl.h>


#line 45 ""
typedef union {
    char *string;
    struct hx_expr *expr;
} YYSTYPE;
#line 37 ""
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
short yylhs[] = {                                        -1,
    0,    1,    1,    1,    1,    1,    1,    1,    4,    4,
    2,    2,    2,    2,    2,    3,    3,    3,    3,    5,
    6,    7,    8,    9,    9,
};
short yylen[] = {                                         2,
    1,    1,    1,    2,    3,    3,    3,    1,    1,    3,
    4,    4,    3,    5,    3,    1,    1,    1,    1,    1,
    1,    4,    4,    3,    1,
};
short yydefred[] = {                                      0,
    2,    3,   20,   21,    0,    0,    0,    0,    0,    0,
    8,    0,   16,   17,   18,   19,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    7,    0,
    0,    0,    0,    0,   15,   13,    0,    0,    0,   22,
    0,   23,    0,   12,   11,   10,   24,   14,
};
short yydgoto[] = {                                       9,
   10,   11,   12,   28,   13,   14,   15,   16,   31,
};
short yysindex[] = {                                    -33,
    0,    0,    0,    0,  -23,  -33,  -33, -105,    0, -247,
    0,  -28,    0,    0,    0,    0,  -36, -247,  -39, -244,
  -33,  -33,  -26,  -36,  -38,  -37,  -22,  -16,    0,  -19,
  -97, -247, -247,  -36,    0,    0,  -36,  -36,  -36,    0,
 -244,    0,   -9,    0,    0,    0,    0,    0,
};
short yyrindex[] = {                                      0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   36,
    0,    0,    0,    0,    0,    0,    0,    3,    0,    0,
    0,    0,    0,    0,    0,    0,   -4,    0,    0,  -87,
    0,    6,    8,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,
};
short yygindex[] = {                                      0,
   13,    0,   -8,  -24,    0,    0,    0,   16,   -1,
};
#define YYTABLESIZE 234
short yytable[] = {                                       6,
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
short yycheck[] = {                                      33,
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
char *yyname[] = {
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
char *yyrule[] = {
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
#if YYDEBUG
#include <stdio.h>
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
int      yyerrflag;
int      yychar;
short   *yyssp;
YYSTYPE *yyvsp;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* variables for the parser stack */
static short   *yyss;
static short   *yysslim;
static YYSTYPE *yyvs;
static int      yystacksize;
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(void)
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = yyssp - yyss;
    newss = (yyss != 0)
          ? (short *)realloc(yyss, newsize * sizeof(*newss))
          : (short *)malloc(newsize * sizeof(*newss));
    if (newss == 0)
        return -1;

    yyss  = newss;
    yyssp = newss + i;
    newvs = (yyvs != 0)
          ? (YYSTYPE *)realloc(yyvs, newsize * sizeof(*newvs))
          : (YYSTYPE *)malloc(newsize * sizeof(*newvs));
    if (newvs == 0)
        return -1;

    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
yyparse(void)
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register const char *yys;

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

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
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
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
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

#ifdef lint
    goto yyerrlab;
#endif

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
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
        yyval = yyvsp[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 1:
#line 73 ""
{ _hx509_expr_input.expr = yyvsp[0].expr; }
break;
case 2:
#line 75 ""
{ yyval.expr = _hx509_make_expr(op_TRUE, NULL, NULL); }
break;
case 3:
#line 76 ""
{ yyval.expr = _hx509_make_expr(op_FALSE, NULL, NULL); }
break;
case 4:
#line 77 ""
{ yyval.expr = _hx509_make_expr(op_NOT, yyvsp[0].expr, NULL); }
break;
case 5:
#line 78 ""
{ yyval.expr = _hx509_make_expr(op_AND, yyvsp[-2].expr, yyvsp[0].expr); }
break;
case 6:
#line 79 ""
{ yyval.expr = _hx509_make_expr(op_OR, yyvsp[-2].expr, yyvsp[0].expr); }
break;
case 7:
#line 80 ""
{ yyval.expr = yyvsp[-1].expr; }
break;
case 8:
#line 81 ""
{ yyval.expr = _hx509_make_expr(op_COMP, yyvsp[0].expr, NULL); }
break;
case 9:
#line 84 ""
{ yyval.expr = _hx509_make_expr(expr_WORDS, yyvsp[0].expr, NULL); }
break;
case 10:
#line 85 ""
{ yyval.expr = _hx509_make_expr(expr_WORDS, yyvsp[-2].expr, yyvsp[0].expr); }
break;
case 11:
#line 88 ""
{ yyval.expr = _hx509_make_expr(comp_EQ, yyvsp[-3].expr, yyvsp[0].expr); }
break;
case 12:
#line 89 ""
{ yyval.expr = _hx509_make_expr(comp_NE, yyvsp[-3].expr, yyvsp[0].expr); }
break;
case 13:
#line 90 ""
{ yyval.expr = _hx509_make_expr(comp_TAILEQ, yyvsp[-2].expr, yyvsp[0].expr); }
break;
case 14:
#line 91 ""
{ yyval.expr = _hx509_make_expr(comp_IN, yyvsp[-4].expr, yyvsp[-1].expr); }
break;
case 15:
#line 92 ""
{ yyval.expr = _hx509_make_expr(comp_IN, yyvsp[-2].expr, yyvsp[0].expr); }
break;
case 16:
#line 95 ""
{ yyval.expr = yyvsp[0].expr; }
break;
case 17:
#line 96 ""
{ yyval.expr = yyvsp[0].expr; }
break;
case 18:
#line 97 ""
{ yyval.expr = yyvsp[0].expr; }
break;
case 19:
#line 98 ""
{ yyval.expr = yyvsp[0].expr; }
break;
case 20:
#line 101 ""
{ yyval.expr = _hx509_make_expr(expr_NUMBER, yyvsp[0].string, NULL); }
break;
case 21:
#line 102 ""
{ yyval.expr = _hx509_make_expr(expr_STRING, yyvsp[0].string, NULL); }
break;
case 22:
#line 104 ""
{
			yyval.expr = _hx509_make_expr(expr_FUNCTION, yyvsp[-3].string, yyvsp[-1].expr); }
break;
case 23:
#line 107 ""
{ yyval.expr = yyvsp[-1].expr; }
break;
case 24:
#line 110 ""
{
			yyval.expr = _hx509_make_expr(expr_VAR, yyvsp[-2].string, yyvsp[0].expr); }
break;
case 25:
#line 112 ""
{
			yyval.expr = _hx509_make_expr(expr_VAR, yyvsp[0].string, NULL); }
break;
#line 500 ""
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
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
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;

yyoverflow:
    yyerror("yacc stack overflow");

yyabort:
    return (1);

yyaccept:
    return (0);
}
