function func_footer() {
	printf("\n\
\n\
	return True;\n\
}\n");
}

function func_header(func_name, struct_name)
{
	printf("\
/*******************************************************************\n\
parse a %s structure\n\
********************************************************************/  \n\
BOOL %s(char *desc, %s **q_u, \n\
                                          prs_struct *ps, int depth)\n\
{	\n\
	%s *il;\n\
	\n\
	prs_debug(ps, depth, desc, \"%s\");\n\
	depth++;\n\
		\n\
	/* reading */\n\
	if (UNMARSHALLING(ps)) {\n\
		il=(%s *)malloc(sizeof(%s));\n\
		if(il == NULL)\n\
			return False;\n\
		ZERO_STRUCTP(il);\n\
		*q_u=il;\n\
	}\n\
	else {\n\
		il=*q_u;\n\
	}\n\
	\n\
	if(!prs_align(ps))\n\
		return False;\n\
\n\
", struct_name, func_name, struct_name, struct_name, func_name, struct_name, struct_name);
}

