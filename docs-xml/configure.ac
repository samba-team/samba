AC_INIT(xslt/latex.xsl)

LATEX_DOCUMENTCLASS_OPTIONS="letterpaper,11pt,openright,twoside"
AC_SUBST(LATEX_DOCUMENTCLASS_OPTIONS)

DOC_BUILD_DATE=`date '+%d-%m-%Y'`
AC_SUBST(DOC_BUILD_DATE)

DOCS_TARGET_REQUIRE_PROGRAM(XSLTPROC, xsltproc, ALL)
DOCS_TARGET_REQUIRE_PROGRAM(RM, rm, ALL)

DOCS_TARGET_REQUIRE_PROGRAM(PNGTOPNM, pngtopnm, PS)
DOCS_TARGET_REQUIRE_PROGRAM(PNMTOPS, pnmtops, PS)
DOCS_TARGET_REQUIRE_PROGRAM(DBLATEX, dblatex, LATEX)
DOCS_TARGET_REQUIRE_PROGRAM(XMLLINT, xmllint, VALIDATE)

AC_MSG_RESULT([])
AC_MSG_RESULT([Summary:])
AC_MSG_RESULT([--------------])

DOCS_DEFINE_TARGET(ALL, [], [base requirements], [])
DOCS_DEFINE_TARGET(LATEX, ALL, [LaTeX versions], [tex ps pdf])
DOCS_DEFINE_TARGET(HTML, ALL, [HTML versions], [html])
DOCS_DEFINE_TARGET(HTMLHELP, ALL, [HTML Help versions], [htmlhelp])
DOCS_DEFINE_TARGET(HTMLMAN, ALL, [HTML versions of the manpages], [htmlman])
DOCS_DEFINE_TARGET(MANPAGES, ALL, [manpages], [manpages])
DOCS_DEFINE_TARGET(VALIDATE, ALL, [validating docbook output], [])

if test x"$TARGETS" = x; then 
	AC_MSG_ERROR([You won't be able to build any of the docs])
else 
	AC_MSG_RESULT([You will be able to build: $TARGETS])
fi

AC_SUBST(TARGETS)

. ../VERSION
if test x"$DOC_VERSION" = x; then
	#AC_MSG_ERROR([Please export DOC_VERSION variable])
	VERSION_SUFFIX=""
	if test x"$SAMBA_VERSION_PRE_RELEASE" != x; then
		VERSION_SUFFIX=pre
	fi
	DOC_VERSION=${SAMBA_VERSION_MAJOR}.${SAMBA_VERSION_MINOR}.${SAMBA_VERSION_RELEASE}${VERSION_SUFFIX}
else
	AC_MSG_RESULT([DOC_VERSION: ${DOC_VERSION}])
fi

doc_version="${DOC_VERSION}"
AC_SUBST(doc_version)
AC_OUTPUT( Makefile.settings build/catalog.xml build/DTD/samba.build.version)
