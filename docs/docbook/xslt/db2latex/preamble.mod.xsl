<?xml version='1.0'?>
<!--############################################################################# 
|- #############################################################################
|
|   PURPOSE: Variables and templates to manage LaTeX preamble. 
+ ############################################################################## -->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>


    <doc:reference id="preamble" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
	    </releaseinfo>
	<authorgroup>
	    <author> <firstname>Ramon</firstname> <surname>Casellas</surname> </author>
	    <author> <firstname>James</firstname> <surname>Devenish</surname> </author>
	</authorgroup>
	    <copyright><year>2000</year><year>2001</year><year>2002</year><year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>

	<title>Variables and Templates used in LaTeX Preamble Generation</title>

	<partintro>
	    <section><title>Introduction</title>
		<para> This section described the variables and templates that are used in the generation of
		    the outtput LaTeX preamble. Basically, the LaTeX preamble depends on the XML document, that is,
		    on whether it is an article or a book.</para>
	    </section>

	    <section><title>Flow</title>
		<section><title>Articles</title>
		    <para></para>
		</section>
		<section><title>Books</title>
		    <para></para>
		</section>
	    </section>
	</partintro>
    </doc:reference>



    <!--#############################################################################
    |  	generate.latex.article.preamble and generate.latex.book.preamble	
    |- #############################################################################
    |	Top-level named templates.
    |	LaTeX Preamble.
    |
    + ############################################################################## -->

    <!-- DOCUMENTATION -->
    <doc:template name="generate.latex.article.preamble" xmlns="">
	<refpurpose> Top level template, called by article template, 
	    responsible of generating the LaTeX preamble according to user 
	    XSL variables and templates.
	</refpurpose>
	<refdescription>
	    <formalpara><title>Overview</title>
		If the xsl:variable <literal>latex.override</literal>
		is empty, the template outputs <literal>latex.article.preamblestart</literal> 
		and calls <literal>generate.latex.common.preamble</literal>. Otherwise,
		it outputs the value of <literal>latex.override</literal> and
		exists.
	    </formalpara>
	</refdescription>
	<refauthor>Ramon Casellas <email>casellas@aist.enst.fr</email></refauthor>
    </doc:template>

    <!-- TEMPLATE -->
    <xsl:template name="generate.latex.article.preamble">
	<xsl:choose>
	    <xsl:when test="$latex.override = ''">
		<xsl:value-of select="$latex.article.preamblestart"/>
		<xsl:value-of select="$latex.article.preamble.pre"/>
		<xsl:call-template name="label.id"/>
		<xsl:call-template name="generate.latex.common.preamble"/>
		<xsl:call-template name="generate.latex.essential.preamble"/>
		<xsl:value-of select="$latex.article.preamble.post"/>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:value-of select="$latex.override"/>
		<xsl:call-template name="generate.latex.essential.preamble"/>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <!-- DOCUMENTATION -->
    <doc:template name="generate.latex.book.preamble" xmlns="">
	<refpurpose> Top level template, called by book template, 
	    responsible of generating the LaTeX preamble according to user 
	    XSL variables and templates.
	</refpurpose>
	<refdescription>
	    <formalpara><title>Overview</title>
		If the xsl:variable <literal>latex.override</literal>
		is empty, the template outputs <literal>latex.book.preamblestart</literal> 
		and calls <literal>generate.latex.common.preamble</literal>. Otherwise,
		it outputs the value of <literal>latex.override</literal> and
		exists.
	    </formalpara>
	</refdescription>
	<refauthor>Ramon Casellas <email>casellas@aist.enst.fr</email></refauthor>
    </doc:template>

    <!-- TEMPLATE -->
    <xsl:template name="generate.latex.book.preamble">
	<xsl:choose>
	    <xsl:when test="$latex.override = ''">
		<xsl:value-of select="$latex.book.preamblestart"/>
		<xsl:value-of select="$latex.book.preamble.pre"/>
		<xsl:call-template name="label.id"/>
		<xsl:call-template name="generate.latex.common.preamble"/>
		<xsl:call-template name="generate.latex.essential.preamble"/>
		<xsl:value-of select="$latex.book.preamble.post"/>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:value-of select="$latex.override"/>
		<xsl:call-template name="generate.latex.essential.preamble"/>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>






    <!--#############################################################################
    |   latex.article.preamblestart and latex.book.preamblestart	
    |- #############################################################################
    |
    + ############################################################################## -->

    <doc:variable name="latex.article.preamblestart" xmlns="">
	<refpurpose> Generated Document class for articles.  </refpurpose>
	<refdescription>
	</refdescription>
	<refreturn>
	    <screen>
		% --------------------------------------------	
		% Autogenerated LaTeX file for articles 	
		% --------------------------------------------	
		\ifx\pdfoutput\undefined
		\documentclass[spanish,french,english,a4paper,10pt,twoside,twocolumn]{article}
		\else
		\documentclass[pdftex,spanish,french,english,a4paper,10pt,twoside,twocolumn]{article}
		\fi
	    </screen>
	</refreturn>
    </doc:variable>

    <xsl:variable name="latex.article.preamblestart">
	<xsl:text>% --------------------------------------------	&#10;</xsl:text>
	<xsl:text>% Autogenerated LaTeX file for articles 			&#10;</xsl:text>
	<xsl:text>% --------------------------------------------	&#10;</xsl:text>
	<xsl:text>\ifx\pdfoutput\undefined&#10;</xsl:text>
	<xsl:text>\documentclass[</xsl:text>
	<xsl:value-of select='$latex.documentclass.common' />
	<xsl:text>,</xsl:text>
	<xsl:value-of select='$latex.documentclass.article' />
	<xsl:text>,</xsl:text>
	<xsl:value-of select='$latex.documentclass.pdftex' />
	<xsl:text>]{</xsl:text>
	<xsl:choose>
		<xsl:when test="$latex.documentclass!=''"><xsl:value-of select="$latex.documentclass" /></xsl:when>
		<xsl:otherwise><xsl:text>article</xsl:text></xsl:otherwise>
	</xsl:choose>
	<xsl:text>}&#10;</xsl:text>
	<xsl:text>\else&#10;</xsl:text>
	<xsl:text>\documentclass[pdftex,</xsl:text>
	<xsl:value-of select='$latex.documentclass.common' />
	<xsl:text>,</xsl:text>
	<xsl:value-of select='$latex.documentclass.article' />
	<xsl:text>,</xsl:text>
	<xsl:value-of select='$latex.documentclass.dvips' />
	<xsl:text>]{</xsl:text>
	<xsl:choose>
		<xsl:when test="$latex.documentclass!=''"><xsl:value-of select="$latex.documentclass" /></xsl:when>
		<xsl:otherwise><xsl:text>article</xsl:text></xsl:otherwise>
	</xsl:choose>
	<xsl:text>}&#10;</xsl:text>
	<xsl:text>\fi&#10;</xsl:text>
    </xsl:variable>
	
    <doc:variable name="latex.book.preamblestart" xmlns="">
	<refpurpose>Generated Document class for books. </refpurpose>
	<refdescription>
	</refdescription>
	<refreturn>
	    <screen>
		% ------------------------------------------------------------
		% Autogenerated LaTeX file for books	
		% ------------------------------------------------------------	
		\ifx\pdfoutput\undefined
		\documentclass[spanish,french,english,a4paper,twoside,openright,10pt,final]{report}	
		\else
		\documentclass[pdftex,spanish,french,english,a4paper,twoside,openright,10pt,final]{report}
		\fi
	    </screen>
	</refreturn>
    </doc:variable>

    <xsl:variable name="latex.book.preamblestart">
	<xsl:text>% ------------------------------------------------------------	&#10;</xsl:text>
	<xsl:text>% Autogenerated LaTeX file for books	&#10;</xsl:text>
	<xsl:text>% ------------------------------------------------------------	&#10;</xsl:text>
	<xsl:text>\ifx\pdfoutput\undefined&#10;</xsl:text>
	<xsl:text>\documentclass[</xsl:text>
	<xsl:value-of select='$latex.documentclass.common' />
	<xsl:text>,</xsl:text>
	<xsl:value-of select='$latex.documentclass.book' />
	<xsl:text>,</xsl:text>
	<xsl:value-of select='$latex.documentclass.pdftex' />
	<xsl:text>]{</xsl:text>
	<xsl:choose>
		<xsl:when test="$latex.documentclass!=''"><xsl:value-of select="$latex.documentclass" /></xsl:when>
		<xsl:otherwise><xsl:text>report</xsl:text></xsl:otherwise>
	</xsl:choose>
	<xsl:text>}&#10;</xsl:text>
	<xsl:text>\else&#10;</xsl:text>
	<xsl:text>\documentclass[pdftex,</xsl:text>
	<xsl:value-of select='$latex.documentclass.common' />
	<xsl:text>,</xsl:text>
	<xsl:value-of select='$latex.documentclass.book' />
	<xsl:text>,</xsl:text>
	<xsl:value-of select='$latex.documentclass.dvips' />
	<xsl:text>]{</xsl:text>
	<xsl:choose>
		<xsl:when test="$latex.documentclass!=''"><xsl:value-of select="$latex.documentclass" /></xsl:when>
		<xsl:otherwise><xsl:text>report</xsl:text></xsl:otherwise>
	</xsl:choose>
	<xsl:text>}&#10;</xsl:text>
	<xsl:text>\fi&#10;</xsl:text>
    </xsl:variable>

    <!--#############################################################################
    |  	generate.latex.common.preamble 
    |- #############################################################################
    |
    + ############################################################################## -->

    <doc:variable name="generate.latex.common.preamble" xmlns="">
	<refpurpose> Common LaTeX preamble shared by articles and books, and other
	    document classes. Most of the packages and package options are managed here </refpurpose>
	<refdescription>
	</refdescription>
	<refreturn>
	    The LaTeX preamble, after the document class and before the <literal>\begin{document}</literal>
	    command.
	</refreturn>
    </doc:variable>



	<xsl:template name="generate.latex.common.preamble">
	<xsl:choose>
		<xsl:when test="$latex.pdf.support=1"><xsl:value-of select="$latex.pdf.preamble"/></xsl:when>
		<xsl:otherwise><xsl:text>\usepackage{graphicx}&#10;</xsl:text></xsl:otherwise>
	</xsl:choose>
	<xsl:if test="local-name(.)='article'">
	    <xsl:value-of select="$latex.article.varsets"/>
	</xsl:if>
	<xsl:if test="local-name(.)='book'">
	    <xsl:value-of select="$latex.book.varsets"/>
	</xsl:if>
	<xsl:if test="$latex.use.fancyhdr=1">
	    <xsl:text>\usepackage{fancyhdr}&#10;</xsl:text>
	    <xsl:call-template name="generate.latex.pagestyle"/>
	    <!-- 
	    Add dollar...
	    <xsl:if test="latex.fancyhdr.lh !=''"><xsl:text>\lhead{</xsl:text><xsl:value-of select="$latex.fancyhdr.lh"/><xsl:text>}&#10;</xsl:text></xsl:if>
	    <xsl:if test="latex.fancyhdr.ch !=''"><xsl:text>\chead{</xsl:text><xsl:value-of select="$latex.fancyhdr.ch"/><xsl:text>}&#10;</xsl:text></xsl:if>
	    <xsl:if test="latex.fancyhdr.rh !=''"><xsl:text>\rhead{</xsl:text><xsl:value-of select="$latex.fancyhdr.rh"/><xsl:text>}&#10;</xsl:text></xsl:if>
	    <xsl:if test="latex.fancyhdr.lf !=''"><xsl:text>\lfoot{</xsl:text><xsl:value-of select="$latex.fancyhdr.lf"/><xsl:text>}&#10;</xsl:text></xsl:if>
	    <xsl:if test="latex.fancyhdr.cf !=''"><xsl:text>\cfoot{</xsl:text><xsl:value-of select="$latex.fancyhdr.cf"/><xsl:text>}&#10;</xsl:text></xsl:if>
	    <xsl:if test="latex.fancyhdr.rf !=''"><xsl:text>\rfoot{</xsl:text><xsl:value-of select="$latex.fancyhdr.rf"/><xsl:text>}&#10;</xsl:text></xsl:if> 
	    -->

	    <xsl:text>\renewcommand{\headrulewidth}{0.4pt}&#10;</xsl:text>
	    <xsl:text>\renewcommand{\footrulewidth}{0.4pt}&#10;</xsl:text>
	</xsl:if>

	<xsl:text>% ---------------------- &#10;</xsl:text>
	<xsl:text>% Most Common Packages   &#10;</xsl:text>
	<xsl:text>% ---------------------- &#10;</xsl:text>
	<xsl:if test="$latex.use.makeidx=1"><xsl:text>\usepackage{makeidx} &#10;</xsl:text></xsl:if>
	<xsl:text>\usepackage{varioref}         &#10;</xsl:text>
	<xsl:text>\usepackage{latexsym}         &#10;</xsl:text>
	<xsl:text>\usepackage{enumerate}         &#10;</xsl:text>
	<xsl:if test="$latex.use.fancybox=1">
		<!-- must be before \usepackage{fancyvrb} -->
		<xsl:text>\usepackage{fancybox}      &#10;</xsl:text>
	</xsl:if>
	<xsl:text>\usepackage{float}       &#10;</xsl:text>
	<xsl:text>\usepackage{ragged2e}       &#10;</xsl:text>
	<xsl:if test="$latex.babel.language!=''">
		<xsl:text>\usepackage[</xsl:text><xsl:value-of select="$latex.babel.language" /><xsl:text>]{babel} &#10;</xsl:text>
	</xsl:if>
	<xsl:if test="$latex.use.fancyvrb=1">
		<!-- must be after \usepackage{fancybox} -->
		<xsl:text>\usepackage{fancyvrb}         &#10;</xsl:text>
		<xsl:text>\makeatletter\@namedef{FV@fontfamily@default}{\def\FV@FontScanPrep{}\def\FV@FontFamily{}}\makeatother&#10;</xsl:text>
		<xsl:if test="$latex.fancyvrb.tabsize!=''">
			<xsl:text>\fvset{obeytabs=true,tabsize=</xsl:text>
			<xsl:value-of select="$latex.fancyvrb.tabsize"/>
			<xsl:text>}&#10;</xsl:text>
		</xsl:if>
	</xsl:if>
	<xsl:if test="$latex.use.isolatin1=1"><xsl:text>\usepackage{isolatin1}         &#10;</xsl:text></xsl:if>
	<xsl:if test="$latex.use.parskip=1"><xsl:text>\usepackage{parskip}         &#10;</xsl:text></xsl:if>
	<xsl:if test="$latex.use.rotating=1"><xsl:text>\usepackage{rotating}         &#10;</xsl:text></xsl:if>
	<xsl:if test="$latex.use.subfigure=1"><xsl:text>\usepackage{subfigure}         &#10;</xsl:text></xsl:if>
	<xsl:if test="$latex.use.tabularx=1"><xsl:text>\usepackage{tabularx}         &#10;</xsl:text></xsl:if>
	<xsl:if test="$latex.use.umoline=1"><xsl:text>\usepackage{umoline}         &#10;</xsl:text></xsl:if>
	<xsl:if test="$latex.use.url=1"><xsl:text>\usepackage{url}         &#10;</xsl:text></xsl:if>

	<!-- Configure document font. -->
	<xsl:if test="$latex.document.font != 'default'">
	    <xsl:text>% ---------------&#10;</xsl:text>
	    <xsl:text>% Document Font  &#10;</xsl:text>
	    <xsl:text>% ---------------&#10;</xsl:text>
	    <xsl:text>\usepackage{</xsl:text><xsl:value-of select="$latex.document.font"/><xsl:text>}&#10;</xsl:text>
	</xsl:if>
	<!-- Support for keywords. -->
	<xsl:text> \def\keywords{\vspace{-.3em}&#10;</xsl:text>
	<xsl:text> \if@twocolumn&#10;</xsl:text>
	<xsl:text> \small{\itshape &#10;</xsl:text>
	<xsl:call-template name="gentext">
        <xsl:with-param name="key">keywords</xsl:with-param>
    </xsl:call-template>
	<xsl:text> }\/\bfseries---$\!$%&#10;</xsl:text>
	<xsl:text> \else&#10;</xsl:text>
	<xsl:text> \begin{center}\small\bfseries &#10;</xsl:text>
	<xsl:call-template name="gentext">
        <xsl:with-param name="key">keywords</xsl:with-param>
    </xsl:call-template>
	<xsl:text> \end{center}\quotation\small&#10;</xsl:text>
	<xsl:text> \fi}&#10;</xsl:text>
	<xsl:text> \def\endkeywords{\vspace{0.6em}\par\if@twocolumn\else\endquotation\fi&#10;</xsl:text>
	<xsl:text> \normalsize\rmfamily}&#10;</xsl:text>

	<xsl:if test="$latex.math.support=1"><xsl:value-of select="$latex.math.preamble"/></xsl:if>
	<xsl:if test="$latex.use.hyperref=1">
		<xsl:call-template name="latex.hyperref.preamble"/>
	</xsl:if>
	<xsl:value-of select="$latex.admonition.environment"/>
	<xsl:call-template name="latex.float.preamble"/>
	<xsl:call-template name="latex.graphicext"/>
	<xsl:choose>
		<xsl:when test='$latex.caption.swapskip=1'>
			<xsl:text>% --------------------------------------------&#10;</xsl:text>
			<xsl:text>% $latex.caption.swapskip enabled for $formal.title.placement support&#10;</xsl:text>
			<xsl:text>\newlength{\docbooktolatextempskip}&#10;</xsl:text>
			<xsl:text>\newcommand{\captionswapskip}{\setlength{\docbooktolatextempskip}{\abovecaptionskip}</xsl:text>
			<xsl:text>\setlength{\abovecaptionskip}{\belowcaptionskip}</xsl:text>
			<xsl:text>\setlength{\belowcaptionskip}{\docbooktolatextempskip}}&#10;</xsl:text>
		</xsl:when>
		<xsl:otherwise>
			<xsl:text>\newcommand{\captionswapskip}{}&#10;</xsl:text>
		</xsl:otherwise>
	</xsl:choose>
	<xsl:if test='$latex.hyphenation.tttricks=1'>
		<xsl:text>% --------------------------------------------&#10;</xsl:text>
		<xsl:text>% Better linebreaks&#10;</xsl:text>
		<xsl:text>\newcommand{\docbookhyphenatedot}[1]{{\hyphenchar\font=`\.\relax #1\hyphenchar\font=`\-}}&#10;</xsl:text>
		<xsl:text>\newcommand{\docbookhyphenatefilename}[1]{{\hyphenchar\font=`\.\relax #1\hyphenchar\font=`\-}}&#10;</xsl:text>
		<xsl:text>\newcommand{\docbookhyphenateurl}[1]{{\hyphenchar\font=`\/\relax #1\hyphenchar\font=`\-}}&#10;</xsl:text>
	</xsl:if>
    </xsl:template>

    <doc:variable name="generate.latex.essential.preamble" xmlns="">
	<refpurpose> Unavoidable LaTeX preamble shared by articles and books </refpurpose>
	<refdescription>
	    <para>Contains custom commands <emphasis>that you just can't get rid of!</emphasis></para>
	</refdescription>
    </doc:variable>
	<xsl:template name="generate.latex.essential.preamble">
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>\makeatletter&#10;</xsl:text>
	<xsl:if test="$latex.use.hyperref!='1'">
		<xsl:text>\newcommand{\href}[1]{{}}&#10;</xsl:text>
		<xsl:text>\newcommand{\hyperlink}[1]{{}}&#10;</xsl:text>
		<xsl:text>\newcommand{\hypertarget}[2]{#2}&#10;</xsl:text>
	</xsl:if>
	<xsl:if test="$latex.use.ucs='1'">
		<xsl:text>\usepackage[</xsl:text>
		<xsl:value-of select="$latex.ucs.options"/>
		<xsl:text>]{ucs}&#10;</xsl:text>
	</xsl:if>
	<xsl:if test="$latex.entities='catcode'">
		<xsl:text>\catcode`\&amp;=\active\def&amp;{\@ifnextchar##{\@docbooktolatexunicode\@gobble}{\&amp;}}&#10;</xsl:text>
		<xsl:if test="$latex.use.ucs!='1'">
			<xsl:text><![CDATA[
% A few example Unicode characters.
% For full support, use the unicode pacakge from Dominique Unruh/CTAN.
\newcommand{\unichar}[1]{%
	\ifnum#1=8212---%
	\else\&\##1;\fi%
}
]]></xsl:text>
		</xsl:if>
		<xsl:text>\def\@docbooktolatexunicode#1;{\edef\@dbtemp{#1}\unichar{\@dbtemp}}&#10;</xsl:text>
	</xsl:if>
	<xsl:if test="$latex.entities='unicode'">
      <xsl:text>\usepackage[utf8]{inputenc}&#10;</xsl:text>
	</xsl:if>
	<xsl:text><![CDATA[
\def\docbooktolatexgobble{\expandafter\@gobble}
% Facilitate use of \cite with \label
\newcommand{\docbooktolatexbibaux}[2]{%
  \protected@write\@auxout{}{\string\global\string\@namedef{docbooktolatexcite@#1}{#2}}
}
\newcommand{\docbooktolatexcite}[2]{%
  \@ifundefined{docbooktolatexcite@#1}%
  {\cite{#1}}%
  {\def\@docbooktolatextemp{#2}\ifx\@docbooktolatextemp\@empty%
   \cite{\@nameuse{docbooktolatexcite@#1}}%
   \else\cite[#2]{\@nameuse{docbooktolatexcite@#1}}%
   \fi%
  }%
}
\newcommand{\docbooktolatexbackcite}[1]{%
  \ifx\Hy@backout\@undefined\else%
    \@ifundefined{docbooktolatexcite@#1}{%
      % emit warning?
    }{%
      \ifBR@verbose%
        \PackageInfo{backref}{back cite \string`#1\string' as \string`\@nameuse{docbooktolatexcite@#1}\string'}%
      \fi%
      \Hy@backout{\@nameuse{docbooktolatexcite@#1}}%
    }%
  \fi%
}
% --------------------------------------------
% A way to honour <footnoteref>s
% Blame j-devenish (at) users.sourceforge.net
% In any other LaTeX context, this would probably go into a style file.
\newcommand{\docbooktolatexusefootnoteref}[1]{\@ifundefined{@fn@label@#1}%
  {\hbox{\@textsuperscript{\normalfont ?}}%
    \@latex@warning{Footnote label `#1' was not defined}}%
  {\@nameuse{@fn@label@#1}}}
\newcommand{\docbooktolatexmakefootnoteref}[1]{%
  \protected@write\@auxout{}%
    {\global\string\@namedef{@fn@label@#1}{\@makefnmark}}%
  \@namedef{@fn@label@#1}{\hbox{\@textsuperscript{\normalfont ?}}}%
  }
% --------------------------------------------
% Hacks for honouring row/entry/@align
% (\hspace not effective when in paragraph mode)
% Naming convention for these macros is:
% 'docbooktolatex' 'align' {alignment-type} {position-within-entry}
% where r = right, l = left, c = centre
\newcommand{\docbooktolatexalignrl}{\protect\ifvmode\raggedleft\else\hfill\fi}
\newcommand{\docbooktolatexalignrr}{\protect}
\newcommand{\docbooktolatexalignll}{\protect\ifvmode\raggedright\else\fi}
\newcommand{\docbooktolatexalignlr}{\protect\ifvmode\else\hspace*\fill\fi}
\newcommand{\docbooktolatexaligncl}{\protect\ifvmode\centering\else\hfill\fi}
\newcommand{\docbooktolatexaligncr}{\protect\ifvmode\else\hspace*\fill\fi}
\ifx\captionswapskip\@undefined\newcommand{\captionswapskip}{}\fi
\makeatother
]]></xsl:text>
	</xsl:template>



    <!--#############################################################################
    | 	Auxiliary templates and variables 
    |- #############################################################################
    |
    + ############################################################################## -->

    <doc:template name="latex.float.preamble" xmlns="">
	<refpurpose> 
	</refpurpose>
	<refdescription>
	</refdescription>
    </doc:template>
    <xsl:template name="latex.float.preamble">
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>% Commands to manage/style/create floats      &#10;</xsl:text>
	<xsl:text>% figures, tables, algorithms, examples, eqn  &#10;</xsl:text>
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text> \floatstyle{ruled}&#10;</xsl:text>
	<xsl:text> \restylefloat{figure}&#10;</xsl:text>
	<xsl:text> \floatstyle{ruled}&#10;</xsl:text>
	<xsl:text> \restylefloat{table}&#10;</xsl:text>
	<xsl:text> \floatstyle{ruled}&#10;</xsl:text>
	<xsl:text> \newfloat{program}{ht}{lop}[section]&#10;</xsl:text>
	<xsl:text> \floatstyle{ruled}&#10;</xsl:text>
	<xsl:text> \newfloat{example}{ht}{loe}[section]&#10;</xsl:text>
	<xsl:text> \floatname{example}{</xsl:text>
	<xsl:call-template name="gentext.element.name">
	    <xsl:with-param name="element.name">example</xsl:with-param>
	</xsl:call-template>
	<xsl:text>}&#10;</xsl:text>
	<xsl:text> \floatstyle{ruled}&#10;</xsl:text>
	<xsl:text> \newfloat{dbequation}{ht}{loe}[section]&#10;</xsl:text>
	<xsl:text> \floatname{dbequation}{</xsl:text>
	<xsl:call-template name="gentext.element.name">
	    <xsl:with-param name="element.name">equation</xsl:with-param>
	</xsl:call-template>
	<xsl:text>}&#10;</xsl:text>
	<xsl:text> \floatstyle{boxed}&#10;</xsl:text>
	<xsl:text> \newfloat{algorithm}{ht}{loa}[section]&#10;</xsl:text>
	<xsl:text> \floatname{algorithm}{Algorithm}&#10;</xsl:text>
    </xsl:template>




    <!-- DOCUMENTATION -->
    <doc:variable name="latex.pdf.preamble" xmlns="">
	<refpurpose> 
	</refpurpose>
	<refdescription>
	    <formalpara><title>Default Value:</title>
		<screen>
		    \usepackage{ifthen}
		    % --------------------------------------------
		    % Check for PDFLaTeX/LaTeX 
		    % --------------------------------------------
		    \newif\ifpdf
		    \ifx\pdfoutput\undefined
		    \pdffalse % we are not running PDFLaTeX
		    \else
		    \pdfoutput=1 % we are running PDFLaTeX
		    \pdftrue
		    \fi
		    % --------------------------------------------
		    % Load graphicx package with pdf if needed 
		    % --------------------------------------------
		    \ifpdf
		    \usepackage[pdftex]{graphicx}
		    \pdfcompresslevel=9
		    \else
		    \usepackage{graphicx}
		    \fi
		</screen>
	    </formalpara>
	</refdescription>
	<refauthor>Ramon Casellas <email>casellas@aist.enst.fr</email></refauthor>
    </doc:variable>

    <!-- VARIABLE -->
    <xsl:variable name="latex.pdf.preamble">
	<xsl:text>\usepackage{ifthen}&#10;</xsl:text>
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>% Check for PDFLaTeX/LaTeX &#10;</xsl:text>
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>\newif\ifpdf&#10;</xsl:text>
	<xsl:text>\ifx\pdfoutput\undefined&#10;</xsl:text>
	<xsl:text>\pdffalse % we are not running PDFLaTeX&#10;</xsl:text>
	<xsl:text>\else&#10;</xsl:text>
	<xsl:text>\pdfoutput=1 % we are running PDFLaTeX&#10;</xsl:text>
	<xsl:text>\pdftrue&#10;</xsl:text>
	<xsl:text>\fi&#10;</xsl:text>
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>% Load graphicx package with pdf if needed &#10;</xsl:text>
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>\ifpdf&#10;</xsl:text>
	<xsl:text>\usepackage[pdftex]{graphicx}&#10;</xsl:text>
	<xsl:text>\pdfcompresslevel=9&#10;</xsl:text>
	<xsl:text>\else&#10;</xsl:text>
	<xsl:text>\usepackage{graphicx}&#10;</xsl:text>
	<xsl:text>\fi&#10;</xsl:text>
    </xsl:variable>



    <!-- DOCUMENTATION -->
    <doc:template name="latex.hyperref.preamble" xmlns="">
	<refpurpose> Manage the part of the preamble that handles the hyperref package.</refpurpose>
	<refdescription>
	    <para> This template outputs the LaTeX code <literal>\usepackage[...]{hyperref}</literal>
		in order to use hyperlinks, backrefs and other goodies. If PDF support is activated, 
		outputs laTeX code to detect whether the document is being compiled with 
		<filename>pdflatex</filename> or <filename>latex</filename> to supply the
		right parameters (pdftex, dvips, etc). </para>
	    <formalpara><title>To Do</title> The package options should be optained
		from XSL variables.</formalpara>
	    <formalpara><title>Default Value with PDF support</title>
		<screen>
		    % --------------------------------------------
		    % Load hyperref package with pdf if needed 
		    % --------------------------------------------
		    \ifpdf
		    \usepackage[pdftex,bookmarksnumbered,colorlinks,backref, bookmarks, breaklinks, linktocpage]{hyperref}
		    \else
		    \usepackage[dvips,bookmarksnumbered,colorlinks,backref, bookmarks, breaklinks, linktocpage]{hyperref}
		    \fi
		    % --------------------------------------------
		</screen>
	    </formalpara>
	    <formalpara><title>Default Value without PDF support</title>
		<screen>
		    % --------------------------------------------
		    % Load hyperref package 
		    % --------------------------------------------
		    \usepackage[dvips,bookmarksnumbered,colorlinks,backref, bookmarks, breaklinks, linktocpage]{hyperref}
		</screen>
	    </formalpara>
	</refdescription>
    </doc:template>
    <!-- TEMPLATE -->
    <xsl:template name="latex.hyperref.preamble">
	<xsl:choose>
	<xsl:when test="$latex.pdf.support=1">
	    <xsl:text>% --------------------------------------------&#10;</xsl:text>
	    <xsl:text>% Load hyperref package with pdf if needed &#10;</xsl:text>
	    <xsl:text>% --------------------------------------------&#10;</xsl:text>
	    <xsl:text>\ifpdf&#10;</xsl:text>
	    <xsl:text>\usepackage[pdftex,</xsl:text>
		<xsl:value-of select="$latex.hyperref.param.common" />
		<xsl:text>,</xsl:text>
		<xsl:value-of select="$latex.hyperref.param.pdftex" />
		<xsl:text>]{hyperref}&#10;</xsl:text>
	    <xsl:text>\else&#10;</xsl:text>
	    <xsl:text>\usepackage[dvips,</xsl:text>
		<xsl:value-of select="$latex.hyperref.param.common" />
		<xsl:text>,</xsl:text>
		<xsl:value-of select="$latex.hyperref.param.dvips" />
		<xsl:text>]{hyperref}&#10;</xsl:text>
	    <xsl:text>\fi&#10;</xsl:text>
	    <xsl:text>% --------------------------------------------&#10;</xsl:text>
	</xsl:when>
	<xsl:otherwise>
	    <xsl:text>% --------------------------------------------&#10;</xsl:text>
	    <xsl:text>% Load hyperref package &#10;</xsl:text>
	    <xsl:text>% --------------------------------------------&#10;</xsl:text>
	    <xsl:text>\usepackage[dvips,</xsl:text>
		<xsl:value-of select="$latex.hyperref.param.common" />
		<xsl:text>,</xsl:text>
		<xsl:value-of select="$latex.hyperref.param.dvips" />
		<xsl:text>]{hyperref}&#10;</xsl:text>
	</xsl:otherwise>
	</xsl:choose>
    </xsl:template>













    <!--#############################################################################
    |	latex.math.preamble	
    |-  #############################################################################
    |   This "preamble chunk" declares usage of most common AMS packages.
	|   Defines new useful commands. 
    +   ############################################################################## -->

    <!-- DOCUMENTATION -->
    <doc:variable name="latex.math.preamble" xmlns="">
	<refpurpose> Manage the math related preamble</refpurpose>
	<refdescription>
	</refdescription>
    </doc:variable>

    <!-- VARIABLE -->
    <xsl:variable name="latex.math.preamble">
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>% Math support                                &#10;</xsl:text>
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>\usepackage{amsmath,amsthm, amsfonts, amssymb, amsxtra,amsopn}&#10;</xsl:text>
	<xsl:text>%\newtheorem{thm}{Theorem}[section]&#10;</xsl:text>
	<xsl:text>%\newtheorem{cor}[section]{Corollary}&#10;</xsl:text>
	<xsl:text>%\newtheorem{lem}[section]{Lemma}&#10;</xsl:text>
	<xsl:text>%\newtheorem{defn}[section]{Definition}&#10;</xsl:text>
	<xsl:text>%\newtheorem{prop}[section]{Proposition}&#10;</xsl:text>
	<xsl:text>%\newtheorem{ax}{Axiom}&#10;</xsl:text>
	<xsl:text>%\newtheorem{theorem}[section]{Theorem}&#10;</xsl:text>
	<xsl:text>%\newtheorem{corollary}{Corollary}&#10;</xsl:text>
	<xsl:text>%\newtheorem{lemma}{Lemma}&#10;</xsl:text>
	<xsl:text>%\newtheorem{proposition}{Proposition}&#10;</xsl:text>
	<xsl:text>%\theoremstyle{definition}&#10;</xsl:text>
	<xsl:text>%\newtheorem{definition}{Definition}&#10;</xsl:text>
	<xsl:text>%\theoremstyle{remark}&#10;</xsl:text>
	<xsl:text>%\newtheorem{rem}{Remark}&#10;</xsl:text>
	<xsl:text>%\newtheorem*{notation}{Notation}&#10;</xsl:text>
	<xsl:text>%\newcommand{\ntt}{\normalfont\ttfamily}&#10;</xsl:text>
	<xsl:text>%\newcommand{\thmref}[1]{Theorem~\ref{#1}}&#10;</xsl:text>
	<xsl:text>%\newcommand{\secref}[1]{\S\ref{#1}}&#10;</xsl:text>
	<xsl:text>%\newcommand{\lemref}[1]{Lemma~\ref{#1}}&#10;</xsl:text>
	<xsl:text> \newcommand{\bysame}{\mbox{\rule{3em}{.4pt}}\,}&#10;</xsl:text>
	<xsl:text> \newcommand{\A}{\mathcal{A}}&#10;</xsl:text>
	<xsl:text> \newcommand{\B}{\mathcal{B}}&#10;</xsl:text>
	<xsl:text> \newcommand{\XcY}{{(X,Y)}}&#10;</xsl:text>
	<xsl:text> \newcommand{\SX}{{S_X}}&#10;</xsl:text>
	<xsl:text> \newcommand{\SY}{{S_Y}}&#10;</xsl:text>
	<xsl:text> \newcommand{\SXY}{{S_{X,Y}}}&#10;</xsl:text>
	<xsl:text> \newcommand{\SXgYy}{{S_{X|Y}(y)}}&#10;</xsl:text>
	<xsl:text> \newcommand{\Cw}[1]{{\hat C_#1(X|Y)}}&#10;</xsl:text>
	<xsl:text> \newcommand{\G}{{G(X|Y)}}&#10;</xsl:text>
	<xsl:text> \newcommand{\PY}{{P_{\mathcal{Y}}}}&#10;</xsl:text>
	<xsl:text> \newcommand{\X}{\mathcal{X}}&#10;</xsl:text>
	<xsl:text> \newcommand{\wt}{\widetilde}&#10;</xsl:text>
	<xsl:text> \newcommand{\wh}{\widehat}&#10;</xsl:text>
	<xsl:text> % --------------------------------------------&#10;</xsl:text>
	<xsl:text> %\DeclareMathOperator{\per}{per}&#10;</xsl:text>
	<xsl:text> \DeclareMathOperator{\cov}{cov}&#10;</xsl:text>
	<xsl:text> \DeclareMathOperator{\non}{non}&#10;</xsl:text>
	<xsl:text> \DeclareMathOperator{\cf}{cf}&#10;</xsl:text>
	<xsl:text> \DeclareMathOperator{\add}{add}&#10;</xsl:text>
	<xsl:text> \DeclareMathOperator{\Cham}{Cham}&#10;</xsl:text>
	<xsl:text> \DeclareMathOperator{\IM}{Im}&#10;</xsl:text>
	<xsl:text> \DeclareMathOperator{\esssup}{ess\,sup}&#10;</xsl:text>
	<xsl:text> \DeclareMathOperator{\meas}{meas}&#10;</xsl:text>
	<xsl:text> \DeclareMathOperator{\seg}{seg}&#10;</xsl:text>
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
    </xsl:variable>




<!--#############################################################################
|  	latex.graphicext 
|- #############################################################################
|
+ ############################################################################## -->

<doc:template name="latex.graphicext" xmlns="">
<refpurpose> Declared graphic extensions </refpurpose>
<refdescription>
This template checks whether the user has overriden <command>grafic.default.extension</command>
Otherwise, declares .pdf, .png, .jpg if using pdflatex and .eps if using latex.
<programlisting><![CDATA[
<xsl:template name="latex.graphicext">
<xsl:choose>
<xsl:when test="$graphic.default.extension !=''">
	<xsl:text>\DeclareGraphicsExtensions{</xsl:text>
	<xsl:if test="not(contains($graphic.default.extension,'.'))">
		<xsl:text>.</xsl:text>
	</xsl:if>
	<xsl:value-of select="$graphic.default.extension"/>
	<xsl:text>}&#10;</xsl:text>
</xsl:when>
<xsl:otherwise>
	<xsl:choose>
	<xsl:when test="$latex.pdf.support=1">
		<xsl:text>\ifpdf&#10;</xsl:text>
		<xsl:text>\DeclareGraphicsExtensions{.pdf,.png,.jpg}&#10;</xsl:text>
		<xsl:text>\else&#10;</xsl:text>
		<xsl:text>\DeclareGraphicsExtensions{.eps}&#10;</xsl:text>
		<xsl:text>\fi&#10;</xsl:text>
	</xsl:when>
	<xsl:otherwise>
		<xsl:text>\DeclareGraphicsExtensions{.eps}&#10;</xsl:text>
	</xsl:otherwise>
	</xsl:choose>
</xsl:otherwise>
</xsl:choose>
</xsl:template>


]]></programlisting>
</refdescription>
<refreturn>
</refreturn>
</doc:template>

<xsl:template name="latex.graphicext">
<xsl:choose>
<xsl:when test="$graphic.default.extension !=''">
	<xsl:text>\DeclareGraphicsExtensions{</xsl:text>
	<xsl:if test="not(contains($graphic.default.extension,'.'))">
		<xsl:text>.</xsl:text>
	</xsl:if>
	<xsl:value-of select="$graphic.default.extension"/>
	<xsl:text>}&#10;</xsl:text>
</xsl:when>
<xsl:otherwise>
	<xsl:choose>
	<xsl:when test="$latex.pdf.support=1">
		<xsl:text>\ifpdf&#10;</xsl:text>
		<xsl:text>\DeclareGraphicsExtensions{.pdf,.png,.jpg}&#10;</xsl:text>
		<xsl:text>\else&#10;</xsl:text>
		<xsl:text>\DeclareGraphicsExtensions{.eps}&#10;</xsl:text>
		<xsl:text>\fi&#10;</xsl:text>
	</xsl:when>
	<xsl:otherwise>
		<xsl:text>\DeclareGraphicsExtensions{.eps}&#10;</xsl:text>
	</xsl:otherwise>
	</xsl:choose>
</xsl:otherwise>
</xsl:choose>
</xsl:template>

	<xsl:template name="generate.latex.cell.separator">
		<xsl:choose>
			<xsl:when test="$latex.entities='catcode'">
				<xsl:text> \catcode`\&amp;=4 &amp;\catcode`\&amp;=\active </xsl:text>
			</xsl:when>
			<xsl:otherwise>
				<xsl:text> &amp; </xsl:text>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>
</xsl:stylesheet>

