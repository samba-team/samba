<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>
<xsl:import href="../settings.xsl"/>
<!--<xsl:import href="docbook.xsl"/>-->
<xsl:import href="http://db2latex.sourceforge.net/xsl/docbook.xsl"/>

<xsl:output method="text" encoding="ISO-8859-1" indent="yes"/>
<xsl:param name="l10n.gentext.default.language" select="'en'"/>
<xsl:param name="latex.example.caption.style"></xsl:param>
<xsl:variable name="latex.documentclass">sambadoc</xsl:variable>
<xsl:variable name="latex.documentclass.common">twoside,11pt,letterpaper</xsl:variable>
<xsl:variable name="latex.documentclass.book"></xsl:variable>
<xsl:variable name="latex.hyperref.param.pdftex">hyperfigures,hyperindex,citecolor=black,urlcolor=black,filecolor=black,linkcolor=black,menucolor=red,pagecolor=black</xsl:variable>
<xsl:variable name="latex.document.font">default</xsl:variable>
<xsl:variable name="admon.graphics.path">xslt/figures</xsl:variable>
<xsl:variable name="latex.use.tabularx">1</xsl:variable>
<xsl:variable name="latex.fancyhdr.lh"></xsl:variable>
<xsl:variable name="latex.use.fancyhdr"></xsl:variable>
<xsl:variable name="latex.use.parskip">1</xsl:variable>
<!--<xsl:variable name="latex.use.ltxtable">1</xsl:variable>-->
<xsl:variable name="latex.hyphenation.tttricks">1</xsl:variable>
<xsl:variable name="latex.book.varsets"></xsl:variable>
<xsl:variable name="latex.titlepage.file"></xsl:variable>
<!--<xsl:variable name="formal.title.placement">
	figure not_before
	example not_before
	equation not_before
	table not_before
	procedure before
</xsl:variable>-->
<!--<xsl:variable name="latex.procedure.title.style"><xsl:text>\subsubsection</xsl:text></xsl:variable>-->
<xsl:template name="latex.thead.row.entry">
<xsl:text>{\bfseries </xsl:text><xsl:apply-templates/><xsl:text>}</xsl:text>
</xsl:template>
<xsl:variable name="latex.book.preamblestart">
\documentclass[twoside,openright,<xsl:value-of select="$fontsize"/>pt]{xslt/latex/sambadoc}

\usepackage[twoside,dvips]{geometry}

%\usepackage[section]{placeins}

\geometry{%
paperwidth=7in,
paperheight=9.25in,
lmargin=.75in,
rmargin=.75in,
bmargin=.625in,
tmargin=.625in,
width=5.5in,
height=7.525in, %7.3
marginparwidth=0.35in,
headheight=0.2in,
headsep=.25in,
footskip=.025in}

\setlength{\headwidth}{\textwidth}

<xsl:if test="$docrop != '0'">
\usepackage[letter,center,dvips]{crop}
</xsl:if>
\usepackage{amsmath}%
\usepackage{amsfonts}%
\usepackage{amssymb}

<xsl:if test="$docrop != '0'">
\special{papersize=11in,8.5in}

%\crop[frame]
\crop
</xsl:if>

\makeindex           

%% Preamble:

% New commands and/or command redefinitions
%
% Added for the samba book
%----------------------- paragraph ----------------------------------
\cleardoublepage
\pagenumbering{roman}

\setcounter{page}{2}
\setcounter{totalnumber}{8}
\setcounter{bottomnumber}{3}
\setcounter{topnumber}{3}
\renewcommand{\textfraction}{0.1}
\renewcommand{\topfraction}{1.0}
\renewcommand{\bottomfraction}{1.0}

%% Document Parts
</xsl:variable>
<xsl:param name="latex.babel.language">english</xsl:param>
<xsl:param name="ulink.url">1</xsl:param>

<xsl:template match="//title/filename|//title/command|//title/parameter|//title/constant">
  <xsl:variable name="content">
    <xsl:apply-templates/>
  </xsl:variable>
  <xsl:if test="$content != ''">
    <xsl:value-of select="$content" />
  </xsl:if>
</xsl:template>


</xsl:stylesheet>

