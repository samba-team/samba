<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>
<xsl:import href="../settings.xsl"/>
<xsl:import href="http://db2latex.sourceforge.net/xsl/docbook.xsl"/>

<xsl:param name="latex.mapping.xml" select="document('latex.overrides.xml')"/>

<xsl:param name="generate.toc">
	/appendix toc,title
	article/appendix  nop
	/article  toc,title
	book      toc,title,figure,table,example,equation
	/chapter  toc,title,lop
	part      toc,title
	/preface  toc,title
	qandadiv  toc
	qandaset  toc
	procedure lop
	reference toc,title
	/sect1    toc
	/sect2    toc
	/sect3    toc
	/sect4    toc
	/sect5    toc
	/section  toc
	set       toc,title
</xsl:param>

<xsl:template name="link">
	<xsl:element name="link">
		<xsl:copy-of select="@*"/>
	</xsl:element>
</xsl:template>

<xsl:output method="text" encoding="ISO-8859-1" indent="yes"/>
<xsl:param name="l10n.gentext.default.language" select="'en'"/>
<xsl:param name="latex.example.caption.style"></xsl:param>
<xsl:variable name="latex.hyperref.param.pdftex">hyperfigures,hyperindex,citecolor=black,urlcolor=black,filecolor=black,linkcolor=black,menucolor=red,pagecolor=black</xsl:variable>
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

\usepackage{amsmath}%
\usepackage{amsfonts}%
\usepackage{amssymb}

\makeindex           

</xsl:variable>
<xsl:param name="latex.babel.language">english</xsl:param>

<xsl:template match="//title/filename|//title/command|//title/parameter|//title/constant">
  <xsl:variable name="content">
    <xsl:apply-templates/>
  </xsl:variable>
  <xsl:if test="$content != ''">
    <xsl:value-of select="$content" />
  </xsl:if>
</xsl:template>

</xsl:stylesheet>
