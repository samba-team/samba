<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>
<xsl:import href="http://db2latex.sourceforge.net/xsl/docbook.xsl"/>

<xsl:output method="text" encoding="ISO-8859-1" indent="yes"/>
<xsl:param name="l10n.gentext.default.language">en</xsl:param>
<xsl:variable name="latex.documentclass">sambadoc</xsl:variable>
<xsl:variable name="latex.documentclass.common">english,final,titlepage,parskip,<xsl:value-of select="$papersize"/>,<xsl:value-of select="$fontsize"/>pt</xsl:variable>
<xsl:variable name="latex.documentclass.book"></xsl:variable>
<xsl:variable name="latex.generate.indexterm">1</xsl:variable>
<xsl:variable name="latex.hyperref.param.pdftex">hyperfigures,hyperindex,citecolor=blue,urlcolor=blue</xsl:variable>
<xsl:variable name="latex.document.font">default</xsl:variable>
<xsl:variable name="latex.admonition.path">xslt/figures</xsl:variable>
<xsl:variable name="latex.hyphenation.tttricks">1</xsl:variable>
<xsl:variable name="latex.use.tabularx">1</xsl:variable>
<xsl:template name="latex.thead.row.entry">
<xsl:text>{\bfseries </xsl:text><xsl:apply-templates/><xsl:text>}</xsl:text>
</xsl:template>
<xsl:param name="latex.babel.language">english</xsl:param>
<xsl:param name="ulink.url">1</xsl:param>

<xsl:variable name="latex.book.preamble.post">\fancyhf{}
\fancyhead[RE]{\slshape \rightmark}
\fancyhead[LO]{\slshape \leftmark}
\fancyfoot[R]{\thepage}
</xsl:variable>

<xsl:template match="//title/filename|//title/command">
  <xsl:variable name="content">
    <xsl:apply-templates/>
  </xsl:variable>
  <xsl:if test="$content != ''">
    <xsl:value-of select="$content" />
  </xsl:if>
</xsl:template>

<xsl:template name="latex.thead.row.entry">
<xsl:text>{\bfseries </xsl:text><xsl:apply-templates/><xsl:text>}</xsl:text>
</xsl:template>

</xsl:stylesheet>

