<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: footnote.mod.xsl,v 1.1.2.1 2003/05/01 14:06:14 jelmer Exp $
|- #############################################################################
|	$Author: jelmer $
|														
|   PURPOSE:
+ ############################################################################## -->
<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="footnote" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: footnote.mod.xsl,v 1.1.2.1 2003/05/01 14:06:14 jelmer Exp $
	    </releaseinfo>
	<authorgroup>
	    <author> <firstname>Ramon</firstname> <surname>Casellas</surname> </author>
	    <author> <firstname>James</firstname> <surname>Devenish</surname> </author>
	</authorgroup>
	    <copyright>
		<year>2000</year> <year>2001</year> <year>2002</year> <year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>
	<title>FootNotes <filename>footnote.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>
    <!--############################################################################# -->



    <xsl:template match="footnote">
	<xsl:call-template name="label.id"/>
	<xsl:text>\begingroup\catcode`\#=12\footnote{</xsl:text>
	<xsl:apply-templates/>
	<xsl:text>}\endgroup\docbooktolatexmakefootnoteref{</xsl:text>
	<xsl:call-template name="generate.label.id"/>
	<xsl:text>}</xsl:text>
    </xsl:template>

	<doc:template name="footnote">
		<refpurpose>Construct a footnote that copes with URLs</refpurpose>
		<refdescription><para>This template exists in this file so that all
		the footnote-generating templates are close to each other. However,
		it is actually a part of the ulink template in xref.mod.xsl</para></refdescription>
	</doc:template>
    <xsl:template name="footnote">
	<xsl:param name="hyphenation"/>
	<xsl:param name="url"/>
	<xsl:call-template name="label.id"/>
	<xsl:text>\begingroup\catcode`\#=12\footnote{</xsl:text>
	<xsl:call-template name="generate.typeset.url">
		<xsl:with-param name="hyphenation" select="$hyphenation"/>
		<xsl:with-param name="url" select="$url"/>
	</xsl:call-template>
	<xsl:text>}\endgroup\docbooktolatexmakefootnoteref{</xsl:text>
	<xsl:call-template name="generate.label.id"/>
	<xsl:text>}</xsl:text>
    </xsl:template>

    <xsl:template match="footnote/para">
	<xsl:apply-templates/>
	<xsl:text>&#10;&#10;</xsl:text>
    </xsl:template>


    <xsl:template match="footnoteref">
	<xsl:variable name="footnote" select="id(@linkend)"/>
	<xsl:text>\docbooktolatexusefootnoteref{</xsl:text>
	<xsl:value-of select="@linkend"/>
	<xsl:text>}</xsl:text>
    </xsl:template>

</xsl:stylesheet>
