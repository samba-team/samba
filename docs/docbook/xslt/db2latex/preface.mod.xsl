<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: preface.mod.xsl,v 1.1.4.1 2003/06/06 15:08:20 jerry Exp $
|- #############################################################################
|	$Author: jerry $
|														
|   PURPOSE:
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="preface" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: preface.mod.xsl,v 1.1.4.1 2003/06/06 15:08:20 jerry Exp $
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

	<title>Preface <filename>preface.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>


<!--############################################################################# 
 |  Preface 
 +- ############################################################################# -->
<xsl:template match="preface">
<xsl:text>\newpage&#10;</xsl:text>
<xsl:text>% -------------------------------------------------------------&#10;</xsl:text>
<xsl:text>% Preface                                                      &#10;</xsl:text>
<xsl:text>% -------------------------------------------------------------&#10;</xsl:text>
<xsl:text>\chapter*{</xsl:text>
<!-- Output preface title or generic text -->
<xsl:choose>
	<xsl:when test="title">
		<xsl:apply-templates select="title"/>
	</xsl:when>
	<xsl:otherwise>
	<xsl:call-template name="gentext">
		<xsl:with-param name="key">preface</xsl:with-param>
	</xsl:call-template>
	</xsl:otherwise>
</xsl:choose>
<xsl:text>}&#10;</xsl:text>
<!-- done with title. Tag it. -->
<xsl:call-template name="label.id"/>
<!-- except title, titleabbrev and subtitle -->
<xsl:apply-templates select="*[name(.) != 'title' and name(.) != 'subtitle' and name(.) != 'titleabbrev']"/>
</xsl:template>


<!--############################################################################# 
 |  Preface Title 
 +- ############################################################################# -->
<xsl:template match="preface/title">
<xsl:apply-templates/>
</xsl:template>


<!--############################################################################# 
 |  Other Preface Elements 
 +- ############################################################################# -->
<xsl:template match="preface/titleabbrev"/>
<xsl:template match="preface/subtitle"/>
<xsl:template match="preface/docinfo|prefaceinfo"/>


<xsl:template match="preface/sect1|preface/simplesect">
<xsl:text>&#10;\section*{</xsl:text>
<xsl:apply-templates select="title"/>
<xsl:text>}&#10;</xsl:text>
<xsl:apply-templates select="*[name(.) != 'title']"/>
</xsl:template>


<xsl:template match="preface/sect1/sect2">
<xsl:text>&#10;\subsection*{</xsl:text>
<xsl:apply-templates select="title"/>
<xsl:text>}&#10;</xsl:text>
<xsl:apply-templates select="*[name(.) != 'title']"/>
</xsl:template>


<xsl:template match="preface/sect1/sect2/sect3">
<xsl:text>&#10;\subsubsection*{</xsl:text>
<xsl:apply-templates select="title"/>
<xsl:text>}&#10;</xsl:text>
<xsl:apply-templates select="*[name(.) != 'title']"/>
</xsl:template>


</xsl:stylesheet>

