<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: dedication.mod.xsl,v 1.1.4.1 2003/06/06 15:08:20 jerry Exp $
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
    <doc:reference id="dedication" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: dedication.mod.xsl,v 1.1.4.1 2003/06/06 15:08:20 jerry Exp $
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

	<title>Dedication <filename>dedication.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>



<!--############################################################################# 
 |  XSL Parameters 
 +- ############################################################################# -->
<xsl:param name="latex.dedication.title.style">\sc</xsl:param>



<!--############################################################################# 
 |  Dedication Template 
 +- ############################################################################# -->
<xsl:template match="dedication">
<xsl:text>\newpage&#10;</xsl:text>
<xsl:text>% -------------------------------------------------------------&#10;</xsl:text>
<xsl:text>% Dedication	                                                 &#10;</xsl:text>
<xsl:text>% -------------------------------------------------------------&#10;</xsl:text>
<xsl:call-template name="label.id"/>
<xsl:call-template name="dedication.title"/>
<xsl:call-template name="dedication.subtitle"/>
<!-- except title, titleabbrev and subtitle -->
<xsl:apply-templates select="*[name(.) != 'title' and name(.) != 'subtitle' and name(.) != 'titleabbrev']"/>
</xsl:template>


<!--############################################################################# 
 |  Dedication Title 
 +- ############################################################################# -->
<xsl:template name="dedication.title">
<!-- Output dedication title or generic text -->
<xsl:text>{</xsl:text>
<xsl:value-of select="$latex.dedication.title.style"/>
<xsl:text> </xsl:text>
<xsl:choose>
	<xsl:when test="title">
		<xsl:apply-templates select="title"/>
	</xsl:when>
	<xsl:otherwise>
	<xsl:call-template name="gentext">
		<xsl:with-param name="key">dedication</xsl:with-param>
	</xsl:call-template>
	</xsl:otherwise>
</xsl:choose>
<xsl:text>}&#10;</xsl:text>
<!-- done with title -->
</xsl:template>


<xsl:template match="dedication/title">
<xsl:apply-templates/>
</xsl:template>



<!--############################################################################# 
 |  Dedication Subtitle 
 +- ############################################################################# -->
<xsl:template name="dedication.subtitle">
<xsl:variable name="subtitle">
	<xsl:apply-templates select="." mode="subtitle.content"/> 
</xsl:variable>
<xsl:if test="$subtitle != ''">
	<xsl:text>{</xsl:text>
	<xsl:value-of select="$latex.dedication.title.style"/>
	<xsl:text> </xsl:text>
	<xsl:copy-of select="$subtitle"/>
	<xsl:text>}&#10;</xsl:text>
</xsl:if>
</xsl:template>


<xsl:template match="dedication/subtitle">
<xsl:apply-templates/>
</xsl:template>

<xsl:template match="dedication/titleabbrev"/>


<!--############################################################################# 
 |  Special treatment for dedication paragraphs 
 +- ############################################################################# -->
<xsl:template match="dedication/para">
<xsl:text>&#10;\paragraph*{}&#10;</xsl:text>  <!-- This is a fixme !! -->
<xsl:apply-templates/>
</xsl:template>

</xsl:stylesheet>

