<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: texmath.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
|- #############################################################################
|	$Author: ab $
|														
|   PURPOSE:
+ ############################################################################## -->


<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="texmath" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: texmath.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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

	<title>LaTeX Only Commands <filename>texmath.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>

    <xsl:template match="alt">
	<xsl:choose>
		<xsl:when test="ancestor::inlineequation and (@role='tex' or @role='latex' or $latex.alt.is.latex='1')">
			<xsl:text>\ensuremath{</xsl:text>
			<xsl:value-of select="."/>
			<xsl:text>}</xsl:text>
		</xsl:when>
		<xsl:when test="ancestor::equation|ancestor::informalequation and (@role='tex' or @role='latex' or $latex.alt.is.latex='1')">
			<xsl:text>\begin{displaymath}</xsl:text>
			<xsl:call-template name="label.id"/>
			<xsl:value-of select="."/>
			<xsl:text>\end{displaymath}&#10;</xsl:text>
		</xsl:when>
		<xsl:when test="$latex.alt.is.latex='1'">
			<xsl:value-of select="."/>
		</xsl:when>
		<xsl:otherwise>
			<xsl:apply-templates/>
		</xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template match="latex|tex">
	<xsl:value-of select="."/>
    </xsl:template>

    <xsl:template match="latex[@fileref]">
	<xsl:text>\input{</xsl:text><xsl:value-of select="@fileref"/><xsl:text>}&#10;</xsl:text>
    </xsl:template>

    <xsl:template match="tex[@fileref]">
	<xsl:text>\input{</xsl:text><xsl:value-of select="@fileref"/><xsl:text>}&#10;</xsl:text>
    </xsl:template>


    <xsl:template match="tm[@fileref]">
	<xsl:text>\input{</xsl:text><xsl:value-of select="@fileref"/><xsl:text>}&#10;</xsl:text>
    </xsl:template>

    <xsl:template match="tm[@tex]">
	<xsl:value-of select="@tex"/>
    </xsl:template>

    <xsl:template match="inlinetm[@fileref]">
	<xsl:text>\input{</xsl:text><xsl:value-of select="@fileref"/><xsl:text>}&#10;</xsl:text>
    </xsl:template>

    <xsl:template match="inlinetm[@tex]">
	<xsl:value-of select="@tex"/>
    </xsl:template>


	<xsl:template match="inlineequation">
	<xsl:variable name="tex" select="alt[@role='tex' or @role='latex']|inlinemediaobject/textobject[@role='tex' or @role='latex']|inlinemediaobject/textobject/phrase[@role='tex' or @role='latex']" />
 	<xsl:choose>
		<xsl:when test="$tex">
			<xsl:apply-templates select="$tex"/>
		</xsl:when>
		<xsl:when test="alt and $latex.alt.is.preferred='1'">
			<xsl:apply-templates select="alt"/>
		</xsl:when>
		<xsl:when test="inlinemediaobject">
			<xsl:apply-templates select="inlinemediaobject"/>
		</xsl:when>
		<xsl:when test="alt">
			<xsl:apply-templates select="alt"/>
		</xsl:when>
		<xsl:otherwise>
			<xsl:apply-templates select="graphic"/>
		</xsl:otherwise>
	</xsl:choose>
	</xsl:template>





</xsl:stylesheet>
