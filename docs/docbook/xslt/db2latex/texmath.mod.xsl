<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: texmath.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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
    <doc:reference id="texmath" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: texmath.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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


    <xsl:template match="alt[@role='tex' or @role='latex']">
	<xsl:choose>
		<xsl:when test="ancestor::inlineequation|ancestor::equation|ancestor::informalequation">
			<xsl:text>\ensuremath{</xsl:text>
			<xsl:value-of select="."/>
			<xsl:text>}</xsl:text>
		</xsl:when>
		<xsl:otherwise>
			<xsl:value-of select="."/>
		</xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template match="alt">
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
		<xsl:otherwise>
			<xsl:apply-templates select="*[not(self::graphic)]"/>
		</xsl:otherwise>
	</xsl:choose>
	</xsl:template>





</xsl:stylesheet>
