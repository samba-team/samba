<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: formal.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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
    <doc:reference id="formal" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: formal.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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

	<title>Formal Objects <filename>formal.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>




    <xsl:template name="formal.object">
	<xsl:call-template name="formal.object.heading">
	    <xsl:with-param name="title"><xsl:apply-templates select="." mode="title.ref"/></xsl:with-param>
	</xsl:call-template>
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template name="formal.object.heading">
	<xsl:param name="title"></xsl:param>
	<xsl:call-template name="label.id"/>
	<xsl:copy-of select="$title"/>
    </xsl:template>

    <xsl:template name="informal.object">
	<xsl:call-template name="label.id"/>
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template name="semiformal.object">
	<xsl:choose>
	    <xsl:when test="title">	<xsl:call-template name="formal.object"/>	</xsl:when>
	    <xsl:otherwise> <xsl:call-template name="informal.object"/></xsl:otherwise>
	</xsl:choose>
    </xsl:template>


	<xsl:template name="generate.formal.title.placement">
		<xsl:param name="object" select="figure" />
		<xsl:variable name="param.placement" select="substring-after(normalize-space($formal.title.placement),concat($object, ' '))"/>
		<xsl:choose>
			<xsl:when test="contains($param.placement, ' ')">
				<xsl:value-of select="substring-before($param.placement, ' ')"/>
			</xsl:when>
			<xsl:when test="$param.placement = ''">before</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="$param.placement"/>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>




<!-- ========================================  -->
<!-- XSL Template for DocBook Equation Element -->
<!-- 2003/07/04 Applied patches from J.Pavlovic -->
<!-- ========================================  -->
<xsl:template match="equation">
<!-- Get LaTeX content if available -->
<xsl:variable name="tex" select=" mediaobject/textobject[@role='tex' or @role='latex'] | mediaobject/textobject/phrase[@role='tex' or @role='latex']"/>
<!-- Equation title placement -->
<xsl:variable name="placement">
	<xsl:call-template name="generate.formal.title.placement">
		<xsl:with-param name="object" select="local-name(.)" />
	</xsl:call-template>
</xsl:variable>
<!-- Equation caption -->
<xsl:variable name="caption">
	<xsl:text>\caption{</xsl:text>
	<xsl:apply-templates select="title" mode="caption.mode"/>
	<xsl:text>}&#10;</xsl:text>
</xsl:variable>
<xsl:call-template name="map.begin"/>
<xsl:if test="$placement='before'">
	<xsl:text>\captionswapskip{}</xsl:text>
	<xsl:value-of select="$caption" />
	<xsl:text>\captionswapskip{}</xsl:text>
</xsl:if>
<xsl:choose>
	<xsl:when test="$tex">
		<xsl:apply-templates select="$tex"/>
	</xsl:when>
	<xsl:otherwise>
		<xsl:apply-templates/>
	</xsl:otherwise>
</xsl:choose>
<xsl:if test="$placement!='before'"><xsl:value-of select="$caption" /></xsl:if>
<xsl:call-template name="map.end"/>
</xsl:template>


<xsl:template match="equation/title"/>





<xsl:template match="informalequation">
<xsl:variable name="tex" select=" mediaobject/textobject[@role='tex'] | mediaobject/textobject[@role='latex']"/>
<xsl:call-template name="informal.object"/>
<xsl:choose>
	<xsl:when test="$tex">
		<xsl:text>$</xsl:text><xsl:value-of select="mediaobject/textobject/phrase"/><xsl:text>$&#10;</xsl:text>
	</xsl:when>
	<xsl:otherwise>
		<xsl:apply-templates/>
	</xsl:otherwise>
</xsl:choose>
</xsl:template>








</xsl:stylesheet>
