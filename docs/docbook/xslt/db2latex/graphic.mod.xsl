<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: graphic.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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
    <doc:reference id="graphic" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: graphic.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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

	<title>Graphics <filename>graphic.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>




    <xsl:template match="screenshot">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="screeninfo">
    </xsl:template>


    <xsl:template match="graphic[@fileref]">
	<xsl:text>\includegraphics{</xsl:text> <xsl:value-of select="normalize-space(@fileref)"/>}
    </xsl:template>

    <xsl:template match="graphic[@entityref]">
	<xsl:text>\includegraphics{</xsl:text> <xsl:value-of select="unparsed-entity-uri(@entityref)"/>}
    </xsl:template>


    <xsl:template match="inlinegraphic[@fileref]">
	<xsl:choose>
	    <xsl:when test="@format='linespecific'">
		<a xml:link="simple" show="embed" actuate="auto" href="{@fileref}"/>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:text>\includegraphics{</xsl:text>
		<xsl:if test="@align">
		    <!-- <xsl:attribute name="align"><xsl:value-of select="@align"/></xsl:attribute> -->
		</xsl:if>
		<xsl:value-of select="normalize-space(@fileref)"/>}
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template match="inlinegraphic[@entityref]">
	<xsl:choose>
	    <xsl:when test="@format='linespecific'">
		<a xml:link="simple" show="embed" actuate="auto" href="{@fileref}"/>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:text>\includegraphics{</xsl:text>
		<xsl:if test="@align">
		    <!-- <xsl:attribute name="align"><xsl:value-of select="@align"/></xsl:attribute> -->
		</xsl:if>
		<xsl:value-of select="unparsed-entity-uri(@entityref)"/>}
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>
</xsl:stylesheet>
