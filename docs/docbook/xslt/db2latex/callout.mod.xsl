<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: callout.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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
    <doc:reference id="callout" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: callout.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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

	<title>Callout <filename>callout.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>




    <xsl:template match="programlistingco|screenco">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="areaspec|areaset|area">
    </xsl:template>

    <xsl:template match="co">
	<xsl:apply-templates select="." mode="callout-bug"/>
    </xsl:template>

    <xsl:template match="co" mode="callout-bug">
	<xsl:variable name="conum">
	    <xsl:number count="co" format="1"/>
	</xsl:variable>

	<xsl:text>(</xsl:text>
	<xsl:value-of select="$conum"/>
	<xsl:text>)</xsl:text>
    </xsl:template>

</xsl:stylesheet>
