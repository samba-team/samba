<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: keywords.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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
    <doc:reference id="keywords" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: keywords.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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

	<title>Keywords <filename>keywords.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>



<xsl:template match="keywordset">
	<xsl:call-template name="map.begin"/>
	<xsl:apply-templates/>
	<xsl:call-template name="map.end"/>
</xsl:template>

<xsl:template match="keyword">
	<xsl:call-template name="normalize-scape">
		<xsl:with-param name="string" select="normalize-space(.)"/>
	</xsl:call-template>
	<xsl:if test="following-sibling::keyword">, </xsl:if>
</xsl:template>





<xsl:template match="subjectset"></xsl:template>

</xsl:stylesheet>
