<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: example.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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
    <doc:reference id="example" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: example.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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

	<title>Example <filename>example.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>



    <xsl:template match="example">
	<xsl:variable name="placement">
		<xsl:call-template name="generate.formal.title.placement">
			<xsl:with-param name="object" select="local-name(.)" />
		</xsl:call-template>
	</xsl:variable>
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
	<xsl:apply-templates />
	<xsl:if test="$placement!='before'"><xsl:value-of select="$caption" /></xsl:if>
	<xsl:call-template name="map.end"/>
    </xsl:template>



    <xsl:template match="example/title"></xsl:template>




    <xsl:template match="informalexample">
	<xsl:call-template name="informal.object"/>
    </xsl:template>



</xsl:stylesheet>
