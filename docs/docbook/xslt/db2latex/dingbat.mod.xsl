<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: dingbat.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
|- #############################################################################
|	$Author: ab $
|														
|   PURPOSE:
|   
+ ############################################################################## -->


<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="dingbat" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: dingbat.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
	    </releaseinfo>
	    <authorgroup>
	    <author> <firstname>Ramon</firstname> <surname>Casellas</surname> </author>
	    <author> <firstname>James</firstname> <surname>Devenish</surname> </author>
	    </authorgroup>
	    <copyright>
		<year>2000</year><year>2001</year><year>2002</year><year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>
	<title>Dingbats <filename>dingbat.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
	    </section>
	</partintro>
    </doc:reference>



    <xsl:template name="dingbat">
	<xsl:param name="dingbat">bullet</xsl:param>
	<xsl:call-template name="dingbat.characters">
	    <xsl:with-param name="dingbat" select="$dingbat"/>
	</xsl:call-template>
    </xsl:template>

    <xsl:template name="dingbat.characters">
	<xsl:param name="dingbat">bullet</xsl:param>
	<xsl:choose>
	    <xsl:when test="$dingbat='bullet'"> $\bullet$ </xsl:when>
	    <xsl:when test="$dingbat='copyright'">\copyright{}</xsl:when>
	    <xsl:when test="$dingbat='trademark'">\texttrademark{}</xsl:when>
	    <xsl:when test="$dingbat='registered'">\textregistered{}</xsl:when>
	    <xsl:when test="$dingbat='nbsp'">~</xsl:when>
	    <xsl:when test="$dingbat='ldquo'">``</xsl:when>
	    <xsl:when test="$dingbat='rdquo'">''</xsl:when>
	    <xsl:when test="$dingbat='lsquo'">`</xsl:when>
	    <xsl:when test="$dingbat='rsquo'">'</xsl:when>
	    <xsl:when test="$dingbat='em-dash'">---</xsl:when>
	    <xsl:when test="$dingbat='mdash'">---</xsl:when>
	    <xsl:when test="$dingbat='en-dash'">--</xsl:when>
	    <xsl:when test="$dingbat='ndash'">--</xsl:when>
	    <xsl:otherwise>
		<xsl:text> [dingbat?] </xsl:text>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

</xsl:stylesheet>
