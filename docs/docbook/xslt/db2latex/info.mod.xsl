<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: info.mod.xsl,v 1.1.2.1 2003/05/01 14:06:14 jelmer Exp $
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
    <doc:reference id="info" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: info.mod.xsl,v 1.1.2.1 2003/05/01 14:06:14 jelmer Exp $
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

	<title>Info <filename>info.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>




    <!-- These templates define the "default behavior" for info
    elements.  Even if you don't process the *info wrappers,
    some of these elements are needed because the elements are
    processed from named templates that are called with modes.
    Since modes aren't sticky, these rules apply. 
    (TODO: clarify this comment) -->


    <xsl:template match="corpauthor">
	<xsl:apply-templates/>
    </xsl:template>


    <xsl:template match="jobtitle">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="orgname">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="orgdiv">
	<xsl:apply-templates/>
    </xsl:template>

</xsl:stylesheet>
