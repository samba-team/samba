<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: email.mod.xsl,v 1.1.2.1 2003/05/01 14:06:14 jelmer Exp $
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
    <doc:reference id="email" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: email.mod.xsl,v 1.1.2.1 2003/05/01 14:06:14 jelmer Exp $
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

	<title>Email <filename>email.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>
    <!--############################################################################# -->


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="email" xmlns="">
	<refpurpose> XSL template for email </refpurpose>
	<refdescription>
	    <para>Outputs the mail in {\texttt }. Calls the normalize-scape template in order to get a 
		normalized email string. It does not process email content model.</para>
	    <formalpara><title>Remarks and Bugs</title>
	    </formalpara>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->


    <xsl:template match="email">
	<xsl:text>\texttt{&lt;</xsl:text> 
	<xsl:call-template name="ulink">
		<xsl:with-param name="url" select="concat('mailto:',.)"/>
	</xsl:call-template>
	<xsl:text>&gt;}</xsl:text>
    </xsl:template>

</xsl:stylesheet>
