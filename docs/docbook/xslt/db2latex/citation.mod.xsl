<?xml version='1.0'?>
<!--############################################################################# 
|- #############################################################################
|														
|   PURPOSE:
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="citation" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
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

	<title>Citation <filename>citation.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para>This file contais a single (and simple!) XSL template, that maps the
		<sgmltag>citation</sgmltag> SGML tag to the LaTeX <literal>\cite{}</literal> 
		command.</para>
	    </section>
	</partintro>
    </doc:reference>


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="citation" xmlns="">
	<refpurpose> Citation XSL template.  </refpurpose>
	<refdescription>
	    <para> Outputs a simple <literal>\cite{ }</literal> Command, 
		containing the result of processing the citation's children
	    </para>
	</refdescription>
    </doc:template>



    <xsl:template match="citation">
	<!-- todo: biblio-citation-check -->
	<xsl:text>\docbooktolatexcite{</xsl:text>
		<xsl:value-of select="."/>
	<xsl:text>}{}</xsl:text>
    </xsl:template>

</xsl:stylesheet>


