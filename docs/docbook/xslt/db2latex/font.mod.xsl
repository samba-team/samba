<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: font.mod.xsl,v 1.1.4.1 2003/06/06 15:08:20 jerry Exp $
|- #############################################################################
|	$Author: jerry $
|														
|   PURPOSE:
+ ############################################################################## -->
<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="font" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: font.mod.xsl,v 1.1.4.1 2003/06/06 15:08:20 jerry Exp $
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

	<title>Font <filename>font.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>




    <doc:param name="latex.document.font" xmlns="">
	<refpurpose> Document Font  </refpurpose>
	<refdescription>
	    Possible values: default, times, palatcm, charter, helvet, palatino, avant, newcent, bookman
	</refdescription>
    </doc:param>


    <xsl:param name="latex.document.font">palatino</xsl:param>

    <!-- 
    If you want to change explicitly to a certain font, use the command \fontfamily{XYZ}\selectfont whereby XYZ can be set to: pag for Adobe AvantGarde, pbk for Adobe Bookman, pcr for Adobe Courier, phv for Adobe Helvetica, pnc for Adobe NewCenturySchoolbook, ppl for Adobe Palatino, ptm for Adobe Times Roman, pzc for Adobe ZapfChancery 
    -->

</xsl:stylesheet>
