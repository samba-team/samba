<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: authorgroup.mod.xsl,v 1.1.2.1 2003/05/01 14:06:14 jelmer Exp $
|- #############################################################################
|	$Author: jelmer $												
|														
|   PURPOSE: Manage Authorgroups 
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="authorgroup" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: authorgroup.mod.xsl,v 1.1.2.1 2003/05/01 14:06:14 jelmer Exp $
	    </releaseinfo>
		<authorgroup>
	    	<author><firstname>Ramon</firstname> <surname>Casellas</surname></author>
		<author><firstname>James</firstname> <surname>Devenish</surname></author>
		</authorgroup>
	    <copyright>
		<year>2000</year> <year>2001</year> <year>2002</year> <year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>

	<title>Authorgroup <filename>authorgroup.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<formalpara><title>Pertinent Variables</title>
			<itemizedlist>
				<listitem><simpara><xref linkend="param.biblioentry.item.separator"/></simpara></listitem>
			</itemizedlist>
		</formalpara>
	    </section>
	</partintro>
    </doc:reference>


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="authorgroup" xmlns="">
	<refpurpose> Authorgroup XSL template.  </refpurpose>
	<refdescription>
	</refdescription>
    </doc:template>

    <xsl:template match="authorgroup">
	<xsl:for-each select="author">
	    <xsl:apply-templates select="."/>
	    <xsl:if test="not(position()=last())">
		<xsl:text> \and </xsl:text>
	    </xsl:if>
	</xsl:for-each>
    </xsl:template>




    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="authorinitials" xmlns="">
	<refpurpose> AuthorInitials XSL template.  </refpurpose>
	<refdescription>
	</refdescription>
    </doc:template>

    <xsl:template match="authorinitials">
	<xsl:apply-templates/>
	<xsl:value-of select="$biblioentry.item.separator"/>
    </xsl:template>

</xsl:stylesheet>

