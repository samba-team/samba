<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: revision.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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
    <doc:reference id="revision" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: revision.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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
	<title>Revision Management <filename>revision.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para>
			This file defines the DB2LaTeX XSL templates for <sgmltag>revision</sgmltag>
			and its children. The basic mapping is to output a LaTeX table and a table
			row for each revision.
		</para>
	    </section>
	</partintro>
    </doc:reference>
    <!--############################################################################# -->




    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="revhistory" xmlns="">
	<refpurpose> revhistory XSL template </refpurpose>
	<refdescription>
		<formalpara><title>User variables</title>
		<itemizedlist>
			<listitem><para><literal>latex.output.revhistory</literal></para></listitem>
		</itemizedlist>
		</formalpara>
		<para>This XSL template depends on the value of <literal>latex.output.revhistory</literal>. 
		If this variable is "1", the XSL template calls <command>map.begin</command>, then
		applies templates and finally calls <command>map.end</command></para>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="revhistory">
	<xsl:message>RCAS: Processing Revision History </xsl:message>
	<xsl:if test="$latex.output.revhistory=1">
	    <xsl:call-template name="map.begin"/>
	    <xsl:apply-templates/>
	    <xsl:call-template name="map.end"/>
	</xsl:if>
    </xsl:template>




    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="revhistory/revision" xmlns="">
	<refpurpose> revhistory/revision XSL template </refpurpose>
	<refdescription>
		<para>Each revhistory/revision corresponds to a LaTeX table row (see revhistory)
		containing the revision number, the date, author initials and the description/
		remarks of the revision.</para>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="revhistory/revision">
	<xsl:variable name="revnumber" select=".//revnumber"/>
	<xsl:variable name="revdate"   select=".//date"/>
	<xsl:variable name="revauthor" select=".//authorinitials"/>
	<xsl:variable name="revremark" select=".//revremark|../revdescription"/>
	<!-- Row starts here -->
	<xsl:if test="$revnumber">
	    <xsl:call-template name="gentext.element.name"/>
	    <xsl:text> </xsl:text>
	    <xsl:apply-templates select="$revnumber"/>
	</xsl:if>
	<xsl:text> &amp; </xsl:text>
	<xsl:apply-templates select="$revdate"/>
	<xsl:text> &amp; </xsl:text>
	<xsl:choose>
	    <xsl:when test="count($revauthor)=0">
		<xsl:call-template name="dingbat">
		    <xsl:with-param name="dingbat">nbsp</xsl:with-param>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:apply-templates select="$revauthor"/>
	    </xsl:otherwise>
	</xsl:choose>
	<!-- End Row here -->
	<xsl:text> \\ \hline&#10;</xsl:text>
	<!-- Add Remark Row if exists-->
	<xsl:if test="$revremark"> 
	    <xsl:text>\multicolumn{3}{l}{</xsl:text>
	    <xsl:apply-templates select="$revremark"/> 
	    <!-- End Row here -->
	    <xsl:text>} \\ \hline&#10;</xsl:text>
	</xsl:if>
    </xsl:template>





    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="revision/authorinitials" xmlns="">
	<refpurpose> revision/authorinitials XSL template </refpurpose>
	<refdescription>
		<para>Applies templates and outputs a "comma" if the node position is not
		last()</para>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="revision/authorinitials">
	<xsl:apply-templates/>
	<xsl:if test="position()!=last()">
	    <xsl:text>, </xsl:text>
	</xsl:if>
    </xsl:template>





    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="revision/revnumber" xmlns="">
	<refpurpose> revision/revnumber XSL template </refpurpose>
	<refdescription>
		<para>Applies templates.</para>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="revision/revnumber">
	<xsl:apply-templates/>
    </xsl:template>






    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="revision/date" xmlns="">
	<refpurpose> revision/date XSL template </refpurpose>
	<refdescription>
		<para>Applies templates.</para>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="revision/date">
	<xsl:apply-templates/>
    </xsl:template>




    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="revision/revremark" xmlns="">
	<refpurpose> revision/revremark XSL template </refpurpose>
	<refdescription>
		<para>Applies templates.</para>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="revision/revremark">
	<xsl:apply-templates/>
    </xsl:template>




    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="revision/revdescription" xmlns="">
	<refpurpose> revision/revdescription XSL template </refpurpose>
	<refdescription>
		<para>Applies templates.</para>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="revision/revdescription">
	<xsl:apply-templates/>
    </xsl:template>

</xsl:stylesheet>
