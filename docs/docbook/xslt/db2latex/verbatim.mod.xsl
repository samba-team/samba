<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: verbatim.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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
    <doc:reference id="verbatim" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: verbatim.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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
	<title>Verbatim <filename>verbatim.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>
    <!--############################################################################# -->


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="literal" xmlns="">
	<refpurpose>Template for <sgmltag>literal</sgmltag></refpurpose>
	<refdescription>
	    Template for literal template
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="literal" mode="latex.verbatim">
	<xsl:text>{\verb </xsl:text>
	<xsl:apply-templates mode="latex.verbatim"/>
	<xsl:text>}</xsl:text>
    </xsl:template>





    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template name="verbatim.apply.templates" xmlns="">
	<refpurpose> Auxiliary template to output verbatim LaTeX code (in verbatim mode)
	that takes into account whether the user is using fancyverb or not. It allows
	veratim line numbering and other fancy stuff. </refpurpose>
	<refdescription>
	<programlisting><![CDATA[
	<xsl:template name="verbatim.apply.templates">
	<xsl:choose>
		<xsl:when test="$latex.use.fancyvrb='1'">
			<xsl:text>&#10;\begin{Verbatim}[</xsl:text>
			<xsl:if test="@linenumbering='numbered'">
				<xsl:text>,numbers=left</xsl:text>
			</xsl:if>
			<xsl:if test="local-name(.)='literallayout' and @format!='monospaced'">
				<xsl:text>,fontfamily=default</xsl:text>
			</xsl:if>
			<xsl:text>]&#10;</xsl:text>
			<xsl:apply-templates mode="latex.verbatim"/>
			<xsl:text>&#10;\end{Verbatim}&#10;</xsl:text>
		</xsl:when>
		<xsl:otherwise>
			<xsl:text>&#10;\begin{verbatim}&#10;</xsl:text>
			<!-- RCAS: Experimental code 
			<xsl:apply-templates/>-->
			<xsl:apply-templates mode="latex.verbatim"/>
			<xsl:text>&#10;\end{verbatim}&#10;</xsl:text>
		</xsl:otherwise>
	</xsl:choose>
	</xsl:template>
	]]></programlisting>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

	<xsl:template name="verbatim.apply.templates">
	<xsl:choose>
		<xsl:when test="$latex.use.fancyvrb='1'">
			<xsl:text>&#10;\begin{Verbatim}[</xsl:text>
			<xsl:if test="@linenumbering='numbered'">
				<xsl:text>,numbers=left</xsl:text>
			</xsl:if>
			<xsl:if test="local-name(.)='literallayout' and @format!='monospaced'">
				<xsl:text>,fontfamily=default</xsl:text>
			</xsl:if>
			<xsl:text>]&#10;</xsl:text>
			<xsl:apply-templates mode="latex.verbatim"/>
			<xsl:text>&#10;\end{Verbatim}&#10;</xsl:text>
		</xsl:when>
		<xsl:otherwise>
			<xsl:text>&#10;\begin{verbatim}&#10;</xsl:text>
			<!-- RCAS: Experimental code 
			<xsl:apply-templates/>-->
			<xsl:apply-templates mode="latex.verbatim"/>
			<xsl:text>&#10;\end{verbatim}&#10;</xsl:text>
		</xsl:otherwise>
	</xsl:choose>
	</xsl:template>



    <xsl:template match="address">
		<xsl:call-template name="verbatim.apply.templates"/>
    </xsl:template>

    <doc:template name="verbatim" match="screen|programlisting|literallayout" xmlns="">
	<refpurpose>Environments in which whitespace is significant</refpurpose>
	<refdescription>
	    <itemizedlist>
			<title>Known Bugs</title>
			<listitem><simpara>Templates are not applied within programlistings.</simpara></listitem>
		</itemizedlist>
	</refdescription>
    </doc:template>
	<xsl:template match="screen|programlisting|literallayout">
		<xsl:call-template name="verbatim.apply.templates"/>
	</xsl:template>

</xsl:stylesheet>
