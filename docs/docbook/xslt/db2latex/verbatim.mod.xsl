<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: verbatim.mod.xsl,v 1.1.2.1 2003/05/01 14:06:15 jelmer Exp $
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
		$Id: verbatim.mod.xsl,v 1.1.2.1 2003/05/01 14:06:15 jelmer Exp $
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
	<refpurpose> Auxiliary template to output verbatim LaTeX code in verbatim mode </refpurpose>
	<refdescription>
	<para> Takes into account whether the user is using fancyvrb or not. It allows
	veratim line numbering and other fancy stuff. </para>
	<para> In order to use a small or large font, you may also wanto to use 
	the <literal>role</literal> attribute : </para>
	<screen><![CDATA[
	<programlisting role="small">
	</programlisting>
	<programlisting role="large">
	</programlisting>
	]]></screen>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

	<xsl:template name="verbatim.apply.templates">
	<xsl:choose>
		<xsl:when test="ancestor::entry">
			<xsl:message>Problem with <xsl:value-of select="local-name(.)"/> inside table entries.</xsl:message>
			<xsl:text>\texttt{</xsl:text>
			<xsl:apply-templates mode="latex.verbatim"/>
			<xsl:text>}</xsl:text>
		</xsl:when>
		<xsl:when test="$latex.use.fancyvrb='1'">
			<xsl:variable name="not_monospaced" select="local-name(.)='literallayout' and @format!='monospaced'"/>
			<xsl:text>&#10;\begin{Verbatim}[</xsl:text>
			<xsl:if test="@linenumbering='numbered'">
				<xsl:text>,numbers=left</xsl:text>
			</xsl:if>
			<xsl:if test="$not_monospaced">
				<xsl:text>,fontfamily=default</xsl:text>
			</xsl:if>
			<xsl:if test="@role">
				<xsl:choose>
					<xsl:when test="@role='small'">
						<xsl:text>,fontsize=\small</xsl:text>
					</xsl:when>
					<xsl:when test="@role='large'">
						<xsl:text>,fontsize=\large</xsl:text>
					</xsl:when>
				</xsl:choose>
			</xsl:if>
			<xsl:text>]&#10;</xsl:text>
			<xsl:choose>
				<xsl:when test="$not_monospaced">
					<!-- Needs to be changed to cope with regular characterset! -->
					<xsl:apply-templates mode="latex.verbatim"/>
				</xsl:when>
				<xsl:otherwise>
					<xsl:apply-templates mode="latex.verbatim"/>
				</xsl:otherwise>
			</xsl:choose>
			<xsl:text>&#10;\end{Verbatim}&#10;</xsl:text>
		</xsl:when>
		<xsl:otherwise>
			<xsl:text>&#10;\begin{verbatim}&#10;</xsl:text>
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
