<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: block.mod.xsl,v 1.1.4.1 2003/06/06 15:08:20 jerry Exp $
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
    <doc:reference id="block" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: block.mod.xsl,v 1.1.4.1 2003/06/06 15:08:20 jerry Exp $
	    </releaseinfo>
	    <authorgroup>
		<author><firstname>Ramon</firstname> <surname>Casellas</surname></author>
		<author><firstname>James</firstname> <surname>Devenish</surname></author>
	    </authorgroup>
	    <copyright>
		<year>2000</year><year>2001</year><year>2002</year><year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>
	<title>Block Objects <filename>block.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para>Sundry block-formatted objects.</para>
	    </section>
	</partintro>
    </doc:reference>



	<doc:template name="block.object" xmlns="">
	<refpurpose>
		Generic handler for block-formatted objects.
	</refpurpose>
	<refdescription>
		<para>
		Calls <xref linkend="template.label.id"/> and then applies templates.
		</para>
	</refdescription>
	</doc:template>

    <xsl:template name="block.object">
	<xsl:call-template name="label.id"/>
	<xsl:apply-templates/>
    </xsl:template>

	<doc:template match="blockquote" xmlns="">
	<refpurpose>
		A quotation set off from the main text (not inline).
	</refpurpose>
	<refdescription>
		<para>
		Uses the LaTeX <literal>quote</literal> environment.
		If an attribution is present, it will be set at the end.
		</para>
	</refdescription>
	</doc:template>

    <xsl:template match="blockquote">
	<xsl:text>\begin{quote}</xsl:text>
	<xsl:apply-templates/>
	<xsl:apply-templates select="attribution" mode="block.attribution"/>
	<xsl:text>\end{quote}&#10;</xsl:text>
    </xsl:template>

	<doc:template match="epigraph" xmlns="">
	<refpurpose>
		A short inscription that occurs at the beginning of a section, chapter, or document.
	</refpurpose>
	<refdescription>
		<para>
		Uses the LaTeX <literal>quote</literal> environment.
		If an attribution is present, it will be set at the end.
		</para>
	</refdescription>
	</doc:template>

    <xsl:template match="epigraph">
	<xsl:text>\begin{quote}</xsl:text>
	<xsl:apply-templates/>
	<xsl:apply-templates select="attribution" mode="block.attribution"/>
	<xsl:text>\end{quote}&#10;</xsl:text>
    </xsl:template>

	<doc:template match="attribution" xmlns="">
	<refpurpose>
		This template produces no output.
	</refpurpose>
	<refdescription>
		<para>
		The <sgmltag class="element">attribution</sgmltag> element only occurs within
		<xref linkend="template.blockquote"/> and <xref linkend="template.epigraph"/>.
		However, the templates for those elements use a <quote>mode</quote> mechanism.
		Therefore, this template is intentionally suppressed and a replacement exists.
		See <xref linkend="template.attribution-block.attribution"/> instead.
		</para>
	</refdescription>
	</doc:template>

    <xsl:template match="attribution"/>

	<doc:template match="attribution" mode="block.attribution" xmlns="">
	<refpurpose>
		The source of a block quote or epigraph.
	</refpurpose>
	<refdescription>
		<para>
		Starts a new line with right-aligned text preceded by an em dash.
		</para>
	</refdescription>
	</doc:template>

    <xsl:template match="attribution" mode="block.attribution">
	<xsl:text>&#10;\hspace*\fill---</xsl:text>
	<xsl:apply-templates/>
    </xsl:template>

	<doc:template match="sidebar" xmlns="">
	<refpurpose>
		A block of text that is isolated from the main flow.
	</refpurpose>
	<refdescription>
		<para>
		This is formatted as a plain block.
		</para>
	</refdescription>
	</doc:template>

    <xsl:template match="sidebar">
	<xsl:call-template name="block.object"/>
    </xsl:template>

	<doc:template match="sidebar/title|blockquote/title" xmlns="">
	<refpurpose>
		Title lines for sundry block elements.
	</refpurpose>
	<refdescription>
		<para>
		This is formatted as a line on its own.
		</para>
	</refdescription>
	</doc:template>

    <xsl:template match="sidebar/title|blockquote/title">
	<xsl:apply-templates/>
	<xsl:text>&#10;</xsl:text>
    </xsl:template>

	<doc:template match="ackno" xmlns="">
	<refpurpose>
		Acknowledgements in an Article.
	</refpurpose>
	<refdescription>
		<para>
		This is formatted as a plain block.
		</para>
	</refdescription>
	</doc:template>

    <xsl:template match="ackno">
	<xsl:apply-templates/>
    </xsl:template>


</xsl:stylesheet>

