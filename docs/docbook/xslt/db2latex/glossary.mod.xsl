<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: glossary.mod.xsl,v 1.1.2.1 2003/05/01 14:06:14 jelmer Exp $
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
    <doc:reference id="glossary" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: glossary.mod.xsl,v 1.1.2.1 2003/05/01 14:06:14 jelmer Exp $
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
	<title>Glossary <filename>glossary.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para>This reference applies to the glossary element name. Altough LaTeX
		    provides some glossary support, the better glossary management support
		    motivates the bypass of the LaTeX <literal>\makeglossary</literal>
		    command.</para>
	    </section>
	</partintro>
    </doc:reference>
    <!--############################################################################# -->


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="glossary" xmlns="">
	<refpurpose> Glossary XSL template / entry point  </refpurpose>
	<refdescription><para>The <sgmltag>glossary</sgmltag> element is the entry point
		to a docbook glossary. The DB2LaTeX processing of the element is quite straight-
		forward. First thing is to check whether the document is a book or article. In 
		both cases two new LaTeX commands are defined. <literal>\dbglossary</literal>
		and <literal>\dbglossdiv</literal>. In the former case, they are mapped to 
		<literal>\chapter*</literal> and <literal>\section*</literal>. In the second
		case to <literal>\section*</literal> and <literal>\subsection*</literal>.</para>
	</refdescription>
	<itemizedlist>
	    <listitem><para>Call template map.begin.</para></listitem>
	    <listitem><para>Apply Templates for Preamble, GlossDivs and GlossEntries (serial).</para></listitem>
	    <listitem><para>Call template map.end.</para></listitem>
	</itemizedlist>
	<formalpara><title>Remarks and Bugs</title>
	    <itemizedlist>
		<listitem><para>Template for glossary/glossaryinfo is EMPTY.</para></listitem>
		<listitem><para>Template for glossary/title | glossary/subtitle is EMPTY.</para></listitem>
		<listitem><para>Template for glossary/titleabbrev is EMPTY.</para></listitem>
	    </itemizedlist>
	</formalpara>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="glossary">
	<xsl:variable name="divs" select="glossdiv"/>
	<xsl:variable name="entries" select="glossentry"/>
	<xsl:variable name="preamble" select="*[not(self::title or self::subtitle or self::glossdiv or self::glossentry)]"/>
	<xsl:choose>
	    <xsl:when test="local-name(..)='book' or local-name(..)='part'">
		<xsl:text>\newcommand{\dbglossary}[1]{\chapter*{#1}}%&#10;</xsl:text>
		<xsl:text>\newcommand{\dbglossdiv}[1]{\section*{#1}}%&#10;</xsl:text>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:text>\newcommand{\dbglossary}[1]{\section*{#1}}%&#10;</xsl:text>
		<xsl:text>\newcommand{\dbglossdiv}[1]{\subsection*{#1}}%&#10;</xsl:text>
	    </xsl:otherwise>
	</xsl:choose>
	<xsl:call-template name="map.begin"/>
	<xsl:if test="./subtitle"><xsl:apply-templates select="./subtitle" mode="component.title.mode"/> </xsl:if>
	<xsl:if test="$preamble"> <xsl:apply-templates select="$preamble"/> </xsl:if>
	<xsl:if test="$divs"> <xsl:apply-templates select="$divs"/> </xsl:if>
	<xsl:if test="$entries"> <xsl:apply-templates select="$entries"/></xsl:if>
	<xsl:call-template name="map.end"/>
    </xsl:template>

    <xsl:template match="glossary/glossaryinfo"/>
    <xsl:template match="glossary/title"/>
    <xsl:template match="glossary/subtitle"/>
    <xsl:template match="glossary/titleabbrev"/>
    <xsl:template match="glossary/title" 	mode="component.title.mode"> <xsl:apply-templates/> </xsl:template>
    <xsl:template match="glossary/subtitle" 	mode="component.title.mode"> <xsl:apply-templates/> </xsl:template>




    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="glossdiv|glosslist" xmlns="">
	<refpurpose> Glossary Division and Glossary Lists XSL templates.  </refpurpose>
	<refdescription><para>T.B.D</para>
	</refdescription>
	<itemizedlist>
	    <listitem><para>Call template map.begin.</para></listitem>
	    <listitem><para>Apply Templates.</para></listitem>
	    <listitem><para>Call template map.end.</para></listitem>
	</itemizedlist>
	<formalpara><title>Remarks and Bugs</title>
	    <itemizedlist>
		<listitem><para>Template for glossdiv/glossaryinfo is EMPTY.</para></listitem>
	    </itemizedlist>
	</formalpara>
    </doc:template>
    <!--############################################################################# -->
    <xsl:template match="glossdiv|glosslist">
	<xsl:call-template name="map.begin"/>
	<xsl:apply-templates/>
	<xsl:call-template name="map.end"/>
    </xsl:template>

    <xsl:template match="glossdiv/title" />




    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="glossentry" xmlns="">
	<refpurpose> Glossary Entry XSL template / entry point  </refpurpose>
	<refdescription>
	    <para>T.B.D.</para>
	</refdescription>
	<itemizedlist>
	    <listitem><para>Apply Templates.</para></listitem>
	</itemizedlist>
	<formalpara><title>Remarks and Bugs</title>
	    <itemizedlist>
		<listitem><para>Explicit Templates for <literal>glossentry/glossterm</literal></para></listitem>
		<listitem><para>Explicit Templates for <literal>glossentry/acronym</literal></para></listitem>
		<listitem><para>Explicit Templates for <literal>glossentry/abbrev</literal></para></listitem>
		<listitem><para>Explicit Templates for <literal>glossentry/glossdef</literal></para></listitem>
		<listitem><para>Explicit Templates for <literal>glossentry/glosssee</literal></para></listitem>
		<listitem><para>Explicit Templates for <literal>glossentry/glossseealso</literal></para></listitem>
		<listitem><para>Template for glossentry/revhistory is EMPTY.</para></listitem>
	    </itemizedlist>
	</formalpara>
    </doc:template>
    <!--############################################################################# -->


    <xsl:template match="glossentry">
	<xsl:apply-templates/>
	<xsl:text>&#10;&#10;</xsl:text>
    </xsl:template>

    <xsl:template match="glossentry/glossterm">
	<xsl:text>\item[</xsl:text>
	<xsl:if test="../@id!=''">
		<xsl:text>\hypertarget{</xsl:text>
		<xsl:value-of select="../@id"/>
		<xsl:text>}</xsl:text>
	</xsl:if>
	<xsl:text>{</xsl:text>
	<xsl:call-template name="normalize-scape">
	    <xsl:with-param name="string" select="."/>
	</xsl:call-template>
	<xsl:text>}] </xsl:text>
    </xsl:template>

    <xsl:template match="glossentry/acronym">
	<xsl:text> ( \texttt {</xsl:text> <xsl:apply-templates/> <xsl:text>} ) </xsl:text>
    </xsl:template>

    <xsl:template match="glossentry/abbrev">
	<xsl:text> [ </xsl:text> <xsl:apply-templates/> <xsl:text> ] </xsl:text> 
    </xsl:template>

    <xsl:template match="glossentry/revhistory"/>

    <xsl:template match="glossentry/glossdef">
	<xsl:text>&#10;</xsl:text>
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="glossseealso|glossentry/glosssee">
	<xsl:variable name="otherterm" select="@otherterm"/>
	<xsl:variable name="targets" select="//node()[@id=$otherterm]"/>
	<xsl:variable name="target" select="$targets[1]"/>
	<xsl:call-template name="gentext.element.name"/>
	<xsl:call-template name="gentext.space"/>
	<xsl:call-template name="gentext.startquote"/>
	<xsl:choose>
	    <xsl:when test="@otherterm">
		<xsl:text>\hyperlink{</xsl:text><xsl:value-of select="@otherterm"/>
		<xsl:text>}{</xsl:text><xsl:apply-templates select="$target" mode="xref"/><xsl:text>}</xsl:text>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:apply-templates/>
	    </xsl:otherwise>
	</xsl:choose>
	<xsl:call-template name="gentext.endquote"/>
	<xsl:text>. </xsl:text>
    </xsl:template>

    <xsl:template match="glossentry" mode="xref">
	<xsl:apply-templates select="./glossterm" mode="xref"/>
    </xsl:template>

    <xsl:template match="glossterm" mode="xref">
	<xsl:apply-templates/>
    </xsl:template>

</xsl:stylesheet>
