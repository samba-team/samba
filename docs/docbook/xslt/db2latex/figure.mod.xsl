<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: figure.mod.xsl,v 1.1.4.1 2003/06/06 15:08:20 jerry Exp $
|- #############################################################################
|	$Author: jerry $												
|														
|   PURPOSE: Template for figure tag.
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>

    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="figure" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: figure.mod.xsl,v 1.1.4.1 2003/06/06 15:08:20 jerry Exp $
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

	<title>Figures and InformalFigures <filename>figure.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>
    <!--############################################################################# -->




    <!--############################################################################# -->
    <doc:template match="figure|informalfigure" xmlns="">
	<refpurpose> XSL template for figure|informalfigure  </refpurpose>
	<refdescription>
	    <para>Outputs <literal>\begin{figure}</literal>,
		applies templates and outputs <literal>\end{figure}</literal>. </para>
	    <formalpara><title>Remarks and Bugs</title>
		<itemizedlist>
			<listitem><para>The <literal>figure.title</literal> can be typset in italics by specifying <literal>$latex.figure.title.style</literal> (<literal>\itshape</literal> would be common).</para></listitem>
			<listitem><para>If a <literal>figure.mediaobject.caption</literal> exists, it will be typeset after the <literal>figure.title</literal> (but only if there is a single <literal>figure.mediaobject.caption</literal>).</para></listitem>
		</itemizedlist>
	    </formalpara>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->


<!-- Auxiliary template to output a figure caption.-->
<xsl:template name="aux.figure.caption">
<xsl:text>\caption{{</xsl:text>
<xsl:value-of select="$latex.figure.title.style"/>
<xsl:text>{</xsl:text>
<xsl:apply-templates select="title"/>
<xsl:text>}}</xsl:text>
<xsl:if test="count(child::mediaobject/caption)=1">
	<xsl:text>. </xsl:text>
	<xsl:apply-templates select="mediaobject/caption" />
</xsl:if>
<xsl:text>}&#10;</xsl:text>
</xsl:template>

<xsl:template match="figure|informalfigure">
	<xsl:variable name="placement">
		<xsl:call-template name="generate.formal.title.placement">
			<xsl:with-param name="object" select="local-name(.)" />
		</xsl:call-template>
	</xsl:variable>
	<xsl:call-template name="map.begin"/>
	<xsl:if test="$placement='before'">
		<xsl:text>\captionswapskip{}</xsl:text>
		<xsl:call-template name="aux.figure.caption" />
		<xsl:text>\captionswapskip{}</xsl:text>
	</xsl:if>
	<xsl:apply-templates select="*[name(.) != 'title']"/>
	<xsl:if test="$placement!='before'">
		<xsl:call-template name="aux.figure.caption" />
	</xsl:if>
	<xsl:call-template name="map.end"/>
</xsl:template>



    <!--############################################################################# -->
	<!--
    <doc:template match="figure[programlisting]" xmlns="">
	<refpurpose> XSL template for programlisting within a figure </refpurpose>
	<refdescription>
	    <para>Outputs <literal>\begin{figure}</literal>,
		applies templates and outputs <literal>\end{abstract}</literal>. </para>
	    <formalpara><title>Remarks and Bugs</title>
		<itemizedlist>
		</itemizedlist>
	    </formalpara>
	</refdescription>
    </doc:template>
	-->
    <!--############################################################################# -->

	<!--
    <xsl:template match="figure[programlisting]">
	<xsl:call-template name="map.begin">
	    <xsl:with-param name="keyword" select="programlisting"/>
	</xsl:call-template>
	<xsl:apply-templates />
	<xsl:call-template name="map.end">
	    <xsl:with-param name="keyword" select="programlisting"/>
	</xsl:call-template>
    </xsl:template>
	-->

    <xsl:template match="figure/title">
	<xsl:apply-templates/>
	</xsl:template>

    <xsl:template match="informalfigure/title">
	</xsl:template>
</xsl:stylesheet>
