<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: admonition.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $		
|- #############################################################################
|	$Author: jelmer $
|
|   PURPOSE: Admonition templates. 
+ ############################################################################## -->
<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference name="admonition" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: admonition.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
	    </releaseinfo>
		<authorgroup>
		<author><firstname>Ramon</firstname> <surname>Casellas</surname></author>
		<author><firstname>James</firstname> <surname>Devenish</surname></author>
		</authorgroup>
	    <copyright><year>2000</year><year>2001</year><year>2002</year><year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>

	<title>Admonition XSL Variables and Templates <filename>admonition.mod.xsl</filename></title>

	<partintro>
	    <section><title>Introduction</title>
		<para>DocBook includes admonitions, which are set off from the main text.</para>
	    </section>
		<formalpara><title>Pertinent Variables</title>
		<itemizedlist>
			<listitem><simpara><xref linkend="param.latex.use.fancybox"/></simpara></listitem>
			<listitem><simpara><xref linkend="param.latex.admonition.path"/></simpara></listitem>
			<listitem><simpara><xref linkend="param.latex.admonition.imagesize"/></simpara></listitem>
			<listitem><simpara><xref linkend="param.latex.apply.title.templates.admonitions"/></simpara></listitem>
		</itemizedlist>
		</formalpara>
	</partintro>
    </doc:reference>

    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:param name="latex.admonition.environment" xmlns="">
	<refpurpose> 
	    Declares a new environment to be used for admonitions
		(warning, tip, important, caution, note).
	</refpurpose>
	<refdescription>
	    <para>
		A LaTeX environment is emitted. That environment has two mandatory parameters.
		Instances of the environment are customised for each admonition via those parameters.
		Instances will be typeset as boxed areas in the document flow.
		</para>
		<para>
		The first argument is the filename for graphics (e.g $latex.admonition.path/warning).
		The second argument is the admonition title or the associated generic text.
		</para>
		<para>
		It requires the LaTeX <link linkend="param.latex.use.fancybox">fancybox package</link>. 
		It also uses graphics, by default.
		</para>
		<example>
			<title>Processing the <sgmltag class="element">warning</sgmltag> admonition</title>
	    <para> When processing the admonition, the following code is generated: </para>
	    <programlisting><![CDATA[
		\begin{admonition}{figures/warning}{My WARNING}
		...
		\end{admonition}]]>
		</programlisting>
		</example>
	</refdescription>
    </doc:param>
    <!--############################################################################# -->

    <xsl:variable name="latex.admonition.environment">
	<xsl:text>\newenvironment{admminipage}{\begin{Sbox}\begin{minipage}}{\end{minipage}\end{Sbox}\fbox{\TheSbox}}&#10;</xsl:text>
	<xsl:text>\newlength{\admlength}&#10;</xsl:text>
	<xsl:text>\newenvironment{admonition}[2] {&#10;</xsl:text>
	<xsl:text> \hspace{0mm}\newline\hspace*\fill\newline&#10;</xsl:text>
	<xsl:text> \noindent&#10;</xsl:text>
	<xsl:text> \setlength{\fboxsep}{5pt}&#10;</xsl:text>
	<xsl:text> \setlength{\admlength}{\linewidth}&#10;</xsl:text>
	<xsl:text> \addtolength{\admlength}{-10\fboxsep}&#10;</xsl:text>
	<xsl:text> \addtolength{\admlength}{-10\fboxrule}&#10;</xsl:text>
	<xsl:text> \admminipage{\admlength}&#10;</xsl:text>
	<xsl:text> {\bfseries \sc\large{#2}} \newline&#10;</xsl:text>
	<xsl:text> \\[1mm]&#10;</xsl:text>
	<xsl:text> \sffamily&#10;</xsl:text>
	<xsl:if test="$latex.admonition.path=''">
		<xsl:text>%</xsl:text>
		<!--
			Comment out the next line (\includegraphics).
			This tactic is to avoid deleting the \includegraphics
			altogether, as that could confuse a person trying to
			find the use of parameter #1 in the environment.
		-->
	</xsl:if>
	<xsl:text> \includegraphics[</xsl:text>
	<xsl:value-of select="$latex.admonition.imagesize" />
	<xsl:text>]{#1}&#10;</xsl:text>
	<xsl:text> \addtolength{\admlength}{-1cm}&#10;</xsl:text>
	<xsl:text> \addtolength{\admlength}{-20pt}&#10;</xsl:text>
	<xsl:text> \begin{minipage}[lt]{\admlength}&#10;</xsl:text>
	<xsl:text> \parskip=0.5\baselineskip \advance\parskip by 0pt plus 2pt&#10;</xsl:text>
	<xsl:text>}{&#10;</xsl:text>
	<xsl:text> \vspace{5mm} &#10;</xsl:text>
	<xsl:text> \end{minipage}&#10;</xsl:text>
	<xsl:text> \endadmminipage&#10;</xsl:text>
	<xsl:text> \vspace{.5em}&#10;</xsl:text>
	<xsl:text> \par&#10;</xsl:text>
	<xsl:text>}&#10;</xsl:text>
    </xsl:variable>

    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template name="admon.graphic" xmlns="">
	<refpurpose> Choose an admonition graphic </refpurpose>
	<refdescription>
	    <para> For each admonition element (note, warning, caution, top, important),
		this template chooses the graphics filename. If the admonition element is
		not known, the <sgmltag class="element">note</sgmltag> graphic is used.
	    </para>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template name="admon.graphic">
	<xsl:param name="node" select="."/>
	<xsl:choose>
	    <xsl:when test="name($node)='note'">note</xsl:when>
	    <xsl:when test="name($node)='warning'">warning</xsl:when>
	    <xsl:when test="name($node)='caution'">caution</xsl:when>
	    <xsl:when test="name($node)='tip'">tip</xsl:when>
	    <xsl:when test="name($node)='important'">important</xsl:when>
	    <xsl:otherwise>note</xsl:otherwise>
	</xsl:choose>
    </xsl:template>


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template name="admonitions" match="note|important|warning|caution|tip" xmlns="">
	<refpurpose> XSL Template for admonitions </refpurpose>
	<refdescription>
	    <para> Uses the <xref linkend="param.latex.admonition.environment"/>.
	    </para>
		<note><para>An admonition will look something like this.</para></note>
	    <formalpara><title>Remarks and Bugs</title>
		<itemizedlist>
		<listitem>
		<para>
		There can be <quote>excessive</quote> whitespace between
		the bottom of the admonition area and a subsequent paragraph.
		</para>
		</listitem>
		</itemizedlist>
	    </formalpara>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="note|important|warning|caution|tip">
	<xsl:call-template name="map.begin">
	    <xsl:with-param name="keyword">admonition</xsl:with-param>
	    <xsl:with-param name="string">
		<xsl:text>{</xsl:text>
		<xsl:value-of select="$latex.admonition.path"/><xsl:text>/</xsl:text>
		<xsl:call-template name="admon.graphic"/>
		<xsl:text>}{</xsl:text>
		<xsl:choose> 
		    <xsl:when test="title and $latex.apply.title.templates.admonitions='1'">
			<xsl:call-template name="extract.object.title">
				<xsl:with-param name="object" select="."/>
			</xsl:call-template>
		    </xsl:when>
		    <xsl:otherwise>
			<xsl:call-template name="gentext.element.name"/>
		    </xsl:otherwise> 
		</xsl:choose>
		<xsl:text>}</xsl:text>
	    </xsl:with-param>
	</xsl:call-template>
	<xsl:apply-templates/>
	<xsl:call-template name="map.end">
	    <xsl:with-param name="keyword">admonition</xsl:with-param>
	</xsl:call-template>
    </xsl:template>

    <!-- Empty title template -->
    <xsl:template match="note/title|important/title|warning/title|caution/title|tip/title"/>

</xsl:stylesheet>
