<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: procedure.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
|- #############################################################################
|	$Author: ab $
|														
|   PURPOSE:
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="procedure" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: procedure.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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

	<title>Procedures <filename>procedure.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>





<!--############################################################################# -->
<doc:template match="procedure" xmlns="">
<refpurpose>Procedure XSL Template.</refpurpose>
<refdescription>
<para></para>
<programlisting><![CDATA[
]]></programlisting>
</refdescription>
</doc:template>
<!--############################################################################# -->

<xsl:template match="procedure">
	<xsl:variable name="placement">
		<xsl:call-template name="generate.formal.title.placement">
			<xsl:with-param name="object" select="local-name(.)" />
		</xsl:call-template>
	</xsl:variable>
	<xsl:choose>
	<xsl:when test="$placement='before' or $placement=''">
		<xsl:apply-templates select="title" mode="procedure.title"/>
		<xsl:text>\begin{enumerate}&#10;</xsl:text>
		<xsl:apply-templates/>
		<xsl:text>\end{enumerate}&#10;</xsl:text>
	</xsl:when>
	<xsl:otherwise>
		<xsl:text>\begin{enumerate}&#10;</xsl:text>
		<xsl:apply-templates/>
		<xsl:text>\end{enumerate}&#10;</xsl:text>
		<xsl:apply-templates select="title" mode="procedure.title"/>
	</xsl:otherwise>
	</xsl:choose>
</xsl:template>


<xsl:template match="procedure/title">
</xsl:template>

<xsl:template match="procedure/title" mode="procedure.title">
	<xsl:text>&#10;&#10;{</xsl:text>
	<xsl:value-of select="$latex.procedure.title.style"/>
	<xsl:text>{</xsl:text>
	<xsl:choose>
		<xsl:when test="$latex.apply.title.templates=1">
			<xsl:apply-templates/>
		</xsl:when>
		<xsl:otherwise>
			<xsl:value-of select="."/>
		</xsl:otherwise>
	</xsl:choose>
	<xsl:text>}}&#10;</xsl:text>
</xsl:template>




<!--############################################################################# -->
<doc:template match="step" xmlns="">
<refpurpose>Step XSL Template.</refpurpose>
<refdescription>
<para></para>
<programlisting><![CDATA[
]]></programlisting>
</refdescription>
</doc:template>
<!--############################################################################# -->

    <xsl:template match="step">
	<xsl:choose>
	    <xsl:when test="title">
			<xsl:text>&#10;\item{{</xsl:text>
			<xsl:value-of select="$latex.step.title.style"/> <!-- by default \sc -->
			<xsl:text>{</xsl:text>
			<xsl:apply-templates select="title"/>
			<xsl:text>}}&#10;</xsl:text>
	    </xsl:when>
	    <xsl:otherwise>
			<xsl:text>&#10;\item{</xsl:text>
	    </xsl:otherwise>
	</xsl:choose>
	 <xsl:apply-templates select="*[not(self::title)]"/>
	<xsl:text>}&#10;</xsl:text>
    </xsl:template>

<!-- step/title, just apply templates ########################################### -->
    <xsl:template match="step/title"> 
		<xsl:apply-templates/>
	</xsl:template>









<!--############################################################################# -->
<doc:template match="substeps" xmlns="">
<refpurpose>SubSteps XSL Template.</refpurpose>
<refdescription>
<para></para>
<programlisting><![CDATA[
<xsl:template match="substeps">
	<xsl:text>\begin{enumerate}&#10;</xsl:text>
	<xsl:apply-templates/>
	<xsl:text>\end{enumerate}&#10;</xsl:text>
</xsl:template>
]]></programlisting>
</refdescription>
</doc:template>
<!--############################################################################# -->

<xsl:template match="substeps">
	<xsl:text>\begin{enumerate}&#10;</xsl:text>
	<xsl:apply-templates/>
	<xsl:text>\end{enumerate}&#10;</xsl:text>
</xsl:template>

</xsl:stylesheet>

