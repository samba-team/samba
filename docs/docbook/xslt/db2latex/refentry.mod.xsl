<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: refentry.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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
    <doc:reference id="refentry" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: refentry.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
	    </releaseinfo>
	<authogroup>
	    <author> <firstname>Ramon</firstname> <surname>Casellas</surname> </author>
	    <author> <firstname>James</firstname> <surname>Devenish</surname> </author>
	</authogroup>
	    <copyright>
		<year>2000</year> <year>2001</year> <year>2002</year> <year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>

	<title>References and Entries <filename>refentry.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>



    <!--############################################################################# 
    |	REFERENCE	
    |- #############################################################################
    |														
    + ############################################################################## -->
    <xsl:template match="reference">
	<xsl:call-template name="map.begin"/>
	<xsl:apply-templates select="partintro"/>
	<xsl:apply-templates select="*[local-name(.) != 'partintro']"/>
    </xsl:template>

    <xsl:template match="reference" mode="division.number">
	<xsl:number from="book" count="reference" format="I."/>
    </xsl:template>

    <xsl:template match="reference/docinfo"/>
    <xsl:template match="reference/title"/>
    <xsl:template match="reference/subtitle"/>



    <!--############################################################################# 
    |	REFENTRY
    |- #############################################################################
    |														
    + ############################################################################## -->
    <xsl:template match="refentry">
	<xsl:variable name="refmeta" select=".//refmeta"/>
	<xsl:variable name="refentrytitle" select="$refmeta//refentrytitle"/>
	<xsl:variable name="refnamediv" select=".//refnamediv"/>
	<xsl:variable name="refname" select="$refnamediv//refname"/>
	<xsl:variable name="title">
	    <xsl:choose>
		<xsl:when test="$refentrytitle">
		    <xsl:apply-templates select="$refentrytitle[1]" mode="title"/>
		</xsl:when>
		<xsl:when test="$refname">
		    <xsl:apply-templates select="$refname[1]" mode="title"/>
		</xsl:when>
		<xsl:otherwise></xsl:otherwise>
	    </xsl:choose>
	</xsl:variable>
	<xsl:call-template name="map.begin">
	    <xsl:with-param name="string" select="$title"/>
	</xsl:call-template>
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="refentrytitle|refname" mode="title">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="refentry/docinfo|refentry/refentryinfo"/>
    <xsl:template match="refmeta"/>

    <xsl:template match="manvolnum">
	<xsl:if test="$refentry.xref.manvolnum != 0">
	    <xsl:text>(</xsl:text>
	    <xsl:apply-templates/>
	    <xsl:text>)</xsl:text>
	</xsl:if>
    </xsl:template>

    <xsl:template match="refmiscinfo"/>

    <xsl:template match="refentrytitle">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="refnamediv">
	<xsl:call-template name="block.object"/>
    </xsl:template>

    <xsl:template match="refname">
	<xsl:apply-templates/>
	<xsl:if test="not (preceding-sibling::refname)">
	    <xsl:text>&#10;\subsection*{</xsl:text>
	    <xsl:if test="$refentry.generate.name != 0">
		<xsl:call-template name="gentext.element.name"/>
	    </xsl:if>
	    <xsl:text>}&#10;</xsl:text>
	</xsl:if>
	<xsl:apply-templates/>
	<xsl:if test="following-sibling::refname">
	    <xsl:text>, </xsl:text>
	</xsl:if>
    </xsl:template>


    <xsl:template match="refpurpose">
	<xsl:text> $-$ </xsl:text>
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="refdescriptor">
	<!-- todo: finish this -->
    </xsl:template>

    <xsl:template match="refclass">
	<xsl:if test="@role">
	    <xsl:value-of select="@role"/>
	    <xsl:text>: </xsl:text>
	</xsl:if>
	<xsl:apply-templates/>
    </xsl:template>



    <!--############################################################################# 
    |	REFSYNOPSIS
    |- #############################################################################
    |														
    + ############################################################################## -->

    <xsl:template match="refsynopsisdiv">
	<xsl:call-template name="label.id"/>
	<xsl:text>&#10;\subsection*{Synopsis}&#10;</xsl:text>
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="refsynopsisdivinfo"></xsl:template>
    <xsl:template match="refsynopsisdiv/title"></xsl:template>


    <!--############################################################################# 
    |	REFSECTS
    |- #############################################################################
    |														
    + ############################################################################## -->

    <xsl:template match="refsect1|refsect2|refsect3">
	<xsl:call-template name="map.begin"/>
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="refsect1/title"/>
    <xsl:template match="refsect2/title"/>
    <xsl:template match="refsect3/title"/>
    <xsl:template match="refsect1info"/>
    <xsl:template match="refsect2info"/>
    <xsl:template match="refsect3info"/>


</xsl:stylesheet>
