<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: part-chap-app.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
|- #############################################################################
|	$Author: ab $
|														
|   PURPOSE: Part
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="part-chap-app" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: part-chap-app.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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
	<title>Parts, Chapters and Appendixes <filename>part-chap-app.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>
    <!--############################################################################# -->




    <xsl:template match="part">
	<xsl:call-template name="map.begin"/>
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="part/docinfo"/>
    <xsl:template match="part/title"/>
    <xsl:template match="part/subtitle"/>
    <xsl:template match="partintro"/>
    <xsl:template match="partintro/title"/>
    <xsl:template match="partintro/subtitle"/>
    <xsl:template match="partintro/titleabbrev"/>


    <!--############################################################################# 
    |	$Id: part-chap-app.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
    |- #############################################################################
    |	$Author: ab $
    |														
    |   PURPOSE: Chapter
    + ############################################################################## -->


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="chapter" xmlns="">
	<refpurpose> XSL template for Chapters.</refpurpose>
	<refdescription>
	    <para> This is the main entry point for a <sgmltag class="start">chapter</sgmltag> subtree.
		This template processes any chapter. Outputs <literal>\chapter{title}</literal>, calls 
		templates and apply-templates. Since chapters only apply in books, 
		some assumptions could be done in order to optimize the stylesheet behaviour.</para>

	    <formalpara><title>Remarks and Bugs</title>
		<itemizedlist>
		    <listitem><para> 
			EMPTY templates: chapter/title, 
			chapter/titleabbrev, 
			chapter/subtitle, 
			chapter/docinfo|chapterinfo.</para></listitem>
		</itemizedlist>
	    </formalpara>

	    <formalpara><title>Affected by</title> map. 
	    </formalpara>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="chapter">
	<xsl:call-template name="map.begin"/>
	<xsl:apply-templates/>
	<xsl:call-template name="map.end"/>
    </xsl:template>

    <xsl:template match="chapter/title"/>
    <xsl:template match="chapter/titleabbrev"/>
    <xsl:template match="chapter/subtitle"/>
    <xsl:template match="chapter/docinfo|chapterinfo"/>


    <!--############################################################################# 
    |	$Id: part-chap-app.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
    |- #############################################################################
    |	$Author: ab $
    |														
    |   PURPOSE:
    + ############################################################################## -->

    <xsl:template match="appendix">
	<xsl:if test="not (preceding-sibling::appendix)">
	    <xsl:text>&#10;</xsl:text>
	    <xsl:choose>
		<xsl:when test="local-name(..)='book' or local-name(..)='part'">
		    <xsl:text>\newcommand{\dbappendix}[1]{\chapter{#1}}%&#10;</xsl:text>
		</xsl:when>
		<xsl:otherwise>
		    <xsl:text>\newcommand{\dbappendix}[1]{\section{#1}}%&#10;</xsl:text>
		</xsl:otherwise>
	    </xsl:choose>
	    <xsl:call-template name="map.begin">
		<xsl:with-param name="keyword">appendixes</xsl:with-param>
	    </xsl:call-template>
	</xsl:if>
	<xsl:call-template name="map.begin"/>
	<xsl:apply-templates/>
	<xsl:call-template name="map.end"/>
    </xsl:template>


    <xsl:template match="appendix/title"/>
    <xsl:template match="appendix/titleabbrev"/>
    <xsl:template match="appendix/subtitle"/>
    <xsl:template match="appendix/docinfo|appendixinfo"/>
</xsl:stylesheet>

