<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: sgmltag.mod.xsl,v 1.1.4.1 2003/06/06 15:08:20 jerry Exp $
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
    <doc:reference id="sgmltag" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: sgmltag.mod.xsl,v 1.1.4.1 2003/06/06 15:08:20 jerry Exp $
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

	<title>SGML Tags <filename>sgmltag.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>




    <xsl:template match="sgmltag">
	<xsl:call-template name="format.sgmltag"/>
    </xsl:template>

    <xsl:template name="format.sgmltag">
	<xsl:param name="class">
	    <xsl:choose>
		<xsl:when test="@class">
		    <xsl:value-of select="normalize-space(@class)"/>
		</xsl:when>
		<xsl:otherwise>element</xsl:otherwise>
	    </xsl:choose>
	</xsl:param>

	<xsl:choose>
	    <xsl:when test="$class='attribute'">
		<xsl:call-template name="inline.charseq"/>
	    </xsl:when>
	    <xsl:when test="$class='attvalue'">
		<xsl:call-template name="inline.monoseq"/>
	    </xsl:when>
	    <xsl:when test="$class='element'">
		<xsl:call-template name="inline.monoseq"/>
	    </xsl:when>
	    <xsl:when test="$class='endtag'">
		<xsl:call-template name="inline.monoseq">
		    <xsl:with-param name="content">
			<xsl:text>&lt;/</xsl:text>
			<xsl:apply-templates/>
			<xsl:text>&gt;</xsl:text>
		    </xsl:with-param>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test="$class='genentity'">
		<xsl:call-template name="inline.monoseq">
		    <xsl:with-param name="content">
			<xsl:text>\&amp;</xsl:text>
			<xsl:apply-templates/>
			<xsl:text>;</xsl:text>
		    </xsl:with-param>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test="$class='numcharref'">
		<xsl:call-template name="inline.monoseq">
		    <xsl:with-param name="content">
			<xsl:text>\&amp;\#</xsl:text>
			<xsl:apply-templates/>
			<xsl:text>;</xsl:text>
		    </xsl:with-param>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test="$class='paramentity'">
		<xsl:call-template name="inline.monoseq">
		    <xsl:with-param name="content">
			<xsl:text>\%</xsl:text>
			<xsl:apply-templates/>
			<xsl:text>;</xsl:text>
		    </xsl:with-param>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test="$class='pi'">
		<xsl:call-template name="inline.monoseq">
		    <xsl:with-param name="content">
			<xsl:text>&lt;?</xsl:text>
			<xsl:apply-templates/>
			<xsl:text>?&gt;</xsl:text>
		    </xsl:with-param>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test="$class='xmlpi'">
		<xsl:call-template name="inline.monoseq">
		    <xsl:with-param name="content">
			<xsl:text>&lt;?</xsl:text>
			<xsl:apply-templates/>
			<xsl:text>?&gt;</xsl:text>
		    </xsl:with-param>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test="$class='starttag'">
		<xsl:call-template name="inline.monoseq">
		    <xsl:with-param name="content">
			<xsl:text>&lt;</xsl:text>
			<xsl:apply-templates/>
			<xsl:text>&gt;</xsl:text>
		    </xsl:with-param>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test="$class='emptytag'">
		<xsl:call-template name="inline.monoseq">
		    <xsl:with-param name="content">
			<xsl:text>&lt;</xsl:text>
			<xsl:apply-templates/>
			<xsl:text>/&gt;</xsl:text>
		    </xsl:with-param>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test="$class='sgmlcomment'">
		<xsl:call-template name="inline.monoseq">
		    <xsl:with-param name="content">
			<xsl:text>&lt;!--</xsl:text>
			<xsl:apply-templates/>
			<xsl:text>--&gt;</xsl:text>
		    </xsl:with-param>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:call-template name="inline.charseq"/>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

</xsl:stylesheet>

