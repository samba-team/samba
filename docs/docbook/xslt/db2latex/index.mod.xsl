<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: index.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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
    <doc:reference id="index" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: index.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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

	<title>Index <filename>index.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>




    <xsl:template match="index|setindex">
	<xsl:call-template name="label.id"/>
	<xsl:text>\printindex&#10;</xsl:text>
    </xsl:template>

    <xsl:template match="index/title"></xsl:template>
    <xsl:template match="index/subtitle"></xsl:template>
    <xsl:template match="index/titleabbrev"></xsl:template>

    <xsl:template match="index/title" mode="component.title.mode">
	<xsl:call-template name="label.id"> <xsl:with-param name="object" select=".."/> </xsl:call-template>
    </xsl:template>

    <xsl:template match="index/subtitle" mode="component.title.mode"/>




    <xsl:template match="indexdiv">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="indexdiv/title">
	<xsl:call-template name="label.id"> <xsl:with-param name="object" select=".."/> </xsl:call-template>
    </xsl:template>


<!-- INDEX TERM CONTENT MODEL
IndexTerm ::=
(Primary,
((Secondary,
((Tertiary,
(See|SeeAlso+)?)|
See|SeeAlso+)?)|
See|SeeAlso+)?)
-->
<xsl:template match="indexterm">
<xsl:text>\index{</xsl:text>
<!-- output primary -->
<xsl:call-template name="normalize-scape">
	<xsl:with-param name="string" select="normalize-space(./primary)"/>
</xsl:call-template>
<!-- output secondary if it exists -->
<xsl:if test="./secondary">
	<xsl:text>!</xsl:text>
	<xsl:call-template name="normalize-scape">
		<xsl:with-param name="string" select="normalize-space(./secondary)"/>
	</xsl:call-template>
</xsl:if>
<!-- output tertiary if it exists -->
<xsl:if test="./tertiary">
	<xsl:text>!</xsl:text>
	<xsl:call-template name="normalize-scape">
		<xsl:with-param name="string" select="normalize-space(./tertiary)"/>
	</xsl:call-template>
</xsl:if>
<!-- idem with see/seealso -->
<xsl:if test="./see">
	<xsl:text>|see{</xsl:text>
	<xsl:call-template name="normalize-scape">
		<xsl:with-param name="string" select="normalize-space(./see)"/>
	</xsl:call-template>
	<xsl:text>}</xsl:text>
</xsl:if>
<xsl:if test="./seealso">
	<xsl:text>|see{</xsl:text>
	<xsl:call-template name="normalize-scape">
		<xsl:with-param name="string" select="normalize-space(./seealso)"/>
	</xsl:call-template>
	<xsl:text>}</xsl:text>
</xsl:if>
<xsl:text>}</xsl:text>
</xsl:template>




    <xsl:template match="primary|secondary|tertiary|see|seealso"/>
    <xsl:template match="indexentry"/>
    <xsl:template match="primaryie|secondaryie|tertiaryie|seeie|seealsoie"/>

</xsl:stylesheet>
