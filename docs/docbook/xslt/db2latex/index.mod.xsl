<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: index.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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
    <doc:reference id="index" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: index.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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


<!-- This parameter is for enabeling or disabling of indexterms -->
<xsl:param name="latex.generate.indexterm">1</xsl:param>

<!-- Our key for ranges -->
<xsl:key name="indexterm-range" match="indexterm[@class='startofrange']" use="@id"/>




<!-- ############################################################### -->
<!-- Index                                                           -->
<!--                                                                 -->
<!-- ############################################################### -->
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


<!-- ############################################################### -->
<!-- IndexDiv                                                        -->
<!--                                                                 -->
<!-- ############################################################### -->
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
<!-- ############################################################### -->
<!-- IndexDiv                                                        -->
<!--                                                                 -->
<!-- ############################################################### -->
<xsl:template match="indexterm">
<xsl:if test="$latex.generate.indexterm != 0">
<!--
		<xsl:text>\index{</xsl:text>
		<xsl:call-template name="normalize-scape">
			<xsl:with-param name="string" select="normalize-space(./primary)"/>
		</xsl:call-template>
		<xsl:if test="./secondary">
			<xsl:text>!</xsl:text>
			<xsl:call-template name="normalize-scape">
				<xsl:with-param name="string" select="normalize-space(./secondary)"/>
			</xsl:call-template>
		</xsl:if>
		<xsl:if test="./tertiary">
			<xsl:text>!</xsl:text>
			<xsl:call-template name="normalize-scape">
				<xsl:with-param name="string" select="normalize-space(./tertiary)"/>
			</xsl:call-template>
		</xsl:if>
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
-->
	<xsl:variable name="idxterm">
		<xsl:apply-templates mode="indexterm"/>
	</xsl:variable>

	<xsl:if test="@class and @zone">
		<xsl:message terminate="yes">Error: Only one attribut (@class or @zone) is in indexterm possible!</xsl:message>
	</xsl:if>

	<xsl:choose>
		<xsl:when test="@class='startofrange'">
			<xsl:text>\index{</xsl:text>
				<xsl:value-of select="normalize-space($idxterm)"/>
			<xsl:text>|(}</xsl:text>
		</xsl:when>
		<xsl:when test="@class='endofrange'">
			<xsl:choose>
				<xsl:when test="count(key('indexterm-range',@startref)) = 0">
					<xsl:message terminate="yes"><xsl:text>Error: No indexterm with </xsl:text>
					<xsl:text>id='</xsl:text><xsl:value-of select="@startref"/>
					<xsl:text>' found!</xsl:text>
					<xsl:text>  Check your attributs id/startref in your indexterms!</xsl:text>
					</xsl:message>
				</xsl:when>
				<xsl:otherwise>
					<xsl:variable name="thekey" select="key('indexterm-range',@startref)"/>
					<xsl:text>\index{</xsl:text>
					<xsl:apply-templates select="$thekey/*"  mode="indexterm"/>
					<xsl:text>|)}</xsl:text>
				</xsl:otherwise>
			</xsl:choose>
		</xsl:when>
		<xsl:otherwise>
			<xsl:text>\index{</xsl:text>
			<xsl:message terminate="no"><xsl:text>Simple case:</xsl:text></xsl:message>
				<xsl:value-of select="normalize-space($idxterm)"/>
			<xsl:text>}</xsl:text>
		</xsl:otherwise>
	</xsl:choose>
</xsl:if>
</xsl:template>


<!-- ================================================ -->
<xsl:template match="*" mode="indexterm">
    <xsl:message>WARNING: Element '<xsl:value-of select="local-name()"/>' in indexterm not supported!</xsl:message>
</xsl:template>



<!-- ================================================ -->
<xsl:template match="primary" mode="indexterm">
<xsl:apply-templates mode="indexterm"/>
</xsl:template>

<xsl:template match="secondary" mode="indexterm">
<xsl:text>!</xsl:text>
<xsl:apply-templates mode="indexterm"/>
</xsl:template>

<xsl:template match="tertiary" mode="indexterm">
<xsl:text>!</xsl:text>
<xsl:apply-templates mode="indexterm"/>
</xsl:template>

<xsl:template match="see|seealso" mode="indexterm">
<xsl:text>|see{</xsl:text>
<xsl:apply-templates mode="indexterm"/>
<xsl:text>} </xsl:text>
</xsl:template>


<!-- ================================================ -->
<!-- A simple example of what can be in an primary,   -->
<!-- secondary or tertiary.                           -->
<!-- ================================================ -->
<xsl:template match="acronym" mode="indexterm">
<xsl:apply-templates mode="indexterm"/>
</xsl:template>


<xsl:template match="primary|secondary|tertiary|see|seealso"/>
<xsl:template match="indexentry"/>
<xsl:template match="primaryie|secondaryie|tertiaryie|seeie|seealsoie"/>

</xsl:stylesheet>
