<?xml version='1.0'?>
<!-- 
	Convert DocBook to XML validating against the Pearson DTD
	Published under the GNU GPL

	(C) Jelmer Vernooij <jelmer@samba.org>			2004
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:exsl="http://exslt.org/common"
	version="1.1"
	extension-element-prefixes="exsl">

	<xsl:import href="../settings.xsl"/>

	<xsl:output method="xml" indent="yes" encoding="UTF-8" doctype-public="-//Pearson//DTD Books//DE" doctype-system="../../Xml_dtd_1.1/pearson.dtd"/>

	<xsl:template match="book">
		<xsl:element name="book">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="authorgroup">
		<xsl:apply-templates/>
	</xsl:template>

	<xsl:template match="pubdate">
		<xsl:element name="publdate">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="para">
		<xsl:element name="p">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="ulink">
		<xsl:element name="url">
			<xsl:value-of select="@ulink"/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="glossentry">
		<xsl:element name="glossitem">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="glossterm">
		<xsl:element name="term">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="itemizedlist">
		<xsl:element name="ul">
			<xsl:for-each select="listitem">
				<xsl:element name="li">
					<xsl:apply-templates/>
				</xsl:element>
			</xsl:for-each>
		</xsl:element>
	</xsl:template>

	<xsl:template match="emphasis">
		<xsl:element name="em">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="link">
		<xsl:element name="xref">
			<xsl:attribute name="linkend"><xsl:value-of select="@linkend"/></xsl:attribute>
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>
	
	<xsl:template match="acronym"/>
	
	<xsl:template match="glossdef/para">
		<xsl:element name="glosspara">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="author">
		<xsl:element name="author">
			<xsl:value-of select="firstname"/><xsl:text> </xsl:text><xsl:value-of select="surname"/>
		</xsl:element>
	</xsl:template>
	
	<xsl:template match="editor">
		<xsl:element name="editor">
			<xsl:value-of select="firstname"/><xsl:text> </xsl:text><xsl:value-of select="surname"/>
		</xsl:element>
	</xsl:template>



	<xsl:template match="@*|node()">
		<xsl:copy>
			<xsl:apply-templates select="@*|node()"/>
		</xsl:copy>
	</xsl:template>

</xsl:stylesheet>
