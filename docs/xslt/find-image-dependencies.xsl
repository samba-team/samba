<?xml version='1.0'?>
<!--
	Find the image dependencies of a certain XML file
	(C) Jelmer Vernooij	2004
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.1">
	<xsl:output method="text"/>

	<xsl:template match="mediaobject/imageobject[@role=$role]">
		<xsl:value-of select="$prepend"/>
		<xsl:value-of select="imagedata/@fileref"/>
		<xsl:value-of select="$append"/>
		<xsl:text> </xsl:text>
	</xsl:template>

	<xsl:template match="text()"/>
	<xsl:template match="*">
		<xsl:apply-templates/>
	</xsl:template>
</xsl:stylesheet>
