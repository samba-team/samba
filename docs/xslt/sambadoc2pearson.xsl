<?xml version='1.0'?>
<!-- 
	Convert DocBook to XML validating against the Pearson DTD

	(C) Jelmer Vernooij <jelmer@samba.org>			2004
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:exsl="http://exslt.org/common"
	xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
	exclude-result-prefixes="doc"
	version="1.1" >

	<xsl:import href="docbook2pearson.xsl"/>

	<xsl:template match="smbfile">
		<xsl:apply-templates/>
	</xsl:template>

	<xsl:template match="smbconfexample/smbconfsection">
		<xsl:value-of select="."/><xsl:text>&#10;</xsl:text>
	</xsl:template>

	<xsl:template match="smbconfexample/smbconfoption">
		<xsl:value-of select="name"/><xsl:text> = </xsl:text><xsl:value-of select="value"/><xsl:text>&#10;</xsl:text>
	</xsl:template>

	<xsl:template match="smbconfexample">
	   <listing>
		   <xsl:if test="title != ''">
			   <description><xsl:value-of select="title"/></description>
		   </xsl:if>
		   <listingcode>
			   <xsl:apply-templates/>
		   </listingcode>
		</listing>
	</xsl:template>
</xsl:stylesheet>
