<?xml version='1.0'?>
<!--
	Generate XML file with out of CVS history using cvs2cl
	(C) Jelmer Vernooij 			2004
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:cvs2cl="http://www.red-bean.com/xmlns/cvs2cl/"
	exclude-result-prefixes="cvs2cl"
	version="1.0">

	<xsl:import href="../settings.xsl"/>

	<xsl:output method="xml"/>

	<xsl:template match="cvs2cl:changelog">
		<xsl:element name="revhistory">
			<xsl:for-each select="cvs2cl:entry">
				<xsl:variable name="idx"><xsl:number count="cvs2cl:entry"/></xsl:variable>
				<xsl:if test="not(number($idx)-number($numclentries) > 0)">
					<xsl:call-template name="clentry"/>
				</xsl:if>
			</xsl:for-each>
		</xsl:element>
	</xsl:template>

	<xsl:template name="clentry">
		<xsl:element name="revision">
			<xsl:element name="revnumber">
				<xsl:value-of select="cvs2cl:file/cvs2cl:revision"/>
			</xsl:element>
			<xsl:element name="date">
				<xsl:value-of select="cvs2cl:date"/>
			</xsl:element>
			<xsl:element name="authorinitials">
				<xsl:value-of select="cvs2cl:author"/>
			</xsl:element>
			<xsl:element name="revremark">
				<xsl:value-of select="cvs2cl:msg"/>
			</xsl:element>
		</xsl:element>
	</xsl:template>
</xsl:stylesheet>
