<?xml version='1.0'?>
<!-- 
	DocBook to yodl converter
	Currently only for manpages

	(C) Jelmer Vernooij 					2004
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:exsl="http://exslt.org/common"
	version="1.1">

	<xsl:output method="text" encoding="iso-8859-1" standalone="yes"/>
	<xsl:strip-space elements="*"/>

	<xsl:template match="refentry">
		<xsl:text>manpage(</xsl:text>
		<xsl:value-of select="refmeta/refentrytitle"/>
		<xsl:text>)()(</xsl:text>
		<xsl:value-of select="refmeta/manvolnum"/>
		<xsl:text>)(package)()&#10;</xsl:text>

		<xsl:apply-templates/>
	</xsl:template>

	<xsl:template match="emphasis">
		<xsl:text>em(</xsl:text>
		<xsl:apply-templates/>
		<xsl:text>)</xsl:text>
	</xsl:template>

	<xsl:template match="command">
		<xsl:text>bf(</xsl:text>
		<xsl:apply-templates/>
		<xsl:text>)</xsl:text>
	</xsl:template>

	<xsl:template match="refnamediv">
		<xsl:text>manpagename(</xsl:text>
		<xsl:value-of select="refname"/>
		<xsl:text>)(</xsl:text>
		<xsl:value-of select="refpurpose"/>
		<xsl:text>)&#10;</xsl:text>
	</xsl:template>

	<xsl:template match="refsynopsisdiv">
		manpagesynopsis()
	</xsl:template>

	<xsl:template match="refsect1">
		<xsl:choose>
			<xsl:when test="title='DESCRIPTION'">
				<xsl:text>&#10;manpagedescription()&#10;&#10;</xsl:text>
			</xsl:when>
			<xsl:when test="title='OPTIONS'">
				<xsl:text>&#10;manpageoptions()&#10;&#10;</xsl:text>
			</xsl:when>
			<xsl:when test="title='FILES'">
				<xsl:text>&#10;manpagefiles()&#10;&#10;</xsl:text>
			</xsl:when>
			<xsl:when test="title='SEE ALSO'">
				<xsl:text>&#10;manpageseealso()&#10;&#10;</xsl:text>
			</xsl:when>
			<xsl:when test="title='DIAGNOSTICS'">
				<xsl:text>&#10;manpagediagnostics()&#10;&#10;</xsl:text>
			</xsl:when>
			<xsl:when test="title='BUGS'">
				<xsl:text>&#10;manpagebugs()&#10;&#10;</xsl:text>
			</xsl:when>
			<xsl:when test="title='AUTHOR'">
				<xsl:text>&#10;manpageauthor()&#10;&#10;</xsl:text>
			</xsl:when>
			<xsl:otherwise>
				<xsl:text>&#10;manpagesection(</xsl:text>
				<xsl:value-of select="title"/>
				<xsl:text>)&#10;&#10;</xsl:text>
			</xsl:otherwise>
		</xsl:choose>
		<xsl:for-each select="para">
			<xsl:text>&#10;&#10;</xsl:text>
			<xsl:apply-templates/>
		</xsl:for-each>
	</xsl:template>

	<xsl:template match="itemizedlist|orderedlist">
		<xsl:text>startdit()&#10;</xsl:text>
		<xsl:for-each select="listitem">
			<xsl:text>dit() </xsl:text>
			<xsl:apply-templates/>
			<xsl:text>&#10;</xsl:text>
		</xsl:for-each>
		<xsl:text>enddit()&#10;</xsl:text>
	</xsl:template>

	<xsl:template match="variablelist">
		<xsl:text>startdit()&#10;</xsl:text>
		<xsl:for-each select="varlistentry">
			<xsl:text>dit(</xsl:text>
			<xsl:value-of select="term"/>
			<xsl:text>) </xsl:text>
			<xsl:apply-templates select="listitem"/>
			<xsl:text>&#10;</xsl:text>
		</xsl:for-each>
		<xsl:text>enddit()&#10;</xsl:text>
	</xsl:template>

	<xsl:template match="*"/>

</xsl:stylesheet>
