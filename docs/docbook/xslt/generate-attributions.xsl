<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:exsl="http://exslt.org/common"
                xmlns:samba="http://samba.org/common"
				version="1.1"
                extension-element-prefixes="exsl">

<xsl:output method="xml" omit-xml-declaration="yes"/>

<!-- Remove all character data -->
<xsl:template match="@*|node()">
   <xsl:apply-templates select="@*|node()"/>
</xsl:template>

<xsl:template match="chapter">
	<xsl:choose>
		<xsl:when test="chapterinfo/author != ''">
			<xsl:element name="para">
				<xsl:element name="link">
					<xsl:attribute name="linkend"><xsl:value-of select="@id"/></xsl:attribute>
					<xsl:value-of select="title"/>
				</xsl:element>
				<xsl:element name="itemizedlist">
					<xsl:apply-templates/>
				</xsl:element>
			</xsl:element>
		</xsl:when>
	</xsl:choose>
</xsl:template>

<xsl:template match="author">
	<xsl:element name="listitem">
		<xsl:element name="para">
			<xsl:value-of select="firstname"/>
			<xsl:if test="othername != ''">
				<xsl:text> </xsl:text>
				<xsl:value-of select="othername"/>
				<xsl:text> </xsl:text>
			</xsl:if>
			<xsl:text> </xsl:text><xsl:value-of select="surname"/>
			<xsl:choose>
				<xsl:when test="affiliation/address/email != ''">
					<xsl:text> &lt;</xsl:text>
					<xsl:element name="ulink">
						<xsl:attribute name="noescape">
						<xsl:text>1</xsl:text>
						</xsl:attribute>
						<xsl:attribute name="url">
							<xsl:text>mailto:</xsl:text>
							<xsl:value-of select="affiliation/address/email"/>
						</xsl:attribute>
						<xsl:value-of select="affiliation/address/email"/>
					</xsl:element>
					<xsl:text>&gt;</xsl:text>
				</xsl:when>
			</xsl:choose>
			<xsl:choose>
				<xsl:when test="contrib != ''">
					<xsl:text> (</xsl:text>
						<xsl:value-of select="contrib"/>
					<xsl:text>) </xsl:text>
					</xsl:when>
			</xsl:choose>
		</xsl:element>
	</xsl:element>
	<xsl:text>
	</xsl:text>
</xsl:template>

</xsl:stylesheet>
