<?xml version='1.0'?>
<!-- 
	Convert DocBook to XML validating against the Pearson DTD

	(C) Jelmer Vernooij <jelmer@samba.org>			2004
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
	exclude-result-prefixes="doc"
	version="1.1" >

	<xsl:import href="docbook2pearson.xsl"/>

	<xsl:strip-space elements="smbconfoption smbconfsection"/>

	<xsl:template match="smbfile">
		<xsl:apply-templates/>
	</xsl:template>

	<xsl:template match="smbconfexample/smbconfsection|smbconfblock/smbconfsection">
		<xsl:text>&#10;</xsl:text>
		<xsl:value-of select="."/><xsl:text>&#10;</xsl:text>
	</xsl:template>

	<xsl:template match="smbconfexample/smbconfoption|smbconfblock/smbconfoption">
		<xsl:text>	</xsl:text><xsl:value-of select="name"/><xsl:text> = </xsl:text><xsl:value-of select="value"/><xsl:text>&#10;</xsl:text>
	</xsl:template>

	<xsl:template match="smbconfexample">
	   <listing>
		   <xsl:call-template name="transform.id.attribute"/>
		   <xsl:if test="title != ''">
			   <description><xsl:value-of select="title"/></description>
		   </xsl:if>
		   <listingcode>
			   <xsl:for-each select="smbconfoption|smbconfsection|smbconfcomment">
			   	<xsl:apply-templates select="."/>
			   </xsl:for-each>
		   </listingcode>
		</listing>
	</xsl:template>

	<xsl:template match="smbconfblock">
		<xsl:call-template name="transform.id.attribute"/>
		<listingcode>
		<xsl:apply-templates/>
		</listingcode>
	</xsl:template>

	<xsl:template match="image">
		<figure>
			<xsl:call-template name="transform.id.attribute"/>
			<description><xsl:value-of select="imagedescription"/></description>
			<figureref>
				<xsl:attribute name="fileref">
					<xsl:value-of select="imagefile"/>
				</xsl:attribute>
				<xsl:if test="@scale != ''">
					<xsl:attribute name="scale">
						<xsl:value-of select="@scale"/>
					</xsl:attribute>
				</xsl:if>
			</figureref>
		</figure>
	</xsl:template>

	<xsl:template match="smbconfexample/smbconfcomment|smbconfblock/smbconfcomment">
		<xsl:text># </xsl:text><xsl:value-of select="text()"/><xsl:text>&#10;</xsl:text>
	</xsl:template>

	<xsl:template match="smbconfexample/member|smbconfblock/member">
		<xsl:value-of select="text()"/><xsl:text>&#10;</xsl:text>
		<xsl:message><xsl:text>Encountered &lt;member&gt; element inside of smbconfexample/smbconfblock!</xsl:text></xsl:message>
	</xsl:template>

	<xsl:template match="filterline">
		<code><xsl:apply-templates/></code>
	</xsl:template>

	<xsl:template match="smbconfoption">
		<code><xsl:value-of select="name"/></code>
		<xsl:if test="value != ''">
			<xsl:text> = </xsl:text>
			<xsl:value-of select="value"/>
		</xsl:if>
		<xsl:text>&#10;</xsl:text>
	</xsl:template>

	<xsl:template match="smbconfsection">
		<code><xsl:apply-templates/></code>
	</xsl:template>

	<xsl:template match="ntgroup|ntuser">
		<em><xsl:apply-templates/></em>
	</xsl:template>
	<!-- translator -->

</xsl:stylesheet>
