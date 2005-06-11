<?xml version='1.0'?>
<!-- Removes particular (unuseful for the book) elements from references -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	version="1.1">
	<xsl:template match="reference/refentry/refsect1">
		<xsl:if test="title!='VERSION' and title!='AUTHOR'">
			<xsl:element name="refsect1">
				<xsl:if test="@id!=''">
					<xsl:attribute name="id">
						<xsl:value-of select="@id"/>
					</xsl:attribute>
				</xsl:if>
				<xsl:apply-templates/>			
			</xsl:element>
		</xsl:if>
	</xsl:template>

	<xsl:template match="reference/refentry">
		<xsl:element name="section">
			<xsl:attribute name="id">
				<xsl:value-of select="@id"/>
			</xsl:attribute>
			<xsl:element name="title">
				<xsl:value-of select="refmeta/refentrytitle"/>
			</xsl:element>
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="reference/refentry/refmeta"/>

	<xsl:template match="reference/refentry/refnamediv"/>

	<xsl:template match="reference">
		<xsl:element name="appendix">
			<xsl:attribute name="id">
				<xsl:value-of select="@id"/>
			</xsl:attribute>
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>
</xsl:stylesheet>
