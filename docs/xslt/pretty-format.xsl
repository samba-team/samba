<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:samba="http://samba.org/common"
	version="1.1">
	
	<xsl:output method="xml" encoding="UTF-8" doctype-public="-//OASIS//DTD DocBook XML V4.2//EN" indent="yes" doctype-system="http://www.oasis-open.org/docbook/xml/4.2/docbookx.dtd"/>

	<!-- This is needed to copy content unchanged -->
	<xsl:template match="@*|node()|processing-instruction()">
		<xsl:copy>
			<xsl:apply-templates select="@*|node()|processing-instruction()"/>
		</xsl:copy>
	</xsl:template>

</xsl:stylesheet>
