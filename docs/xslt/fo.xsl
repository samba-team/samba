<?xml version='1.0'?>
<!-- vim:set sts=2 shiftwidth=2 syntax=xml: -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version='1.0'>

<xsl:import href="../settings.xsl"/>
<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/fo/docbook.xsl"/>

<xsl:param name="paper.type">
  <xsl:choose>
	<xsl:when test="$papersize = 'a4paper'">
	  <xsl:text>A4</xsl:text>
	</xsl:when>
	<xsl:when test="$papersize = 'letter'">
	  <xsl:text>USletter</xsl:text>
	</xsl:when>
  </xsl:choose>
</xsl:param>


</xsl:stylesheet>
