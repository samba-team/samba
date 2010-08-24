<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version="1.0">
 <xsl:output method="text"/>
 <xsl:strip-space elements="*"/>
 <xsl:include href="text.xsl"/>

 <xsl:template match="section">
  <xsl:apply-templates select="title"/>
  <xsl:text>    </xsl:text><xsl:apply-templates select="subtitle"/>
 </xsl:template>

 <xsl:template match="para">
  <xsl:apply-templates/>
 </xsl:template>

</xsl:stylesheet>
