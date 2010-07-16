<?xml version="1.0"?>

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version="1.0">
 <xsl:output method="text"/>
 <xsl:strip-space elements="*"/>

 <xsl:template match="/">
  <xsl:apply-templates select="article"/>
 </xsl:template>

 <xsl:template match="article">
  <xsl:apply-templates select="section"/><xsl:text>
</xsl:text>
 </xsl:template>

 <xsl:template match="section">
  <xsl:apply-templates select="title|para|cmdsynopsis|section"/>
 </xsl:template>

 <xsl:template match="title">
  <xsl:apply-templates/><xsl:text>
</xsl:text>
 </xsl:template>

 <xsl:template match="subtitle">
  <xsl:apply-templates/><xsl:text>
</xsl:text>
 </xsl:template>

 <xsl:template match="command|filename|varname|computeroutput|constant">
  <xsl:apply-templates/>
 </xsl:template>

 <xsl:template match="option">
  <xsl:apply-templates/>
 </xsl:template>

 <xsl:template match="screen">
  <xsl:text>
</xsl:text><xsl:apply-templates/><xsl:text>
</xsl:text>
 </xsl:template>


 <xsl:template match="arg">
  <xsl:choose>
   <xsl:when test="@choice='opt'">
    <xsl:text> [</xsl:text><xsl:apply-templates/><xsl:text>]</xsl:text>
   </xsl:when>
   <xsl:otherwise>
    <xsl:text> </xsl:text><xsl:apply-templates/>
   </xsl:otherwise>
  </xsl:choose>
 </xsl:template>

 <xsl:template match="para">
  <xsl:text>
</xsl:text>
<xsl:apply-templates/><xsl:text>
</xsl:text>
</xsl:template>

 <xsl:template match="cmdsynopsis">
  <xsl:text>
</xsl:text>
  <xsl:apply-templates select="command|sbr|arg"/><xsl:text>
</xsl:text>
 </xsl:template>

 <xsl:template match="synopfragmentref">
  <xsl:variable name="target" select="id(@linkend)"/>
  <xsl:apply-templates select="$target"/>
 </xsl:template>

 <xsl:template match="synopfragment">
  <xsl:apply-templates/>
 </xsl:template>

 <xsl:template match="group">
  <xsl:text>{ </xsl:text><xsl:for-each select="arg">
   <xsl:apply-templates/>
   <xsl:if test="position() != last()"><xsl:text> | </xsl:text></xsl:if>
  </xsl:for-each><xsl:text> }</xsl:text>
 </xsl:template>


 <xsl:template match="replaceable">{<xsl:apply-templates/>}</xsl:template>


 <xsl:template match="sbr">
  <xsl:text>
</xsl:text>
</xsl:template>

 <xsl:template match="text()"><xsl:value-of select="."/></xsl:template>

 <xsl:template match="node()">
  <xsl:message terminate="yes">Unknown node <xsl:value-of select="name()"/>
</xsl:message>
 </xsl:template>

 <xsl:template match="simplelist">
  <xsl:for-each select="member">
   <xsl:apply-templates/>
   <xsl:if test="position() != last()"><xsl:text>, </xsl:text></xsl:if>
  </xsl:for-each>
 </xsl:template>


</xsl:stylesheet>
