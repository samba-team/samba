<?xml version='1.0'?>
<!-- vim:set sts=2 shiftwidth=2 syntax=xml: -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:exsl="http://exslt.org/common"
                xmlns:samba="http://samba.org/common"
		version="1.1"
                extension-element-prefixes="exsl">

<xsl:output method="xml"/>

<!-- Generates one big XML file for smb.conf -->

<xsl:param name="xmlSambaNsUri" select="'http://samba.org/common'"/>

<!-- This is needed to copy content unchanged -->
<xsl:template match="@*|node()">
  <xsl:copy>
    <xsl:apply-templates select="@*|node()"/>
  </xsl:copy>
</xsl:template>


<xsl:template match="//samba:parameter">
  <!-- reconstruct varlistentry - not all of them will go into separate files
       and also we must repair the main varlistentry itself.
  -->
      <xsl:message>
        <xsl:text>Processing samba:parameter (</xsl:text>
        <xsl:value-of select="@name"/>
        <xsl:text>)</xsl:text>
      </xsl:message>

  <xsl:variable name="name"><xsl:value-of select="translate(translate(string(@name),' ',''),
                  'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
  </xsl:variable>
  
  <xsl:variable name="anchor">
     <xsl:element name="anchor">
        <xsl:attribute name="id">
          <xsl:value-of select="$name"/>
        </xsl:attribute>
     </xsl:element>
  </xsl:variable>

  <xsl:variable name="context">
     <xsl:text> (</xsl:text>
     <xsl:value-of select="@context"/>
     <xsl:text>)</xsl:text>
  </xsl:variable>

  <xsl:variable name="term">
     <xsl:element name="term">
          <xsl:copy-of select="$anchor"/>
          <xsl:value-of select="@name"/>
          <xsl:value-of select="$context"/>
     </xsl:element>
  </xsl:variable>

  <xsl:variable name="content">
       <xsl:apply-templates/>
  </xsl:variable>
  
  <xsl:element name="varlistentry">
     <xsl:text>
</xsl:text>     
     <xsl:copy-of select="$term"/>
     <xsl:copy-of select="$content"/>
     <xsl:text>
</xsl:text>     
  </xsl:element>

</xsl:template>

</xsl:stylesheet>
