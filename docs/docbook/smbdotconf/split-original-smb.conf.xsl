<?xml version='1.0'?>
<!-- vim:set sts=2 shiftwidth=2 syntax=xml: -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:exsl="http://exslt.org/common"
                xmlns:samba="http://samba.org/common"
		version="1.1"
                extension-element-prefixes="exsl">

<xsl:output method="xml"/>

<xsl:param name="output.dir.name" select="'test/'"/>

<!-- This is needed to copy content unchanged -->
<xsl:template match="@*|node()">
  <xsl:copy>
    <xsl:apply-templates select="@*|node()"/>
  </xsl:copy>
</xsl:template>

<!-- Parse all varlistentries and extract those of them which are descriptions of smb.conf
     parameters. We determine them by existence of <anchor> element inside <term> element.
     If <anchor> is there, then its 'id' attribute is translated to lower case and is used
     as basis for file name for that parameter.
-->
<xsl:template match="varlistentry">
  <xsl:variable name="output.dir.name" select="$output.dir.name"/>
  <!-- Extract anchor's 'id' and translate it to lower case -->
  <xsl:variable name="fname">
        <xsl:value-of select="translate(string(term/anchor/@id),
                'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')"/>
  </xsl:variable>
  <!-- reconstruct varlistentry - not all of them will go into separate files
       and also we must repair the main varlistentry itself.
  -->
  <xsl:variable name="content">
       <xsl:apply-templates/>
  </xsl:variable>
  <!-- Now put varlistentry into separate file _if_ it has anchor associated with it -->
  <xsl:choose>
    <xsl:when test="$fname != ''">
      <!-- full file name -->
      <xsl:variable name="filename"><xsl:value-of select="$output.dir.name"/><xsl:value-of select="$fname"/>.xml</xsl:variable>
      <!-- Debug message for an operator, just to show progress of processing :) -->
      <xsl:message>
        <xsl:text>Writing </xsl:text>
        <xsl:value-of select="$filename"/>
        <xsl:text> for </xsl:text>
        <xsl:value-of select="name(.)"/>
        <xsl:if test="term/anchor/@id">
          <xsl:text>(</xsl:text>
          <xsl:value-of select="term/anchor/@id"/>
          <xsl:text>)</xsl:text>
        </xsl:if>
      </xsl:message>
      <!-- Write finally varlistentry to a separate file -->
      <exsl:document href="{$filename}" 
                   method="xml" 
                   encoding="UTF-8" 
                   indent="yes"
                   omit-xml-declaration="yes">
        <xsl:element name="samba:parameter">
           <xsl:copy-of select="$content"/>
        </xsl:element>
      </exsl:document>
      <xsl:text disable-output-escaping="yes">&amp;smb.</xsl:text>
      <xsl:value-of select="$fname"/>
      <xsl:text>;</xsl:text>
    </xsl:when>
   <!-- this was a varlistentry w/o anchor associated, just dump it to the main document -->
  <xsl:otherwise>
    <xsl:element name="varlistentry">
      <xsl:copy-of select="$content"/>
    </xsl:element>
  </xsl:otherwise>
  </xsl:choose>
</xsl:template>

</xsl:stylesheet>
