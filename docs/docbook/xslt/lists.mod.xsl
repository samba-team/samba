<?xml version='1.0'?>
<!--############################################################################# 
|- #############################################################################
|														
|   PURPOSE:
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>


    <xsl:template match="simplelist">
	<xsl:if test="title"> <xsl:apply-templates select="title"/></xsl:if>
	<xsl:text>&#10;\begin{itemize}&#10;</xsl:text>
	<xsl:apply-templates select="member"/>
	<xsl:text>&#10;\end{itemize}&#10;</xsl:text>
    </xsl:template>


    <xsl:template match="member">
	<xsl:text>&#10;%--- Item&#10;</xsl:text>
	<xsl:text>\item[] </xsl:text>
	<xsl:apply-templates/>
	<xsl:text>&#10;</xsl:text>
    </xsl:template>

</xsl:stylesheet>
