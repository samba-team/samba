<?xml version='1.0'?>
<!DOCTYPE xsl:stylesheet
[
 <!ENTITY % mmlalias PUBLIC "MathML alias" "ent/mmlalias.ent">  %mmlalias;
 <!ENTITY % mmlextra PUBLIC "MathML extra" "ent/mmlextra.ent">  %mmlextra;
]>
<!--############################################################################# 
 |	$Id: mathml.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $		
 |- #############################################################################
 |	$Author: jelmer $
 |														
 |   PURPOSE: MathML presentation and content markup.
 |	Note: these elements are not part of the DocBook DTD. I have extended
 |    the docbook DTD in order to support this tags, so that's why I have these 
 |	templates here.
 |   
 |	MathML namespace used -> mml
 + ############################################################################## -->

<xsl:stylesheet version='1.0'
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
	xmlns:mml="http://www.w3.org/1998/Math/MathML" xmlns="http://www.w3.org/1998/Math/MathML">

<xsl:strip-space elements="mml:math mml:mrow"/>


<xsl:template match="mml:math">
	<xsl:text>\begin{displaymath}</xsl:text>
	<xsl:apply-templates/>
	<xsl:text>\end{displaymath}</xsl:text>
</xsl:template>

<xsl:template match="mml:math[@mode='inline']">
	<xsl:text> \begin{math} </xsl:text>
	<xsl:apply-templates/>
	<xsl:text> \end{math} </xsl:text>
</xsl:template>

<xsl:template match="mml:math[@mode='display']">
	<xsl:text>\begin{displaymath}</xsl:text>
	<xsl:apply-templates/>
	<xsl:text>\end{displaymath}</xsl:text>
</xsl:template>


<xsl:template match="p">
	<xsl:text>\section{</xsl:text> <xsl:value-of select="normalize-space(.)"/> <xsl:text>}</xsl:text>
</xsl:template>


</xsl:stylesheet>
