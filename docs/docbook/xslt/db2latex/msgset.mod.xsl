<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>
    <!--############################################################################# 
    |	$Id: msgset.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
    |- #############################################################################
    |	$Author: jelmer $
    |														
    |   PURPOSE:
    + ############################################################################## -->


    <xsl:template match="msgset">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="msgentry">
	<xsl:call-template name="block.object"/>
    </xsl:template>

    <xsl:template match="simplemsgentry">
	<xsl:call-template name="block.object"/>
    </xsl:template>

    <xsl:template match="msg">
	<xsl:call-template name="block.object"/>
    </xsl:template>

    <xsl:template match="msgmain">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="msgmain/title">
	<b><xsl:apply-templates/></b>
    </xsl:template>

    <xsl:template match="msgsub">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="msgsub/title">
	<b><xsl:apply-templates/></b>
    </xsl:template>

    <xsl:template match="msgrel">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="msgrel/title">
	<b><xsl:apply-templates/></b>
    </xsl:template>

    <xsl:template match="msgtext">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="msginfo">
	<xsl:call-template name="block.object"/>
    </xsl:template>

    <xsl:template match="msglevel|msgorig|msgaud">
	<p>
	    <b>
		<xsl:call-template name="gentext.element.name"/>
		<xsl:text>: </xsl:text>
	    </b>
	    <xsl:apply-templates/>
	</p>
    </xsl:template>

    <xsl:template match="msgexplan">
	<xsl:call-template name="block.object"/>
    </xsl:template>

    <xsl:template match="msgexplan/title">
	<xsl:apply-templates/>
    </xsl:template>

</xsl:stylesheet>
