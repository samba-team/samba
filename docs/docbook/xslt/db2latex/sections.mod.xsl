<?xml version='1.0'?>
<!--############################################################################# 
|- #############################################################################
|														
|   PURPOSE: sections.
|   PENDING:
|	- Nested section|simplesect > 3 mapped to subsubsection*
|    - No sectinfo (!)
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="sections" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
	    </releaseinfo>
	<authogroup>
	    <author> <firstname>Ramon</firstname> <surname>Casellas</surname> </author>
	    <author> <firstname>James</firstname> <surname>Devenish</surname> </author>
	</authogroup>
	    <copyright>
		<year>2000</year> <year>2001</year> <year>2002</year> <year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>

	<title>Sections <filename>sections.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>





    <xsl:template match="sect1|sect2|sect3|sect4|sect5">
	<xsl:call-template name="map.begin"/>
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="sect1/title"/>
    <xsl:template match="sect2/title"/>
    <xsl:template match="sect3/title"/>
    <xsl:template match="sect4/title"/>
    <xsl:template match="sect5/title"/>


    <xsl:template match="section">
	<xsl:text>&#10;</xsl:text>
	<xsl:variable name="level" select="count(ancestor::section)+1"/>
	<xsl:choose>
	    <xsl:when test='$level=1'>
		<xsl:call-template name="map.begin">
		    <xsl:with-param name="keyword" select="'sect1'"/>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test='$level=2'>
		<xsl:call-template name="map.begin">
		    <xsl:with-param name="keyword" select="'sect2'"/>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test='$level=3'>
		<xsl:call-template name="map.begin">
		    <xsl:with-param name="keyword" select="'sect3'"/>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test='$level=4'>
		<xsl:call-template name="map.begin">
		    <xsl:with-param name="keyword" select="'sect4'"/>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test='$level=5'>
		<xsl:call-template name="map.begin">
		    <xsl:with-param name="keyword" select="'sect5'"/>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:otherwise> 
		<xsl:message>DB2LaTeX: recursive section|simplesect &gt; 5 Not  well Supported</xsl:message> 
		<xsl:call-template name="map.begin">
		    <xsl:with-param name="keyword" select="'sect6'"/>
		</xsl:call-template>
	    </xsl:otherwise>
	</xsl:choose>
	<xsl:apply-templates/>
    </xsl:template>


    <xsl:template match="simplesect">
	<xsl:text>&#10;</xsl:text>
	<xsl:variable name="level" select="count(ancestor::section) + 1"/>
	<xsl:choose>
	    <xsl:when test='$level=1'>
		<xsl:call-template name="map.begin">
		    <xsl:with-param name="keyword" select="'sect1'"/>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test='$level=2'>
		<xsl:call-template name="map.begin">
		    <xsl:with-param name="keyword" select="'sect2'"/>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test='$level=3'>
		<xsl:call-template name="map.begin">
		    <xsl:with-param name="keyword" select="'sect3'"/>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test='$level=4'>
		<xsl:call-template name="map.begin">
		    <xsl:with-param name="keyword" select="'sect4'"/>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:when test='$level=5'>
		<xsl:call-template name="map.begin">
		    <xsl:with-param name="keyword" select="'sect5'"/>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:otherwise> 
		<xsl:message>DB2LaTeX: recursive section|simplesect &gt; 5 Not  well Supported</xsl:message> 
		<xsl:call-template name="map.begin">
		    <xsl:with-param name="keyword" select="'sect6'"/>
		</xsl:call-template>
	    </xsl:otherwise>
	</xsl:choose>
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="section/title"/>
    <xsl:template match="simplesect/title"/>

    <xsl:template match="sectioninfo"/>
    <xsl:template match="sect1info"/>
    <xsl:template match="sect2info"/>
    <xsl:template match="sect3info"/>
    <xsl:template match="sect4info"/>
    <xsl:template match="sect5info"/>

</xsl:stylesheet>
