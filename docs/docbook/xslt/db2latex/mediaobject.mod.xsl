<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: mediaobject.mod.xsl,v 1.1.2.1 2003/05/01 14:06:15 jelmer Exp $
|- #############################################################################
|	$Author: jelmer $												
|														
|   PURPOSE: Manage Imageobject related tags.
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="mediaobject" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: mediaobject.mod.xsl,v 1.1.2.1 2003/05/01 14:06:15 jelmer Exp $
	    </releaseinfo>
	<authorgroup>
	    <author> <firstname>Ramon</firstname> <surname>Casellas</surname> </author>
	    <author> <firstname>James</firstname> <surname>Devenish</surname> </author>
	</authorgroup>
	    <copyright>
		<year>2000</year> <year>2001</year> <year>2002</year> <year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>

	<title>MediaObjects <filename>mediaobject.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>



    <xsl:template match="videoobject">
	<xsl:apply-templates select="videodata"/>
    </xsl:template>
    <xsl:template match="audioobject">
	<xsl:apply-templates select="audiodata"/>
    </xsl:template>
    <xsl:template match="textobject">
	<!-- TODO if mixed in with imageobjects, use subfigure (if appropriate) -->
	<xsl:apply-templates/>
    </xsl:template>


    <xsl:template match="mediaobject">
		<xsl:if test="local-name(preceding-sibling::*[1])!='mediaobject'">
			<xsl:text>&#10;</xsl:text>
		</xsl:if>
		<xsl:call-template name="mediacontent"/>
		<xsl:text>&#10;</xsl:text>
	</xsl:template>

    <xsl:template match="inlinemediaobject">
		<xsl:call-template name="mediacontent"/>
	</xsl:template>

    <xsl:template name="mediacontent">
	<xsl:choose>
		<xsl:when test="count(imageobject)&lt;1">
			<xsl:apply-templates select="textobject[1]"/>
		</xsl:when>
		<xsl:when test="$use.role.for.mediaobject='1' and $preferred.mediaobject.role!='' and count(imageobject[@role='$preferred.mediaobject.role'])!=0">
			<xsl:apply-templates select="imageobject[@role=$preferred.mediaobject.role]"/>
		</xsl:when>
		<xsl:when test="$use.role.for.mediaobject='1' and count(imageobject[@role='latex'])!=0">
			<xsl:apply-templates select="imageobject[@role='latex']"/>
		</xsl:when>
		<xsl:when test="$use.role.for.mediaobject='1' and count(imageobject[@role='tex'])!=0">
			<xsl:apply-templates select="imageobject[@role='tex']"/>
		</xsl:when>
		<xsl:when test="$latex.graphics.formats!='' and count(imageobject/imagedata[@format!=''])!=0">
			<!-- this is not really the right method: formats to the left of $latex.graphics.formats
			should be given higher 'priority' than those to the right in a command-separated list -->
			<xsl:variable name="formats" select="concat(',',$latex.graphics.formats,',')"/>
			<xsl:variable name="candidates" select="imageobject/imagedata[contains($formats,concat(',',@format,','))]"/>
			<xsl:choose>
				<xsl:when test="count($candidates)!=0">
					<xsl:apply-templates select="$candidates[1]"/>
				</xsl:when>
				<xsl:otherwise>
					<xsl:variable name="fallbacks" select="imageobject/imagedata[@format='']"/>
					<xsl:choose>
						<xsl:when test="count($fallbacks)!=0">
							<xsl:apply-templates select="$fallbacks[1]"/>
						</xsl:when>
						<xsl:when test="count(textobject)!=0">
							<xsl:apply-templates select="textobject[1]"/>
						</xsl:when>
						<xsl:otherwise>
							<xsl:apply-templates select="imageobject[1]"/>
						</xsl:otherwise>
					</xsl:choose>
				</xsl:otherwise>
			</xsl:choose>
		</xsl:when>
		<xsl:otherwise>
			<xsl:apply-templates select="imageobject[1]"/>
		</xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template match="imageobject">
	<xsl:apply-templates select="imagedata"/>
    </xsl:template>








    <!--############################################################################# -->
    <!-- DOCUMENTATION -->
    <doc:template match="imagedata" xmlns="">
	<refpurpose>XSL template for images.</refpurpose>
	<refdescription>
	    <para></para>
	    <formalpara><title>Remarks and Bugs</title>
		<itemizedlist>
			<listitem><para>If both <literal>@width</literal> and <literal>@scale</literal> are given but <literal>@scalefit='0'</literal>, whitespace is added to the left and right in order to match the specified width.</para></listitem>
			<listitem><para>If <literal>@width</literal> is given and either <literal>@scalefit=1</literal> or no <literal>@scale</literal> is given, then the image is scale to <literal>@width</literal>. Otherwise, <literal>@scale</literal> is used, if it is present.</para></listitem>
			<listitem><para>If this is not the only <literal>imagedata</literal> within the figure, this will be rendered as a 'subfigure', including the <literal>caption</literal> of its enclosing <literal>mediaobject</literal>.</para></listitem>
		</itemizedlist>
	    </formalpara>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->
    <xsl:template match="imagedata">
	<xsl:variable name="filename" select="@fileref"/>
	<xsl:variable name="ext">
	    <xsl:call-template name="filename-extension">
		<xsl:with-param name="filename" select="$filename"/>
	    </xsl:call-template>
	</xsl:variable>
	<xsl:variable name="imageobjectscnt" select="count(../../..//imageobject)"/>
	<xsl:variable name="width">
	    <xsl:choose>
		<xsl:when test="contains(@width, '%') and substring-after(@width, '%')=''">
		    <xsl:value-of select="number(substring-before(@width, '%')) div 100"/>
		    <xsl:text>\textwidth</xsl:text>
		</xsl:when>
		<xsl:otherwise>
		    <xsl:value-of select="@width"/>
		</xsl:otherwise>
	    </xsl:choose>
	</xsl:variable>
	<xsl:if test="$width!='' and (@scalefit='0' or count(@scale)&gt;0)">
		<xsl:text>\makebox[</xsl:text><xsl:value-of select='$width' /><xsl:text>]</xsl:text>
	</xsl:if>
	<xsl:text>{</xsl:text>
	<!-- TODO this logic actually needs to make decisions based on the ALLOWED imagedata,
	not all the imagedata present in the source file. -->
	<xsl:if test="$imageobjectscnt &gt; 1 and $latex.use.subfigure='1' and count(ancestor::figure) &gt; 0">
	    <xsl:text>\subfigure[</xsl:text>
		<xsl:if test="count(../../..//caption)&gt;1">
			<xsl:value-of select="../../caption"/>
		</xsl:if>
		<xsl:text>]</xsl:text>
	</xsl:if>
	<xsl:text>{\includegraphics[</xsl:text>
	<xsl:choose>
	    <xsl:when test="@scale"> 
		<xsl:text>scale=</xsl:text>
		<xsl:value-of select="number(@scale) div 100"/>
	    </xsl:when>
		<xsl:when test="$width!='' and @scalefit='1'">
		<xsl:text>width=</xsl:text><xsl:value-of select="normalize-space($width)"/>
		</xsl:when>
		<xsl:when test="@depth!='' and @scalefit='1'">
		<xsl:text>height=</xsl:text><xsl:value-of select="normalize-space(@depth)"/>
		</xsl:when>
	</xsl:choose>
	<xsl:choose>
	    <xsl:when test="@format = 'PRN'"><xsl:text>,angle=270</xsl:text></xsl:when>
	</xsl:choose>
	<xsl:text>]{</xsl:text>
	<xsl:choose><!-- package graphicx and DeclareGraphicExtensions will take care of this -->
	    <xsl:when test="$ext != ''">
		<xsl:value-of select="$filename"/>
	    </xsl:when>
	    <xsl:otherwise> 
		<xsl:value-of select="$filename"/>
	    </xsl:otherwise>
	</xsl:choose>
	<xsl:text>}}}</xsl:text>
    </xsl:template>



    <xsl:template match="videodata">
	<xsl:variable name="filename">
	    <xsl:call-template name="mediaobject.filename"><xsl:with-param name="object" select=".."/>
	    </xsl:call-template>
	</xsl:variable>
	<xsl:variable name="alt">
	    <xsl:apply-templates select="(../../textobject/phrase)[1]"/>
	</xsl:variable>
    </xsl:template>

    <xsl:template match="audiodata">
	<xsl:variable name="filename">
	    <xsl:call-template name="mediaobject.filename"><xsl:with-param name="object" select=".."/>
	    </xsl:call-template>
	</xsl:variable>
	<xsl:variable name="alt">
	    <xsl:apply-templates select="(../../textobject/phrase)[1]"/>
	</xsl:variable>
    </xsl:template>


    <xsl:template match="caption">
	<xsl:apply-templates/>
    </xsl:template>

</xsl:stylesheet>
