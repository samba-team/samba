<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: normalize-scape.mod.xsl,v 1.1 2003/12/05 06:53:48 ab Exp $
|- #############################################################################
|	$Author: ab $
|														
|   PURPOSE:
|	Escape LaTeX and normalize-space templates.
|    < > # $ % & ~ _ ^ \ { } |
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    xmlns:exsl="http://exslt.org/common" 
    exclude-result-prefixes="doc"
    extension-element-prefixes="exsl"
    version='1.0'>


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="normalize-scape" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: normalize-scape.mod.xsl,v 1.1 2003/12/05 06:53:48 ab Exp $
	    </releaseinfo>
	<authorgroup>
	    <author> <firstname>Ramon</firstname> <surname>Casellas</surname> </author>
	    <author> <firstname>James</firstname> <surname>Devenish</surname> </author>
	</authorgroup>
	    <copyright><year>2000</year><year>2001</year><year>2002</year><year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>
	<title>Normalize and Scape strings.</title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>
    <!--############################################################################# -->

  <xsl:key name="character" match="character" use="unicode"/>
  <xsl:param name="unicode.mapping.local" select="''"/>
  <xsl:param name="unicode.mapping.default" select="'unicode.mapping.xml'"/>
  <xsl:param name="unicode.mapping.languages" select="''"/>
  <xsl:variable name="unicode.mapping.sources">
    <xsl:if test="not(function-available('exsl:node-set'))">
      <xsl:message terminate="yes">
        <xsl:text>Error: this style requires support for extension 'exsl:node-set()'</xsl:text>
      </xsl:message>
    </xsl:if>
    <file><xsl:value-of select="$unicode.mapping.local"/></file>
    <xsl:call-template name="parse.unicode.mapping.languages">
      <xsl:with-param name="languages" select="$unicode.mapping.languages"/>
    </xsl:call-template>
    <file><xsl:value-of select="$unicode.mapping.default"/></file>
  </xsl:variable>

  <xsl:variable name="unicode.mapping.database" select="document(exsl:node-set($unicode.mapping.sources)/file,document(''))/mapping"/>

  <xsl:template name="parse.unicode.mapping.languages">
    <xsl:param name="languages"/>
    <xsl:if test="contains($languages,' ')">
      <xsl:variable name="unicode.mapping.lang.file" select="concat('unicode.mapping.',substring-before($languages,' '),'.xml')"/>
      <xsl:if test="document($unicode.mapping.lang.file)">
        <file><xsl:value-of select="$unicode.mapping.lang.file"/></file>
      </xsl:if>
      <xsl:call-template name="parse.unicode.mapping.languages">
        <xsl:with-param name="languages" select="substring-after($languages,' ')"/>
      </xsl:call-template>
    </xsl:if>
    <xsl:if test="not(string-length($languages)=0)">
      <xsl:variable name="unicode.mapping.lang.file" select="concat('unicode.mapping.',$languages,'.xml')"/>
      <xsl:if test="document($unicode.mapping.lang.file)">
        <file><xsl:value-of select="$unicode.mapping.lang.file"/></file>
      </xsl:if>
    </xsl:if>
  </xsl:template>

  <xsl:template name="scape">
    <xsl:param name="string"/>
    <xsl:if test="not(string-length($string)=0)">
      <xsl:variable name="char" select="substring($string,1,1)"/>
      <xsl:variable name="preferred">
        <xsl:for-each select="$unicode.mapping.database">
          <preferred><xsl:value-of select="key('character',$char)/preferred"/></preferred>
        </xsl:for-each>
      </xsl:variable>
      <xsl:choose>
        <!-- Do not optimize it to variable calculation. I already test it for speed with xsltproc :) -->
        <xsl:when test="exsl:node-set($preferred)/preferred[not(string-length(.)=0)][1]">
          <xsl:value-of select="exsl:node-set($preferred)/preferred[not(string-length(.)=0)][1]"/>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="$char"/>
        </xsl:otherwise>
      </xsl:choose>
      <xsl:call-template name="scape">
        <xsl:with-param name="string" select="substring($string,2)"/>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <xsl:template name="scape-href">
    <xsl:param name="string"/>
    <xsl:call-template name="scape">
      <xsl:with-param name="string" select="$string"/>
    </xsl:call-template>
  </xsl:template>

 <xsl:template name="scape-verbatim">
    <xsl:param name="string"/>
    <xsl:call-template name="scape">
      <xsl:with-param name="string" select="$string"/>
    </xsl:call-template>
  </xsl:template>

  <xsl:template name="scape.slash.hyphen">
    <xsl:param name="string"/>
    <xsl:call-template name="scape">
      <xsl:with-param name="string" select="$string"/>
    </xsl:call-template>
  </xsl:template>

  <xsl:template name="scape-url">
    <xsl:param name="string"/>
    <xsl:call-template name="scape">
      <xsl:with-param name="string" select="$string"/>
    </xsl:call-template>
  </xsl:template>

  <xsl:template match="example">
    <xsl:variable name="placement">
      <xsl:call-template name="generate.formal.title.placement">
        <xsl:with-param name="object" select="local-name(.)" />
      </xsl:call-template>
    </xsl:variable>
    <xsl:variable name="caption">
      <xsl:text>{</xsl:text>
      <xsl:value-of select="$latex.example.caption.style"/>
      <xsl:text>{\caption{</xsl:text>
      <!-- WARNING: do not scape if title output already scaped by original title parsing -->
      <xsl:call-template name="scape">
        <xsl:with-param name="string">
          <xsl:apply-templates select="title" mode="caption.mode"/>
        </xsl:with-param>
      </xsl:call-template>
      <xsl:text>}</xsl:text>
      <xsl:text>}}&#10;</xsl:text>
    </xsl:variable>
    <xsl:call-template name="map.begin"/>
    <xsl:if test="$placement='before'">
      <xsl:text>\captionswapskip{}</xsl:text>
      <xsl:value-of select="$caption"/>
      <xsl:text>\captionswapskip{}</xsl:text>
    </xsl:if>
    <xsl:apply-templates />
    <xsl:if test="$placement!='before'">
      <xsl:value-of select="$caption"/>
    </xsl:if>
    <xsl:call-template name="map.end"/>
  </xsl:template>


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template name="normalize-scape" xmlns="">
	<refpurpose> Abstract XSL template.  </refpurpose>
	<refdescription>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="text()" name="text">
		<xsl:call-template name="trim-outer">
			<xsl:with-param name="string">
				<xsl:choose>
					<xsl:when test="ancestor::literal|ancestor::filename|ancestor::userinput|ancestor::systemitem|ancestor::prompt|ancestor::email|ancestor::sgmltag">
						<xsl:call-template name="scape-verbatim">
							<xsl:with-param name="string" select="."/>
						</xsl:call-template>
					</xsl:when>
					<xsl:otherwise>
						<xsl:call-template name="scape">
							<xsl:with-param name="string" select="."/>
						</xsl:call-template>
					</xsl:otherwise>
				</xsl:choose>
			</xsl:with-param>
		</xsl:call-template>
    </xsl:template>

	<!--
	<xsl:template match="abbrev/text()">
		<xsl:variable name="string">
			<xsl:call-template name="text()"/>
		</xsl:variable>
		<xsl:call-template name="string-replace">
			<xsl:with-param name="to">.\ </xsl:with-param>
			<xsl:with-param name="from">. </xsl:with-param>
			<xsl:with-param name="string" select="$string"/>
		</xsl:call-template>
	</xsl:template>
	-->

    <xsl:template match="text()" mode="xref.text">
		<xsl:call-template name="trim-outer">
			<xsl:with-param name="string">
				<xsl:call-template name="scape">
					<xsl:with-param name="string" select="."/>
				</xsl:call-template>
			</xsl:with-param>
		</xsl:call-template>
    </xsl:template>

    <xsl:template match="text()" mode="xref-to">
		<xsl:call-template name="trim-outer">
			<xsl:with-param name="string">
				<xsl:call-template name="scape">
					<xsl:with-param name="string" select="."/>
				</xsl:call-template>
			</xsl:with-param>
		</xsl:call-template>
    </xsl:template>

    <xsl:template match="text()" mode="latex.verbatim">
		<!--
		<xsl:call-template name="trim-outer">
			<xsl:with-param name="string">
			-->
				<xsl:value-of select="."/> 
			<!--
			</xsl:with-param>
		</xsl:call-template>
		-->
    </xsl:template>

	<!-- this template is noly used by xref.mod.xsl and only when
	     $latex.hyphenation.tttricks != 1. -->
    <xsl:template match="text()" mode="slash.hyphen">
		<xsl:call-template name="trim-outer">
			<xsl:with-param name="string">
				<xsl:call-template name="scape.slash.hyphen">
					<xsl:with-param name="string" select="." />
				</xsl:call-template>
			</xsl:with-param>
		</xsl:call-template>
	</xsl:template>

	<xsl:template name="trim-outer">
		<xsl:param name="string"/>
		<xsl:variable name="trimleft" select="position()=1"/>
		<xsl:variable name="trimright" select="position()=last()"/>
		<xsl:choose>
			<xsl:when test="$trimleft and not($trimright)">
				<xsl:value-of select="substring-before(normalize-space(concat($string,'$$')),'$$')"/>
			</xsl:when>
			<xsl:when test="$trimright and not($trimleft)">
				<xsl:value-of select="substring-after(normalize-space(concat('$$',$string)),'$$')"/>
			</xsl:when>
			<xsl:when test="$trimleft and $trimright">
				<xsl:value-of select="normalize-space($string)"/>
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="$string"/>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>

	<xsl:template name="scape.slash.hyphen">
	<xsl:param name="string" />
	<xsl:choose>
	    <xsl:when test="contains($string,'://')">
			<xsl:call-template name="string-replace">
				<xsl:with-param name="to">/\dbz{}</xsl:with-param>
				<xsl:with-param name="from">/</xsl:with-param>
				<xsl:with-param name="string">
					<xsl:call-template name="string-replace">
						<xsl:with-param name="to">.\dbz{}</xsl:with-param>
						<xsl:with-param name="from">.</xsl:with-param>
						<xsl:with-param name="string">
							<xsl:value-of select="substring-before($string,'://')"/>
							<xsl:value-of select="'://'"/>
							<xsl:call-template name="scape">
								<xsl:with-param name="string" select="substring-after($string,'://')"/>
							</xsl:call-template>
						</xsl:with-param>
					</xsl:call-template>
				</xsl:with-param>
			</xsl:call-template>
	    </xsl:when>
	    <xsl:otherwise>
			<xsl:call-template name="string-replace">
				<xsl:with-param name="to">/\dbz{}</xsl:with-param>
				<xsl:with-param name="from">/</xsl:with-param>
				<xsl:with-param name="string">
					<xsl:call-template name="string-replace">
						<xsl:with-param name="to">.\dbz{}</xsl:with-param>
						<xsl:with-param name="from">.</xsl:with-param>
						<xsl:with-param name="string">
							<xsl:call-template name="scape">
								<xsl:with-param name="string" select="$string"/>
							</xsl:call-template>
						</xsl:with-param>
					</xsl:call-template>
				</xsl:with-param>
			</xsl:call-template>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template name="normalize-scape" >
	<xsl:param name="string"/>
	<xsl:variable name="result">
	    <xsl:call-template name="scape"><xsl:with-param name="string" select="$string"/></xsl:call-template>
	</xsl:variable>
	<xsl:value-of select="normalize-space($result)"/>
    </xsl:template>


    <doc:template name="scape-optionalarg" xmlns="">
	<refpurpose> Escape the ] character in LaTeX optional arguments (experimental)  </refpurpose>
	<refdescription>
	</refdescription>
    </doc:template>
	<xsl:template name="scape-optionalarg" >
	<xsl:param name="string"/>
	<xsl:call-template name="string-replace">
		<xsl:with-param name="to">{\rbrack}</xsl:with-param>
		<xsl:with-param name="from">]</xsl:with-param>
		<xsl:with-param name="string" select="$string"/>
	</xsl:call-template>
    </xsl:template>




    <xsl:template name="string-replace">
	<xsl:param name="string"/>
	<xsl:param name="from"/>
	<xsl:param name="to"/>

	<xsl:choose>
	    <xsl:when test="contains($string, $from)">

		<xsl:variable name="before" select="substring-before($string, $from)"/>
		<xsl:variable name="after" select="substring-after($string, $from)"/>
		<xsl:variable name="prefix" select="concat($before, $to)"/>

		<xsl:value-of select="$before"/>
		<xsl:value-of select="$to"/>
		<xsl:call-template name="string-replace">
		    <xsl:with-param name="string" select="$after"/>
		    <xsl:with-param name="from" select="$from"/>
		    <xsl:with-param name="to" select="$to"/>
		</xsl:call-template>
	    </xsl:when> 
	    <xsl:otherwise>
		<xsl:value-of select="$string"/>  
	    </xsl:otherwise>
	</xsl:choose>            
    </xsl:template>




    <!--  
    (c) David Carlisle
    replace all occurences of the character(s) `from'
    by the string `to' in the string `string'.
    <xsl:template name="string-replace" >
	<xsl:param name="string"/>
	<xsl:param name="from"/>
	<xsl:param name="to"/>
	<xsl:choose>
	    <xsl:when test="contains($string,$from)">
		<xsl:value-of select="substring-before($string,$from)"/>
		<xsl:value-of select="$to"/>
		<xsl:call-template name="string-replace">
		    <xsl:with-param name="string" select="substring-after($string,$from)"/>
		    <xsl:with-param name="from" select="$from"/>
		    <xsl:with-param name="to" select="$to"/>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:value-of select="$string"/>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>
    -->

</xsl:stylesheet>
