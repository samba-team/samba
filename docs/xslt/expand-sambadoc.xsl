<?xml version='1.0'?>
<!-- 
	Samba-documentation specific stylesheets
	Published under the GNU GPL

	(C) Jelmer Vernooij 					2002-2004
	(C) Alexander Bokovoy 					2002-2004
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:exsl="http://exslt.org/common"
	xmlns:samba="http://samba.org/common"
	version="1.1"
	extension-element-prefixes="exsl">

	<xsl:import href="../settings.xsl"/>

	<xsl:output method="xml" encoding="UTF-8" doctype-public="-//OASIS//DTD DocBook XML V4.2//EN" indent="yes" doctype-system="http://www.oasis-open.org/docbook/xml/4.2/docbookx.dtd"/>

	<xsl:param name="xmlSambaNsUri" select="'http://samba.org/common'"/>

	<xsl:template match="reference/refentry/refsect1">
		<xsl:if test="title!='VERSION' and title!='AUTHOR'">
			<xsl:element name="refsect1">
				<xsl:if test="@id!=''">
					<xsl:attribute name="id">
						<xsl:value-of select="@id"/>
					</xsl:attribute>
				</xsl:if>
				<xsl:apply-templates/>			
			</xsl:element>
		</xsl:if>
	</xsl:template>

	<xsl:template match="translator">
		<xsl:element name="othercredit">
			<xsl:element name="author">
				<xsl:apply-templates/>
				<xsl:element name="contrib">
					<xsl:text>Translation to </xsl:text><xsl:value-of select="@lang"/>
				</xsl:element>
			</xsl:element>
		</xsl:element>
	</xsl:template>

	<xsl:template match="reference/refentry">
		<xsl:element name="section">
			<xsl:attribute name="id">
				<xsl:value-of select="@id"/>
			</xsl:attribute>
			<xsl:element name="title">
				<xsl:value-of select="refmeta/refentrytitle"/>
				<!--			<xsl:text> (</xsl:text>
				<xsl:value-of select="refnamediv/refpurpose"/>
				<xsl:text>)</xsl:text>-->
			</xsl:element>
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="reference/refentry/refmeta"/>

	<xsl:template match="reference/refentry/refnamediv"/>

	<xsl:template match="reference">
		<xsl:element name="appendix">
			<xsl:attribute name="id">
				<xsl:value-of select="@id"/>
			</xsl:attribute>
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>


	<!-- This is needed to copy content unchanged -->
	<xsl:template match="@*|node()">
		<xsl:copy>
			<xsl:apply-templates select="@*|node()"/>
		</xsl:copy>
	</xsl:template>

	<xsl:template match="smbconfexample/smbconfoption|smbconfblock/smbconfoption">

		<xsl:element name="member">
			<xsl:element name="indexterm">
				<xsl:element name="primary">
					<xsl:value-of select="name"/>
				</xsl:element>
			</xsl:element>
			<xsl:element name="parameter">
				<xsl:text disable-output-escaping="yes">
					&lt;?latex \hspace{1cm} ?&gt;
				</xsl:text>
				<xsl:value-of select="name"/>
				<xsl:choose>
					<xsl:when test="value != ''">
						<xsl:text> = </xsl:text>
						<xsl:value-of select="value"/>
					</xsl:when>
				</xsl:choose>
			</xsl:element>
		</xsl:element>
	</xsl:template>

	<xsl:template match="smbconfexample/smbconfcomment|smbconfblock/smbconfcomment">
		<xsl:text disable-output-escaping="yes">
			&lt;?latex \hspace{1cm} ?&gt;
		</xsl:text>
		<xsl:element name="member">
			<xsl:text># </xsl:text>
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="smbconfexample/smbconfsection|smbconfblock/smbconfsection">
		<xsl:element name="member">
			<xsl:text> </xsl:text>
		</xsl:element>
		<xsl:element name="member">
			<xsl:element name="parameter">
				<xsl:apply-templates/>
			</xsl:element>
		</xsl:element>
	</xsl:template>

	<xsl:template match="smbconfoption">
		<!-- Include an index term -->
		<xsl:element name="indexterm">
			<xsl:element name="primary">
				<xsl:value-of select="name"/>
			</xsl:element>
		</xsl:element>

		<xsl:variable name="linkcontent">
			<xsl:element name="parameter">
				<xsl:attribute name="moreinfo">
					<xsl:text>none</xsl:text>
				</xsl:attribute>
				<xsl:value-of select="name"/>	
			</xsl:element>

			<xsl:choose>
				<xsl:when test="value != ''">
					<xsl:text> = </xsl:text>
					<xsl:value-of select="value"/>
				</xsl:when>
			</xsl:choose>
		</xsl:variable>

		<xsl:choose>
			<xsl:when test="$noreference = 1">
				<xsl:value-of select="$linkcontent"/>
			</xsl:when>
			<xsl:otherwise>
				<xsl:element name="link">
					<xsl:attribute name="linkend">
						<xsl:value-of select="translate(translate(string(name),' ',''),'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
					</xsl:attribute>
					<xsl:value-of select="$linkcontent"/>
				</xsl:element>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>

	<!-- FIXME: Needs extension sometime -->
	<xsl:template match="ntgroup|ntuser">
		<xsl:element name="emphasis">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="smbconfexample">
		<xsl:choose>
			<xsl:when test="title = ''">
				<xsl:message>
					<xsl:text>Warning: smbconfexample does not have title!</xsl:text>
				</xsl:message>
			</xsl:when>
		</xsl:choose>
		<xsl:element name="example">
			<xsl:choose>
				<xsl:when test="@id != ''">
					<xsl:attribute name="id">
						<xsl:value-of select="@id"/>
					</xsl:attribute>
				</xsl:when>
			</xsl:choose>

			<xsl:element name="title">
				<xsl:value-of select="title"/>
			</xsl:element>
			<xsl:element name="simplelist">
				<xsl:apply-templates/>
			</xsl:element>
		</xsl:element>
	</xsl:template>

	<xsl:template match="smbconfexample/title">
	</xsl:template>

	<xsl:template match="smbconfblock">
		<xsl:element name="simplelist">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="smbconfsection">
		<xsl:element name="parameter">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="smbconfcomment">
		<xsl:text># </xsl:text>
		<xsl:apply-templates/>
	</xsl:template>

	<xsl:template match="smbfile">
		<xsl:apply-templates/>
	</xsl:template>

	<xsl:template match="image">
		<xsl:element name="figure">
			<xsl:attribute name="id">
				<xsl:choose>
					<xsl:when test="@id != ''">
						<xsl:value-of select="@id"/>
					</xsl:when>
					<xsl:otherwise>
						<xsl:value-of select="imagefile"/>
					</xsl:otherwise>
				</xsl:choose>
			</xsl:attribute>

			<xsl:element name="title">
				<xsl:value-of select="imagedescription"/>
			</xsl:element>
			<xsl:element name="mediaobject">
				<xsl:element name="imageobject">
					<xsl:attribute name="role"><xsl:text>latex</xsl:text></xsl:attribute>
					<xsl:element name="imagedata">
						<xsl:attribute name="fileref">
							<xsl:text>howto/imagefiles/</xsl:text><xsl:value-of select="imagefile"/></xsl:attribute>
						<xsl:attribute name="scale">
							<xsl:choose>
								<xsl:when test="@scale != ''">
									<xsl:value-of select="@scale"/>
								</xsl:when>

								<xsl:otherwise>
									<xsl:text>50</xsl:text>
								</xsl:otherwise>
							</xsl:choose>
						</xsl:attribute>
						<xsl:attribute name="scalefit"><xsl:text>1</xsl:text></xsl:attribute>
					</xsl:element>
				</xsl:element>
				<xsl:element name="imageobject">
					<xsl:attribute name="role"><xsl:text>html</xsl:text></xsl:attribute>
					<xsl:element name="imagedata">
						<xsl:attribute name="fileref">
							<xsl:text>images/</xsl:text><xsl:value-of select="imagefile"/><xsl:text>.png</xsl:text></xsl:attribute>
						<xsl:attribute name="scale"><xsl:text>50</xsl:text></xsl:attribute>
						<xsl:attribute name="scalefit"><xsl:text>1</xsl:text></xsl:attribute>
					</xsl:element>
				</xsl:element>
				<xsl:element name="imageobject">
					<xsl:element name="imagedata">
						<xsl:attribute name="fileref">
							<xsl:text>images/</xsl:text><xsl:value-of select="imagefile"/><xsl:text>.png</xsl:text></xsl:attribute>
						<xsl:attribute name="scale"><xsl:text>50</xsl:text></xsl:attribute>
						<xsl:attribute name="scalefit"><xsl:text>1</xsl:text></xsl:attribute>
					</xsl:element>
				</xsl:element>

			</xsl:element>
		</xsl:element>
	</xsl:template>

	<xsl:template match="description"><xsl:apply-templates/></xsl:template>

	<xsl:template match="value"><xsl:apply-templates/></xsl:template>

	<xsl:template match="synonym"><xsl:apply-templates/></xsl:template>

	<xsl:template match="related"><xsl:apply-templates/></xsl:template>

	<xsl:template match="filterline">
		<xsl:element name="programlisting">
			<xsl:apply-templates/>
		</xsl:element>
	</xsl:template>

	<xsl:template match="//samba:parameterlist">
		<xsl:apply-templates>
			<xsl:sort select="varlistentry/term/anchor"/>
		</xsl:apply-templates>
	</xsl:template>

	<xsl:template match="value/comment">
		<xsl:text>&#10;# </xsl:text>
		<xsl:apply-templates/>
	</xsl:template>

	<xsl:template match="//samba:parameter">
		<!-- reconstruct varlistentry - not all of them will go into separate files
		and also we must repair the main varlistentry itself.
		-->
		<xsl:variable name="cname"><xsl:value-of select="translate(translate(string(@name),' ',''),
				'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
		</xsl:variable>

		<xsl:variable name="name"><xsl:value-of select="@name"/></xsl:variable>

		<xsl:variable name="anchor">
			<xsl:element name="anchor">
				<xsl:attribute name="id">
					<xsl:value-of select="$cname"/>
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


		<!-- Generate list of examples -->
		<xsl:variable name="examples">
			<xsl:for-each select="value">
				<xsl:if test="@type = 'example'">
					<xsl:element name="para">
						<xsl:text>Example: </xsl:text>
						<xsl:element name="emphasis">
							<xsl:element name="parameter">
								<xsl:copy-of select="$name"/>
							</xsl:element>
							<xsl:text> = </xsl:text>
							<xsl:apply-templates select="."/>
							<xsl:text>&#10;</xsl:text>
						</xsl:element>
						<xsl:text>&#10;</xsl:text>
					</xsl:element>
				</xsl:if>
			</xsl:for-each>
		</xsl:variable>

		<xsl:variable name="tdefault">
			<xsl:for-each select="value">
				<xsl:if test="@type = 'default'">
					<xsl:element name="para">
						<xsl:text>Default: </xsl:text>
						<xsl:element name="emphasis">
							<xsl:element name="parameter">
								<xsl:copy-of select="$name"/>
							</xsl:element>
							<xsl:text> = </xsl:text>
							<xsl:apply-templates select="."/>
							<xsl:text>&#10;</xsl:text>
						</xsl:element>
						<xsl:text>&#10;</xsl:text>
					</xsl:element>
				</xsl:if>
			</xsl:for-each>
		</xsl:variable>

		<xsl:variable name="default">
			<xsl:choose>
				<xsl:when test="$tdefault = ''">
					<xsl:element name="para">
						<xsl:element name="emphasis">
							<xsl:text>No default</xsl:text>
						</xsl:element>	
					</xsl:element>
				</xsl:when>
				<xsl:otherwise>
					<xsl:copy-of select="$tdefault"/>
				</xsl:otherwise>
			</xsl:choose>
		</xsl:variable>

		<xsl:variable name="content">
			<xsl:apply-templates select="description"/>
		</xsl:variable>

		<xsl:for-each select="synonym">
			<xsl:element name="varlistentry">
				<xsl:text>&#10;</xsl:text>     
				<xsl:element name="indexterm">
					<xsl:attribute name="significance">
						<xsl:text>preferred</xsl:text>
					</xsl:attribute>
					<xsl:element name="primary">
						<xsl:value-of select="."/>
					</xsl:element>
					<xsl:element name="see">
						<xsl:value-of select="$name"/>
					</xsl:element>
				</xsl:element>

				<xsl:element name="term">
					<xsl:element name="anchor">
						<xsl:attribute name="id">
							<xsl:value-of select="translate(translate(string(.),' ',''), 'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
						</xsl:attribute>
					</xsl:element>
					<xsl:value-of select="."/>
				</xsl:element>

				<xsl:element name="listitem">
					<xsl:element name="para"><xsl:text>This parameter is a synonym for </xsl:text><xsl:copy-of select="$name"/><xsl:text>.</xsl:text></xsl:element>
				</xsl:element>
			</xsl:element>
		</xsl:for-each>

		<xsl:element name="varlistentry">
			<xsl:text>&#10;</xsl:text>     
			<xsl:element name="indexterm">
				<xsl:attribute name="significance">
					<xsl:text>preferred</xsl:text>
				</xsl:attribute>
				<xsl:element name="primary">
					<xsl:value-of select="@name"/>
				</xsl:element>
			</xsl:element>
			<xsl:copy-of select="$term"/>
			<xsl:element name="listitem">
				<xsl:copy-of select="$content"/> <xsl:text>&#10;</xsl:text>     
				<xsl:copy-of select="$default"/> <xsl:text>&#10;</xsl:text>     
				<xsl:copy-of select="$examples"/> <xsl:text>&#10;</xsl:text>     
			</xsl:element>
		</xsl:element>
	</xsl:template>

	<xsl:template match="ulink">
		<xsl:element name="ulink">
			<xsl:attribute name="url">
				<xsl:value-of select="@url"/>
			</xsl:attribute>

			<xsl:apply-templates/>
			<xsl:if test="contains(@url,'http://') or contains(@url,'ftp://')">
				<xsl:if test="$duplicate_ulinks='brackets'">
					<xsl:text> (</xsl:text>
					<xsl:value-of select="@url"/>
					<xsl:text>)</xsl:text>
				</xsl:if>
				<xsl:if test="$duplicate_ulinks='footnote'">
					<xsl:element name="footnote">
						<xsl:element name="para">
							<xsl:value-of select="@url"/>
						</xsl:element>
					</xsl:element>
				</xsl:if>
			</xsl:if>
		</xsl:element>
	</xsl:template>

	<!-- Just ignore these -->
	<xsl:template match="smbfile">
		<xsl:apply-templates/>
	</xsl:template>

	<xsl:template match="quote">
		<xsl:element name="quote">
			<xsl:element name="emphasis">
				<xsl:apply-templates/>
			</xsl:element>
		</xsl:element>
	</xsl:template>

</xsl:stylesheet>
