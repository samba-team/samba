<?xml version='1.0'?>
<!-- 
	Samba-documentation specific stylesheets
	Published under the GNU GPL

	(C) Jelmer Vernooij 					2002-2004
	(C) Alexander Bokovoy 					2002-2004
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:samba="http://www.samba.org/samba/DTD/samba-doc"
	version="1.1">

	<xsl:import href="../settings.xsl"/>
	<xsl:import href="strip-references.xsl"/>
	<xsl:import href="expand-smbconfdoc.xsl"/>

	<xsl:output method="xml" encoding="UTF-8" doctype-public="-//OASIS//DTD DocBook XML V4.2//EN" indent="yes" doctype-system="http://www.oasis-open.org/docbook/xml/4.2/docbookx.dtd"/>

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
					<xsl:value-of select="@name"/>
				</xsl:element>
			</xsl:element>
			<xsl:element name="parameter">
				<xsl:text disable-output-escaping="yes">
					&lt;?latex \hspace{1cm} ?&gt;
				</xsl:text>
				<xsl:value-of select="@name"/>
				<xsl:choose>
					<xsl:when test="text() != ''">
						<xsl:text> = </xsl:text>
						<xsl:value-of select="text()"/>
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
				<xsl:value-of select="@name"/>
			</xsl:element>
		</xsl:element>
	</xsl:template>

	<xsl:template match="smbconfoption">
		<!-- Include an index term -->
		<xsl:element name="indexterm">
			<xsl:element name="primary">
				<xsl:value-of select="@name"/>
			</xsl:element>
		</xsl:element>

		<xsl:variable name="linkcontent">
			<xsl:element name="parameter">
				<xsl:attribute name="moreinfo">
					<xsl:text>none</xsl:text>
				</xsl:attribute>
				<xsl:value-of select="@name"/>	
			</xsl:element>

			<xsl:choose>
				<xsl:when test="text() != ''">
					<xsl:text> = </xsl:text>
					<xsl:value-of select="text()"/>
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
						<xsl:value-of select="translate(translate(string(@name),' ',''),'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
					</xsl:attribute>
					<xsl:value-of select="$linkcontent"/>
				</xsl:element>
			</xsl:otherwise>
		</xsl:choose>
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
			<xsl:value-of select="@name"/>
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
				<xsl:if test="imagedescription = ''">
					<xsl:message><xsl:text>imagedescription of image with id </xsl:text><xsl:value-of select="@id"/><xsl:text> is empty.</xsl:text></xsl:message>
				</xsl:if>
				<xsl:value-of select="imagedescription"/>
			</xsl:element>
			<xsl:element name="mediaobject">
				<xsl:element name="imageobject">
					<xsl:attribute name="role"><xsl:text>latex</xsl:text></xsl:attribute>
					<xsl:element name="imagedata">
						<xsl:attribute name="fileref">
							<xsl:value-of select="$latex.imagebasedir"/><xsl:text>images/</xsl:text><xsl:value-of select="imagefile"/></xsl:attribute>
						<xsl:attribute name="scale">
							<xsl:choose>
								<xsl:when test="@scale != ''">
									<xsl:value-of select="@scale"/>
								</xsl:when>

								<xsl:when test="imagefile/@scale != ''">
									<xsl:value-of select="imagefile/@scale"/>
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
						<xsl:attribute name="scale">
							<xsl:choose>
								<xsl:when test="@scale != ''">
									<xsl:value-of select="@scale"/>
								</xsl:when>

								<xsl:when test="imagefile/@scale != ''">
									<xsl:value-of select="imagefile/@scale"/>
								</xsl:when>

								<xsl:otherwise>
									<xsl:text>100</xsl:text>
								</xsl:otherwise>
							</xsl:choose>
						</xsl:attribute>
						<xsl:attribute name="scalefit"><xsl:text>1</xsl:text></xsl:attribute>
					</xsl:element>
				</xsl:element>
				<xsl:element name="imageobject">
					<xsl:element name="imagedata">
						<xsl:attribute name="fileref">
							<xsl:text>images/</xsl:text><xsl:value-of select="imagefile"/><xsl:text>.png</xsl:text></xsl:attribute>
						<xsl:attribute name="scale">
							<xsl:choose>
								<xsl:when test="@scale != ''">
									<xsl:value-of select="@scale"/>
								</xsl:when>

								<xsl:when test="imagefile/@scale != ''">
									<xsl:value-of select="imagefile/@scale"/>
								</xsl:when>

								<xsl:otherwise>
									<xsl:text>50</xsl:text>
								</xsl:otherwise>
							</xsl:choose>
						</xsl:attribute>
						<xsl:attribute name="scalefit"><xsl:text>1</xsl:text></xsl:attribute>
					</xsl:element>
				</xsl:element>

			</xsl:element>
		</xsl:element>
	</xsl:template>

</xsl:stylesheet>
