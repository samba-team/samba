#################################################################
# Makefile for Samba Documentation
# Authors:	
# 		James Moore <jmoore@php.net>
# 		Gerald Carter <jerry@samba.org>
# 		Jelmer Vernooij <jelmer@samba.org>
include Makefile.settings

# Docs to build
MAIN_DOCS = $(patsubst %/index.xml,%,$(wildcard */index.xml))
MANPAGES = $(wildcard $(MANPAGEDIR)/*.?.xml)

# Lists of files to process
MANPAGES_PLUCKER = $(patsubst $(MANPAGEDIR)/%.xml,$(PLUCKERDIR)/%.pdb,$(MANPAGES))
DBLATEX_OPTIONS = -p xslt/latex.xsl -i xslt/latex

DATETIME := $(shell date +%Y%m%d%H%M%S)

ifeq ($(PROFILE), Y)
XSLTPROC += --profile --load-trace --timing
endif

ifndef OUTPUTDIR
Makefile.settings: configure
	./configure

configure: configure.ac
	autoreconf
endif

help: 
	@echo "Supported make targets:"
	@echo " release - Build the docs needed for a Samba release"
	@echo " all - Build all docs that can be build using the utilities found by configure"
	@echo " everything - Build all of the above"
	@echo " pdf,tex,ps,manpages,txt,pearson,htmlhelp - Build specific output format"
	@echo " html - Build multi-file HTML versions"
	@echo " html-single - Build single-file HTML versions"
	@echo " htmlman - Build HTML version of manpages"
	@echo " samples - Extract examples"

$(PDFDIR)/Samba3-ByExample.pdf $(PSDIR)/Samba3-ByExample.ps $(DOCBOOKDIR)/Samba3-ByExample.xml Samba3-ByExample.tex: $(wildcard Samba3-ByExample/*.xml)
$(PDFDIR)/Samba3-HOWTO.pdf $(PSDIR)/Samba3-HOWTO.ps Samba3-HOWTO.tex $(DOCBOOKDIR)/Samba3-HOWTO.xml: $(wildcard Samba3-HOWTO/*.xml) Samba3-HOWTO-attributions.xml
Samba3-HOWTO/manpages.xml: $(MANPAGEDIR)/smb.conf.5.xml
$(PDFDIR)/Samba3-Developers-Guide.pdf $(PSDIR)/Samba3-Developers-Guide.ps $(DOCBOOKDIR)/Samba3-Developers-Guide.xml Samba3-Developers-Guide.tex: $(wildcard Samba3-Developers-Guide/*.xml) Samba3-Developers-Guide-attributions.xml

# Pseudo targets 
all:: $(TARGETS)
everything:: manpages pdf html-single html htmlman txt ps fo htmlhelp pearson
release:: manpages htmlman html pdf
clean::
	@echo "Cleaning up..." 
	rm -rf $(OUTPUTDIR)/* $(DOCBOOKDIR)
	rm -f *-attributions.xml
	rm -f $(patsubst %.svg,%.png,$(foreach DOC,$(MAIN_DOCS),$($(DOC)-images-latex-dia))) \
			$(patsubst %.svg,%.pdf,$(foreach DOC,$(MAIN_DOCS),$($(DOC)-images-latex-svg))) \
			$(patsubst %.svg,%.eps,$(foreach DOC,$(MAIN_DOCS),$($(DOC)-images-latex-svg))) \
			$(patsubst %.svg,%.png,$(foreach DOC,$(MAIN_DOCS),$($(DOC)-images-latex-svg)))
	rm -f *-attributions.xml *.d *.tpt *.tex *.loc *.toc *.lof *.glo *.idx *.aux
	rm -f *-images-html*
	rm -f *-images-latex-* $(LATEX_FIGURES)
	rm -f xslt/figures/*pdf
	rm -f $(SMBDOTCONFDOC)/parameters.*.xml
	rm -f build/catalog.xml

# Output format targets
pdf:: $(patsubst %,$(PDFDIR)/%.pdf,$(MAIN_DOCS))
ps:: $(patsubst %,$(PSDIR)/%.ps,$(MAIN_DOCS))
txt:: $(patsubst %,$(TXTDIR)/%.txt,$(MAIN_DOCS))
tex:: $(addsuffix .tex,$(MAIN_DOCS))
texi:: $(patsubst %,$(TEXINFODIR)/%.texi,$(MAIN_DOCS))
texiinfo:: $(patsubst %,$(TEXINFODIR)/%.info,$(MAIN_DOCS))
manpages:: $(patsubst $(MANPAGEDIR)/%.xml,$(OUTPUTDIR)/manpages/%,$(MANPAGES))
pearson:: $(PEARSONDIR)/Samba3-HOWTO.xml
pearson-verify:: $(PEARSONDIR)/Samba3-HOWTO.report.html
plucker:: $(patsubst %,$(PLUCKERDIR)/%.pdb,$(MAIN_DOCS))
htmlman:: $(patsubst $(MANPAGEDIR)/%.xml,$(HTMLDIR)/manpages/%.html,$(MANPAGES)) $(HTMLDIR)/manpages/index.html
html-single:: $(patsubst %,$(HTMLDIR)/%.html,$(MAIN_DOCS))
html:: $(patsubst %,$(HTMLDIR)/%/index.html,$(MAIN_DOCS)) $(HTMLDIR)/index.html
htmlhelp:: $(addprefix $(HTMLHELPDIR)/,$(MAIN_DOCS))
validate:: $(addsuffix -validate,$(MAIN_DOCS))

test:: validate
check:: validate

.PHONY: test check validate manpages

# Intermediate docbook docs
#
$(DOCBOOKDIR)/%.xml: %/index.xml xslt/expand-sambadoc.xsl
	@echo "Converting Samba-specific tags for $*..."
	@mkdir -p $(@D)
	@$(XSLTPROC) --stringparam latex.imagebasedir "$*/"  --stringparam noreference 0  --xinclude --output $@ xslt/expand-sambadoc.xsl $<

$(DOCBOOKDIR)/manpages/%.xml: $(MANPAGEDIR)/%.xml xslt/expand-sambadoc.xsl
	@mkdir -p $(@D)
	$(XSLTPROC) --xinclude --stringparam noreference 0 --output $@ xslt/expand-sambadoc.xsl $<

$(DOCBOOKDIR)/manpages/index.xml: $(MANPAGES) xslt/manpage-summary.xsl
	@mkdir -p $(@D)
	echo "<article><variablelist>" > $@
	$(XSLTPROC) xslt/manpage-summary.xsl $(MANPAGES) >> $@
	@echo "</variablelist></article>" >> $@

# HTML docs
$(HTMLDIR)/index.html: htmldocs.html
	@mkdir -p $(@D)
	cp $< $@

$(HTMLDIR)/%/index.html: $(DOCBOOKDIR)/%.xml $(HTMLDIR)/%/samba.css xslt/html-chunk.xsl %-images-html-chunks
	@mkdir -p $(@D)
	$(XSLTPROC) --stringparam base.dir "$(HTMLDIR)/$*/" xslt/html-chunk.xsl $<

# Single large HTML files
$(OUTPUTDIR)/%/samba.css: xslt/html/samba.css
	@mkdir -p $(@D)
	cp $< $@

$(patsubst %,$(HTMLDIR)/%.html,$(MAIN_DOCS)): $(HTMLDIR)/%.html: %-images-html-single

$(HTMLDIR)/%.html: $(DOCBOOKDIR)/%.xml $(HTMLDIR)/samba.css xslt/html.xsl 
	$(XSLTPROC) --output $@ xslt/html.xsl $<

# Attributions
%-attributions.xml: 
	@echo "Generating attributions file $@ from $*/"
	@cp -f templates/attributions.xml $@
	@$(XSLTPROC) --xinclude -o $@ xslt/generate-attributions.xsl $*/index.xml 

# Text files
$(TXTDIR)/%.txt: $(HTMLDIR)/%.html
	@mkdir -p $(@D)
	$(HTML2TEXT) -nobs -style pretty -o $@ $<

# Tex files
%.tex: %/index.xml xslt/latex.xsl
	@echo "Generating $@..."
	@mkdir -p $(@D)
	@$(DBLATEX) $(DBLATEX_OPTIONS) -t tex -o $@ $<

# Dependency files
%.d: $(DOCBOOKDIR)/%.xml xslt/generate-dependencies.xsl
	@echo "Generating dependency file for $*" 
	@$(XSLTPROC) --novalid \
		--stringparam txtbasedir "$(TXTDIR)/$*/" \
		--stringparam target "$*" \
		-o $@ xslt/generate-dependencies.xsl $<
	@echo "$*-images-latex-svg = \$$(wildcard \$$(addsuffix .svg, \$$($*-images-latex)))" >> $@
	@echo "$*-images-latex-eps: \$$(addsuffix .eps, \$$($*-images-latex))" >> $@
	@echo "$*-images-latex-pdf: \$$(patsubst %.svg, %.pdf, \$$($*-images-latex-svg))" >> $@
	@echo "$*-images-latex-png: \$$(filter-out \$$(patsubst %.svg,%.png,\$$($*-images-latex-svg)), \$$(addsuffix .png, \$$($*-images-latex)))" >> $@

	@echo >> $@
	@echo "\$$(HTMLDIR)/%: $*/%" >> $@
	@echo "	@mkdir -p \$$(@D)" >> $@
	@echo "	@cp \$$< \$$@" >> $@
	@echo >> $@
	@echo "\$$(HTMLDIR)/$*/%: $*/%" >> $@
	@echo "	@mkdir -p \$$(@D)" >> $@
	@echo "	@cp \$$< \$$@" >> $@
	@echo >> $@
	@echo "\$$(HTMLHELPDIR)/$*/%: $*/%" >> $@
	@echo "	@mkdir -p \$$(@D)" >> $@
	@echo "	@cp \$$< \$$@" >> $@
	@echo >> $@
	@echo "$*-images-html-single: \$$(addprefix \$$(HTMLDIR)/, \$$($*-images-html))" >> $@
	@echo "$*-images-html-chunks: \$$(addprefix \$$(HTMLDIR)/$*/, \$$($*-images-html))" >> $@
	@echo "$*-images-htmlhelp: \$$(addprefix \$$(HTMLHELPDIR)/$*/, \$$($*-images-html))" >> $@

ifdef OUTPUTDIR 
ifneq ($(MAKECMDGOALS),clobber)
-include $(addsuffix .d,$(MAIN_DOCS))
endif
endif

# Adobe PDF files  
$(PDFDIR)/%.pdf: %/index.xml $(PDFDIR) xslt/latex.xsl %-images-latex-png %-images-latex-pdf
	$(DBLATEX) $(DBLATEX_OPTIONS) -I $*/images -t pdf -o $@ $<

# PostScript files
$(PSDIR)/%.ps: %/index.xml $(PSDIR) xslt/latex.xsl %-images-latex-eps
	$(DBLATEX) $(DBLATEX_OPTIONS) -I $*/images -t ps -o $@ $<

%.eps: %.svg
	$(INKSCAPE) -z -f $(abspath $<) --export-eps=$(abspath $@)

%.png: %.svg
	$(INKSCAPE) -z -f $(abspath $<) --export-png=$(abspath $@)

%.eps: %.png
	$(PNGTOPNM) $< | $(PNMTOPS) > $@

%.pdf: %.svg
	$(INKSCAPE) -z -f $(abspath $<) --export-pdf=$(abspath $@)

$(HTMLHELPDIR)/%: $(DOCBOOKDIR)/%.xml %-images-htmlhelp
	$(XSLTPROC) --stringparam htmlhelp.chm $*.chm \
				--stringparam manifest.in.base.dir "$@/" \
				--stringparam base.dir "$@/" \
	http://docbook.sourceforge.net/release/xsl/current/htmlhelp/htmlhelp.xsl $<

# Plucker docs
$(PLUCKERDIR)/%.pdb: $(HTMLDIR)/%.html 
	@mkdir -p $(@D)
	$(PLUCKERBUILD) -v -V 2 --stayonhost --zlib-compression -f $* -p $(PLUCKERDIR) file:$< 

# Texinfo docs
$(TEXINFODIR)/%.texi: $(DOCBOOKDIR)/%.xml
	@mkdir -p $(@D)
	cd $(@D) && $(DB2TEXI) $(shell pwd)/$<

$(TEXINFODIR)/%.info: $(TEXINFODIR)/%.texi
	$(MAKEINFO) --no-validate --force -o $@ "$<"

# Manpages
$(MANPAGEDIR)/smb.conf.5.xml: parameters

# The phony parameters target exists in order to always create the
# the parameters xml files. Otherwise, when parameters.*.xml does not exist
# yet, the parameters are not generated when smb.conf.5.xml is newer than
# any smbdotconf/*/*.xml file ...
.PHONY: parameters

parameters: $(SMBDOTCONFDOC)/parameters.all.xml

$(SMBDOTCONFDOC)/parameters.all.xml: $(wildcard $(SMBDOTCONFDOC)/*/*.xml) $(SMBDOTCONFDOC)/generate-file-list.sh
	$(SMBDOTCONFDOC)/generate-file-list.sh $(SMBDOTCONFDOC) > $@

$(OUTPUTDIR):
	test -d $@ || mkdir $@

$(OUTPUTDIR)/%: $(DOCBOOKDIR)/%.xml xslt/man.xsl
	@mkdir -p $(@D)
	$(XSLTPROC) --output $@ xslt/man.xsl $<

# Individual smb.conf parameters
smb.conf-chunks: $(patsubst $(SMBDOTCONFDOC)/%.xml,$(HTMLDIR)/smb.conf/%.html,$(wildcard $(SMBDOTCONFDOC)/*/*.xml))

$(HTMLDIR)/smb.conf/%.html: $(SMBDOTCONFDOC)/%.xml
	@mkdir -p $(@D)
	$(XSLTPROC) --output $@ xslt/smb.conf-html.xsl $<

# Pearson compatible XML
$(PEARSONDIR)/%.xml: %/index.xml xslt/pearson.xsl
	@mkdir -p $(@D)
	$(XSLTPROC) --xinclude --output $@ xslt/sambadoc2pearson.xsl $<

$(PEARSONDIR)/%.report.html: $(PEARSONDIR)/%.xml
	@mkdir -p $(@D)
	-$(XMLLINT) --valid --noout $< 2> $@

# Validation verification
%-validate: %/index.xml
	cd $(<D) && $(XMLLINT) --xinclude --noent --postvalid --noout $(<F)

samples: $(DOCBOOKDIR)/Samba3-HOWTO.xml xslt/extract-examples.xsl scripts/indent-smb.conf.pl
	@mkdir -p examples
	$(XSLTPROC) --xinclude xslt/extract-examples.xsl $< > /dev/null 2> examples/README
	for I in examples/*.conf; do { ./scripts/indent-smb.conf.pl < $$I > $$I.tmp; mv $$I.tmp $$I; } done

# Archiving
archive: pdf
	@mkdir -p $(ARCHIVEDIR)
	cp $(PDFDIR)/Samba3-HOWTO.pdf $(ARCHIVEDIR)/TOSHARG-$(DATETIME).pdf
	cp $(PDFDIR)/Samba3-ByExample.pdf $(ARCHIVEDIR)/S3bE-$(DATETIME).pdf

# XSL scripts
xslt/html.xsl: xslt/html-common.xsl 
xslt/html-chunk.xsl: xslt/html-common.xsl 
xslt/latex.xsl: 
xslt/expand-sambadoc.xsl: 
xslt/generate-attributions.xsl: 
xslt/man.xsl:
xslt/pearson.xsl:

distclean clobber:: clean
	rm -f Makefile.settings config.status config.log

realdistclean:: distclean
	rm -f configure
	rm -rf autom4te.cache
	rm -rf output

# Always keep intermediate files if we can
.SECONDARY:
.PHONY: clean clobber archive release everything all 
