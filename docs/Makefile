#################################################################
# Makefile for Samba Documentation
# Authors:	
# 		James Moore <jmoore@php.net>
# 		Gerald Carter <jerry@samba.org>
# 		Jelmer Vernooij <jelmer@samba.org>
-include Makefile.settings

# Docs to build
MAIN_DOCS = $(patsubst %/index.xml,$(DOCBOOKDIR)/%.xml,$(wildcard */index.xml))
MANPAGES = $(wildcard $(MANPAGEDIR)/*.?.xml)

# Lists of files to process
LATEX_FIGURES = xslt/figures/caution.pdf xslt/figures/important.pdf xslt/figures/note.pdf xslt/figures/tip.pdf xslt/figures/warning.pdf
MANPAGES_PLUCKER = $(patsubst $(MANPAGEDIR)/%.xml,$(PLUCKERDIR)/%.pdb,$(MANPAGES))

ifndef OUTPUTDIR
Makefile.settings: Makefile.settings.in configure
	@echo Makefile.settings not present, trying to run configure...
	@./configure

configure: configure.in
	@echo configure not present, trying to generate
	@autoreconf
endif

help: 
	@echo "Supported make targets:"
	@echo " release - Build the docs needed for a Samba release"
	@echo " all - Build all docs that can be build using the utilities found by configure"
	@echo " everything - Build all of the above"
	@echo " pdf,tex,dvi,ps,manpages,txt,pearson,fo,htmlhelp - Build specific output format"
	@echo " html - Build multi-file HTML versions"
	@echo " html-single - Build single-file HTML versions"
	@echo " htmlman - Build HTML version of manpages"
	@echo " undocumented - Output list of undocumented smb.conf options"
	@echo " samples - Extract examples"
	@echo " files - Extract other files"

Samba-Guide/index.xml: $(subst Samba-Guide/index.xml,,$(wildcard Samba-Guide/*.xml))
Samba-HOWTO-Collection/index.xml: $(subst Samba-HOWTO-Collection/index.xml,,$(wildcard Samba-HOWTO-Collection/*.xml)) Samba-HOWTO-Collection-attributions.xml
Samba-Developers-Guide/index.xml: $(subst Samba-Developers-Guide/index.xml,,$(wildcard Samba-Developers-Guide/*.xml)) Samba-Developers-Guide-attributions.xml

# Pseudo targets 
all: $(TARGETS)
everything: manpages pdf html-single html htmlman txt ps fo htmlhelp pearson validate
release: manpages htmlman html pdf 

# Output format targets
pdf: $(patsubst $(DOCBOOKDIR)/%.xml,$(PDFDIR)/%.pdf,$(MAIN_DOCS))
dvi: $(patsubst $(DOCBOOKDIR)/%.xml,$(DVIDIR)/%.dvi,$(MAIN_DOCS))
ps: $(patsubst $(DOCBOOKDIR)/%.xml,$(PSDIR)/%.ps,$(MAIN_DOCS))
txt: $(patsubst $(DOCBOOKDIR)/%.xml,$(TXTDIR)/%.txt,$(MAIN_DOCS))
txt-chunks: $(patsubst $(DOCBOOKDIR)/%.xml,$(TXTDIR)/%/,$(MAIN_DOCS))
fo: $(patsubst $(DOCBOOKDIR)/%.xml,$(FODIR)/%.fo,$(MAIN_DOCS))
fo-pdf: $(patsubst $(DOCBOOKDIR)/%.xml,$(FOPDFDIR)/%.pdf,$(MAIN_DOCS))
tex: $(patsubst $(DOCBOOKDIR)/%.xml,%.tex,$(MAIN_DOCS))
texi: $(patsubst $(DOCBOOKDIR)/%.xml,$(TEXINFODIR)/%.texi,$(MAIN_DOCS))
texiinfo: $(patsubst $(DOCBOOKDIR)/%.xml,$(TEXINFODIR)/%.info,$(MAIN_DOCS))
manpages: $(patsubst $(MANPAGEDIR)/%.xml,$(MANDIR)/%,$(MANPAGES)) 
pearson: $(PEARSONDIR)/Samba-HOWTO-Collection.xml
pearson-verify: $(PEARSONDIR)/Samba-HOWTO-Collection.report.html
plucker: $(patsubst $(DOCBOOKDIR)/%.xml,$(PLUCKERDIR)/%.pdb,$(MAIN_DOCS))
htmlman: $(patsubst $(MANPAGEDIR)/%.xml,$(HTMLDIR)/%.html,$(MANPAGES)) $(HTMLDIR)/manpages.html
html-single: $(patsubst $(DOCBOOKDIR)/%.xml,$(HTMLDIR)/%.html,$(MAIN_DOCS))
html: $(patsubst $(DOCBOOKDIR)/%.xml,$(HTMLDIR)/%/index.html,$(MAIN_DOCS)) $(HTMLDIR)/index.html
htmlhelp: $(patsubst $(DOCBOOKDIR)/%.xml,$(HTMLHELPDIR)/%,$(MAIN_DOCS))
validate: $(patsubst $(DOCBOOKDIR)/%.xml,$(VALIDATEDIR)/%.report,$(MAIN_DOCS))

# Intermediate docbook docs

$(DOCBOOKDIR)/%.xml: %/index.xml xslt/expand-sambadoc.xsl
	mkdir -p $(@D)
	$(XSLTPROC) --stringparam latex.imagebasedir "$*/" --stringparam noreference 1 --xinclude --output $@ xslt/expand-sambadoc.xsl $<

$(DOCBOOKDIR)/%.xml: $(MANPAGEDIR)/%.xml xslt/expand-sambadoc.xsl
	mkdir -p $(@D)
	$(XSLTPROC) --xinclude --stringparam latex.imagebasedir "$*/" --stringparam noreference 1 --output $@ xslt/expand-sambadoc.xsl $<

$(DOCBOOKDIR)/manpages.xml: $(MANPAGES) xslt/manpage-summary.xsl
	mkdir -p $(@D)
	echo "<article><variablelist>" > $@
	for I in $(MANPAGES); do $(XSLTPROC) xslt/manpage-summary.xsl $$I >> $@; done
	echo "</variablelist></article>" >> $@

# HTML docs

$(HTMLDIR)/index.html: htmldocs.html
	mkdir -p $(@D)
	cp $< $@
	
$(HTMLDIR)/%/index.html: $(DOCBOOKDIR)/%.xml $(HTMLDIR)/%/samba.css  xslt/html-chunk.xsl
	mkdir -p $(@D)
	$(XSLTPROC) --stringparam base.dir "$(HTMLDIR)/$*/" xslt/html-chunk.xsl $<
	mkdir -p $(@D)/images
	$(COPY_IMAGES) html $(DOCBOOKDIR)/$*.xml $* $(@D)

# Single large HTML files
$(OUTPUTDIR)/%/samba.css: xslt/html/samba.css
	mkdir -p $(@D)
	cp $< $@

$(HTMLDIR)/%.html: $(DOCBOOKDIR)/%.xml $(HTMLDIR)/samba.css xslt/html.xsl 
	mkdir -p $(@D)/images
	$(COPY_IMAGES) html $(DOCBOOKDIR)/$*.xml $* $(@D)
	$(XSLTPROC) --output $@ xslt/html.xsl $<

# Attributions
%-attributions.xml: 
	$(XSLTPROC) --xinclude -o $@ xslt/generate-attributions.xsl $*/index.xml 

# Text files
$(TXTDIR)/%.txt: $(HTMLDIR)/%.html
	mkdir -p $(@D)
	$(HTML2TEXT) -nobs -style pretty -o $@ $<

$(TXTDIR)/%/: $(HTMLDIR)/%/index.html 
	$(MAKE) `echo $(HTMLDIR)/$*/*.html | $(PERL) -p -e 's|$(HTMLDIR)|$(TXTDIR)|g;s/\.html/\.txt/g;'`

# Tex files
%.tex: $(DOCBOOKDIR)/%.xml xslt/latex.xsl
	mkdir -p $(@D)
	$(XSLTPROC) --output $@ xslt/latex.xsl $<

latexfigures: $(LATEX_FIGURES)

$(PDFDIR)/%.pdf: %.pdf
	mkdir -p $(@D)
	cp $< $@

%.idx: %.tex latexfigures
	-$(PDFLATEX) $<

%.ind: %.idx
	$(MAKEINDEX) $<

# Adobe PDF files
%.pdf: %.tex %.ind latexfigures 
	$(MAKE) $(shell $(XSLTPROC) --stringparam prepend "" --stringparam append ".png" --stringparam role latex xslt/find-image-dependencies.xsl $(DOCBOOKDIR)/$*.xml)
	-$(PDFLATEX) $<
	$(THUMBPDF) $*.pdf
	-$(PDFLATEX) $<

# DVI files
$(DVIDIR)/%.dvi: %.dvi
	mkdir -p $(@D)
	cp $< $@

%.dvi: %.tex %.idx 
	$(MAKE) $(shell $(XSLTPROC) --stringparam prepend "" --stringparam append ".eps" --stringparam role latex xslt/find-image-dependencies.xsl $(DOCBOOKDIR)/$*.xml)
	-$(LATEX) $< 

%.png: %.dia
	$(DIA) -e $@ $<

%.eps: %.png
	$(PNGTOPNM) $< | $(PNMTOPS) > $@

# PostScript files
$(PSDIR)/%.ps: $(DVIDIR)/%.dvi
	mkdir -p $(@D)
	$(DVIPS) -o $@ $<

xslt/figures/%.pdf: xslt/figures/%.eps
	$(EPSTOPDF) $<

# Fo
$(FODIR)/%.fo: $(DOCBOOKDIR)/%.xml
	mkdir -p $(@D)
	$(XSLTPROC) --output $@ http://docbook.sourceforge.net/release/xsl/current/fo/docbook.xsl $<

# PDF thru Fo
$(FOPDFDIR)/%.pdf: $(FODIR)/%.fo
	mkdir -p $(@D)
	$(FOP) -q -d $< -pdf $@

$(HTMLHELPDIR)/%: $(DOCBOOKDIR)/%.xml
	mkdir -p $@/images
	$(COPY_IMAGES) html $(DOCBOOKDIR)/$*.xml $* $@
	$(XSLTPROC) --stringparam htmlhelp.chm $*.chm --stringparam manifest.in.base.dir "$@/" --stringparam base.dir "$@/" http://docbook.sourceforge.net/release/xsl/current/htmlhelp/htmlhelp.xsl $<

# Plucker docs
$(PLUCKERDIR)/%.pdb: $(HTMLDIR)/%.html 
	mkdir -p $(@D)
	$(PLUCKERBUILD) -v -V 2 --stayonhost --zlib-compression -f $* -p $(PLUCKERDIR) file:$< 

# Texinfo docs
$(TEXINFODIR)/%.texi: $(DOCBOOKDIR)/%.xml
	mkdir -p $(@D)
	cd $(@D) && $(DB2TEXI) $(shell pwd)/$<

$(TEXINFODIR)/%.info: $(TEXINFODIR)/%.texi
	$(MAKEINFO) --no-validate --force -o $@ "$<"

# Manpages
$(MANPAGEDIR)/smb.conf.5.xml: $(SMBDOTCONFDOC)/parameters.all.xml $(SMBDOTCONFDOC)/parameters.service.xml $(SMBDOTCONFDOC)/parameters.global.xml

$(SMBDOTCONFDOC)/parameters.all.xml: $(shell find $(SMBDOTCONFDOC) -type f -name '*.xml' -mindepth 2 | sort -t/ -k3 | xargs) $(SMBDOTCONFDOC)/generate-file-list.sh
	$(SMBDOTCONFDOC)/generate-file-list.sh $(SMBDOTCONFDOC) > $@

$(SMBDOTCONFDOC)/parameters.global.xml: $(SMBDOTCONFDOC)/parameters.all.xml $(SMBDOTCONFDOC)/generate-context.xsl
	$(XSLTPROC) --xinclude --param smb.context "'G'" --output $(SMBDOTCONFDOC)/parameters.global.xml $(SMBDOTCONFDOC)/generate-context.xsl $<

$(SMBDOTCONFDOC)/parameters.service.xml: $(SMBDOTCONFDOC)/parameters.all.xml $(SMBDOTCONFDOC)/generate-context.xsl
	$(XSLTPROC) --xinclude --param smb.context "'S'" --output $(SMBDOTCONFDOC)/parameters.service.xml $(SMBDOTCONFDOC)/generate-context.xsl $<

$(MANDIR)/%: $(DOCBOOKDIR)/%.xml xslt/man.xsl
	mkdir -p $(@D)
	$(XSLTPROC) --output $@ xslt/man.xsl $<

# Individual smb.conf parameters
smb.conf-chunks: $(patsubst $(SMBDOTCONFDOC)/%.xml,$(HTMLDIR)/smb.conf/%.html,$(wildcard $(SMBDOTCONFDOC)/*/*.xml))
	
$(HTMLDIR)/smb.conf/%.html: $(SMBDOTCONFDOC)/%.xml
	mkdir -p $(@D)
	$(XSLTPROC) --output $@ xslt/smb.conf-html.xsl $<

# Pearson compatible XML
$(PEARSONDIR)/%.xml: %/index.xml xslt/pearson.xsl
	mkdir -p $(@D)
	$(XSLTPROC) --xinclude --output $@ xslt/sambadoc2pearson.xsl $<

$(PEARSONDIR)/%.report.html: $(PEARSONDIR)/%.xml
	mkdir -p $(@D)
	-$(XMLLINT) --valid --noout $< 2> $@

# Validation verification
$(VALIDATEDIR)/%.report: %/index.xml
	mkdir -p $(@D)
	-$(XMLLINT) --xinclude --postvalid --noout $< 2> $@

# Find undocumented parameters
undocumented: $(SMBDOTCONFDOC)/parameters.all.xml scripts/find_missing_doc.pl scripts/find_missing_manpages.pl
	@$(PERL) scripts/find_missing_doc.pl $(SRCDIR)
	@$(PERL) scripts/find_missing_manpages.pl $(SRCDIR)

# Examples and the like
files: Samba-HOWTO-Collection/index.xml xslt/extract-smbfiles.xsl
	$(XSLTPROC) xslt/extract-smbfiles.xsl $< > /dev/null

samples: $(DOCBOOKDIR)/Samba-HOWTO-Collection.xml xslt/extract-examples.xsl scripts/indent-smb.conf.pl
	mkdir -p $(EXAMPLESDIR)
	$(XSLTPROC) --xinclude xslt/extract-examples.xsl $< > /dev/null 2> examples/README
	for I in examples/*.conf; do { ./scripts/indent-smb.conf.pl < $$I > $$I.tmp; mv $$I.tmp $$I; } done

# Archiving
archive: pdf
	mkdir -p $(ARCHIVEDIR)
	cp $(PDFDIR)/Samba-HOWTO-Collection.pdf $(ARCHIVEDIR)/TOSHARG-$(shell date +%Y%m%d%H%M%S).pdf
	cp $(PDFDIR)/Samba-Guide.pdf $(ARCHIVEDIR)/S3bE-$(shell date +%Y%m%d%H%M%S).pdf

# XSL scripts
xslt/html.xsl: xslt/html-common.xsl settings.xsl
xslt/html-chunk.xsl: xslt/html-common.xsl settings.xsl
xslt/latex.xsl: settings.xsl
xslt/expand-sambadoc.xsl: settings.xsl
xslt/generate-attributions.xsl: 
xslt/man.xsl:
xslt/pearson.xsl:

clobber: clean
	rm Makefile.settings settings.xsl config.status config.log configure

clean: 
	rm -rf $(OUTPUTDIR)/* $(DOCBOOKDIR)
	rm -f *.xml
	rm -f xslt/figures/*pdf
	rm -f $(SMBDOTCONFDOC)/parameters.*.xml
	rm -f $(patsubst $(DOCBOOKDIR)/%.xml,%.*,$(MAIN_DOCS))

# Always keep intermediate files if we can
.SECONDARY:
