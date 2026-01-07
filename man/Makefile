all: certspotter-script.8 certspotter.8 certspotter-authorize.8

%.8: %.md
	lowdown -s -Tman \
		-M title:$(basename $(notdir $@)) \
		-M section:$(subst .,,$(suffix $@)) \
		-M date:$(if $(SOURCE_DATE_EPOCH),$(shell date -I -u -d "@$(SOURCE_DATE_EPOCH)"),$(shell date -I -u)) \
		-o $@ $<

