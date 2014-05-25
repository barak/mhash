EXTRA_DIST = mhash.pod

# Debatable whether this should be dist_ or nodist_:
dist_man_MANS = mhash.3

# The date is set to nothing instead of something misleading.
# The version number would seem to suffice.
# Leaving off the --date option inserts the date of conversion, which is not so unreasonable.
# Might wish to consider some mechanism to put something informative there, like the date
# of release of the current version.
PODPARAMS=--section=3 --center="mhash library" --date=" " --release="mhash $(PACKAGE_VERSION)"

dist_doc_DATA = skid2-authentication example.c

# Debatable whether these should be dist_ or nodist_:
dist_doc_DATA += mhash.html mhash.3.txt

mhash.html: mhash.pod
	pod2html --noindex --title="mhash library" $< | sed 's/MHASH_VERSION/$(PACKAGE_VERSION)/' > $@

mhash.3.txt: mhash.3
	nroff -man $< > $@

mhash.3: mhash.pod
	pod2man $(PODPARAMS) $< | sed 's/MHASH_VERSION/$(PACKAGE_VERSION)/' > $@

MOSTLYCLEANFILES = mhash.3 mhash.html mhash.3.txt
