AUTOMAKE_OPTIONS = foreign

SUBDIRS = doc

noinst_HEADERS = gosthash.h mhash_crc32.h mhash_md5.h mhash_tiger.h rmd160.h libdefs.h mhash_haval.h mhash_sha1.h rmd128.h
 
include_HEADERS = mhash.h

lib_LTLIBRARIES = libmhash.la

libmhash_la_SOURCES = mhash.c swap.c bzero.c crc32.c md5.c sha1.c haval.c \
		rmd128.c rmd160.c tiger.c tiger_sboxes.c gosthash.c crc-32b.c

libmhash_la_LDFLAGS = -version-info 1 -export-symbols $(srcdir)/libmhash.sym

EXTRA_DIST = hash_test.sh libmhash.sym

TESTS = hash_test.sh hmac_test

hmac_test_SOURCES = hmac_test.c
hmac_test_LDADD = libmhash.la

noinst_PROGRAMS = driver hmac_test

driver_SOURCES = driver.c
driver_LDADD = libmhash.la

dist-hook:
	find $(distdir) -name CVS -o -name .cvsignore | xargs rm -rf
