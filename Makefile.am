ACLOCAL_AMFLAGS = -I m4
SUBDIRS = include lib doc src
EXTRA_DIST = mhash.spec.in mhash.spec
USE_MHASH_CONFIG = yes

# Some git equivalent of this needs to be found.
# Something like the git-dch but not specific to Debian.
ChangeLog:
	cvs2cl --utc --fsf -t -S --prune

# Pre-CVS artifact: this generates a ChangeLog from RCS!
EXTRA_DIST += changelog-update.sh

if ENABLE_PKGCONFIG
mhash.pc:
	echo 'prefix=$(prefix)'			>  $@
	echo 'exec_prefix=$(exec_prefix)'	>> $@
	echo 'includedir=$(includedir)'		>> $@
	echo 'libdir=$(libdir)'			>> $@
	echo					>> $@
	echo 'Name: $(PACKAGE_TARNAME)'		>> $@
	echo 'Description: $(PACKAGE_NAME)'	>> $@
	echo 'URL: $(PACKAGE_URL)'		>> $@
	echo 'Version: $(PACKAGE_VERSION)'	>> $@
	echo 'Cflags: -I$(includedir)'		>> $@
	echo 'Libs: -L$(libdir) -lmhash'	>> $@
	echo 'Libs.private: $(LDFLAGS) $(LIBS)'	>> $@

pkgconfig_DATA = mhash.pc
endif

MOSTLYCLEAN = $(pkgconfig_DATA)
