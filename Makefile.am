ACLOCAL_AMFLAGS = -I m4
SUBDIRS = include lib doc src

EXTRA_DIST = autogen.sh

# Some git equivalent of this needs to be found.
# Something like the git-dch but not specific to Debian.
ChangeLog:
	cvs2cl --utc --fsf -t -S --prune

# Pre-CVS artifact: this generates a ChangeLog from RCS!
EXTRA_DIST += changelog-update.sh

# MS Windows support, include in "make dist":
EXTRA_DIST += CYGWIN-PATCHES/README CYGWIN-PATCHES/setup.hint \
 win32/libmhash/libmhash.dsp win32/mhash/mhash.dsp

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

MOSTLYCLEANFILES = mhash.pc
