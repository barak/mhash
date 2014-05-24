#! /bin/sh

set -e

autoreconf --warning=all --install $*

echo
echo "Generation of autotools files complete."
echo "To continue build:"
echo "  ./configure"
echo "  make"
echo "  make install"
