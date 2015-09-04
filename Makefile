builddir=.
top_srcdir=/usr/lib/apache2
top_builddir=${top_srcdir}
include ${top_srcdir}/build/special.mk
builddir=.

#   the used tools
APXS=apxs
APACHECTL=apachectl

#   additional defines, includes and libraries
LDFLAGS=-ldb -lcrypto -lssl
DEFS = -std=gnu99 -pedantic -Wall -Wno-format -I..

#   the default target
all: local-shared-build
