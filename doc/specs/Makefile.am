#
# Copyright (c) 2005, 2006, 2010 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = draft-morgan-pam-current.txt *~

EXTRA_DIST = draft-morgan-pam.raw std-agent-id.raw rfc86.0.txt

draft-morgan-pam-current.txt: padout draft-morgan-pam.raw
	./padout < $(srcdir)/draft-morgan-pam.raw > draft-morgan-pam-current.txt

AM_YFLAGS = -d

CC = @CC_FOR_BUILD@
CFLAGS = @BUILD_CFLAGS@
LDFLAGS = @BUILD_LDFLAGS@

BUILT_SOURCES = parse_y.h

noinst_PROGRAMS = padout

padout_SOURCES = parse_l.l parse_y.y

padout_LDADD = @LEXLIB@

doc_DATA = draft-morgan-pam-current.txt rfc86.0.txt
