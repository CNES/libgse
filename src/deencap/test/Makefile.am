################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE deencapsulation test program
################################################################################

noinst_PROGRAMS = \
	test_deencap

TESTS = \
	test_deencap_complete.sh \
	test_deencap_frag.sh

INCLUDES = \
	-I.. \
	-I$(top_srcdir)/src/common

test_deencap_SOURCES = test_deencap.c
test_deencap_LDADD = \
  -lpcap \
	../libgse_deencap.la \
	$(top_builddir)/src/common/libgse_common.la

