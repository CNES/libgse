################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE deencapsulation test program
################################################################################

noinst_PROGRAMS = \
	test_deencap \
	test_deencap_fault \
	test_deencap_timeout

TESTS = \
	test_deencap_complete.sh \
	test_deencap_frag.sh \
	test_deencap_interleaving.sh \
	test_deencap_incomplete_pdu_overwritten.sh \
	test_deencap_padding.sh \
	test_deencap_fault.sh

INCLUDES = \
	-I.. \
	-I$(top_srcdir)/src/common

test_deencap_SOURCES = test_deencap.c
test_deencap_LDADD = \
  -lpcap \
	../libgse_deencap.la \
	$(top_builddir)/src/common/libgse_common.la

test_deencap_fault_SOURCES = test_deencap_fault.c
test_deencap_fault_LDADD = \
  -lpcap \
	../libgse_deencap.la \
	$(top_builddir)/src/common/libgse_common.la

test_deencap_timeout_SOURCES = test_deencap_timeout.c
test_deencap_timeout_LDADD = \
  -lpcap \
	../libgse_deencap.la \
	$(top_builddir)/src/common/libgse_common.la

