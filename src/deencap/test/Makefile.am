################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE deencapsulation test program
################################################################################

check_PROGRAMS = \
	test_deencap \
	test_deencap_interleaving \
	test_deencap_fault \
	test_deencap_timeout

TESTS_DEENCAP = \
	test_deencap_complete.sh \
	test_deencap_frag.sh \
	test_deencap_complete_ext.sh \
	test_deencap_frag_ext.sh \
	test_deencap_interleaving.sh \
	test_deencap_incomplete_pdu_overwritten.sh \
	test_deencap_padding.sh \
	test_deencap_timeout.sh \
	test_deencap_fault.sh \
	test_deencap_labels.sh

TESTS = \
	$(TESTS_DEENCAP)

EXTRA_DIST = \
	$(TESTS_DEENCAP) \
	input \
	output

INCLUDES = \
	-I$(top_srcdir)/src/deencap \
	-I$(top_srcdir)/src/common

test_deencap_SOURCES = test_deencap.c
test_deencap_LDADD = \
	-lpcap \
	$(top_builddir)/src/deencap/libgse_deencap.la \
	$(top_builddir)/src/common/libgse_common.la

test_deencap_interleaving_SOURCES = test_deencap_interleaving.c
test_deencap_interleaving_LDADD = \
	-lpcap \
	$(top_builddir)/src/deencap/libgse_deencap.la \
	$(top_builddir)/src/common/libgse_common.la

test_deencap_fault_SOURCES = test_deencap_fault.c
test_deencap_fault_LDADD = \
	-lpcap \
	$(top_builddir)/src/deencap/libgse_deencap.la \
	$(top_builddir)/src/common/libgse_common.la

test_deencap_timeout_SOURCES = test_deencap_timeout.c
test_deencap_timeout_LDADD = \
	-lpcap \
	$(top_builddir)/src/deencap/libgse_deencap.la \
	$(top_builddir)/src/common/libgse_common.la

