################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE encapsulation test program
################################################################################

noinst_PROGRAMS = \
	test_encap \
	test_encap_copy \
	test_encap_robust \
	test_encap_length_min \
	test_encap_bad_zero_copy \
	test_fifo \
	test_refrag \
	test_refrag_robust \
	test_add_ext

TESTS_ENCAP = \
	test_encap_complete.sh \
	test_encap_complete_copy.sh \
	test_encap_frag_dflt_length.sh \
	test_encap_frag.sh \
	test_encap_frag_copy.sh \
	test_encap_frag_dflt_length_copy.sh \
	test_encap_robust.sh \
	test_encap_length_min.sh \
	test_encap_labels.sh \
	test_encap_labels_copy.sh \
	test_encap_complete_ext.sh  \
	test_encap_frag_ext.sh \
	test_add_ext.sh

TESTS_FIFO = \
	test_fifo.sh \
	test_fifo_mult.sh

TESTS_REFRAG = \
	test_refrag.sh \
	test_refrag_robust.sh \
	test_refrag_labels.sh

TESTS = \
	$(TESTS_ENCAP) \
	$(TESTS_FIFO) \
	$(TESTS_REFRAG)

EXTRA_DIST = \
	$(TESTS_ENCAP) \
	$(TESTS_FIFO) \
	$(TESTS_REFRAG) \
	input \
	output

INCLUDES = \
	-I$(top_srcdir)/src/encap \
	-I$(top_srcdir)/src/common

test_encap_SOURCES = test_encap.c
test_encap_LDADD = \
	-lpcap \
	$(top_builddir)/src/encap/libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la

test_encap_copy_SOURCES = test_encap_copy.c
test_encap_copy_LDADD = \
	-lpcap \
	$(top_builddir)/src/encap/libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la

test_encap_robust_SOURCES = test_encap_robust.c
test_encap_robust_LDADD = \
	-lpcap \
	$(top_builddir)/src/encap/libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la

test_encap_length_min_SOURCES = test_encap_length_min.c
test_encap_length_min_LDADD = \
	-lpcap \
	$(top_builddir)/src/encap/libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la

test_encap_bad_zero_copy_SOURCES = test_encap_bad_zero_copy.c
test_encap_bad_zero_copy_LDADD = \
	-lpcap \
	$(top_builddir)/src/encap/libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la

test_fifo_SOURCES = test_fifo.c
test_fifo_LDADD = \
	-lpcap \
	$(top_builddir)/src/encap/libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la

test_refrag_SOURCES = test_refrag.c
test_refrag_LDADD = \
	-lpcap \
	$(top_builddir)/src/encap/libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la

test_refrag_robust_SOURCES = test_refrag_robust.c
test_refrag_robust_LDADD = \
	-lpcap \
	$(top_builddir)/src/encap/libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la

test_add_ext_SOURCES = test_add_ext.c
test_add_ext_LDADD = \
	-lpcap \
	../libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la
