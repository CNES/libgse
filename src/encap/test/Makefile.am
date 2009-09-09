################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE encapsulation test program
################################################################################

noinst_PROGRAMS = \
	test_encap \
	test_encap_copy \
	test_fifo \
	test_refrag

TESTS = \
	test_encap_complete.sh \
	test_encap_complete_copy.sh \
	test_encap_frag_dflt_length.sh \
	test_encap_frag_dflt_length_copy.sh \
	test_encap_frag.sh \
	test_encap_frag_copy.sh \
	test_fifo.sh \
	test_fifo_mult.sh \
	test_refrag.sh

INCLUDES = \
	-I.. \
	-I$(top_srcdir)/src/common

test_encap_SOURCES = test_encap.c
test_encap_LDADD = \
	-lpcap \
	../libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la

test_encap_copy_SOURCES = test_encap_copy.c
test_encap_copy_LDADD = \
	-lpcap \
	../libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la

test_fifo_SOURCES = test_fifo.c
test_fifo_LDADD = \
	-lpcap \
	../libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la

test_refrag_SOURCES = test_refrag.c
test_refrag_LDADD = \
	-lpcap \
	../libgse_encap.la \
	$(top_builddir)/src/common/libgse_common.la

