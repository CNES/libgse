################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE test program
################################################################################

SUBDIRS = . samples

noinst_PROGRAMS = \
	test_encap_deencap \
	non_regression_tests

TESTS = \
	test_encap_deencap.sh

EXTRA_DIST = \
	encap_deencap_max_pdu_length.pcap \
	test_encap_deencap.sh \
	non_regression_tests.sh

INCLUDES = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/encap \
	-I$(top_srcdir)/src/deencap

AM_LDFLAGS = -L$(top_srcdir)/src/

test_encap_deencap_SOURCES = test_encap_deencap.c
test_encap_deencap_LDADD = \
	-lpcap \
	-lgse

non_regression_tests_SOURCES = non_regression_tests.c
non_regression_tests_LDADD = \
	-lpcap \
	-lgse

