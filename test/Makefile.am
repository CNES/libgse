################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE test program
################################################################################

SUBDIRS = . \
	samples

noinst_PROGRAMS = \
	test_encap_deencap \
	non_regression_tests

TESTS = \
	test_encap_deencap.sh

INCLUDES = \
	-I../src/common \
	-I../src/encap \
	-I../src/deencap

AM_LDFLAGS = -L../src/

test_encap_deencap_SOURCES = test_encap_deencap.c
test_encap_deencap_LDADD = \
	-lpcap \
	-lgse

non_regression_tests_SOURCES = non_regression_tests.c
non_regression_tests_LDADD = \
	-lpcap \
	-lgse

