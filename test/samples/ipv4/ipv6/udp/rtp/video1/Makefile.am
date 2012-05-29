################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE test program
################################################################################

SUBDIRS = . \
	extension

TESTS = \
	$(top_builddir)/test/non_regression_tests.sh

TESTS_ENVIRONMENT = builddir=$(top_builddir)

EXTRA_DIST = \
	fragmented.pcap \
	refragmented.pcap \
	source.pcap
