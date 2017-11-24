################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE virtual buffer test program
################################################################################

check_PROGRAMS = \
	test_vfrag \
	test_vfrag_robust \
	test_header_access

SCRIPTS_SH = \
	test_vfrag.sh \
	test_vfrag_robust.sh \
	test_header_access.sh
	

TESTS = \
	$(SCRIPTS_SH)

EXTRA_DIST = \
	$(SCRIPTS_SH) \
	input

INCLUDES = \
	-I$(top_srcdir)/src/common/ 

test_vfrag_SOURCES = test_vfrag.c
test_vfrag_LDADD = $(top_builddir)/src/common/libgse_common.la

test_vfrag_robust_SOURCES = test_vfrag_robust.c
test_vfrag_robust_LDADD = $(top_builddir)/src/common/libgse_common.la

test_header_access_SOURCES = test_header_access.c
test_header_access_LDADD = \
	-lpcap \
	$(top_builddir)/src/common/libgse_common.la
