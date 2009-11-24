################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE virtual buffer test program
################################################################################

noinst_PROGRAMS = \
	test_vfrag \
	test_vfrag_robust

TESTS = \
	test_vfrag.sh \
	test_vfrag_robust.sh

INCLUDES = \
	-I.. 

test_vfrag_SOURCES = test_vfrag.c
test_vfrag_LDADD = ../libgse_common.la

test_vfrag_robust_SOURCES = test_vfrag_robust.c
test_vfrag_robust_LDADD = ../libgse_common.la
