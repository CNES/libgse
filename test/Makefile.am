################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE test program
################################################################################

noinst_PROGRAMS = test

INCLUDES = \
	-I../src/common \
	-I../src/encap \
	-I../src/deencap

AM_LDFLAGS = -L../src/.libs

test_SOURCES = test.c

test_LDADD = \
	-lpcap \
	-lgse

