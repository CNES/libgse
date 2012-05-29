################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE common convenience library
################################################################################

SUBDIRS = . \
	test

noinst_LTLIBRARIES = libgse_common.la

sources = \
	virtual_fragment.c \
	header.c \
	status.c \
	crc.c \
	header_fields.c	
headers = \
	constants.h \
	virtual_fragment.h \
	header.h \
	status.h \
	crc.h \
	header_fields.h \
	gse_pages.h

libgse_common_la_SOURCES = $(sources) $(headers)

