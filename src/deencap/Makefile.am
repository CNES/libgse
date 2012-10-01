################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE de-encapsulation convenience library
################################################################################

SUBDIRS = . \
	test

noinst_LTLIBRARIES = libgse_deencap.la

sources = \
	deencap.c \
	deencap_header_ext.c

headers = \
	deencap.h

libgse_deencap_la_SOURCES = $(sources) $(headers)

INCLUDES = \
	-I$(top_srcdir)/src/common

