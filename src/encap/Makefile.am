################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE encapsulation convenience library
################################################################################

SUBDIRS = . \
	test

noinst_LTLIBRARIES = libgse_encap.la

sources = \
	fifo.c \
	encap.c \
	refrag.c \
	encap_header_ext.c

headers = \
	fifo.h \
	encap.h \
	refrag.h \
	encap_ctx.h \
	encap_header_ext.h


libgse_encap_la_SOURCES = $(sources) $(headers)

AM_LDFLAGS = -lpthread 

INCLUDES = \
	-I$(top_srcdir)/src/common

