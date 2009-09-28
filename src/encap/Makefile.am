################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE encapsulation convenience library
################################################################################

SUBDIRS = . test

noinst_LTLIBRARIES = libgse_encap.la

sources = \
	gse_encap_ctx.c \
	gse_fifo.c \
	gse_encap.c \
	gse_encap_fct.c \
	gse_refrag.c

libgse_encap_la_SOURCES = $(sources)

AM_LDFLAGS = -lpthread 

INCLUDES = \
	-I../common

