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
	refrag.c

libgse_encap_la_SOURCES = $(sources)

AM_LDFLAGS = -lpthread 

INCLUDES = \
	-I../common

