################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE de-encapsulation convenience library
################################################################################

SUBDIRS = . test

noinst_LTLIBRARIES = libgse_deencap.la

sources = \
	gse_deencap.c \
	gse_deencap_fct.c

libgse_deencap_la_SOURCES = $(sources)

INCLUDES = \
	-I../common

