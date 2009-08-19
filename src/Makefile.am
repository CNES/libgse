################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE library
################################################################################

SUBDIRS = \
	common \
	encap \
	deencap

	
lib_LTLIBRARIES = libgse.la

libgse_la_SOURCES =

libgse_la_LIBADD = \
	common/libgse_common.la \
	encap/libgse_encap.la \
	deencap/libgse_deencap.la

include_HEADERS =

