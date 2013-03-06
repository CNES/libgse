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

libgse_includedir = ${includedir}/gse

libgse_include_HEADERS = \
	common/constants.h \
	common/status.h \
	common/virtual_fragment.h \
	common/header_fields.h \
	encap/encap.h \
	encap/refrag.h \
	encap/encap_header_ext.h \
	deencap/deencap.h \
	deencap/deencap_header_ext.h

