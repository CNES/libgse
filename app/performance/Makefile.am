################################################################################
#	Name       : Makefile
#	Author     : Audric Schiltknecht <audric.schiltknecht@toulouse.viveris.com>
#	Description: create the GSE performance application
################################################################################

noinst_PROGRAMS = \
	eval_gse_trunk \
	eval_gse_no_alloc

INCLUDES = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/encap \
	-I$(top_srcdir)/src/deencap

AM_LDFLAGS = \
	-L$(top_srcdir)/src/ \
	-lpthread

eval_gse_trunk_SOURCES = eval_gse_trunk.c
eval_gse_trunk_LDADD = \
	$(top_builddir)/src/libgse.la

eval_gse_no_alloc_SOURCES = eval_gse_no_alloc.c
eval_gse_no_alloc_LDADD = \
	$(top_builddir)/src/libgse.la
