################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE tunnel
################################################################################

noinst_PROGRAMS = \
	gsetunnel

INCLUDES = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/encap \
	-I$(top_srcdir)/src/deencap

AM_LDFLAGS = -L$(top_srcdir)/src/

gsetunnel_SOURCES = tunnel.c
gsetunnel_LDADD = \
	-lpcap \
	-lgse
