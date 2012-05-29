################################################################################
#	Name       : Makefile
#	Author     : Didier Barvaux <didier.barvaux@toulouse.viveris.com>
#	Description: create the GSE tunnel
################################################################################

noinst_PROGRAMS = \
	gsetunnel \
	gsetunnel_thread

INCLUDES = \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/encap \
	-I$(top_srcdir)/src/deencap

AM_LDFLAGS = \
	-L$(top_srcdir)/src/ \
	-lpthread

gsetunnel_SOURCES = tunnel.c
gsetunnel_LDADD = \
	$(top_builddir)/src/libgse.la \
	-lpcap

gsetunnel_thread_SOURCES = tunnel_thread.c
gsetunnel_thread_LDADD = \
	$(top_builddir)/src/libgse.la \
	-lpcap
