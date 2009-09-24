# Process this file with autoconf to produce a configure script.
AC_INIT(gse, trunk, [Viveris Technologies])
AC_CONFIG_SRCDIR([src])
AM_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

# Disable static libraries by default
AC_DISABLE_STATIC

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([malloc calloc free memcpy memcmp bzero])

# check for pkg-config
PKG_PROG_PKG_CONFIG

AC_SUBST(AM_CFLAGS, "-g -Wall -W -Werror -Wstrict-prototypes")

AM_DEP_TRACK

AC_CONFIG_FILES([Makefile \
                 src/Makefile \
                 src/common/Makefile \
                 src/common/test/Makefile \
                 src/encap/Makefile \
                 src/encap/test/Makefile \
                 src/deencap/Makefile \
                 src/deencap/test/Makefile \
                 gse.pc \
                 app/Makefile \
                 app/tunnel/Makefile \
                 test/Makefile \
                 test/samples/Makefile \
                 test/samples/ipv4/Makefile \
                 test/samples/ipv4/icmp/Makefile \
                 test/samples/ipv4/icmp+tcp/Makefile \
                 test/samples/ipv4/ipv4/Makefile \
                 test/samples/ipv4/ipv4/icmp/Makefile \
                 test/samples/ipv4/ipv4/udp/Makefile \
                 test/samples/ipv4/ipv4/udplite/Makefile \
                 test/samples/ipv4/ipv4/udp/rtp/Makefile \
                 test/samples/ipv4/ipv4/udp/rtp/mp3/Makefile \
                 test/samples/ipv4/ipv4/udp/rtp/video1/Makefile \
                 test/samples/ipv4/ipv4/udp/rtp/video2/Makefile \
                 test/samples/ipv4/ipv6/Makefile \
                 test/samples/ipv4/ipv6/icmp/Makefile \
                 test/samples/ipv4/ipv6/udp/Makefile \
                 test/samples/ipv4/ipv6/udp/rtp/Makefile \
                 test/samples/ipv4/ipv6/udp/rtp/video1/Makefile \
                 test/samples/ipv4/ipv6/udp/rtp/video1/extension/Makefile \
                 test/samples/ipv4/ipv6/udp/rtp/video2/Makefile \
                 test/samples/ipv4/ipv6/udplite/Makefile \
                 test/samples/ipv4/udp/Makefile \
                 test/samples/ipv4/udp/rtp/Makefile \
                 test/samples/ipv4/udp/rtp/h323/Makefile \
                 test/samples/ipv4/udp/rtp/misc/Makefile \
                 test/samples/ipv4/udp/rtp/mp3/Makefile \
                 test/samples/ipv4/udp/rtp/rtp_rtp_icmp/Makefile \
                 test/samples/ipv4/udp/rtp/video1/Makefile \
                 test/samples/ipv4/udp/rtp/video2/Makefile \
                 test/samples/ipv4/udp/rtp/video3/Makefile \
                 test/samples/ipv4/udp/rtp/voip/Makefile \
                 test/samples/ipv4/udp/rtp/voip+video/Makefile \
                 test/samples/ipv4/udplite/Makefile \
                 test/samples/ipv6/Makefile \
                 test/samples/ipv6/icmp/Makefile \
                 test/samples/ipv6/icmp/extension/Makefile \
                 test/samples/ipv6/ipv6/Makefile \
                 test/samples/ipv6/ipv6/icmp/Makefile \
                 test/samples/ipv6/ipv6/icmp/extension/Makefile \
                 test/samples/ipv6/ipv6/udp/Makefile \
                 test/samples/ipv6/ipv6/udplite/Makefile \
                 test/samples/ipv6/udp/Makefile \
                 test/samples/ipv6/udp/extension/Makefile \
                 test/samples/ipv6/udp/rtp/Makefile \
                 test/samples/ipv6/udp/rtp/audio_vlc/Makefile \
                 test/samples/ipv6/udp/rtp/audio_vlc/extension/Makefile \
                 test/samples/ipv6/udp/rtp/video1/Makefile \
                 test/samples/ipv6/udp/rtp/video2/Makefile \
                 test/samples/ipv6/udplite/Makefile \
                 test/samples/ipv4fragmented/Makefile \
                 ])

AC_OUTPUT

