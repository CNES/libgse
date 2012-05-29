# Process this file with autoconf to produce a configure script.
AC_INIT(gse, 1.0.1, [https://launchpad.net/libgse])
# Use tar-pax (POSIX 1003.1-2001) to handle filename longer than 99 characters
AM_INIT_AUTOMAKE([1.9 tar-pax])
AC_CONFIG_SRCDIR([src])
AM_CONFIG_HEADER([config.h])

# Disable static libraries by default
AC_DISABLE_STATIC

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h stdlib.h stdint.h string.h strings.h assert.h arpa/inet.h endian.h pthread.h])

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
AC_CHECK_FUNCS([malloc calloc free memcpy memcmp bzero pthread_mutex_lock pthread_mutex_unlock assert htonl htons ntohl ntohs pthread_join pthread_create pselect])

# check for pkg-config
PKG_PROG_PKG_CONFIG


# allow users to specify a special location for libpcap includes
AC_ARG_WITH(libpcap_includes,
            AS_HELP_STRING([--with-libpcap-includes=DIR],
                           [libpcap include directory]),
            [with_libpcap_includes="$withval"],
            [with_libpcap_includes="no"])
if test "x$with_libpcap_includes" != "xno"; then
	CPPFLAGS="${CPPFLAGS} -I${with_libpcap_includes}"
fi


# allow users to specify a special location for libpcap libraries
AC_ARG_WITH(libpcap_libraries,
            AS_HELP_STRING([--with-libpcap-libraries=DIR],
                           [libpcap library directory]),
            [with_libpcap_libraries="$withval"],
            [with_libpcap_libraries="no"])
if test "x$with_libpcap_libraries" != "xno"; then
	LDFLAGS="${LDFLAGS}  -L${with_libpcap_libraries}"
fi

# check for libpcap presence
LPCAP=""
AC_CHECK_LIB(pcap, pcap_open_offline, , LPCAP="no")
AC_CHECK_LIB(pcap, pcap_datalink, , LPCAP="no")
AC_CHECK_LIB(pcap, pcap_next, , LPCAP="no")
AC_CHECK_LIB(pcap, pcap_close, , LPCAP="no")

# abort if libpcap is not found
if test "x$LPCAP" = "xno"; then
	echo
	echo "ERROR: libpcap library/headers not found"
	echo
	echo "Go get it from http://www.tcpdump.org/ or use the --with-libpcap-* "
	echo "options, if you have it installed in unusual place. Also check if "
	echo "your libpcap depends on another shared library that may be installed "
	echo "in an unusual place."
	exit 1
fi

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
                 test/samples/internet_trafic/Makefile
                 ])

AC_OUTPUT

