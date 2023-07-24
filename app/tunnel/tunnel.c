/*
 *
 * This piece of software is an implementation of the Generic Stream
 * Encapsulation (GSE) standard defined by ETSI for Linux (or other
 * Unix-compatible OS). The library may be used to add GSE
 * encapsulation/de-encapsulation capabilities to an application.
 *
 *
 * Copyright © 2016 TAS
 *
 *
 * This file is part of the GSE library.
 *
 *
 * The GSE library is free software : you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

/**
 * @file tunnel.c
 * @brief GSE tunnel
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Julien Bernard <julien.bernard@toulouse.viveris.com>
 *
 * Description
 * -----------
 *
 * The program creates a GSE tunnel over UDP. A GSE tunnel encapsulate the IP
 * packets it receives from a virtual network interface and deencapsulate the
 * GSE packets it receives from one UDP flow.
 *
 *               +-----------+                          +----------+
 * IP packets    |           |     +--------------+     |          |
 * sent by   --> |           | --> | Encapsulator | --> |          |
 * the host      |  Virtual  |     +--------------+     |   GSE    |
 *               | interface |                          |  packets |
 * IP packets    |   (TUN)   |     +--------------+     | over UDP |
 * received  <-- |           | <-- |Deencapsulator| <-- |          |
 * from the      |           |     +--------------+     |          |
 * tunnel        +-----------+                          +----------+
 *
 * The program outputs debug messages from the GSE library on stdout.
 * On error it outputs error and terminates.
 *
 * The tunnel can emulate a lossy medium with a given error rate. Unidirectional
 * mode can be forced (no feedback channel).
 *
 * Usage
 * -----
 *
 * Run the gsetunnel without any argument to see what arguments the application
 * accepts.
 *
 * Basic example
 * -------------
 *
 * Type as root on machine A:
 *
 *  # gsetunnel gse0 remote 192.168.0.20 local 192.168.0.21 port 5000
 *  # ip link set gse0 up
 *  # ip -4 addr add 10.0.0.1/24 dev gse0
 *  # ip -6 addr add 2001:eeee::1/64 dev gse0
 *
 * Type as root on machine B:
 *
 *  # gsetunnel gse0 remote 192.168.0.21 local 192.168.0.20 port 5000
 *  # ip link set gse up
 *  # ip -4 addr add 10.0.0.2/24 dev gse0
 *  # ip -6 addr add 2001:eeee::2/64 dev gse0
 *
 * Then, on machine B:
 *
 *  $ ping 10.0.0.1
 *  $ ping6 2001:eeee::1
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <signal.h>
#include <errno.h>
#include <math.h> /* for HUGE_VAL */
#include <sys/time.h>
#include <time.h>

/* TUN includes */
#include <net/if.h> /* for IFNAMSIZ */
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>

/* UDP includes */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* GSE includes */
#include "constants.h"
#include "encap.h"
#include "deencap.h"
#include "refrag.h"

/*
 * Macros & definitions:
 */

/* Return the greater value from the two */
#define MAX(x, y)  (((x) > (y)) ? (x) : (y))

/* The maximal size of data that can be received on the virtual interface */
#define TUNTAP_BUFSIZE 1518

/* The maximal size of a GSE packet */
#define MAX_GSE_SIZE  4096

/* GSE parameters */
#define QOS_NBR 4
#define FIFO_SIZE 100

/* DEBUG macro */
#define DEBUG(is_debug, out, format, ...) \
  do { \
    if(is_debug) \
      fprintf(out, format, ##__VA_ARGS__); \
  } while(0)


/*
 * Function prototypes:
 */

int tun_create(char *name);
int read_from_tun(int fd, gse_vfrag_t *vfrag);
int write_to_tun(int fd, gse_vfrag_t *vfrag);

int udp_create(struct in_addr laddr, int port);
int read_from_udp(int sock, gse_vfrag_t *vfrag);
int write_to_udp(int sock, struct in_addr raddr, int port,
                 unsigned char *packet, unsigned int length);

int tun2udp(gse_encap_t *encap,
            int from, int to,
            struct in_addr raddr, int port,
            int error, double ber, double pe2, double p2,
            int refrag, int copy);
int udp2tun(gse_deencap_t *deencap, int from, int to);

void dump_packet(char *descr, unsigned char *packet, unsigned int length);
double get_probability(char *arg, int *error);
int is_timeout(struct timeval first,
               struct timeval second,
               unsigned int max);



/*
 * Main functions:
 */


/* Whether the application should continue to live or not */
int alive;


/**
 * @brief Catch the INT, TERM and KILL signals to properly shutdown the tunnel
 *
 * @param sig  The signal caught: SIGINT, SIGTERM or SIGKILL
 */
void sighandler(int sig)
{
  fprintf(stderr, "signal %d received, terminate the process\n", sig);
  alive = 0;
}


/**
 * @brief Display the application usage
 */
void usage(void)
{
  printf("GSE tunnel: make a GSE over UDP tunnel\n\n\
usage: gsetunnel [-v] [-r] [-c] NAME remote RADDR local LADDR port PORT [error MODEL PARAMS]\n\
  -v      activate verbose mode\n\
  -r      enable refragmentation\n\
  -c      disable zero-copy\n\
  NAME    the name of the tunnel\n\
  RADDR   the IP address of the remote host\n\
  LADDR   the IP address of the local host\n\
  PORT    the UDP port to use (local and remote)\n\
  MODEL   the error model to apply (none, uniform, burst)\n\
  PARAMS  the error model parameters:\n\
            none     no extra parameter\n\
            uniform  RATE = the BER (binary error rate) to emulate\n\
            burst    PE2  = the probability to be in error state\n\
                     P2   = the probability to stay in error state\n\
example: gsetunnel -r -c gse0 remote 192.168.0.20 local 192.168.0.21 port 5000 error uniform 1e-5\n");
}


/* The sequence number for the UDP tunnel (used to discover lost packets) */
unsigned int seq;
/* The pdu and packets numbers for debug */
unsigned int pdu;
unsigned int rcv_pdu;
unsigned int nbr_pkt;
/* Debug variable */
unsigned int is_debug;


/**
 * @brief Setup a gse over UDP tunnel
 *
 * @param argc  The number of arguments given on the command line
 * @param argv  The arguments given on the command line
 * @return      0 in case of success, > 0 otherwise
 */
int main(int argc, char *argv[])
{
  int failure = 0;

  char *tun_name;
  struct in_addr raddr;
  struct in_addr laddr;
  int port;
  int error_model;
  int conv_error;
  double ber = 0;
  double pe2 = 0;
  double p2 = 0;
  int arg_count;

  int refrag = 0;
  int copy = 0;

  int ret;

  int tun, udp;

  fd_set readfds;
  struct timespec timeout;
  sigset_t sigmask;

  struct timeval last;

  gse_encap_t *encap;
  gse_deencap_t *deencap;

  int ref;

  /*
   * Parse arguments:
   */

  if(argc < 8 || argc > 15)
  {
    usage();
    goto quit;
  }
  is_debug = 0;

  /* Read options */
  for(ref = 3; ref > 0; ref--)
  {
    if(!(strcmp(argv[1], "-r")))
    {
      refrag = 1;
      argv++;
      argc--;
    }
    else if(!strcmp(argv[1], "-c"))
    {
      copy = 1;
      argv++;
      argc--;
    }
    else if(!strcmp(argv[1], "-v"))
    {
      is_debug = 1;
      argv++;
      argc--;
    }
  }


  /* get the tunnel name */
  tun_name = argv[1];

  /* get the remote IP address */
  if(strcmp(argv[2], "remote") != 0)
  {
    usage();
    goto quit;
  }
  if(!inet_aton(argv[3], &raddr))
  {
    fprintf(stderr, "bad remote IP address: %s\n", argv[3]);
    goto quit;
  }

  /* get the local IP address */
  if(strcmp(argv[4], "local") != 0)
  {
    usage();
    goto quit;
  }
  if(!inet_aton(argv[5], &laddr))
  {
    fprintf(stderr, "bad local IP address: %s\n", argv[5]);
    goto quit;
  }

  /* get the device name */
  if(strcmp(argv[6], "port") != 0)
  {
    usage();
    goto quit;
  }
  port = atoi(argv[7]);
  if(port <= 0 || port >= 0xffff)
  {
    fprintf(stderr, "bad port: %s\n", argv[7]);
    goto quit;
  }

  /* get the error model and its parameters if present */
  if(argc > 8)
  {
    if(strcmp(argv[8], "error") != 0)
    {
      usage();
      goto quit;
    }

    arg_count = 9;

    if(strcmp(argv[arg_count], "none") == 0)
    {
      /* no error model */
      fprintf(stderr, "do not emulate lossy medium\n");
      error_model = 0;
      arg_count++;
    }
    else if(strcmp(argv[arg_count], "uniform") == 0)
    {
      /* uniform error model */
      error_model = 1;
      arg_count++;

      /* check if parameters are present */
      if(argc < arg_count + 1)
      {
        usage();
        goto quit;
      }

      /* get the RATE value */
      ber = get_probability(argv[arg_count], &conv_error);
      if(conv_error != 0)
      {
        fprintf(stderr, "cannot read the RATE parameter\n");
        goto quit;
      }
      arg_count++;

      fprintf(stderr, "emulate lossy medium with %e errors/bit "
                      "= 1 error every %lu bytes\n",
              ber, (unsigned long) (1 / (ber * 8)));
    }
    else if(strcmp(argv[arg_count], "burst") == 0)
    {
      /* non-uniform/burst error model */
      error_model = 2;
      arg_count++;

      /* check if parameters are present */
      if(argc < arg_count + 2)
      {
        usage();
        goto quit;
      }

      /* get the PE2 probability */
      pe2 = get_probability(argv[arg_count], &conv_error);
      if(conv_error != 0)
      {
        fprintf(stderr, "cannot read the PE2 parameter\n");
        goto quit;
      }
      arg_count++;

      /* get the P2 probability */
      p2 = get_probability(argv[arg_count], &conv_error);
      if(conv_error != 0)
      {
        fprintf(stderr, "cannot read the P2 parameter\n");
        goto quit;
      }
      arg_count++;

      fprintf(stderr, "emulate lossy medium with PE2 = %e and P2 = %e\n",
              pe2, p2);
    }
    else
    {
      fprintf(stderr, "bad error model: %s\n", argv[arg_count]);
      goto quit;
    }
  }
  else
  {
    error_model = 0;
    arg_count = 8;
  }

  /*
   * Network interface part:
   */

  /* create virtual network interface */
  tun = tun_create(tun_name);
  if(tun < 0)
  {
    fprintf(stderr, "%s creation failed\n", tun_name);
    failure = 1;
    goto quit;
  }
  fprintf(stderr, "%s created, fd %d\n", tun_name, tun);

  /* create a UDP socket */
  udp = udp_create(laddr, port);
  if(udp < 0)
  {
    fprintf(stderr, "UDP socket creation on port %d failed\n",
            port);
    failure = 1;
    goto close_tun;
  }
  fprintf(stderr, "UDP socket created on port %d, fd %d\n",
          port, udp);
  if(copy)
  {
    fprintf(stderr, "Copy activated\n");
  }
  if(refrag)
  {
    fprintf(stderr, "Refragmentation activated\n");
  }
  if(is_debug)
  {
    fprintf(stderr, "DEBUG activated\n");
  }


  /*
   * GSE part:
   */

  /* init the GSE library */
  ret = gse_encap_init(QOS_NBR, FIFO_SIZE, &encap);
  if(ret > GSE_STATUS_OK)
  {
    fprintf(stderr, "Fail to initialize encapsulation library: %s",
            gse_get_status(ret));
    goto close_udp;
  }
  ret = gse_deencap_init(QOS_NBR, &deencap);
  if(ret > GSE_STATUS_OK)
  {
    fprintf(stderr, "Fail to initialize deencapsulation library: %s",
            gse_get_status(ret));
    goto release_encap;
  }
  /* Set offsets to take into account the 2 bits of sequence number before
   * the GSE packets if library is used with copy */
  ret = gse_encap_set_offsets(encap, 2 + GSE_MAX_REFRAG_HEAD_OFFSET, 0);
  if(ret > GSE_STATUS_OK)
  {
    fprintf(stderr, "Fail to initialize encapsulation offsets: %s",
            gse_get_status(ret));
    goto release_deencap;
  }
  /* Set offsets to take into account the bits of tun header */
  ret = gse_deencap_set_offsets(deencap, 4, 0);
  if(ret > GSE_STATUS_OK)
  {
    fprintf(stderr, "Fail to initialize de-encapsulation offsets: %s",
            gse_get_status(ret));
    goto release_deencap;
  }

  /*
   * Main program:
   */


  /* init the tunnel sequence and pdu numbers */
  seq = 0;
  pdu = 0;
  rcv_pdu = 0;
  nbr_pkt = 0;

  /* catch signals to properly shutdown the bridge */
  alive = 1;
  signal(SIGKILL, sighandler);
  signal(SIGTERM, sighandler);
  signal(SIGINT, sighandler);

  /* poll network interfaces each second */
  timeout.tv_sec = 1;
  timeout.tv_nsec = 0;

  /* mask signals during interface polling */
  sigemptyset(&sigmask);
  sigaddset(&sigmask, SIGKILL);
  sigaddset(&sigmask, SIGTERM);
  sigaddset(&sigmask, SIGINT);

  /* initialize the last time we sent a packet */
  gettimeofday(&last, NULL);

  /* tunnel each packet from the UDP socket to the virtual interface
   * and from the virtual interface to the UDP socket */
  do
  {
    /* poll the read sockets/file descriptors */
    FD_ZERO(&readfds);
    FD_SET(tun, &readfds);
    FD_SET(udp, &readfds);

    ret = pselect(MAX(tun, udp) + 1, &readfds, NULL, NULL, &timeout, &sigmask);
    if(ret < 0)
    {
      fprintf(stderr, "pselect failed: %s (%d)\n", strerror(errno), errno);
      failure = 1;
      alive = 0;
    }
    else if(ret > GSE_STATUS_OK)
    {
      /* bridge from TUN to UDP */
      if(FD_ISSET(tun, &readfds))
      {
        failure = tun2udp(encap, tun, udp, raddr, port,
                          error_model, ber, pe2, p2, refrag, copy);
        gettimeofday(&last, NULL);
#if STOP_ON_FAILURE
        if(failure)
          alive = 0;
#endif
      }

      /* bridge from UDP to TUN */
      if(
#if STOP_ON_FAILURE
         !failure &&
#endif
         FD_ISSET(udp, &readfds))
      {
        failure = udp2tun(deencap, udp, tun);
#if STOP_ON_FAILURE
        if(failure)
          alive = 0;
#endif
      }
    }
  }
  while(alive);


  /*
   * Cleaning:
   */

release_deencap:
  gse_deencap_release(deencap);
release_encap:
  gse_encap_release(encap);
close_udp:
  close(udp);
close_tun:
  close(tun);
quit:
  return failure;
}



/*
 * TUN interface:
 */


/**
 * @brief Create a virtual network interface of type TUN
 *
 * @param name  The name of the TUN interface to create
 * @return      An opened file descriptor on the TUN interface in case of
 *              success, a negative value otherwise
 */
int tun_create(char *name)
{
  struct ifreq ifr;
  int fd, err;

  /* open a file descriptor on the kernel interface */
  if((fd = open("/dev/net/tun", O_RDWR)) < 0)
    return fd;

  /* flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *        IFF_NO_PI - Do not provide packet information */
  bzero(&ifr, sizeof(ifr));
  strncpy(ifr.ifr_name, name, IFNAMSIZ);
  ifr.ifr_name[IFNAMSIZ - 1] = '\0';
  ifr.ifr_flags = IFF_TUN;

  /* create the TUN interface */
  if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
  {
    close(fd);
    return err;
  }

  return fd;
}


/**
 * @brief Read data from the TUN interface
 *
 * Data read by this function contains a 4-byte header that gives the protocol
 * of the data.
 *
 *   +-----+-----+-----+-----+
 *   |  0  |  0  |  Protocol |
 *   +-----+-----+-----+-----+
 *
 * Protocol = 0x0800 for IPv4
 *            0x86dd for IPv6
 *
 * @param fd         The TUN file descriptor to read data from
 * @param rcv_vfrag  The virtual fragment where to store the data
 * @param length     IN: the maximum length of the data
 *                   OUT: the length of the data
 * @return           0 in case of success, a non-null value otherwise
 */
int read_from_tun(int fd, gse_vfrag_t *vfrag)
{
  int ret;
  int read_length;

  read_length = read(fd, gse_get_vfrag_start(vfrag), gse_get_vfrag_length(vfrag));

  if(read_length < 0 || read_length > (int)gse_get_vfrag_length(vfrag))
  {
    fprintf(stderr, "read failed: %s (%d)\n", strerror(errno), errno);
    goto error;
  }
  ret = gse_set_vfrag_length(vfrag, read_length);
  if(ret > GSE_STATUS_OK)
  {
    fprintf(stderr, "error when setting fragment length: %s\n", gse_get_status(ret));
    goto error;
  }

  DEBUG(is_debug, stderr, "read %zu bytes on fd %d\n", gse_get_vfrag_length(vfrag), fd);

  return 0;

error:
  return 1;
}


/**
 * @brief Write data to the TUN interface
 *
 * Data written to the TUN interface must contain a 4-byte header that gives
 * the protocol of the data. See the read_from_tun function for details.
 *
 * @param fd         The TUN file descriptor to write data to
 * @param vfrag_pkt  The packet to write to the TUN interface (header included)
 * @param length     The length of the packet (header included)
 * @return           0 in case of success, a non-null value otherwise
 */
int write_to_tun(int fd, gse_vfrag_t *vfrag)
{
  int ret;

  ret = write(fd, gse_get_vfrag_start(vfrag), gse_get_vfrag_length(vfrag));
  if(ret < 0)
  {
    fprintf(stderr, "write failed: %s (%d)\n", strerror(errno), errno);
    goto error;
  }

  DEBUG(is_debug, stderr, "%d bytes written on fd %d\n", ret, fd);

  return 0;

error:
  return 1;
}


/*
 * Raw socket:
 */


/**
 * @brief Create an UDP socket
 *
 * @param laddr  The local address to bind the socket to
 * @param port   The UDP port to bind the socket to
 * @return       An opened socket descriptor on the TUN interface in case of
 *               success, a negative value otherwise
 */
int udp_create(struct in_addr laddr, int port)
{
  int sock;
  int len;
  int ret;
  struct sockaddr_in addr;

  /* create a UDP socket */
  sock = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);
  if(sock < 0)
  {
    fprintf(stderr, "cannot create the UDP socket\n");
    goto quit;
  }

  /* try to reuse the socket */
  len = 1;
  ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &len, sizeof(len));
  if(ret < 0)
  {
    fprintf(stderr, "cannot reuse the UDP socket\n");
    goto close;
  }

  /* bind the socket on given port */
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = laddr;
  addr.sin_port = htons(port);

  ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
  if(ret < 0)
  {
    fprintf(stderr, "cannot bind to UDP socket: %s (%d)\n",
            strerror(errno), errno);
    goto close;
  }

  return sock;

close:
  close(sock);
quit:
  return -1;
}


/**
 * @brief Read data from the UDP socket
 *
 * @param sock    The UDP socket descriptor to read data from
 * @param vfrag   The virtual fragment where to store the data
 * @return        0 in case of success, a non-null value otherwise
 */
int read_from_udp(int sock, gse_vfrag_t *vfrag)
{
  struct sockaddr_in addr;
  socklen_t addr_len;
  int read_length;
  int ret;

  addr_len = sizeof(struct sockaddr_in);
  bzero(&addr, addr_len);

  /* read data from the UDP socket */
  read_length = recvfrom(sock, gse_get_vfrag_start(vfrag), gse_get_vfrag_length(vfrag),
                 0, (struct sockaddr *) &addr, &addr_len);

  if(read_length < 0 || (unsigned int)read_length > gse_get_vfrag_length(vfrag))
  {
    fprintf(stderr, "recvfrom failed: %s (%d)\n", strerror(errno), errno);
    goto error;
  }

  if(read_length == 0)
    goto quit;

  ret = gse_set_vfrag_length(vfrag, read_length);
  if(ret > GSE_STATUS_OK)
  {
    fprintf(stderr, "error when setting fragment length: %s\n", gse_get_status(ret));
    goto error;
  }

  DEBUG(is_debug, stderr, "read one %zu-byte GSE packet on UDP sock %d\n",
        gse_get_vfrag_length(vfrag) - 2, sock);

quit:
  return 0;

error:
  gse_get_vfrag_length(vfrag);
  return 1;
}


/**
 * @brief Write data to the UDP socket
 *
 * All UDP packets contain a sequence number that identify the UDP packet. It
 * helps discovering lost packets (for statistical purposes). The buffer that
 * contains the GSE packet must have 2 bytes of free space at the beginning.
 * This allows the write_to_udp function to add the 2-bytes sequence number in
 * the UDP packet without allocating new memory.
 *
 * @param sock    The UDP socket descriptor to write data to
 * @param raddr   The remote address of the tunnel (ie. the address where to
 *                send the UDP datagrams)
 * @param port    The remote UDP port  where to send the UDP data
 * @param buffer  The packet to write to the UDP socket
 * @param length  The length of the packet
 * @return        0 in case of success, a non-null value otherwise
 */
int write_to_udp(int sock, struct in_addr raddr, int port,
                 unsigned char *packet, unsigned int length)
{
  struct sockaddr_in addr;
  int ret;

  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = raddr.s_addr;
  addr.sin_port = htons(port);

  /* write the tunnel sequence number at the beginning of packet */
  packet[0] = (htons(seq) >> 8) & 0xff;
  packet[1] = htons(seq) & 0xff;

  /* send the data on the UDP socket */
  ret = sendto(sock, packet, length, 0, (struct sockaddr *) &addr,
               sizeof(struct sockaddr_in));
  if(ret < 0)
  {
    fprintf(stderr, "sendto failed: %s (%d)\n", strerror(errno), errno);
    goto error;
  }

  DEBUG(is_debug, stderr, "%d bytes written on socket %d\n", length, sock);

  return 0;

error:
  return 1;
}



/*
 * Forwarding between the TUN interface and the UDP socket
 */


/**
 * @brief Forward IP packets received on the TUN interface to the UDP socket
 *
 * The function encapsulate the IP packets thanks to the GSE library before
 * sending them on the UDP socket.
 *
 * @param encap  The GSE encapsulation context
 * @param from   The TUN file descriptor to read from
 * @param to     The UDP socket descriptor to write to
 * @param raddr  The remote address of the tunnel
 * @param port   The remote port of the tunnel
 * @param error  Type of error emulation (0 = none, 1 = uniform,
 *               2 = non-uniform/burst)
 * @param ber    The BER (Binary Error Rate) to emulate (value used on first
 *               call only if error model is uniform)
 * @param pe2    The probability to be in error state (value used on first
 *               call only if error model is non-uniform)
 * @param p2     The probability to stay in error state (value used on first
 *               call only if error model is non-uniform)
 * @return       0 in case of success, a non-null value otherwise
 */
int tun2udp(gse_encap_t *encap,
            int from, int to,
            struct in_addr raddr, int port,
            int error, double ber, double pe2, double p2,
            int refrag, int copy)
{
  gse_vfrag_t *vfrag_pdu = NULL;
  gse_vfrag_t *vfrag_pkt = NULL;
  gse_vfrag_t *refrag_pkt = NULL;
  int frag_nbr;

  int is_failure = 1;
  int ret;
  int err;

  /* error emulation */
  static unsigned int dropped = 0;
  int to_drop = 0;

  /* uniform model */
  static unsigned long nb_bytes = 0;
  static unsigned long bytes_without_error = 0;

  /* non-uniform error model */
  static int is_state_drop = 0;
  static float p1 = 0;
  static struct timeval last;
  struct timeval now;

  uint8_t label_type = 0;
  uint16_t protocol;
  uint8_t label[6] = {
    [0] =  0,
    [1] =  1,
    [2] =  2,
    [3] =  3,
    [4] =  4,
    [5] =  5,
  };
  uint8_t qos = 0;

  /* init the error model variables */
  if(error > 0)
  {
    /* init uniform error model variables */
    if(error == 1 && bytes_without_error == 0)
    {
      /* find out the number of bytes without an error */
      bytes_without_error = (unsigned long) (1 / (ber * 8));
    }

    /* init non-uniform error model variables */
    if(error == 2 && p1 == 0)
    {
      /* init of the random generator */
      gettimeofday(&last, NULL);
      srand(last.tv_sec);

      /* init the probability to stay in non-error state */
      p1 = (p2 - 1) / (1 - pe2) + 2 - p2;
    }
  }

  DEBUG(is_debug, stderr, "\n");

  /* Create the PDU virtual fragment */
  ret = gse_create_vfrag(&vfrag_pdu,
                         GSE_MAX_PDU_LENGTH,
                         GSE_MAX_HEADER_LENGTH + 2, GSE_MAX_TRAILER_LENGTH);
  if(ret > GSE_STATUS_OK)
  {
    fprintf(stderr, "Error when creating PDU virtual fragment (%s)\n",
            gse_get_status(ret));
    goto error;
  }

  /* read the IP packet from the virtual interface */
  ret = read_from_tun(from, vfrag_pdu);
  if(ret != GSE_STATUS_OK)
  {
    fprintf(stderr, "read_from_tun failed\n");
    goto free_vfrag_pdu;
  }

  protocol = ntohs(*(uint16_t*)(gse_get_vfrag_start(vfrag_pdu) + 2));

  if(gse_get_vfrag_length(vfrag_pdu) == 0)
  {
    goto free_vfrag_pdu;
  }

  /* remove tun header from packet */
  ret = gse_shift_vfrag(vfrag_pdu, 4, 0);
  if(ret > GSE_STATUS_OK)
  {
    fprintf(stderr, "Error when shifting PDU: %s\n", gse_get_status(ret));
    goto free_vfrag_pdu;
  }

  /* Encapsulate the IP packet */
  DEBUG(is_debug, stderr, "encapsulate packet #%u (%zu bytes |  protocol %#.4x )\n",
        seq, gse_get_vfrag_length(vfrag_pdu), protocol);


  ret = gse_encap_receive_pdu(vfrag_pdu, encap, label, label_type, protocol, qos);
  if(ret > GSE_STATUS_OK)
  {
    fprintf(stderr, "encapsulation of packet #%u failed (%s)\n",
            seq, gse_get_status(ret));
    goto free_vfrag_pdu;
  }
  pdu++;

  /* Fragment the IP packet */
  frag_nbr = 0;
  err = 0;
  srand(time(NULL));
  while((ret != GSE_STATUS_FIFO_EMPTY) && (err < 5))
  {
    if(!copy)
    {
      ret = gse_encap_get_packet(&vfrag_pkt, encap,
                                 rand() % 1500 + 1, qos);
    }
    else
    {
      ret = gse_encap_get_packet_copy(&vfrag_pkt, encap,
                                      rand() % 1500 + 1, qos);
    }
    if((ret > GSE_STATUS_OK) && (ret != GSE_STATUS_FIFO_EMPTY))
    {
      fprintf(stderr, "Error when getting packet #%u from PDU #%u: %s\n",
              seq, pdu, gse_get_status(ret));
      err++;
    }
    else if(ret != GSE_STATUS_FIFO_EMPTY)
    {
      refrag_pkt = NULL;
      if(refrag)
      {
        ret = gse_refrag_packet(vfrag_pkt, &refrag_pkt, 2, 0, qos, rand() % 800 + 1);
        if((ret > GSE_STATUS_OK) && (ret != GSE_STATUS_REFRAG_UNNECESSARY))
        {
          fprintf(stderr, "Error when refragmenting packet #%u from PDU #%u: %s\n",
                  seq, pdu, gse_get_status(ret));
        }

        else if(ret == GSE_STATUS_OK)
        {
          DEBUG(is_debug, stderr, "Packet #%u from PDU #%u refragmented\n",
                  seq, pdu);
        }
        else if(ret == GSE_STATUS_REFRAG_UNNECESSARY)
        {
          DEBUG(is_debug, stderr, "GSE packet #%u from PDU #%u: %s\n",
                  seq, pdu, gse_get_status(ret));
        }

      }
      /* emulate lossy medium if asked to do so */
      if(error == 1) /* uniform error model */
      {
        if(nb_bytes + gse_get_vfrag_length(vfrag_pkt) >= bytes_without_error)
        {
          to_drop = 1;
          dropped++;
          fprintf(stderr, "error inserted, GSE packet #%u from PDU #%u dropped\n",
                  seq, pdu);
          nb_bytes = gse_get_vfrag_length(vfrag_pkt) -
                     (bytes_without_error - nb_bytes);
        }

        nb_bytes += gse_get_vfrag_length(vfrag_pkt);
      }
      else if(error == 2) /* non-uniform/burst error model */
      {
        /* reset to normal state if too much time between two packets */
        gettimeofday(&now, NULL);
        if(is_state_drop && is_timeout(last, now, 2))
        {
          fprintf(stderr, "go back to normal state (too much time between "
                  "packets #%u and #%u)\n", seq - 1, seq);
          is_state_drop = 0;
        }
        last = now;

        /* do we change state ? */
        int r = rand() % 1000;
        if(!is_state_drop)
          is_state_drop = (r > (int) (p1 * 1000));
        else
          is_state_drop = (r <= (int) (p2 * 1000));

        if(is_state_drop)
        {
          to_drop = 1;
          dropped++;
          fprintf(stderr, "error inserted, GSE packet #%u from PDU #%u dropped\n",
                  seq, pdu);
        }
      }

      /* write the GSE packet in the UDP tunnel if not dropped */
      if(!to_drop)
      {
        //dump_packet("SENT", gse_get_vfrag_start(vfrag_pkt), gse_get_vfrag_length(vfrag_pkt));
        ret = write_to_udp(to, raddr, port,
                           gse_get_vfrag_start(vfrag_pkt) - 2,
                           gse_get_vfrag_length(vfrag_pkt) + 2);
        if(ret != GSE_STATUS_OK)
        {
          fprintf(stderr, "write_to_udp failed\n");
          goto free_vfrag_pdu;
        }
      }
      frag_nbr++;
      /* release the fragment */
      ret = gse_free_vfrag(&vfrag_pkt);
      if(ret > GSE_STATUS_OK)
      {
        fprintf(stderr, "Error when releasing fragment #%u from PDU #%u: %s\n",
                seq, pdu, gse_get_status(ret));
      }
      /* increment the tunnel sequence number */
      seq++;

      if((refrag) && (refrag_pkt != NULL))
      {
        /* emulate lossy medium if asked to do so */
        if(error == 1) /* uniform error model */
        {
          if(nb_bytes + gse_get_vfrag_length(refrag_pkt) >= bytes_without_error)
          {
            to_drop = 1;
            dropped++;
            fprintf(stderr, "error inserted, GSE packet #%u from PDU #%u dropped\n",
                    seq, pdu);
            nb_bytes = gse_get_vfrag_length(refrag_pkt) -
                       (bytes_without_error - nb_bytes);
          }

          nb_bytes += gse_get_vfrag_length(refrag_pkt);
        }
        else if(error == 2) /* non-uniform/burst error model */
        {
          /* reset to normal state if too much time between two packets */
          gettimeofday(&now, NULL);
          if(is_state_drop && is_timeout(last, now, 2))
          {
            fprintf(stderr, "go back to normal state (too much time between "
                    "packets #%u and #%u)\n", seq - 1, seq);
            is_state_drop = 0;
          }
          last = now;

          /* do we change state ? */
          int r = rand() % 1000;
          if(!is_state_drop)
            is_state_drop = (r > (int) (p1 * 1000));
          else
            is_state_drop = (r <= (int) (p2 * 1000));

          if(is_state_drop)
          {
            to_drop = 1;
            dropped++;
            fprintf(stderr, "error inserted, GSE packet #%u from PDU #%u dropped\n",
                    seq, pdu);
          }
        }

        /* write the GSE packet in the UDP tunnel if not dropped */
        if(!to_drop)
        {
          //dump_packet("SENT REFRAG", gse_get_vfrag_start(refrag_pkt), gse_get_vfrag_length(refrag_pkt));
          ret = write_to_udp(to, raddr, port,
                             gse_get_vfrag_start(refrag_pkt) - 2,
                             gse_get_vfrag_length(refrag_pkt) + 2);
          if(ret != GSE_STATUS_OK)
          {
            fprintf(stderr, "write_to_udp failed\n");
            goto free_vfrag_pdu;
          }
        }
        frag_nbr++;
        /* release the fragment */
        ret = gse_free_vfrag(&refrag_pkt);
        if(ret > GSE_STATUS_OK)
        {
          fprintf(stderr, "Error when releasing fragment #%u from PDU #%u: %s\n",
                  seq, pdu, gse_get_status(ret));
        }
        /* increment the tunnel sequence number */
        seq++;
      }
    }
  }
  if(err > 5)
  {
    fprintf(stderr, "Two many errors when getting packet\n");
    goto free_vfrag_pdu;
  }
  if(frag_nbr > 1)
  {
    fprintf(stderr, "Send PDU #%u fragmented in %d GSE packets\n",
            pdu - 1, frag_nbr);
  }
  else
  {
    fprintf(stderr, "Send PDU #%u not fragmented\n", pdu - 1);
  }

  /* everything went fine */
  is_failure = 0;

free_vfrag_pdu:
  gse_free_vfrag(&vfrag_pdu);
error:
  return is_failure;
}

/**
 * @brief Forward GSE packets received on the UDP socket to the TUN interface
 *
 * The function deencapsulate the GSE packets thanks to the GSE library before
 * sending them on the TUN interface.
 *
 * @param deencap The GSE deencapsulation context
 * @param from    The UDP socket descriptor to read from
 * @param to      The TUN file descriptor to write to
 * @return        0 in case of success, a non-null value otherwise
 */
int udp2tun(gse_deencap_t *deencap, int from, int to)
{
  gse_vfrag_t *vfrag_pkt = NULL;
  gse_vfrag_t *pdu = NULL;

  uint8_t label_type;
  uint8_t label[6];
  uint16_t protocol;
  uint16_t gse_length;

  int ret;
  int j;
  static unsigned int max_seq = 0;
  unsigned int new_seq;
  static unsigned long lost_packets = 0;

  DEBUG(is_debug, stderr, "\n");

  ret = gse_create_vfrag(&vfrag_pkt, GSE_MAX_PACKET_LENGTH + 2, 0, 0);
  if(ret > GSE_STATUS_OK)
  {
    fprintf(stderr, "Error when creating reception fragment: %s\n",
            gse_get_status(ret));
    goto error;
  }

  /* read the sequence number + GSE packet from the UDP tunnel */
  ret = read_from_udp(from, vfrag_pkt);
  if(ret != GSE_STATUS_OK)
  {
    fprintf(stderr, "read_from_udp failed\n");
    gse_free_vfrag(&vfrag_pkt);
    goto error;
  }

  if(gse_get_vfrag_length(vfrag_pkt) <= 2)
  {
    gse_free_vfrag(&vfrag_pkt);
    goto quit;
  }

  /* find out if some GSE packets were lost between encapsulation and
   * de-encapsulation (use the tunnel sequence number) */
  new_seq = ntohs((gse_get_vfrag_start(vfrag_pkt)[0] << 8) +
                  gse_get_vfrag_start(vfrag_pkt)[1]);
  ret = gse_shift_vfrag(vfrag_pkt, 2, 0);
  if(ret != GSE_STATUS_OK)
  {
    fprintf(stderr, "Error when shifting reception fragment: %s\n",
            gse_get_status(ret));
    gse_free_vfrag(&vfrag_pkt);
    goto error;
  }
  //dump_packet("RECEIVE", gse_get_vfrag_start(vfrag_pkt), gse_get_vfrag_length(vfrag_pkt));

  if(new_seq < max_seq)
  {
    /* some packets were reordered, the packet was wrongly
     * considered as lost */
    fprintf(stderr, "GSE packet with seq = %u received after seq = %u\n",
            new_seq, max_seq);
    lost_packets--;
  }
  else if(new_seq > max_seq + 1)
  {
    /* there is a gap between sequence numbers, some packets were lost */
    fprintf(stderr, "GSE packet(s) probably lost between "
            "seq = %u and seq = %u\n", max_seq, new_seq);
    lost_packets += new_seq - (max_seq + 1);
  }
  else if(new_seq == max_seq)
  {
    /* should not append */
    fprintf(stderr, "GSE packet #%u duplicated\n", new_seq);
  }

  if(new_seq > max_seq)
  {
    /* update max sequence numbers */
    max_seq = new_seq;
  }

  /* de-encapsulate the GSE packet */
  DEBUG(is_debug, stderr, "de-encapsulate GSE packet #%u (%zu bytes)\n",
          new_seq, gse_get_vfrag_length(vfrag_pkt));

  ret = gse_deencap_packet(vfrag_pkt, deencap, &label_type, label, &protocol,
                           &pdu, &gse_length);
  if((ret > GSE_STATUS_OK) && (ret != GSE_STATUS_PDU_RECEIVED) && (ret != GSE_STATUS_DATA_OVERWRITTEN))
  {
    fprintf(stderr, "Error when de-encapsulating GSE packet #%u: %s\n",
            new_seq, gse_get_status(ret));
  }
  nbr_pkt++;

  if(ret == GSE_STATUS_DATA_OVERWRITTEN)
  {
    DEBUG(is_debug, stderr, "PDU incomplete dropped\n");
  }
  if(ret == GSE_STATUS_OK)
  {
    DEBUG(is_debug, stderr, "GSE packet #%u: packet length = %u\n", new_seq, gse_length);
  }

  if(ret == GSE_STATUS_PDU_RECEIVED)
  {
    fprintf(stderr, "PDU #%u received in %d GSE packet(s)\n", rcv_pdu, nbr_pkt);
    nbr_pkt = 0;

    DEBUG(is_debug, stderr, "Label Type: %d | Protocol: %#.4x | Label: %.2d",
            label_type, protocol, label[0]);
    for(j = 1 ; j < gse_get_label_length(label_type) ; j++)
    {
      DEBUG(is_debug, stderr, ":%.2d", label[j]);
    }
    DEBUG(is_debug, stderr, " (in hexa)\n");

    rcv_pdu++;

    ret = gse_shift_vfrag(pdu, -4, 0);
    if(ret > GSE_STATUS_OK)
    {
      fprintf(stderr, "Error when shifting PDU #%u: %s\n",
              rcv_pdu, gse_get_status(ret));
    }
    /* build the TUN header */
    gse_get_vfrag_start(pdu)[0] = 0;
    gse_get_vfrag_start(pdu)[1] = 0;
    protocol = htons(protocol);
    memcpy(&gse_get_vfrag_start(pdu)[2], &protocol, 2);

    /* write the IP packet on the virtual interface */
    ret = write_to_tun(to, pdu);
    if(ret != GSE_STATUS_OK)
    {
      fprintf(stderr, "write_to_tun failed\n");
      goto free_pdu;
    }

    gse_free_vfrag(&pdu);
  }

quit:
  return 0;

free_pdu:
    gse_free_vfrag(&pdu);
error:
  return 1;
}


/*
 * Miscellaneous functions:
 */


/**
 * @brief Display the content of a IP or GSE packet
 *
 * This function is used for debugging purposes.
 *
 * @param descr   A string that describes the packet
 * @param packet  The packet to display
 * @param length  The length of the packet to display
 */
void dump_packet(char *descr, unsigned char *packet, unsigned int length)
{
  unsigned int i;

  fprintf(stderr, "-------------------------------\n");
  fprintf(stderr, "%s (%u bytes):\n", descr, length);
  for(i = 0; i < length; i++)
  {
    if(i > 0 && (i % 16) == 0)
      fprintf(stderr, "\n");
    else if(i > 0 && (i % 8) == 0)
      fprintf(stderr, "\t");

    fprintf(stderr, "%.2x ", packet[i]);
  }
  fprintf(stderr, "\n");
  fprintf(stderr, "-------------------------------\n");
}


/**
 * @brief Get a probability number from the command line
 *
 * If error = 1, the return value is undetermined.
 *
 * @param arg    The argument from the command line
 * @param error  OUT: whether the conversion failed or not
 * @return       The probability
 */
double get_probability(char *arg, int *error)
{
  double proba;
  char *endptr;

  /* set error by default */
  *error = 1;

  /* convert from string to double */
  proba = strtod(arg, &endptr);

  /* check for conversion error */
  if(proba == 0 && endptr == arg)
  {
    if(errno == ERANGE)
      fprintf(stderr, "probability out of range (underflow): %s (%d)\n",
              strerror(errno), errno);
    else
      fprintf(stderr, "bad probability value\n");
    goto quit;
  }

  /* check for overflow */
  if(proba == HUGE_VAL)
  {
    fprintf(stderr, "probability out of range (overflow): %s (%d)\n",
            strerror(errno), errno);
    goto quit;
  }

  /* check probability value */
  if(proba < 0 || proba > 1)
  {
    fprintf(stderr, "probability must not be negative nor greater than 1\n");
    goto quit;
  }

  /* everything is fine */
  *error = 0;

quit:
  return proba;
}

/**
 * @brief Whether timeout is reached or not ?
 *
 * Timeout is reached if the differences between the two dates
 * is greater than the amount of time given as third parameter.
 *
 * @param first   The first date
 * @param second  The second date
 * @param max     The maximal amount of time between the two dates
 *                in seconds
 * @return        Whether timeout is reached or not ?
 */
int is_timeout(struct timeval first,
               struct timeval second,
               unsigned int max)
{
  unsigned int delta_sec;
  int is_timeout;

  delta_sec = second.tv_sec - first.tv_sec;

  if(delta_sec > max)
    is_timeout = 1;
  else if(delta_sec == max)
  {
    if(second.tv_usec > first.tv_usec)
      is_timeout = 1;
    else
      is_timeout = 0;
  }
  else
    is_timeout = 0;

  return is_timeout;
}
