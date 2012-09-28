/*
 *
 * This piece of software is an implementation of the Generic Stream
 * Encapsulation (GSE) standard defined by ETSI for Linux (or other
 * Unix-compatible OS). The library may be used to add GSE
 * encapsulation/de-encapsulation capabilities to an application.
 *
 *
 * Copyright © 2011 TAS
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

/****************************************************************************/
/**
 *   @file          non_regression_tests.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: TESTS
 *
 *   @brief         GSE non regression tests
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 * Introduction
 * ------------
 *
 * The program takes a flow of IP packets as input (in the PCAP format) and
 * tests the GSE library with them.
 *
 * Details
 * -------
 *
 * The program encapsulates the flow of IP packet and then deencapsulates
 * the GSE packets.
 * Between encapsulation and deencapsulation, the GSE packets can be
 * refragmented if the option is activated
 *
 *
 * Checks
 * ------
 *
 * The program input IP packets with deencapsulated IP packets.
 *
 * The program compares the GSE packets generated with the ones given as input
 * to the program if the save option is deactivated.
 * If the refragmentation is activated it also compares the refragmented GSE
 * packets with the ones given as input to the program.
 *
 * Output
 * ------
 *
 * The program outputs the GSE packets in a PCAP packet if the save option is
 * activated.
 * If the refragmentation is activated it also outputs the refragmented GSE
 * packets
 *
 */
/****************************************************************************/

/****************************************************************************
 *
 *   INCLUDES
 *
 *****************************************************************************/

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <net/ethernet.h>
#include <stdint.h>

/* include for the PCAP library */
#include <pcap.h>

/* GSE includes */
#include "constants.h"
#include "encap.h"
#include "deencap.h"
#include "refrag.h"

/****************************************************************************
 *
 *   MACROS AND CONSTANTS
 *
 *****************************************************************************/

/** A very simple maximum macro */
#define MAX(x, y)  (((x) > (y)) ? (x) : (y))

/** A very simple minimum macro */
#define MIN(x, y)  (((x) < (y)) ? (x) : (y))

/** The program usage */
#define TEST_USAGE \
"GSE test application: test the GSE library with a flow of IP packets\n\n\
usage: test [--verbose (-v) LEVEL] [-h] [-s] [--label-type LT] [-r REFRAG_FILENAME] -c FRAG_FILENAME -i FLOW\n\
  --verbose        Print DEBUG information level 1\n\
  LEVEL            The DEBUG level [0, 2]\n\
  -h               Print this usage and exit\n\
  -s               Save output packets instead of compare them\n\
  -r               Activate refragmentation\n\
  LT               The label_type (0, 1, 2, 3) (default: 0)\n\
  REFRAG_FILENAME  Save the refragmented packets or compare them\n\
                   with the reference packets stored in refrag_file (PCAP format)\n\
  FRAG_FILENAME    Save the fragmented packets or compare them\n\
                   with the reference packets stored in frag_file (PCAP format)\n\
  FLOW             Flow of Ethernet frames to encapsulate (PCAP format)\n"

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16

/** Number of FIFOs */
#define QOS_NBR 10
/** Size of FIFOs */
#define FIFO_SIZE 100
/** Maximum number of fragments for one PDU */
#define PKT_NBR_MAX 1000
/** Protocol to put in the protocol type field */
#define PROTOCOL 9029

/** DEBUG macro */
#define DEBUG(verbose, format, ...) \
  do { \
    if(verbose) \
      printf(format, ##__VA_ARGS__); \
  } while(0)

#define DEBUG_L2(verbose, format, ...) \
  do { \
    if(verbose > 1) \
      printf(format, ##__VA_ARGS__); \
  } while(0)

static const size_t frag_length[20] = {
  128,  0,    1024, 256,  2048, 4096, 16,   64,   1024, 512,
  256,  512,  4096, 64,   128,  1024, 2048, 512,  256,  1024,
  };

static const size_t refrag_length[20] = {
  64,   1024, 512,  128,  32,   512,  16,   16,   256,  32,
  128,  128,  2048, 16,   64,   512,  16,   128,  128,  64,
  };



/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 *****************************************************************************/

static int test_encap_deencap(int verbose, uint8_t label_type, int save,
                              char *src_filename,
                              char *frag_filename,
                              char *refrag_filename);
static int open_pcap(char *filename, int verbose, pcap_t **handle,
                     uint32_t *link_len);
static int get_gse_packets(int verbose,
                           int save,
                           gse_vfrag_t **vfrag_pkt,
                           gse_encap_t **encap,
                           pcap_t **frag_handle,
                           pcap_dumper_t **frag_dumper,
                           uint32_t link_len_frag,
                           uint32_t link_len_src,
                           unsigned char *link_layer_head,
                           int frag_length_idx,
                           uint8_t qos,
                           unsigned long pkt_nbr);
static int refrag(int verbose,
                  int save,
                  gse_vfrag_t **vfrag_pkt,
                  gse_vfrag_t **refrag_pkt,
                  pcap_t **refrag_handle,
                  pcap_dumper_t **refrag_dumper,
                  uint32_t link_len_refrag,
                  uint32_t link_len_src,
                  unsigned char *link_layer_head,
                  int refrag_length_idx,
                  uint8_t qos,
                  unsigned long pkt_nbr);
static int deencap_pkt(int verbose,
                       gse_vfrag_t *vfrag_pkt,
                       gse_vfrag_t *refrag_pkt,
                       gse_deencap_t **deencap,
                       pcap_t **cmp_handle,
                       uint32_t link_len_cmp,
                       unsigned long rcv_pkt_nbr,
                       unsigned long *rcv_tot_nbr,
                       unsigned long pdu_counter);
static int compare_packets(int verbose,
                           unsigned char *pkt1, int pkt1_size,
                           unsigned char *pkt2, int pkt2_size);


/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 *****************************************************************************/

/**
 * @brief Main function for the GSE test program
 *
 * @param argc  the number of program arguments
 * @param argv  the program arguments
 * @return      the unix return code:
 *               \li 0 in case of success,
 *               \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
  char *src_filename = NULL;
  char *frag_filename = NULL;
  char *refrag_filename = NULL;
  char *label_type = 0;
  int save = 0;
  int refrag = 0;
  int failure = 1;
  int verbose = 0;
  int ref;

  for(ref = argc; (ref > 0 && argc > 1); ref--)
  {
    if(!(strcmp(argv[1], "--verbose")) || !(strcmp(argv[1], "-v")))
    {
      verbose = 1;
      argv += 1;
      argc -= 1;
      if(argc > 1 && argv[1][0] != '-')
      {
        verbose = atoi(argv[1]);
        if((verbose < 0)  || (verbose > 2))
        {
          fprintf(stderr, "Wrong verbose value\n");
          fprintf(stderr, TEST_USAGE);
          goto quit;
        }
        argv += 1;
        argc -= 1;
      }
    }
    else if(!strcmp(argv[1], "--label-type"))
    {
      if(!argv[2])
      {
        fprintf(stderr, "Missing LT\n");
        fprintf(stderr, TEST_USAGE);
        goto quit;
      }
      label_type = argv[2];
      if(atoi(label_type) < 0 && atoi(label_type) > 3)
      {
        fprintf(stderr, "Bad Label Type\n");
        goto quit;
      }
      argv += 2;
      argc -= 2;
    }
    else if(!strcmp(argv[1], "-c"))
    {
      if(!argv[2])
      {
        fprintf(stderr, "Missing FRAG_FILENAME\n");
        fprintf(stderr, TEST_USAGE);
        goto quit;
      }
      frag_filename = argv[2];
      argv += 2;
      argc -= 2;
    }
    else if(!strcmp(argv[1], "-i"))
    {
      if(!argv[2])
      {
        fprintf(stderr, "Missing FLOW\n");
        fprintf(stderr, TEST_USAGE);
        goto quit;
      }
      src_filename = argv[2];
      argv += 2;
      argc -= 2;
    }
    else if(!strcmp(argv[1], "-h"))
    {
      fprintf(stderr, TEST_USAGE);
      goto quit;
    }
    else if(!strcmp(argv[1], "-r"))
    {
      if(!argv[2])
      {
        fprintf(stderr, "Missing REFRAG_FILENAME\n");
        fprintf(stderr, TEST_USAGE);
        goto quit;
      }
      refrag = 1;
      refrag_filename = argv[2];
      argv += 2;
      argc -= 2;
    }
    else if(!strcmp(argv[1], "-s"))
    {
      save = 1;
      argv += 1;
      argc -= 1;
    }
    else
    {
      fprintf(stderr, "unknown option %s\n", argv[1]);
      fprintf(stderr, TEST_USAGE);
       goto quit;
     }
  }

  if(!src_filename || !frag_filename)
  {
    fprintf(stderr, "missing mandatory options\n");
    fprintf(stderr, TEST_USAGE);
    goto quit;
  }

  failure = test_encap_deencap(verbose,
                               (label_type ? atoi(label_type):0),
                               save, src_filename, frag_filename,
                               refrag_filename);

quit:
  return failure;
}

/****************************************************************************
 *
 *   PRIVATE FUNCTIONS
 *
 *****************************************************************************/

/**
 * @brief Test the GSE library with a flow of IP or GSE packets to encapsulate
 *
 * @param verbose       0 for no debug messages, 1 for debug, 2 for more debug
 * @param label_type    the label type
 * @param src_filename  The name of the PCAP file that contains the source packets
 * @param gse_frag_filename  The name of the PCAP file that contains the reference packets
 *                      used for comparison
 * @return              0 in case of success, 1 otherwise
 */
static int test_encap_deencap(int verbose, uint8_t label_type, int save,
                              char *src_filename,
                              char *frag_filename,
                              char *refrag_filename)
{
  pcap_t *src_handle;
  pcap_t *frag_handle = NULL;
  pcap_t *refrag_handle = NULL;
  pcap_t *cmp_handle;
  pcap_dumper_t *frag_dumper = NULL;
  pcap_dumper_t *refrag_dumper = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  uint32_t link_len_src;
  uint32_t link_len_frag = 0;
  uint32_t link_len_refrag = 0;
  uint32_t link_len_cmp;
  struct pcap_pkthdr header;
  unsigned char *packet;
  unsigned char link_layer_head[MAX(ETHER_HDR_LEN, LINUX_COOKED_HDR_LEN)];
  int is_failure = 1;
  unsigned long counter;
  unsigned long pkt_nbr = 0;
  unsigned long tot_nbr = 0;
  unsigned long rcv_pkt_nbr = 0;
  unsigned long rcv_tot_nbr = 0;
  unsigned long pdu_counter;
  gse_encap_t *encap = NULL;
  gse_deencap_t *deencap = NULL;
  gse_vfrag_t *vfrag_pkt = NULL;
  gse_vfrag_t *refrag_pkt = NULL;
  gse_vfrag_t *pdu = NULL;
  uint8_t qos = 0;
  gse_status_t status;
  int frag_length_idx = 0;
  int refrag_length_idx = 0;

  uint8_t label[6] = {
    0, 1, 2, 3, 4, 5,
    };

  if(!save)
  {
    if(refrag_filename != NULL)
    {
      DEBUG(verbose, "Compare fragmented packets with those in %s\n"
                     "Compare refragmented packets with those in %s\n",
            frag_filename, refrag_filename);
    }
    else
    {
      DEBUG(verbose, "Compare fragmented packets with those in %s\n",
            frag_filename);
    }
  }
  else
  {
    if(refrag_filename != NULL)
    {
      DEBUG(verbose, "Save fragmented packets in %s\n"
                     "Save refragmented packets in %s\n",
                     frag_filename, refrag_filename);
    }
    else
    {
      DEBUG(verbose, "Save fragmented packets in %s\n", frag_filename);
    }
  }
  /* open the source dump file */
  if(open_pcap(src_filename, verbose, &src_handle, &link_len_src) != 0)
  {
    goto error;
  }

  if(!save)
  {
    /* open the comparison dump file for fragmented packets */
    if(open_pcap(frag_filename, verbose, &frag_handle, &link_len_frag) != 0)
    {
      goto close_input;
    }

    if(refrag_filename != NULL)
    {
      /* open the comparison dump file for refragmented packets */
      if(open_pcap(refrag_filename, verbose, &refrag_handle, &link_len_refrag) != 0)
      {
        goto close_frag_handle;
      }
    }
  }
  else /* Create PCAP file to store GSE packets */
  {
    /* open the dump file to store fragmented packets */
    frag_dumper = pcap_dump_open(src_handle, frag_filename);
    if(frag_dumper == NULL)
    {
      DEBUG(verbose, "failed to open the refragment pcap dump: %s\n", errbuf);
      goto close_input;
    }

    if(refrag_filename != NULL)
    {
      /* open the dump file to store refragmented packets */
      refrag_dumper = pcap_dump_open(src_handle, refrag_filename);
      if(refrag_dumper == NULL)
      {
        DEBUG(verbose, "failed to open the refragment pcap dump: %s\n", errbuf);
        goto close_frag_handle;
      }
    }
  }

  /* open the comparison dump file for received pdu */
  if(open_pcap(src_filename, verbose, &cmp_handle, &link_len_cmp) != 0)
  {
    goto close_refrag_handle;
  }

  /* Initialize the GSE library */
  status = gse_encap_init(QOS_NBR, FIFO_SIZE, &encap);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when initializing encapsulation (%s)\n", status,
          gse_get_status(status));
    goto close_comparison;
  }
  status = gse_deencap_init(QOS_NBR, &deencap);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when initializing deencapsulation (%s)\n", status,
          gse_get_status(status));
    goto release_encap;
  }

  /* for each packet in the dump */
  counter = 0;
  pdu_counter = 0;
  while((packet = (unsigned char *) pcap_next(src_handle, &header)) != NULL)
  {
    unsigned char *in_packet;
    size_t in_size;
    int ret;

    counter++;

    /* check Ethernet frame length */
    if(header.len <= link_len_src || header.len != header.caplen)
    {
      DEBUG(verbose, "PDU #%lu: bad PCAP packet (len = %d, caplen = %d)\n",
             counter, header.len, header.caplen);
      goto release_lib;
    }
    if(counter == 1)
    {
      memcpy(link_layer_head, packet, link_len_src);
    }

    in_packet = packet + link_len_src;
    in_size = header.len - link_len_src;

    /* Encapsulate the input packets, use in_packet and in_size as
       input */
    status = gse_create_vfrag_with_data(&pdu, in_size,
                                        GSE_MAX_HEADER_LENGTH,
                                        GSE_MAX_TRAILER_LENGTH,
                                        in_packet, in_size);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when creating virtual fragment #%lu (%s)\n",
            status, counter, gse_get_status(status));
      goto release_lib;
    }

    status = gse_encap_receive_pdu(pdu, encap, label, label_type, PROTOCOL, qos);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when receiving PDU #%lu (%s)\n", status, counter,
            gse_get_status(status));
      goto release_lib;
    }

    DEBUG_L2(verbose, "\nPDU #%lu received from source file\n", counter);

    pkt_nbr = 0; /* number of packets received in the FIFO */
    tot_nbr = 0; /* number of fragments (frag_nbr + nbr refragmentation) */
    rcv_pkt_nbr = 0;
    rcv_tot_nbr = 0;
    /* Encapsulate and deencapsulate GSE packets while a complete PDU has not been received */
    do
    {
      /* Get a GSE packet in the FIFO */
      if(get_gse_packets(verbose,
                         save,
                         &vfrag_pkt,
                         &encap,
                         &frag_handle,
                         &frag_dumper,
                         link_len_frag,
                         link_len_src,
                         link_layer_head,
                         frag_length_idx,
                         qos,
                         pkt_nbr) != 0)
      {
        goto release_lib;
      }
      pkt_nbr++;
      tot_nbr ++;
      frag_length_idx = (frag_length_idx + 1) % 20;

      /* If refragmentation is activated */
      if(refrag_filename != NULL)
      {
        /* Refragment the GSE packet */
        if(refrag(verbose,
                  save,
                  &vfrag_pkt,
                  &refrag_pkt,
                  &refrag_handle,
                  &refrag_dumper,
                  link_len_refrag,
                  link_len_src,
                  link_layer_head,
                  refrag_length_idx,
                  qos,
                  pkt_nbr) > 0)
        {
          goto release_lib;
        }
        if(refrag_pkt != NULL)
        {
          tot_nbr++;
        }
        refrag_length_idx = (refrag_length_idx + 1) % 20;
      }

      /* Deencapsualte the GSE packet (possibly refragmented) */
      ret = deencap_pkt(verbose,
                        vfrag_pkt,
                        refrag_pkt,
                        &deencap,
                        &cmp_handle,
                        link_len_cmp,
                        rcv_pkt_nbr,
                        &rcv_tot_nbr,
                        pdu_counter);
      rcv_pkt_nbr++;
      refrag_pkt = NULL;
      vfrag_pkt = NULL;
      if(ret > 0)
      {
        goto release_lib;
      }
      /* Check that the FIFO is empty when a complete PDU is received */
      if(ret == -1)
      {
         if(get_gse_packets(verbose,
                            save,
                            &vfrag_pkt,
                            &encap,
                            &frag_handle,
                            &frag_dumper,
                            link_len_frag,
                            link_len_src,
                            link_layer_head,
                            frag_length_idx,
                            qos,
                            pkt_nbr) >= 0)
        {
          DEBUG(verbose, "Error, complete PDU received while packet is not "
                "completely sent...\n");
          if(vfrag_pkt != NULL)
          {
            status = gse_free_vfrag(&vfrag_pkt);
            if(status != GSE_STATUS_OK)
            {
              DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n",
                    status, gse_get_status(status));
            }
          }
          if(refrag_pkt != NULL)
          {
            status = gse_free_vfrag(&refrag_pkt);
            if(status != GSE_STATUS_OK)
            {
              DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n",
                    status, gse_get_status(status));
            }
          }
          goto release_lib;
        }
        frag_length_idx = (frag_length_idx + 1) % 20;
      }
    }while(ret == 0);
    pdu_counter++;

    DEBUG(verbose, "PDU #%lu: %lu packet(s) refragmented %lu time(s), FIFO %d\n",
          pdu_counter, rcv_pkt_nbr, rcv_tot_nbr - rcv_pkt_nbr, qos);

    qos = (qos + 1) % QOS_NBR;
  }

  /* everything went fine */
  is_failure = 0;

release_lib:
  status = gse_deencap_release(deencap);
  if(status != GSE_STATUS_OK)
  {
    is_failure = 1;
    DEBUG(verbose, "Error %#.4x when releasing deencapsulation (%s)\n", status,
          gse_get_status(status));
  }
release_encap:
  status = gse_encap_release(encap);
  if(status != GSE_STATUS_OK)
  {
    is_failure = 1;
    DEBUG(verbose, "Error %#.4x when releasing encapsulation (%s)\n", status, gse_get_status(status));
  }
close_comparison:
  pcap_close(cmp_handle);
close_refrag_handle:
  if(refrag_filename != NULL)
  {
    if(!save)
    {
      pcap_close(refrag_handle);
    }
    else
    {
      if(refrag_dumper != NULL)
      {
        pcap_dump_close(refrag_dumper);
      }
    }
  }
close_frag_handle:
  if(!save)
  {
    pcap_close(frag_handle);
  }
  else
  {
    if(frag_dumper != NULL)
    {
      pcap_dump_close(frag_dumper);
    }
  }
close_input:
  pcap_close(src_handle);

error:
  return is_failure;
}

/**
 * @brief Open a PCAP file and check link layer parameters
 *
 * @param filename  The file name
 * @param verbose   0 for no debug messages, 1 for debug, 2 for more debug
 * @param link_len  Link layer length
 * @return          0 on success, 1 on failure
 */
static int open_pcap(char *filename, int verbose, pcap_t **handle,
                     uint32_t *link_len)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  int link_layer_type;
  int is_failure = 1;

  *handle = pcap_open_offline(filename, errbuf);
  if(*handle == NULL)
  {
    DEBUG(verbose, "failed to open the PCAP file: %s\n", errbuf);
    goto error;
  }

  /* link layer in the dump must be supported */
  link_layer_type = pcap_datalink(*handle);
  if(link_layer_type != DLT_EN10MB &&
     link_layer_type != DLT_LINUX_SLL &&
     link_layer_type != DLT_RAW)
  {
    DEBUG(verbose, "link layer type %d not supported in dump (supported = "
           "%d, %d, %d)\n", link_layer_type, DLT_EN10MB, DLT_LINUX_SLL,
           DLT_RAW);
    goto close_input;
  }

  if(link_layer_type == DLT_EN10MB)
    *link_len = ETHER_HDR_LEN;
  else if(link_layer_type == DLT_LINUX_SLL)
    *link_len = LINUX_COOKED_HDR_LEN;
  else /* DLT_RAW */
    *link_len = 0;

  is_failure = 0;
  return is_failure;

close_input:
  pcap_close(*handle);
error:
  return is_failure;
}

/**
 * @brief Get a GSE packet in the FIFO and compare or save it
 *
 * @param verbose          0 for no debug messages, 1 for debug, 2 for more debug
 * @param save             the save flag
 * @param vfrag_pkt        OUT: the virtual fragment which will contain the GSE packet
 * @param encap            the encapsulation context
 * @param frag_length_idx  the index on fragment length
 * @param frag_handle      the PCAP file which contains the GSE packets to compare
 * @pram  frag_dumper      the PCAP dump file used to store the GSE packets
 * @param link_len_frag    link layer length for fragmented packets
 * @param link_layer_head  header written in front of the packets for the PCAP file
 * @param qos              the qos value used to identify the FIFO
 * @param pkt_nbr          the number of packet got in FIFO
 * @return                 0 on success, -1 if FIFO is empty and 1 on failure
 */
static int get_gse_packets(int verbose,
                           int save,
                           gse_vfrag_t **vfrag_pkt,
                           gse_encap_t **encap,
                           pcap_t **frag_handle,
                           pcap_dumper_t **frag_dumper,
                           uint32_t link_len_frag,
                           uint32_t link_len_src,
                           unsigned char *link_layer_head,
                           int frag_length_idx,
                           uint8_t qos,
                           unsigned long pkt_nbr)
{
  struct pcap_pkthdr frag_header;
  unsigned char *frag_packet;
  struct ether_header *eth_header;
  struct pcap_pkthdr header;
  gse_status_t status;

  /* Get a packet in the FIFO */
  status = gse_encap_get_packet_copy(vfrag_pkt, *encap,
                                     frag_length[frag_length_idx], qos);
  if((status != GSE_STATUS_OK) && (status != GSE_STATUS_FIFO_EMPTY))
  {
    DEBUG(verbose, "Error %#.4x when getting packet #%lu (%s)\n",
          status, pkt_nbr + 1, gse_get_status(status));
    goto free_packet;
  }
  if(status == GSE_STATUS_OK)
  {
    DEBUG_L2(verbose, "Packet #%lu got in FIFO %u\n", pkt_nbr + 1, qos);
    /* If the save option is deactivated, the packet is compared with a reference given as input */
    if(!save)
    {
      frag_packet = (unsigned char *) pcap_next(*frag_handle, &frag_header);
      if(frag_packet == NULL)
      {
        DEBUG(verbose, "packet #%lu: no packet available for comparison\n", pkt_nbr + 1);
        goto free_packet;
      }

      /* compare the output fragmented packets with the ones given by the user */
      if(frag_header.caplen <= link_len_frag)
      {
        DEBUG(verbose, "packet #%lu: packet available for comparison but too small\n",
              pkt_nbr + 1);
        goto free_packet;
      }

      if(!compare_packets(verbose, gse_get_vfrag_start(*vfrag_pkt),
                          gse_get_vfrag_length(*vfrag_pkt),
                          frag_packet + link_len_frag,
                          frag_header.caplen - link_len_frag))
      {
        DEBUG(verbose, "packet #%lu: fragmented packet is not as attended\n", pkt_nbr + 1);
        goto free_packet;
      }
    }
    else /* The save option is activated */
    {
      if(*frag_dumper != NULL)
      {
        header.len = link_len_src + gse_get_vfrag_length(*vfrag_pkt);
        header.caplen = header.len;
        unsigned char output_frag[gse_get_vfrag_length(*vfrag_pkt) + link_len_src];
        memcpy(output_frag + link_len_src, gse_get_vfrag_start(*vfrag_pkt),
               gse_get_vfrag_length(*vfrag_pkt));
        if(link_len_src != 0)
        {
          /* Copy link layer header from source packet */
          memcpy(output_frag, link_layer_head, link_len_src);
          if(link_len_src == ETHER_HDR_LEN) /* Ethernet only */
          {
            eth_header = (struct ether_header *) output_frag;
            eth_header->ether_type = 0x162f; /* unused Ethernet ID ? */
          }
          else if(link_len_src == LINUX_COOKED_HDR_LEN) /* Linux Cooked Sockets only */
          {
            output_frag[LINUX_COOKED_HDR_LEN - 2] = 0x16;
            output_frag[LINUX_COOKED_HDR_LEN - 1] = 0x2f;
          }
        }
        pcap_dump((u_char *) (*frag_dumper), &header, output_frag);
      }
      else
      {
        DEBUG(verbose, "Fragment dumper missing\n");
        goto free_packet;
      }
    }
  }
  else
  {
    DEBUG_L2(verbose, "FIFO %u empty\n", qos);
    return -1;
  }

  return 0;

free_packet:
  status = gse_free_vfrag(vfrag_pkt);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
  }
  return 1;
}

/**
 * @brief Refragment a GSE packet and compare or save it
 *
 * @param verbose            0 for no debug messages, 1 for debug, 2 for more debug
 * @param save               the save flag
 * @param vfrag_pkt          IN: the virtual fragment which contains the GSE packet
 *                           OUT: the virtual fragment which contains the first
 *                                refragmented GSE packet
 * @param refrag_pkt         OUT: the virtual fragment which contains the second
 *                                refragmented GSE packet
 * @param refrag_length_idx  the index on fragment length
 * @param refrag_handle      the PCAP file which contains the GSE packets to compare
 * @param refrag_dumper      the PCAP dumper file used to store the GSE packets
 * @param link_len_refrag    link layer length for fragmented packets
 * @param link_layer_head    header written in front of the packets for the PCAP file
 * @param qos                the qos value used to identify the FIFO
 * @param pkt_nbr            the number of packet got in FIFO
 * @return                   0 on success, 1 on failure
 */
static int refrag(int verbose,
                  int save,
                  gse_vfrag_t **vfrag_pkt,
                  gse_vfrag_t **refrag_pkt,
                  pcap_t **refrag_handle,
                  pcap_dumper_t **refrag_dumper,
                  uint32_t link_len_refrag,
                  uint32_t link_len_src,
                  unsigned char *link_layer_head,
                  int refrag_length_idx,
                  uint8_t qos,
                  unsigned long pkt_nbr)
{
  unsigned char *refrag_packet;
  struct pcap_pkthdr refrag_header;
  struct ether_header *eth_header;
  struct pcap_pkthdr header;
  gse_status_t status;

  /* Refragment the GSE packet */
  status = gse_refrag_packet(*vfrag_pkt, refrag_pkt,
                             0, 0, qos, refrag_length[refrag_length_idx]);
  if((status != GSE_STATUS_OK) && (status != GSE_STATUS_REFRAG_UNNECESSARY))
  {
    DEBUG(verbose, "Error %#.4x when refragmenting packet #%lu (%s)\n",
          status, pkt_nbr, gse_get_status(status));
    goto free_packets;
  }

  /* If the save option is deactivated, the packets are compared with the references
   * given as input */
  if(!save)
  {
    // First fragment
    refrag_packet = (unsigned char *) pcap_next(*refrag_handle, &refrag_header);
    if(refrag_packet == NULL)
    {
      DEBUG(verbose, "packet #%lu: no packet available for comparison\n", pkt_nbr);
      goto free_packets;
    }

    /* compare the output refragmented packets with the ones given by the user */
    if(refrag_header.caplen <= link_len_refrag)
    {
      DEBUG(verbose, "packet #%lu: packet available for comparison but too small\n",
            pkt_nbr);
      goto free_packets;
    }

    if(!compare_packets(verbose, gse_get_vfrag_start(*vfrag_pkt),
                        gse_get_vfrag_length(*vfrag_pkt),
                        refrag_packet + link_len_refrag,
                        refrag_header.caplen - link_len_refrag))
    {
      DEBUG(verbose, "packet #%lu: first refragmented packet is not as attended\n", pkt_nbr);
      goto free_packets;
    }

    /* If the packet has been refragmented */
    if(*refrag_pkt != NULL)
    {
      DEBUG_L2(verbose, "packet #%lu has been refragmented\n", pkt_nbr);
      // Second fragment
      refrag_packet = (unsigned char *) pcap_next(*refrag_handle, &refrag_header);
      if(refrag_packet == NULL)
      {
        DEBUG(verbose, "packet #%lu: no packet available for comparison\n", pkt_nbr);
        goto free_packets;
      }

      /* compare the output refragmented packets with the ones given by the user */
      if(refrag_header.caplen <= link_len_refrag)
      {
        DEBUG(verbose, "packet #%lu: packet available for comparison but too small\n", pkt_nbr);
        goto free_packets;
      }

      if(!compare_packets(verbose, gse_get_vfrag_start(*refrag_pkt),
                          gse_get_vfrag_length(*refrag_pkt),
                          refrag_packet + link_len_refrag,
                          refrag_header.caplen - link_len_refrag))
      {
        DEBUG(verbose, "packet #%lu: second refragmented packet is not as attended\n",
              pkt_nbr);
        goto free_packets;
      }
    }
  }
  else /* The save option is activated */
  {
    if(*refrag_dumper != NULL)
    {
      unsigned char output_refrag_first[gse_get_vfrag_length(*vfrag_pkt) + link_len_src];
      //first fragment
      header.len = link_len_src + gse_get_vfrag_length(*vfrag_pkt);
      header.caplen = header.len;
      memcpy(output_refrag_first + link_len_src,
             gse_get_vfrag_start(*vfrag_pkt),
             gse_get_vfrag_length(*vfrag_pkt));
      if(link_len_src != 0)
      {
        //Copy link layer header from source packet
        memcpy(output_refrag_first, link_layer_head, link_len_src);
        if(link_len_src == ETHER_HDR_LEN) /* Ethernet only */
        {
          eth_header = (struct ether_header *) output_refrag_first;
          eth_header->ether_type = 0x162f; /* unused Ethernet ID ? */
        }
        else if(link_len_src == LINUX_COOKED_HDR_LEN) /* Linux Cooked Sockets only */
        {
          output_refrag_first[LINUX_COOKED_HDR_LEN - 2] = 0x16;
          output_refrag_first[LINUX_COOKED_HDR_LEN - 1] = 0x2f;
        }
      }
      pcap_dump((u_char *) (*refrag_dumper), &header, output_refrag_first);

      /* If the packet has been refragmented */
      if(*refrag_pkt != NULL)
      {
        /* second fragment */
        unsigned char output_refrag_second[gse_get_vfrag_length(*refrag_pkt) + link_len_src];
        memcpy(output_refrag_second + link_len_src, gse_get_vfrag_start(*refrag_pkt),
               gse_get_vfrag_length(*refrag_pkt));
        header.len = link_len_src + gse_get_vfrag_length(*refrag_pkt);
        header.caplen = header.len;
        if(link_len_src != 0)
        {
          /* Copy link layer header from source packet */
          memcpy(output_refrag_second, link_layer_head, link_len_src);
          if(link_len_src == ETHER_HDR_LEN) /* Ethernet only */
          {
            eth_header = (struct ether_header *) output_refrag_second;
            eth_header->ether_type = 0x162f; /* unused Ethernet ID ? */
          }
          else if(link_len_src == LINUX_COOKED_HDR_LEN) /* Linux Cooked Sockets only */
          {
            output_refrag_second[LINUX_COOKED_HDR_LEN - 2] = 0x16;
            output_refrag_second[LINUX_COOKED_HDR_LEN - 1] = 0x2f;
          }
        }
        pcap_dump((u_char *) (*refrag_dumper), &header, output_refrag_second);
      }
    }
    else
    {
      DEBUG(verbose, "Fragment dumper missing\n");
      goto free_packets;
    }
  }

  return 0;

free_packets:
  status = gse_free_vfrag(vfrag_pkt);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
  }
  status = gse_free_vfrag(refrag_pkt);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
  }
  return 1;
}

/**
 * @brief Deencapsulate one or two GSE packets
 *
 * @param verbose         0 for no debug messages, 1 for debug, 2 for more debug
 * @param save            the save flag
 * @param vfrag_pkt       IN: the virtual fragment which contains a first refragmented
 *                            GSE packet
 * @param vfrag_pkt       IN: the virtual fragment which contains a second refragmented
 *                            GSE packet
 * @param deencap         the deencapsulation context
 * @param cmp_handle      the PCAP file which contains the GSE packets to compare
 * @param link_len_cmp    link layer length for fragmented packets
 * @return                0 on success, -1 if a PDU is received, 1 on failure
 */
static int deencap_pkt(int verbose,
                       gse_vfrag_t *vfrag_pkt,
                       gse_vfrag_t *refrag_pkt,
                       gse_deencap_t **deencap,
                       pcap_t **cmp_handle,
                       uint32_t link_len_cmp,
                       unsigned long rcv_pkt_nbr,
                       unsigned long *rcv_tot_nbr,
                       unsigned long pdu_counter)
{
  uint8_t rcv_label[6];
  uint8_t label_type;
  uint16_t protocol;
  uint16_t gse_length;
  unsigned char *cmp_packet;
  struct pcap_pkthdr cmp_header;
  int j;
  int is_failure = 1;
  gse_vfrag_t *rcv_pdu = NULL;

  gse_status_t status= GSE_STATUS_OK;

  /* Deencap the GSE packet of the first fragment of the refragmented packet */
  status = gse_deencap_packet(vfrag_pkt, *deencap, &label_type, rcv_label,
                              &protocol, &rcv_pdu, &gse_length);
  if((status != GSE_STATUS_OK) && (status != GSE_STATUS_PDU_RECEIVED))
  {
    DEBUG(verbose, "Error %#.4x when deencapsulating packet #%lu (fragment 1) (%s)\n",
          status, rcv_pkt_nbr + 1, gse_get_status(status));
    goto free_packets;
  }
  vfrag_pkt = NULL;
  DEBUG_L2(verbose, "GSE packet #%lu (fragment 1) received, packet length = %d\n",
           *rcv_tot_nbr + 1, gse_length);
  *rcv_tot_nbr = *rcv_tot_nbr + 1;

  /* Deencapsulate the second fragment if the packet has been refragmented */
  if((refrag_pkt != NULL) && (status != GSE_STATUS_PDU_RECEIVED))
  {
    status = gse_deencap_packet(refrag_pkt, *deencap, &label_type, rcv_label,
                                &protocol, &rcv_pdu, &gse_length);
    if((status != GSE_STATUS_OK) && (status != GSE_STATUS_PDU_RECEIVED))
    {
      DEBUG(verbose, "Error %#.4x when deencapsulating packet #%lu (fragment 2) (%s)\n",
            status, rcv_pkt_nbr + 1, gse_get_status(status));
      goto free_refrag;
    }
    DEBUG_L2(verbose, "GSE packet #%lu (fragment 2) received, packet length = %d\n",
             *rcv_tot_nbr + 1, gse_length);
    *rcv_tot_nbr = *rcv_tot_nbr + 1;
  }

  /* A complete PDU has been received */
  if(status == GSE_STATUS_PDU_RECEIVED)
  {
    cmp_packet = (unsigned char *) pcap_next(*cmp_handle, &cmp_header);
    if(cmp_packet == NULL)
    {
      DEBUG(verbose, "PDU #%lu: no PDU available for comparison\n", pdu_counter);
      goto free_pdu;
    }

    /* compare the output packets with the ones given by the user */
    if(cmp_header.caplen <= link_len_cmp)
    {
      DEBUG(verbose, "PDU #%lu: PDU available for comparison but too small\n",
            pdu_counter);
      goto free_pdu;
    }

    if(!compare_packets(verbose, gse_get_vfrag_start(rcv_pdu), gse_get_vfrag_length(rcv_pdu),
                        cmp_packet + link_len_cmp, cmp_header.caplen - link_len_cmp))
    {
      DEBUG(verbose, "PDU #%lu: generated PDU is not as attended\n", pdu_counter);
      goto free_pdu;
    }

    DEBUG_L2(verbose, "Complete PDU #%lu:\nLabel Type: %d | Protocol: %#.4x | Label: %.2d",
             pdu_counter, label_type, protocol, rcv_label[0]);
    for(j = 1 ; j < gse_get_label_length(label_type) ; j++)
    {
      DEBUG_L2(verbose, ":%.2d", rcv_label[j]);
    }
    DEBUG_L2(verbose, " (in hexa)\n");

    if(rcv_pdu != NULL)
    {
      status = gse_free_vfrag(&rcv_pdu);
      if(status != GSE_STATUS_OK)
      {
        DEBUG(verbose, "Error %#.4x when destroying pdu (%s)\n", status, gse_get_status(status));
        goto free_pdu;
      }
    }
    is_failure = -1;
  }
  else
  {
    is_failure = 0;
  }

  return is_failure;

free_packets:
  status = gse_free_vfrag(&vfrag_pkt);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
  }
free_refrag:
  status = gse_free_vfrag(&refrag_pkt);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
  }
  return is_failure;
free_pdu:
  status = gse_free_vfrag(&rcv_pdu);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying PDU (%s)\n", status, gse_get_status(status));
  }
  return is_failure;
}


/**
 * @brief Compare two network packets and print differences if any
 *
 * @param verbose   0 for no debug messages, 1 for debug, 2 for more debug
 * @param pkt1      The first packet
 * @param pkt1_size The size of the first packet
 * @param pkt2      The second packet
 * @param pkt2_size The size of the second packet
 * @return          Whether the packets are equal or not
 */
static int compare_packets(int verbose,
                           unsigned char *pkt1, int pkt1_size,
                           unsigned char *pkt2, int pkt2_size)
{
  int valid = 1;
  int min_size;
  int i, j, k;
  char str1[4][7], str2[4][7];
  char sep1, sep2;

  min_size = pkt1_size > pkt2_size ? pkt2_size : pkt1_size;

  /* do not compare more than 180 bytes to avoid huge output */
  min_size = MIN(180, min_size);

  /* if packets are equal, do not print the packets */
  if(pkt1_size == pkt2_size && memcmp(pkt1, pkt2, pkt1_size) == 0)
    goto skip;

  /* packets are different */
  valid = 0;

  DEBUG(verbose, "------------------------------ Compare ------------------------------\n");

  if(pkt1_size != pkt2_size)
  {
    DEBUG(verbose, "packets have different sizes (%d != %d), compare only the %d "
           "first bytes\n", pkt1_size, pkt2_size, min_size);
  }

  j = 0;
  for(i = 0; i < min_size; i++)
  {
    if(pkt1[i] != pkt2[i])
    {
      sep1 = '#';
      sep2 = '#';
    }
    else
    {
      sep1 = '[';
      sep2 = ']';
    }

    sprintf(str1[j], "%c0x%.2x%c", sep1, pkt1[i], sep2);
    sprintf(str2[j], "%c0x%.2x%c", sep1, pkt2[i], sep2);

    /* make the output human readable */
    if(j >= 3 || (i + 1) >= min_size)
    {
      for(k = 0; k < 4; k++)
      {
        if(k < (j + 1))
          DEBUG(verbose, "%s  ", str1[k]);
        else /* fill the line with blanks if nothing to print */
          DEBUG(verbose, "        ");
      }

      DEBUG(verbose, "      ");

      for(k = 0; k < (j + 1); k++)
        DEBUG(verbose, "%s  ", str2[k]);

      DEBUG(verbose, "\n");

      j = 0;
    }
    else
    {
      j++;
    }
  }

  DEBUG(verbose, "----------------------- packets are different -----------------------\n");

skip:
  return valid;
}
