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

/****************************************************************************/
/**
 *   @file          test_encap_bad_zero_copy.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: ENCAP
 *
 *   @brief         GSE encapsulation bad zero copy usage test
 *
 *   @author        Julien BERNARD / Viveris Technologies
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
usage: test [-verbose] output_value flow\n\
  verbose         Print DEBUG information\n\
  output_value    Attended output error value (see status)\n\
  frag_length     Maximal length of GSE fragments\n\
  flow            flow of Ethernet frames to encapsulate (PCAP format)\n"

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16

#define QOS_NBR 1
#define FIFO_SIZE 5
#define PROTOCOL 9029

/** DEBUG macro */
#define DEBUG(verbose, format, ...) \
  do { \
    if(verbose) \
      printf(format, ##__VA_ARGS__); \
  } while(0)

/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 *****************************************************************************/

static int test_encap(int verbose, gse_status_t output_value, size_t frag_length,
                      char *src_filename);

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
  unsigned int output_value = 0;
  size_t frag_length = 0;
  int verbose;
  int failure = 1;

  /* parse program arguments, print the help message in case of failure */
  if((argc < 4) || (argc > 5))
  {
    printf(TEST_USAGE);
    goto quit;
  }

  if(argc == 4)
  {
    output_value = strtol(argv[1], NULL, 16);
    frag_length = atoi(argv[2]);
    src_filename = argv[3];
    verbose = 0;
  }
  if(argc == 5)
  {
    if(strcmp(argv[1], "verbose"))
    {
      printf(TEST_USAGE);
      goto quit;
    }
    output_value = strtoul(argv[2], NULL, 16);
    frag_length = atoi(argv[3]);
    src_filename = argv[4];
    verbose = 1;
  }
  failure = test_encap(verbose, output_value, frag_length, src_filename);

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
 * @param verbose       0 for no debug messages, 1 for debug
 * @param output_value  The status code attended
 * @param frag_length   Maximum length of fragments
 * @param src_filename  The name of the PCAP file that contains the source packets
 * @return              0 in case of success, 1 otherwise
 */
static int test_encap(int verbose, gse_status_t output_value, size_t frag_length,
                      char *src_filename)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  int link_layer_type_src;
  uint32_t link_len_src;
  struct pcap_pkthdr header;
  unsigned char *packet;
  int is_failure = 1;
  unsigned long counter;
  gse_encap_t *encap = NULL;
  gse_vfrag_t *vfrag_pkt[2];
  uint8_t label[6];
  gse_vfrag_t *pdu = NULL;
  int i;
  gse_status_t status;
  uint8_t qos = 0;
  int pkt_nbr;

  vfrag_pkt[0] = NULL;
  vfrag_pkt[1] = NULL;

  DEBUG(verbose, "Tested output status %#.4x (%s)\n", output_value, gse_get_status(output_value));
  /* open the source dump file */
  handle = pcap_open_offline(src_filename, errbuf);
  if(handle == NULL)
  {
    DEBUG(verbose, "failed to open the source pcap file: %s\n", errbuf);
    goto error;
  }

  /* link layer in the source dump must be supported */
  link_layer_type_src = pcap_datalink(handle);
  if(link_layer_type_src != DLT_EN10MB &&
     link_layer_type_src != DLT_LINUX_SLL &&
     link_layer_type_src != DLT_RAW)
  {
    DEBUG(verbose, "link layer type %d not supported in source dump (supported = "
           "%d, %d, %d)\n", link_layer_type_src, DLT_EN10MB, DLT_LINUX_SLL,
           DLT_RAW);
    goto close_input;
  }

  if(link_layer_type_src == DLT_EN10MB)
    link_len_src = ETHER_HDR_LEN;
  else if(link_layer_type_src == DLT_LINUX_SLL)
    link_len_src = LINUX_COOKED_HDR_LEN;
  else /* DLT_RAW */
    link_len_src = 0;

  /* Initialize the GSE library */
  status = gse_encap_init(QOS_NBR, FIFO_SIZE, &encap);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when initializing library (%s)\n", status, gse_get_status(status));
    goto close_input;
  }

  /* for each packet in the dump */
  counter = 0;
  while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
  {
    unsigned char *in_packet;
    size_t in_size;

    counter++;

    /* check Ethernet frame length */
    if(header.len <= link_len_src || header.len != header.caplen)
    {
      DEBUG(verbose, "packet #%lu: bad PCAP packet (len = %d, caplen = %d)\n",
             counter, header.len, header.caplen);
      goto check_status;
    }

    in_packet = packet + link_len_src;
    in_size = header.len - link_len_src;

    /* Encapsulate the input packets, use in_packet and in_size as
       input */
    for(i=0 ; i<6 ; i++)
      label[i] = i;
    status = gse_create_vfrag_with_data(&pdu, in_size,
                                        GSE_MAX_HEADER_LENGTH,
                                        GSE_MAX_TRAILER_LENGTH,
                                        in_packet, in_size);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when creating virtual fragment (%s)\n", status, gse_get_status(status));
      goto check_status;
    }
    status = gse_encap_receive_pdu(pdu, encap, label, 0, PROTOCOL, qos);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when encapsulating pdu (%s)\n", status, gse_get_status(status));
      goto check_status;
    }
  }

  /* get next GSE packet from the comparison dump file */
  /* The following might be done several times in case of fragmentation */
  pkt_nbr = 0;
  do{
    status = gse_encap_get_packet(&vfrag_pkt[pkt_nbr], encap, frag_length, qos);
    if((status != GSE_STATUS_OK) && (status != GSE_STATUS_FIFO_EMPTY))
    {
      DEBUG(verbose, "Error %#.4x when getting packet (%s)\n", status, gse_get_status(status));
      goto free_vfrag;
    }
    pkt_nbr++;
  }while((status != GSE_STATUS_FIFO_EMPTY) && (pkt_nbr < 2));

  /* everything went fine */
  is_failure = 0;

free_vfrag:
  for(i = 0 ; i < pkt_nbr ; i++)
  {
    if(vfrag_pkt[i] != NULL)
    {
      gse_free_vfrag(&vfrag_pkt[i]);
    }
  }
check_status:
  if(status == output_value)
  {
    is_failure = 0;
  }
  else
  {
    is_failure = 1;
  }
  status = gse_encap_release(encap);
  if(status != GSE_STATUS_OK)
  {
    is_failure = 1;
    DEBUG(verbose, "Error %#.4x when releasing library (%s)\n", status, gse_get_status(status));
  }
close_input:
  pcap_close(handle);
error:
  return is_failure;
}
