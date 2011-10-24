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
 *   @file         test_header_access.c 
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: COMMON
 *
 *   @brief         GSE header access tests
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
#include "header_fields.h"
#include "status.h"

/****************************************************************************
 *
 *   MACROS AND CONSTANTS
 *
 *****************************************************************************/

/** The program usage */
#define TEST_USAGE \
"GSE test application: test the GSE header acces with a flow of packets\n\n\
usage: test [-verbose] src_file \n\
  verbose         Print DEBUG information\n\
  src_file        the flow of packets\n"

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16

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

static int test_header_access(int verbose, char *src_filename);
static int check_header_fields(int verbose, int counter, unsigned char *in_packet);
static void dump_packet(char *descr, unsigned char *packet, unsigned int length);

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
  int failure = 1;
  int verbose = 0;

  /* parse program arguments, print the help message in case of failure */
  if((argc < 2) || (argc > 3))
  {
    printf(TEST_USAGE);
  }
  else
  {
    if(argc == 2)
    {
      src_filename = argv[1];
    }
    else if(argc == 3)
    {
      if(strcmp(argv[1], "verbose"))
      {
        printf(TEST_USAGE);
        goto quit;
      }
      verbose = 1;
      src_filename = argv[2];
    }
    failure = test_header_access(verbose, src_filename);
  }

quit:
  return failure;
}

/****************************************************************************
 *
 *   PRIVATE FUNCTIONS
 *
 *****************************************************************************/

/**
 * @brief Test the haeder access in a flow of GSE packets
 *
 * @param verbose       0 for no debug messages, 1 for debug
 * @param src_filename  The name of the PCAP file that contains 4 source packets
 * @return              0 in case of success, 1 otherwise
 */
static int test_header_access(int verbose, char *src_filename)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  int link_layer_type_src;
  uint32_t link_len_src;
  struct pcap_pkthdr header;
  unsigned char *packet;
  int is_failure = 1;
  unsigned int counter = 0;
  unsigned char *in_packet = NULL;
  unsigned int in_size = 0;


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
    DEBUG(verbose, "link layer type %u not supported in source dump (supported = "
           "%u, %u, %u)\n", link_layer_type_src, DLT_EN10MB, DLT_LINUX_SLL,
           DLT_RAW);
    goto close_input;
  }

  if(link_layer_type_src == DLT_EN10MB)
    link_len_src = ETHER_HDR_LEN;
  else if(link_layer_type_src == DLT_LINUX_SLL)
    link_len_src = LINUX_COOKED_HDR_LEN;
  else /* DLT_RAW */
    link_len_src = 0;

  /* for each packet in the dump */
  while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
  {

    counter++;
    if(counter > 4)
    {
       DEBUG(verbose, "Too much packet in PCAP capture !\n");
       goto close_input;
    }

    /* check Ethernet frame length */
    if(header.len <= link_len_src || header.len != header.caplen)
    {
      DEBUG(verbose, "packet #%u: bad PCAP packet (len = %u, caplen = %u)\n",
             counter - 1, header.len, header.caplen);
      goto close_input;
    }

    in_packet = packet + link_len_src;
    in_size = header.len - link_len_src;

    if(check_header_fields(verbose, counter, in_packet) != 0)
    {
      is_failure = 1;
      goto close_input;
    }
  }

  /* everything went fine */
  is_failure = 0;

close_input:
  if(is_failure && in_packet != NULL && verbose)
  {
    char desc[10];
    sprintf(desc, "packet #%u", counter - 1);
    dump_packet(desc, in_packet, in_size);
  }
  pcap_close(handle);
error:
  return is_failure;
}

/**
 * @brief Check the header fields content
 *
 * @param verbose    The verbose flag
 * @param in_packet  The GSE packet to check
 * @return           0 on success, 1 on failure
 */
static int check_header_fields(int verbose, int counter, unsigned char *in_packet)
{
  uint8_t s_ref[4] = {1, 1, 0, 0};
  uint8_t e_ref[4] = {1, 0, 0, 1};
  uint8_t lt_ref[4] = {0, 0, 3, 3};
  uint16_t gse_length_ref[4] = {112, 37, 37, 37};
  uint8_t frag_id_ref[4] = {0, 0, 1, 2};
  uint16_t total_length_ref[4] = {0, 102, 0, 0};
  uint16_t protocol_type_ref[4] = {9029, 10000, 0, 0};
  uint8_t label_ref[4][6] = {{0, 1, 2, 3, 4, 5},
                             {5, 4, 3, 2, 1, 0},
                             {0, 0, 0, 0, 0, 0},
                             {0, 0, 0, 0, 0, 0}};

  uint8_t s;
  uint8_t e;
  uint8_t lt;
  uint16_t gse_length;
  uint8_t frag_id;
  uint16_t total_length;
  uint16_t protocol_type;
  uint8_t label[6];
  gse_status_t status;

  /* Check start indicator */
  status = gse_get_start_indicator(in_packet, &s);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error when getting start indicator in packet #%u (%s)\n",
           counter - 1, gse_get_status(status));
    goto error;
  }
  if(s != s_ref[counter - 1])
  {
    DEBUG(verbose, "Bad start indicator value in packet #%u (%u instead of %u)\n",
           counter - 1, s, s_ref[counter - 1]);
    goto error;
  }

  /* Check end indicator */
  status = gse_get_end_indicator(in_packet, &e);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error when getting end indicator in packet #%u (%s)\n",
           counter - 1, gse_get_status(status));
    goto error;
  }
  if(e != e_ref[counter - 1])
  {
    DEBUG(verbose, "Bad end indicator value in packet #%u (%u instead of %u)\n",
           counter - 1, e, e_ref[counter - 1]);
    goto error;
  }

  /* Check label type */
  status = gse_get_label_type(in_packet, &lt);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error when getting label type in packet #%u (%s)\n",
           counter - 1, gse_get_status(status));
    goto error;
  }
  if(lt != lt_ref[counter - 1])
  {
    DEBUG(verbose, "Bad label type value in packet #%u (%u instead of %u)\n",
           counter - 1, lt, lt_ref[counter - 1]);
    goto error;
  }

  /* Check gse length */
  status = gse_get_gse_length(in_packet, &gse_length);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error when getting gse length in packet #%u (%s)\n",
           counter - 1, gse_get_status(status));
    goto error;
  }
  if(gse_length != gse_length_ref[counter - 1])
  {
    DEBUG(verbose, "Bad gse length value in packet #%u (%u instead of %u)\n",
           counter - 1, gse_length, gse_length_ref[counter - 1]);
    goto error;
  }

  /* Check frag id */
  status = gse_get_frag_id(in_packet, &frag_id);
  if(status != GSE_STATUS_OK && status != GSE_STATUS_FIELD_ABSENT)
  {
    DEBUG(verbose, "Error when getting frag_id in packet #%u (%s)\n",
           counter - 1, gse_get_status(status));
    goto error;
  }
  if(status != GSE_STATUS_FIELD_ABSENT &&
     frag_id != frag_id_ref[counter - 1])
  {
    DEBUG(verbose, "Bad frag_id value in packet #%u (%u instead of %u)\n",
           counter - 1, frag_id, frag_id_ref[counter - 1]);
    goto error;
  }

  /* Check total length */
  status = gse_get_total_length(in_packet, &total_length);
  if(status != GSE_STATUS_OK && status != GSE_STATUS_FIELD_ABSENT)
  {
    DEBUG(verbose, "Error when getting total_length in packet #%u (%s)\n",
           counter - 1, gse_get_status(status));
    goto error;
  }
  if(status != GSE_STATUS_FIELD_ABSENT &&
     total_length != total_length_ref[counter - 1])
  {
    DEBUG(verbose, "Bad total_length value in packet #%u (%u instead of %u)\n",
           counter - 1, total_length, total_length_ref[counter - 1]);
    goto error;
  }

  /* Check protocol type */
  status = gse_get_protocol_type(in_packet, &protocol_type);
  if(status != GSE_STATUS_OK && status != GSE_STATUS_FIELD_ABSENT)
  {
    DEBUG(verbose, "Error when getting protocol_type in packet #%u (%s)\n",
           counter - 1, gse_get_status(status));
    goto error;
  }
  if(status != GSE_STATUS_FIELD_ABSENT &&
     protocol_type != protocol_type_ref[counter - 1])
  {
    DEBUG(verbose, "Bad protocol_type value in packet #%u (%u instead of %u)\n",
           counter - 1, protocol_type, protocol_type_ref[counter - 1]);
    goto error;
  }

  /* Check label */
  status = gse_get_label(in_packet, label);
  if(status != GSE_STATUS_OK && status != GSE_STATUS_FIELD_ABSENT)
  {
    DEBUG(verbose, "Error when getting label in packet #%u (%s)\n",
           counter - 1, gse_get_status(status));
    goto error;
  }
  if(status != GSE_STATUS_FIELD_ABSENT &&
     memcmp(label, label_ref[counter - 1], 6 * sizeof(uint8_t)))
  {
    int i;
    DEBUG(verbose, "Bad label value in packet #%u ( ", counter - 1);
    for(i = 0; i < 6; i++)
    {
      DEBUG(verbose, "0x%.2x ", label[i]);
    }
    DEBUG(verbose, "instead of ");
    for(i = 0; i < 6; i++)
    {
      DEBUG(verbose, "0x%.2x ", label_ref[counter - 1][i]);
    }
    DEBUG(verbose, ")\n");
    goto error;
  }

  return 0;

error:
  return 1;
}

/**
 * @brief Display the content of a IP or GSE packet
 *
 * This function is used for debugging purposes.
 *
 * @param descr   A string that describes the packet
 * @param packet  The packet to display
 * @param length  The length of the packet to display
 */
static void dump_packet(char *descr, unsigned char *packet, unsigned int length)
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
