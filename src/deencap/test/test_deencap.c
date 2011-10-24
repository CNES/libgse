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
 *   @file          test_deencap.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: DEENCAP
 *
 *   @brief         GSE deencapsulation tests
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
#include "deencap.h"

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
usage: test [-verbose] cmp_file flow\n\
  verbose         Print DEBUG information\n\
  cmp_file        compare the generated packets with the reference packets\n\
                  stored in cmp_file (PCAP format)\n\
  flow            flow of Ethernet frames to deencapsulate (PCAP format)\n"


/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16

/** The number of FIFOs */
#define QOS_NBR 5
/** The type of label carried by the GSE packets */
#define LABEL_TYPE 0x0
/* The protocol carried by the GSE packets */
#define PROTOCOL 0x2345
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

static int test_deencap(int verbose, char *src_filename, char *cmp_filename);
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
  char *cmp_filename = NULL;
  int verbose;
  int failure = 1;

  /* parse program arguments, print the help message in case of failure */
  if((argc < 3) || (argc > 4))
  {
    printf(TEST_USAGE);
    goto quit;
  }

  if(argc == 3)
  {
    /* get the name of the file where the reference packets used for
       comparison are stored */
    cmp_filename = argv[1];
    /* get the name of the file that contains the packets to
       (de-)encapsulate */
    src_filename = argv[2];
    verbose = 0;
  }
  if(argc == 4)
  {
    if(strcmp(argv[1], "verbose"))
    {
      printf(TEST_USAGE);
      goto quit;
    }
    /* get the name of the file where the reference packets used for
       comparison are stored */
    cmp_filename = argv[2];
    /* get the name of the file that contains the packets to
       (de-)encapsulate */
    src_filename = argv[3];
    verbose = 1;
  }
  failure = test_deencap(verbose, src_filename, cmp_filename);

quit:
  return failure;
}

/****************************************************************************
 *
 *   PRIVATE FUNCTIONS
 *
 *****************************************************************************/

/**
 * @brief Test the GSE library with a flow of IP or GSE packets to deencapsulate
 *
 * @param verbose       0 for no debug messages, 1 for debug
 * @param src_filename  The name of the PCAP file that contains the source packets
 * @param cmp_filename  The name of the PCAP file that contains the reference packets
 *                      used for comparison
 * @return              0 in case of success, 1 otherwise
 */
static int test_deencap(int verbose, char *src_filename, char *cmp_filename)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  pcap_t *cmp_handle;
  int link_layer_type_src;
  int link_layer_type_cmp;
  uint32_t link_len_src;
  uint32_t link_len_cmp;
  struct pcap_pkthdr header;
  struct pcap_pkthdr cmp_header;
  unsigned char *packet;
  unsigned char *cmp_packet;
  int is_failure = 1;
  unsigned long counter;
  gse_deencap_t *deencap = NULL;
  gse_vfrag_t *gse_packet = NULL;
  uint8_t label[6];
  uint8_t ref_label[6];
  gse_vfrag_t *pdu = NULL;
  uint8_t label_type;
  uint16_t protocol;
  uint16_t gse_length;
  gse_status_t status;
  int i;
  int pkt_nbr = 0;

  for(i=0 ; i<6 ; i++)
    ref_label[i] = i;

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

  /* open the comparison dump file */
  cmp_handle = pcap_open_offline(cmp_filename, errbuf);
  if(cmp_handle == NULL)
  {
    DEBUG(verbose, "failed to open the comparison pcap file: %s\n", errbuf);
    goto close_input;
  }

  /* link layer in the comparison dump must be supported */
  link_layer_type_cmp = pcap_datalink(cmp_handle);
  if(link_layer_type_cmp != DLT_EN10MB &&
     link_layer_type_cmp != DLT_LINUX_SLL &&
     link_layer_type_cmp != DLT_RAW)
  {
    DEBUG(verbose, "link layer type %d not supported in comparison dump "
           "(supported = %d, %d, %d)\n", link_layer_type_cmp, DLT_EN10MB,
           DLT_LINUX_SLL, DLT_RAW);
    goto close_comparison;
  }

  if(link_layer_type_cmp == DLT_EN10MB)
    link_len_cmp = ETHER_HDR_LEN;
  else if(link_layer_type_cmp == DLT_LINUX_SLL)
    link_len_cmp = LINUX_COOKED_HDR_LEN;
  else /* DLT_RAW */
    link_len_cmp = 0;

  /* Initialize the GSE library */
  status = gse_deencap_init(QOS_NBR, &deencap);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when initializing library (%s)\n", status, gse_get_status(status));
    goto close_comparison;
  }

  /* for each packet in the dump */
  counter = 0;
  while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
  {
    unsigned char *in_packet;
    size_t in_size;

    pkt_nbr++;

    /* check Ethernet frame length */
    if(header.len <= link_len_src || header.len != header.caplen)
    {
      DEBUG(verbose, "packet #%lu: bad PCAP packet (len = %d, caplen = %d)\n",
             counter, header.len, header.caplen);
      goto release_lib;
    }

    in_packet = packet + link_len_src;
    in_size = header.len - link_len_src;

    /* Encapsulate the input packets, use in_packet and in_size as
       input */
    status = gse_create_vfrag_with_data(&gse_packet, in_size,
                                        GSE_MAX_HEADER_LENGTH,
                                        GSE_MAX_TRAILER_LENGTH,
                                        in_packet, in_size);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when creating virtual fragment (%s)\n", status, gse_get_status(status));
      goto release_lib;
    }

    /* get next GSE packet from the comparison dump file */
    /* The following might be done several times in case of fragmentation */
    status = gse_deencap_packet(gse_packet, deencap, &label_type, label,
                                &protocol, &pdu, &gse_length);
    if((status != GSE_STATUS_OK) && (status != GSE_STATUS_PDU_RECEIVED) && (status != GSE_STATUS_DATA_OVERWRITTEN))
    {
      DEBUG(verbose, "Error %#.4x when getting packet (%s)\n", status, gse_get_status(status));
      goto free_pdu;
    }
    DEBUG(verbose, "GSE packet #%d received, packet length = %d\n", pkt_nbr, gse_length);

    if(status == GSE_STATUS_PDU_RECEIVED)
    {
      counter++;
      DEBUG(verbose, "%d packet received\n", pkt_nbr);
      pkt_nbr = 0;
      cmp_packet = (unsigned char *) pcap_next(cmp_handle, &cmp_header);
      if(cmp_packet == NULL)
      {
        DEBUG(verbose, "PDU #%lu: no PDU available for comparison\n", counter);
        goto free_pdu;
      }

      /* compare the output packets with the ones given by the user */
      if(cmp_header.caplen <= link_len_cmp)
      {
        DEBUG(verbose, "PDU #%lu: PDU available for comparison but too small\n",
              counter);
        goto free_pdu;
      }

      if(!compare_packets(verbose, pdu->start, pdu->length,
                          cmp_packet + link_len_cmp, cmp_header.caplen - link_len_cmp))
      {
        DEBUG(verbose, "PDU #%lu: generated PDU is not as attended\n", counter);
        goto free_pdu;
      }
      DEBUG(verbose, "Complete PDU #%lu:\nLabel Type: %d | Protocol: %#.4x | Label: %.2d",
            counter, label_type, protocol, label[0]);
      for(i = 1 ; i < gse_get_label_length(label_type) ; i++)
      {
        DEBUG(verbose, ":%.2d", label[i]);
      }
      DEBUG(verbose, " (in hexa)\n");
      if((label_type != LABEL_TYPE) && (protocol != PROTOCOL))
      {
        DEBUG(verbose, "---------- BAD PARAMETERS VALUE ----------\n");
        DEBUG(verbose, "Reference label type = %d\n Reference protocol = %#.4x\n",
              LABEL_TYPE, PROTOCOL);
        goto free_pdu;
      }
      for(i = 0 ; i < gse_get_label_length(label_type) ; i++)
      {
        if(label[i] != ref_label[i])
        {
          DEBUG(verbose, "---------- BAD PARAMETERS VALUE ----------\n");
          DEBUG(verbose, "Reference label octet %d = %.2d\n", i, ref_label[i]);
          goto free_pdu;
        }
      }

      if(pdu != NULL)
      {
        status = gse_free_vfrag(&pdu);
        if(status != GSE_STATUS_OK)
        {
          DEBUG(verbose, "Error %#.4x when destroying pdu (%s)\n", status, gse_get_status(status));
          goto release_lib;
        }
      }
    }
  }

  /* everything went fine */
  is_failure = 0;

free_pdu:
  if(pdu != NULL)
  {
    status = gse_free_vfrag(&pdu);
    if(status != GSE_STATUS_OK)
    {
      is_failure = 1;
      DEBUG(verbose, "Error %#.4x when destroying pdu (%s)\n", status, gse_get_status(status));
    }
  }
release_lib:
  status = gse_deencap_release(deencap);
  if(status != GSE_STATUS_OK)
  {
    is_failure = 1;
    DEBUG(verbose, "Error %#.4x when releasing library (%s)\n", status, gse_get_status(status));
  }
close_comparison:
  pcap_close(cmp_handle);
close_input:
  pcap_close(handle);
error:
  return is_failure;
}


/**
 * @brief Compare two network packets and print differences if any
 *
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

  min_size = MIN(pkt1_size, pkt2_size);

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
    DEBUG(verbose, "PDU have different sizes (%d != %d), compare only the %d "
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

  DEBUG(verbose, "----------------------- PDU are different -----------------------\n");

skip:
  return valid;
}
