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
 *   @file          test_encap.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: ENCAP
 *
 *   @brief         GSE encapsulation tests
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
#include "encap.h"
#include "constants.h"

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
usage: test [--verbose (-v)] [--label-type lt] [-l frag_length] [--ext ext_nbr]  -c cmp_file -i input_flow\n\
  --verbose       print DEBUG information\n\
  --label_type    the label_type (0, 1, 2, 3) (default: 0)\n\
  frag_length     length of the GSE packets\n\
  ext_nbr      the number of header extensions (max 2)\n\
  cmp_file        compare the generated packets with the reference packets\n\
                  stored in cmp_file (PCAP format)\n\
  input_flow      flow of Ethernet frames to encapsulate (PCAP format)\n"


/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16

#define QOS_NBR 1
#define FIFO_SIZE 100
#define PROTOCOL 9029
#define EXT_LEN 14

/** DEBUG macro */
#define DEBUG(verbose, format, ...) \
  do { \
    if(verbose) \
      printf(format, ##__VA_ARGS__); \
  } while(0)


typedef struct
{
  unsigned char *data;
  size_t length;
  uint16_t extension_type;
  int verbose;
} ext_data_t;

/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 *****************************************************************************/

static int test_encap(int verbose, uint8_t label_type, size_t frag_length,
                      int ext_nbr, char *src_filename, char *cmp_filename);
static int compare_packets(int verbose,
                           unsigned char *pkt1, int pkt1_size,
                           unsigned char *pkt2, int pkt2_size);
static int ext_cb(unsigned char *ext,
                  size_t *length,
                  uint16_t *extension_type,
                  uint16_t protocol_type,
                  void *opaque);


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
  char *frag_length = 0;
  int verbose = 0;
  char *label_type = 0;
  char *ext_nbr = 0;
  int failure = 1;
  int ref;

  /* parse program arguments, print the help message in case of failure */
  for(ref = argc; (ref > 0 && argc > 1); ref--)
  {
    if(!(strcmp(argv[1], "--verbose")) || !(strcmp(argv[1], "-v")))
    {
      verbose = 1;
      argv += 1;
      argc -= 1;
    }
    else if(!strcmp(argv[1], "--label-type"))
    {
      if(!argv[2])
      {
        fprintf(stderr, "Missing label type\n");
        fprintf(stderr, TEST_USAGE);
        goto quit;
      }
      label_type = argv[2];
      if(atoi(label_type) < 0 && atoi(label_type) > 3)
      {
        fprintf(stderr, "Bad label type\n");
        goto quit;
      }
      argv += 2;
      argc -= 2;
    }
    else if(!strcmp(argv[1], "--ext"))
    {
      if(!argv[2])
      {
        fprintf(stderr, "Missing extension number\n");
        fprintf(stderr, TEST_USAGE);
        goto quit;
      }
      ext_nbr = argv[2];
      argv += 2;
      argc -= 2;
    }
    else if(!strcmp(argv[1], "-l"))
    {
      if(!argv[2])
      {
        fprintf(stderr, "Missing frag_length\n");
        fprintf(stderr, TEST_USAGE);
        goto quit;
      }
      frag_length = argv[2];
      argv += 2;
      argc -= 2;
    }
    else if(!strcmp(argv[1], "-c"))
    {
      if(!argv[2])
      {
        fprintf(stderr, "Missing cmp_file\n");
        fprintf(stderr, TEST_USAGE);
        goto quit;
      }
      cmp_filename = argv[2];
      argv += 2;
      argc -= 2;
    }
    else if(!strcmp(argv[1], "-i"))
    {
      if(!argv[2])
      {
        fprintf(stderr, "Missing input_flow\n");
        fprintf(stderr, TEST_USAGE);
        goto quit;
      }
      src_filename = argv[2];
      argv += 2;
      argc -= 2;
    }
    else
    {
      fprintf(stderr, "unknown option %s\n", argv[1]);
      fprintf(stderr, TEST_USAGE);
      goto quit;
    }
  }

  if(!src_filename || !cmp_filename)
  {
    fprintf(stderr, "missing mandatory options\n");
    fprintf(stderr, TEST_USAGE);
    goto quit;
  }

  failure = test_encap(verbose,
                       (label_type ? atoi(label_type):0),
                       (frag_length ? atoi(frag_length):0),
                       (ext_nbr ? atoi(ext_nbr):0),
                       src_filename, cmp_filename);

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
 * @param label_type    The label type
 * @param frag_length   The maximum length of the fragments (0 for default)
 * @param ext_nbr       The number of extensions
 * @param src_filename  The name of the PCAP file that contains the source packets
 * @param cmp_filename  The name of the PCAP file that contains the reference packets
 *                      used for comparison
 * @return              0 in case of success, 1 otherwise
 */
static int test_encap(int verbose, uint8_t label_type, size_t frag_length,
                      int ext_nbr, char *src_filename, char *cmp_filename)
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
  gse_encap_t *encap = NULL;
  gse_vfrag_t *vfrag_pkt = NULL;
  uint8_t label[6];
  gse_vfrag_t *pdu = NULL;
  int i;
  int nbr_pkt = 0;
  gse_status_t status;
  uint8_t qos = 0;

  DEBUG(verbose, "Maximum length of fragments is: %zu\n", frag_length);
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
  status = gse_encap_init(QOS_NBR, FIFO_SIZE, &encap);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when initializing library (%s)\n", status,
          gse_get_status(status));
    goto close_comparison;
  }

  /* handle extensions */
  if(ext_nbr > 0)
  {
    ext_data_t opaque;
    unsigned char data[EXT_LEN];

    opaque.length = 4;

    for(i = 0; i < 2; i++)
    {
      /* first ext data */
      data[i] = i;
    }

    if(ext_nbr > 1)
    {
      /* first extension type field */
      /* H-LEN */
      data[2] = 0x05;
      /* H-TYPE */
      data[3] = 0xCD;

      for(i = 4; i < 12; i++)
      {
        /* second ext data */
        data[i] = i;
      }
      /* second extension type field */
      /* PROTOCOL */
      data[12] = 0x23;
      data[13] = 0x45;
      opaque.length += 10;
    }
    else
    {
      /* first extension type field */
      /* H-LEN */
      data[2] = (PROTOCOL >> 8) & 0xFF;
      /* H-TYPE */
      data[3] = PROTOCOL & 0xFF;
    }
    opaque.data = data;
    /* 00000 | H-LEN | H-TYPE
     * 00000 |  010  |  0xAB  */
    opaque.extension_type = 0x02AB;
    opaque.verbose = verbose;

    gse_encap_set_extension_callback(encap, ext_cb, &opaque);
  }

  /* for each packet in the dump */
  counter = 0;
  while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
  {
    unsigned char *in_packet;
    size_t in_size;
    size_t head_len;

    counter++;

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
    for(i = 0 ; i < gse_get_label_length(label_type) ; i++)
      label[i] = i;

    head_len = GSE_MAX_HEADER_LENGTH;
    if(ext_nbr > 0)
    {
      head_len += EXT_LEN;
    }
    status = gse_create_vfrag_with_data(&pdu, in_size,
                                        head_len,
                                        GSE_MAX_TRAILER_LENGTH,
                                        in_packet, in_size);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when creating virtual fragment (%s)\n", status,
            gse_get_status(status));
      goto release_lib;
    }
    status = gse_encap_receive_pdu(pdu, encap, label, label_type, PROTOCOL, qos);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when encapsulating pdu (%s)\n", status,
            gse_get_status(status));
      goto release_lib;
    }

    /* get next GSE packet from the comparison dump file */
    /* The following might be done several times in case of fragmentation */
    do{
      status = gse_encap_get_packet(&vfrag_pkt, encap, frag_length, qos);
      if((status != GSE_STATUS_OK) && (status != GSE_STATUS_FIFO_EMPTY))
      {
        DEBUG(verbose, "Error %#.4x when getting packet (%s)\n", status,
              gse_get_status(status));
        goto release_lib;
      }

      if(status != GSE_STATUS_FIFO_EMPTY)
      {
        cmp_packet = (unsigned char *) pcap_next(cmp_handle, &cmp_header);
        if(cmp_packet == NULL)
        {
          DEBUG(verbose, "packet #%lu: no packet available for comparison\n", counter);
          goto release_lib;
        }

        /* compare the output packets with the ones given by the user */
        if(cmp_header.caplen <= link_len_cmp)
        {
          DEBUG(verbose, "packet #%lu: packet available for comparison but too small\n",
                counter);
          goto release_lib;
        }

        if(!compare_packets(verbose, vfrag_pkt->start, vfrag_pkt->length,
                            cmp_packet + link_len_cmp, cmp_header.caplen - link_len_cmp))
        {
          DEBUG(verbose, "packet #%lu: generated packet is not as attended\n", counter);
          goto release_lib;
        }
        nbr_pkt++;
        DEBUG(verbose, "Packet %d OK\n", nbr_pkt);
      }
      else
      {
        DEBUG(verbose, "Fifo is empty\n");
      }
      if(vfrag_pkt != NULL)
      {
        status = gse_free_vfrag(&vfrag_pkt);
        if((status != GSE_STATUS_OK) && (status != GSE_STATUS_FIFO_EMPTY))
        {
          DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status,
                gse_get_status(status));
          goto release_lib;
        }
      }
    }while(status != GSE_STATUS_FIFO_EMPTY);
  }


  /* everything went fine */
  is_failure = 0;

release_lib:
  status = gse_encap_release(encap);
  if(status != GSE_STATUS_OK)
  {
    is_failure = 1;
    DEBUG(verbose, "Error %#.4x when releasing library (%s)\n", status,
          gse_get_status(status));
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

static int ext_cb(unsigned char *ext,
                  size_t *length,
                  uint16_t *extension_type,
                  uint16_t protocol_type,
                  void *opaque)
{
  ext_data_t *ext_info = (ext_data_t *)opaque;

  if(ext_info->length > *length)
  {
    DEBUG(ext_info->verbose, "Not enough space for extensions:\n"
          "available: %zu, necessary: %zu\n", *length, ext_info->length);
    goto error;
  }
  if(protocol_type != PROTOCOL)
  {
    DEBUG(ext_info->verbose, "Wrong protocol type %u\n", protocol_type);
    goto error;
  }
  
  memcpy(ext, ext_info->data, ext_info->length);

  *extension_type = ext_info->extension_type;
  *length = ext_info->length;
  DEBUG(ext_info->verbose, "Extension length: %zu\n", ext_info->length);
  return ext_info->length;
error:
  return -1;
}

