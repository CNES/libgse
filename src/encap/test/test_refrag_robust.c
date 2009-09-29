/****************************************************************************/
/**
 * @file    test_refrag_robust.c
 * @brief   GSE refragmentation robustness tests
 * @author  Didier Barvaux / Viveris Technologies
 * @author  Julien Bernard / Viveris Technologies
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
usage: test [-verbose] cmp_file flow\n\
  verbose         Print DEBUG information\n\
  output_value    Attended output error value (see status)\n\
  frag_length     length of first refragmented GSE packet\n\
  flow            flow of Ethernet frames to fragment and refragment (PCAP format)\n"


/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16

#define QOS_NBR 1
#define FIFO_SIZE 100

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

static int test_refrag(int verbose, int output_value, size_t frag_length,
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
  char *frag_length = NULL;
  unsigned int output_value;
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
    frag_length = argv[2];
    src_filename = argv[3];
    failure = test_refrag(0, output_value, atoi(frag_length), src_filename);
  }
  if(argc == 5)
  {
    if(strcmp(argv[1], "verbose"))
    {
      printf(TEST_USAGE);
      goto quit;
    }
    output_value = strtol(argv[2], NULL, 16);
    frag_length = argv[3];
    src_filename = argv[4];
    failure = test_refrag(1, output_value, atoi(frag_length), src_filename);
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
 * @brief Test the GSE library with a flow of IP or GSE packets to refragment
 *
 * @param verbose       0 for no debug messages, 1 for debug
 * @param outpu_value   Expected output value
 * @param frag_length   The length of the first refragment packet
 * @param src_filename  The name of the PCAP file that contains the source packets
 * @return              0 in case of success, 1 otherwise
 */
static int test_refrag(int verbose, int output_value, size_t frag_length,
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
  vfrag_t *vfrag = NULL;
  vfrag_t *vfrag_pkt = NULL;
  int status = STATUS_OK;
  uint8_t qos = 0;

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
      goto close_input;
    }

    in_packet = packet + link_len_src;
    in_size = header.len - link_len_src;

    /* Create a fragment containing a GSE packet */
    status = gse_create_vfrag_with_data(&vfrag, in_size,
                                        GSE_MAX_HEADER_LENGTH,
                                        GSE_MAX_TRAILER_LENGTH,
                                        in_packet, in_size);
    if(status != STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when creating virtual fragment (%s)\n", status, gse_get_status(status));
      goto close_input;
    }

    /* Refragment the GSE packet */
    status = gse_refrag_packet(vfrag, &vfrag_pkt, 0, 0, qos, frag_length);
    if(status != STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when refragment packet (%s)\n", status, gse_get_status(status));
      goto free_vfrag;
    }


    // Free packets
    if(vfrag != NULL)
    {
      status = gse_free_vfrag(vfrag);
      if(status != STATUS_OK)
      {
        DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
        goto close_input;
      }
      vfrag = NULL;
    }
    if(vfrag_pkt != NULL)
    {
      status = gse_free_vfrag(vfrag_pkt);
      if(status != STATUS_OK)
      {
        DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
        goto close_input;
      }
      vfrag_pkt = NULL;
    }
  }

free_vfrag:
  if(status == output_value)
  {
    is_failure = 0;
  }
  else
  {
    is_failure = 1;
  }
  if(vfrag != NULL)
    {
      status = gse_free_vfrag(vfrag);
      if(status != STATUS_OK)
      {
        DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
        is_failure = 1;
      }
    }
close_input:
  pcap_close(handle);
error:
  return is_failure;
}

