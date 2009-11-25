/****************************************************************************/
/**
 * @file    test_encap.c
 * @brief   GSE encapsulation tests
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
#include "header_fields.h"
#include "status.h"

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
usage: test [-verbose] frag_length cmp_file flow\n\
  verbose         Print DEBUG information\n\
  frag_length     length of the GSE packets\n\
  cmp_file        compare the generated packets with the reference packets\n\
                  stored in cmp_file (PCAP format)\n\
  flow            flow of Ethernet frames to encapsulate (PCAP format)\n"


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
void dump_packet(char *descr, unsigned char *packet, unsigned int length);

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

  /* parse program arguments, print the help message in case of failure */
  if((argc < 2) || (argc > 3))
  {
    printf(TEST_USAGE);
    goto quit;
  }

  if(argc == 2)
  {
    src_filename = argv[1];
    failure = test_header_access(0, src_filename);
  }
  if(argc == 3)
  {
    if(strcmp(argv[1], "verbose"))
    {
      printf(TEST_USAGE);
      goto quit;
    }
    src_filename = argv[2];
    failure = test_header_access(1, src_filename);
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
 * @brief Test the GSE library with a flow of IP or GSE packets to encapsulate
 *
 * @param verbose       0 for no debug messages, 1 for debug
 * @param src_filename  The name of the PCAP file that contains the source packets
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
  uint8_t s;
  uint8_t e;
  uint8_t lt;
  uint16_t gse_length;
  uint8_t frag_id;
  uint16_t total_length;
  uint16_t protocol_type;
  uint8_t label[6];
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
  gse_status_t status;

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

    /* check Ethernet frame length */
    if(header.len <= link_len_src || header.len != header.caplen)
    {
      DEBUG(verbose, "packet #%u: bad PCAP packet (len = %u, caplen = %u)\n",
             counter - 1, header.len, header.caplen);
      goto close_input;
    }

    in_packet = packet + link_len_src;
    in_size = header.len - link_len_src;

    /* Check start indicator */
    status = gse_get_start_indicator(in_packet, &s);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error when getting start indicator in packet #%u (%s)\n",
             counter - 1, gse_get_status(status));
      goto close_input;
    }
    if(s != s_ref[counter - 1])
    {
      DEBUG(verbose, "Bad start indicator value in packet #%u (%u instead of %u)\n",
             counter - 1, s, s_ref[counter - 1]);
      goto close_input;
    }

    /* Check end indicator */
    status = gse_get_end_indicator(in_packet, &e);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error when getting end indicator in packet #%u (%s)\n",
             counter - 1, gse_get_status(status));
      goto close_input;
    }
    if(e != e_ref[counter - 1])
    {
      DEBUG(verbose, "Bad end indicator value in packet #%u (%u instead of %u)\n",
             counter - 1, e, e_ref[counter - 1]);
      goto close_input;
    }

    /* Check label type */
    status = gse_get_label_type(in_packet, &lt);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error when getting label type in packet #%u (%s)\n",
             counter - 1, gse_get_status(status));
      goto close_input;
    }
    if(lt != lt_ref[counter - 1])
    {
      DEBUG(verbose, "Bad label type value in packet #%u (%u instead of %u)\n",
             counter - 1, lt, lt_ref[counter - 1]);
      goto close_input;
    }

    /* Check gse length */
    status = gse_get_gse_length(in_packet, &gse_length);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error when getting gse length in packet #%u (%s)\n",
             counter - 1, gse_get_status(status));
      goto close_input;
    }
    if(gse_length != gse_length_ref[counter - 1])
    {
      DEBUG(verbose, "Bad gse length value in packet #%u (%u instead of %u)\n",
             counter - 1, gse_length, gse_length_ref[counter - 1]);
      goto close_input;
    }

    /* Check frag id */
    status = gse_get_frag_id(in_packet, &frag_id);
    if(status != GSE_STATUS_OK && status != GSE_STATUS_FIELD_ABSENT)
    {
      DEBUG(verbose, "Error when getting frag_id in packet #%u (%s)\n",
             counter - 1, gse_get_status(status));
      goto close_input;
    }
    if(frag_id != frag_id_ref[counter - 1] &&
       status != GSE_STATUS_FIELD_ABSENT)
    {
      DEBUG(verbose, "Bad frag_id value in packet #%u (%u instead of %u)\n",
             counter - 1, frag_id, frag_id_ref[counter - 1]);
      goto close_input;
    }

    /* Check total length */
    status = gse_get_total_length(in_packet, &total_length);
    printf("status = %s\n", gse_get_status(status));
    if(status != GSE_STATUS_OK && status != GSE_STATUS_FIELD_ABSENT)
    {
      DEBUG(verbose, "Error when getting total_length in packet #%u (%s)\n",
             counter - 1, gse_get_status(status));
      goto close_input;
    }
    if(total_length != total_length_ref[counter - 1] &&
       status != GSE_STATUS_FIELD_ABSENT)
    {
      DEBUG(verbose, "Bad total_length value in packet #%u (%u instead of %u)\n",
             counter - 1, total_length, total_length_ref[counter - 1]);
      goto close_input;
    }

    /* Check protocol type */
    status = gse_get_protocol_type(in_packet, &protocol_type);
    if(status != GSE_STATUS_OK && status != GSE_STATUS_FIELD_ABSENT)
    {
      DEBUG(verbose, "Error when getting protocol_type in packet #%u (%s)\n",
             counter - 1, gse_get_status(status));
      goto close_input;
    }
    if(protocol_type != protocol_type_ref[counter - 1] &&
       status != GSE_STATUS_FIELD_ABSENT)
    {
      DEBUG(verbose, "Bad protocol_type value in packet #%u (%u instead of %u)\n",
             counter - 1, protocol_type, protocol_type_ref[counter - 1]);
      goto close_input;
    }

    /* Check label */
    status = gse_get_label(in_packet, label);
    if(status != GSE_STATUS_OK && status != GSE_STATUS_FIELD_ABSENT)
    {
      DEBUG(verbose, "Error when getting label in packet #%u (%s)\n",
             counter - 1, gse_get_status(status));
      goto close_input;
    }
    if(memcmp(label, label_ref[counter - 1], 6 * sizeof(uint8_t)) &&
       status != GSE_STATUS_FIELD_ABSENT)
    {
      int i;
      DEBUG(verbose, "Bad label value in packet #%u ( ", counter - 1);
      for(i = 0; i < 6; i++)
      {
        printf("0x%.2x ", label[i]);
      }
      printf("instead of ");
      for(i = 0; i < 6; i++)
      {
        printf("0x%.2x ", label_ref[counter - 1][i]);
      }
      printf(")\n");
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

