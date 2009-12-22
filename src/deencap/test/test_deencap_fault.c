/****************************************************************************/
/**
 *   @file          test_deencap_fault.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: DEENCAP
 *
 *   @brief         GSE deencapsulation fault tolerance tests
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
usage: test [-verbose] output_value flow\n\
  verbose         Print DEBUG information\n\
  output_value    Attended output error value (see status)\n\
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

static int test_deencap(int verbose, gse_status_t output_value, char *src_filename);

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
    output_value = strtol(argv[1], NULL, 16);
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
    output_value = strtoul(argv[2], NULL, 16);
    src_filename = argv[3];
    verbose = 1;
  }
  failure = test_deencap(verbose, output_value, src_filename);

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
 * @param output_value  The status code attended
 * @param src_filename  The name of the PCAP file that contains the source packets
 * @return              0 in case of success, 1 otherwise
 */
static int test_deencap(int verbose, gse_status_t output_value, char *src_filename)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  int link_layer_type_src;
  uint32_t link_len_src;
  struct pcap_pkthdr header;
  unsigned char *packet;
  int is_failure = 1;
  unsigned long counter;
  gse_deencap_t *deencap = NULL;
  gse_vfrag_t *gse_packet = NULL;
  uint8_t label[6];
  gse_vfrag_t *pdu = NULL;
  uint8_t label_type;
  uint16_t protocol;
  uint16_t gse_length;
  gse_status_t status;

  DEBUG(verbose, "Tested status is %#.4x (%s)\n", output_value, gse_get_status(output_value));
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
  status = gse_deencap_init(QOS_NBR, &deencap);
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
    status = gse_create_vfrag_with_data(&gse_packet, in_size,
                                        GSE_MAX_HEADER_LENGTH,
                                        GSE_MAX_TRAILER_LENGTH,
                                        in_packet, in_size);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when creating virtual fragment (%s)\n", status, gse_get_status(status));
      goto check_status;
    }

    /* get next GSE packet */
    status = gse_deencap_packet(gse_packet, deencap, &label_type, label,
                                &protocol, &pdu, &gse_length);
    if((status != GSE_STATUS_OK) && (status != GSE_STATUS_PDU_RECEIVED))
    {
      DEBUG(verbose, "Error %#.4x when getting packet (%s)\n", status, gse_get_status(status));
      goto check_status;
    }
    if(pdu != NULL)
    {
      status = gse_free_vfrag(&pdu);
      if(status != GSE_STATUS_OK)
      {
        goto check_status;
      }
    }
  }

  /* everything went fine */
  is_failure = 0;

check_status:
  if(status == output_value)
  {
    is_failure = 0;
  }
  else
  {
    is_failure = 1;
  }
  status = gse_deencap_release(deencap);
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

