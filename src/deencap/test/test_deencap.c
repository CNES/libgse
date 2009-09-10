/****************************************************************************/
/**
 * @file    test.c
 * @brief   The GSE test program
 * @author  Didier Barvaux / Viveris Technologies
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
#include "gse_deencap_fct.h"
#include "gse_deencap.h"

/****************************************************************************
 *
 *   MACROS AND CONSTANTS
 *
 *****************************************************************************/

/** A very simple maximum macro */
#define MAX(x, y)  (((x) > (y)) ? (x) : (y))

/** A very simple minimum macro */
#define MIN(x, y)  (((x) < (y)) ? (x) : (y))

/** The program version */
#define TEST_VERSION  	"GSE test application, version 0.1\n"

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

#define QOS_NBR 5
#define LABEL_TYPE 0x0
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
    failure = test_deencap(0, src_filename, cmp_filename);
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
    failure = test_deencap(1, src_filename, cmp_filename);
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
  vfrag_t *gse_packet = NULL;
  uint8_t label[6];
  vfrag_t *pdu = NULL;
  uint8_t label_type;
  uint16_t protocol;
  int status;
  int i;
  int pkt_nbr = 0;

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
  if(status != STATUS_OK)
  {
    DEBUG(verbose, "Error %d when initializing library\n", status);
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
    status = gse_create_vfrag_with_data(&gse_packet, in_size, in_packet, in_size);
    if(status != STATUS_OK)
    {
      DEBUG(verbose, "Error %d when creating virtual fragment\n", status);
      goto release_lib;
    }

    /* get next GSE packet from the comparison dump file */
    /* The following might be done several times in case of fragmentation */
    status = gse_deencap_packet(gse_packet, deencap, &label_type, label,
                                &protocol, &pdu);
    if((status != STATUS_OK) && (status != PDU))
    {
      DEBUG(verbose, "Error %d when getting packet\n", status);
      goto free_pdu;
    }

    if(status == PDU)
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
      DEBUG(verbose, "Complete PDU #%lu:\nLabel Type: %d | Protocol: %#x | Label: %.2d",
            counter, label_type, protocol, label[0]);
      for(i = 1 ; i < gse_get_label_length(label_type) ; i++)
      {
        DEBUG(verbose, ":%.2d", label[i]);
      }
      DEBUG(verbose, " (in hexa)\n");
      if((label_type != LABEL_TYPE) || (protocol != PROTOCOL))
      {
        DEBUG(verbose, "---------- Incorrect output parameters ! ----------\n");
        goto free_pdu;
      }
      if(pdu != NULL)
      {
        status = gse_free_vfrag(pdu);
        if(status != STATUS_OK)
        {
          DEBUG(verbose, "Error %d when destroying pdu\n", status);
          goto release_lib;
        }
        pdu = NULL;
      }
    }
  }

  /* everything went fine */
  is_failure = 0;

free_pdu:
  if(pdu != NULL)
  {
    status = gse_free_vfrag(pdu);
    if(status != STATUS_OK)
    {
      DEBUG(verbose, "Error %d when destroying pdu\n", status);
    }
  }
release_lib:
  status = gse_deencap_release(deencap);
  if(status != STATUS_OK)
  {
    is_failure = 1;
    DEBUG(verbose, "Error %d when releasing library\n", status);
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

