/****************************************************************************/
/**
 * @file    test_refrag.c
 * @brief   GSE refragmentation tests
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
#include "gse_refrag.h"

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
  frag_length     length of first refragmented GSE packet\n\
  cmp_file        compare the generated packets with the reference packets\n\
                  stored in cmp_file (PCAP format)\n\
  flow            flow of Ethernet frames to fragment and refragment (PCAP format)\n"


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

static int test_refrag(int verbose, size_t frag_length,
                      char *src_filename, char *cmp_filename);
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
  char *frag_length = NULL;
  int failure = 1;

  /* parse program arguments, print the help message in case of failure */
  if((argc < 4) || (argc > 5))
  {
    printf(TEST_USAGE);
    goto quit;
  }

  if(argc == 4)
  {
    frag_length = argv[1];
    cmp_filename = argv[2];
    src_filename = argv[3];
    failure = test_refrag(0, atoi(frag_length), src_filename, cmp_filename);
  }
  if(argc == 5)
  {
    if(strcmp(argv[1], "verbose"))
    {
      printf(TEST_USAGE);
      goto quit;
    }
    frag_length = argv[2];
    cmp_filename = argv[3];
    src_filename = argv[4];
    failure = test_refrag(1, atoi(frag_length), src_filename, cmp_filename);
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
 * @param frag_length   The length of the first refragment packet
 * @param src_filename  The name of the PCAP file that contains the source packets
 * @param cmp_filename  The name of the PCAP file that contains the reference packets
 *                      used for comparison
 * @return              0 in case of success, 1 otherwise
 */
static int test_refrag(int verbose, size_t frag_length,
                      char *src_filename, char *cmp_filename)
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
  vfrag_t *vfrag = NULL;
  vfrag_t *vfrag_pkt = NULL;
  int status;
  uint8_t qos = 0;

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
      goto close_comparison;
    }

    in_packet = packet + link_len_src;
    in_size = header.len - link_len_src;

    /* Create a fragment containing a GSE packet */
    status = gse_create_vfrag_with_data(&vfrag, in_size,
                                        MAX_HEADER_LENGTH, CRC_LENGTH,
                                        in_packet, in_size);
    if(status != STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when creating virtual fragment (%s)\n", status, gse_get_status(status));
      goto close_comparison;
    }

    /* Refragment the GSE packet */
    status = gse_refrag_packet(vfrag, &vfrag_pkt, 0, 0, qos, frag_length);
    if((status != STATUS_OK))
    {
      DEBUG(verbose, "Error %#.4x when refragment packet (%s)\n", status, gse_get_status(status));
      goto free_vfrag;
    }

    cmp_packet = (unsigned char *) pcap_next(cmp_handle, &cmp_header);
    if(cmp_packet == NULL)
    {
      DEBUG(verbose, "packet #%lu: no packet available for comparison\n", counter);
      goto free_packets;
    }

    /* compare the first output packets with the ones given by the user */
    if(cmp_header.caplen <= link_len_cmp)
    {
      DEBUG(verbose, "packet #%lu: packet available for comparison but too small\n",
            counter);
      goto free_packets;
    }

    if(!compare_packets(verbose, vfrag->start, vfrag->length,
                        cmp_packet + link_len_cmp, cmp_header.caplen - link_len_cmp))
    {
      DEBUG(verbose, "packet #%lu: generated packet is not as attended\n", counter);
      goto free_packets;
    }
    else
    {
      DEBUG(verbose, "Packet #%lu - Fragment 1 : OK\n", counter);
    }

    cmp_packet = (unsigned char *) pcap_next(cmp_handle, &cmp_header);
    if(cmp_packet == NULL)
    {
      DEBUG(verbose, "packet #%lu: no packet available for comparison\n", counter);
      goto free_packets;
    }

    /* compare the second output packets with the ones given by the user */
    if(cmp_header.caplen <= link_len_cmp)
    {
      DEBUG(verbose, "packet #%lu: packet available for comparison but too small\n",
            counter);
      goto free_packets;
    }

    if(!compare_packets(verbose, vfrag_pkt->start, vfrag_pkt->length,
                        cmp_packet + link_len_cmp, cmp_header.caplen - link_len_cmp))
    {
      DEBUG(verbose, "packet #%lu: generated packet is not as attended\n", counter);
      goto free_packets;
    }
    else
    {
      DEBUG(verbose, "Packet #%lu - Fragment 2 : OK\n", counter);
    }

    // Free packets
    if(vfrag != NULL)
    {
      status = gse_free_vfrag(vfrag);
      if(status != STATUS_OK)
      {
        DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
        goto free_packets;
      }
      vfrag = NULL;
    }
    if(vfrag_pkt != NULL)
    {
      status = gse_free_vfrag(vfrag_pkt);
      if(status != STATUS_OK)
      {
        DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
        goto close_comparison;
      }
      vfrag_pkt = NULL;
    }
  }


  /* everything went fine */
  is_failure = 0;

free_packets:
  // Free packets
  if(vfrag_pkt != NULL)
  {
    status = gse_free_vfrag(vfrag_pkt);
    if(status != STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
      is_failure = 1;
    }
    vfrag_pkt = NULL;
  }
free_vfrag:
  if(vfrag != NULL)
  {
    status = gse_free_vfrag(vfrag);
    if(status != STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
      is_failure = 1;
    }
    vfrag = NULL;
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

