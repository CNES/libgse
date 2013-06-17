/****************************************************************************/
/**
 *   @file          test_add_ext.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: ENCAP
 *
 *   @brief         GSE extensions tests
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
#include "encap_header_ext.h"

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
usage: test [--verbose (-v)] [-l frag_length] [--ext ext_nbr] -c cmp_file -i input_flow\n\
  --verbose    print DEBUG information\n\
  frag_length  length of the GSE packets (default: 0)\n\
  ext_nbr      the number of header extensions (max 2)\n\
  cmp_file     the file where the reference packets to compare with generated ones are stored\n\
  input_flow   flow of GSE packets (PCAP format)\n"

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16
#define EXT_LEN 14
#define PROTOCOL 9029

/** DEBUG macro */
#define DEBUG(verbose, format, ...) \
  do { \
    if(verbose) \
      printf(format, ##__VA_ARGS__); \
  } while(0)

typedef struct
{
  unsigned char data[EXT_LEN];
  size_t length;
  uint16_t extension_type;
  int verbose;
} ext_data_t;

/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 *****************************************************************************/

static int test_add_ext(int verbose, size_t frag_length,
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
  char *frag_length = NULL;
  char *ext_nbr = 0;
  int verbose = 0;
  int failure = 1;
  int ref;
 
  for(ref = argc; (ref > 0 && argc > 1); ref--)
  {
    if(!(strcmp(argv[1], "--verbose")) || !(strcmp(argv[1], "-v")))
     {
      verbose = 1;
      argv += 1;
      argc -= 1;
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

  failure = test_add_ext(verbose,
                         atoi(frag_length),
                         atoi(ext_nbr),
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
 * @brief Test the GSE library with a flow of IP or GSE packets in which
 *        extensions are add
 *
 * @param verbose       0 for no debug messages, 1 for debug
 * @param frag_length   The maximum length of fragments
 * @param ext_nbr       The number of extensions
 * @param src_filename  The name of the PCAP file that contains the source packets
 * @param cmp_filename  The name of the PCAP file that contains the reference packets
 *                      used for comparison
 * @return              0 in case of success, 1 otherwise
 */
static int test_add_ext(int verbose, size_t frag_length,
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
  gse_vfrag_t *vfrag = NULL;
  gse_vfrag_t *vfrag_pkt = NULL;
  gse_status_t status;
  uint8_t qos = 0;
  ext_data_t opaque;
  int update_crc = 0;

  DEBUG(verbose, "\n\n\t\t***************\nSource: '%s' Comparison: '%s'\n",
        src_filename, cmp_filename);

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

  /* handle extensions */
  if(ext_nbr > 0)
  {
    unsigned char data[EXT_LEN];
    int i;

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
      data[12] = (PROTOCOL >> 8) & 0xFF;
      data[13] = PROTOCOL & 0xFF;
      opaque.length += 10;
    }
    else
    {
      /* first extension type field */
      /* PROTOCOL */
      data[2] = (PROTOCOL >> 8) & 0xFF;
      data[3] = PROTOCOL & 0xFF;
    }
    memcpy(opaque.data, data, opaque.length);
    /* 00000 | H-LEN | H-TYPE
     * 00000 |  010  |  0xAB  */
    opaque.extension_type = 0x02AB;
    opaque.verbose = verbose;
  }
  else
  {
    DEBUG(verbose, "Please specify an extension number > 0\n");
  }

  /* for each packet in the dump */
  counter = 0;
  while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
  {
    unsigned char *in_packet;
    size_t in_size;
    uint32_t tmp_crc;

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
                                        GSE_MAX_HEADER_LENGTH,
                                        GSE_MAX_TRAILER_LENGTH,
                                        in_packet, in_size);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "packet #%lu: error %#.4x when creating virtual fragment (%s)\n",
            counter, status, gse_get_status(status));
      goto close_comparison;
    }

    if(update_crc)
    {
      status = gse_encap_update_crc(vfrag, &tmp_crc);
      if(status != GSE_STATUS_OK &&
         status != GSE_STATUS_PARTIAL_CRC)
      {
        DEBUG(verbose, "packet #%lu: error %#.4x when updating CRC (%s)\n",
              counter, status, gse_get_status(status));
        goto free_vfrag;
      }
      else if(status != GSE_STATUS_PARTIAL_CRC)
      {
        update_crc = 0;
      }     
    }
    else
    {
      /* Add extensions in the GSE packet */
      status = gse_encap_add_header_ext(vfrag, &vfrag_pkt, &tmp_crc,
                                        ext_cb, frag_length, 0, 0, qos, &opaque);
      if(status != GSE_STATUS_OK &&
         status != GSE_STATUS_PARTIAL_CRC)
      {
        DEBUG(verbose, "packet #%lu: error %#.4x when adding extensions in packet (%s)\n",
              counter, status, gse_get_status(status));
        goto free_vfrag;
      }
      else if(status == GSE_STATUS_PARTIAL_CRC)
      {
        update_crc = 1;
      }
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

    if(vfrag_pkt != NULL)
    {
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
    }

    /* Free packets */
    if(vfrag != NULL)
    {
      status = gse_free_vfrag(&vfrag);
      if(status != GSE_STATUS_OK)
      {
        DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
        goto free_packets;
      }
    }
    if(vfrag_pkt != NULL)
    {
      status = gse_free_vfrag(&vfrag_pkt);
      if(status != GSE_STATUS_OK)
      {
        DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
        goto close_comparison;
      }
    }
  }


  /* everything went fine */
  is_failure = 0;

free_packets:
  /* Free packets */
  if(vfrag_pkt != NULL)
  {
    status = gse_free_vfrag(&vfrag_pkt);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
      is_failure = 1;
    }
  }
free_vfrag:
  if(vfrag != NULL)
  {
    status = gse_free_vfrag(&vfrag);
    if(status != GSE_STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
      is_failure = 1;
    }
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
  return ext_info->length;
error:
  return -1;
}
