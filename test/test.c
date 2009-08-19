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
/* TODO: to complete */


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
usage: test [-h] [-v] [-d] cmp_file flow\n\
  -v              print version information and exit\n\
  -h              print this usage and exit\n\
  -d              de-encapsulate PDUs from the GSE packets given as input\n\
  cmp_file        compare the generated packets with the reference packets\n\
                  stored in cmp_file (PCAP format)\n\
  flow            flow of Ethernet frames to (de-)encapsulate (PCAP format)\n"


/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16


/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 *****************************************************************************/

static int test_encap_deencap(int do_encap,
                              char *src_filename,
                              char *cmp_filename);
static int compare_packets(unsigned char *pkt1, int pkt1_size,
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
  int do_encap = 1;
  int failure = 1;
  int args_used;

  /* parse program arguments, print the help message in case of failure */
  if(argc <= 1)
  {
    printf(TEST_USAGE);
    goto quit;
  }

  for(argc--, argv++; argc > 0; argc -= args_used, argv += args_used)
  {
    args_used = 1;

    if(!strcmp(*argv, "-v"))
    {
      /* print version */
      printf(TEST_VERSION);
      goto quit;
    }
    else if(!strcmp(*argv, "-h"))
    {
      /* print help */
      printf(TEST_USAGE);
      goto quit;
    }
    else if(!strcmp(*argv, "-c"))
    {
      args_used++;
    }
    else if(!strcmp(*argv, "-d"))
    {
      /* do we encapsulate or de-encapsulate ? */
      do_encap = 0;
    }
    else if(cmp_filename == NULL)
    {
      /* get the name of the file where the reference packets used for
         comparison are stored */
      cmp_filename = argv[0];
    }
    else if(src_filename == NULL)
    {
      /* get the name of the file that contains the packets to
         (de-)encapsulate */
      src_filename = argv[0];
    }
    else
    {
      /* do not accept more than 2 arguments without option name */
      printf(TEST_USAGE);
      goto quit;
    }
  }

  /* the comparison filename is mandatory */
  if(cmp_filename == NULL)
  {
    printf(TEST_USAGE);
    goto quit;
  }

  /* the source filename is mandatory */
  if(src_filename == NULL)
  {
    printf(TEST_USAGE);
    goto quit;
  }

  /* test (de-)encapsulation with the packets from the file */
  if(do_encap)
  {
    failure = test_encap_deencap(do_encap, src_filename, cmp_filename);
  }
  else
  {
    failure = test_encap_deencap(do_encap, src_filename, cmp_filename);
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
 * @brief Test the GSE library with a flow of IP or GSE packets to (de-)encapsulate
 *
 * @param do_encap      1 for encapsulation testing, 0 of de-encapsulation testing
 * @param src_filename  The name of the PCAP file that contains the source packets
 * @param cmp_filename  The name of the PCAP file that contains the reference packets
 *                      used for comparison
 * @return              0 in case of success, 1 otherwise
 */
static int test_encap_deencap(int do_encap,
                              char *src_filename,
                              char *cmp_filename)
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

  /* open the source dump file */
  handle = pcap_open_offline(src_filename, errbuf);
  if(handle == NULL)
  {
    printf("failed to open the source pcap file: %s\n", errbuf);
    goto error;
  }

  /* link layer in the source dump must be supported */
  link_layer_type_src = pcap_datalink(handle);
  if(link_layer_type_src != DLT_EN10MB &&
     link_layer_type_src != DLT_LINUX_SLL &&
     link_layer_type_src != DLT_RAW)
  {
    printf("link layer type %d not supported in source dump (supported = "
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
    printf("failed to open the comparison pcap file: %s\n", errbuf);
    goto close_input;
  }

  /* link layer in the comparison dump must be supported */
  link_layer_type_cmp = pcap_datalink(cmp_handle);
  if(link_layer_type_cmp != DLT_EN10MB &&
     link_layer_type_cmp != DLT_LINUX_SLL &&
     link_layer_type_cmp != DLT_RAW)
  {
    printf("link layer type %d not supported in comparison dump "
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

  /* TODO: init the GSE library here */

  /* for each packet in the dump */
  counter = 0;
  while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
  {
    unsigned char out_packet[4096];
    unsigned char *in_packet;
    size_t in_size;
    size_t out_size;

    counter++;

    /* check Ethernet frame length */
    if(header.len <= link_len_src || header.len != header.caplen)
    {
      printf("packet #%lu: bad PCAP packet (len = %d, caplen = %d)\n",
             counter, header.len, header.caplen);
      goto release_lib;
    }

    in_packet = packet + link_len_src;
    in_size = header.len - link_len_src;

    if(do_encap)
    {
      /* TODO: encapsulate the input packets, use in_packet and in_size as
               input and out_packet and out_size as output */
      out_size = MIN(in_size, 4096); /* TODO: replace this */
      memcpy(out_packet, in_packet, out_size); /* TODO: replace this */
    }
    else
    {
      /* TODO: de-encapsulate the input packets, use in_packet and in_size as
               input and out_packet and out_size as output */
      out_size = MIN(in_size, 4096); /* TODO: replace this */
      memcpy(out_packet, in_packet, out_size); /* TODO: replace this */
    }

    /* get next GSE packet from the comparison dump file */
    /* TODO: the following might be done several times in case of fragmentation */
    cmp_packet = (unsigned char *) pcap_next(cmp_handle, &cmp_header);
    if(cmp_packet == NULL)
    {
      printf("packet #%lu: no packet available for comparison\n", counter);
      goto release_lib;
    }

    /* compare the output packets with the ones given by the user */
    if(cmp_header.caplen <= link_len_cmp)
    {
      printf("packet #%lu: packet available for comparison but too small\n",
             counter);
      goto release_lib;
    }

    if(!compare_packets(out_packet, out_size, cmp_packet + link_len_cmp,
                        cmp_header.caplen - link_len_cmp))
    {
      printf("packet #%lu: generated packet is not as attended\n", counter);
      goto release_lib;
    }
  }

  /* everything went fine */
  is_failure = 0;

release_lib:
  /* TODO: relase the GSE library here */
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
static int compare_packets(unsigned char *pkt1, int pkt1_size,
                           unsigned char *pkt2, int pkt2_size)
{
  int valid = 1;
  int min_size;
  int i, j, k;
  char str1[4][7], str2[4][7];
  char sep1, sep2;

  min_size = pkt1_size > pkt2_size ? pkt2_size : pkt1_size;

  /* do not compare more than 180 bytes to avoid huge output */
  min_size = MAX(180, min_size);

  /* if packets are equal, do not print the packets */
  if(pkt1_size == pkt2_size && memcmp(pkt1, pkt2, pkt1_size) == 0)
    goto skip;

  /* packets are different */
  valid = 0;

  printf("------------------------------ Compare ------------------------------\n");

  if(pkt1_size != pkt2_size)
  {
    printf("packets have different sizes (%d != %d), compare only the %d "
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
          printf("%s  ", str1[k]);
        else /* fill the line with blanks if nothing to print */
          printf("        ");
      }

      printf("      ");

      for(k = 0; k < (j + 1); k++)
        printf("%s  ", str2[k]);

      printf("\n");

      j = 0;
    }
    else
    {
      j++;
    }
  }

  printf("----------------------- packets are different -----------------------\n");

skip:
  return valid;
}

