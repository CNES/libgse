/****************************************************************************/
/**
 * @file    test_encap_deencap.c
 * @brief   GSE encapsulation and deencapsulation test
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
#include "encap.h"
#include "deencap.h"
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
usage: test [verbose] [-lvl LEVEL] [-h] [-s] [-r REFRAG_FILENAME] FRAG_FILENAME FLOW\n\
  verbose          Print DEBUG information level 1\n\
  -lvl             Modify DEBUG level\n\
  LEVEL            New DEBUG level [0, 2]\n\
  -h               Print this usage and exit\n\
  -s               Save output packets instead of compare them\n\
  -r               Activate refragmentation\n\
  REFRAG_FILENAME  Save the refragmented packets or compare them\n\
                   with the reference packets stored in refrag_file (PCAP format)\n\
  FRAG_FILENAME    Save the fragmented packets or compare them\n\
                   with the reference packets stored in frag_file (PCAP format)\n\
  FLOW             Flow of Ethernet frames to encapsulate (PCAP format)\n"

/** The length of the Linux Cooked Sockets header */
#define LINUX_COOKED_HDR_LEN  16

#define QOS_NBR 10
#define FIFO_SIZE 100
#define PKT_NBR_MAX 1000 /** Number of fragments for one PDU */
#define PROTOCOL 9029

/** DEBUG macro */
#define DEBUG(verbose, format, ...) \
  do { \
    if(verbose) \
      printf(format, ##__VA_ARGS__); \
  } while(0)

#define DEBUG_L2(verbose, format, ...) \
  do { \
    if(verbose > 1) \
      printf(format, ##__VA_ARGS__); \
  } while(0)

static const size_t frag_length[20] = {
  128,  0,    1024, 256,  2048, 4096, 16,   64,   1024, 512,
  256,  512,  4096, 64,   128,  1024, 2048, 512,  256,  1024,
  };

static const size_t refrag_length[20] = {
  64,   1024, 512,  128,  32,   512,  16,   16,   256,  32,
  128,  128,  2048, 16,   64,   512,  16,   128,  128,  64,
  };



/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 *****************************************************************************/

static int test_encap_deencap(int verbose, int save, char *src_filename,
                              char *frag_filename, char *refrag_filename);
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
  char *frag_filename = NULL;
  char *refrag_filename = NULL;
  int save = 0;
  int refrag = 0;
  int failure = 1;
  int verbose = 0;
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

    if(!strcmp(*argv, "verbose"))
    {
      verbose = 1;
    }
    else if(!strcmp(*argv, "-lvl"))
    {
      args_used++;
      verbose = atoi(argv[1]);
      if((verbose < 0)  || (verbose > 2))
      {
         printf(TEST_USAGE);
         goto quit;
      }
    }
    else if(!strcmp(*argv, "-h"))
    {
      /* print help */
      printf(TEST_USAGE);
      goto quit;
    }
    else if(!strcmp(*argv, "-r"))
    {
      refrag = 1;
      args_used++;
      if(refrag_filename == NULL)
      {
        refrag_filename = argv[1];
      }
    }
    else if(!strcmp(*argv, "-s"))
    {
      /* do we save or compare packets */
      save = 1;
    }
    else if(frag_filename == NULL)
    {
      /* get the name of the file where the fragmented packets used for
         comparison are stored */
      frag_filename = argv[0];
    }
    else if(src_filename == NULL)
    {
      /* get the name of the file that contains the packets to
         encapsulate */
      src_filename = argv[0];
    }
    else
    {
      /* do not accept more than 2 arguments without option name */
      printf(TEST_USAGE);
      goto quit;
    }
  }

  /* the fragment filename is mandatory */
  if(frag_filename == NULL)
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

  if(refrag)
  {
    if(refrag_filename == NULL)
    {
      printf(TEST_USAGE);
      goto quit;
    }
    failure = test_encap_deencap(verbose, save, src_filename, frag_filename,
                                 refrag_filename);
  }
  else
  {
    failure = test_encap_deencap(verbose, save, src_filename, frag_filename, NULL);
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
 * @param frag_length   The maximum length of the fragments (0 for default)
 * @param src_filename  The name of the PCAP file that contains the source packets
 * @param gse_frag_filename  The name of the PCAP file that contains the reference packets
 *                      used for comparison
 * @return              0 in case of success, 1 otherwise
 */
static int test_encap_deencap(int verbose, int save, char *src_filename,
                              char *frag_filename, char *refrag_filename)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  pcap_t *frag_handle = NULL;
  pcap_t *refrag_handle = NULL;
  pcap_t *cmp_handle;
  pcap_dumper_t *frag_dumper = NULL;
  pcap_dumper_t *refrag_dumper = NULL;
  int link_layer_type_src;
  int link_layer_type_frag = 0;
  int link_layer_type_refrag = 0;
  int link_layer_type_cmp;
  uint32_t link_len_src;
  uint32_t link_len_frag = 0;
  uint32_t link_len_refrag = 0;
  uint32_t link_len_cmp;
  struct pcap_pkthdr header;
  struct pcap_pkthdr frag_header;
  struct pcap_pkthdr refrag_header;
  struct pcap_pkthdr cmp_header;
  unsigned char *packet;
  unsigned char *frag_packet;
  unsigned char *refrag_packet;
  unsigned char *cmp_packet;
  unsigned char link_layer_head[MAX(ETHER_HDR_LEN, LINUX_COOKED_HDR_LEN)];
  struct ether_header *eth_header;
  int is_failure = 1;
  unsigned long counter;
  unsigned long pkt_nbr = 0;
  unsigned long rcv_pkt_idx = 0;
  unsigned long pdu_counter;
  unsigned long refrag_idx = 0;
  unsigned long rcv_pkt_nbr = 0;
  gse_encap_t *encap = NULL;
  gse_deencap_t *deencap = NULL;
  vfrag_t **vfrag_pkt = NULL;
  vfrag_t **refrag_pkt = NULL;
  vfrag_t *pdu = NULL;
  vfrag_t *rcv_pdu = NULL;
  uint8_t rcv_label[6];
  uint8_t label_type;
  uint16_t protocol;
  uint16_t gse_length;
  uint8_t qos = 0;
  unsigned long i;
  int status;
  int frag_length_idx = 0;
  int refrag_length_idx = 0;
  int j;

  uint8_t label[6] = {
    0, 1, 2, 3, 4, 5,
    };

  if(!save)
  {
    if(refrag_filename != NULL)
    {
      DEBUG(verbose, "Compare fragmented packets with those in %s\n"
                     "Compare refragmented packets with those in %s\n",
            frag_filename, refrag_filename);
    }
    else
    {
      DEBUG(verbose, "Compare fragmented packets with those in %s\n",
            frag_filename);
    }
  }
  else
  {
    if(refrag_filename != NULL)
    {
      DEBUG(verbose, "Save fragmented packets in %s\n"
                     "Save refragmented packets in %s\n",
                     frag_filename, refrag_filename);
    }
    else
    {
      DEBUG(verbose, "Save fragmented packets in %s\n", frag_filename);
    }
  }
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

  if(!save)
  {
    /* open the comparison dump file for fragmented packets */
    frag_handle = pcap_open_offline(frag_filename, errbuf);
    if(frag_handle == NULL)
    {
      DEBUG(verbose, "failed to open the fragment pcap file: %s\n", errbuf);
      goto close_input;
    }

    /* link layer in the comparison dump must be supported */
    link_layer_type_frag = pcap_datalink(frag_handle);
    if(link_layer_type_frag != DLT_EN10MB &&
       link_layer_type_frag != DLT_LINUX_SLL &&
       link_layer_type_frag != DLT_RAW)
    {
      DEBUG(verbose, "link layer type %d not supported in fragment dump "
             "(supported = %d, %d, %d)\n", link_layer_type_frag, DLT_EN10MB,
             DLT_LINUX_SLL, DLT_RAW);
      goto close_frag_handle;
    }

    if(link_layer_type_frag == DLT_EN10MB)
      link_len_frag = ETHER_HDR_LEN;
    else if(link_layer_type_frag == DLT_LINUX_SLL)
      link_len_frag = LINUX_COOKED_HDR_LEN;
    else /* DLT_RAW */
      link_len_frag = 0;

    if(refrag_filename != NULL)
    {
      /* open the comparison dump file for refragmented packets */
      refrag_handle = pcap_open_offline(refrag_filename, errbuf);
      if(refrag_handle == NULL)
      {
        DEBUG(verbose, "failed to open the refragment pcap file: %s\n", errbuf);
        goto close_frag_handle;
      }

      /* link layer in the comparison dump must be supported */
      link_layer_type_refrag = pcap_datalink(refrag_handle);
      if(link_layer_type_refrag != DLT_EN10MB &&
         link_layer_type_refrag != DLT_LINUX_SLL &&
         link_layer_type_refrag != DLT_RAW)
      {
        DEBUG(verbose, "link layer type %d not supported in refragment dump "
               "(supported = %d, %d, %d)\n", link_layer_type_refrag, DLT_EN10MB,
               DLT_LINUX_SLL, DLT_RAW);
        goto close_refrag_handle;
      }

      if(link_layer_type_refrag == DLT_EN10MB)
        link_len_refrag = ETHER_HDR_LEN;
      else if(link_layer_type_refrag == DLT_LINUX_SLL)
        link_len_refrag = LINUX_COOKED_HDR_LEN;
      else /* DLT_RAW */
        link_len_refrag = 0;
    }
  }
  else
  {
    frag_dumper = pcap_dump_open(handle, frag_filename);
    if(frag_dumper == NULL)
    {
      DEBUG(verbose, "failed to open the refragment pcap dump: %s\n", errbuf);
      goto close_input;
    }

    if(refrag_filename != NULL)
    {
      refrag_dumper = pcap_dump_open(handle, refrag_filename);
      if(refrag_dumper == NULL)
      {
        DEBUG(verbose, "failed to open the refragment pcap dump: %s\n", errbuf);
        goto close_frag_handle;
      }
    }
  }

  /* open the comparison dump file for received pdu */
  cmp_handle = pcap_open_offline(src_filename, errbuf);
  if(cmp_handle == NULL)
  {
    DEBUG(verbose, "failed to open the comparison pcap file: %s\n", errbuf);
    goto close_refrag_handle;
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
  if(status != STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when initializing encapsulation (%s)\n", status,
          gse_get_status(status));
    goto close_comparison;
  }
  status = gse_deencap_init(QOS_NBR, &deencap);
  if(status != STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when initializing deencapsulation (%s)\n", status,
          gse_get_status(status));
    goto release_encap;
  }

  vfrag_pkt = malloc(sizeof(vfrag_t*) * PKT_NBR_MAX);
  refrag_pkt = malloc(sizeof(vfrag_t*) * PKT_NBR_MAX * 2);

  /* for each packet in the dump */
  counter = 0;
  pdu_counter = 0;
  while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
  {
    unsigned char *in_packet;
    size_t in_size;

    counter++;

    /* check Ethernet frame length */
    if(header.len <= link_len_src || header.len != header.caplen)
    {
      DEBUG(verbose, "PDU #%lu: bad PCAP packet (len = %d, caplen = %d)\n",
             counter, header.len, header.caplen);
      goto release_lib;
    }
    if(counter == 1)
    {
      memcpy(link_layer_head, packet, link_len_src);
    }

    in_packet = packet + link_len_src;
    in_size = header.len - link_len_src;

    /* Encapsulate the input packets, use in_packet and in_size as
       input */
    status = gse_create_vfrag_with_data(&pdu, in_size,
                                        GSE_MAX_HEADER_LENGTH,
                                        GSE_MAX_TRAILER_LENGTH,
                                        in_packet, in_size);
    if(status != STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when creating virtual fragment #%lu (%s)\n",
            status, counter, gse_get_status(status));
      goto release_lib;
    }

    status = gse_encap_receive_pdu(pdu, encap, label, 0, PROTOCOL, qos);
    if(status != STATUS_OK)
    {
      DEBUG(verbose, "Error %#.4x when receiving PDU #%lu (%s)\n", status, counter,
            gse_get_status(status));
      goto release_lib;
    }

    DEBUG(verbose, "\nPDU #%lu received from source file\n", counter);

    pkt_nbr = 0;
    rcv_pkt_idx = 0;
    rcv_pkt_nbr = 0;

    do{
      status = gse_encap_get_packet_copy(&vfrag_pkt[pkt_nbr], encap,
                                         frag_length[frag_length_idx], qos);
      if((status != STATUS_OK) && (status != FIFO_EMPTY))
      {
        DEBUG(verbose, "Error %#.4x when getting packet #%lu (%s)\n",
              status, pkt_nbr, gse_get_status(status));
        goto free_packets;
      }
      frag_length_idx = (frag_length_idx + 1) % 20;

      if(status == STATUS_OK)
      {
        if(!save)
        {
          frag_packet = (unsigned char *) pcap_next(frag_handle, &frag_header);
          if(frag_packet == NULL)
          {
            DEBUG(verbose, "packet #%lu: no packet available for comparison\n", pkt_nbr);
            goto free_packets;
          }

          /* compare the output fragmented packets with the ones given by the user */
          if(frag_header.caplen <= link_len_frag)
          {
            DEBUG(verbose, "packet #%lu: packet available for comparison but too small\n",
                  pkt_nbr);
            goto free_packets;
          }

          if(!compare_packets(verbose, vfrag_pkt[pkt_nbr]->start, vfrag_pkt[pkt_nbr]->length,
                              frag_packet + link_len_frag, frag_header.caplen - link_len_frag))
          {
            DEBUG(verbose, "packet #%lu: fragmented packet is not as attended\n", pkt_nbr);
            goto free_packets;
          }
        }
        else
        {
          if(frag_dumper != NULL)
          {
            header.len = link_len_src + vfrag_pkt[pkt_nbr]->length;
            header.caplen = header.len;
            unsigned char output_frag[vfrag_pkt[pkt_nbr]->length + link_len_src];
            memcpy(output_frag + link_len_src, vfrag_pkt[pkt_nbr]->start, vfrag_pkt[pkt_nbr]->length);
            if(link_len_src != 0)
            {
              //Copy link layer header from source packet
              memcpy(output_frag, link_layer_head, link_len_src);
              if(link_len_src == ETHER_HDR_LEN) /* Ethernet only */
              {
                eth_header = (struct ether_header *) output_frag;
                eth_header->ether_type = 0x162f; /* unused Ethernet ID ? */
              }
              else if(link_len_src == LINUX_COOKED_HDR_LEN) /* Linux Cooked Sockets only */
              {
                output_frag[LINUX_COOKED_HDR_LEN - 2] = 0x16;
                output_frag[LINUX_COOKED_HDR_LEN - 1] = 0x2f;
              }
            }
            pcap_dump((u_char *) frag_dumper, &header, output_frag);
          }
          else
          {
            DEBUG(verbose, "Fragment dumper missing\n");
            goto free_packets;
          }
        }
        pkt_nbr++;
      }
    }while(status != FIFO_EMPTY);

    DEBUG(verbose, "%lu packets got in FIFO %d\n", pkt_nbr, qos);

    if(refrag_filename != NULL)
    {
      for(refrag_idx = 0 ; refrag_idx < pkt_nbr ; refrag_idx++)
      {
        status = gse_refrag_packet(vfrag_pkt[refrag_idx], &refrag_pkt[refrag_idx], 
                 0, 0, qos, refrag_length[refrag_length_idx]);
        if((status != STATUS_OK) && (status != REFRAG_UNNECESSARY))
        {
          DEBUG(verbose, "Error %#.4x when refragmenting packet (%s)\n",
                status, gse_get_status(status));
          goto free_packets;
        }

        refrag_length_idx = (refrag_length_idx + 1) % 20;

        if(!save)
        {
          // First fragment
          refrag_packet = (unsigned char *) pcap_next(refrag_handle, &refrag_header);
          if(refrag_packet == NULL)
          {
            DEBUG(verbose, "packet #%lu: no packet available for comparison\n", refrag_idx);
            goto free_refrag_packets;
          }

          /* compare the output refragmented packets with the ones given by the user */
          if(refrag_header.caplen <= link_len_refrag)
          {
            DEBUG(verbose, "packet #%lu: packet available for comparison but too small\n",
                  refrag_idx);
            goto free_refrag_packets;
          }

          if(!compare_packets(verbose, vfrag_pkt[refrag_idx]->start, vfrag_pkt[refrag_idx]->length,
                              refrag_packet + link_len_refrag, refrag_header.caplen - link_len_refrag))
          {
            DEBUG(verbose, "packet #%lu: first refragmented packet is not as attended\n", refrag_idx);
            goto free_refrag_packets;
          }

          if(refrag_pkt[refrag_idx] != NULL)
          {
            // Second fragment
            refrag_packet = (unsigned char *) pcap_next(refrag_handle, &refrag_header);
            if(refrag_packet == NULL)
            {
              DEBUG(verbose, "packet #%lu: no packet available for comparison\n", refrag_idx);
              goto free_refrag_packets;
            }

            /* compare the output refragmented packets with the ones given by the user */
            if(refrag_header.caplen <= link_len_refrag)
            {
              DEBUG(verbose, "packet #%lu: packet available for comparison but too small\n", refrag_idx);
              goto free_refrag_packets;
            }

            if(!compare_packets(verbose, refrag_pkt[refrag_idx]->start, refrag_pkt[refrag_idx]->length,
                                refrag_packet + link_len_refrag, refrag_header.caplen - link_len_refrag))
            {
              DEBUG(verbose, "packet #%lu: second refragmented packet is not as attended\n", 
                    refrag_idx);
              goto free_refrag_packets;
            }
          }
        }
        else
        {
          if(refrag_dumper != NULL)
          {
            unsigned char output_refrag_first[vfrag_pkt[refrag_idx]->length + link_len_src];
            //first fragment
            header.len = link_len_src + vfrag_pkt[refrag_idx]->length;
            header.caplen = header.len;
            memcpy(output_refrag_first + link_len_src, vfrag_pkt[refrag_idx]->start,
                   vfrag_pkt[refrag_idx]->length);
            if(link_len_src != 0)
            {
              //Copy link layer header from source packet
              memcpy(output_refrag_first, link_layer_head, link_len_src);
              if(link_len_src == ETHER_HDR_LEN) /* Ethernet only */
              {
                eth_header = (struct ether_header *) output_refrag_first;
                eth_header->ether_type = 0x162f; /* unused Ethernet ID ? */
              }
              else if(link_len_src == LINUX_COOKED_HDR_LEN) /* Linux Cooked Sockets only */
              {
                output_refrag_first[LINUX_COOKED_HDR_LEN - 2] = 0x16;
                output_refrag_first[LINUX_COOKED_HDR_LEN - 1] = 0x2f;
              }
            }
            pcap_dump((u_char *) refrag_dumper, &header, output_refrag_first);

            if(refrag_pkt[refrag_idx] != NULL)
            {
              //second fragment
              unsigned char output_refrag_second[refrag_pkt[refrag_idx]->length + link_len_src];
              memcpy(output_refrag_second + link_len_src, refrag_pkt[refrag_idx]->start,
                     refrag_pkt[refrag_idx]->length);
              header.len = link_len_src + refrag_pkt[refrag_idx]->length;
              header.caplen = header.len;
              if(link_len_src != 0)
              {
                //Copy link layer header from source packet
                memcpy(output_refrag_second, link_layer_head, link_len_src);
                if(link_len_src == ETHER_HDR_LEN) /* Ethernet only */
                {
                  eth_header = (struct ether_header *) output_refrag_second;
                  eth_header->ether_type = 0x162f; /* unused Ethernet ID ? */
                }
                else if(link_len_src == LINUX_COOKED_HDR_LEN) /* Linux Cooked Sockets only */
                {
                  output_refrag_second[LINUX_COOKED_HDR_LEN - 2] = 0x16;
                  output_refrag_second[LINUX_COOKED_HDR_LEN - 1] = 0x2f;
                }
              }
              pcap_dump((u_char *) refrag_dumper, &header, output_refrag_second);
            }
          }
          else
          {
            DEBUG(verbose, "Fragent dumper missing\n");
            goto free_packets;
          }
        }
      }
    }

    do{
      do{
        if((vfrag_pkt[rcv_pkt_idx] != NULL))
        {
          status = gse_deencap_packet(vfrag_pkt[rcv_pkt_idx], deencap, &label_type, rcv_label,
                                      &protocol, &rcv_pdu, &gse_length);
          if((status != STATUS_OK) && (status != PDU))
          {
            DEBUG(verbose, "Error %#.4x when deencapsulating packet 1#%lu (%s)\n",
                  status, rcv_pkt_idx, gse_get_status(status));
            goto free_refrag_packets;
          }
          DEBUG_L2(verbose, "GSE packet #%lu received, GSE Length = %d\n", rcv_pkt_nbr,
                   gse_length);
          vfrag_pkt[rcv_pkt_idx] = NULL;
          rcv_pkt_nbr++;
        }
        if((refrag_filename != NULL) && (refrag_pkt[rcv_pkt_idx] != NULL) && (status != PDU))
        {
          status = gse_deencap_packet(refrag_pkt[rcv_pkt_idx], deencap, &label_type, rcv_label,
                                      &protocol, &rcv_pdu, &gse_length);
          if((status != STATUS_OK) && (status != PDU))
          {
            DEBUG(verbose, "Error %#.4x when deencapsulating packet 2#%lu (%s)\n",
                  status, rcv_pkt_idx, gse_get_status(status));
            goto free_refrag_packets;
          }
          DEBUG_L2(verbose, "GSE packet #%lu received, GSE Length = %d\n", rcv_pkt_nbr,
                   gse_length);
          refrag_pkt[rcv_pkt_idx] = NULL;
          rcv_pkt_nbr++;
        }
        rcv_pkt_idx++;
      }while((status != PDU) && (vfrag_pkt[rcv_pkt_idx] != NULL));
      if(status != PDU)
      {
        DEBUG(verbose, "Error not enough packet for PDU #%lu\n", pdu_counter + 1);
      }

      pdu_counter++;

      cmp_packet = (unsigned char *) pcap_next(cmp_handle, &cmp_header);
      if(cmp_packet == NULL)
      {
        DEBUG(verbose, "PDU #%lu: no PDU available for comparison\n", pdu_counter);
        goto free_pdu;
      }

      /* compare the output packets with the ones given by the user */
      if(cmp_header.caplen <= link_len_cmp)
      {
        DEBUG(verbose, "PDU #%lu: PDU available for comparison but too small\n",
              pdu_counter);
        goto free_pdu;
      }

      if(!compare_packets(verbose, rcv_pdu->start, rcv_pdu->length,
                          cmp_packet + link_len_cmp, cmp_header.caplen - link_len_cmp))
      {
        DEBUG(verbose, "PDU #%lu: generated PDU is not as attended\n", pdu_counter);
        goto free_pdu;
      }

      DEBUG(verbose, "Complete PDU #%lu:\nLabel Type: %d | Protocol: %#.4x | Label: %.2d",
            pdu_counter, label_type, protocol, rcv_label[0]);
      for(j = 1 ; j < gse_get_label_length(label_type) ; j++)
      {
        DEBUG(verbose, ":%.2d", rcv_label[j]);
      }
      DEBUG(verbose, " (in hexa)\n");

      if(rcv_pdu != NULL)
      {
        status = gse_free_vfrag(rcv_pdu);
        if(status != STATUS_OK)
        {
          DEBUG(verbose, "Error %#.4x when destroying pdu (%s)\n", status, gse_get_status(status));
          goto free_pdu;
        }
      rcv_pdu = NULL; 
      }
    }while(rcv_pkt_idx < pkt_nbr);
    qos = (qos + 1) % QOS_NBR;
  }

  /* everything went fine */
  is_failure = 0;

free_pdu:
  if(rcv_pdu != NULL)
  {
    status = gse_free_vfrag(rcv_pdu);
    if(status != STATUS_OK)
    {
      is_failure = 1;
      DEBUG(verbose, "Error %#.4x when destroying pdu (%s)\n", status, gse_get_status(status));
    }
  }
free_refrag_packets:
  if(refrag_filename != NULL)
  {
    for(i = refrag_idx ; i < pkt_nbr ; i++)
    {
      if(refrag_pkt[i] != NULL)
      {
        status = gse_free_vfrag(refrag_pkt[i]);
        if(status != STATUS_OK)
        {
          DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
        }
      }
    }
  }
free_packets:
  for(i = rcv_pkt_idx ; i < pkt_nbr ; i++)
  {
    if(vfrag_pkt[i] != NULL)
    {
      status = gse_free_vfrag(vfrag_pkt[i]);
      if(status != STATUS_OK)
      {
        DEBUG(verbose, "Error %#.4x when destroying packet (%s)\n", status, gse_get_status(status));
        is_failure = 1;
      }
    }
  }
release_lib:
  if(refrag_pkt != NULL)
  {
    free(refrag_pkt);
  }
  if(vfrag_pkt != NULL)
  {
    free(vfrag_pkt);
  }
  status = gse_deencap_release(deencap);
  if(status != STATUS_OK)
  {
    is_failure = 1;
    DEBUG(verbose, "Error %#.4x when releasing deencapsulation (%s)\n", status,
          gse_get_status(status));
  }
release_encap:
  status = gse_encap_release(encap);
  if(status != STATUS_OK)
  {
    is_failure = 1;
    DEBUG(verbose, "Error %#.4x when releasing encapsulation (%s)\n", status, gse_get_status(status));
  }
close_comparison:
    pcap_close(cmp_handle);
close_refrag_handle:
  if(refrag_filename != NULL)
  {
    if(!save)
    {
      pcap_close(refrag_handle);
    }
    else
    {
      if(refrag_dumper != NULL)
      {
        pcap_dump_close(refrag_dumper);
      }
    }
  }
close_frag_handle:
  if(!save)
  {
    pcap_close(frag_handle);
  }
  else
  {
    if(frag_dumper != NULL)
    {
      pcap_dump_close(frag_dumper);
    }
  }
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

