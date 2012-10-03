/****************************************************************************/
/**
 *   @file          encap_header_ext.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: ENCAPSULATION
 *
 *   @brief         GSE functions for header extensions encapsulation
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "encap_header_ext.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <assert.h>

#include "refrag.h"
#include "header.h"
#include "header_fields.h"
#include "crc.h"


/** Get the minimum between two values */
#define MAX(x, y)  (((x) > (y)) ? (x) : (y))


/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

gse_status_t gse_encap_add_header_ext(gse_vfrag_t *packet,
                                      gse_vfrag_t **frag,
                                      uint32_t *crc,
                                      gse_encap_build_header_ext_cb_t callback,
                                      size_t max_packet_length,
                                      size_t head_offset,
                                      size_t trail_offset,
                                      uint8_t qos,
                                      void *opaque)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_header_t *header;
  size_t header_length = 0;
  gse_label_type_t lt;
  uint16_t protocol_type;
  uint16_t proto;
  uint16_t ext_type;
  uint16_t gse_length;
  gse_payload_type_t payload_type;
  unsigned char extensions[GSE_MAX_EXT_LENGTH];
  size_t tot_ext_length;
  size_t header_shift;
  int label_length;

  /* the space available for data in virtual fragment */
  size_t available_space;
  /* the size of GSE packet with extension */
  size_t new_packet_length;
  /* the space available before the packet in the virtual fragment */
  size_t available_start_offset;
  /* iterator to avoid infinite recursion */
  int iter = 0;
  int ret;

  *frag = NULL;

restart:
  iter ++;

  if(packet == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  header = (gse_header_t *)(packet->start);

  /* Determine the type of payload of the GSE packet being refragmented with
   * the values of the S and E fields.
   * S and E values: - '00': subsequent fragment (not last)
   *                 - '01': last fragment
   *                 - '10': first fragment
   *                 - '11': complete PDU
   */
  if(header->s == 0x1)
  {
    if(header->e == 0x1)
    {
      payload_type = GSE_PDU_COMPLETE;
      protocol_type = ntohs(header->complete_s.protocol_type);
    }
    else
    {
      payload_type = GSE_PDU_FIRST_FRAG;
      protocol_type = ntohs(header->first_frag_s.protocol_type);
    }
  }
  else
  {
    /* PDU fragment, no protocol_type field in header: cannot add extension */
    status = GSE_STATUS_EXTENSION_UNAVAILABLE;
    goto error;
  }
  if(protocol_type < GSE_MIN_ETHER_TYPE)
  {
    status = GSE_STATUS_EXTENSION_UNAVAILABLE;
    goto error;
  }

  tot_ext_length = GSE_MAX_EXT_LENGTH;
  /* get the extensions in order to use their length as soon as possible */
  ret = callback(extensions, &tot_ext_length, &ext_type, protocol_type, opaque);
  if(ret < 0)
  {
    status = GSE_STATUS_EXTENSION_CB_FAILED;
    goto error;
  }
  status = gse_check_header_extension_validity(extensions,
                                               &tot_ext_length,
                                               ext_type,
                                               &proto);
  if(status != GSE_STATUS_OK)
  {
    goto error;
  }
  if(proto != protocol_type)
  {
    status = GSE_STATUS_INVALID_EXTENSIONS;
    goto error;
  }

  /* compute the length for fragment shifting */
  header_shift = tot_ext_length;

  available_space = packet->vbuf->length - head_offset - trail_offset;
  new_packet_length = packet->length + header_shift;
  available_start_offset = (packet->start - packet->vbuf->start) -
                           head_offset;

  /* the maximum length should be at least the packet length but
   * at most the GSE maximum packet length */
  if(max_packet_length > 0)
  {
    max_packet_length = MAX(max_packet_length, packet->length);
    max_packet_length = MIN(GSE_MAX_PACKET_LENGTH, max_packet_length);
  }
  else
  {
    max_packet_length = GSE_MAX_PACKET_LENGTH;
  }

  gse_length = ((uint16_t)header->gse_length_hi << 8) |
               header->gse_length_lo;

  if(gse_length != packet->length - GSE_MANDATORY_FIELDS_LENGTH)
  {
    status = GSE_STATUS_INVALID_GSE_LENGTH;
    goto error;
  }

  /* handle complete PDU */
  if(payload_type == GSE_PDU_COMPLETE)
  {
    /* packet + extensions to long to carry a complete PDU  => fragment it */
    if(new_packet_length > max_packet_length)
    {
      status = gse_refrag_packet(packet, frag, head_offset, trail_offset, qos,
                                 max_packet_length - header_shift);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
      goto restart;
    }

    /* check if we have enough space at virtual buffer beginning,
     * else reallocate it */
    if(available_space < new_packet_length ||
       available_start_offset < header_shift)
    {
      status = gse_reallocate_vfrag(packet,
                                    head_offset + header_shift,
                                    new_packet_length,
                                    head_offset, trail_offset);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
    }

    /* Get the Label Type */
    lt = header->lt;
    label_length = gse_get_label_length(lt);
    if(label_length < 0)
    {
      status = GSE_STATUS_INVALID_LT;
      goto error;
    }

    /* get the header length in order to move the header */
    header_length = gse_compute_header_length(payload_type, lt);
    if(header_length == 0)
    {
      status = GSE_STATUS_INTERNAL_ERROR;
      goto error;
    }

    /* move the start of packet in order to add extensions */
    status = gse_shift_vfrag(packet, header_shift * -1, 0);
    if(status != GSE_STATUS_OK)
    {
      goto error;
    }
    /* move the header data */
    memmove(packet->start, header, header_length);
    header = (gse_header_t *)(packet->start);

    /* add extensions */
    memcpy(packet->start + header_length, extensions, tot_ext_length);

    /* modify the Protocol Type and GSE Length fields */
    header->gse_length_hi = ((gse_length + header_shift) >> 8)
                            & 0x0F;
    header->gse_length_lo = (gse_length + header_shift) & 0xFF;
    header->complete_s.protocol_type = htons(ext_type);
  }

  if(iter > 2)
  {
    status = GSE_STATUS_INTERNAL_ERROR;
    goto error;
  }

  /* handle first_fragment, shall be done here because it is also used in
   * case of refragmentation */
  if(payload_type == GSE_PDU_FIRST_FRAG)
  {
    uint16_t total_length;

    total_length = ntohs(header->first_frag_s.total_length);

    /* PDU + extensions too long to be encapsulated */
    if(total_length + header_shift > GSE_MAX_PDU_LENGTH)
    {
      status = GSE_STATUS_EXTENSION_UNAVAILABLE;
      goto error;
    }

    /* packet + extensions to long to carry the data => fragment it */
    if(new_packet_length > max_packet_length)
    {
      /* we should not refragment if it was already done */
      if(*frag != NULL)
      {
        status = GSE_STATUS_INTERNAL_ERROR;
        goto error;
      }

      status = gse_refrag_packet(packet, frag, head_offset, trail_offset, qos,
                                 max_packet_length - header_shift);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
      goto restart;
    }

    /* check if we have enough space at virtual buffer beginning,
     * else reallocate it */
    if(available_space < new_packet_length ||
       available_start_offset < header_shift)
    {
      status = gse_reallocate_vfrag(packet,
                                    head_offset + header_shift,
                                    new_packet_length,
                                    head_offset, trail_offset);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
    }

    /* Get the Label Type */
    lt = header->lt;
    label_length = gse_get_label_length(lt);
    if(label_length < 0)
    {
      status = GSE_STATUS_INVALID_LT;
      goto error;
    }

    /* get the header length in order to move the header */
    header_length = gse_compute_header_length(payload_type, lt);
    if(header_length == 0)
    {
      status = GSE_STATUS_INTERNAL_ERROR;
      goto error;
    }

    /* move the start of packet in order to add extensions */
    status = gse_shift_vfrag(packet, header_shift * -1, 0);
    if(status != GSE_STATUS_OK)
    {
      goto error;
    }
    /* move the header data */
    memmove(packet->start, header, header_length);
    header = (gse_header_t *)(packet->start);

    /* add extensions */
    memcpy(packet->start + header_length, extensions, tot_ext_length);

    /* modify the Protocol Type, GSE Length and Total Length fields */
    header->gse_length_hi = ((gse_length + header_shift) >> 8)
                            & 0x0F;
    header->first_frag_s.total_length = htons(total_length + header_shift);
    header->gse_length_lo = (gse_length + header_shift) & 0xFF;
    header->first_frag_s.protocol_type = htons(ext_type);
  }

  /* if we got a first fragment, compute the temporary CRC;
   * if frag is a last fragment, modify its CRC */
  if(payload_type != GSE_PDU_COMPLETE || *frag != NULL)
  {
    uint32_t tmp_crc;
    unsigned char *data;
    size_t length;

    /* compute CRC on the first fragment */
    data = packet->start + GSE_MANDATORY_FIELDS_LENGTH + GSE_FRAG_ID_LENGTH;
    length = packet->length - GSE_MANDATORY_FIELDS_LENGTH - GSE_FRAG_ID_LENGTH;
    tmp_crc = compute_crc(data, length, GSE_CRC_INIT);

    /* add CRC computation on frag if necessary */
    if(*frag != NULL)
    {
      status = gse_encap_update_crc(*frag, &tmp_crc);
      if(status == GSE_STATUS_PARTIAL_CRC)
      {
        *crc = tmp_crc;
      }
    }
    /* we only got the first fragment, return CRC */
    else
    {
      *crc = tmp_crc;
      status = GSE_STATUS_PARTIAL_CRC;
    }
  }

error:
  return status;
}

gse_status_t gse_encap_update_crc(gse_vfrag_t *packet,
                                  uint32_t *crc)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_header_t *header;
  gse_payload_type_t payload_type;
  uint32_t tmp_crc;
  unsigned char *data;
  size_t length;
  int label_length;

  if(packet == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto quit;
  }

  header = (gse_header_t *)(packet->start);

  /* Determine the type of payload of the GSE packet being refragmented with
   * the values of the S and E fields.
   * S and E values: - '00': subsequent fragment (not last)
   *                 - '01': last fragment
   *                 - '10': first fragment
   *                 - '11': complete PDU
   */
  if(header->s == 0x1)
  {
    /* last packet should have been lost or the function was badly called */
    *crc = GSE_CRC_INIT;
    goto quit;
  }
  else
  {
    if(header->e == 0x1)
    {
      payload_type = GSE_PDU_LAST_FRAG;
    }
    else
    {
      payload_type = GSE_PDU_SUBS_FRAG;
    }
  }

  label_length = gse_get_label_length(header->lt);
  if(label_length < 0)
  {
    status = GSE_STATUS_INVALID_LT;
    goto quit;
  }

  data = packet->start + GSE_MANDATORY_FIELDS_LENGTH + GSE_FRAG_ID_LENGTH;
  length = packet->length - GSE_MANDATORY_FIELDS_LENGTH
                          - GSE_FRAG_ID_LENGTH
                          - label_length;

  if(payload_type == GSE_PDU_LAST_FRAG)
  {
    length -= GSE_MAX_TRAILER_LENGTH;
  }

  tmp_crc = compute_crc(data, length, *crc);

  if(payload_type == GSE_PDU_LAST_FRAG)
  {
    tmp_crc = htonl(tmp_crc);
    memcpy(packet->end - GSE_MAX_TRAILER_LENGTH, &tmp_crc,
           GSE_MAX_TRAILER_LENGTH);
  }
  else
  {
    *crc = tmp_crc;
    status = GSE_STATUS_PARTIAL_CRC;
  }

quit:
  return status;
}


