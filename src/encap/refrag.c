/*
 *
 * This piece of software is an implementation of the Generic Stream
 * Encapsulation (GSE) standard defined by ETSI for Linux (or other
 * Unix-compatible OS). The library may be used to add GSE
 * encapsulation/de-encapsulation capabilities to an application.
 *
 *
 * Copyright © 2016 TAS
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
 *   @file          refrag.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: REFRAGMENTATION
 *
 *   @brief         GSE refragmentation functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "refrag.h"

#include <assert.h>
#include <arpa/inet.h>

#include "constants.h"
#include "header.h"
#include "crc.h"



/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 ****************************************************************************/

/**
 *  @brief   Modify the header of the GSE packet that is being refragmented
 *
 *  @param   packet        IN/OUT: The GSE packet that is being refragmented
 *  @param   header        The initial header of the GSE packet that is being
 *                         refragmented
 *  @param   qos           The QoS of the packet
 *  @param   data_length   The length of the data field of the GSE packet (in bytes)
 *  @param   payload_type  The type of payload of the initial packet
 *
 *  @return
 *                         - success/informative code among:
 *                           - \ref GSE_STATUS_OK
 *                         - warning/error code among:
 *                           - \ref GSE_STATUS_INVALID_GSE_LENGTH
 *                           - \ref GSE_STATUS_INTERNAL_ERROR
 */
static gse_status_t gse_refrag_modify_header(gse_vfrag_t *packet,
                                             gse_header_t header,
                                             uint8_t qos, size_t data_length,
                                             gse_payload_type_t payload_type);

/**
 *  @brief   Compute the header length of the first fragment of a refragmented
 *           GSE packet according to its type
 *
 *  @param   payload_type   Type of data carried by the GSE packet
 *  @param   label_type     The Label Type of the GSE packet
 *
 *  @return                 The header length (in bytes) on success,
 *                          0 on error
 */
static size_t gse_refrag_compute_header_length(gse_payload_type_t payload_type,
                                               gse_label_type_t label_type);

/**
 *  @brief   Compute the value of the 'GSE Length' field of a GSE packet header
 *
 *  @param   payload_type   Type of data carried by the GSE packet
 *  @param   label_type     The Label Type of the GSE packet
 *  @param   data_length    The length of data field of the GSE packet
 *  @param   new_header     IN/OUT: The header of the GSE packet to update
 *
 *  @return
 *                          - success/informative code among:
 *                            - \ref GSE_STATUS_OK
 *                          - warning/error code among:
 *                            - \ref GSE_STATUS_INVALID_GSE_LENGTH
 *                            - \ref GSE_STATUS_INTERNAL_ERROR
 */
static gse_status_t gse_refrag_compute_gse_length(gse_payload_type_t payload_type,
                                                  gse_label_type_t label_type,
                                                  size_t data_length,
                                                  gse_header_t *new_header);

/**
 *  @brief   Create the header of the second fragment of GSE packet that is
 *           being refragmented
 *
 *  @param   packet         IN/OUT: The second fragment of the GSE packet being
 *                          refragmented
 *  @param   payload_type   The payload carried by the GSE packet being
 *                          refragmented
 *  @param   label_type     The Label Type of the GSE packet being refragmented
 *  @param   qos            The QoS of the GSE packet being refragmented
 *  @param   data_length    The length of data field of the second fragment
 *
 *  @return
 *                          - success/informative code among:
 *                            - \ref GSE_STATUS_OK\n
 *                          - warning/error code among:
 *                            - \ref GSE_STATUS_INVALID_GSE_LENGTH
 *                            - \ref GSE_STATUS_INTERNAL_ERROR
 */
static gse_status_t gse_refrag_create_header(gse_vfrag_t *packet,
                                             gse_payload_type_t payload_type,
                                             gse_label_type_t label_type,
                                             uint8_t qos,
                                             size_t data_length);

/**
 *  @brief   Compute the CRC32 from a GSE packet carrying a complete PDU.
 *
 *  The CRC32 is returned in NBO (Network Byte Order)
 *
 *  @param   packet        The GSE packet to compute the CRC for
 *  @param   data_length   The length of the PDU carried by the GSE packet
 *  @param   label_length  The length of the label of the GSE packet
 *
 *  @return                The CRC32
 */
static uint32_t gse_refrag_compute_crc(gse_vfrag_t *const packet,
                                       size_t data_length,
                                       size_t label_length);

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

gse_status_t gse_refrag_packet(gse_vfrag_t *packet1, gse_vfrag_t **packet2,
                               size_t head_offset, size_t trail_offset,
                               uint8_t qos, size_t max_length)
{
  gse_status_t status = GSE_STATUS_OK;

  gse_header_t header;
  gse_payload_type_t payload_type;
  size_t header_shift;
  size_t header_length;
  size_t init_data_length;
  size_t remaining_length;
  size_t header_shift_bkp;
  size_t trailer_shift_bkp;
  size_t header_length_bkp;
  uint32_t crc;
  uint16_t gse_length;

  if(packet1 == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  if(max_length > GSE_MAX_PACKET_LENGTH)
  {
    status = GSE_STATUS_LENGTH_TOO_HIGH;
    goto error;
  }
  if(max_length < GSE_MIN_PACKET_LENGTH)
  {
    status = GSE_STATUS_LENGTH_TOO_SMALL;
    goto error;
  }
  if(max_length >= packet1->length)
  {
    status = GSE_STATUS_REFRAG_UNNECESSARY;
    goto error;
  }

  /* make a backup copy of the header of the GSE packet being fragmented before
   * altering it */
  memcpy(&header, packet1->start, MIN(sizeof(gse_header_t), packet1->length));

  /* Extract the GSE Length of the header of the GSE packet */
  gse_length = ((uint16_t)header.gse_length_hi << 8) | header.gse_length_lo;
  if(gse_length != packet1->length - GSE_MANDATORY_FIELDS_LENGTH)
  {
    status = GSE_STATUS_INVALID_GSE_LENGTH;
    goto error;
  }
  /* Check the validity of the Label Length field */
  if(gse_get_label_length(header.lt) < 0)
  {
    status = GSE_STATUS_INVALID_LT;
    goto error;
  }

  /* Determine the type of payload of the GSE packet being refragmented with
   * the values of the S and E fields.
   * S and E values: - '00': subsequent fragment (not last)
   *                 - '01': last fragment
   *                 - '10': first fragment
   *                 - '11': complete PDU
   */
  if(header.s == 0x1)
  {
    if(header.e == 0x1)
    {
      payload_type = GSE_PDU_COMPLETE;
    }
    else
    {
      payload_type = GSE_PDU_FIRST_FRAG;
    }
  }
  else
  {
    if(header.e == 0x1)
    {
      payload_type = GSE_PDU_LAST_FRAG;
    }
    else
    {
      payload_type = GSE_PDU_SUBS_FRAG;
    }
  }
  /* Determine the header length of the GSE packet being refragmented */
  header_length = gse_compute_header_length(payload_type, header.lt);
  if(header_length == 0)
  {
    status = GSE_STATUS_INTERNAL_ERROR;
    goto error;
  }

  if(header_length > packet1->length)
  {
    status = GSE_STATUS_INVALID_HEADER;
    goto error;
  }

  /* Remember the payload length of the packet being refragmented */
  init_data_length = packet1->length - header_length;

  /* Compute the difference between the header length of the first GSE fragment
   * and the header length of the initial GSE packet.
   * There is a header shift only if the initial GSE packet contain a complete
   * PDU */
  header_shift = 0;
  if(payload_type == GSE_PDU_COMPLETE)
  {
    header_shift = GSE_MAX_REFRAG_HEAD_OFFSET;
  }

  /* Check if wanted length allows at least 1 bit of data */
  if((header_length + header_shift + 1) > max_length)
  {
    status = GSE_STATUS_LENGTH_TOO_SMALL;
    goto error;
  }

  /* Compute the remaining length of the data after first fragment creation */
  remaining_length = packet1->length + header_shift - max_length;

  /* Check if CRC32 will be fragmented in the case of a last fragment and avoid it */
  if((payload_type == GSE_PDU_LAST_FRAG) &&
     (remaining_length < GSE_MAX_TRAILER_LENGTH))
  {
    /* Reduce the length of the first fragment to be sure that the CRC32 field
     * of the second fragment will not be cut between two fragments */
    max_length -= (GSE_MAX_TRAILER_LENGTH - remaining_length);
    remaining_length = GSE_MAX_TRAILER_LENGTH;
  }

  /* Resize the GSE packet being fragmented to the size of the first fragment */
  status = gse_shift_vfrag(packet1, header_shift * -1, remaining_length * -1);
  if(status != GSE_STATUS_OK)
  {
    goto error;
  }
  /* Store the values of header and trailer shift and header length for
   * reinitialization in case of error */
  header_shift_bkp = header_shift;
  trailer_shift_bkp = remaining_length;
  header_length_bkp = header_length;

  /* Create the header of the first GSE fragment thanks to the backup of the
   * header of the original GSE packet */
  status = gse_refrag_modify_header(packet1, header, qos, init_data_length,
                                    payload_type);
  if(status != GSE_STATUS_OK)
  {
    goto resize;
  }

  /* Compute the header length of the second GSE fragment:
   * the second fragment is always a subsequent fragment or a last fragment and
   * these two packets types got the same header size */
  header_length = gse_compute_header_length(GSE_PDU_SUBS_FRAG, header.lt);
  if(header_length == 0)
  {
    status = GSE_STATUS_INTERNAL_ERROR;
    goto reinit;
  }

  /* Create the second fragment with remaining data. If the initial GSE packet
   * was carrying a complete PDU, a CRC32 must be added at the end of the data
   * because the second fragment will be a last one, so there is two separate
   * cases */
  if(payload_type == GSE_PDU_COMPLETE)
  {
    /* Second created fragment will be a last fragment, we need to add a CRC */
    status = gse_create_vfrag_with_data(packet2, remaining_length,
                                        header_length + head_offset,
                                        GSE_MAX_TRAILER_LENGTH + trail_offset,
                                        packet1->end, remaining_length);
    if(status != GSE_STATUS_OK)
    {
      goto reinit;
    }

    crc = gse_refrag_compute_crc(packet1, init_data_length,
                                 gse_get_label_length(header.lt));

    memcpy((*packet2)->end, &crc, GSE_MAX_TRAILER_LENGTH);

    status = gse_shift_vfrag(*packet2, header_length * -1, GSE_MAX_TRAILER_LENGTH);
    if(status != GSE_STATUS_OK)
    {
      goto free_packet;
    }

    /* Add CRC length to remaining length */
    remaining_length += GSE_MAX_TRAILER_LENGTH;
  }
  else
  {
    /* Check QoS */
    if(header.subs_frag_s.frag_id != qos)
    {
      status = GSE_STATUS_INVALID_QOS;
      goto reinit;
    }

    /* Create the second fragment */
    status = gse_create_vfrag_with_data(packet2, remaining_length,
                                        header_length + head_offset,
                                        trail_offset, packet1->end,
                                        remaining_length);
    if(status != GSE_STATUS_OK)
    {
      goto reinit;
    }

    status = gse_shift_vfrag(*packet2, header_length * -1, 0);
    if(status != GSE_STATUS_OK)
    {
      goto free_packet;
    }
  }

  /* Create the header of the second GSE fragment */
  status = gse_refrag_create_header(*packet2, payload_type, header.lt, qos,
                                    remaining_length);
  if(status != GSE_STATUS_OK)
  {
    goto free_packet;
  }

  return status;
free_packet:
  gse_free_vfrag(packet2);
reinit:
  gse_shift_vfrag(packet1, header_shift_bkp, trailer_shift_bkp);
  memcpy(packet1->start, &header, header_length_bkp);
error:
  *packet2 = NULL;
  return status;
resize:
  gse_shift_vfrag(packet1, header_shift_bkp, trailer_shift_bkp);
  *packet2 = NULL;
  return status;
}

/****************************************************************************
 *
 *   PRIVATE FUNCTIONS
 *
 ****************************************************************************/

static gse_status_t gse_refrag_modify_header(gse_vfrag_t *packet,
                                             gse_header_t header,
                                             uint8_t qos, size_t data_length,
                                             gse_payload_type_t payload_type)
{
  gse_status_t status = GSE_STATUS_OK;

  size_t data_field_length;
  size_t header_length;
  uint16_t total_length;
  gse_header_t *modified_hdr;

  assert(packet != NULL);

  modified_hdr = ((gse_header_t *)packet->start);

  header_length = gse_refrag_compute_header_length(payload_type, header.lt);
  if(header_length == 0)
  {
    status = GSE_STATUS_INTERNAL_ERROR;
    goto error;
  }
  data_field_length = packet->length - header_length;

  /* Determine the type of the GSE fragment according to the type of the initial
   * GSE packet and modify the GSE header in consequence.
   * There is no header shift except for complete payload type, so all the
   * fields are in correct position and only those which need to be modified
   * are changed */
  switch(payload_type)
  {
    /* Initial GSE packet carrying a complete PDU */
    case GSE_PDU_COMPLETE:
    {
      /* Complete -> FIRST FRAGMENT + last fragment */
      status = gse_refrag_compute_gse_length(GSE_PDU_FIRST_FRAG, header.lt,
                                             data_field_length, modified_hdr);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
      total_length = gse_get_label_length(header.lt) + data_length
                     + GSE_PROTOCOL_TYPE_LENGTH;

      modified_hdr->s = 0x1;
      modified_hdr->e = 0x0;
      modified_hdr->lt = header.lt;
      modified_hdr->first_frag_s.frag_id = qos;
      modified_hdr->first_frag_s.total_length = htons(total_length);
      modified_hdr->first_frag_s.protocol_type = header.complete_s.protocol_type;
      modified_hdr->first_frag_s.label = header.complete_s.label;
    }
    break;

    /* Initial GSE packet carrying a first fragment of PDU */
    case GSE_PDU_FIRST_FRAG:
    {
      /* First fragment -> FIRST FRAGMENT + subsequent fragment */
      status = gse_refrag_compute_gse_length(GSE_PDU_FIRST_FRAG, header.lt,
                                             data_field_length, modified_hdr);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
    }
    break;

    /* Initial GSE packet carrying a subsequent fragment of PDU which is not
     * the last one */
    case GSE_PDU_SUBS_FRAG:
    {
      /* Subsequent fragment -> SUBSEQUENT FRAGMENT + subsequent fragment */
      status = gse_refrag_compute_gse_length(GSE_PDU_SUBS_FRAG, header.lt,
                                             data_field_length, modified_hdr);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
    }
    break;

    /* Initial GSE packet carrying a last fragment of PDU */
    case GSE_PDU_LAST_FRAG:
    {
      /* Last fragment -> SUBSEQUENT FRAGMENT + last fragment */
      status = gse_refrag_compute_gse_length(GSE_PDU_SUBS_FRAG, header.lt,
                                             data_field_length, modified_hdr);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
      modified_hdr->e = 0x0;
    }
    break;

    default:
      /* Should not append */
      assert(0);
      status = GSE_STATUS_INTERNAL_ERROR;
      goto error;
  }

error:
  return status;
}

static size_t gse_refrag_compute_header_length(gse_payload_type_t payload_type,
                                               gse_label_type_t label_type)
{
  size_t header_length;

  switch(payload_type)
  {
    /* Initial GSE packet carrying a complete PDU or a first fragment of PDU */
    case GSE_PDU_COMPLETE:
    case GSE_PDU_FIRST_FRAG:
      /* complete | first fragment -> FIRST FRAGMENT + ... */
      header_length = gse_compute_header_length(GSE_PDU_FIRST_FRAG, label_type);
      break;

    /* Initial GSE packet carrying a subsequent fragment of PDU */
    case GSE_PDU_SUBS_FRAG:
    case GSE_PDU_LAST_FRAG:
      /* subsequent | last fragment -> SUBSEQUENT FRAGMENT + ... */
      header_length = gse_compute_header_length(GSE_PDU_SUBS_FRAG, label_type);
      break;

    default:
      /* Should not append */
      assert(0);
      header_length = 0;
  }
  return header_length;
}

static gse_status_t gse_refrag_compute_gse_length(gse_payload_type_t payload_type,
                                                  gse_label_type_t label_type,
                                                  size_t data_length,
                                                  gse_header_t *new_header)
{
  gse_status_t status = GSE_STATUS_OK;

  uint16_t gse_length;

  switch(payload_type)
  {
    /* There is no complete case because only fragments are considered */

    /* GSE packet carrying a first fragment of PDU */
    case GSE_PDU_FIRST_FRAG:
      gse_length = GSE_FRAG_ID_LENGTH +
                   GSE_TOTAL_LENGTH_LENGTH +
                   GSE_PROTOCOL_TYPE_LENGTH +
                   gse_get_label_length(label_type) +
                   data_length;
      break;

    /* GSE packet carrying a subsequent fragment of PDU */
    case GSE_PDU_SUBS_FRAG:
    case GSE_PDU_LAST_FRAG:
      gse_length = GSE_FRAG_ID_LENGTH +
                   data_length;
      break;

    default:
      /* Should not append */
      assert(0);
      status = GSE_STATUS_INTERNAL_ERROR;
      goto error;
  }
  if(gse_length > 0xFFF)
  {
    status = GSE_STATUS_INVALID_GSE_LENGTH;
    goto error;
  }

  new_header->gse_length_hi = (gse_length >> 8) & 0x0F;
  new_header->gse_length_lo = gse_length & 0xFF;

error:
  return status;
}

static gse_status_t gse_refrag_create_header(gse_vfrag_t *packet,
                                             gse_payload_type_t payload_type,
                                             gse_label_type_t label_type,
                                             uint8_t qos,
                                             size_t data_length)
{
  gse_status_t status = GSE_STATUS_OK;

  gse_header_t *created_hdr;

  assert(packet != NULL);

  created_hdr = ((gse_header_t *)packet->start);
  switch(payload_type)
  {
    /* Initial GSE packet carrying a complete PDU or a last fragment of PDU */
    case GSE_PDU_COMPLETE:
    case GSE_PDU_LAST_FRAG:
    {
      /* Complete | last fragment -> ... + LAST FRAGMENT */
      status = gse_refrag_compute_gse_length(GSE_PDU_LAST_FRAG, label_type,
                                             data_length, created_hdr);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
      created_hdr->s = 0x0;
      created_hdr->e = 0x1;
      created_hdr->lt = GSE_LT_REUSE;
      created_hdr->subs_frag_s.frag_id = qos;
    }
    break;

    /* Initial GSE packet carrying a fragment of PDU which is not the last one
     * or a complete PDU */
    case GSE_PDU_FIRST_FRAG:
    case GSE_PDU_SUBS_FRAG:
    {
      /* First | subsequent fragment -> ... + SUBSEQUENT FRAGMENT */
      status = gse_refrag_compute_gse_length(GSE_PDU_SUBS_FRAG, label_type,
                                             data_length, created_hdr);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
      created_hdr->s = 0x0;
      created_hdr->e = 0x0;
      created_hdr->lt = GSE_LT_REUSE;
      created_hdr->subs_frag_s.frag_id = qos;
    }
    break;

    default:
      /* Should not append */
      assert(0);
      status = GSE_STATUS_INTERNAL_ERROR;
      goto error;
  }

error:
  return status;
}

static uint32_t gse_refrag_compute_crc(gse_vfrag_t *const packet,
                                       size_t data_length,
                                       size_t label_length)
{
  uint32_t crc;
  unsigned char *data;

  data = packet->start + GSE_MANDATORY_FIELDS_LENGTH + GSE_FRAG_ID_LENGTH;
  data_length += GSE_TOTAL_LENGTH_LENGTH +
                 GSE_PROTOCOL_TYPE_LENGTH +
                 label_length;

  crc = compute_crc(data, data_length, GSE_CRC_INIT);

  return htonl(crc);
}
