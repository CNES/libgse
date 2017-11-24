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
 *   @file          deencap.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: DEENCAPSULATION
 *
 *   @brief         GSE deencapsulation functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "deencap.h"

#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>

#include "constants.h"
#include "header.h"
#include "crc.h"
#include "header_fields.h"


/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** Deencapsulation context */
typedef struct
{
  gse_vfrag_t *partial_pdu;    /**< Virtual buffer containing the PDU chunks */
  gse_label_t label;           /**< Label field value */
  uint16_t total_length;       /**< Total length field value */
  size_t tot_ext_length;       /**< The length of extensions */
  uint16_t protocol_type;      /**< Protocol type field value */
  gse_label_type_t label_type; /**< Label type field value */
  unsigned int bbframe_nbr;    /**< Number of BB Frames since the reception of
                                    first fragment */
  uint32_t crc;                /**< CRC32 computed with chunks of PDU */
} gse_deencap_ctx_t;

/** Deencapsulation structure */
struct gse_deencap_s
{
  gse_deencap_ctx_t *deencap_ctx; /**< Table of deencapsulation contexts */
  size_t head_offset;             /**< Offset applied on the beginning of the
                                       returned PDU (default: 0) */
  size_t trail_offset;            /**< Offset applied on the end of the
                                       returned PDU (default: 0) */
  uint8_t qos_nbr;                /**< Size of the deencapsulation context table,
                                       number of potential Frag ID */
  /**> Callback to read header extensions */
  gse_deencap_read_header_ext_cb_t read_header_ext;
  void *opaque;                   /**< User specific data for extension callback */
};


/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 ****************************************************************************/

/**
 *  @brief   Get the QoS number for deencapsulation context
 *
 *  @param   deencap   Structure of deencapsulation contexts
 *
 *  @return            Number of different QoS values on success,
 *                     -1 on failure
 */
static uint8_t gse_deencap_get_qos_nbr(gse_deencap_t *const deencap);

/**
 *  @brief   Create deencapsulation context
 *
 *  @param   partial_pdu  The GSE packet received
 *  @param   deencap      The deencapsulation structure
 *  @param   header       Header of the GSE packet carrying data
 *  @param   crc          The header part of CRC32
 *
 *  @return
 *                        - success/informative code among:
 *                          - \ref GSE_STATUS_OK
 *                        - warning/error code among:
 *                          - \ref GSE_STATUS_INVALID_QOS
 *                          - \ref GSE_STATUS_EXTENSION_NOT_SUPPORTED
 *                          - \ref GSE_STATUS_DATA_OVERWRITTEN
 *                          - \ref GSE_STATUS_INVALID_LT
 *                          - \ref GSE_STATUS_BUFF_LENGTH_NULL
 *                          - \ref GSE_STATUS_MALLOC_FAILED
 *                          - \ref GSE_STATUS_NULL_PTR
 *                          - \ref GSE_STATUS_MULTIPLE_VBUF_ACCESS
 *                          - \ref GSE_STATUS_DATA_TOO_LONG
 */
static gse_status_t gse_deencap_create_ctx(gse_vfrag_t *partial_pdu,
                                           gse_deencap_t *deencap,
                                           gse_header_t header,
                                           uint32_t crc);

/**
 *  @brief   Fill deencapsulation context with fragments
 *
 *  @param   pactial_pdu  The GSE packet received
 *  @param   deencap      The deencapsulation structure
 *  @param   header       Header of the GSE packet carrying data
 *
 *  @return
 *                        - success/informative code among:
 *                          - \ref GSE_STATUS_OK
 *                          - \ref GSE_STATUS_TIMEOUT
 *                        - warning/error code among:
 *                          - \ref GSE_STATUS_INVALID_LT
 *                          - \ref GSE_STATUS_INVALID_QOS
 *                          - \ref GSE_STATUS_CTX_NOT_INIT
 *                          - \ref GSE_STATUS_NO_SPACE_IN_BUFF
 *                          - \ref GSE_STATUS_NULL_PTR
 *                          - \ref GSE_STATUS_PTR_OUTSIDE_BUFF
 *                          - \ref GSE_STATUS_FRAG_PTRS
 */
static gse_status_t gse_deencap_add_frag(gse_vfrag_t *data, gse_deencap_t *deencap,
                                         gse_header_t header);

/**
 *  @brief   Complete deencapsulation context with a last fragment
 *
 *  @param   partial_pdu  The GSE packet received
 *  @param   deencap      The deencapsulation structure
 *  @param   header       Header of the GSE packet carrying data
 *
 *  @return
 *                        - success/informative code among:
 *                          - \ref GSE_STATUS_OK
 *                        - warning/error code among:
 *                          - \ref GSE_STATUS_NULL_PTR
 *                          - \ref GSE_STATUS_PTR_OUTSIDE_BUFF
 *                          - \ref GSE_STATUS_FRAG_PTRS
 *                          - \ref GSE_STATUS_INVALID_LT
 *                          - \ref GSE_STATUS_INVALID_QOS
 *                          - \ref GSE_STATUS_CTX_NOT_INIT
 *                          - \ref GSE_STATUS_NO_SPACE_IN_BUFF
 *                          - \ref GSE_STATUS_INVALID_DATA_LENGTH
 *                          - \ref GSE_STATUS_INVALID_CRC
 */
static gse_status_t gse_deencap_add_last_frag(gse_vfrag_t *data,
                                              gse_deencap_t *deencap,
                                              gse_header_t header);

/**
 *  @brief   Compute PDU length from total length field
 *
 *  @param   total_length   The total length field of the GSE packet
 *  @param   label_type     The type of label
 *  @param   tot_ext_length The total extension length
 *
 *  @return                 The PDU Length
 */
static size_t gse_deencap_compute_pdu_length(uint16_t total_length,
                                             gse_label_type_t label_type,
                                             size_t tot_ext_length);

/**
 *  @brief   Compute the CRC32
 *
 *  The CRC32 is returned in NBO (Network Byte Order)
 *
 *  @pram    data      The data used to compute the CRC32
 *  @param   length    The length of the data
 *  @param   crc_init  The initial value of CRC32
 *
 *  @return            The CRC32
 */
static uint32_t gse_deencap_compute_crc(unsigned char *data,
                                        size_t length,
                                        uint32_t crc_init);


/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

/* Deencapsulation context initialization and release */

gse_status_t gse_deencap_init(uint8_t qos_nbr, gse_deencap_t **deencap)
{
  gse_status_t status;

  if(deencap == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  /* Allocate memory for the deencapsulation structure */
  *deencap = calloc(1, sizeof(gse_deencap_t));
  if(*deencap == NULL)
  {
    status = GSE_STATUS_MALLOC_FAILED;
    goto error;
  }

  /* Check the QoS number value is correct */
  if(qos_nbr == 0)
  {
    status = GSE_STATUS_INVALID_QOS;
    goto error;
  }

  /* Create as deencapsulation contexts as QoS values
   * The context are initialized to 0 because on release, virtual fragments
   * contained by context must be destroyed only if they exist */
  (*deencap)->deencap_ctx = calloc(qos_nbr, sizeof(gse_deencap_ctx_t));
  if((*deencap)->deencap_ctx == NULL)
  {
    status = GSE_STATUS_MALLOC_FAILED;
    goto free_deencap;
  }
  (*deencap)->qos_nbr = qos_nbr;

  /* Initialize the offsets of the virtual buffers of the PDUs to 0 by default */
  status = gse_deencap_set_offsets(*deencap, 0, 0);
  if(status != GSE_STATUS_OK)
  {
    goto free_deencap;
  }

  return GSE_STATUS_OK;

free_deencap:
  free(*deencap);
  *deencap = NULL;
error:
  return status;
}

gse_status_t gse_deencap_release(gse_deencap_t *deencap)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_status_t stat_mem = GSE_STATUS_OK;

  unsigned int i;

  if(deencap == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  /* Release each context */
  for(i = 0; i < gse_deencap_get_qos_nbr(deencap); i++)
  {
    if(deencap->deencap_ctx[i].partial_pdu != NULL)
    {
      status = gse_free_vfrag(&(deencap->deencap_ctx[i].partial_pdu));
      if(status != GSE_STATUS_OK)
      {
        stat_mem = status;
      }
    }
  }
  free(deencap->deencap_ctx);
  free(deencap);

  return stat_mem;
error:
  return status;
}

gse_status_t gse_deencap_set_offsets(gse_deencap_t *deencap, size_t head_offset,
                                     size_t trail_offset)
{
  if(deencap == NULL)
  {
    return GSE_STATUS_NULL_PTR;
  }
  deencap->head_offset = head_offset;
  deencap->trail_offset = trail_offset;
  return GSE_STATUS_OK;
}

/* Deencapsulation functions */

gse_status_t gse_deencap_packet(gse_vfrag_t *data, gse_deencap_t *deencap,
                                uint8_t *label_type, uint8_t label[6],
                                uint16_t *protocol, gse_vfrag_t **pdu,
                                uint16_t *packet_length)
{
  gse_status_t status = GSE_STATUS_OK;

  gse_header_t header;
  gse_payload_type_t payload_type;
  size_t header_length;
  size_t head_offset;
  size_t field_length;
  uint16_t data_length;
  int label_length;
  uint32_t crc = GSE_CRC_INIT;
  gse_vfrag_t *packet;

  if((data == NULL) || (deencap == NULL) || (label_type == NULL) ||
     (protocol == NULL) || (packet_length == NULL) || (pdu == NULL))
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }
  *pdu = NULL;

  /* Sanity check for arguments */
  if(data->length < GSE_MIN_PACKET_LENGTH)
  {
    status = GSE_STATUS_PACKET_TOO_SMALL;
    goto free_data;
  }

  memcpy(&header, data->start, MIN(sizeof(gse_header_t), data->length));

  /* Check for padding pattern in data */
  if((header.s == 0x0) && (header.e == 0x0) && (header.lt == 0x0))
  {
    /* Padding was detected so there is no GSE packet to deencapsulate, stop
     * algorithm now */
    status = GSE_STATUS_PADDING_DETECTED;
    goto free_data;
  }

  /* Determine the length of the GSE packet in the received data */
  *packet_length = (((uint16_t)header.gse_length_hi << 8) | header.gse_length_lo)
                   + GSE_MANDATORY_FIELDS_LENGTH;
  if((size_t)(*packet_length) > data->length)
  {
    status = GSE_STATUS_INVALID_GSE_LENGTH;
    goto free_data;
  }

  /* Create a GSE packet from the received data */
  status = gse_duplicate_vfrag(&packet, data, *packet_length);
  if(status != GSE_STATUS_OK)
  {
    goto free_data;
  }

  /* Destroy the received data since it is not required anymore
   * The error are not treated because the data are correctly saved */
  gse_free_vfrag(&data);

  if(packet->length < GSE_MIN_PACKET_LENGTH)
  {
    status = GSE_STATUS_PACKET_TOO_SMALL;
    goto free_packet;
  }

  /* Get the payload type with S and E values:
   *    - '00': subsequent fragment (but not the last one)
   *    - '01': last fragment
   *    - '10': first fragment
   *    - '11': complete PDU
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

  /* Determine the length of the label of the GSE packet */
  label_length = gse_get_label_length(header.lt);
  if(label_length < 0)
  {
    goto free_packet;
  }

  /* Determine the length of the GSE header */
  header_length = gse_compute_header_length(payload_type, header.lt);
  if(header_length == 0)
  {
    status = GSE_STATUS_INTERNAL_ERROR;
    goto free_packet;
  }
  if(header_length > packet->length)
  {
    status = GSE_STATUS_INVALID_HEADER;
    goto free_packet;
  }

  /* Check if the last fragment contain at least the complete CRC */
  data_length = packet->length - header_length;
  if((payload_type == GSE_PDU_LAST_FRAG) && (data_length < GSE_MAX_TRAILER_LENGTH))
  {
    status = GSE_STATUS_CRC_FRAGMENTED;
    goto free_packet;
  }

  /* Compute the header part of the CRC32 if the fragment is a first one */
  if(payload_type == GSE_PDU_FIRST_FRAG)
  {
    head_offset = GSE_MANDATORY_FIELDS_LENGTH + GSE_FRAG_ID_LENGTH;
    field_length = GSE_TOTAL_LENGTH_LENGTH + GSE_PROTOCOL_TYPE_LENGTH +
                   gse_get_label_length(header.lt);
    crc = gse_deencap_compute_crc(packet->start + head_offset, field_length,
                                  GSE_CRC_INIT);
  }

  /* Move fragment start pointer to the beginning of data field */
  status = gse_shift_vfrag(packet, header_length, 0);
  if(status != GSE_STATUS_OK)
  {
    goto free_packet;
  }

  /* Deencapsulate the GSE packet according to its payload */
  switch(payload_type)
  {
    /* GSE packet carrying a complete PDU */
    case GSE_PDU_COMPLETE:
    {
      size_t tot_ext_length = 0;
      
      *protocol = ntohs(header.complete_s.protocol_type);
      /* read header extensions */
      if(*protocol < GSE_MIN_ETHER_TYPE)
      {
        int ret;
        uint16_t protocol_type;
        uint16_t extension_type = *protocol;

        if(deencap->read_header_ext == NULL)
        {
          status = GSE_STATUS_EXTENSION_NOT_SUPPORTED;
          goto free_packet;
        }

        tot_ext_length = packet->length;
        ret = deencap->read_header_ext(packet->start, &tot_ext_length,
                                       &protocol_type, extension_type,
                                       deencap->opaque);
        if(ret < 0)
        {
          status = GSE_STATUS_EXTENSION_CB_FAILED;
          goto free_packet;
        }
        *protocol = protocol_type;

        /* check extensions validity */
        status = gse_check_header_extension_validity(packet->start,
                                                     &tot_ext_length,
                                                     extension_type,
                                                     &protocol_type);
        if(status != GSE_STATUS_OK)
        {
          goto free_packet;
        }
        if(protocol_type != *protocol)
        {
          status = GSE_STATUS_INVALID_EXTENSIONS;
          goto free_packet;
        }

        /* move PDU start after extensions */
        status = gse_shift_vfrag(packet, tot_ext_length, 0);
        if(status != GSE_STATUS_OK)
        {
          goto free_packet;
        }
      }
      *label_type = header.lt;
      memcpy(label, header.complete_s.label.six_bytes_label,
             label_length);
      /* Check if label is not '00:00:00:00:00:00' */
      if(label_length == 6 &&
         memcmp(label, "\x0\x0\x0\x0\x0\x0", 6) == 0)
      {
        status = GSE_STATUS_INVALID_LABEL;
        goto free_packet;
      }
      *protocol = ntohs(header.complete_s.protocol_type);
      *pdu = packet;

      /* Create the virtual buffer containing the PDU with appropriated offsets */
      status = gse_create_vfrag_with_data(pdu, packet->length,
                                          deencap->head_offset,
                                          deencap->trail_offset,
                                          packet->start, packet->length);
      gse_free_vfrag(&packet);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
      status = GSE_STATUS_PDU_RECEIVED;
    }
    break;

    /* GSE packet carrying a first fragment of PDU */
    case GSE_PDU_FIRST_FRAG:
    {
      status = gse_deencap_create_ctx(packet, deencap, header, crc);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
    }
    break;

    /* GSE packet carrying a subsequent fragment of PDU (but not the last one) */
    case GSE_PDU_SUBS_FRAG:
    {
      status = gse_deencap_add_frag(packet, deencap, header);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
    }
    break;

    /* GSE packet carrying a last fragment of PDU */
    case GSE_PDU_LAST_FRAG:
    {
      gse_deencap_ctx_t *ctx;

      status = gse_deencap_add_last_frag(packet, deencap, header);
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }

      /*  Create a new fragment in order to free context */
      ctx = &(deencap->deencap_ctx[header.subs_frag_s.frag_id]);
      *label_type = ctx->label_type;
      label_length = gse_get_label_length(ctx->label_type);
      if(label_length < 0)
      {
        status = GSE_STATUS_INVALID_LT;
        goto error;
      }
      memcpy(label, &(ctx->label), label_length);
      *protocol = ctx->protocol_type;

      /* Create the virtual buffer containing the PDU with appropriated offsets */
      status = gse_create_vfrag_with_data(pdu, ctx->partial_pdu->length,
                                          deencap->head_offset,
                                          deencap->trail_offset,
                                          ctx->partial_pdu->start,
                                          ctx->partial_pdu->length);
      gse_free_vfrag(&(ctx->partial_pdu));
      if(status != GSE_STATUS_OK)
      {
        goto error;
      }
      status = GSE_STATUS_PDU_RECEIVED;
    }
    break;

    default:
      /* Should not append */
      assert(0);
      status = GSE_STATUS_INTERNAL_ERROR;
      goto free_packet;
  }

  return status;
free_data:
  gse_free_vfrag(&data);
  return status;
free_packet:
  gse_free_vfrag(&packet);
error:
  return status;
}

gse_status_t gse_deencap_new_bbframe(gse_deencap_t *deencap)
{
  unsigned int i;

  if(deencap == NULL)
  {
    return GSE_STATUS_NULL_PTR;
  }

  for(i = 0 ; i < gse_deencap_get_qos_nbr(deencap) ; i++)
  {
    if(deencap->deencap_ctx[i].partial_pdu != NULL)
    {
      deencap->deencap_ctx[i].bbframe_nbr++;
    }
  }

  return GSE_STATUS_OK;
}

gse_status_t gse_deencap_set_extension_callback(gse_deencap_t *deencap,
                                                gse_deencap_read_header_ext_cb_t callback,
                                                void *opaque)
{
  if(deencap == NULL)
  {
    return GSE_STATUS_NULL_PTR;
  }

  deencap->read_header_ext = callback;
  deencap->opaque = opaque;

  return GSE_STATUS_OK;
}


/****************************************************************************
 *
 *   PRIVATE FUNCTIONS
 *
 ****************************************************************************/

static uint8_t gse_deencap_get_qos_nbr(gse_deencap_t *deencap)
{
  assert(deencap != NULL);

  return deencap->qos_nbr;
}

static gse_status_t gse_deencap_create_ctx(gse_vfrag_t *partial_pdu, gse_deencap_t *deencap,
                                           gse_header_t header, uint32_t crc)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_deencap_ctx_t *ctx;
  uint16_t pdu_length;
  size_t partial_pdu_start_offset;

  assert(partial_pdu != NULL);
  assert(deencap != NULL);

  /* Check if a context can exist for this Frag ID */
  if(header.first_frag_s.frag_id >= gse_deencap_get_qos_nbr(deencap))
  {
    status = GSE_STATUS_INVALID_QOS;
    goto free_partial_pdu;
  }

  /* check Protocol Type */
  if(ntohs(header.first_frag_s.protocol_type) < GSE_MIN_ETHER_TYPE &&
     deencap->read_header_ext == NULL)
  {
    status = GSE_STATUS_EXTENSION_NOT_SUPPORTED;
    goto free_partial_pdu;
  }

  /* Retrieve the context structure */
  ctx = &(deencap->deencap_ctx[header.first_frag_s.frag_id]);

  /* Compute the data field part of the CRC32 and store it */
  ctx->crc = gse_deencap_compute_crc(partial_pdu->start, partial_pdu->length, crc);

  /* Overwrite partial PDU if context is not empty */
  if(ctx->partial_pdu != NULL)
  {
    status = GSE_STATUS_DATA_OVERWRITTEN;
    gse_free_vfrag(&(ctx->partial_pdu));
  }
  ctx->label_type = header.lt;
  ctx->total_length = ntohs(header.first_frag_s.total_length);
  pdu_length = gse_deencap_compute_pdu_length(ctx->total_length, header.lt,
                                              ctx->tot_ext_length);

  /* Compute offset from start of buffer to partial PDU start */
  partial_pdu_start_offset = partial_pdu->start - partial_pdu->vbuf->start;
  /* Check if there is enough space in the virtual buffer for the complete PDU */
  if((partial_pdu->vbuf->length - partial_pdu_start_offset) < pdu_length)
  {
    /* Create a new virtual fragment for PDU because current virtual fragment is
     * too small */
    status = gse_create_vfrag_with_data(&(ctx->partial_pdu), pdu_length, 0,
                                        GSE_MAX_TRAILER_LENGTH,
                                        partial_pdu->start,
                                        partial_pdu->length);
    if(status != GSE_STATUS_OK)
    {
      goto free_partial_pdu;
    }

    /* Free the partial PDU because it has been saved in the context
     * The error are not treated because the data are correctly saved */
    gse_free_vfrag(&partial_pdu);
  }
  else
  {
    ctx->partial_pdu = partial_pdu;
  }
  ctx->protocol_type = ntohs(header.first_frag_s.protocol_type);
  memcpy(&(ctx->label), &(header.first_frag_s.label),
         gse_get_label_length(header.lt));

  /* Check if label is not '00:00:00:00:00:00' */
  if(header.lt == GSE_LT_6_BYTES &&
     memcmp(&(ctx->label), "\x0\x0\x0\x0\x0\x0", 6) == 0)
  {
    status = GSE_STATUS_INVALID_LABEL;
    goto free_vfrag;
  }
  ctx->bbframe_nbr = 0;

  return status;
free_vfrag:
  if(ctx != NULL)
  {
    gse_free_vfrag(&(ctx->partial_pdu));
  }
free_partial_pdu:
  if(partial_pdu != NULL)
  {
    gse_free_vfrag(&partial_pdu);
  }
  return status;
}

static gse_status_t gse_deencap_add_frag(gse_vfrag_t *partial_pdu,
                                         gse_deencap_t *deencap,
                                         gse_header_t header)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_deencap_ctx_t *ctx;

  assert(partial_pdu != NULL);
  assert(deencap != NULL);

  if(header.lt != GSE_LT_REUSE)
  {
    status = GSE_STATUS_INVALID_LT;
    goto free_partial_pdu;
  }

  /* Check if a context can exist for this Frag ID */
  if(header.subs_frag_s.frag_id >= gse_deencap_get_qos_nbr(deencap))
  {
    status = GSE_STATUS_INVALID_QOS;
    goto free_partial_pdu;
  }
  ctx = &(deencap->deencap_ctx[header.subs_frag_s.frag_id]);

  /* Check if context exists for this Frag ID */
  if(ctx->partial_pdu == NULL)
  {
    status = GSE_STATUS_CTX_NOT_INIT;
    goto free_partial_pdu;
  }

  /* Check if a timeout occured (ie. if the complete PDU had not been received
   * in 256 BBFrames */
  if(ctx->bbframe_nbr > 255)
  {
    status = GSE_STATUS_TIMEOUT;
    goto free_ctx;
  }

  /* Check if there is enough space in buffer for the fragment of PDU */
  if((ctx->partial_pdu->end + partial_pdu->length) > ctx->partial_pdu->vbuf->end)
  {
    status = GSE_STATUS_NO_SPACE_IN_BUFF;
    goto free_ctx;
  }
  memcpy(ctx->partial_pdu->end, partial_pdu->start, partial_pdu->length);
  status = gse_shift_vfrag(ctx->partial_pdu, 0, partial_pdu->length);
  if(status != GSE_STATUS_OK)
  {
    goto free_ctx;
  }

  /* Compute the data field part of the CRC32 and store it */
  ctx->crc = gse_deencap_compute_crc(partial_pdu->start, partial_pdu->length,
                                     ctx->crc);

  /* Free partial_pdu as it is stored in context
   * The error are not treated because the data are correctly saved */
  gse_free_vfrag(&partial_pdu);

  return status;
free_ctx:
  gse_free_vfrag(&(ctx->partial_pdu));
free_partial_pdu:
  gse_free_vfrag(&partial_pdu);
  return status;
}

static gse_status_t gse_deencap_add_last_frag(gse_vfrag_t *partial_pdu,
                                              gse_deencap_t *deencap,
                                              gse_header_t header)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_deencap_ctx_t *ctx;
  uint32_t rcv_crc;

  assert(partial_pdu != NULL);
  assert(deencap != NULL);

  if(header.lt != GSE_LT_REUSE)
  {
    status = GSE_STATUS_INVALID_LT;
    goto free_partial_pdu;
  }

  /* Check if a context can exist for this Frag ID */
  if(header.subs_frag_s.frag_id >= gse_deencap_get_qos_nbr(deencap))
  {
    status = GSE_STATUS_INVALID_QOS;
    goto free_partial_pdu;
  }

  ctx = &(deencap->deencap_ctx[header.subs_frag_s.frag_id]);
  /* Check if context exists for this Frag ID */
  if(ctx->partial_pdu == NULL)
  {
    status = GSE_STATUS_CTX_NOT_INIT;
    goto free_partial_pdu;
  }

  /* Move end pointer to the end of the data field */
  status = gse_shift_vfrag(partial_pdu, 0, GSE_MAX_TRAILER_LENGTH * -1);
  if(status != GSE_STATUS_OK)
  {
    goto free_partial_pdu;
  }

  /* Store the received CRC32 */
  memcpy(&rcv_crc, partial_pdu->end, GSE_MAX_TRAILER_LENGTH);

  /* Add the fragment to deencapsulation buffer */
  status = gse_deencap_add_frag(partial_pdu, deencap, header);
  if(status != GSE_STATUS_OK)
  {
    goto error;
  }

  /* read header extensions (when entire data is received because extensions
   * can be fragmented */
  ctx->tot_ext_length = 0;
  if(ctx->protocol_type < GSE_MIN_ETHER_TYPE)
  {
    int ret;
    uint16_t protocol_type;
    uint16_t extension_type = ctx->protocol_type;

    if(deencap->read_header_ext == NULL)
    {
      status = GSE_STATUS_EXTENSION_NOT_SUPPORTED;
      goto free_ctx;
    }

    ctx->tot_ext_length = partial_pdu->length;
    ret = deencap->read_header_ext(partial_pdu->start, &(ctx->tot_ext_length),
                                   &protocol_type, extension_type,
                                   deencap->opaque);
    if(ret < 0)
    {
      status = GSE_STATUS_EXTENSION_CB_FAILED;
      goto free_ctx;
    }
    ctx->protocol_type = protocol_type;

    /* check extensions validity */
    status = gse_check_header_extension_validity(partial_pdu->start,
                                                 &ctx->tot_ext_length,
                                                 extension_type,
                                                 &protocol_type);
    if(status != GSE_STATUS_OK)
    {
      goto free_ctx;
    }
    if(protocol_type != ctx->protocol_type)
    {
      status = GSE_STATUS_INVALID_EXTENSIONS;
      goto free_ctx;
    }

    /* move PDU start after extensions */
    status = gse_shift_vfrag(partial_pdu, ctx->tot_ext_length, 0);
    if(status != GSE_STATUS_OK)
    {
      goto free_ctx;
    }
  }

  /* Chek PDU length according to Total Length */
  if(gse_deencap_compute_pdu_length(ctx->total_length, ctx->label_type,
                                    ctx->tot_ext_length)
     != ctx->partial_pdu->length)
  {
    status = GSE_STATUS_INVALID_DATA_LENGTH;
    goto free_ctx;
  }

  if(ntohl(rcv_crc) != ctx->crc)
  {
    status = GSE_STATUS_INVALID_CRC;
    goto free_ctx;
  }

  return status;
free_ctx:
  gse_free_vfrag(&(ctx->partial_pdu));
  return status;
free_partial_pdu:
  gse_free_vfrag(&partial_pdu);
error:
  return status;
}

static size_t gse_deencap_compute_pdu_length(uint16_t total_length,
                                             gse_label_type_t label_type,
                                             size_t tot_ext_length)
{
  uint16_t pdu_length;
  pdu_length = total_length - gse_get_label_length(label_type)
               - GSE_PROTOCOL_TYPE_LENGTH - tot_ext_length;
  return pdu_length;
}

static uint32_t gse_deencap_compute_crc(unsigned char *data,
                                        size_t length,
                                        uint32_t crc_init)
{
  uint32_t crc;

  crc = compute_crc(data, length, crc_init);

  return crc;
}
