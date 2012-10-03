/*
 *
 * This piece of software is an implementation of the Generic Stream
 * Encapsulation (GSE) standard defined by ETSI for Linux (or other
 * Unix-compatible OS). The library may be used to add GSE
 * encapsulation/de-encapsulation capabilities to an application.
 *
 *
 * Copyright © 2011 TAS
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
 *   @file          encap.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: ENCAPSULATION
 *
 *   @brief         GSE encapsulation functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "encap.h"

#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>

#include "constants.h"
#include "fifo.h"
#include "crc.h"
#include "header_fields.h"


/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** Encapsulation structure
 *
 *  If library is used with zero copy, the header and trailer offsets are not
 *  used.\n
 *  With zero copy, the header offsets depend on the offset specified on
 *  fragment creation and on the fragment type.\n
 *  Trailer offset usage on GSE packets is not possible with zero-copy else
 *  data could be overwritten.
 */
struct gse_encap_s
{
  fifo_t *fifo;          /**< Table of FIFOs
                              The size of the table is given by qos_nbr */
  size_t head_offset;    /**< Offset applied on the beginning of each copied
                              GSE packet (in bytes)
                              (default: GSE_MAX_REFRAG_HEAD_OFFSET) */
  size_t trail_offset;   /**< Offset applied on the end of each copied
                              GSE packet (in bytes)
                              (default: 0) */
  uint8_t qos_nbr;       /**< Number of QoS values */
  /**> Callback to build header extensions */
  gse_encap_build_header_ext_cb_t build_header_ext;
  void *opaque;          /**< User specific data for extension callback */
};



/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 ****************************************************************************/

/**
 *  @brief   Create the GSE header and CRC
 *
 *  CRC is only created in the case of a first fragment, it is written at the
 *  end of the PDU.
 *
 *  @param   pdu_type       Type of payload (GSE_PDU_COMPLETE, GSE_PDU_SUBS_FRAG,
 *                                           GSE_PDU_FIRST_FRAG, GSE_PDU_LAST_FRAG)
 *  @param   encap_ctx      Encapsulation context of the PDU
 *  @param   length         Length of the GSE packet (in bytes)
 *
 *  @return
 *                       - success/informative code among:
 *                         - \ref GSE_STATUS_OK
 *                       - warning/error code among:
 *                         - \ref GSE_STATUS_INVALID_GSE_LENGTH
 *                         - \ref GSE_STATUS_INTERNAL_ERROR
 */
static gse_status_t gse_encap_create_header_and_crc(gse_payload_type_t payload_type,
                                                    gse_encap_ctx_t *const encap_ctx,
                                                    size_t length);

/**
 *  @brief   Compute the GSE packet Total Length header field
 *
 *  @param   encap_ctx     Encapsulation context
 *
 *  @return                The total Length (in bytes)
 */
static uint16_t gse_encap_compute_total_length(gse_encap_ctx_t *const encap_ctx);

/**
 *  @brief   Compute the GSE Length header field from the total length of the
 *           GSE packet
 *
 *  This function takes the complete GSE packet length and deduces the mandatory
 *  fields length.
 *
 *  @param   packet_length  The total length of GSE packet (in bytes)
 *  @param   header         IN/OUT: the updated header of GSE packet
 *
 *  @return
 *                          - success/informative code among:
 *                            - \ref GSE_STATUS_OK
 *                          - warning/error code among:
 *                            - \ref GSE_STATUS_INVALID_GSE_LENGTH
 */
static gse_status_t gse_encap_set_gse_length(size_t packet_length,
                                             gse_header_t *header);

/**
 *  @brief   Compute the GSE packet length
 *
 *  The length are expressed in bytes.
 *
 *  @param   desired_length         The length desired by the user for the next
 *                                  GSE packet
 *  @param   remaining_data_length  The data length remaining in the PDU
 *  @pram    header_length          The length of the header
 *
 *  @return                         The GSE packet length
 */
static size_t gse_encap_compute_packet_length(size_t desired_length,
                                              size_t remaining_data_length,
                                              size_t header_length);

/**
 *  @brief   Compute the CRC32
 *
 *  @pram    vfrag   Virtual fragment
 *
 *  @return          The CRC32
 */
static uint32_t gse_encap_compute_crc(gse_vfrag_t *vfrag);

/**
 *  @brief   Get a GSE packet from the encapsulation context structure
 *
 *  @param   copy             Activate copy or not
 *  @param   packet           OUT: The GSE packet on success,
 *                                 NULL on error
 *  @param   encap            The encapsulation context structure
 *  @param   desired_length   The desired length for the packet (in bytes)
 *  @param   qos              The QoS of the packet
 *
 *  @return
 *                            - success/informative code among:
 *                              - \ref GSE_STATUS_OK
 *                            - warning/error code among:
 *                              - \ref GSE_STATUS_NULL_PTR
 *                              - \ref GSE_STATUS_INVALID_QOS
 *                              - \ref GSE_STATUS_FIFO_EMPTY
 *                              - \ref GSE_STATUS_PTHREAD_MUTEX
 *                              - \ref GSE_STATUS_LENGTH_TOO_HIGH
 *                              - \ref GSE_STATUS_LENGTH_TOO_SMALL
 *                              - \ref GSE_STATUS_PTHREAD_MUTEX
 *                              - \ref GSE_STATUS_INTERNAL_ERROR;
 *                              - \ref GSE_STATUS_PTR_OUTSIDE_BUFF
 *                              - \ref GSE_STATUS_FRAG_PTRS
 *                              - \ref GSE_STATUS_INVALID_GSE_LENGTH
 *                              - \ref GSE_STATUS_BUFF_LENGTH_NULL
 *                              - \ref GSE_STATUS_MULTIPLE_VBUF_ACCESS
 *                              - \ref GSE_STATUS_DATA_TOO_LONG
 *                              - \ref GSE_STATUS_MALLOC_FAILED
 *                              - \ref GSE_STATUS_EMPTY_FRAG
 *                              - \ref GSE_STATUS_FRAG_NBR
 *                              - \ref GSE_STATUS_EXTENSION_CB_FAILED
 */
static gse_status_t gse_encap_get_packet_common(int copy, gse_vfrag_t **packet,
                                                gse_encap_t *encap,
                                                size_t desired_length,
                                                uint8_t qos);


/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

/* Encapsulation initialization and release */

gse_status_t gse_encap_init(uint8_t qos_nbr, size_t fifo_size,
                            gse_encap_t **encap)
{
  gse_status_t status = GSE_STATUS_OK;

  unsigned int i;

  if(encap == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  if(qos_nbr == 0)
  {
    status = GSE_STATUS_QOS_NBR_NULL;
    goto error;
  }
  if(fifo_size == 0)
  {
    status = GSE_STATUS_FIFO_SIZE_NULL;
    goto error;
  }
  *encap = calloc(1, sizeof(gse_encap_t));
  if(*encap == NULL)
  {
    status = GSE_STATUS_MALLOC_FAILED;
    goto error;
  }
  (*encap)->fifo = malloc(sizeof(fifo_t) * qos_nbr);
  (*encap)->qos_nbr = qos_nbr;
  if((*encap)->fifo == NULL)
  {
    status = GSE_STATUS_MALLOC_FAILED;
    goto free_encap;
  }

  /* Initialize each FIFO in encapsulation context */
  for(i = 0 ; i < qos_nbr ; i++)
  {
    status = gse_init_fifo(&(*encap)->fifo[i], fifo_size);
    if(status != GSE_STATUS_OK)
    {
      goto free_fifo;
    }
  }

  /* Initialize offsets
   * The head offset length difference between first fragment header and
   * complete one, it allows to allocate enough space for a complete PDU
   * refragmentation */
  status = gse_encap_set_offsets(*encap, GSE_MAX_REFRAG_HEAD_OFFSET, 0);
  if(status != GSE_STATUS_OK)
  {
    goto free_fifo;
  }

  return status;
free_fifo:
  free((*encap)->fifo);
free_encap:
  free(*encap);
error:
  *encap = NULL;
  return status;
}

gse_status_t gse_encap_release(gse_encap_t *encap)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_status_t stat_mem = GSE_STATUS_OK;

  unsigned int i;

  if(encap == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  /* Release FIFO in each context */
  for(i = 0 ; i < encap->qos_nbr ; i++)
  {
    status = gse_release_fifo(&encap->fifo[i]);
    if(status != GSE_STATUS_OK)
    {
      stat_mem = status;
    }
  }
  free(encap->fifo);
  free(encap);

  return stat_mem;
error:
  return status;
}

gse_status_t gse_encap_set_offsets(gse_encap_t *encap,
                                   size_t head_offset, size_t trail_offset)
{
  if(encap == NULL)
  {
    return GSE_STATUS_NULL_PTR;
  }
  encap->head_offset = head_offset;
  encap->trail_offset = trail_offset;
  return GSE_STATUS_OK;
}

/* Encapsulation functions */

gse_status_t gse_encap_receive_pdu(gse_vfrag_t *pdu, gse_encap_t *encap,
                                   uint8_t label[6], uint8_t label_type,
                                   uint16_t protocol, uint8_t qos)
{
  gse_status_t status = GSE_STATUS_OK;

  gse_encap_ctx_t *encap_ctx;
  gse_encap_ctx_t ctx_elts;
  int label_length = -1;

  /* Check parameters validity */
  if(pdu == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }
  if(encap == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto free_pdu;
  }
  label_length = gse_get_label_length(label_type);
  if(label_length < 0)
  {
    status = GSE_STATUS_INVALID_LT;
    goto free_pdu;
  }
  /* Total length field shall be < 65536 */
  if(pdu->length > (GSE_MAX_PDU_LENGTH - GSE_PROTOCOL_TYPE_LENGTH -
                    (unsigned int)label_length))
  {
    status = GSE_STATUS_PDU_LENGTH;
    goto free_pdu;
  }
  /* Check if we got a good protocol */
  if(protocol < GSE_MIN_ETHER_TYPE)
  {
    status = GSE_STATUS_WRONG_PROTOCOL;
    goto free_pdu;
  }
  /* Check if QoS value is supported */
  if(qos >= encap->qos_nbr)
  {
    status = GSE_STATUS_INVALID_QOS;
    goto free_pdu;
  }

  /* Fill context used to push the FIFO */
  ctx_elts.vfrag = pdu;
  ctx_elts.qos = qos;
  ctx_elts.protocol_type = htons(protocol);
  ctx_elts.label_type = label_type;
  memcpy(&(ctx_elts.label), label, label_length);
  ctx_elts.frag_nbr = 0;
  ctx_elts.total_length = gse_encap_compute_total_length(&ctx_elts);

  /* Push FIFO */
  encap_ctx = NULL;
  status = gse_push_fifo(&encap->fifo[qos], &encap_ctx, ctx_elts);
  if(status != GSE_STATUS_OK)
  {
    goto free_pdu;
  }

error:
  return status;
free_pdu:
  gse_free_vfrag(&pdu);
  return status;
}

gse_status_t gse_encap_get_packet(gse_vfrag_t **packet, gse_encap_t *encap,
                                  size_t length, uint8_t qos)
{
  return gse_encap_get_packet_common(0, packet, encap, length, qos);
}

gse_status_t gse_encap_get_packet_copy(gse_vfrag_t **packet, gse_encap_t *encap,
                                       size_t length, uint8_t qos)
{
  return gse_encap_get_packet_common(1, packet, encap, length, qos);
}

gse_status_t gse_encap_set_extension_callback(gse_encap_t *encap,
                                              gse_encap_build_header_ext_cb_t callback,
                                              void *opaque)
{
  if(encap == NULL)
  {
    return GSE_STATUS_NULL_PTR;
  }

  encap->build_header_ext = callback;
  encap->opaque = opaque;

  return GSE_STATUS_OK;
}


/****************************************************************************
 *
 *   PRIVATE FUNCTIONS
 *
 ****************************************************************************/

static gse_status_t gse_encap_create_header_and_crc(gse_payload_type_t payload_type,
                                                    gse_encap_ctx_t *const encap_ctx,
                                                    size_t length)
{
  gse_status_t status = GSE_STATUS_OK;

  uint32_t crc;
  gse_header_t *gse_header;

  assert(encap_ctx != NULL);

  gse_header = (gse_header_t*)encap_ctx->vfrag->start;
  status = gse_encap_set_gse_length(length, gse_header);
  if(status != GSE_STATUS_OK)
  {
    goto error;
  }

  switch(payload_type)
  {
    /* GSE packet carrying a complete PDU */
    /* Header fields are S | E | LT | GSE Length | Protocol Type | Label | Ext */
    case GSE_PDU_COMPLETE:
      gse_header->s = 0x1;
      gse_header->e = 0x1;
      gse_header->lt = encap_ctx->label_type;
      gse_header->complete_s.protocol_type = encap_ctx->protocol_type;
      memcpy(&(gse_header->complete_s.label), &(encap_ctx->label),
             gse_get_label_length(encap_ctx->label_type));
      break;

    /* GSE packet carrying a first fragment of PDU */
    /* Header fields are
     * S | E | LT | GSE Length | FragID | Total Length | Protocol Type | Label | Ext */
    case GSE_PDU_FIRST_FRAG:
      gse_header->s = 0x1;
      gse_header->e = 0x0;
      gse_header->lt = encap_ctx->label_type;
      gse_header->first_frag_s.frag_id = encap_ctx->qos;
      gse_header->first_frag_s.total_length = htons(encap_ctx->total_length);
      gse_header->first_frag_s.protocol_type = encap_ctx->protocol_type;
      memcpy(&(gse_header->first_frag_s.label), &(encap_ctx->label),
             gse_get_label_length(encap_ctx->label_type));

      /* CRC is computed with first fragment because the complete PDU and
       * some of its header elements are necessary */
      crc = gse_encap_compute_crc(encap_ctx->vfrag);
      /* Add CRC at the end of the data field */
      memcpy(encap_ctx->vfrag->end - GSE_MAX_TRAILER_LENGTH, &crc,
             GSE_MAX_TRAILER_LENGTH);
      break;

    /* GSE packet carrying a subsequent fragment of PDU
     * which is not the last one */
    /* Header fields are S | E | LT | GSE Length | FragID */
    case GSE_PDU_SUBS_FRAG:
      gse_header->s = 0x0;
      gse_header->e = 0x0;
      gse_header->lt = GSE_LT_REUSE;
      gse_header->subs_frag_s.frag_id = encap_ctx->qos;
      break;

    /* GSE packet carrying a last fragment of PDU */
    /* Header fields are S | E | LT | GSE Length | FragID */
    case GSE_PDU_LAST_FRAG:
      gse_header->s = 0x0;
      gse_header->e = 0x1;
      gse_header->lt = GSE_LT_REUSE;
      gse_header->subs_frag_s.frag_id = encap_ctx->qos;
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

static uint16_t gse_encap_compute_total_length(gse_encap_ctx_t *const encap_ctx)
{
  uint16_t total_length;
  assert(encap_ctx != NULL);
  total_length = gse_get_label_length(encap_ctx->label_type)
                 + GSE_PROTOCOL_TYPE_LENGTH
                 + encap_ctx->vfrag->length;
  return total_length;
}

static gse_status_t gse_encap_set_gse_length(size_t packet_length,
                                             gse_header_t *header)
{
  gse_status_t status = GSE_STATUS_OK;

  uint16_t gse_length;

  assert(header != NULL);
  /* GSE Length take into account all the fields following it */
  gse_length = packet_length - GSE_MANDATORY_FIELDS_LENGTH;
  /* GSE Length field contain 12 bits */
  if(gse_length > 0xFFF)
  {
    status = GSE_STATUS_LENGTH_TOO_HIGH;
    goto error;
  }

  header->gse_length_hi = (gse_length >> 8) & 0x0F;
  header->gse_length_lo = gse_length & 0xFF;

error:
  return status;
}

static size_t gse_encap_compute_packet_length(size_t desired_length,
                                              size_t remaining_data_length,
                                              size_t header_length)
{
  size_t packet_length;

  packet_length = MIN(desired_length, GSE_MAX_PACKET_LENGTH);
  packet_length = MIN(desired_length, remaining_data_length + header_length);
  /* Avoid fragmentation of CRC field between 2 GSE fragments:
   * if the computed packet length is too short by less than 4 bytes to contain
   * the whole remaining part of the PDU and the CRC, then reduce the packet
   * length so that the 4-bytes CRC is left for the next fragment */
  if((packet_length < remaining_data_length + header_length) &&
     ((remaining_data_length + header_length - packet_length)
       < GSE_MAX_TRAILER_LENGTH))
  {
    packet_length = remaining_data_length - GSE_MAX_TRAILER_LENGTH +
                    header_length;
  }

  return packet_length;
}

static uint32_t gse_encap_compute_crc(gse_vfrag_t *vfrag)
{
  uint32_t crc;
  unsigned char *data;
  size_t length;

  /* CRC is computed with complete PDU, Total length, Protocol Type and Label */
  data = vfrag->start + GSE_MANDATORY_FIELDS_LENGTH + GSE_FRAG_ID_LENGTH;
  length = vfrag->length -
          (GSE_MANDATORY_FIELDS_LENGTH + GSE_FRAG_ID_LENGTH + GSE_MAX_TRAILER_LENGTH);
  crc = compute_crc(data, length, GSE_CRC_INIT);

  return htonl(crc);
}

static gse_status_t gse_encap_get_packet_common(int copy, gse_vfrag_t **packet,
                                                gse_encap_t *encap,
                                                size_t desired_length,
                                                uint8_t qos)
{
  gse_status_t status = GSE_STATUS_OK;

  if(packet == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  size_t remaining_data_length;
  size_t header_length;
  int elt_nbr;
  gse_encap_ctx_t* encap_ctx;
  gse_payload_type_t payload_type;
  unsigned char *extensions = NULL;
  size_t tot_ext_length;

  /* Check parameters */
  if(encap == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto packet_null;
  }
  if(qos >= encap->qos_nbr)
  {
    status = GSE_STATUS_INVALID_QOS;
    goto packet_null;
  }

  /* Check if there is elements for the specified QoS */
  elt_nbr = gse_get_fifo_elt_nbr(&encap->fifo[qos]);
  if(elt_nbr == 0)
  {
    status = GSE_STATUS_FIFO_EMPTY;
    goto packet_null;
  }
  else if(elt_nbr < 0)
  {
    status = GSE_STATUS_PTHREAD_MUTEX;
    goto packet_null;
  }

  /* If the desired length = 0, then use the maximum possible value */
  if(desired_length == 0)
  {
    desired_length = GSE_MAX_PACKET_LENGTH;
  }
  if(desired_length > GSE_MAX_PACKET_LENGTH)
  {
    status = GSE_STATUS_LENGTH_TOO_HIGH;
    goto packet_null;
  }
  if(desired_length < GSE_MIN_PACKET_LENGTH)
  {
    status = GSE_STATUS_LENGTH_TOO_SMALL;
    goto packet_null;
  }
  status = gse_get_fifo_elt(&encap->fifo[qos], &encap_ctx);
  if(status != GSE_STATUS_OK)
  {
    goto packet_null;
  }

  remaining_data_length = encap_ctx->vfrag->length;

  /* There should always been data because free fragment are removed from the
   * FIFO at the end of this function */
  assert(remaining_data_length > 0);
  if(remaining_data_length <= 0)
  {
    status = GSE_STATUS_INTERNAL_ERROR;
    goto packet_null;
  }

  /* There is a complete PDU in the context */
  if(encap_ctx->frag_nbr == 0)
  {
    tot_ext_length = 0;
    /* Check if we need extensions */
    if(encap->build_header_ext != NULL)
    {
      int ret;
      uint16_t ext_type;
      uint16_t proto;

      extensions = calloc(GSE_MAX_EXT_LENGTH, sizeof(unsigned char));
      if(extensions == NULL)
      {
        status = GSE_STATUS_MALLOC_FAILED;
        goto packet_null;
      }
      tot_ext_length = GSE_MAX_EXT_LENGTH;
      ret = encap->build_header_ext(extensions, &tot_ext_length, &ext_type,
                                    ntohs(encap_ctx->protocol_type),
                                    encap->opaque);
      if(ret < 0)
      {
        status = GSE_STATUS_EXTENSION_CB_FAILED;
        goto packet_null;
      }

      status = gse_check_header_extension_validity(extensions,
                                                   &tot_ext_length,
                                                   ext_type,
                                                   &proto);
      if(status != GSE_STATUS_OK)
      {
        goto packet_null;
      }
      if(proto != ntohs(encap_ctx->protocol_type))
      {
        status = GSE_STATUS_INVALID_EXTENSIONS;
        goto packet_null;
      }

      /* update the context protocol type with the extension type */
      encap_ctx->protocol_type = htons(ext_type);
      encap_ctx->total_length = gse_encap_compute_total_length(encap_ctx);
    }

    /* Total length field shall be < 65536 */
    if(encap_ctx->total_length + tot_ext_length > GSE_MAX_PDU_LENGTH)
    {
      status = GSE_STATUS_PDU_LENGTH;
      goto packet_null;
    }
    /* update total_length value */
    encap_ctx->total_length += tot_ext_length;
    /* update remaining data length (consider extensions as data) */
    remaining_data_length += tot_ext_length;
    /* move the start pointer in the buffer and add extensions */

    status = gse_shift_vfrag(encap_ctx->vfrag, tot_ext_length * -1, 0);
    if(status != GSE_STATUS_OK)
    {
      goto packet_null;
    }
    memcpy(encap_ctx->vfrag->start, extensions, tot_ext_length);

    /* Can the PDU be completely encapsulated ? */
    header_length = gse_compute_header_length(GSE_PDU_COMPLETE, encap_ctx->label_type);
    if(header_length == 0)
    {
      status = GSE_STATUS_INTERNAL_ERROR;
      goto packet_null;
    }
    if(desired_length >= (remaining_data_length + header_length))
    {
      payload_type = GSE_PDU_COMPLETE;
    }
    else
    {
      header_length = gse_compute_header_length(GSE_PDU_FIRST_FRAG,
                                                encap_ctx->label_type);
      if(header_length == 0)
      {
        status = GSE_STATUS_INTERNAL_ERROR;
        goto packet_null;
      }
      payload_type = GSE_PDU_FIRST_FRAG;
      /* Check if wanted length allows 1 bit of data */
      if((header_length + 1) > desired_length)
      {
        status = GSE_STATUS_LENGTH_TOO_SMALL;
        goto packet_null;
      }
    }
  }
  /* There is a PDU fragment in the context */
  else
  {
    header_length = gse_compute_header_length(GSE_PDU_SUBS_FRAG, encap_ctx->label_type);
    if(header_length == 0)
    {
      status = GSE_STATUS_INTERNAL_ERROR;
      goto packet_null;
    }
    /* Is this the last fragment ? */
    if(desired_length >= (remaining_data_length + header_length))
    {
      payload_type = GSE_PDU_LAST_FRAG;
      /* Check if complete CRC can be sent */
      if((header_length + GSE_MAX_TRAILER_LENGTH) > desired_length)
      {
        status = GSE_STATUS_LENGTH_TOO_SMALL;
        goto packet_null;
      }
    }
    else
    {
      payload_type = GSE_PDU_SUBS_FRAG;
      /* Check if wanted length allows 1 bit of data */
      if((header_length + 1) > desired_length)
      {
        status = GSE_STATUS_LENGTH_TOO_SMALL;
        goto packet_null;
      }
    }
  }

  /* Compute the amount of PDU bytes that is encapsulated in the GSE packet we
   * are building */
  desired_length = gse_encap_compute_packet_length(desired_length,
                                                   remaining_data_length,
                                                   header_length);

  /* Make room for the GSE header at the beginning of the PDU data and - if the
   * GSE packet is a first fragment - for the CRC at the end of the PDU data */
  if(payload_type == GSE_PDU_FIRST_FRAG)
  {
    /* TODO reallocate if not enough space due to extensions instead of 
     *      an error ? */
    status = gse_shift_vfrag(encap_ctx->vfrag, header_length * -1,
                             GSE_MAX_TRAILER_LENGTH);
  }
  else
  {
    status = gse_shift_vfrag(encap_ctx->vfrag, header_length * -1, 0);
  }
  if(status != GSE_STATUS_OK)
  {
    goto packet_null;
  }

  status = gse_encap_create_header_and_crc(payload_type, encap_ctx, desired_length);
  if(status != GSE_STATUS_OK)
  {
    goto packet_null;
  }

  /* Code depending on copy parameter */
  if(copy)
  {
    /* Create a new fragment */
    status = gse_create_vfrag_with_data(packet, desired_length,
                                        encap->head_offset,
                                        encap->trail_offset,
                                        encap_ctx->vfrag->start,
                                        desired_length);
    if(status != GSE_STATUS_OK)
    {
      goto packet_null;
    }
  }
  else
  {
    /* Duplicate the fragment */
    status = gse_duplicate_vfrag(packet, encap_ctx->vfrag, desired_length);
    if(status != GSE_STATUS_OK)
    {
      goto packet_null;
    }
  }

  encap_ctx->frag_nbr++;
  /* Remove copied or duplicated data from the initial fragment */
  status = gse_shift_vfrag(encap_ctx->vfrag, (*packet)->length, 0);
  if(status != GSE_STATUS_OK)
  {
    goto free_packet;
  }

  /* Go to the next FIFO element if the initial fragment is empty */
  if(encap_ctx->vfrag->length <= 0)
  {
    status = gse_free_vfrag(&(encap_ctx->vfrag));
    if(status != GSE_STATUS_OK)
    {
      goto free_packet;
    }
    status = gse_pop_fifo(&encap->fifo[qos]);
    if(status != GSE_STATUS_OK)
    {
      goto free_packet;
    }
  }

  return status;
free_packet:
  gse_free_vfrag(packet);
packet_null:
  if(extensions != NULL)
  {
    free(extensions);
  }
error:
  *packet = NULL;
  return status;
}
