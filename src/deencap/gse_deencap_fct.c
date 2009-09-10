/****************************************************************************/
/**
 *   @file          gse_deencap_fct.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: DEENCAPSULATION
 *
 *   @brief         GSE deencapsulation functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "gse_deencap_fct.h"

/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 ****************************************************************************/

/**
 *  @brief   Create Deencapsulation context
 *
 *  @param   data        Received data
 *  @param   deencap     The deencapsulation structure
 *  @param   header      Header of the GSE packet carrying data
 *  @return  status code
 */
static status_t gse_deencap_create_ctx(vfrag_t *data, gse_deencap_t *deencap,
                                gse_header_t header);

/**
 *  @brief   Fill Deencapsulation context with fragments
 *
 *  @param   data        Received data
 *  @param   deencap     The deencapsulation structure
 *  @param   header      Header of the GSE packet carrying data
 *  @return  status code
 */
static status_t gse_deencap_add_frag(vfrag_t *data, gse_deencap_t *deencap,
                              gse_header_t header);

/**
 *  @brief   Complete Deencapsulation context with a last fragment
 *
 *  @param   data        Received data
 *  @param   deencap     The deencapsulation structure
 *  @param   header      Header of the GSE packet carrying data
 *  @return  status code
 */
static status_t gse_deencap_add_last_frag(vfrag_t *data, gse_deencap_t *deencap,
                                   gse_header_t header);

/**
 *  @brief   Compute PDU length from total length field
 *
 *  @param   total_length   The total length field of the GSE packet
 *  @param   label_type     Type of label
 *  @return  PDU Length
 */
static size_t gse_deencap_compute_pdu_length(uint16_t total_length,
                                               uint8_t label_type);

/**
 *  @brief   Compute CRC32
 *
 *  @pram    vfrag          Virtual fragment
 *  @param   label_type     Type of label
 *  @return  CRC32
 */
static uint32_t gse_deencap_compute_crc(vfrag_t *vfrag, uint8_t label_type);

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

status_t gse_deencap_packet (vfrag_t *packet, gse_deencap_t *deencap,
                           uint8_t *label_type, uint8_t label[6],
                           uint16_t *protocol, vfrag_t **pdu)
{
  status_t status = STATUS_OK;

  gse_header_t header;
  payload_type_t payload_type;
  size_t header_length;
  uint16_t gse_length;
  uint16_t data_length;

  *pdu = NULL;

  memcpy(&header, packet->start, sizeof(gse_header_t));

  if((header.s == 0x0) && (header.e == 0x0) && (header.lt == 0x0))
  {
    status = PADDING_DETECTED;
    goto free_packet;
  }

  // Check packet validity
  gse_length = ((uint16_t)header.gse_length_hi << 8) | header.gse_length_lo;
  if(gse_length != packet->length - MANDATORY_FIELDS_LENGTH)
  {
    status = ERR_INVALID_GSE_LENGTH;
    goto free_packet;
  }
  if(gse_get_label_length(header.lt) < 0)
  {
    status = ERR_INVALID_LT;
    goto free_packet;
  }
/**@todo label (il faudrait une liste de label) */

  if(header.s == 0x1)
  {
    if(header.e == 0x1)
    {
      payload_type = COMPLETE;
    }
    else
    {
      payload_type = FIRST_FRAG;
    }
  }
  else
  {
    if(header.e == 0x1)
    {
      payload_type = LAST_FRAG;
    }
    else
    {
      payload_type = SUBS_FRAG;
    }
  }

  header_length = gse_compute_header_length(payload_type, header.lt);

  data_length = packet->length - header_length;

  gse_shift_vfrag(packet, header_length, 0);

  switch(payload_type)
  {
    case COMPLETE:
      // Discard packet if it contains header extensions
      if(ntohs(header.opt.complete.protocol_type) < MIN_ETHER_TYPE)
      {
        status = EXTENSION_NOT_SUPPORTED;
        goto free_packet;
      }
      *label_type = header.lt;
      memcpy(label, header.opt.complete.label.six_bytes_label,
             gse_get_label_length(header.lt));
      *protocol = ntohs(header.opt.complete.protocol_type);
      *pdu = packet;
      status = PDU;
      break;
    case FIRST_FRAG:
      status = gse_deencap_create_ctx(packet, deencap, header);
      if(status != STATUS_OK)
      {
        goto error;
      }
      break;
    case SUBS_FRAG:
      status = gse_deencap_add_frag(packet, deencap, header);
      if(status != STATUS_OK)
      {
        goto error;
      }
      break;
    case LAST_FRAG:
      status = gse_deencap_add_last_frag(packet, deencap, header);
      if(status != STATUS_OK)
      {
        goto error;
      }
      // Create a new fragment in order to free context
      gse_deencap_ctx_t *ctx;
      ctx = &(deencap->deencap_ctx[header.opt.first.frag_id]);
      *label_type = ctx->label_type;
      memcpy(label, &(ctx->label), gse_get_label_length(ctx->label_type));
      *protocol = ctx->protocol_type;

      status = gse_create_vfrag_with_data(pdu, ctx->vfrag->length,
                                          ctx->vfrag->start, ctx->vfrag->length);
      gse_free_vfrag(ctx->vfrag);
      ctx->vfrag = NULL;
      if(status != STATUS_OK)
      {
        goto error;
      }
      status = PDU;
      break;
    default:
      assert(0);
  }

  return status;
free_packet:
  gse_free_vfrag(packet);
error:
  return status;
}

void gse_deencap_new_bbframe (gse_deencap_t *deencap)
{
  unsigned int i;

  for(i = 0 ; i < gse_deencap_get_qos_nbr(deencap) ; i++)
  {
    deencap->deencap_ctx[i].bbframe_nbr++;
  }
}

/****************************************************************************
 *
 *   PRIVATE FUNCTIONS
 *
 ****************************************************************************/

status_t gse_deencap_create_ctx(vfrag_t *data, gse_deencap_t *deencap,
                                gse_header_t header)
{
  status_t status = STATUS_OK;
  gse_deencap_ctx_t *ctx;
  uint16_t pdu_length;
  size_t offset;

  if(header.opt.first.frag_id >= gse_deencap_get_qos_nbr(deencap))
  {
    status = ERR_INVALID_QOS;
    goto free_data;
  }
  // Discard packet if it contains header extensions
  if(ntohs(header.opt.first.protocol_type) < MIN_ETHER_TYPE)
  {
    status = EXTENSION_NOT_SUPPORTED;
    goto free_data;
  }
  ctx = &(deencap->deencap_ctx[header.opt.first.frag_id]);
  if(ctx->vfrag != NULL)
  {
    gse_free_vfrag(ctx->vfrag);
    ctx->vfrag = NULL;
  }
  ctx->label_type = header.lt;
  ctx->total_length = ntohs(header.opt.first.total_length);
  pdu_length = gse_deencap_compute_pdu_length(ctx->total_length, header.lt);
  if((data->vbuf->length - MAX_HEADER_LENGTH) < pdu_length)
  {
    status = gse_create_vfrag_with_data(&(ctx->vfrag), pdu_length,
                                        data->start, data->length);
    if(status != STATUS_OK)
    {
      goto free_data;
    }
    // Copy useful fields for CRC computation before data
    offset = TOTAL_LENGTH_LENGTH + PROTOCOL_TYPE_LENGTH + 
             gse_get_label_length(header.lt);
    memcpy(ctx->vfrag->start - offset, data->start - offset, offset);
    gse_free_vfrag(data);
  }
  else
  {
    ctx->vfrag = data;
  }
  ctx->protocol_type = ntohs(header.opt.first.protocol_type);
  memcpy(&(ctx->label), &(header.opt.first.label),
         gse_get_label_length(header.lt));
  ctx->bbframe_nbr = 0;
  
  return status;
free_data:
  gse_free_vfrag(data);
  return status;
}

status_t gse_deencap_add_frag(vfrag_t *data, gse_deencap_t *deencap,
                              gse_header_t header)
{
  status_t status = STATUS_OK;
  gse_deencap_ctx_t *ctx;

  if(header.lt != 0x3)
  {
    status = ERR_INVALID_LT;
    goto free_data;
  }

  if(header.opt.first.frag_id >= gse_deencap_get_qos_nbr(deencap))
  {
    status = ERR_INVALID_QOS;
    goto free_data;
  }
  ctx = &(deencap->deencap_ctx[header.opt.first.frag_id]);
  if(ctx->vfrag == NULL)
  {
    status = ERR_UNINITIALIZED_CTX;
    goto free_data;
  }
  if(ctx->bbframe_nbr > 255)
  {
    status = TIMEOUT;
    goto free_ctx;
  }
  memcpy(ctx->vfrag->end, data->start, data->length);
  gse_shift_vfrag(ctx->vfrag, 0, data->length);

  // don't free data if this is the last fragment because data contain CRC
  if(header.e != 0x1)
  {
    gse_free_vfrag(data);
  }

  return status;
free_ctx:
  gse_free_vfrag(ctx->vfrag);
  ctx->vfrag = NULL;
free_data:
  gse_free_vfrag(data);
  return status;
}

status_t gse_deencap_add_last_frag(vfrag_t *data, gse_deencap_t *deencap,
                                   gse_header_t header)
{
  status_t status = STATUS_OK;
  gse_deencap_ctx_t *ctx;
  uint32_t rcv_crc;
  uint32_t calc_crc;

  gse_shift_vfrag(data, 0, CRC_LENGTH * -1);

  status = gse_deencap_add_frag(data, deencap, header);
  if(status != STATUS_OK)
  {
    goto error;
  }
  ctx = &(deencap->deencap_ctx[header.opt.first.frag_id]);
  if(gse_deencap_compute_pdu_length(ctx->total_length, ctx->label_type)
     != ctx->vfrag->length)
  {
    status = ERR_INVALID_DATA_LENGTH;
    goto error;
  }

  memcpy(&rcv_crc, data->end, CRC_LENGTH);
  gse_free_vfrag(data);
  calc_crc = gse_deencap_compute_crc(ctx->vfrag, ctx->label_type);
  if(rcv_crc != calc_crc)
  {
    status = ERR_INVALID_CRC;
    goto error;
  }

error:
  return status;
}

size_t gse_deencap_compute_pdu_length(uint16_t total_length, uint8_t label_type)
{
  uint16_t pdu_length;
  pdu_length = total_length - gse_get_label_length(label_type)
               - PROTOCOL_TYPE_LENGTH;
  return pdu_length;
}

uint32_t gse_deencap_compute_crc(vfrag_t *pdu, uint8_t label_type)
{
  uint32_t crc;
  size_t offset;

  offset = TOTAL_LENGTH_LENGTH + PROTOCOL_TYPE_LENGTH +
           gse_get_label_length(label_type);

  crc = compute_crc(pdu->start - offset, pdu->length + offset);

  return htonl(crc);
}

