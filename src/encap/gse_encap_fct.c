/****************************************************************************/
/**
 *   @file          gse_encap_fct.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: ENCAPSULATION
 *
 *   @brief         GSE encapsulation functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "gse_encap_fct.h"

/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 ****************************************************************************/

/**
 *  @brief   Create GSE header
 *
 *  @param   pdu_type    Type of payload (COMPLETE, SUBS_FRAG, FIRST_FRAG)
 *  @param   encap_ctx   Encapsulation context of the PDU
 *  @param   length      Length of the GSE packet
 */
static void gse_encap_create_header(payload_type_t payload_type,
                                    gse_encap_ctx_t *const encap_ctx,
                                    size_t length);

/**
 *  @brief   Compute GSE packet Total Length header field
 *
 *  @param   encap_ctx    Encapsulation encap_ctx
 *  @return  Total Length
 */
static uint16_t gse_encap_compute_total_length(gse_encap_ctx_t *const encap_ctx);

/**
 *  @brief   Compute GSE packet GSE Length header field
 *
 *  This function takes the complete GSE packet length and deduces the mandatory
 *  fields length
 *
 *  @param   length  Length of GSE packet
 *  @param   header  Header of GSE packet
 */
static void gse_encap_compute_gse_length(size_t length, gse_header_t *header);

/**
 *  @brief   Compute GSE packet length
 *
 *  @param   length      Wanted length
 *  @param   remaining   Remaining data length
 *  @pram    header      Header length
 *  @return  GSE packet length
 */
static size_t gse_encap_compute_packet_length(size_t length,
                                              size_t remaining_data_length,
                                              size_t header_length);

/**
 *  @brief   Compute CRC32
 *
 *  @pram    vfrag   Virtual fragment
 *  @return  CRC32
 */
static uint32_t gse_encap_compute_crc(vfrag_t *vfrag);

/**
 *  @brief   Identical block between get_packet and get_packet_copy
 *
 *  @param   encap         Encapsulation context structure
 *  @param   length        Desired length for the packet
 *  @param   qos           QoS of the packet
 *  @return  GSE packet length
 */
static status_t gse_encap_get_packet_common(gse_encap_t *encap,
                                            size_t *length, uint8_t qos);

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

status_t gse_encap_receive_pdu(vfrag_t *pdu, gse_encap_t *encap,
                               uint8_t label[6], uint8_t label_type,
                               uint16_t protocol, uint8_t qos)
{
  status_t status = STATUS_OK;

  gse_encap_ctx_t *encap_ctx;
  int label_length = -1;

  //Check parameters validity
  label_length = gse_get_label_length(label_type);
  if(label_length < 0)
  {
    status = ERR_INVALID_LT;
    goto free_vfrag;
  }
  //Total length field shall be < 65536
  if(pdu->length > (MAX_PDU_LENGTH - PROTOCOL_TYPE_LENGTH -
                    (unsigned int)label_length))
  {
    status = ERR_PDU_LENGTH;
    goto free_vfrag;
  }
  if(label_type != 0x00)
  {
    status = ERR_INVALID_LT;
    goto free_vfrag;
  }
  //Check if protocol value is correct
  if(protocol < MIN_ETHER_TYPE)
  {
    status = EXTENSION_NOT_SUPPORTED;
    goto free_vfrag;
  }
  if(qos > gse_encap_get_qos_nbr(encap))
  {
    status = ERR_INVALID_QOS;
    goto free_vfrag;
  }

  //Fill encapsulation context
  encap_ctx = NULL;
  status = gse_push_fifo(&encap->fifo[qos], &encap_ctx);
  if(status != STATUS_OK)
  {
    goto free_vfrag;
  }
  encap_ctx->vfrag = pdu;
  encap_ctx->qos = qos;
  encap_ctx->protocol_type = protocol;
  encap_ctx->label_type = label_type;
  memcpy(&(encap_ctx->label), label, label_length);
  encap_ctx->frag_nbr = 0;
  encap_ctx->total_length = gse_encap_compute_total_length(encap_ctx);

  return status;
free_vfrag:
    gse_free_vfrag(pdu);
    return status;
}

status_t gse_encap_get_packet(vfrag_t **packet, gse_encap_t *encap,
                              size_t length, uint8_t qos)
{
  status_t status = STATUS_OK;

  int fifo_elt;
  gse_encap_ctx_t *encap_ctx;

  fifo_elt = encap->fifo[qos].first;
  encap_ctx = &encap->fifo[qos].value[fifo_elt];

  status = gse_encap_get_packet_common(encap, &length, qos);
  if(status != STATUS_OK)
  {
    goto error;
  }

  status = gse_duplicate_vfrag(packet, encap_ctx->vfrag,length);
  if(status != STATUS_OK)
  {
    goto error;
  }
  encap_ctx->frag_nbr++;
  /* Remove duplicated data from the initial fragment */
  status = gse_shift_vfrag(encap_ctx->vfrag, (*packet)->length, 0);
  if(status != STATUS_OK)
  {
    goto error;
  }

  if(encap_ctx->vfrag->length <= 0)
  {
    status = gse_free_vfrag(encap->fifo[qos].value[fifo_elt].vfrag);
    if(status != STATUS_OK)
    {
      goto error;
    }
    status = gse_pop_fifo(&encap->fifo[qos]);
    if(status != STATUS_OK)
    {
      goto error;
    }
  }

  return status;
error:
  *packet = NULL;
  return status;
}

status_t gse_encap_get_packet_copy(vfrag_t **packet,
                                   gse_encap_t *encap,
                                   size_t length, uint8_t qos)
{
  status_t status = STATUS_OK;

  int fifo_elt;
  gse_encap_ctx_t *encap_ctx;

  fifo_elt = encap->fifo[qos].first;
  encap_ctx = &encap->fifo[qos].value[fifo_elt];

  status = gse_encap_get_packet_common(encap, &length, qos);
  if(status != STATUS_OK)
  {
    goto error;
  }

  status = gse_create_vfrag_with_data(packet, length,
                                      encap_ctx->vfrag->start,
                                      length);
  if(status != STATUS_OK)
  {
    goto error;
  }
  encap_ctx->frag_nbr++;
  /* Remove copied data from the initial fragment */
  status = gse_shift_vfrag(encap_ctx->vfrag, (*packet)->length, 0);
  if(status != STATUS_OK)
  {
    goto error;
  }

  if(encap_ctx->vfrag->length <= 0)
  {
    status = gse_free_vfrag(encap->fifo[qos].value[fifo_elt].vfrag);
    if(status != STATUS_OK)
    {
      goto error;
    }
    status = gse_pop_fifo(&encap->fifo[qos]);
    if(status != STATUS_OK)
    {
      goto error;
    }
  }

  return status;
error:
  *packet = NULL;
  return status;
}

/****************************************************************************
 *
 *   PRIVATE FUNCTIONS
 *
 ****************************************************************************/

void gse_encap_create_header(payload_type_t payload_type,
                             gse_encap_ctx_t *const encap_ctx,
                             size_t length)
{
  uint32_t crc;
  gse_header_t *gse_header;

  gse_header = (gse_header_t*)encap_ctx->vfrag->start;

  gse_encap_compute_gse_length(length, gse_header);

  switch (payload_type)
  {
    /* GSE packet carrying a complete PDU */
    case COMPLETE:
      gse_header->s = 0x1;
      gse_header->e = 0x1;
      gse_header->lt = encap_ctx->label_type;
      gse_header->opt.complete.protocol_type = encap_ctx->protocol_type;
      memcpy(&(gse_header->opt.complete.label), &(encap_ctx->label),
             gse_get_label_length(encap_ctx->label_type));
      break;
    /* GSE packet carrying a first fragment of PDU */
    case FIRST_FRAG:
      gse_header->s = 0x1;
      gse_header->e = 0x0;
      gse_header->lt = encap_ctx->label_type;
      gse_header->opt.first.frag_id = encap_ctx->qos;
      gse_header->opt.first.total_length = encap_ctx->total_length;
      gse_header->opt.first.protocol_type = encap_ctx->protocol_type;
      memcpy(&(gse_header->opt.first.label), &(encap_ctx->label),
             gse_get_label_length(encap_ctx->label_type));

      crc = gse_encap_compute_crc(encap_ctx->vfrag);
      memcpy(encap_ctx->vfrag->end - 4, &crc, CRC_LENGTH);
      break;
    /* GSE packet carrying a subsequent fragment of PDU
     * which is not the last one*/
    case SUBS_FRAG:
      gse_header->s = 0x0;
      gse_header->e = 0x0;
      gse_header->lt = 0x3;
      gse_header->opt.first.frag_id = encap_ctx->qos;
      break;
    /* GSE packet carrying a last fragment of PDU */
    case LAST_FRAG:
      gse_header->s = 0x0;
      gse_header->e = 0x1;
      gse_header->lt = 0x3;
      gse_header->opt.first.frag_id = encap_ctx->qos;
      break;
    default:
      assert(0);
  }
}

uint16_t gse_encap_compute_total_length(gse_encap_ctx_t *const encap_ctx)
{
  uint16_t total_length;
  total_length = gse_get_label_length(encap_ctx->label_type)
                 + PROTOCOL_TYPE_LENGTH
                 + encap_ctx->vfrag->length;
  return  htons(total_length);
}

void gse_encap_compute_gse_length(size_t length, gse_header_t *header)
{
  uint16_t gse_length;
  gse_length = length - MANDATORY_FIELDS_LENGTH;

  header->gse_length_hi = (gse_length >> 8) & 0x0F;
  header->gse_length_lo = gse_length & 0xFF;
}

size_t gse_encap_compute_packet_length(size_t length,
                                       size_t remaining_data_length,
                                       size_t header_length)
{
  size_t packet_length;

  packet_length = MIN(length, MAX_GSE_PACKET_LENGTH);
  packet_length = MIN(length, remaining_data_length + header_length);

  return packet_length;
}

uint32_t gse_encap_compute_crc(vfrag_t *vfrag)
{
  uint32_t crc;
  unsigned char *data;
  size_t length;

  data = vfrag->start + MANDATORY_FIELDS_LENGTH + FRAG_ID_LENGTH;
  length = vfrag->length - (MANDATORY_FIELDS_LENGTH + FRAG_ID_LENGTH + CRC_LENGTH);
  crc = compute_crc(data, length);

  return htonl(crc);
}

status_t gse_encap_get_packet_common(gse_encap_t *encap,
                                     size_t *length, uint8_t qos)
{
  status_t status = STATUS_OK;

  size_t remaining_data_length;
  size_t header_length;
  unsigned int fifo_elt;
  gse_encap_ctx_t* encap_ctx;
  payload_type_t payload_type;

  if(gse_get_elt_nbr_fifo(&encap->fifo[qos]) == 0)
  {
    status = FIFO_EMPTY;
    goto error;
  }
  //Check parameters
  if(qos > gse_encap_get_qos_nbr(encap))
  {
    status = ERR_INVALID_QOS;
    goto error;
  }
  //If length = 0, the default value is used
  if(*length == 0)
  {
    *length = MAX_GSE_PACKET_LENGTH;
  }
  if(*length > MAX_GSE_PACKET_LENGTH)
  {
    status = LENGTH_TOO_HIGH;
    goto error;
  }
  if(*length < MIN_GSE_PACKET_LENGTH)
  {
    status = LENGTH_TOO_SMALL;
    goto error;
  }
  fifo_elt = encap->fifo[qos].first;
  encap_ctx = &encap->fifo[qos].value[fifo_elt];

  remaining_data_length = encap_ctx->vfrag->length;

  if(remaining_data_length <= 0)
  {
    status = gse_free_vfrag(encap->fifo[qos].value[fifo_elt].vfrag);
    if(status != STATUS_OK)
    {
      goto error;
    }
    status = gse_pop_fifo(&encap->fifo[qos]);
    if(status != STATUS_OK)
    {
      goto error;
    }
    gse_encap_get_packet_common(encap, length, qos);
    status = STATUS_OK;
    goto error;
  }

  header_length = gse_compute_header_length(COMPLETE, encap_ctx->label_type);
  //This is a complete PDU
  if(gse_get_frag_number(encap_ctx) == 0)
  {
    //Can the PDU be completly encapsulated ?
    if(*length >= (remaining_data_length + header_length))
    {
      payload_type = COMPLETE;
    }
    else
    {
      header_length = gse_compute_header_length(FIRST_FRAG,
                                                encap_ctx->label_type);
      payload_type = FIRST_FRAG;
    }
  }
  //This is a PDU fragment
  else
  {
    header_length = gse_compute_header_length(SUBS_FRAG, encap_ctx->label_type);
    //Is this the last fragment ?
    if(*length >= (remaining_data_length + header_length))
    {
      payload_type = LAST_FRAG;
      //Check if wanted length allow 1 bit of data
      //For last fragment CRC should not be forgotten
      if((header_length + 1 + CRC_LENGTH) > *length)
      {
        status = LENGTH_TOO_SMALL;
        goto error;
      }
    }
    else
    {
      payload_type = SUBS_FRAG;
    }
  }
  //Check if wanted length allow 1 bit of data
  if((header_length + 1) > *length)
  {
    status = LENGTH_TOO_SMALL;
    goto error;
  }

  *length = gse_encap_compute_packet_length(*length, remaining_data_length,
                                           header_length);

  if(payload_type == FIRST_FRAG)
  {
    status = gse_shift_vfrag(encap_ctx->vfrag, header_length * -1, CRC_LENGTH);
    if(status != STATUS_OK)
    {
      goto error;
    }
  }
  else
  {
    status = gse_shift_vfrag(encap_ctx->vfrag, header_length * -1, 0);
    if(status != STATUS_OK)
    {
      goto error;
    }
  }

  gse_encap_create_header(payload_type, encap_ctx, *length);

error:
  return status;
}

