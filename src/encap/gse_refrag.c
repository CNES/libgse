/****************************************************************************/
/**
 *   @file          gse_refrag.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: REFRAGMENTATION
 *
 *   @brief         GSE refragmentation functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "gse_refrag.h"

/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 ****************************************************************************/

/**
 *  @brief   Compute shift to applicate on header pointer
 *
 *  This is the difference between the former and the new header length
 *
 *  @param   payload_type   Type of data carried by the GSE packet
 *  @return  Header shift
*/
static size_t gse_refrag_compute_header_shift(payload_type_t payload_type);

/**
 *  @brief   Modify header of a GSE packet
 *
 *  @param   packet        The GSE packet
 *  @param   header        The GSE initial header
 *  @param   qos           The QoS of the packet
 *  @param   pdu_length    The length of the complete PDU
 *  @param   payload_type  The type of payload of the initial packet
*/
static void gse_refrag_modify_header(vfrag_t *packet, gse_header_t header,
                                         uint8_t qos, size_t pdu_length,
                                         payload_type_t payload_type);

/**
 *  @brief   Compute the header length of a GSE packet refragmented
 *
 *  @param   payload_type   Type of data carried by the initial GSE packet
 *  @param   label_type     Label Type filed of the GSE packet header
 *  @return  Header length
*/
static size_t gse_refrag_compute_header_length(payload_type_t payload_type,
                                               uint8_t label_type);

/**
 *  @brief   Compute the gse length header field of a GSE packet
 *
 *  @param   payload_type   Type of data carried by the GSE packet
 *  @param   header         Header of the initial GSE packet
 *  @param   data_length    Length of data field
 *  @param   new_header     Header of the new GSE packet
*/
static void gse_refrag_compute_gse_length(payload_type_t payload_type,
                                          gse_header_t header,
                                          size_t data_length,
                                          gse_header_t *new_header);

/**
 *  @brief   Create the header of a GSE packet depending on a GSE initial header
 *
 *  @param   packet         The GSE packet
 *  @param   payload_type   The payload carried by the packet
 *  @param   header         The GSE initial header
 *  @param   qos            The QoS of the packet
 *  @param   data_length    Length of the packet data field
*/
static void gse_refrag_create_header(vfrag_t *packet, payload_type_t payload_type,
                                         gse_header_t header, uint8_t qos,
                                         size_t data_length);

/**
 *  @brief   Compute CRC32 from two packets containing the two fragments of
 *           a PDU
 *
 *  @param   packet1      The GSE packet carrying the first fragment of the PDU
 *  @param   length       Length of data
 *  @param   label_length Length of label
 *  @return  status code
*/
static uint32_t gse_refrag_compute_crc(vfrag_t *const packet1, size_t length,
                                       size_t label_length);

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

status_t gse_refrag_packet(vfrag_t *packet1, vfrag_t **packet2,
                           uint8_t qos, size_t max_length)
{
  status_t status = STATUS_OK;

  gse_header_t header;
  payload_type_t payload_type;
  size_t header_shift;
  size_t header_length;
  size_t init_data_length;
  size_t remaining_length;
  uint32_t crc;
  uint16_t gse_length;

  if(max_length > MAX_GSE_PACKET_LENGTH)
  {
    status = LENGTH_TOO_HIGH;
    goto error;
  }
  if(max_length < MIN_GSE_PACKET_LENGTH)
  {
    status = LENGTH_TOO_SMALL;
    goto error;
  }
  if(max_length >= packet1->length)
  {
    status = REFRAG_UNNECESSARY;
    goto error;
  }

  memcpy(&header, packet1->start, MIN(sizeof(gse_header_t), packet1->length));

  gse_length = ((uint16_t)header.gse_length_hi << 8) | header.gse_length_lo;
  if(gse_length != packet1->length - MANDATORY_FIELDS_LENGTH)
  {
    status = ERR_INVALID_GSE_LENGTH;
    goto error;
  }
  if(gse_get_label_length(header.lt) < 0)
  {
    status = ERR_INVALID_LT;
    goto error;
  }

  if(header.s == 0x1)
  {
    if(header.e == 0x1)
    {
      payload_type = COMPLETE;
      header_length = gse_compute_header_length(COMPLETE, header.lt);
    }
    else
    {
      payload_type = FIRST_FRAG;
      header_length = gse_compute_header_length(FIRST_FRAG, header.lt);
    }
  }
  else
  {
    if(header.e == 0x1)
    {
      payload_type = LAST_FRAG;
      header_length = gse_compute_header_length(LAST_FRAG, header.lt);
      //Check if wanted length allow 1 bit of data
      //For first fragment CRC should not be forgotten
      if((header_length + 1 + CRC_LENGTH) > max_length)
      {
        status = LENGTH_TOO_SMALL;
        goto error;
      }
    }
    else
    {
      payload_type = SUBS_FRAG;
      header_length = gse_compute_header_length(SUBS_FRAG, header.lt);
    }
  }
  //Check if wanted length allow 1 bit of data
  if((header_length + 1) > max_length)
  {
    status = LENGTH_TOO_SMALL;
    goto error;
  }
  if(header_length > packet1->length)
  {
    status = ERR_INVALID_HEADER;
    goto error;
  }

  init_data_length = packet1->length -
                     gse_compute_header_length(payload_type, header.lt);

  header_shift = gse_refrag_compute_header_shift(payload_type);

  remaining_length = packet1->length - max_length - header_shift;

  status = gse_shift_vfrag(packet1, header_shift, remaining_length * -1);
  if(status != STATUS_OK)
  {
    goto error;
  }

  gse_refrag_modify_header(packet1, header, qos, init_data_length, payload_type);

  status = gse_create_vfrag_with_data(packet2, remaining_length,
                                      packet1->end, remaining_length);
  if(status != STATUS_OK)
  {
    goto error;
  }

  /* Second paquet is always a subsequent fragment or a last fragment */
  header_length = gse_compute_header_length(SUBS_FRAG, header.lt);

  if(payload_type == COMPLETE)
  {
    crc = gse_refrag_compute_crc(packet1, init_data_length,
                                 gse_get_label_length(header.lt));

    memcpy((*packet2)->end, &crc, CRC_LENGTH);

    status = gse_shift_vfrag(*packet2, header_length * -1, CRC_LENGTH);
    if(status != STATUS_OK)
    {
      goto free_packet;
    }

    // Add CRC length to remaining length
    remaining_length += CRC_LENGTH;
  }
  else
  {
    // Check QoS
    if(header.opt.frag_id != qos)
    {
      status = ERR_INVALID_QOS;
      goto free_packet;
    }
    status = gse_shift_vfrag(*packet2, header_length * -1, 0);
    if(status != STATUS_OK)
    {
      goto free_packet;
    }
  }

  gse_refrag_create_header(*packet2, payload_type, header, qos, remaining_length);

  return status;
free_packet:
  gse_free_vfrag(*packet2);
error:
  *packet2 = NULL;
  return status;
}

/****************************************************************************
 *
 *   PRIVATE FUNCTIONS
 *
 ****************************************************************************/

size_t gse_refrag_compute_header_shift(payload_type_t payload_type)
{
  size_t header_shift = 0;

  switch (payload_type)
  {
    /* GSE packet carrying a complete PDU */
    case COMPLETE:
      // difference between complete PDU and first fragment header
      header_shift = (FRAG_ID_LENGTH + TOTAL_LENGTH_LENGTH) * -1;
      break;
    /* GSE packet carrying a fragment of PDU */
    case FIRST_FRAG:
    case SUBS_FRAG:
    case LAST_FRAG:
      header_shift = 0;
      break;
    default:
      assert(0);
  }
  return header_shift;
}


void gse_refrag_modify_header(vfrag_t *packet, gse_header_t header,
                              uint8_t qos, size_t pdu_length,
                              payload_type_t payload_type)
{
  size_t data_field_length;
  uint16_t total_length;
  gse_header_t* modified_hdr;

  modified_hdr = ((gse_header_t*)packet->start);

  data_field_length = packet->length -
                      gse_refrag_compute_header_length(payload_type, header.lt);
/** @todo perform some fields verification */
  switch (payload_type)
  {
    /* Initial GSE packet carrying a complete PDU */
    case COMPLETE:
      gse_refrag_compute_gse_length(FIRST_FRAG, header,
                                    data_field_length, modified_hdr);

      total_length = gse_get_label_length(header.lt) + pdu_length
                     + PROTOCOL_TYPE_LENGTH;

      /* Complete -> first fragment */
      modified_hdr->s = 0x1;
      modified_hdr->e = 0x0;
      modified_hdr->lt = header.lt;
      modified_hdr->opt.first.frag_id = qos;
      modified_hdr->opt.first.total_length = htons(total_length);
      modified_hdr->opt.first.protocol_type = header.opt.complete.protocol_type;
      modified_hdr->opt.first.label = header.opt.complete.label;
      break;
    /*For the other payload types, there is no header switch so all the fields
     * are in correct position when vfrag->start is copied and only those which
     * need to be modified are changed */
    /* Initial GSE packet carrying a first fragment of PDU */
    case FIRST_FRAG:
      gse_refrag_compute_gse_length(FIRST_FRAG, header,
                                    data_field_length, modified_hdr);
      break;
    /* Initial GSE packet carrying a subsequent fragment of PDU whic is not the first*/
    case SUBS_FRAG:
      gse_refrag_compute_gse_length(SUBS_FRAG, header,
                                    data_field_length, modified_hdr);
      break;
    /* Initial GSE packet carrying a last fragment of PDU */
    case LAST_FRAG:
      /* Last fragment -> subsequent fragment */
      gse_refrag_compute_gse_length(SUBS_FRAG, header,
                                    data_field_length, modified_hdr);

      modified_hdr->e = 0x0;
      break;
    default:
      assert(0);
  }
}

size_t gse_refrag_compute_header_length(payload_type_t payload_type,
                                        uint8_t label_type)
{
  size_t header_length = 0;

  switch (payload_type)
  {
    /* Initial GSE packet carrying a complete PDU or a first fragment of PDU */
    case COMPLETE:
    case FIRST_FRAG:
      /* complete | first fragment -> first fragment */
      header_length = gse_compute_header_length(FIRST_FRAG, label_type);
      break;
    /* Initial GSE packet carrying a subsequent fragment of PDU */
    case SUBS_FRAG:
    case LAST_FRAG:
      header_length = gse_compute_header_length(SUBS_FRAG, label_type);
      break;
    default:
      assert(0);
  }
  return header_length;
}

void gse_refrag_compute_gse_length(payload_type_t payload_type,
                                   gse_header_t header, size_t data_length,
                                   gse_header_t *new_header)
{
  uint16_t gse_length = 0;

  switch (payload_type)
  {
    /* There is no complete case because only fragments are considered */

    /* GSE packet carrying a first fragment of PDU */
    case FIRST_FRAG:
      gse_length = FRAG_ID_LENGTH +
                   TOTAL_LENGTH_LENGTH +
                   PROTOCOL_TYPE_LENGTH +
                   gse_get_label_length(header.lt) +
                   data_length;
      break;
    /* GSE packet carrying a subsequent fragment of PDU */
    case SUBS_FRAG:
    case LAST_FRAG:
       gse_length = FRAG_ID_LENGTH +
                    data_length;
       break;
    default:
       assert(0);
  }
  new_header->gse_length_hi = (gse_length >> 8) & 0x0F;
  new_header->gse_length_lo = gse_length & 0xFF;
}

void gse_refrag_create_header(vfrag_t *packet, payload_type_t payload_type,
                                  gse_header_t header, uint8_t qos,
                                  size_t data_length)
{
  gse_header_t* created_hdr;

  created_hdr = ((gse_header_t*)packet->start);

  switch (payload_type)
  {
    /* Initial GSE packet carrying a complete PDU or a last fragment of PDU */
    case COMPLETE:
    case LAST_FRAG:
      gse_refrag_compute_gse_length(LAST_FRAG, header,
                                    data_length, created_hdr);

      /* complete -> first fragment + last fragment */
      created_hdr->s = 0x0;
      created_hdr->e = 0x1;
      created_hdr->lt = 0x3;
      created_hdr->opt.frag_id = qos;
      break;
    /* Initial GSE packet carrying a fragment of PDU which is not the last one */
    case FIRST_FRAG:
    case SUBS_FRAG:
      gse_refrag_compute_gse_length(SUBS_FRAG, header,
                                    data_length, created_hdr);

      /* first fragment -> first fragment + subsequent fragment */
      created_hdr->s = 0x0;
      created_hdr->e = 0x0;
      created_hdr->lt = 0x3;
      created_hdr->opt.frag_id = qos;
      break;
    default:
      assert(0);
  }
}

uint32_t gse_refrag_compute_crc(vfrag_t *const packet1, size_t length,
                                size_t label_length)
{
  uint32_t crc;
  unsigned char *data;

  data = packet1->start + MANDATORY_FIELDS_LENGTH + FRAG_ID_LENGTH;
  length += TOTAL_LENGTH_LENGTH + PROTOCOL_TYPE_LENGTH + label_length;

  crc = compute_crc(data, length);

  return htonl(crc);
}

