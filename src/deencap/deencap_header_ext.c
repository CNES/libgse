/****************************************************************************/
/**
 *   @file          deencap_header_ext.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: deencapSULATION
 *
 *   @brief         GSE functions for header extensions deencapsulation
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "deencap_header_ext.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <assert.h>

#include "header.h"
//#include "header_fields.h"


/** Get the minimum between two values */
#define MAX(x, y)  (((x) > (y)) ? (x) : (y))


/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

gse_status_t gse_deencap_get_header_ext(unsigned char *packet,
                                        gse_deencap_read_header_ext_cb_t callback,
                                        void *opaque)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_header_t *header;
  size_t ext_shift = 0;
  gse_label_type_t lt;
  uint16_t extension_type;
  uint16_t protocol_type;
  uint16_t gse_length;
  size_t max_ext_length;
  gse_payload_type_t payload_type;
  int label_length;

  int ret;

  if(packet == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  header = (gse_header_t *)packet;

  /* the extensions are at least after S, E, LT and GSE Length */
  ext_shift = GSE_MANDATORY_FIELDS_LENGTH;

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
      /* add the Protocol Type lentgh for extension shift */
      ext_shift += GSE_PROTOCOL_TYPE_LENGTH;
      extension_type = ntohs(header->complete_s.protocol_type);
    }
    else
    {
      payload_type = GSE_PDU_FIRST_FRAG;
      /* add the FragID and Total Length fields lentgh for extension shift */
      ext_shift += GSE_FRAG_ID_LENGTH + GSE_TOTAL_LENGTH_LENGTH;
      /* add the Protocol Type lentgh for extension shift */
      ext_shift += GSE_PROTOCOL_TYPE_LENGTH;
      extension_type = ntohs(header->first_frag_s.protocol_type);
    }
  }
  else
  {
    /* subsequent fragment, no protocol_type field in header: no extension */
    status = GSE_STATUS_EXTENSION_UNAVAILABLE;
    goto error;
  }

  if(extension_type >= GSE_MIN_ETHER_TYPE)
  {
      /* no header extension */
      status = GSE_STATUS_EXTENSION_UNAVAILABLE;
      goto error;
  }

  /* Get the Label Type */
  lt = header->lt;
  label_length = gse_get_label_length(lt);
  if(label_length < 0)
  {
    status = GSE_STATUS_INVALID_LT;
    goto error;
  }
  ext_shift += label_length;

  /* Extract the GSE Length of the header of the GSE packet */
  gse_length = ((uint16_t)header->gse_length_hi << 8) |
               header->gse_length_lo;

  max_ext_length = gse_length - (ext_shift - GSE_MANDATORY_FIELDS_LENGTH);

  /* read the extensions */
  ret = callback(packet + ext_shift, &max_ext_length, &protocol_type,
                 extension_type, opaque);
  if(ret < 0)
  {
    status = GSE_STATUS_EXTENSION_CB_FAILED;
    goto error;
  }

error:
  return status;
}

