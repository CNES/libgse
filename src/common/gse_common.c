/****************************************************************************/
/**
 *   @file          gse_common.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: COMMON
 *
 *   @brief         Common functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "gse_common.h"

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

int gse_get_label_length(uint8_t label_type)
{
  switch (label_type)
  {
    /* LT = '00' : 6-Bytes label */
    case 0 :
      return 6;
      break;
    /* LT = '01' : 3-Bytes label */
    case 1 :
      return 3;
      break;
    /* LT = '10' : no label */
    case 2 :
    /* LT = '11' : label re-use */
    case 3 :
      return 0;
    /* Invalid LT */
    default :
      return -1;
  }
}

size_t gse_compute_header_length(payload_type_t payload_type,
                                 uint8_t label_type)
{
  size_t header_length = 0;

  switch (payload_type)
  {
    /* GSE packet carrying a complete PDU */
    case COMPLETE:
      header_length = MANDATORY_FIELDS_LENGTH +
                      PROTOCOL_TYPE_LENGTH +
                      gse_get_label_length(label_type);
      break;
    /* GSE packet carrying a first fragment of PDU */
    case FIRST_FRAG:
      header_length = MANDATORY_FIELDS_LENGTH +
                      FRAG_ID_LENGTH +
                      TOTAL_LENGTH_LENGTH +
                      PROTOCOL_TYPE_LENGTH +
                      gse_get_label_length(label_type);
      break;
    /* GSE packet carrying a subsequent fragment of PDU */
    case SUBS_FRAG:
    case LAST_FRAG:
      header_length = MANDATORY_FIELDS_LENGTH +
                      FRAG_ID_LENGTH;
      break;
    default:
      assert(0);
  }
  return header_length;
}
