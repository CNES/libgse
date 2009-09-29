/****************************************************************************/
/**
 *   @file          header.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: COMMON
 *
 *   @brief         Header functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include <assert.h>

#include "constants.h"
#include "header.h"

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

size_t gse_compute_header_length(payload_type_t payload_type,
                                 uint8_t label_type)
{
  size_t header_length = 0;

  switch (payload_type)
  {
    //GSE packet carrying a complete PDU
    case COMPLETE:
      header_length = GSE_MANDATORY_FIELDS_LENGTH +
                      GSE_PROTOCOL_TYPE_LENGTH +
                      gse_get_label_length(label_type);
      break;
    //GSE packet carrying a first fragment of PDU
    case FIRST_FRAG:
      header_length = GSE_MANDATORY_FIELDS_LENGTH +
                      GSE_FRAG_ID_LENGTH +
                      GSE_TOTAL_LENGTH_LENGTH +
                      GSE_PROTOCOL_TYPE_LENGTH +
                      gse_get_label_length(label_type);
      break;
    //GSE packet carrying a subsequent fragment of PDU
    case SUBS_FRAG:
    case LAST_FRAG:
      header_length = GSE_MANDATORY_FIELDS_LENGTH +
                      GSE_FRAG_ID_LENGTH;
      break;
    default:
      assert(0);
  }
  return header_length;
}
