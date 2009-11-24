/****************************************************************************/
/**
 *   @file          header.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: COMMON
 *
 *   @brief         Header functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "header.h"

#include <assert.h>

#include "constants.h"

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

size_t gse_compute_header_length(gse_payload_type_t payload_type,
                                 gse_label_type_t label_type)
{
  size_t header_length;

  switch(payload_type)
  {
    /* GSE packet carrying a complete PDU */
    case GSE_PDU_COMPLETE:
      header_length = GSE_MANDATORY_FIELDS_LENGTH +
                      GSE_PROTOCOL_TYPE_LENGTH +
                      gse_get_label_length(label_type);
      break;

    /* GSE packet carrying a first fragment of PDU */
    case GSE_PDU_FIRST_FRAG:
      header_length = GSE_MANDATORY_FIELDS_LENGTH +
                      GSE_FRAG_ID_LENGTH +
                      GSE_TOTAL_LENGTH_LENGTH +
                      GSE_PROTOCOL_TYPE_LENGTH +
                      gse_get_label_length(label_type);
      break;

    /* GSE packet carrying a subsequent fragment of PDU */
    case GSE_PDU_SUBS_FRAG:
    case GSE_PDU_LAST_FRAG:
      header_length = GSE_MANDATORY_FIELDS_LENGTH +
                      GSE_FRAG_ID_LENGTH;
      break;

    default:
      /* should not append */
      assert(0);
      header_length = 0;
  }
  return header_length;
}
