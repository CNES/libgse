/****************************************************************************/
/**
 *   @file          constants.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: COMMON
 *
 *   @brief         Public constants for GSE library usage
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_CONSTANTS_H
#define GSE_CONSTANTS_H

#include <stdint.h>

/**< Maximum length of a PDU (in Bytes) */
#define GSE_MAX_PDU_LENGTH 65535
/**< Maximum length of a GSE packet (in Bytes) \
  * 4095 corresponds to the maximum for GSE length field 2 corresponds to the \
  * bytes which are not counted in GSE length field */
#define GSE_MAX_PACKET_LENGTH (4095 + 2)
/**< Maximum length of a GSE header (in Bytes) */
#define GSE_MAX_HEADER_LENGTH 13
/**< Maximum length of a GSE trailer (in Bytes) (length of CRC32) */
#define GSE_MAX_TRAILER_LENGTH 4
/**< Maximum offset between a fragmented PDU and a refragmented one */
#define GSE_MAX_REFRAG_HEAD_OFFSET 3

/** Type of label */
typedef enum
{
  GSE_LT_6_BYTES  = 0,   /**< 6-bytes label '00' */
  GSE_LT_3_BYTES  = 1,   /**< 3-bytes label '01' */
  GSE_LT_NO_LABEL = 2,   /**< No label '10' */
  GSE_LT_REUSE    = 3,   /**< label re-use or reserved value for PDU subsequent
                              fragments '11' */
} gse_label_type_t;

/**
 *  @brief   Get the GSE label length depending on label type value
 *
 *  @param   label_type    Label Type field of GSE packet header
 *
 *  @return                the label length on success,
 *                         -1 if the label type is unknown
 */
static inline int gse_get_label_length(gse_label_type_t label_type)
{
  switch(label_type)
  {
    /* LT = '00' : 6-Bytes label */
    case GSE_LT_6_BYTES :
      return 6;
      break;

    /* LT = '01' : 3-Bytes label */
    case GSE_LT_3_BYTES :
      return 3;
      break;

    /* LT = '10' : no label */
    case GSE_LT_NO_LABEL :
    /* LT = '11' : label re-use */
    case GSE_LT_REUSE :
      return 0;
      break;

    /* Invalid LT */
    default :
      return -1;
  }
}

#endif
