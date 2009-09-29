/****************************************************************************/
/**
 *   @file          constants.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
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

#include "stdint.h"

#define GSE_MAX_PDU_LENGTH 65535     /**< Maximum length of a PDU (in Bytes) */
#define GSE_MAX_PACKET_LENGTH 4095+2 /**< Maximum length of a GSE packet (in Bytes) */
/* 4095 corresponds to the maximum for GSE length field 2 corresponds to the bytes
 * which are not counted in GSE length field */
#define GSE_MAX_HEADER_LENGTH 13     /**< Maximum length of a GSE header (in Bytes) */
#define GSE_MAX_TRAILER_LENGTH 4     /**< Maximum length of a GSE trailer (in Bytes) \
                                       (length of CRC32) */
#define GSE_MAX_REFRAG_HEAD_OFFSET 3 /**< Maximum offset between a fragmented PDU and \
                                        a refragmented one */


/**
 *  @brief   Get GSE length depending on label type value
 *
 *  @param   label_type    Label Type field of GSE packet header
 *  @return  label_length on success, -1 if label_type is wrong
 */
static inline int gse_get_label_length(uint8_t label_type)
{
  switch (label_type)
  {
    // LT = '00' : 6-Bytes label
    case 0 :
      return 6;
      break;
    //LT = '01' : 3-Bytes label
    case 1 :
      return 3;
      break;
    //LT = '10' : no label
    case 2 :
    //LT = '11' : label re-use
    case 3 :
      return 0;
    //Invalid LT
    default :
      return -1;
  }
}

#endif
