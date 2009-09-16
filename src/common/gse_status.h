/****************************************************************************/
/**
 *   @file          gse_status.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: STATUS
 *
 *   @brief         Status codes
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_STATUS_H
#define GSE_STATUS_H

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** Error return codes */
typedef enum
{

  STATUS_OK = 0x0000,               /**< There is no error or warning */
  ERR_MALLOC_FAILED = 0x0101,       /**< Error when calling malloc function */

  /** Virtual buffer status */
  ERR_FRAG_NBR = 0x0201,            /**< Error when manipulating buffer related
                                         to number of fragments (< 0 or > 2) */
  EMPTY_FRAG = 0x0202,              /**< Fragment does not contain data */
  ERR_MULTIPLE_VBUF_ACCESS = 0x0203,/**< The data can't be modified in fragment because
                                         another fragment has access to the buffer */
  ERR_DATA_TOO_LONG = 0x0204,       /**< Data length is greater than fragment length */
  ERR_PTR_OUTSIDE_BUFF = 0x0205,    /**< Virtual fragments pointers are outside allocated
                                         memory */
  ERR_FRAG_PTRS = 0x0206,           /**< Fragments pointers are erroneous */

  /** FIFO status */
  FIFO_FULL = 0x0301,               /**< FIFO is full, no more context can be
                                         created */
  FIFO_EMPTY = 0x0302,              /**< The FIFO is empty, try to get packet
                                         from another one */
  ERR_FIFO_SIZE_NULL = 0x0303,      /**< The FIFO size is 0 */
  ERR_QOS_NBR_NULL = 0x0304,        /**< There is no FIFO */

  /** Length parameters status */
  ERR_PDU_LENGTH = 0x0401,          /**< PDU length is greater than maximum PDU size */
  LENGTH_TOO_SMALL = 0x0402,        /**< GSE packet length wanted is smaller than the
                                         minimum packet length, padding recommended */
  LENGTH_TOO_HIGH = 0x0403,         /**< Length parameter is to high for a GSE
                                         packet */
  REFRAG_UNNECESSARY = 0x0404,      /**< The packet is smaller than the wanted length */

  /** Header status */
  ERR_INVALID_LT = 0x0501,          /**< Label Type is not supported */
  ERR_INVALID_GSE_LENGTH = 0x0502,  /**< The GSE length field is incorrect */
  ERR_INVALID_QOS = 0x0503,         /**< The FragID field does not correspond to
                                         the wanted QoS value */
  EXTENSION_NOT_SUPPORTED = 0x0504, /**< Header extension detected */
  ERR_INVALID_LABEL = 0x0505,       /**< Label is incorrect */
  ERR_INVALID_HEADER = 0x506,       /**< Header is not valid */

  /** Deencapsulation context status */
  ERR_CTX_NOT_INIT = 0x0601,        /**< The deencapsulation context does not exist
                                         while receiving a subsequent fragment of PDU */
  TIMEOUT = 0x0602,                 /**< The PDU was not completly received in
                                         256 BBFrames */
  PDU = 0x0603,                     /**< A PDU and useful information are returned */
  PADDING_DETECTED = 0x0604,        /**< Padding is received */
  ERR_NO_SPACE_IN_BUFF = 0x0605,    /**< The packet is too long for the deencapsulation
                                         buffer */
  ERR_PACKET_TOO_SMALL = 0x0606,    /**< The packet is to small for a GSE packet */

  /** Received PDU status */
  ERR_INVALID_DATA_LENGTH = 0x0701, /**< DATA length are different from PDU length
                                         computed with total length */
  ERR_INVALID_CRC = 0x0702,         /**< CRC32 computed does not correspond to received
                                         CRC32 */

  STATUS_MAX = 0x0800,
} status_t;

/****************************************************************************
 *
 *   PROTOTYPES OF PUBLIC FUNCTIONS
 *
 ****************************************************************************/

/**
 *  @brief   Print warning or error corresponding to status
 *
 *           If the mask &0xFF00 is applied on status, global error is returned
 *
 *  @param   status     Status code
 *  @return  String containing status description
 */
char* gse_get_status(int status);

#endif
