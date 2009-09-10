/****************************************************************************/
/**
 *   @file          gse_status.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: ERROR
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

  STATUS_OK = 0,            /**< There is no error or warning */
  ERR_MALLOC_FAILED,        /**< Error when calling malloc function */

  /** Virtual buffer status */
  ERR_FRAG_NBR,             /**< Error when manipulating buffer related
                                 to number of fragments (< 0 or > 2) */
  EMPTY_FRAG,               /**< Fragment does not contain data */
  ERR_FRAG_LENGTH,          /**< Length parameter is to high for a GSE
                                 packet */
  ERR_MULTIPLE_VBUF_ACCESS, /**< The data can't be modified in fragment because
                                 another fragment has access to the buffer */
  ERR_DATA_TOO_LONG,        /**< Data length is greater than fragment length */

  /** FIFO status */
  FIFO_FULL,                /**< FIFO is full, no more context can be
                                 created */
  FIFO_EMPTY,               /**< The FIFO is empty, try to get packet
                                 from another one */
  ERR_FIFO_SIZE_NULL,       /**< The FIFO size is 0 */
  ERR_QOS_NBR_NULL=10,      /**< There is no FIFO */

  /** Length parameters status */
  ERR_PDU_LENGTH,           /**< PDU length is greater than maximum PDU size */
  LENGTH_TO_SMALL,          /**< GSE packet length wanted is smaller than the
                                 minimum packet length, padding recommended */
  REFRAG_UNNECESSARY,       /**< The packet is smaller than the wanted length */

  /** Header status */
  ERR_INVALID_LT,           /**< Label Type is not supported */
  ERR_INVALID_GSE_LENGTH,   /**< The GSE length field is incorrect */
  ERR_INVALID_QOS,          /**< The FragID field does not correspond to
                                 the wanted QoS value */
  EXTENSION_NOT_SUPPORTED,  /**< Header extension detected */

  /** Deencapsulation context status */
  ERR_UNINITIALIZED_CTX,    /**< The deencapsulation context does not exist
                                 while receiving a subsequent fragment of PDU */
  TIMEOUT,                  /**< The PDU was not completly received in 
                                 256 BBFrames */
  PDU = 20,                 /**< A PDU and useful information are returned */
  PADDING_DETECTED,         /**< Padding is received */

  /** Received PDU status */
  ERR_INVALID_DATA_LENGTH,  /**< DATA length are different from PDU length
                                 computed with total length */
  ERR_INVALID_CRC,          /**< CRC32 computed does not correspond to received
                                 CRC32 */
} status_t;

#endif
