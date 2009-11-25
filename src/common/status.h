/****************************************************************************/
/**
 *   @file          status.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
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
  /** There is no error or warning */
  GSE_STATUS_OK                       = 0x0000,
  /** Error when calling malloc function */
  GSE_STATUS_MALLOC_FAILED            = 0x0101,
  /** NULL pointer given as parameter */
  GSE_STATUS_NULL_PTR                 = 0x0102,
  /** A pthread_mutex function returned an error */
  GSE_STATUS_PTHREAD_MUTEX            = 0x0103,
  /** Internal error, please report bug */
  GSE_STATUS_INTERNAL_ERROR           = 0x0104,

  /* Virtual buffer status */

  /** Error when manipulating buffer related to number of fragments (< 0 or > 2) */
  GSE_STATUS_FRAG_NBR                 = 0x0201,
  /** Fragment does not contain data */
  GSE_STATUS_EMPTY_FRAG               = 0x0202,
  /** The data can't be modified in fragment because another fragment has access
   *  to the buffer
   */
  GSE_STATUS_MULTIPLE_VBUF_ACCESS     = 0x0203,
  /** Data length is greater than fragment length */
  GSE_STATUS_DATA_TOO_LONG            = 0x0204,
  /** Virtual fragments pointers are outside allocated memory */
  GSE_STATUS_PTR_OUTSIDE_BUFF         = 0x0205,
  /** Fragments pointers are erroneous */
  GSE_STATUS_FRAG_PTRS                = 0x0206,
  /** Sum of offsets is greater than allocated length */
  GSE_STATUS_OFFSET_TOO_HIGH          = 0x0207,
  /** Specified length for buffer is null */
  GSE_STATUS_BUFF_LENGTH_NULL         = 0x0208,

  /* FIFO status */

  /** FIFO is full, no more context can be created */
  GSE_STATUS_FIFO_FULL                = 0x0301,
  /** The FIFO is empty, try to get packet from another one */
  GSE_STATUS_FIFO_SIZE_NULL           = 0x0303,
  /** The FIFO size is 0 */
  GSE_STATUS_FIFO_EMPTY               = 0x0302,
  /** There is no FIFO */
  GSE_STATUS_QOS_NBR_NULL             = 0x0304,

  /* Length parameters status */

  /** PDU length is greater than maximum PDU size */
  GSE_STATUS_PDU_LENGTH               = 0x0401,
  /** GSE packet length wanted is smaller than the minimum packet length,
   *  padding recommended
   */
  GSE_STATUS_LENGTH_TOO_SMALL         = 0x0402,
  /** Length parameter is to high for a GSE packet */
  GSE_STATUS_LENGTH_TOO_HIGH          = 0x0403,
  /** The packet is smaller than the wanted length */
  GSE_STATUS_REFRAG_UNNECESSARY       = 0x0404,

  /* Header status */

  /** Label Type is not supported */
  GSE_STATUS_INVALID_LT               = 0x0501,
  /** The GSE length field is incorrect */
  GSE_STATUS_INVALID_GSE_LENGTH       = 0x0502,
  /** The FragID field does not correspond to the wanted QoS value */
  GSE_STATUS_INVALID_QOS              = 0x0503,
  /** Header extension detected */
  GSE_STATUS_EXTENSION_NOT_SUPPORTED  = 0x0504,
  /** Label is incorrect */
  GSE_STATUS_INVALID_LABEL            = 0x0505,
  /** Header is not valid */
  GSE_STATUS_INVALID_HEADER           = 0x0506,

  /* Deencapsulation context status */

  /** The deencapsulation context does not exist while receiving a subsequent
   *  fragment of PDU
   */
  GSE_STATUS_CTX_NOT_INIT             = 0x0601,
  /** The PDU was not completly received in 256 BBFrames */
  GSE_STATUS_TIMEOUT                  = 0x0602,
  /** A PDU and useful information are returned */
  GSE_STATUS_PDU_RECEIVED             = 0x0603,
  /** Padding is received */
  GSE_STATUS_PADDING_DETECTED         = 0x0604,
  /** The packet is too long for the deencapsulation buffer */
  GSE_STATUS_NO_SPACE_IN_BUFF         = 0x0605,
  /** The packet is to small for a GSE packet */
  GSE_STATUS_PACKET_TOO_SMALL         = 0x0606,
  /** The context is not empty when receiving a first fragment, previous data
   *  is overwritten
   */
  GSE_STATUS_DATA_OVERWRITTEN         = 0x0607,

  /* Received PDU status */

  /** Data length are different from PDU length computed with total length */
  GSE_STATUS_INVALID_DATA_LENGTH      = 0x0701,
  /** CRC32 computed does not correspond to received CRC32 */
  GSE_STATUS_INVALID_CRC              = 0x0702,
  /** Last packet containis less than 4 bytes after header */
  GSE_STATUS_CRC_FRAGMENTED           = 0x0703,

  /* Header fields access */

  /** The GSE packet does not contain the requested field */
  GSE_STATUS_FIELD_ABSENT             = 0x0801,

  GSE_STATUS_MAX                      = 0x0900,
} gse_status_t;

/****************************************************************************
 *
 *   PROTOTYPES OF PUBLIC FUNCTIONS
 *
 ****************************************************************************/

/**
 *  @brief   Print warning or error corresponding to status
 *
 *  The status is coded on 2 bytes : the Most Significant Byte (MSB)
 *  codes for the status family and the Least Significant Byte (LSB)
 *  codes for a specific status in this family.
 *  So if the mask 0xFF00 is applied on the status, then the status
 *  family is returned
 *
 *  @param   status     The Status code
 *
 *  @return             String containing status description
 */
char *gse_get_status(gse_status_t status);

#endif
