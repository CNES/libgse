/****************************************************************************/
/**
 *   @file          gse_common.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: COMMON
 *
 *   @brief         Common include, preprocessor, structures and functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_COMMON_H
#define GSE_COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <endian.h>
#include <arpa/inet.h>

#include "gse_status.h"
#include "crc.h"

/** Limits length */
#define MAX_PDU_LENGTH 65535         /**< Maximum length of a PDU (in Bytes) */
#define MAX_GSE_PACKET_LENGTH 4095+2
/**< Maximum length of a GSE packet (in Bytes) \
     4095 corresponds to the maximum for GSE length field \
     2 corresponds to the bytes which are not counted in GSE length field */
#define MIN_GSE_PACKET_LENGTH 3      /**< Minimum length of a GSE packet (in Bytes) */
#define MAX_HEADER_LENGTH 13         /**< Maximum length of GSE header (in Bytes) */
#define MIN_ETHER_TYPE 1536          /**< Minimum value for EtherTypes */

/** Header field length */
#define MANDATORY_FIELDS_LENGTH 2    /**< Length of the mandatory fields (in Bytes) \
                                          (E, S, LT, GSE_Length) */
#define FRAG_ID_LENGTH 1             /**< Length of Frag ID field (in Bytes) */
#define TOTAL_LENGTH_LENGTH 2        /**< Length of Total length field (in Bytes) */
#define PROTOCOL_TYPE_LENGTH 2       /**< Length of Protocol type field (in Bytes) */
#define CRC_LENGTH 4                 /**< Length of CRC32 (in Bytes) */

#define MIN(x, y)  (((x) < (y)) ? (x) : (y))

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** Label field structure */
typedef union
{
  uint8_t no_label[0];           /**< No label or label re-use */
  uint8_t three_bytes_label[3];  /**< 3-Bytes Label */
  uint8_t six_bytes_label[6];    /**< 6-Bytes Label */
} gse_label_t;

/** GSE header structure */
typedef struct
{
#if __BYTE_ORDER == __BIG_ENDIAN
  unsigned int s:1;             /**< Start Indicator field */
  unsigned int e:1;             /**< End Indicator field */
  unsigned int lt:2;            /**< Label Type field */
  unsigned int gse_length_hi:4; /**< GSE Length field MSB */
  unsigned int gse_length_lo:8; /**< Gse Length field LSB*/
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned int gse_length_hi:4; /**< GSE Length field MSB */
  unsigned int lt:2;            /**< Label Type field */
  unsigned int e:1;             /**< End Indicator field */
  unsigned int s:1;             /**< Start Indicator field */
  unsigned int gse_length_lo:8; /**< Gse Length field LSB */
#else
#error "Please fix <bits/endian.h>"
#endif

  union
  {
    uint8_t frag_id;              /**< Frag ID Field
                                       Used for a subsequent fragment of PDU */
    struct
    {
      uint8_t frag_id;              /**< Frag ID Field */
      uint16_t total_length;        /**< Total Length field */
      uint16_t protocol_type;       /**< Protocol Type field */
      gse_label_t label;            /**< Label field */
    } __attribute__((packed)) first;                      /**< First fragment of PDU */

    struct
    {
      uint16_t protocol_type;        /**< Protocol Type field */
      gse_label_t label;             /**< Label field */
    } __attribute__((packed)) complete;                   /**< Complete PDU */

  } opt;                        /**< Optionnal fields depending on payload type*/
} __attribute__((packed)) gse_header_t;

/** Type of payload carried bye the GSE packet */
typedef enum
{
  COMPLETE,    /**< Complete PDU */
  FIRST_FRAG,  /**< First fragment of PDU */
  SUBS_FRAG,   /**< Subsequent fragment of PDU which is not the last one*/
  LAST_FRAG,   /**< Last fragment of PDU */
} payload_type_t;

/****************************************************************************
 *
 *   FUNCTIONS
 *
 ****************************************************************************/

/**
 *  @brief   Get GSE length depending on label type value
 *
 *  @param   label_type    Label Type field of GSE packet header
 *  @return  label_length on success, -1 if label_type is wrong
 */
int gse_get_label_length(uint8_t label_type);

/**
 *  @brief   Compute GSE packet header length
 *
 *  @param   pdu_type    Type of PDU (COMPLETE, SUBS_FRAG, FIRST_FRAG, LAST_FRAG)
 *  @return  header length
 */
size_t gse_compute_header_length(payload_type_t payload_type,
                                 uint8_t label_type);

#endif
