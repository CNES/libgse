/*
 *
 * This piece of software is an implementation of the Generic Stream
 * Encapsulation (GSE) standard defined by ETSI for Linux (or other
 * Unix-compatible OS). The library may be used to add GSE
 * encapsulation/de-encapsulation capabilities to an application.
 *
 *
 * Copyright © 2016 TAS
 *
 *
 * This file is part of the GSE library.
 *
 *
 * The GSE library is free software : you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

/****************************************************************************/
/**
 *   @file          header.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: COMMON
 *
 *   @brief         Sets of header constants, structures and functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef HEADER_H
#define HEADER_H

#include <stdint.h>
#include <string.h>
#include <endian.h>

#include "constants.h"

/**< Minimum length of a GSE packet (in Bytes) */
#define GSE_MIN_PACKET_LENGTH 3
/**< Minimum value for EtherTypes */
#define GSE_MIN_ETHER_TYPE 1536
/**< Length of the mandatory fields (in Bytes) (E, S, LT, GSE_Length) */
#define GSE_MANDATORY_FIELDS_LENGTH 2
/**< Length of Frag ID field (in Bytes) */
#define GSE_FRAG_ID_LENGTH 1
/**< Length of Total length field (in Bytes) */
#define GSE_TOTAL_LENGTH_LENGTH 2
/**< Length of Protocol type field (in Bytes) */
#define GSE_PROTOCOL_TYPE_LENGTH 2

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
  unsigned int gse_length_hi:4; /**< GSE length field MSB */
  unsigned int gse_length_lo:8; /**< GSE length field LSB */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned int gse_length_hi:4; /**< GSE length field MSB */
  unsigned int lt:2;            /**< Label Type field */
  unsigned int e:1;             /**< End Indicator field */
  unsigned int s:1;             /**< Start Indicator field */
  unsigned int gse_length_lo:8; /**< GSE length field LSB */
#else
#error "Please fix <bits/endian.h>"
#endif

  union
  {
    /**< Subsequent fragment of PDU */
    struct
    {
      uint8_t frag_id;              /**< Frag ID field */
    } __attribute__((packed)) subs_frag_s;

    /**< First fragment of PDU */
    struct
    {
      uint8_t frag_id;              /**< Frag ID Field */
      uint16_t total_length;        /**< Total Length field */
      uint16_t protocol_type;       /**< Protocol Type field */
      gse_label_t label;            /**< Label field */
    } __attribute__((packed)) first_frag_s;

    /**< Complete PDU */
    struct
    {
      uint16_t protocol_type;        /**< Protocol Type field */
      gse_label_t label;             /**< Label field */
    } __attribute__((packed)) complete_s;
  } __attribute__((packed));

} __attribute__((packed)) gse_header_t;

/** Type of payload carried by the GSE packet */
typedef enum
{
  GSE_PDU_COMPLETE,    /**< Complete PDU */
  GSE_PDU_FIRST_FRAG,  /**< First fragment of PDU */
  GSE_PDU_SUBS_FRAG,   /**< Subsequent fragment of PDU which is not the last one */
  GSE_PDU_LAST_FRAG,   /**< Last fragment of PDU */
} gse_payload_type_t;

/****************************************************************************
 *
 *   FUNCTIONS
 *
 ****************************************************************************/

/**
 *  @brief   Compute GSE packet header length
 *
 *  @param   payload_type  Type of payload (GSE_PDU_COMPLETE, GSE_PDU_SUBS_FRAG,
 *                                          GSE_PDU_FIRST_FRAG, GSE_PDU_LAST_FRAG)
 *  @param   label_type    Type of label (GSE_LT_6_BYTES, GSE_LT_3_BYTES,
 *                                        GSE_LT_NO_LABEL, GSE_LT_REUSE)
 *
 *  @return                The header length on success,
 *                         0 on error
 */
size_t gse_compute_header_length(gse_payload_type_t payload_type,
                                 gse_label_type_t label_type);

#endif
