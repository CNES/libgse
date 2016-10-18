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
 *   @file          encap_ctx.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: ENCAPSULATION CONTEXT
 *
 *   @brief         Encapsulation context definition
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_ENCAP_CTX_H
#define GSE_ENCAP_CTX_H

#include "header.h"
#include "virtual_fragment.h"

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** Encapsulation context */
typedef struct
{
  gse_vfrag_t *vfrag;     /**< Virtual fragment containing the PDU */
  gse_label_t label;      /**< Label field value */
  uint16_t total_length;  /**< Total length field value in Network Byte Order (NBO) */
  uint16_t protocol_type; /**< Protocol type field value in NBO */
  uint8_t qos;            /**< QoS value of the context : used as FragID value */
  uint8_t label_type;     /**< Label type field value */
  unsigned int frag_nbr;  /**< Number of fragment */
} gse_encap_ctx_t;

#endif
