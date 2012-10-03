/*
 *
 * This piece of software is an implementation of the Generic Stream
 * Encapsulation (GSE) standard defined by ETSI for Linux (or other
 * Unix-compatible OS). The library may be used to add GSE
 * encapsulation/de-encapsulation capabilities to an application.
 *
 *
 * Copyright © 2011 TAS
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
 *   @file          header_fields.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: COMMON
 *
 *   @brief         Function related to header fields
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "header_fields.h"

#include <arpa/inet.h>

#include "header.h"

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

gse_status_t gse_get_start_indicator(unsigned char *packet,
                                     uint8_t *start_indicator)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_header_t *header;

  if(packet == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  header = (gse_header_t *)packet;
  *start_indicator = header->s;

error:
  return status;
}

gse_status_t gse_get_end_indicator(unsigned char *packet,
                                   uint8_t *end_indicator)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_header_t *header;

  if(packet == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  header = (gse_header_t *)packet;
  *end_indicator = header->e;

error:
  return status;
}

gse_status_t gse_get_label_type(unsigned char *packet, uint8_t *label_type)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_header_t *header;

  if(packet == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  header = (gse_header_t *)packet;
  *label_type = header->lt;

error:
  return status;
}

gse_status_t gse_get_gse_length(unsigned char *packet, uint16_t *gse_length)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_header_t *header;

  if(packet == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  header = (gse_header_t *)packet;
  *gse_length = ((uint16_t)header->gse_length_hi << 8) | header->gse_length_lo;

error:
  return status;
}

gse_status_t gse_get_frag_id(unsigned char *packet, uint8_t *frag_id)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_header_t *header;

  if(packet == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  header = (gse_header_t *)packet;
  // Test if the GSE packet contains a fragment of PDU and not a complete PDU
  if(header->s == 1 && header->e == 1)
  {
    status = GSE_STATUS_FIELD_ABSENT;
    goto error;
  }
  // Set the Frag Id according to payload type
  if(header->s == 0)
  {
    *frag_id = header->subs_frag_s.frag_id;
  }
  else
  {
    *frag_id = header->first_frag_s.frag_id;
  }

error:
  return status;
}

gse_status_t gse_get_total_length(unsigned char *packet, uint16_t *total_length)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_header_t *header;

  if(packet == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  header = (gse_header_t *)packet;
  // Test if the GSE packet contains the good fragment type
  if(header->s != 1 || header->e != 0)
  {
    status = GSE_STATUS_FIELD_ABSENT;
    goto error;
  }
  *total_length = ntohs(header->first_frag_s.total_length);

error:
  return status;
}

gse_status_t gse_get_protocol_type(unsigned char *packet,
                                   uint16_t *protocol_type)
{
  gse_status_t status = GSE_STATUS_OK;
  gse_header_t *header;

  if(packet == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  header = (gse_header_t *)packet;
  // Test if the GSE packet contains the good payload type
  if(header->s != 1)
  {
    status = GSE_STATUS_FIELD_ABSENT;
    goto error;
  }
  // Set the Protocol Type according to payload type
  if(header->e == 0)
  {
    *protocol_type = ntohs(header->first_frag_s.protocol_type);
  }
  else
  {
    *protocol_type = ntohs(header->complete_s.protocol_type);
  }

error:
  return status;
}

gse_status_t gse_get_label(unsigned char *packet, uint8_t label[6])
{
  gse_status_t status = GSE_STATUS_OK;
  gse_header_t *header;

  if(packet == NULL)
  {
    status = GSE_STATUS_NULL_PTR;
    goto error;
  }

  header = (gse_header_t *)packet;
  // Test if the GSE packet contains the good payload type
  if(header->s != 1)
  {
    status = GSE_STATUS_FIELD_ABSENT;
    goto error;
  }
  // Set the Label according to payload type
  if(header->e == 0)
  {
    memcpy(label, &header->first_frag_s.label,
           gse_get_label_length(header->lt));
  }
  else
  {
    memcpy(label, &header->complete_s.label,
           gse_get_label_length(header->lt));
  }

error:
  return status;
}

gse_status_t gse_check_header_extension_validity(unsigned char *extension,
                                                 size_t *ext_length,
                                                 uint16_t extension_type,
                                                 uint16_t *protocol_type)
{
  gse_status_t status = GSE_STATUS_OK;

  gse_ext_type_t current_type;
  size_t current_length = 0;

  current_type.null_1 = (extension_type >> 12) & 0xF;
  current_type.null_2 = (extension_type >> 8) & 0x08;
  current_type.h_len = (extension_type >> 8) & 0x07;
  current_type.h_type = extension_type & 0xFF;

  while(current_length < *ext_length)
  {
    if(current_type.null_1 != 0 || current_type.null_2 != 0)
    {
      /* got protocol_type, end of extensions */
      break;
    }

    switch(current_type.h_len)
    {
      case(0x0):
        /* TODO mandatory header extension */
        status = GSE_STATUS_INVALID_EXTENSIONS;
        goto error;
        break;

      case(0x1):
        current_length += 2;
        break;

      case(0x2):
        current_length += 4;
        break;

      case(0x3):
        current_length += 6;
        break;

      case(0x4):
        current_length += 8;
        break;

      case(0x5):
        current_length += 10;
        break;

      default:
        status = GSE_STATUS_INVALID_EXTENSIONS;
        goto error;
    }
    if(current_length <= *ext_length)
    {
      memcpy(&current_type, extension + current_length - 2, sizeof(gse_ext_type_t));
    }
    else
    {
      status = GSE_STATUS_INVALID_EXTENSIONS;
      goto error;
    }
  }

  *protocol_type = (current_type.null_1 & 0xF) << 12 |
                   (current_type.null_2 & 0x08) << 8 |
                   (current_type.h_len & 0x07) << 8 |
                   (current_type.h_type & 0xFF);
  if(*protocol_type < GSE_MIN_ETHER_TYPE)
  {
    status = GSE_STATUS_INVALID_EXTENSIONS;
    goto error;
  }

  *ext_length = current_length;

error:
  return status;
}

 
