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
 *   @file          status.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: STATUS
 *
 *   @brief         Function which allows to get a status code description
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "status.h"

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

/** Table of strings containing status descriptions */
static char *gse_status_string[GSE_STATUS_MAX] =
{
  [0x0000] = "No error or warning",
  [0x0001 ... 0x00FF] = "Unknown status",
  [0x0100] = "Allocation error",
  [0x0101] = "Malloc failed",
  [0x0102] = "Pointer given in parameter is NULL",
  [0x0103] = "Error with pthread_mutex function",
  [0x0104] = "Internal error, please report bug",
  [0x0105 ... 0x01FF] = "Unknown status",
  [0x0200] = "Warning or error on virtual buffer management",
  [0x0201] = "Number of fragments can not be outside [0,2]",
  [0x0202] = "Fragment does not contain data",
  [0x0203] = "Two fragments in virtual buffer, can not modify data",
  [0x0204] = "Fragment is too small for data",
  [0x0205] = "Fragments limits are outside allocated memory",
  [0x0206] = "Incorrect pointers in fragment",
  [0x0207] = "The specified offset are too long for the virtual buffer",
  [0x0208] = "The specified length for buffer is null",
  [0x0209 ... 0x02FF] = "Unknown status",
  [0x0300] = "Warning or error on FIFO management",
  [0x0301] = "FIFO is full",
  [0x0302] = "FIFO is empty",
  [0x0303] = "FIFO size is null",
  [0x0304] = "FIFO number is null",
  [0x0305 ... 0x03FF] = "Unknown status",
  [0x0400] = "Warning or error on length parameters",
  [0x0401] = "PDU is to long",
  [0x0402] = "Length is too small for a GSE packet (try another FragID or use padding)",
  [0x0403] = "Length is too high for a GSE packet",
  [0x0404] = "There is no need to refragment, GSE packet length is under the specified value",
  [0x0405 ... 0x04FF] = "Unknown status",
  [0x0500] = "Warning or error on GSE packet header",
  [0x0501] = "Label type is invalid or incorrect",
  [0x0502] = "GSE length does not match GSE packet length",
  [0x0503] = "The FragID field is invalid",
  [0x0504] = "Header extensions are not supported",
  [0x0505] = "Label is invalid",
  [0x0506] = "Header format is invalid",
  [0x0507 ... 0x05FF] = "Unknown status",
  [0x0600] = "Warning or error on deencapsulation",
  [0x0601] = "Subsequent fragment of PDU received while first fragment is missing: packet dropped",
  [0x0602] = "Timeout, PDU was not completely received in 256 BBFrames: PDU dropped",
  [0x0603] = "Packet is too long for the deencapsulation buffer: PDU dropped",
  [0x0604] = "Packet is too small for a GSE packet",
  [0x0605 ... 0x06FF] = "Unknown status",
  [0x0700] = "Warning or error when verifying incoming PDU data",
  [0x0701] = "Total length does not match the PDU length: PDU dropped",
  [0x0702] = "CRC32 computed does not match the received one: PDU dropped",
  [0x0703] = "Last fragment does not contain enough data for containing a complete CRC : PDU dropped",
  [0x0704 ... 0x07FF] = "Unknown status",
  [0x0800] = "Deencapsulation informative code received, don't treat it as error",
  [0x0801] = "Padding received: ignore all following data in BBFrame",
  [0x0802] = "Context is not empty while receiving a first fragment, previous data overwritten",
  [0x0803 ... 0x08FF] = "Unknown status",
  [0x0900] = "Deencapsulation success code received, a complete PDU is returned",
  [0x0903] = "A complete PDU is returned",
  [0x0904 ... 0x09FF] = "Unknown status",
  [0x0A00] = "Warning or error when retrieving a header field value",
  [0x0A01] = "The GSE packet does not contain the requested field",
  [0x0A02 ... 0x0AFF] = "Unknown status",
};

char *gse_get_status(gse_status_t status)
{
  if(status >= GSE_STATUS_MAX)
  {
    return "Unknown status";
  }
  else
  {
    return gse_status_string[status];
  }
}
