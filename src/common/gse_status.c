/****************************************************************************/
/**
 *   @file          gse_status.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: STATUS
 *
 *   @brief         Status code functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "gse_status.h"

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

static char *gse_status_string[STATUS_MAX + 1] =
{
  [0x0000] = "No error or warning",
  [0x0001 ... 0x00FF] = "Unknown status",
  [0x0100] = "Allocation error",
  [0x0101] = "Malloc failed",
  [0x0102 ... 0x01FF] = "Unknown status",
  [0x0200] = "Warning or error on virtual buffer management",
  [0x0201] = "Number of fragments can not be outside [0,2]",
  [0x0202] = "Fragment does not contain data",
  [0x0203] = "Two fragments in virtual buffer, can not modify data",
  [0x0204] = "Fragment is too small for data",
  [0x0205 ... 0x02FF] = "Unknown status",
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
  [0x0501] = "Label type is invalid or not supported",
  [0x0502] = "GSE length does not match GSE packet length",
  [0x0503] = "The FragID field is invalid",
  [0x0504] = "Header extensions are not supported",
  [0x0505] = "Label is invalid",
  [0x0506] = "Header format is invalid",
  [0x0507 ... 0x05FF] = "Unknown status",
  [0x0600] = "Warning or error on deencapsulation",
  [0x0601] = "Subsequent fragment of PDU received while first fragment is missing: packet dropped",
  [0x0602] = "Timeout, PDU was not completely received in 256 BBFrames: PDU dropped",
  [0x0603] = "A complete PDU is returned",
  [0x0604] = "Padding received: ignore all following data in BBFrame",
  [0x0605] = "Packet is too long for the deencapsulation buffer: PDU dropped",
  [0x0606 ... 0x06FF] = "Unknown status",
  [0x0700] = "Warning or error when verifying incoming PDU data",
  [0x0701] = "Total length does not match the PDU length: PDU dropped",
  [0x0702] = "CRC32 computed does not match the received one: PDU dropped",
  [0x0703 ... 0x07FF] = "Unknown status",
  [0x0800] = "Unknown status",
};

char* gse_get_status(int status)
{
  if((status < STATUS_OK) || (status > STATUS_MAX))
  {
    return "Unknown status";
  }
  else return gse_status_string[status];
}
