/****************************************************************************/
/**
 *   @file          deencap.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: DEENCAPSULATION CONTEXT
 *
 *   @brief         GSE deencapsulation public functions definition
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_DEENCAP_H
#define GSE_DEENCAP_H

#include <stdint.h>

#include "virtual_buffer.h"

struct gse_deencap_s;
typedef struct gse_deencap_s gse_deencap_t;

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/* Deencapsulation structure management */

/**
 *  @brief   Initialize the deencapsulation structure
 *
 *  The function return the deencapsulation structure which is a table of
 *  deencapsulation contexts
 *
 *  @param   qos_nbr   Number of qos values
 *  @param   deencap   Structure of de-encapsulation contexts
 *  @return  status code
 */
status_t gse_deencap_init(uint8_t qos_nbr, gse_deencap_t **deencap);

/**
 *  @brief   Release the encapsulation structure
 *
 *  @param   deencap   Structure of de-encapsulation contexts
 *  @return  status code
 */
status_t gse_deencap_release(gse_deencap_t *deencap);

/**
 *  @brief   Set the offset applied on all the received PDU
 *
 *  @param   deencap       Structure of de-encapsulation contexts
 *  @param   head_offset   Offset applied on the beginning of the PDU
 *  @param   trail_offset  Offset applied on the end of the PDU
 *  @return  status code
 */
status_t gse_deencap_set_offsets(gse_deencap_t *deencap,
                                 size_t head_offset, size_t trail_offset);

/* Deencapsulation functions */

/**
 *  @brief   Deencapsulate a PDU from one or more packets
 *
 *           If the complete PDU is deencapsulated, label_type, label, protocol
 *           and the PDU itself are returned, else only GSE Length is returned
 *
 *  @param   data           The data containing packet to deencapsulate
 *                          The first bytes of data should contain the packet
 *  @param   deencap        The deencapsulation context structure
 *  @param   label_type     OUT: The label type field value
 *                          only '00' is implemented
 *  @param   label          OUT: The packet label
 *  @param   protocol       OUT: The PDU protocol
 *  @param   pdu            OUT: The PDU
 *  @param   gse_length     OUT: The GSE Length field value
 *                          The length of th GSE packet is GSE Length + 2 Bytes
 *  @return  status code
 */
status_t gse_deencap_packet(vfrag_t *data, gse_deencap_t *deencap,
                            uint8_t *label_type, uint8_t label[6],
                            uint16_t *protocol, vfrag_t **pdu,
                            uint16_t *gse_length);

/**
 *  @brief   Signal that a new BBFrame has been received
 *
 *  @param   deencap       The deencapsulation context structure
 *  @return  status code
 */
status_t gse_deencap_new_bbframe(gse_deencap_t *deencap);

#endif
