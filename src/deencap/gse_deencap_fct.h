/****************************************************************************/
/**
 *   @file          gse_deencap_fct.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: DEENCAPSULATION
 *
 *   @brief         GSE deencapsulation functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_DEENCAP_FCT_H
#define GSE_DEENCAP_FCT_H

#include "gse_common.h"
#include "gse_deencap.h"

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/**
 *  @brief   Deencapsulate a PDU from one or more packets
 *
 *           If the complete PDU is deencapsulated, it is returned
 *
 *  @param   packet         The packet to deencapsulate
 *  @param   deencap        The deencapsulation context structure
 *  @param   label_type     The label type field value
 *                          //'00' only implemented
 *  @param   label          The packet label
 *  @param   protocol       The PDU protocol
 *  @param   pdu            The PDU
 *  @return  status code
 */
status_t gse_deencap_packet(vfrag_t *packet, gse_deencap_t *deencap,
                            uint8_t *label_type, uint8_t label[6],
                            uint16_t *protocol, vfrag_t **pdu);

/**
 *  @brief   Signal that a new BBFrame has been received
 *
 *  @param   deencap       The deencapsulation context structure
 */
void gse_deencap_new_bbframe(gse_deencap_t *deencap);

#endif
