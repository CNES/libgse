/****************************************************************************/
/**
 *   @file          gse_encap_fct.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: ENCAPSULATION
 *
 *   @brief         GSE encapsulation functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_ENCAP_FCT_H
#define GSE_ENCAP_FCT_H

#include "gse_common.h"
#include "gse_fifo.h"
#include "gse_encap.h"
#include "gse_encap_ctx.h"

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/**
 *  @brief   Receive a PDU which is stored in a virtual buffer
 *
 *  @param   pdu            The PDU to encapsulate
 *  @param   encap          The encapsulation context structure
 *  @param   label          The packet label
 *  @param   label_type     The label type field value
 *                          //'00' only implemented
 *  @param   protocol       The PDU protocol
 *  @param   qos            The QoS value of the PDU
 *  @return  status code
 */
status_t gse_encap_receive_pdu(vfrag_t *pdu, gse_encap_t *encap,
                               uint8_t label[6], uint8_t label_type,
                               uint16_t protocol, uint8_t qos);

/**
 *  @brief   Get a packet from the encapsulation context structure
 *
 *  @param   packet        The GSE packet
 *  @param   encap         The encapsulation context structure
 *  @param   length        Desired length for the packet
 *  @param   qos           QoS of the packet
 *  @return  status code
 */
status_t gse_encap_get_packet(vfrag_t **packet, gse_encap_t *encap,
                              size_t length, uint8_t qos);

/**
 *  @brief   Get a packet from the encapsulation context structure
 *
 *  This function does not use zero copy strategy
 *
 *  @param   packet        The GSE packet
 *  @param   encap         The encapsulation context structure related
 *  @param   length        Desired length for the packet
 *  @param   qos           QoS of the packet
 *  @return  status code
 */
status_t gse_encap_get_packet_copy(vfrag_t **packet, gse_encap_t *encap,
                                   size_t length, uint8_t qos);

#endif
