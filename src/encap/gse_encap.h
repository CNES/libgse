/****************************************************************************/
/**
 *   @file          gse_encap.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: ENCAPSULATION CONTEXT
 *
 *   @brief         Encapsulation structure definition
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_ENCAP_H
#define GSE_ENCAP_H

#include "gse_common.h"
#include "gse_fifo.h"

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/**Encapsulation structure*/
typedef struct
{
   fifo_t *fifo;     /**< Table of FIFOs */
   uint8_t qos_nbr;  /**<Number of QoS values */
} gse_encap_t;

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/**
 *  @brief   Initialize the encapsulation structure
 *
 *  The function return the encapsulation structure which is a fifo table
 *
 *  @param   qos_nbr        number of qos values
 *  @param   fifo_size      size of FIFOs
 *  @param   encap          Encapsulation structure (table of FIFOs associated
 *                          to a QoS value)
 *  @return  status code
 */
status_t gse_encap_init(uint8_t qos_nbr, size_t fifo_size,
                        gse_encap_t **encap);

/**
 *  @brief   Release the encapsulation structure
 *
 *  @param   encap   Encapsulation structure
 *  @return  status code
 */
status_t gse_encap_release(gse_encap_t *encap);

/**
 *  @brief   Get the QoS number
 *
 *  @param   encap   Encapsulation structure
 *  @return  QoS number
 */
uint8_t gse_encap_get_qos_nbr(gse_encap_t *const encap);

#endif
