/****************************************************************************/
/**
 *   @file          gse_encap_ctx.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
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

#include "gse_common.h"
#include "gse_virtual_buffer.h"

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** Encapsulation context */
typedef struct
{
  uint8_t qos;            /**< QoS value of the context : used as FragID value */
  vfrag_t *vfrag;         /**< Virtual fragment containing the PDU */
  uint16_t total_length;  /**< Total length field value */
  uint16_t protocol_type;  /**< Protocol type field value */
  uint8_t label_type;     /**< Label type field value */
  gse_label_t label;      /**< Label field value */
  unsigned int frag_nbr;  /**< Number of fragment */
} gse_encap_ctx_t;

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

/**
 *  @brief   Get the number of created fragments
 *
 *  This function is used mainly to know if a fragment is the first one or not
 *
 *  @param   encap_ctx    Teh encapsulation context
 *  @return  Fragment number
 */
unsigned int gse_get_frag_number(gse_encap_ctx_t *const encap_ctx);

#endif
