/****************************************************************************/
/**
 *   @file          gse_encap_ctx.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: ENCAPSULATION CONTEXT
 *
 *   @brief         Encapsulation context functions
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "gse_encap_ctx.h"

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

unsigned int gse_get_frag_number(gse_encap_ctx_t *const encap_ctx)
{
  return (encap_ctx->frag_nbr);
}

