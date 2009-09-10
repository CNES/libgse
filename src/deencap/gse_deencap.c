/****************************************************************************/
/**
 *   @file          gse_deencap.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: DEENCAPSULATION
 *
 *   @brief         GSE deencapsulation structure management
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "gse_deencap.h"

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

status_t gse_deencap_init(uint8_t qos_nbr, gse_deencap_t **deencap)
{
  status_t status = STATUS_OK;

  *deencap = malloc(sizeof(gse_deencap_t));
  if(*deencap == NULL)
  {
    status = ERR_MALLOC_FAILED;
    goto error;
  }
  (*deencap)->deencap_ctx = malloc(sizeof(gse_deencap_ctx_t) * qos_nbr);
  if((*deencap)->deencap_ctx == NULL)
  {
    status = ERR_MALLOC_FAILED;
    goto free_deencap;
  }
  //Each value is set to 0 because on release, virtual fragments conatained by
  //context are destroyed only if they exist
  memset((*deencap)->deencap_ctx, 0, sizeof(gse_deencap_ctx_t) * qos_nbr);
  (*deencap)->qos_nbr = qos_nbr;

  return status;
free_deencap:
  free(*deencap);
  *deencap = NULL;
error:
  return status;
}

status_t gse_deencap_release(gse_deencap_t *deencap)
{
  status_t status = STATUS_OK;
  status_t stat_mem = STATUS_OK;

  unsigned int i;

  for(i = 0; i < gse_deencap_get_qos_nbr(deencap) ; i++)
  {
    if(deencap->deencap_ctx[i].vfrag != NULL)
    {
      status = gse_free_vfrag(deencap->deencap_ctx[i].vfrag);
      if(status != STATUS_OK)
      {
        stat_mem = status;
      }
    }
  }
  free(deencap->deencap_ctx);
  free(deencap);

  return stat_mem;
}

uint8_t gse_deencap_get_qos_nbr(gse_deencap_t *deencap)
{
  return (deencap->qos_nbr);
}
