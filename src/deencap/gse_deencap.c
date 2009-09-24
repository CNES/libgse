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
  //Create as deencapsulation contexts as QoS values
  (*deencap)->deencap_ctx = malloc(sizeof(gse_deencap_ctx_t) * qos_nbr);
  if((*deencap)->deencap_ctx == NULL)
  {
    status = ERR_MALLOC_FAILED;
    goto free_deencap;
  }
  //Each value is set to 0 because on release, virtual fragments contained by
  //context are destroyed only if they exist
  memset((*deencap)->deencap_ctx, 0, sizeof(gse_deencap_ctx_t) * qos_nbr);
  (*deencap)->qos_nbr = qos_nbr;

  //Initialize offsets
  gse_deencap_set_offsets(*deencap, 0, 0);

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

  if(deencap == NULL)
  {
    status = ERR_NULL_PTR;
    goto error;
  }

  //Release each context
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
error:
  return status;
}

status_t gse_deencap_set_offsets(gse_deencap_t *deencap, size_t head_offset,
                             size_t trail_offset)
{
  if(deencap == NULL)
  {
    return ERR_NULL_PTR;
  }
  deencap->head_offset = head_offset;
  deencap->trail_offset = trail_offset;
  return STATUS_OK;
}

uint8_t gse_deencap_get_qos_nbr(gse_deencap_t *deencap)
{
  if(deencap == NULL)
  {
    return -1;
  }
  return (deencap->qos_nbr);
}
