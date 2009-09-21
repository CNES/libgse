/****************************************************************************/
/**
 *   @file          gse_encap.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: ENCAPSULATION
 *
 *   @brief         GSE encapsulation structure management
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "gse_encap.h"

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

status_t gse_encap_init(uint8_t qos_nbr, size_t fifo_size,
                        gse_encap_t **encap)
{
  status_t status = STATUS_OK;

  unsigned int i;

  if(qos_nbr == 0)
  {
    status = ERR_QOS_NBR_NULL;
    goto error;
  }
  if(fifo_size == 0)
  {
    status = ERR_FIFO_SIZE_NULL;
    goto error;
  }
  *encap = malloc(sizeof(gse_encap_t));
  if(*encap == NULL)
  {
    status = ERR_MALLOC_FAILED;
    goto error;
  }
  (*encap)->fifo =  malloc(sizeof(fifo_t) * qos_nbr);
  (*encap)->qos_nbr = qos_nbr;
  if((*encap)->fifo == NULL)
  {
    status = ERR_MALLOC_FAILED;
    goto free_encap;
  }

  //Initialize each FIFO in encapsulation context
  for(i = 0 ; i < qos_nbr ; i++)
  {
    status = gse_init_fifo(&(*encap)->fifo[i], fifo_size);
    if(status != STATUS_OK)
    {
      goto free_fifo;
    }
  }

  return status;
free_fifo:
  free((*encap)->fifo);
free_encap:
  free(*encap);
error:
  *encap = NULL;
  return status;
}

status_t gse_encap_release(gse_encap_t *encap)
{
  status_t status = STATUS_OK;
  status_t stat_mem = STATUS_OK;

  unsigned int i;

  if(encap == NULL)
  {
    status = ERR_NULL_PTR;
    goto error;
  }

  //release FIFO in each context
  for(i = 0 ; i < encap->qos_nbr ; i++)
  {
    status = gse_release_fifo(&encap->fifo[i]);
    if(status != STATUS_OK)
    {
      stat_mem = status;
    }
  }
  free(encap->fifo);
  free(encap);

  return stat_mem;
error:
  return status;
}

uint8_t gse_encap_get_qos_nbr(gse_encap_t *const encap)
{
  return (encap->qos_nbr);
}
