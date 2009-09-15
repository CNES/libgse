/****************************************************************************/
/**
 *   @file          gse_virtual_buffer.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: VIRTUAL BUFFER
 *
 *   @brief         Virtual buffer and fragments mangement
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

#include "gse_virtual_buffer.h"

/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 ****************************************************************************/

/**
 *  @brief   Create a virtual buffer
 *
 *  @param   vbuf    The virtual buffer
 *  @param   length  The virtual buffer length, in bytes
 *  @return  status code
 */
static status_t gse_create_vbuf(vbuf_t **vbuf, size_t length);

/**
 *  @brief    Free a virtual buffer
 *
 *  @param   vbuf  The virtual buffer that will be destroyed
 *  @return  status code
 */
static status_t gse_free_vbuf(vbuf_t *vbuf);

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 ****************************************************************************/

status_t gse_create_vfrag(vfrag_t **vfrag, size_t max_length)
{
  status_t status = STATUS_OK;

  vbuf_t *vbuf;
  size_t length_buf = 0;

  /* Tyhe buffer shall be abole to contain each type of header and a CRC32 */
  length_buf = max_length + MAX_HEADER_LENGTH + CRC_LENGTH;

  status = gse_create_vbuf(&vbuf, length_buf);
  if(status != STATUS_OK)
  {
    goto error;
  }

  *vfrag = malloc(sizeof(vfrag_t));
  if(*vfrag == NULL)
  {
    status = ERR_MALLOC_FAILED;
    goto error;
  }
  (*vfrag)->vbuf = vbuf;
  (*vfrag)->start = ((*vfrag)->vbuf->start + MAX_HEADER_LENGTH),
  (*vfrag)->length = 0;
  status = gse_shift_pointer(&(*vfrag)->end, &(*vfrag)->start, 0);
  if(status != STATUS_OK)
  {
    goto free_vfrag;
  }
  vbuf->vfrag_count++;

  return status;
free_vfrag:
  free(*vfrag);
  *vfrag = NULL;
error:
  return status;
}

status_t gse_create_vfrag_with_data(vfrag_t **vfrag, size_t max_length,
                                    unsigned char const* data,
                                    size_t data_length)
{
  status_t status = STATUS_OK;

  status = gse_create_vfrag(vfrag, max_length);
  if(status != STATUS_OK)
  {
    goto error;
  }

  status = gse_copy_data((*vfrag), data, data_length);
  if(status != STATUS_OK)
  {
    goto free_vfrag;
  }

  return status;
free_vfrag:
  gse_free_vfrag(*vfrag);
  *vfrag = NULL;
error:
  return status;
}

status_t gse_copy_data(vfrag_t *vfrag, unsigned char const* data,
                       size_t data_length)
{
  status_t status = STATUS_OK;

  /* If there is more than one virtual fragment in buffer, don't overwrite data */
  if(gse_get_vfrag_nbr(vfrag) > 1)
  {
    status = ERR_MULTIPLE_VBUF_ACCESS;
    goto error;
  }
  /* Check if there is enough space in buffer */
  if((vfrag->vbuf->length - (MAX_HEADER_LENGTH + CRC_LENGTH)) < data_length)
  {
    status = ERR_DATA_TOO_LONG;
    goto error;
  }
  /* Copy data in vfrag and update vfrag structure */
  vfrag->start = memcpy((vfrag->vbuf->start + MAX_HEADER_LENGTH),
                        data, data_length);
  vfrag->length = data_length;
  status = gse_shift_pointer(&vfrag->end, &vfrag->start, vfrag->length);
  if(status != STATUS_OK)
  {
    goto error;
  }

  assert((vfrag->end) <= (vfrag->vbuf->end));

error:
  return status;
}

status_t gse_free_vfrag(vfrag_t *vfrag)
{
  status_t status = STATUS_OK;

  if(gse_get_vfrag_nbr(vfrag) <= 0)
  {
    status = ERR_FRAG_NBR;
    goto error;
  }

  vfrag->vbuf->vfrag_count--;

  if(gse_get_vfrag_nbr(vfrag) == 0)
  {
    status = gse_free_vbuf(vfrag->vbuf);
    if(status != STATUS_OK)
    {
      goto free_vfrag;
    }
  }

free_vfrag:
  free(vfrag);
error:
  return status;
}

status_t gse_duplicate_vfrag(vfrag_t **vfrag, vfrag_t *father, size_t length)
{
  status_t status = STATUS_OK;

  /* If the father does not contain data it is not duplicated */
  if(father->length == 0)
  {
    status = EMPTY_FRAG;
    goto error;
  }

  /* There can be only two access to virtual buffer to avoid multiple access
   * from duplicated virtual fragments */
  if(gse_get_vfrag_nbr(father) >= 2)
  {
    status = ERR_FRAG_NBR;
    goto error;
  }

  *vfrag = malloc(sizeof(vfrag_t));
  if(*vfrag == NULL)
  {
    status = ERR_MALLOC_FAILED;
    goto error;
  }

  (*vfrag)->vbuf = father->vbuf;
  (*vfrag)->start = father->start;
  (*vfrag)->length = MIN(length, father->length);
  status = gse_shift_pointer(&(*vfrag)->end, &(*vfrag)->start, (*vfrag)->length);
  if(status != STATUS_OK)
  {
    goto free_vfrag;
  }

  assert(((*vfrag)->end) <= ((*vfrag)->vbuf->end));
  (*vfrag)->vbuf->vfrag_count++;

  return status;
free_vfrag:
  free(*vfrag);
error:
  *vfrag = NULL;
  return status;
}

void gse_shift_vfrag(vfrag_t *vfrag, size_t start_shift, size_t end_shift)
{
  vfrag->start += start_shift;
  vfrag->end += end_shift;
  vfrag->length = vfrag->end - vfrag->start;
}

status_t gse_shift_pointer(unsigned char **pointer, unsigned char **origin, size_t shift)
{
  status_t status = STATUS_OK;

  *pointer = *origin + shift;

  return status;
}

int gse_get_vfrag_nbr(vfrag_t *vfrag)
{
  return(vfrag->vbuf->vfrag_count);
}

/****************************************************************************
 *
 *   PRIVATE FUNCTIONS
 *
 ****************************************************************************/

status_t gse_create_vbuf(vbuf_t **vbuf, size_t length)
{
  status_t status = STATUS_OK;

  *vbuf = malloc(sizeof(vbuf_t));
  if(*vbuf == NULL)
  {
    status = ERR_MALLOC_FAILED;
    goto error;
  }

  (*vbuf)->start = malloc(sizeof(unsigned char) * length);
  if((*vbuf)->start == NULL)
  {
    status = ERR_MALLOC_FAILED;
    goto free_vbuf;
  }
  (*vbuf)->length = length;
  status = gse_shift_pointer(&(*vbuf)->end, &(*vbuf)->start, (*vbuf)->length);
  if(status != STATUS_OK)
  {
    goto free_vbuf_start;
  }
  (*vbuf)->vfrag_count = 0;

  return status;
free_vbuf_start:
  free((*vbuf)->start);
free_vbuf:
  free(*vbuf);
  *vbuf = NULL;
error:
  return status;
}

status_t gse_free_vbuf(vbuf_t *vbuf)
{
  status_t status = STATUS_OK;

  if(vbuf->vfrag_count != 0)
  {
    status = ERR_FRAG_NBR;
    goto error;
  }
  free(vbuf->start);
  free(vbuf);

error:
  return status;
}

