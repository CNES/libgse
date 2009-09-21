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

status_t gse_create_vfrag(vfrag_t **vfrag, size_t max_length,
                          size_t head_offset, size_t trail_offset)
{
  status_t status = STATUS_OK;

  vbuf_t *vbuf;
  size_t length_buf = 0;

  /* The length of the buffer contining the fragment is the fragment length
     plus the offsets */
  length_buf = max_length + head_offset + trail_offset;
  if(length_buf == 0)
  {
    status = ERR_BUFF_LENGTH_NULL;
    goto error;
  }

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
  (*vfrag)->start = ((*vfrag)->vbuf->start + head_offset),
  (*vfrag)->length = max_length;
  (*vfrag)->end = (*vfrag)->start + (*vfrag)->length;
  assert(((*vfrag)->end) <= ((*vfrag)->vbuf->end));
  assert(((*vfrag)->end) >= ((*vfrag)->vbuf->start));
  vbuf->vfrag_count++;

  return status;
error:
  *vfrag = NULL;
  return status;
}

status_t gse_create_vfrag_with_data(vfrag_t **vfrag, size_t max_length,
                                    size_t head_offset, size_t trail_offset,
                                    unsigned char const* data,
                                    size_t data_length)
{
  status_t status = STATUS_OK;

  status = gse_create_vfrag(vfrag, max_length, head_offset, trail_offset);
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

  if(vfrag == NULL)
  {
    status = ERR_NULL_PTR;
    goto error;
  }

  //If there is more than one virtual fragment in buffer, don't overwrite data
  if(gse_get_vfrag_nbr(vfrag) > 1)
  {
    status = ERR_MULTIPLE_VBUF_ACCESS;
    goto error;
  }
  //Check if there is enough space in buffer
  if((vfrag->length) < data_length)
  {
    status = ERR_DATA_TOO_LONG;
    goto error;
  }
  //Copy data in vfrag and update vfrag structure
  memcpy(vfrag->start, data, data_length);
  vfrag->length = data_length;
  vfrag->end = vfrag->start + vfrag->length;
  assert((vfrag->end) <= (vfrag->vbuf->end));
  assert((vfrag->end) >= (vfrag->vbuf->start));

error:
  return status;
}

status_t gse_free_vfrag(vfrag_t *vfrag)
{
  status_t status = STATUS_OK;

  if(vfrag == NULL)
  {
    status = ERR_NULL_PTR;
    goto error;
  }

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

  if(father == NULL)
  {
    status = ERR_NULL_PTR;
    goto error;
  }

  //If the father is empty it is not duplicated */
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

  (*vfrag)->end = (*vfrag)->start + (*vfrag)->length;
  assert(((*vfrag)->end) <= ((*vfrag)->vbuf->end));
  assert(((*vfrag)->end) >= ((*vfrag)->vbuf->start));
  (*vfrag)->vbuf->vfrag_count++;

  return status;
error:
  *vfrag = NULL;
  return status;
}

status_t gse_shift_vfrag(vfrag_t *vfrag, size_t start_shift, size_t end_shift)
{
  status_t status = STATUS_OK;

  if(vfrag == NULL)
  {
    status = ERR_NULL_PTR;
    goto error;
  }

  //Check if pointer will not be outside buffer
  if(((vfrag->start + start_shift) < vfrag->vbuf->start) ||
     ((vfrag->start + start_shift) > vfrag->vbuf->end))
  {
    status = ERR_PTR_OUTSIDE_BUFF;
    goto error;
  }

  if(((vfrag->end + end_shift) < vfrag->vbuf->start) ||
     ((vfrag->end + end_shift) > vfrag->vbuf->end))
  {
    status = ERR_PTR_OUTSIDE_BUFF;
    goto error;
  }

  vfrag->start += start_shift;
  vfrag->end += end_shift;
  vfrag->length = vfrag->end - vfrag->start;

  if(vfrag->start > vfrag->end)
  {
    status = ERR_FRAG_PTRS;
    goto error;
  }

error:
  return status;
}

status_t gse_reset_vfrag(vfrag_t *vfrag, size_t *length,
                         size_t head_offset, size_t trail_offset)
{
  status_t status = STATUS_OK;

  if(vfrag == NULL)
  {
    status = ERR_NULL_PTR;
    goto error;
  }

  if(vfrag->vbuf->length < (head_offset + trail_offset))
  {
    status = ERR_OFFSET_TOO_HIGH;
    goto error;
  }
  vfrag->start = vfrag->vbuf->start + head_offset;
  vfrag->end = vfrag->vbuf->end - trail_offset;
  vfrag->length = vfrag->end - vfrag->start;
  assert((vfrag->end) <= (vfrag)->vbuf->end);
  assert((vfrag->end) >= (vfrag->vbuf->start));
  assert((vfrag->start) <= (vfrag)->vbuf->end);
  assert((vfrag->start) >= (vfrag->vbuf->start));

  *length = vfrag->length;

error:
  return status;
}

unsigned char *gse_get_vfrag_start(vfrag_t *vfrag)
{
  return(vfrag->start);
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

  (*vbuf)->end = (*vbuf)->start + (*vbuf)->length;
  (*vbuf)->vfrag_count = 0;

  return status;
free_vbuf:
  free(*vbuf);
  *vbuf = NULL;
error:
  return status;
}

status_t gse_free_vbuf(vbuf_t *vbuf)
{
  status_t status = STATUS_OK;

  assert(vbuf != NULL);

  //This function should only be called if there is no mor fragment in buffer
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

