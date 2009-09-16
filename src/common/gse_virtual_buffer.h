/****************************************************************************/
/**
 *   @file          gse_virtual_buffer.h
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     VIVERIS TECHNOLOGIES
 *
 *          Module name: VIRTUAL BUFFER
 *
 *   @brief         Prototypes of elements used by the virtual buffer
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/


#ifndef GSE_VIRTUAL_BUFFER_H
#define GSE_VIRTUAL_BUFFER_H

#include "gse_common.h"

/****************************************************************************
 *
 *   STRUCTURES AND TYPES
 *
 ****************************************************************************/

/** Virtual buffer */
typedef struct
{
  unsigned char* start; /**< Point on the beginning of the virtual buffer */
  unsigned char* end;   /**< Point on the end of the virtual buffer */
  size_t length;        /**< Length of the virtual buffer */
  int vfrag_count;      /**< Number of virtual fragments
                             This value should not be greater than 2 */
} vbuf_t;

/** Virtual fragment: contain a part of a virtual buffer */
typedef struct
{
  vbuf_t *vbuf;         /**< The virtual buffer to which the fragment belongs */
  unsigned char* start; /**< Point on the beginning of the virtual fragment */
  unsigned char* end;   /**< Point on the end of the virtual fragment */
  size_t length;        /**< length of the virtual fragment */
} vfrag_t;

/****************************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 ****************************************************************************/

/**
 *  @brief   Create an empty virtual fragment
 *
 *  @param   vfrag     The virtual fragment
 *  @param   length    The maximum length of the fragment
 *                     If length = 0, default length is used
 *  @return  status code
 */
status_t gse_create_vfrag(vfrag_t **vfrag, size_t max_length);

/**
 *  @brief   Create a virtual fragment containing data
 *
 *  @param   vfrag       The virtual fragment
 *  @param   length      The maximum length of the fragment
 *                       If length = 0, default length is used
 *  @param   data        The data to write in the virtual fragment
 *  @param   data_length The length of the data
 *  @return  status code
 */
status_t gse_create_vfrag_with_data(vfrag_t **vfrag, size_t max_length,
                                    unsigned char const *data,
                                    size_t data_length);

/**
 *  @brief   Copy data in a virtual fragment
 *
 *  @param   vfrag       The virtual fragment
 *  @param   data        The data to write in the virtual fragment
 *  @param   data_length The length of the data
 *  @return  status code
 */
status_t gse_copy_data(vfrag_t *vfrag, unsigned char const* data,
                       size_t data_lenth);

/**
 *  @brief   Free a virtual fragment
 *
 *  The value is added to the pointer
 *
 *  @param   vfrag         The virtual fragment that will be destoyed
 *  @return  status code
 */
status_t gse_free_vfrag(vfrag_t *vfrag);

/**
 *  @brief   Create a virtual fragment from an existing one
 *
 *  @param   vfrag        The duplicated virtual fragment
 *  @param   father       The virtual fragment which will be duplicated
 *  @param   length       The length of the duplicated virtual fragment
 *  @return  status code
 */
status_t gse_duplicate_vfrag(vfrag_t **vfrag, vfrag_t *father, size_t length);

/**
 *  @brief   Shift the virtual fragment
 *
 *  @param   vfrag        The virtual fragment
 *  @param   start_shift  The shift value to apply on the beginning of the
 *                        fragment
 *  @param   end_shift    The shift value to apply on the end of the fragment
 *  @return  status code
 */
status_t gse_shift_vfrag(vfrag_t *vfrag, size_t start_shift, size_t end_shift);

/**
 *  @brief   Shift a pointer
 *
 *  Be careful, if you shift a start or end pointer from a virtual buffer
 *  (or fragment) this function does not modify length element !
 *
 *  @param   pointer      The pointer to shift
 *  @param   origin       The original adress
 *  @param   shift        The shift value to apply on the pointer
 */
void gse_shift_pointer(unsigned char **pointer, unsigned char *origin,
                       size_t shift);

/**
 *  @brief   Get the number of fragments in a virtual buffer related to a
 *           virtual fragment
 *
 *  @param   vfrag The virtual fragment depending on the virtual buffer
 *  @return  Number of fragments
 */
int gse_get_vfrag_nbr(vfrag_t *vfrag);

#endif
