/*
 *
 * This piece of software is an implementation of the Generic Stream
 * Encapsulation (GSE) standard defined by ETSI for Linux (or other
 * Unix-compatible OS). The library may be used to add GSE
 * encapsulation/de-encapsulation capabilities to an application.
 *
 *
 * Copyright © 2016 TAS
 *
 *
 * This file is part of the GSE library.
 *
 *
 * The GSE library is free software : you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

/****************************************************************************/
/**
 *   @file          test_vfrag_robust.c
 *
 *          Project:     GSE LIBRARY
 *
 *          Company:     THALES ALENIA SPACE
 *
 *          Module name: COMMON
 *
 *   @brief         Virtual fragment robustness tests
 *
 *   @author        Julien BERNARD / Viveris Technologies
 *
 */
/****************************************************************************/

/****************************************************************************
 *
 *   INCLUDES
 *
 *****************************************************************************/

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <assert.h>

/* GSE includes */
#include "virtual_fragment.h"

/****************************************************************************
 *
 *   MACROS AND CONSTANTS
 *
 *****************************************************************************/

/** Length of data to write in the virtual fragment */
#define DATA_LENGTH 64
/** Length of data to write in the virtual fragment with overflow */
#define BAD_DATA_LENGTH 128
/** Length of the virtual fragment */
#define VFRAG_LENGTH 64
/** Length of the duplicated virtual fragment */
#define DUP_LENGTH 32

/* DEBUG macro */
#define DEBUG(verbose, format, ...) \
  do { \
    if(verbose) \
      printf(format, ##__VA_ARGS__); \
  } while(0)

/****************************************************************************
 *
 *   PROTOTYPES OF PRIVATE FUNCTIONS
 *
 *****************************************************************************/

static int test_vfrag_robust(int verbose);

/****************************************************************************
 *
 *   PUBLIC FUNCTIONS
 *
 *****************************************************************************/

/**
 * @brief Main function for the GSE virtual buffer robustness test program
 *
 * @param argc  the number of program arguments
 * @param argv  the program arguments
 * @return      the unix return code:
 *               \li 0 in case of success,
 *               \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
  int res = 1;
  int verbose = 0;

  if(argc > 2 || argc < 1)
  {
    printf("USAGE : test_vfrag_robust [verbose]\n");
  }
  else 
  {
    if(argc == 2)
    {
      if(!strcmp(argv[1], "verbose"))
      {
        verbose = 1;
      }
      else
      {
        printf("USAGE : test_vfrag_robust [verbose]\n");
        goto quit;
      }
    }
    res = test_vfrag_robust(verbose);
  }

quit:
  return res;
}

/****************************************************************************
 *
 *   PRIVATE FUNCTIONS
 *
 *****************************************************************************/

/**
 * @brief Test the virtual buffer creation, duplication and release
 *
 * @param   verbose  Print debug if verbose is 1
 * @return           0 on sucess, 1 on failure
 */
static int test_vfrag_robust(int verbose)
{
  int is_failure = 1;
  unsigned char *data;
  gse_vfrag_t *vfrag;
  gse_vfrag_t *dup_vfrag;
  gse_vfrag_t *dup_vfrag_2;
  gse_status_t status;
  unsigned int i;

  data = malloc(sizeof(unsigned char) * BAD_DATA_LENGTH);
  if(data == NULL)
  {
    DEBUG(verbose, "Malloc failed for data\n");
    goto quit;
  }

  /* Create fake data for the test */
  for(i = 0 ; i < BAD_DATA_LENGTH ; i++)
  {
    data[i] = i;
  }

  /****************************** TEST_ROBUST_1 ******************************/
  assert(BAD_DATA_LENGTH > DATA_LENGTH);

  /* Create a fragment with too much data */
  DEBUG(verbose, "\nCreate a fragment with max_length < data_length...\n");
  status = gse_create_vfrag_with_data(&vfrag, VFRAG_LENGTH, 0, 0, data,
                                      BAD_DATA_LENGTH);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when creating fragment (%s)\n", status,
          gse_get_status(status));
    if(status != GSE_STATUS_DATA_TOO_LONG)
    {
      goto failure;
    }
  }
  else
  {
    DEBUG(verbose, "ERROR: fragment was created with to much data...\n");
    goto failure;
  }

  DEBUG(verbose, "\n***********************************************************\n\n");

  /****************************** TEST_ROBUST_2 ******************************/

  /* Create a fragment */
  DEBUG(verbose, "Create a correct fragment and duplicate it\n");
  status = gse_create_vfrag_with_data(&vfrag, VFRAG_LENGTH, 0, 0, data,
                                      DATA_LENGTH);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when creating fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  /* Duplicate the fragment */
  status = gse_duplicate_vfrag(&dup_vfrag, vfrag, DUP_LENGTH);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when duplicating fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  DEBUG(verbose, "\n***********************************************************\n\n");

  DEBUG(verbose, "Move the fragments pointers outside the memory\n\tStart pointer:\n");
  status = gse_shift_vfrag(dup_vfrag, DATA_LENGTH + 5, 0);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when moving start of fragment (%s)\n", status,
          gse_get_status(status));
    if(status != GSE_STATUS_PTR_OUTSIDE_BUFF)
    {
      goto failure;
    }
  }
  else
  {
     DEBUG(verbose, "ERROR: Pointer shifted outside buffer...\n");
     goto failure;
  }
  DEBUG(verbose, "\tEnd pointer:\n");
  status = gse_shift_vfrag(dup_vfrag, 0, DATA_LENGTH + 5);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when moving end of fragment (%s)\n", status,
          gse_get_status(status));
    if(status != GSE_STATUS_PTR_OUTSIDE_BUFF)
    {
      goto failure;
    }
  }
  else
  {
     DEBUG(verbose, "ERROR: Pointer shifted outside buffer...\n");
     goto failure;
  }
  DEBUG(verbose, "Move the start pointer behind the end pointer\n");
  status = gse_shift_vfrag(dup_vfrag, DUP_LENGTH + 1, 0);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when moving start of fragment behind end of it (%s)\n",
          status, gse_get_status(status));
    if(status != GSE_STATUS_FRAG_PTRS)
    {
      goto failure;
    }
  }
  else
  {
     DEBUG(verbose, "ERROR: Start pointer shifted behind end pointer...\n");
     goto failure;
  }

  /****************************** TEST_ROBUST_3 ******************************/
  assert(vfrag->vbuf->vfrag_count > 1);

  DEBUG(verbose, "\n***********************************************************\n\n");

  /* Create new data */
  for(i = 0 ; i < DATA_LENGTH ; i++)
  {
    data[i] = DATA_LENGTH - i;
  }

  DEBUG(verbose, "Copy data in fragment while buffer contains %d fragments...\n",
        vfrag->vbuf->vfrag_count);
  /* Copy the data */
  status = gse_copy_data(vfrag, data, DATA_LENGTH);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when copying data in fragment (%s)\n", status,
          gse_get_status(status));
    if(status != GSE_STATUS_MULTIPLE_VBUF_ACCESS)
    {
      goto failure;
    }
  }

  DEBUG(verbose, "\n***********************************************************\n\n");

  /****************************** TEST_ROBUST_4 ******************************/
  assert(vfrag->vbuf->vfrag_count >= 2);

  DEBUG(verbose, "Duplicate fragment while buffer contains %d fragments...\n",
          vfrag->vbuf->vfrag_count);
  /* Duplicate the fragment */
  status = gse_duplicate_vfrag(&dup_vfrag_2, vfrag, DUP_LENGTH);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when duplicating fragment (%s)\n", status,
          gse_get_status(status));
    if(status != GSE_STATUS_FRAG_NBR)
    {
      goto failure;
    }
  }

  DEBUG(verbose, "\n***********************************************************\n\n");

  /* free the virtual fragment */
  status = gse_free_vfrag(&vfrag);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying the virtual fragment (%s)\n", status,
        gse_get_status(status));
    goto failure;
  }

  /* free the duplicated fragment */
  status = gse_free_vfrag(&dup_vfrag);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying the dumplicated fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }
  DEBUG(verbose, "The fragments and the buffer are destroyed\n");

  DEBUG(verbose, "\n***********************************************************\n\n");

  /****************************** TEST_ROBUST_5 ******************************/

  /* Create a fragment with data size 0 */
  DEBUG(verbose, "Create a fragment with data size 0 and duplicate it...\n");
  status = gse_create_vfrag_with_data(&vfrag, VFRAG_LENGTH, 10, 10, data, 0);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when creating fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }

  /* Duplicate the fragment */
  status = gse_duplicate_vfrag(&dup_vfrag, vfrag, DUP_LENGTH);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when duplicating fragment (%s)\n", status,
          gse_get_status(status));
    if(status != GSE_STATUS_EMPTY_FRAG)
    {
      goto failure;
    }
  }
  else
  {
    DEBUG(verbose, "ERROR: Fragment duplicated although it was empty...\n");
    goto failure;
  }

  status = gse_free_vfrag(&vfrag);
  if(status != GSE_STATUS_OK)
  {
    DEBUG(verbose, "Error %#.4x when destroying the virtual fragment (%s)\n", status,
          gse_get_status(status));
    goto failure;
  }
  DEBUG(verbose, "\nThe fragment and the buffer are destroyed\n");

  is_failure = 0;

failure:
  free(data);
quit:
  return is_failure;
}
