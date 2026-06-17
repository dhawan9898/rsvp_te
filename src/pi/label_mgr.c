/**
 * @file label_mgr.c
 * @brief MPLS Label Manager Implementation.
 * @details Implements the allocation and release of MPLS labels using a bitmap allocator.
 */

#include "label_mgr.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static uint32_t label_min = 1000;
static uint32_t label_max = 2000;
static uint32_t label_next = 1000;
static uint8_t* label_bitmap = NULL;
static size_t label_bitmap_size = 0;

/**
 * @brief Check if a label is within the configured allocation range.
 * @details Validates if the given label falls within the initialized bounds [label_min, label_max].
 * @param [in] label The label to check.
 * @return true if the label is in range, false otherwise.
 */
static inline bool label_in_range(uint32_t label) {
    return label >= label_min && label <= label_max;
}

/**
 * @brief Check if a specific label is currently allocated.
 * @details Reads the corresponding bit in the label bitmap.
 * @param [in] label The label to check.
 * @return true if the label is allocated, false otherwise.
 */
static inline bool label_is_allocated(uint32_t label) {
    if (!label_in_range(label) || label_bitmap == NULL) {
        return false;
    }
    uint32_t idx = label - label_min;
    return (label_bitmap[idx / 8] >> (idx % 8)) & 1;
}

/**
 * @brief Mark a specific label as allocated.
 * @details Sets the corresponding bit in the label bitmap to 1.
 * @param [in] label The label to mark as allocated.
 */
static inline void label_set_allocated(uint32_t label) {
    if (!label_in_range(label) || label_bitmap == NULL) return;
    uint32_t idx = label - label_min;
    label_bitmap[idx / 8] |= (1 << (idx % 8));
}

/**
 * @brief Mark a specific label as free.
 * @details Clears the corresponding bit in the label bitmap to 0.
 * @param [in] label The label to free.
 */
static inline void label_clear_allocated(uint32_t label) {
    if (!label_in_range(label) || label_bitmap == NULL) return;
    uint32_t idx = label - label_min;
    label_bitmap[idx / 8] &= ~(1 << (idx % 8));
}

void label_mgr_init(uint32_t min, uint32_t max) {
    /* If a bitmap already exists, free it to avoid memory leaks on re-init */
    if (label_bitmap != NULL) {
        free(label_bitmap);
    }
    label_min = min;
    label_max = max;
    label_next = min;
    
    /* Calculate the number of bytes required for the bitmap */
    size_t count = (size_t)max - (size_t)min + 1;
    label_bitmap_size = (count + 7) / 8;
    label_bitmap = calloc(label_bitmap_size, 1);
}

uint32_t label_mgr_alloc(void) {
    if (label_bitmap == NULL || label_min > label_max) {
        return 0;
    }

    size_t range = (size_t)label_max - (size_t)label_min + 1;
    
    /* Search for the next free label starting from label_next, wrapping around if necessary */
    for (size_t offset = 0; offset < range; offset++) {
        uint32_t label = label_next + offset;
        if (label > label_max) {
            label = label_min + (label - label_max - 1);
        }
        if (!label_is_allocated(label)) {
            /* Found an unallocated label, mark it and update label_next */
            label_set_allocated(label);
            label_next = label + 1;
            if (label_next > label_max) {
                label_next = label_min;
            }
            return label;
        }
    }

    return 0;
}

void label_mgr_free(uint32_t label) {
    if (!label_in_range(label)) {
        return;
    }
    if (!label_is_allocated(label)) {
        return;
    }
    
    /* Clear the allocation bit and potentially reset label_next to prioritize lower labels */
    label_clear_allocated(label);
    if (label < label_next) {
        label_next = label;
    }
}
