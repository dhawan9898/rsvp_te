/**
 * @file label_mgr.h
 * @brief MPLS Label Manager.
 * @details Provides functionality to allocate and free MPLS labels from a managed pool.
 */

#ifndef LABEL_MGR_H
#define LABEL_MGR_H

#include <stdint.h>

/**
 * @brief Initialize the label manager.
 * @details Sets the minimum and maximum label range available for allocation and resets the current allocation pointer.
 * @param [in] min The minimum label value to allocate.
 * @param [in] max The maximum label value to allocate.
 */
void label_mgr_init(uint32_t min, uint32_t max);

/**
 * @brief Allocate a label from the pool.
 * @details Retrieves the next available label from the managed pool.
 * @return The allocated label value, or 0 if no labels are available.
 */
uint32_t label_mgr_alloc(void);

/**
 * @brief Free a label back to the pool.
 * @details Marks the previously allocated label as free and available for reuse.
 * @param [in] label The label value to release.
 */
void label_mgr_free(uint32_t label);

#endif /* LABEL_MGR_H */
