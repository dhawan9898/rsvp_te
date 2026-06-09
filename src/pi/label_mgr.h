#ifndef LABEL_MGR_H
#define LABEL_MGR_H

#include <stdint.h>

/**
 * Initialize the label manager.
 */
void label_mgr_init(uint32_t min, uint32_t max);

/**
 * Allocate a label from the pool.
 * Returns 0 if no labels available.
 */
uint32_t label_mgr_alloc(void);

/**
 * Free a label back to the pool.
 */
void label_mgr_free(uint32_t label);

#endif /* LABEL_MGR_H */
