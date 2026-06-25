/**
 * @file rsvp_state_db.h
 * @brief RSVP State Database.
 * @details Provides an in-memory storage mechanism (hash tables) for tracking Path State Blocks (PSB) and Reservation State Blocks (RSB).
 */

#ifndef RSVP_STATE_DB_H
#define RSVP_STATE_DB_H

#include "rsvp_state.h"

/**
 * @brief Initialize the state database.
 * @details Clears the hash tables used for storing PSBs and RSBs.
 */
void rsvp_state_db_init(void);

/**
 * @brief Cleanup the state database.
 * @details Frees all allocated memory in the state blocks.
 */
void rsvp_state_db_cleanup(void);

/**
 * @brief Find a Path State Block (PSB) by its key.
 * @param [in] key Pointer to the path key.
 * @return Pointer to the matching PSB, or NULL if not found.
 */
struct rsvp_psb* rsvp_psb_find(struct rsvp_path_key* key);

/**
 * @brief Create a new Path State Block (PSB).
 * @details Allocates memory for a new PSB, initializes it with the given key, and inserts it into the database.
 * @param [in] key Pointer to the path key.
 * @return Pointer to the newly created PSB, or NULL on memory allocation failure.
 */
struct rsvp_psb* rsvp_psb_create(struct rsvp_path_key* key);

/**
 * @brief Find a Path State Block (PSB) by tunnel ID and LSP ID.
 * @details Linearly searches the hash table for a PSB matching the given IDs.
 * @param [in] tunnel_id The tunnel identifier.
 * @param [in] lsp_id The LSP identifier.
 * @return Pointer to the matching PSB, or NULL if not found.
 */
struct rsvp_psb* rsvp_psb_find_by_id(uint16_t tunnel_id, uint16_t lsp_id);

/**
 * @brief Delete a Path State Block (PSB).
 * @details Removes the PSB from the hash table and frees its allocated memory.
 * @param [in] psb Pointer to the PSB to delete.
 */
void rsvp_psb_delete(struct rsvp_psb* psb);

/**
 * @brief Find a Reservation State Block (RSB) by its key.
 * @param [in] key Pointer to the path key.
 * @return Pointer to the matching RSB, or NULL if not found.
 */
struct rsvp_rsb* rsvp_rsb_find(struct rsvp_path_key* key);

/**
 * @brief Create a new Reservation State Block (RSB).
 * @details Allocates memory for a new RSB, initializes it with the given key, and inserts it into the database.
 * @param [in] key Pointer to the path key.
 * @return Pointer to the newly created RSB, or NULL on memory allocation failure.
 */
struct rsvp_rsb* rsvp_rsb_create(struct rsvp_path_key* key);

/**
 * @brief Delete a Reservation State Block (RSB).
 * @details Removes the RSB from the hash table and frees its allocated memory.
 * @param [in] rsb Pointer to the RSB to delete.
 */
void rsvp_rsb_delete(struct rsvp_rsb* rsb);

/**
 * @brief Find a Blockade State Block (BSB) by its key.
 * @param [in] key Pointer to the path key.
 * @return Pointer to the matching BSB, or NULL if not found.
 */
struct rsvp_bsb* rsvp_bsb_find(struct rsvp_path_key* key);

/**
 * @brief Create a new Blockade State Block (BSB).
 * @details Allocates memory for a new BSB, initializes it with the given key, and inserts it into the database.
 * @param [in] key Pointer to the path key.
 * @return Pointer to the newly created BSB, or NULL on memory allocation failure.
 */
struct rsvp_bsb* rsvp_bsb_create(struct rsvp_path_key* key);

/**
 * @brief Delete a Blockade State Block (BSB).
 * @details Removes the BSB from the hash table and frees its allocated memory.
 * @param [in] bsb Pointer to the BSB to delete.
 */
void rsvp_bsb_delete(struct rsvp_bsb* bsb);

/**
 * @brief Return the first PSB in a given hash bucket.
 * @details Used by the FRR trigger and graceful shutdown to iterate over all
 *          active PSBs.  The hash table has 1024 buckets (indices 0–1023).
 *          Callers must save psb->next_hash before modifying the list.
 * @param [in] bucket  Hash bucket index (0 to 1023).
 * @return Pointer to the first PSB in the bucket, or NULL if empty.
 */
struct rsvp_psb* rsvp_psb_find_by_bucket(int bucket);

/**
 * @brief Dump all Path State Blocks (PSBs) to standard output.
 * @details Useful for debugging and CLI 'show' commands.
 */
void rsvp_psb_dump(void);

/**
 * @brief Dump all Reservation State Blocks (RSBs) to standard output.
 * @details Useful for debugging and CLI 'show' commands.
 */
void rsvp_rsb_dump(void);

#endif /* RSVP_STATE_DB_H */
