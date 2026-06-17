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
 * @brief Find a Path State Block (PSB) by tunnel ID.
 * @details Linearly searches the hash table for a PSB matching the given tunnel ID.
 * @param [in] tunnel_id The tunnel identifier.
 * @return Pointer to the matching PSB, or NULL if not found.
 */
struct rsvp_psb* rsvp_psb_find_by_id(uint16_t tunnel_id);

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
