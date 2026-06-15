#ifndef RSVP_STATE_DB_H
#define RSVP_STATE_DB_H

#include "rsvp_state.h"

/**
 * Initialize the state database.
 */
void rsvp_state_db_init(void);

/**
 * Find or create a PSB for a given key.
 */
struct rsvp_psb* rsvp_psb_find(struct rsvp_path_key* key);
struct rsvp_psb* rsvp_psb_create(struct rsvp_path_key* key);
struct rsvp_psb* rsvp_psb_find_by_id(uint16_t tunnel_id);
void rsvp_psb_delete(struct rsvp_psb* psb);

/**
 * Find or create an RSB for a given key.
 */
struct rsvp_rsb* rsvp_rsb_find(struct rsvp_path_key* key);
struct rsvp_rsb* rsvp_rsb_create(struct rsvp_path_key* key);
void rsvp_rsb_delete(struct rsvp_rsb* rsb);

void rsvp_psb_dump(void);
void rsvp_rsb_dump(void);

#endif /* RSVP_STATE_DB_H */
