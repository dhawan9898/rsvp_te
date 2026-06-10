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
struct rsvp_psb *rsvp_psb_find(struct rsvp_path_key *key);
struct rsvp_psb *rsvp_psb_create(struct rsvp_path_key *key);
void rsvp_psb_delete(struct rsvp_psb *psb);

/**
 * Find or create an RSB for a given key.
 */
struct rsvp_rsb *rsvp_rsb_find(struct rsvp_path_key *key);
struct rsvp_rsb *rsvp_rsb_create(struct rsvp_path_key *key);
void rsvp_rsb_delete(struct rsvp_rsb *rsb);

#endif /* RSVP_STATE_DB_H */
