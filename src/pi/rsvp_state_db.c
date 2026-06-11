#include "rsvp_state_db.h"

#include <stdlib.h>
#include <string.h>

#define HASH_SIZE 1024

static struct rsvp_psb* psb_table[HASH_SIZE];
static struct rsvp_rsb* rsb_table[HASH_SIZE];

static uint32_t rsvp_key_hash(struct rsvp_path_key* key) {
    uint32_t hash = 0;
    uint8_t* p = (uint8_t*)key;
    for (size_t i = 0; i < sizeof(struct rsvp_path_key); i++) {
        hash = hash * 31 + p[i];
    }
    return hash % HASH_SIZE;
}

void rsvp_state_db_init(void) {
    memset(psb_table, 0, sizeof(psb_table));
    memset(rsb_table, 0, sizeof(rsb_table));
}

struct rsvp_psb* rsvp_psb_find(struct rsvp_path_key* key) {
    uint32_t h = rsvp_key_hash(key);
    struct rsvp_psb* psb = psb_table[h];
    while (psb) {
        if (memcmp(&psb->key, key, sizeof(struct rsvp_path_key)) == 0) {
            return psb;
        }
        psb = psb->next_hash;
    }
    return NULL;
}

struct rsvp_psb* rsvp_psb_create(struct rsvp_path_key* key) {
    struct rsvp_psb* psb = calloc(1, sizeof(struct rsvp_psb));
    if (!psb) return NULL;

    memcpy(&psb->key, key, sizeof(struct rsvp_path_key));
    uint32_t h = rsvp_key_hash(key);
    psb->next_hash = psb_table[h];
    psb_table[h] = psb;

    return psb;
}

void rsvp_psb_delete(struct rsvp_psb* psb) {
    uint32_t h = rsvp_key_hash(&psb->key);
    struct rsvp_psb** prev = &psb_table[h];
    struct rsvp_psb* curr = psb_table[h];

    while (curr) {
        if (curr == psb) {
            *prev = curr->next_hash;
            if (psb->lsp_name) free(psb->lsp_name);
            free(psb);
            return;
        }
        prev = &curr->next_hash;
        curr = curr->next_hash;
    }
}

struct rsvp_rsb* rsvp_rsb_find(struct rsvp_path_key* key) {
    uint32_t h = rsvp_key_hash(key);
    struct rsvp_rsb* rsb = rsb_table[h];
    while (rsb) {
        if (memcmp(&rsb->key, key, sizeof(struct rsvp_path_key)) == 0) {
            return rsb;
        }
        rsb = rsb->next_hash;
    }
    return NULL;
}

struct rsvp_rsb* rsvp_rsb_create(struct rsvp_path_key* key) {
    struct rsvp_rsb* rsb = calloc(1, sizeof(struct rsvp_rsb));
    if (!rsb) return NULL;

    memcpy(&rsb->key, key, sizeof(struct rsvp_path_key));
    uint32_t h = rsvp_key_hash(key);
    rsb->next_hash = rsb_table[h];
    rsb_table[h] = rsb;

    return rsb;
}

void rsvp_rsb_delete(struct rsvp_rsb* rsb) {
    uint32_t h = rsvp_key_hash(&rsb->key);
    struct rsvp_rsb** prev = &rsb_table[h];
    struct rsvp_rsb* curr = rsb_table[h];

    while (curr) {
        if (curr == rsb) {
            *prev = curr->next_hash;
            free(rsb);
            return;
        }
        prev = &curr->next_hash;
        curr = curr->next_hash;
    }
}
