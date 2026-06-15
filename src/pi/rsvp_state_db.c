#include "rsvp_state_db.h"
#include "common/rsvp_log.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define HASH_SIZE 1024

static struct rsvp_psb* psb_table[HASH_SIZE];
static struct rsvp_rsb* rsb_table[HASH_SIZE];

static uint32_t rsvp_key_hash(struct rsvp_path_key* key) {
    uint32_t hash = 0;
    hash = hash * 31 + key->session.dest_addr.s_addr;
    hash = hash * 31 + key->session.tunnel_id;
    hash = hash * 31 + key->session.extended_tunnel_id.s_addr;
    hash = hash * 31 + key->sender.source_addr.s_addr;
    hash = hash * 31 + key->sender.lsp_id;
    return hash % HASH_SIZE;
}

void rsvp_state_db_init(void) {
    LOG_INFO("Initializing RSVP State Database");
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
    char dest_buf[INET_ADDRSTRLEN];
    char src_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key->session.dest_addr, dest_buf, sizeof(dest_buf));
    inet_ntop(AF_INET, &key->sender.source_addr, src_buf, sizeof(src_buf));
    
    LOG_DEBUG("Creating PSB: Tunnel ID %d, Dest %s, Source %s", 
              ntohs(key->session.tunnel_id), dest_buf, src_buf);

    struct rsvp_psb* psb = calloc(1, sizeof(struct rsvp_psb));
    if (!psb) {
        LOG_ERROR("Failed to allocate memory for PSB");
        return NULL;
    }

    memcpy(&psb->key, key, sizeof(struct rsvp_path_key));
    uint32_t h = rsvp_key_hash(key);
    psb->next_hash = psb_table[h];
    psb_table[h] = psb;

    return psb;
}

void rsvp_psb_delete(struct rsvp_psb* psb) {
    char dest_buf[INET_ADDRSTRLEN];
    char src_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &psb->key.session.dest_addr, dest_buf, sizeof(dest_buf));
    inet_ntop(AF_INET, &psb->key.sender.source_addr, src_buf, sizeof(src_buf));
    
    LOG_DEBUG("Deleting PSB: Tunnel ID %d, Dest %s, Source %s", 
              ntohs(psb->key.session.tunnel_id), dest_buf, src_buf);

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
    char dest_buf[INET_ADDRSTRLEN];
    char src_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &key->session.dest_addr, dest_buf, sizeof(dest_buf));
    inet_ntop(AF_INET, &key->sender.source_addr, src_buf, sizeof(src_buf));
    
    LOG_DEBUG("Creating RSB: Tunnel ID %d, Dest %s, Source %s", 
              ntohs(key->session.tunnel_id), dest_buf, src_buf);

    struct rsvp_rsb* rsb = calloc(1, sizeof(struct rsvp_rsb));
    if (!rsb) {
        LOG_ERROR("Failed to allocate memory for RSB");
        return NULL;
    }

    memcpy(&rsb->key, key, sizeof(struct rsvp_path_key));
    uint32_t h = rsvp_key_hash(key);
    rsb->next_hash = rsb_table[h];
    rsb_table[h] = rsb;

    return rsb;
}

void rsvp_rsb_delete(struct rsvp_rsb* rsb) {
    char dest_buf[INET_ADDRSTRLEN];
    char src_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &rsb->key.session.dest_addr, dest_buf, sizeof(dest_buf));
    inet_ntop(AF_INET, &rsb->key.sender.source_addr, src_buf, sizeof(src_buf));
    
    LOG_DEBUG("Deleting RSB: Tunnel ID %d, Dest %s, Source %s", 
              ntohs(rsb->key.session.tunnel_id), dest_buf, src_buf);

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

void rsvp_psb_dump(void) {
    printf("--- Path State Blocks (PSBs) ---\n");
    int count = 0;
    char dest_buf[INET_ADDRSTRLEN];
    char src_buf[INET_ADDRSTRLEN];
    for (int i = 0; i < HASH_SIZE; i++) {
        struct rsvp_psb* psb = psb_table[i];
        while (psb) {
            inet_ntop(AF_INET, &psb->key.session.dest_addr, dest_buf, sizeof(dest_buf));
            inet_ntop(AF_INET, &psb->key.sender.source_addr, src_buf, sizeof(src_buf));
            printf("PSB: Tunnel ID %d, Dest: %s, Sender: %s, LSP Name: %s\n",
                   ntohs(psb->key.session.tunnel_id),
                   dest_buf, src_buf,
                   psb->lsp_name ? psb->lsp_name : "N/A");
            psb = psb->next_hash;
            count++;
        }
    }
    printf("Total PSBs: %d\n", count);
}

void rsvp_rsb_dump(void) {
    printf("--- Reservation State Blocks (RSBs) ---\n");
    int count = 0;
    char dest_buf[INET_ADDRSTRLEN];
    char src_buf[INET_ADDRSTRLEN];
    for (int i = 0; i < HASH_SIZE; i++) {
        struct rsvp_rsb* rsb = rsb_table[i];
        while (rsb) {
            inet_ntop(AF_INET, &rsb->key.session.dest_addr, dest_buf, sizeof(dest_buf));
            inet_ntop(AF_INET, &rsb->key.sender.source_addr, src_buf, sizeof(src_buf));
            printf("RSB: Tunnel ID %d, Dest: %s, Sender: %s, Label In: %u, Label Out: %u\n",
                   ntohs(rsb->key.session.tunnel_id),
                   dest_buf, src_buf,
                   rsb->label_in, rsb->label_out);
            rsb = rsb->next_hash;
            count++;
        }
    }
    printf("Total RSBs: %d\n", count);
}
