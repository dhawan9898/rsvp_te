/**
 * @file rsvp_state_machine.h
 * @brief RSVP-TE State Machine — message processing, ERO routing, and FRR.
 * @details Core logic for processing all RSVP message types, managing PSB/RSB state,
 *          forwarding PATH messages along ERO-specified next hops, and implementing
 *          RFC 4090 Fast ReRoute facility-backup mode.
 */

#ifndef RSVP_STATE_MACHINE_H
#define RSVP_STATE_MACHINE_H

#include <netinet/in.h>

#include "rsvp_parser.h"
#include "rsvp_state.h"

/**
 * @brief Dispatch a fully parsed RSVP message to the appropriate handler.
 * @details Handles PATH, RESV, PathTear, ResvTear, PathErr, ResvErr, ResvConf,
 *          and SRefresh.  Unknown types are logged and discarded.
 * @param [in] info Parsed message info produced by rsvp_parse_packet().
 */
void rsvp_handle_message(struct rsvp_message_info* info);

/**
 * @brief Initiate an LSP PATH using IGP-computed routing (no ERO).
 * @details Creates a PSB at the ingress and sends the first PATH downstream.
 *          The path follows the IGP shortest route to the destination.
 * @param [in] src     Ingress (source) IPv4 address.
 * @param [in] dest    Egress (destination) IPv4 address.
 * @param [in] tunnel_id Unique 16-bit tunnel identifier.
 * @param [in] lsp_name  Optional human-readable LSP name (may be NULL).
 */
void rsvp_initiate_path(struct in_addr* src, struct in_addr* dest,
                        uint16_t tunnel_id, const char* lsp_name);

/**
 * @brief Initiate an LSP PATH along an explicit ERO, with optional FRR request.
 * @details Creates a PSB at the ingress and sends the first PATH downstream.
 *          Each hop on the path receives the FAST_REROUTE object if @p request_frr
 *          is true, instructing PLRs to establish facility-backup bypass tunnels.
 * @param [in] src        Ingress IPv4 address.
 * @param [in] dest       Egress IPv4 address.
 * @param [in] tunnel_id  Unique 16-bit tunnel identifier.
 * @param [in] lsp_name   Optional LSP name (may be NULL).
 * @param [in] ero        Array of IPv4 ERO subobjects defining the explicit path.
 * @param [in] ero_count  Number of entries in @p ero (0 means fall back to IGP).
 * @param [in] request_frr If true, add a FAST_REROUTE object requesting facility backup.
 */
void rsvp_initiate_path_with_ero(struct in_addr* src, struct in_addr* dest,
                                  uint16_t tunnel_id, const char* lsp_name,
                                  struct rsvp_ero_ipv4_subobj* ero,
                                  uint8_t ero_count,
                                  bool request_frr);

/**
 * @brief Establish a bypass tunnel for RFC 4090 facility-backup FRR.
 * @details Creates a bypass PSB that avoids the specified protected interface.
 *          The bypass tunnel is a regular LSP with @p is_bypass_tunnel set so
 *          the state machine tracks it for FRR switchover.
 * @param [in] src                Ingress (PLR) IPv4 address.
 * @param [in] dest               Merge-point IPv4 address (next-next-hop around failure).
 * @param [in] tunnel_id          Unique 16-bit tunnel ID for this bypass.
 * @param [in] name               Optional bypass tunnel name (may be NULL).
 * @param [in] ero                Explicit route avoiding the protected link/node.
 * @param [in] ero_count          Number of ERO subobjects.
 * @param [in] protected_ifindex  Egress interface index this bypass protects.
 */
void rsvp_initiate_bypass_tunnel(struct in_addr* src, struct in_addr* dest,
                                  uint16_t tunnel_id, const char* name,
                                  struct rsvp_ero_ipv4_subobj* ero,
                                  uint8_t ero_count,
                                  uint32_t protected_ifindex);

/**
 * @brief Associate an existing LSP with a pre-established bypass tunnel.
 * @details Links the PSB identified by (tunnel_id, lsp_id) to the bypass PSB
 *          identified by bypass_tunnel_id.  Once linked, rsvp_frr_trigger() can
 *          switch the LSP to the bypass path in microseconds on link failure.
 * @param [in] tunnel_id         Protected LSP tunnel ID.
 * @param [in] lsp_id            Protected LSP ID.
 * @param [in] frr_mode          RSVP_FRR_FACILITY (only supported mode currently).
 * @param [in] bypass_tunnel_id  Tunnel ID of the pre-established bypass PSB.
 * @return RSVP_SUCCESS on success, RSVP_ERR_NOT_FOUND if either PSB is missing,
 *         or RSVP_ERR_FRR_NOT_CONFIGURED if no bypass RSB has a valid label yet.
 */
rsvp_error_t rsvp_frr_enable_protection(uint16_t tunnel_id, uint16_t lsp_id,
                                          rsvp_frr_mode_t frr_mode,
                                          uint16_t bypass_tunnel_id);

/**
 * @brief Trigger FRR switchover for all LSPs egressing a failed interface.
 * @details Called by the failure detection subsystem (e.g., BFD, link-down event).
 *          For each PSB using @p failed_ifindex as its egress and with
 *          facility-backup FRR configured, this function immediately reprograms
 *          the MPLS forwarding plane to use the bypass path and sets frr_active.
 *          A PATH message with LOCAL_PROTECTION_IN_USE is re-sent after switchover
 *          so ingress and transit nodes update their RRO flags.
 * @param [in] failed_ifindex  The interface index that has gone down.
 */
void rsvp_frr_trigger(uint32_t failed_ifindex);

/**
 * @brief Gracefully tear down all active LSPs and release all resources.
 * @details Sends PathTear and ResvTear for every active PSB/RSB, releases labels,
 *          removes MPLS entries, and stops all timers.  Should be called on
 *          SIGTERM before the process exits so peer nodes can flush soft-state
 *          immediately instead of waiting for the cleanup timeout.
 */
void rsvp_state_machine_shutdown(void);

/**
 * @brief Teardown an existing LSP identified by Tunnel ID and LSP ID.
 * @details Looks up the PSB and sends PathTear downstream to remove state from
 *          every node along the path.
 * @param [in] tunnel_id The tunnel identifier.
 * @param [in] lsp_id    The LSP identifier.
 */
void rsvp_teardown_path(uint16_t tunnel_id, uint16_t lsp_id);

#endif /* RSVP_STATE_MACHINE_H */
