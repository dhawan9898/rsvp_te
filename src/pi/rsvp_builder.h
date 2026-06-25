/**
 * @file rsvp_builder.h
 * @brief RSVP message builder utilities.
 * @details Provides an API to construct RSVP messages object by object before transmission.
 */

#ifndef RSVP_BUILDER_H
#define RSVP_BUILDER_H

#include <stddef.h>

#include "common/rsvp_protocol.h"

/**
 * @brief Context structure for building an RSVP message.
 * @details Keeps track of the buffer, its capacity, current offset, and a pointer to the common header.
 */
struct rsvp_builder {
    uint8_t* buffer;            /**< Pointer to the start of the message buffer */
    size_t size;                /**< Total size of the buffer */
    size_t offset;              /**< Current write offset within the buffer */
    struct rsvp_common_hdr* hdr;/**< Pointer to the common header of the message being built */
};

/**
 * @brief Initialize a builder with a buffer.
 * @details Sets up the builder context and writes the common RSVP header.
 * @param [out] b Pointer to the builder context to initialize.
 * @param [in] buffer The memory buffer to write into.
 * @param [in] size The capacity of the memory buffer.
 * @param [in] msg_type The RSVP message type (e.g., RSVP_MSG_PATH, RSVP_MSG_RESV).
 */
void rsvp_builder_init(struct rsvp_builder* b, uint8_t* buffer, size_t size,
                       uint8_t msg_type);

/**
 * @brief Add an object to the RSVP message.
 * @details Appends an object header followed by its data payload, ensuring 4-byte alignment.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] class_num The class number of the object.
 * @param [in] c_type The C-Type of the object.
 * @param [in] data Pointer to the object payload.
 * @param [in] data_len Length of the object payload in bytes.
 * @return 0 on success, or an RSVP error code if buffer is too small.
 */
int rsvp_builder_add_obj(struct rsvp_builder* b, uint8_t class_num,
                         uint8_t c_type, void* data, size_t data_len);

/* Helper functions for common objects */

/**
 * @brief Add an IPv4 Session object.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] dest The tunnel destination IPv4 address.
 * @param [in] tunnel_id The Tunnel ID.
 * @param [in] ext_tunnel_id The Extended Tunnel ID (usually the ingress address).
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_session_ipv4(struct rsvp_builder* b, struct in_addr* dest,
                                  uint16_t tunnel_id,
                                  struct in_addr* ext_tunnel_id);

/**
 * @brief Add an IPv6 Session object.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] dest The tunnel destination IPv6 address.
 * @param [in] tunnel_id The Tunnel ID.
 * @param [in] ext_tunnel_id The Extended Tunnel ID.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_session_ipv6(struct rsvp_builder* b, struct in6_addr* dest,
                                  uint16_t tunnel_id,
                                  struct in6_addr* ext_tunnel_id);

/**
 * @brief Add a SESSION_ATTRIBUTE object with default priorities and SE-style flag.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] name Optional LSP display name (may be NULL).
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_session_attribute(struct rsvp_builder* b, const char* name);

/**
 * @brief Add a SESSION_ATTRIBUTE object with explicit priorities and flags.
 * @details Use this variant to set FRR-related flags such as
 *          RSVP_SESSATTR_LOCAL_PROT_DESIRED or RSVP_SESSATTR_LOCAL_PROT_IN_USE.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] name Optional LSP display name (may be NULL).
 * @param [in] setup_prio Setup priority (0 = highest).
 * @param [in] holding_prio Holding priority (0 = highest).
 * @param [in] flags Bitfield of RSVP_SESSATTR_* flags.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_session_attribute_ex(struct rsvp_builder* b,
                                           const char* name,
                                           uint8_t setup_prio,
                                           uint8_t holding_prio,
                                           uint8_t flags);

/**
 * @brief Add a FAST_REROUTE object (RFC 4090 §4.1, Class 205 C-Type 1).
 * @details Included in PATH messages by ingress nodes to request FRR protection
 *          at PLR nodes along the path.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] setup_prio Setup priority for the backup path.
 * @param [in] holding_prio Holding priority for the backup path.
 * @param [in] hop_limit Maximum hops allowed on the backup path.
 * @param [in] flags RSVP_FRR_FLAG_ONE_TO_ONE or RSVP_FRR_FLAG_FACILITY.
 * @param [in] bandwidth Bandwidth to protect in bytes/sec (host float).
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_fast_reroute(struct rsvp_builder* b,
                                   uint8_t setup_prio, uint8_t holding_prio,
                                   uint8_t hop_limit, uint8_t flags,
                                   float bandwidth);

/**
 * @brief Add a DETOUR object (RFC 4090 §4.2, Class 63 C-Type 7).
 * @details Carried in detour (one-to-one backup) PATH messages to identify
 *          the PLR and the node being avoided.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] plr_id IPv4 address of the Point of Local Repair.
 * @param [in] avoid_node_id IPv4 address of the node or link endpoint to avoid.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_detour(struct rsvp_builder* b,
                             struct in_addr* plr_id,
                             struct in_addr* avoid_node_id);

/**
 * @brief Add an IPv4 RSVP_HOP object.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] neighbor The IPv4 address of the sender interface.
 * @param [in] logical_intf The logical interface handle.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_hop_ipv4(struct rsvp_builder* b, struct in_addr* neighbor,
                              uint32_t logical_intf);

/**
 * @brief Add an IPv6 RSVP_HOP object.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] neighbor The IPv6 address of the sender interface.
 * @param [in] logical_intf The logical interface handle.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_hop_ipv6(struct rsvp_builder* b, struct in6_addr* neighbor,
                              uint32_t logical_intf);

/**
 * @brief Add an IPv4 Label object.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] label The allocated MPLS label value.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_label_ipv4(struct rsvp_builder* b, uint32_t label);

/**
 * @brief Add a Label Request object.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] l3pid The Layer 3 Protocol ID.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_label_request(struct rsvp_builder* b, uint16_t l3pid);

/**
 * @brief Add a Style object.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] style_val The reservation style (e.g., RSVP_STYLE_FF).
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_style(struct rsvp_builder* b, uint32_t style_val);

/**
 * @brief Add a TIME_VALUES object.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] refresh_ms The refresh interval in milliseconds.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_time_values(struct rsvp_builder* b, uint32_t refresh_ms);

/**
 * @brief Add a Sender TSpec object.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] tspec Pointer to the traffic specification structure.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_tspec(struct rsvp_builder* b,
                           struct rsvp_sender_tspec* tspec);

/**
 * @brief Add a Flowspec object.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] tspec Pointer to the flowspec specification structure.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_flowspec(struct rsvp_builder* b,
                           struct rsvp_sender_tspec* tspec);

/**
 * @brief Add an AdSpec object.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] adspec Pointer to the AdSpec structure.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_adspec(struct rsvp_builder* b, struct rsvp_adspec* adspec);

/**
 * @brief Add an INTEGRITY object.
 * @details Appends cryptographic digest for message authentication.
 * @param [in,out] b Pointer to the builder context.
 * @param [in] flags Integrity flags.
 * @param [in] key_id 6-byte key identifier.
 * @param [in] sequence_number Message sequence number.
 * @param [in] digest Pointer to the digest.
 * @param [in] digest_len Length of the digest.
 * @return Total bytes appended, or 0 on error.
 */
size_t rsvp_builder_add_integrity(struct rsvp_builder* b, uint8_t flags, uint8_t* key_id, uint64_t sequence_number, uint8_t* digest, size_t digest_len);

/**
 * @brief Add a HELLO object (RFC 3209 §5.3, Class 22).
 * @param [in,out] b Pointer to the builder context.
 * @param [in] src_instance Sender's unique instance identifier.
 * @param [in] dst_instance Last received src_instance from the peer (0 if unknown).
 * @param [in] c_type RSVP_HELLO_CTYPE_REQUEST (1) or RSVP_HELLO_CTYPE_ACK (2).
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_hello(struct rsvp_builder* b, uint32_t src_instance,
                            uint32_t dst_instance, uint8_t c_type);

/**
 * @brief Add an Explicit Route Object (ERO).
 * @param [in,out] b Pointer to the builder context.
 * @param [in] ero_list Array of ERO IPv4 subobjects.
 * @param [in] count Number of subobjects in the array.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_ero(struct rsvp_builder* b, struct rsvp_ero_ipv4_subobj* ero_list, size_t count);

/**
 * @brief Add a Record Route Object (RRO).
 * @param [in,out] b Pointer to the builder context.
 * @param [in] rro_list Array of RRO IPv4 subobjects.
 * @param [in] count Number of subobjects in the array.
 * @return 0 on success, or an error code.
 */
int rsvp_builder_add_rro(struct rsvp_builder* b, struct rsvp_ero_ipv4_subobj* rro_list, size_t count);

/**
 * @brief Convert a network byte order floating point value to host order.
 * @param [in] net_value The network byte order value.
 * @return The host order floating point value.
 */
float rsvp_net_to_float(uint32_t net_value);

/**
 * @brief Convert a host order floating point value to network order.
 * @param [in] host_value The host order value.
 * @return The network byte order representation.
 */
uint32_t rsvp_float_to_net(float host_value);

/**
 * @brief Verify the RSVP checksum of a message without mutating the buffer.
 * @param [in] buf Pointer to the RSVP message.
 * @param [in] len Length of the RSVP message.
 * @return 0 if checksum is valid, -1 otherwise.
 */
int rsvp_checksum_verify(const void* buf, size_t len);

/**
 * @brief Finalize the constructed RSVP message.
 * @details Updates the message length field and computes the checksum.
 * @param [in,out] b Pointer to the builder context.
 * @return The final length of the constructed message in bytes.
 */
size_t rsvp_builder_finalize(struct rsvp_builder* b);

/**
 * @brief Compute the RSVP checksum.
 * @details Calculates the 16-bit one's complement of the one's complement sum over the packet.
 * @param [in] buf Pointer to the data.
 * @param [in] len Length of the data in bytes.
 * @return The computed 16-bit checksum.
 */
uint16_t rsvp_checksum(const void* buf, size_t len);

#endif /* RSVP_BUILDER_H */
