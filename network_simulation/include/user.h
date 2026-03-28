#ifndef USER_H
#define USER_H

#include "dat-tws.h"
#include "../../common//include/Serializer.h"

#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <string>
#include <vector>

/**
 * @file user.h
 * @brief Declaration of the User node.
 *
 * The User is the core prover in the DAT-TWS protocol.
 * Responsibilities:
 * - Register with the Regulator to obtain system parameters and H_u.
 * - Generate local user keys (usk, PK_U).
 * - Communicate with multiple Issuers to obtain public keys and certificates.
 * - Aggregate certificates and generate a Zero-Knowledge Proof (Sign).
 * - Submit the final signature and tags to the Verifier.
 */

namespace UserNode {

    using Client = websocketpp::client<websocketpp::config::asio_client>;
    using MsgClient = websocketpp::config::asio_client::message_type::ptr;
    using websocketpp::connection_hdl;

    // ============================================================
    // Global State
    // ============================================================
    extern DatTws::DatParams pp;               ///< System parameters.
    extern DatTws::DatOpener opener_pk;        ///< Regulator's public view key.
    extern DatTws::DatUser user_keys;          ///< User's private keys, tags, and witnesses.

    /**
     * @brief A helper function to make a synchronous WebSocket request.
     * @param uri The WebSocket URI (e.g., "ws://localhost:9002").
     * @param payload The message to send.
     * @return The string response from the server.
     */
    std::string syncWebsocketRequest(const std::string& uri, const std::string& payload);

    /**
     * @brief Connects to the Regulator to fetch parameters and H_u.
     * @return 0 on success, -1 on failure.
     */
    int registerWithRegulator();

    /**
     * @brief Fetches an Issuer's public key and requests a certificate.
     * @param issuer_port The port the Issuer is listening on.
     * @return 0 on success, -1 on failure.
     */
    int obtainCertificateFromIssuer(const std::string& issuer_ip, int issuer_port);

    /**
     * @brief Generates the aggregated signature and sends it to the Verifier.
     * @param verifier_port The port the Verifier is listening on.
     * @param msg The message to sign.
     * @return 0 on success, -1 on failure.
     */
    int proveToVerifier(const std::string& verifier_ip, int verifier_port, const std::string& msg);

    /**
     * @brief Main execution sequence for the User node.
     * @return 0 on success, -1 on failure.
     */
    int run();

} // namespace UserNode

#endif // USER_H