#ifndef VERIFIER_H
#define VERIFIER_H

#include "../../DAT-TWS/include/dat-tws.h"
#include "../../common/include/Serializer.h"

#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

#include <string>
#include <vector>

/**
 * @file verifier.h
 * @brief Declaration of the Verifier node.
 *
 * The Verifier is the entity responsible for validating the Zero-Knowledge Proofs
 * and aggregated signatures submitted by Users in the DAT-TWS protocol.
 * Responsibilities:
 * - Fetch global public parameters from the Regulator upon initialization.
 * - Listen for incoming "VERIFY" requests from Users.
 * - Deserialize the DatSignature and DatTag array.
 * - Execute the verification algorithm and return the boolean result.
 */

namespace VerifierNode {

    using Client = websocketpp::client<websocketpp::config::asio_client>;
    using MsgClient = websocketpp::config::asio_client::message_type::ptr;
    using Server = websocketpp::server<websocketpp::config::asio>;
    using MsgServer = Server::message_ptr;
    using websocketpp::connection_hdl;

    // ============================================================
    // Global State
    // ============================================================
    extern DatTws::DatParams pp;    ///< System public parameters.
    extern int my_port;             ///< The port this Verifier listens on.

    /**
     * @brief Connects to the Regulator to fetch the initial system parameters.
     * @return 0 on success, -1 on failure.
     */
    int connectToRegulator();

    /**
     * @brief Server message handler for incoming User verification requests.
     * * Parses the payload, rebuilds the cryptographic structures, and runs
     * the DatTws::Verify algorithm.
     */
    void serverOnMessage(Server* server, connection_hdl hdl, MsgServer msg);

    /**
     * @brief Starts the Verifier's WebSocket server to listen for Users.
     * @param port The port to bind to (e.g., 9003).
     */
    void startVerifierServer(int port);

    /**
     * @brief Main execution sequence for the Verifier node.
     * @param port The port number.
     * @return 0 on success, -1 on failure.
     */
    int run(int port);

} // namespace VerifierNode

#endif // VERIFIER_H