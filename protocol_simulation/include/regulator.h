#ifndef REGULATOR_H
#define REGULATOR_H

#include "../../DAT-TWS/include/dat-tws.h"
#include "../../common/include/Serializer.h"

#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

#include <iostream>
#include <string>

/**
 * @file regulator.h
 * @brief Declaration of the Regulator (Opener/Tracer) node.
 *
 * In the DAT-TWS protocol, the Regulator acts as the trusted parameter server
 * and the tracer. It is responsible for:
 * - Generating the global system parameters (DatParams).
 * - Generating the Opener's key pair (Master View Secret Key and Public View Key).
 * - Securely distributing the public parameters and public view key to
 * Issuers, Users, and Verifiers via WebSocket.
 */

namespace RegulatorNode {

    using websocketpp::connection_hdl;
    using Server = websocketpp::server<websocketpp::config::asio>;
    using MessagePtr = Server::message_ptr;

    // ============================================================
    // Global State
    // ============================================================

    extern DatTws::DatParams pp;       ///< Global system public parameters.
    extern DatTws::DatOpener opener;   ///< Regulator's key pair (includes secret rsk).

    /**
     * @brief Initializes the Regulator's internal parameters.
     * * Executes the Setup algorithm to generate global parameters and
     * generates the Opener's cryptographic key pair.
     */
    void initParams();

    /**
     * @brief WebSocket message handler for incoming network requests.
     * * Listens for "GET_PARAMS" requests. Upon receiving a valid request,
     * it sanitizes the Opener object (removing the private key) and securely
     * transmits the system parameters and public view key to the client.
     * * @param server Pointer to the WebSocket server instance.
     * @param hdl    Connection handle for the requesting client.
     * @param msg    The received message payload.
     */
    void onMessage(Server* server, connection_hdl hdl, MessagePtr msg);

    /**
     * @brief Configures and starts the Regulator's WebSocket server.
     * * Binds the server to port 9002 and begins the ASIO event loop to
     * listen for incoming entity connections.
     * * @return 0 on success, -1 on failure.
     */
    int startServer(int port);

    /**
     * @brief Main execution sequence for the Regulator node.
     * * Calls initParams() followed by startServer().
     * * @return 0 on success, -1 on failure.
     */
    int run(int port);

} // namespace RegulatorNode

#endif // REGULATOR_H