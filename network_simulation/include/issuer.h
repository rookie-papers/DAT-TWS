#ifndef ISSUER_H
#define ISSUER_H

#include "dat-tws.h"
#include "../../common/include/Serializer.h"

#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

#include <string>
#include <vector>

/**
 * @file issuer.h
 * @brief Declaration of the Issuer node.
 *
 * The Issuer acts as the credential provider in the DAT-TWS protocol.
 * Responsibilities:
 * - Fetch global parameters from the Regulator on startup.
 * - Generate a local signing key pair (a, b) and public keys (A_tilde, B_tilde).
 * - Listen for User requests to distribute public keys or issue signatures.
 * - Communicate with the Regulator to derive H_u based on the User's PK_U.
 */

namespace IssuerNode {

    using Client = websocketpp::client<websocketpp::config::asio_client>;
    using MsgClient = websocketpp::config::asio_client::message_type::ptr;
    using Server = websocketpp::server<websocketpp::config::asio>;
    using MsgServer = Server::message_ptr;
    using websocketpp::connection_hdl;

    // ============================================================
    // Global State
    // ============================================================
    extern DatTws::DatParams pp;            ///< System parameters from Regulator.
    extern DatTws::DatOpener opener_pk;     ///< Regulator's public view key.
    extern DatTws::DatIssuer issuer_keys;   ///< Local signing keys and public keys.
    extern int my_port;                     ///< The port this Issuer listens on.

    /**
     * @brief Connects to the Regulator to fetch initial system parameters.
     * @return 0 on success, -1 on failure.
     */
    int connectToRegulator();

    /**
     * @brief Synchronously fetches H_u from the Regulator for a specific User.
     * @param PK_U The User's public key.
     * @return The derived ECP point H_u.
     */
    ECP fetchHuFromRegulator(const ECP2& PK_U);

    /**
     * @brief Server message handler for incoming User requests.
     */
    void serverOnMessage(Server* server, connection_hdl hdl, MsgServer msg);

    /**
     * @brief Starts the Issuer's WebSocket server to listen for Users.
     * @param port The port to bind to.
     */
    void startIssuerServer(int port);

    /**
     * @brief Main execution sequence for the Issuer node.
     * @param port The port number.
     * @return 0 on success, -1 on failure.
     */
    int run(int port);

} // namespace IssuerNode

#endif // ISSUER_H