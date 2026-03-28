#include "../include/regulator.h"

namespace RegulatorNode {

    // ============================================================
    // Global State Initialization
    // ============================================================
    DatTws::DatParams pp;
    DatTws::DatOpener opener;

    // ============================================================
    // Core Functions
    // ============================================================

    void initParams() {
        std::cout << "[Regulator] Initializing DAT-TWS system parameters..." << std::endl;

        // 1. Generate core cryptographic parameters
        pp = DatTws::Setup();

        // 2. Generate Opener (Regulator) keys
        // rsk is the Master View Secret Key, PK_R is the Public View Key
        initState(DatTws::state_gmp);
        opener.rsk = rand_mpz(DatTws::state_gmp);

        ECP_copy(&opener.PK_R, &pp.X);
        ECP_mul(opener.PK_R, opener.rsk);

        std::cout << "[Regulator] System initialization complete." << std::endl;
        std::cout << "[Regulator] Opener Public Key (PK_R) successfully generated." << std::endl;
    }

    void onMessage(Server* server, connection_hdl hdl, MessagePtr msg) {
        std::string request = msg->get_payload();
        std::cout << "[Regulator] Received connection request: " << request << std::endl;

        if (request == "GET_PARAMS") {
            // Create a sanitized opener object containing ONLY the Public View Key (PK_R).
            DatTws::DatOpener safe_opener;
            safe_opener.rsk = 0; // Scrub the private key
            safe_opener.PK_R = opener.PK_R;

            // Serialize data using a custom delimiter "||" to separate the two structures
            std::string response = DatParams_to_str(pp) + "||" + DatOpener_to_str(safe_opener);

            try {
                server->send(hdl, response, websocketpp::frame::opcode::text);
                std::cout << "[Regulator] Successfully transmitted System Parameters and PK_R." << std::endl;
            } catch (const websocketpp::exception& e) {
                std::cerr << "[Regulator Error] Failed to send message: " << e.what() << std::endl;
            }
        } else if (request.substr(0, 8) == "GET_HU||") {
            std::string pk_str = request.substr(8);
            ECP2 PK_U = str_to_ECP2(pk_str);

            // Compute H_u = X^{f(rsk, PK_U)}
            mpz_class hu_val = DatTws::f_hash(opener.rsk, PK_U);
            ECP H_u;
            ECP_copy(&H_u, &pp.X);
            ECP_mul(H_u, hu_val);

            try {
                server->send(hdl, ECP_to_str(H_u), websocketpp::frame::opcode::text);
            } catch (const websocketpp::exception& e) {
                std::cerr << "[Regulator Error] Failed to send H_u: " << e.what() << std::endl;
            }
        }
        else {
            std::cerr << "[Regulator Warning] Unknown request type received: " << request << std::endl;
        }
    }

    int startServer(int port) {
        Server server;

        try {
            // Configure logging channels for a clean console output
            server.set_access_channels(websocketpp::log::alevel::all);
            server.clear_access_channels(websocketpp::log::alevel::frame_payload);
            server.clear_access_channels(websocketpp::log::alevel::frame_header);

            server.init_asio();

            // Bind the incoming message handler
            server.set_message_handler(
                    websocketpp::lib::bind(
                            &onMessage,
                            &server,
                            websocketpp::lib::placeholders::_1,
                            websocketpp::lib::placeholders::_2
                    )
            );

            // Bind to port 9002 (Acting as the central parameter authority)
            server.listen(port);
            server.start_accept();
            std::cout << "[Regulator] Server is running and listening on 0.0.0.0:" << port << std::endl;

            // Execute the ASIO IO service loop
            server.run();
        }
        catch (const std::exception& e) {
            std::cerr << "[Regulator Fatal Error] Exception caught: " << e.what() << std::endl;
            return -1;
        }
        catch (...) {
            std::cerr << "[Regulator Fatal Error] Unknown exception occurred!" << std::endl;
            return -1;
        }

        return 0;
    }

    int run(int port) {
        initParams();
        return startServer(port);
    }

} // namespace RegulatorNode

// ============================================================
// Standalone Executable Entry Point
// ============================================================
int main(int argc, char* argv[]) {
    int port = (argc >= 2) ? std::stoi(argv[1]) : 9002;
    return RegulatorNode::run(port);
}