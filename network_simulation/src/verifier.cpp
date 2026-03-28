#include "../include/verifier.h"
#include <iostream>
#include <chrono>

namespace VerifierNode {

    // ============================================================
    // Network Configuration (Modify these for distributed testing)
    // ============================================================
    const std::string REGULATOR_IP = "10.0.0.10";
    const std::string REGULATOR_PORT = "9002";
    const std::string REGULATOR_URI = "ws://" + REGULATOR_IP + ":" + REGULATOR_PORT;

    // ============================================================
    // Global State Initialization
    // ============================================================
    DatTws::DatParams pp;
    int my_port;

    // ============================================================
    // Client Mode: Startup Connection to Regulator
    // ============================================================
    int connectToRegulator() {
        Client client;

        std::cout << "[Verifier] Connecting to Regulator at " << REGULATOR_URI << " to fetch system parameters..." << std::endl;

        try {
            client.set_access_channels(websocketpp::log::alevel::none);
            client.init_asio();

            client.set_open_handler([&](connection_hdl hdl) {
                websocketpp::lib::error_code ec;
                client.send(hdl, "GET_PARAMS", websocketpp::frame::opcode::text, ec);
            });

            client.set_message_handler([&](connection_hdl hdl, MsgClient msg) {
                std::string payload = msg->get_payload();
                size_t pos = payload.find("||");
                if (pos != std::string::npos) {
                    // Verifier only needs DatParams, the opener key is ignored
                    pp = str_to_DatParams(payload.substr(0, pos));
                    std::cout << "[Verifier] System parameters successfully loaded." << std::endl;
                }
                client.close(hdl, websocketpp::close::status::normal, "Setup Complete");
            });

            websocketpp::lib::error_code ec;
            auto con = client.get_connection(REGULATOR_URI, ec);
            if (ec) return -1;

            client.connect(con);
            client.run(); // Block until parameters are received
        } catch (const std::exception& e) {
            std::cerr << "[Verifier Exception] " << e.what() << std::endl;
            return -1;
        }
        return 0;
    }

    // ============================================================
    // Server Mode: Validate User Signatures
    // ============================================================
    void serverOnMessage(Server* server, connection_hdl hdl, MsgServer msg) {
        std::string payload = msg->get_payload();

        // Expected format: "VERIFY||<message>||<DatSignature>||<DatTagArray>"
        if (payload.substr(0, 8) == "VERIFY||") {
            std::cout << "\n[Verifier] Received a verification request." << std::endl;

            try {
                std::string data = payload.substr(8);

                // 1. Extract the signed message
                size_t pos1 = data.find("||");
                if (pos1 == std::string::npos) throw std::runtime_error("Malformed payload");
                std::string signed_msg = data.substr(0, pos1);

                std::string remaining1 = data.substr(pos1 + 2);

                // 2. Extract DatSignature and DatTagArray
                size_t pos2 = remaining1.find("||");
                if (pos2 == std::string::npos) throw std::runtime_error("Malformed payload");
                std::string sig_str = remaining1.substr(0, pos2);
                std::string tags_str = remaining1.substr(pos2 + 2);

                // 3. Deserialize structures
                DatTws::DatSignature sig = str_to_DatSignature(sig_str);
                std::vector<DatTws::DatTag> tags = str_to_DatTagArr(tags_str);

                std::cout << "[Verifier] Payload unpacked. Message: \"" << signed_msg << "\"" << std::endl;
                std::cout << "[Verifier] Aggregated tags count: " << tags.size() << std::endl;
                std::cout << "[Verifier] Executing cryptographic verification..." << std::endl;

                // ================= START TIMING: PURE COMPUTE =================
                auto t_compute_start = std::chrono::high_resolution_clock::now();

                // 4. Run the core verification algorithm
                bool is_valid = DatTws::Verify(pp, sig, tags, signed_msg);

                // ================= END TIMING: PURE COMPUTE =================
                auto t_compute_end = std::chrono::high_resolution_clock::now();
                auto compute_duration = std::chrono::duration_cast<std::chrono::milliseconds>(t_compute_end - t_compute_start).count();

                // 5. Send response back to User
                std::string response = is_valid ? "SUCCESS: Signature is VALID." : "ERROR: Signature is INVALID.";
                server->send(hdl, response, websocketpp::frame::opcode::text);

                if (is_valid) {
                    std::cout << "[Verifier] Result: \033[1;32mVALID\033[0m" << std::endl;
                } else {
                    std::cout << "[Verifier] Result: \033[1;31mINVALID\033[0m" << std::endl;
                }

                std::cout << ">>> Pure Cryptographic Verification Time: " << compute_duration << " ms <<<" << std::endl;

            } catch (const std::exception& e) {
                std::cerr << "[Verifier Error] Parsing failed: " << e.what() << std::endl;
                server->send(hdl, "ERROR: Malformed data format.", websocketpp::frame::opcode::text);
            }
        }
    }

    void startVerifierServer(int port) {
        Server server;
        try {
            server.set_access_channels(websocketpp::log::alevel::none);
            server.init_asio();
            server.set_message_handler(websocketpp::lib::bind(&serverOnMessage, &server, websocketpp::lib::placeholders::_1, websocketpp::lib::placeholders::_2));

            server.listen(port);
            server.start_accept();

            std::cout << "[Verifier] Online and listening on port " << port << std::endl;
            server.run();
        } catch (const std::exception& e) {
            std::cerr << "[Verifier Server Exception] " << e.what() << std::endl;
        }
    }

    // ============================================================
    // Entry Point
    // ============================================================
    int run(int port) {
        my_port = port;
        std::cout << "[Verifier " << port << "] Booting up..." << std::endl;

        initState(DatTws::state_gmp);

        if (connectToRegulator() != 0) {
            std::cerr << "[Verifier Error] Failed to fetch parameters from Regulator." << std::endl;
            return -1;
        }

        startVerifierServer(port);
        return 0;
    }

} // namespace VerifierNode

// ============================================================
// Standalone Executable
// ============================================================
int main(int argc, char* argv[]) {
    // Default to port 9003 if not provided
    int port = (argc >= 2) ? std::stoi(argv[1]) : 9003;
    return VerifierNode::run(port);
}