#include "../include/issuer.h"
#include <iostream>
#include <thread>

namespace IssuerNode {

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
    DatTws::DatOpener opener_pk;
    DatTws::DatIssuer issuer_keys;
    int my_port;

    // ============================================================
    // Client Mode: Startup Connection to Regulator
    // ============================================================
    int connectToRegulator() {
        Client client;

        try {
            client.set_access_channels(websocketpp::log::alevel::none);
            client.init_asio();

            client.set_open_handler([&](connection_hdl hdl) {
                initState(DatTws::state_gmp);
                websocketpp::lib::error_code ec;
                client.send(hdl, "GET_PARAMS", websocketpp::frame::opcode::text, ec);
            });

            client.set_message_handler([&](connection_hdl hdl, MsgClient msg) {
                std::string payload = msg->get_payload();
                size_t pos = payload.find("||");
                if (pos != std::string::npos) {
                    pp = str_to_DatParams(payload.substr(0, pos));
                    opener_pk = str_to_DatOpener(payload.substr(pos + 2));

                    // Generate local Issuer key pair
                    issuer_keys.a = rand_mpz(DatTws::state_gmp);
                    issuer_keys.b = rand_mpz(DatTws::state_gmp);
                    ECP2_copy(&issuer_keys.A_tilde, &pp.Y_tilde);
                    ECP2_mul(issuer_keys.A_tilde, issuer_keys.a);
                    ECP2_copy(&issuer_keys.B_tilde, &pp.Y_tilde);
                    ECP2_mul(issuer_keys.B_tilde, issuer_keys.b);

                    std::cout << "[Issuer] Fetched parameters and generated local keys." << std::endl;
                }
                client.close(hdl, websocketpp::close::status::normal, "Setup Complete");
            });

            websocketpp::lib::error_code ec;
            auto con = client.get_connection(REGULATOR_URI, ec);
            if (ec) return -1;
            client.connect(con);
            client.run(); // Block until parameters are received
        } catch (const std::exception& e) {
            std::cerr << "[Issuer Exception] " << e.what() << std::endl;
            return -1;
        }
        return 0;
    }

    // ============================================================
    // Client Mode: Fetch H_u from Regulator (On-Demand)
    // ============================================================
    ECP fetchHuFromRegulator(const ECP2& PK_U) {
        ECP Hu;
        Client client;

        try {
            client.set_access_channels(websocketpp::log::alevel::none);
            client.init_asio();

            client.set_open_handler([&](connection_hdl hdl) {
                // Forward the User's PK_U to the Regulator
                std::string req = "GET_HU||" + ECP2_to_str(PK_U);
                websocketpp::lib::error_code ec;
                client.send(hdl, req, websocketpp::frame::opcode::text, ec);
            });

            client.set_message_handler([&](connection_hdl hdl, MsgClient msg) {
                // Receive the computed H_u from the Regulator
                Hu = str_to_ECP(msg->get_payload());
                client.close(hdl, websocketpp::close::status::normal, "H_u fetched");
            });

            websocketpp::lib::error_code ec;
            auto con = client.get_connection(REGULATOR_URI, ec);
            if (!ec) {
                client.connect(con);
                client.run(); // Synchronously wait for the response
            }
        } catch (...) {
            std::cerr << "[Issuer Error] Failed to fetch H_u from Regulator." << std::endl;
            ECP_inf(&Hu);
        }
        return Hu;
    }

    // ============================================================
    // Server Mode: Serve Users
    // ============================================================
    void serverOnMessage(Server* server, connection_hdl hdl, MsgServer msg) {
        std::string payload = msg->get_payload();

        // User requests a Certificate: Payload format "ISSUE||<PK_U>"
        if (payload.substr(0, 7) == "ISSUE||") {
            std::string pku_str = payload.substr(7);
            ECP2 PK_U = str_to_ECP2(pku_str);

            // Create a dummy user object just to hold PK_U for TagGen compatibility
            DatTws::DatUser dummy_user;
            dummy_user.PK_U = PK_U;

            // Step A: Issuer locally generates the Tag
            DatTws::DatTag tag = DatTws::TagGen(pp, issuer_keys, dummy_user, opener_pk);

            // Step B: Proxy the request to the Regulator to get H_u
            ECP H_u = fetchHuFromRegulator(PK_U);

            // Step C: Issuer computes certificate sigma_i = H_u^{a + b * m}
            mpz_class m = DatTws::H_Tag(tag);
            mpz_class sig_exp = (issuer_keys.a + issuer_keys.b * m) % pp.q;

            ECP sigma_i;
            ECP_copy(&sigma_i, &H_u);
            ECP_mul(sigma_i, sig_exp);

            // Step D: Send Tag, Signature, AND H_u back to the User
            std::string resp = DatTag_to_str(tag) + "||" + ECP_to_str(sigma_i) + "||" + ECP_to_str(H_u);

            try {
                server->send(hdl, resp, websocketpp::frame::opcode::text);
                std::cout << "[Issuer " << my_port << "] Generated Tag and issued certificate (with H_u) for User."
                          << std::endl;
            } catch (const websocketpp::exception &e) {
                std::cerr << "[Issuer Error] Failed to send certificate: " << e.what() << std::endl;
            }
        }
    }

    void startIssuerServer(int port) {
        Server server;
        try {
            server.set_access_channels(websocketpp::log::alevel::none);
            server.init_asio();
            server.set_message_handler(websocketpp::lib::bind(&serverOnMessage, &server, websocketpp::lib::placeholders::_1, websocketpp::lib::placeholders::_2));

            server.listen(port);
            server.start_accept();

            std::cout << "[Issuer] Listening for Users on port " << port << std::endl;
            server.run();
        } catch (const std::exception& e) {
            std::cerr << "[Issuer Server Exception] " << e.what() << std::endl;
        }
    }

    // ============================================================
    // Entry Point
    // ============================================================
    int run(int port) {
        my_port = port;
        std::cout << "[Issuer " << port << "] Booting up..." << std::endl;

        if (connectToRegulator() != 0) {
            std::cerr << "[Issuer Error] Failed to initialize parameters from Regulator." << std::endl;
            return -1;
        }

        startIssuerServer(port);
        return 0;
    }

} // namespace IssuerNode

// ============================================================
// Standalone Executable
// ============================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: ./issuer <port>" << std::endl;
        return -1;
    }
    return IssuerNode::run(std::stoi(argv[1]));
}