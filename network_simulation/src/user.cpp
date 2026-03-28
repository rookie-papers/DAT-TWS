#include "../include/user.h"
#include <iostream>
#include <stdexcept>
#include <chrono>

namespace UserNode {

    // ============================================================
    // Network Configuration (Modify these for distributed testing)
    // ============================================================
    const std::string REGULATOR_IP = "10.0.0.10";
    const std::string REGULATOR_PORT = "9002";
    const std::string REGULATOR_URI = "ws://" + REGULATOR_IP + ":" + REGULATOR_PORT;

    const std::string VERIFIER_IP = "10.0.0.20";
    const std::string VERIFIER_PORT = "9003";

    // The base IP prefix for all Issuers
    const std::string ISSUER_SUBNET_PREFIX = "10.0.0.";

    // ============================================================
    // Global State Initialization
    // ============================================================
    DatTws::DatParams pp;
    DatTws::DatOpener opener_pk;
    DatTws::DatUser user_keys;

    // ============================================================
    // Synchronous WebSocket Request Helper
    // ============================================================
    std::string syncWebsocketRequest(const std::string& uri, const std::string& payload) {
        Client client;
        std::string response_data = "";
        bool request_failed = false;

        try {
            client.set_access_channels(websocketpp::log::alevel::none);
            client.init_asio();

            client.set_open_handler([&](connection_hdl hdl) {
                websocketpp::lib::error_code ec;
                client.send(hdl, payload, websocketpp::frame::opcode::text, ec);
                if (ec) request_failed = true;
            });

            client.set_message_handler([&](connection_hdl hdl, MsgClient msg) {
                response_data = msg->get_payload();
                client.close(hdl, websocketpp::close::status::normal, "Completed");
            });

            client.set_fail_handler([&](connection_hdl hdl) {
                request_failed = true;
            });

            websocketpp::lib::error_code ec;
            auto con = client.get_connection(uri, ec);
            if (ec) return "";

            client.connect(con);
            client.run(); // Blocks until connection is closed

        } catch (...) {
            return "";
        }

        if (request_failed) return "";
        return response_data;
    }

    // ============================================================
    // Step 1: Registration with Regulator
    // ============================================================
    int registerWithRegulator() {
        std::cout << "[User] Connecting to Regulator for registration..." << std::endl;

        // 1.1 Fetch System Parameters
        std::string param_resp = syncWebsocketRequest(REGULATOR_URI, "GET_PARAMS");
        if (param_resp.empty()) {
            std::cerr << "[User Error] Failed to fetch parameters." << std::endl;
            return -1;
        }

        size_t pos = param_resp.find("||");
        if (pos != std::string::npos) {
            pp = str_to_DatParams(param_resp.substr(0, pos));
            opener_pk = str_to_DatOpener(param_resp.substr(pos + 2));
        }

        // 1.2 Generate local keys
        initState(DatTws::state_gmp);
        user_keys.usk = rand_mpz(DatTws::state_gmp);
        ECP2_copy(&user_keys.PK_U, &pp.Y_tilde);
        ECP2_mul(user_keys.PK_U, user_keys.usk);
        std::cout << "[User] Generated local User keys (usk, PK_U)." << std::endl;

        // 1.3 Fetch H_u from Regulator
        std::string req_hu = "GET_HU||" + ECP2_to_str(user_keys.PK_U);
        std::string hu_resp = syncWebsocketRequest(REGULATOR_URI, req_hu);
        if (hu_resp.empty()) {
            std::cerr << "[User Error] Failed to fetch H_u." << std::endl;
            return -1;
        }

        user_keys.H = str_to_ECP(hu_resp);
        std::cout << "[User] Registration complete. Base H_u received." << std::endl;

        return 0;
    }

    // ============================================================
    // Step 2: Fetch Certificate from an Issuer
    // ============================================================
    int obtainCertificateFromIssuer(const std::string& issuer_ip, int issuer_port) {
        std::string issuer_uri = "ws://" + issuer_ip + ":" + std::to_string(issuer_port);
        std::cout << "[User] Contacting Issuer on port " << issuer_port << " for issuance..." << std::endl;

        // 2.1 Send ISSUE request with ONLY the User's Public Key (PK_U)
        std::string issue_req = "ISSUE||" + ECP2_to_str(user_keys.PK_U);
        std::string resp = syncWebsocketRequest(issuer_uri, issue_req);
        if (resp.empty()) {
            std::cerr << "[User Error] No response from Issuer " << issuer_port << std::endl;
            return -1;
        }

        // 2.2 Parse the response format: "<DatTag>||<Signature>"
        size_t pos = resp.find("||");
        if (pos == std::string::npos) {
            std::cerr << "[User Error] Invalid payload format from Issuer." << std::endl;
            return -1;
        }

        std::string tag_str = resp.substr(0, pos);
        std::string sig_str = resp.substr(pos + 2);

        // Deserialize the Tag and the Signature (Witness)
        DatTws::DatTag tag = str_to_DatTag(tag_str);
        DatTws::DatWitness wit;
        wit.sigma_prime = str_to_ECP(sig_str);

        // 2.3 Derive T_sk = T_vk ^ usk
        ECP tsk_temp;
        ECP_copy(&tsk_temp, &tag.T_vk);
        ECP_mul(tsk_temp, user_keys.usk);

        // 2.4 Store into local vectors for future aggregation
        user_keys.tags.push_back(tag);
        user_keys.witnesses.push_back(wit);
        user_keys.T_sk.push_back(tsk_temp);

        std::cout << "[User] Successfully obtained Tag and Certificate from Issuer " << issuer_port << "." << std::endl;
        return 0;
    }

    // ============================================================
    // Step 3: Prove to Verifier
    // ============================================================
    int proveToVerifier(const std::string& verifier_ip, int verifier_port, const std::string& msg) {
        std::string verifier_uri = "ws://" + verifier_ip + ":" + std::to_string(verifier_port);
        std::cout << "\n[User] Generating Aggregated Zero-Knowledge Proof..." << std::endl;

        // ================= START TIMING: VERIFICATION =================
        auto t_verify_start = std::chrono::high_resolution_clock::now();

        // 3.1 Generate Signature
        DatTws::DatSignature sig = DatTws::Sign(pp, user_keys, msg);
        std::cout << "[User] Signature generated. Sending to Verifier..." << std::endl;

        // 3.2 Serialize Payload: "VERIFY||<msg>||<Signature>||<TagArray>"
        std::string payload = "VERIFY||" + msg + "||" + DatSignature_to_str(sig) + "||" + DatTagArr_to_str(user_keys.tags);

        // 3.3 Send to Verifier
        std::string resp = syncWebsocketRequest(verifier_uri, payload);

        // ================= END TIMING: VERIFICATION =================
        auto t_verify_end = std::chrono::high_resolution_clock::now();
        auto verify_duration = std::chrono::duration_cast<std::chrono::milliseconds>(t_verify_end - t_verify_start).count();

        std::cout << "=======================================================" << std::endl;
        std::cout << "[Verifier Response]: " << resp << std::endl;
        std::cout << ">>> Proof Gen + Verify Time (incl. network): " << verify_duration << " ms <<<" << std::endl;
        std::cout << "=======================================================" << std::endl;

        return 0;
    }

    // ============================================================
    // Main Execution
    // ============================================================

    int run(int num_issuers, int base_port) {
        // 1. Setup Phase
        if (registerWithRegulator() != 0) return -1;

        // ================= START TIMING: ISSUANCE =================
        auto t_issue_start = std::chrono::high_resolution_clock::now();

        // 2. Issuance Phase: Dynamically generate the list of Issuer IPs
        std::cout << "\n[User] Starting Issuance Phase with " << num_issuers << " Issuers..." << std::endl;
        std::vector<std::string> issuer_ips;
        for (int i = 1; i <= num_issuers; ++i) {
            // Generates 10.0.0.101, 10.0.0.102, etc.
            issuer_ips.push_back(ISSUER_SUBNET_PREFIX + std::to_string(100 + i));
        }

        // Sequentially request certificates from each configured Issuer
        // Note: We use the base_port since they can all bind to 8001 inside their own namespaces
        for (const std::string& ip : issuer_ips) {
            if (obtainCertificateFromIssuer(ip, base_port) != 0) {
                std::cerr << "[User Error] Failed to get certificate from " << ip << ". Skipping." << std::endl;
            }
        }
        // Ensure we obtained at least one certificate before proceeding
        if (user_keys.tags.empty()) {
            std::cerr << "[User Error] No certificates obtained. Aborting." << std::endl;
            return -1;
        }

        // ================= END TIMING: ISSUANCE =================
        auto t_issue_end = std::chrono::high_resolution_clock::now();
        auto issue_duration = std::chrono::duration_cast<std::chrono::milliseconds>(t_issue_end - t_issue_start).count();

        std::cout << "\n=======================================================" << std::endl;
        std::cout << ">>> Total Issuance Time (incl. network): " << issue_duration << " ms <<<" << std::endl;
        std::cout << "=======================================================\n" << std::endl;

        // 3. Verification Phase
        std::string test_msg = "Authorized Drone Deployment Request #42";
        proveToVerifier(VERIFIER_IP, std::stoi(VERIFIER_PORT), test_msg);

        return 0;
    }

} // namespace UserNode


// ============================================================
// Standalone Executable
// ============================================================
int main(int argc, char* argv[]) {
    // Parse command-line arguments:
    // Usage: ./user <num_issuers> <base_port>
    // Defaults: 3 Issuers, starting from port 8001
    int num_issuers = (argc >= 2) ? std::stoi(argv[1]) : 3;
    int base_port   = (argc >= 3) ? std::stoi(argv[2]) : 8001;

    return UserNode::run(num_issuers, base_port);
}