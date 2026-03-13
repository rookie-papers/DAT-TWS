#include "../include/ntat.h"
#include <iostream>

using namespace std;
using namespace Ntat;

int main() {
    // 1. Initialize the random number generator environment
    initState(Ntat::state_gmp);
    initRNG(&Ntat::rng);

    cout << "=== Starting Pairing-Based NTAT Test (Appendix D.1 Variant) ===" << endl;

    // 2. Initialize system parameters (Setup)
    cout << "[1] Generating system public parameters..." << endl;
    NtatParams pp = Setup();

    // 3. Generate key pairs for the client and the server
    cout << "[2] Generating client and server key pairs..." << endl;
    ClientKeys client_keys = ClientKeyGen(pp);
    ServerKeys server_keys = ServerKeyGen(pp);

    // ==========================================
    // Issuance Phase
    // ==========================================
    cout << "\n--- Phase 1: Issuance ---" << endl;

    // Step 1: Client initiates a query, generating a blinded commitment T and a NIZK proof Pi_c
    ClientState st;
    QueryPayload query = ClientQuery(pp, client_keys, st);
    cout << "  -> ClientQuery completed. Generated T and Pi_c proof." << endl;

    // Step 2: Server processes the query, verifies Pi_c, and issues a response
    ServerIssueResp issue_resp = ServerIssue(pp, server_keys, client_keys.pk_c, query);
    if (issue_resp.s == -1) {
        cout << "  -> [Error] ServerIssue failed: Client's Pi_c proof is invalid!" << endl;
        return -1;
    }
    cout << "  -> ServerIssue completed. Server generated issuance response (s, S)." << endl;

    // Step 3: Client finalizes the credential construction (includes bilinear pairing verification)
    NtatToken token = ClientFinal(pp, server_keys.pk_s, st, issue_resp);

    // Simple check to ensure the generated token is valid (s == 0 and r == 0 usually implies failure)
    if (token.s == 0 && token.r == 0) {
        cout << "  -> [Error] ClientFinal failed: Server response failed bilinear pairing verification!" << endl;
        return -1;
    }
    cout << "  -> ClientFinal completed. Client successfully obtained NTAT credential (sigma, r, s)." << endl;

    // ==========================================
    // Redemption Phase
    // ==========================================
    cout << "\n--- Phase 2: Redemption ---" << endl;

    // Step 1: Client generates a redemption proof (converted to non-interactive mode using Fiat-Shamir)
    RedeemPayload redeem_payload = ClientProve(pp, client_keys, server_keys.pk_s, token);
    cout << "  -> ClientProve completed. Generated redemption payload (includes sigma, sigma', comm, v0, v1, v2)." << endl;

    // Step 2: Server publicly verifies the redemption proof
    bool is_valid = ServerVerify(pp, server_keys.pk_s, redeem_payload);

    cout << "\n==========================================" << endl;
    if (is_valid) {
        cout << ">>> Test PASS! Credential redemption verification succeeded." << endl;
    } else {
        cout << ">>> Test FAIL! Credential redemption verification failed." << endl;
    }
    cout << "==========================================" << endl;

    return 0;
}