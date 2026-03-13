#include "../include/ntat.h"
#include <iostream>
#include <benchmark/benchmark.h>

using namespace std;
using namespace Ntat;

//int main() {
//    // 1. Initialize the random number generator environment
//    initState(Ntat::state_gmp);
//    initRNG(&Ntat::rng);
//
//    cout << "=== Starting Pairing-Based NTAT Test (Appendix D.1 Variant) ===" << endl;
//
//    // 2. Initialize system parameters (Setup)
//    cout << "[1] Generating system public parameters..." << endl;
//    NtatParams pp = Setup();
//
//    // 3. Generate key pairs for the client and the server
//    cout << "[2] Generating client and server key pairs..." << endl;
//    ClientKeys client_keys = ClientKeyGen(pp);
//    ServerKeys server_keys = ServerKeyGen(pp);
//
//    // ==========================================
//    // Issuance Phase
//    // ==========================================
//    cout << "\n--- Phase 1: Issuance ---" << endl;
//
//    // Step 1: Client initiates a query, generating a blinded commitment T and a NIZK proof Pi_c
//    ClientState st;
//    QueryPayload query = ClientQuery(pp, client_keys, st);
//    cout << "  -> ClientQuery completed. Generated T and Pi_c proof." << endl;
//
//    // Step 2: Server processes the query, verifies Pi_c, and issues a response
//    ServerIssueResp issue_resp = ServerIssue(pp, server_keys, client_keys.pk_c, query);
//    if (issue_resp.s == -1) {
//        cout << "  -> [Error] ServerIssue failed: Client's Pi_c proof is invalid!" << endl;
//        return -1;
//    }
//    cout << "  -> ServerIssue completed. Server generated issuance response (s, S)." << endl;
//
//    // Step 3: Client finalizes the credential construction (includes bilinear pairing verification)
//    NtatToken token = ClientFinal(pp, server_keys.pk_s, st, issue_resp);
//
//    // Simple check to ensure the generated token is valid (s == 0 and r == 0 usually implies failure)
//    if (token.s == 0 && token.r == 0) {
//        cout << "  -> [Error] ClientFinal failed: Server response failed bilinear pairing verification!" << endl;
//        return -1;
//    }
//    cout << "  -> ClientFinal completed. Client successfully obtained NTAT credential (sigma, r, s)." << endl;
//
//    // ==========================================
//    // Redemption Phase
//    // ==========================================
//    cout << "\n--- Phase 2: Redemption ---" << endl;
//
//    // Step 1: Client generates a redemption proof (converted to non-interactive mode using Fiat-Shamir)
//    RedeemPayload redeem_payload = ClientProve(pp, client_keys, server_keys.pk_s, token);
//    cout << "  -> ClientProve completed. Generated redemption payload (includes sigma, sigma', comm, v0, v1, v2)." << endl;
//
//    // Step 2: Server publicly verifies the redemption proof
//    bool is_valid = ServerVerify(pp, server_keys.pk_s, redeem_payload);
//
//    cout << "\n==========================================" << endl;
//    if (is_valid) {
//        cout << ">>> Test PASS! Credential redemption verification succeeded." << endl;
//    } else {
//        cout << ">>> Test FAIL! Credential redemption verification failed." << endl;
//    }
//    cout << "==========================================" << endl;
//
//    return 0;
//}

// ---------------------------------------------------------
// 1. Test Setup (System Initialization)
// ---------------------------------------------------------
static void BM_Ntat_Setup(benchmark::State &state) {
    initState(state_gmp);
    initRNG(&rng);

    for (auto _ : state) {
        NtatParams pp = Setup();
    }
}

// ---------------------------------------------------------
// 2. Test KeyGen (Client and Server Key Generation)
// ---------------------------------------------------------
static void BM_Ntat_KeyGen(benchmark::State &state) {
    initState(state_gmp);
    initRNG(&rng);
    NtatParams pp = Setup();

    for (auto _ : state) {
        ClientKeys ck = ClientKeyGen(pp);
        ServerKeys sk = ServerKeyGen(pp);
    }
}

// ---------------------------------------------------------
// 3. Test Issuance Phase 1: ClientQuery
//    (Client generates commitment and NIZK proof)
// ---------------------------------------------------------
static void BM_Ntat_ClientQuery(benchmark::State &state) {
    initState(state_gmp);
    initRNG(&rng);
    NtatParams pp = Setup();
    ClientKeys ck = ClientKeyGen(pp);
    ClientState st;

    for (auto _ : state) {
        QueryPayload query = ClientQuery(pp, ck, st);
    }
}

// ---------------------------------------------------------
// 4. Test Issuance Phase 2: ServerIssue
//    (Server verifies proof and blindly signs)
// ---------------------------------------------------------
static void BM_Ntat_ServerIssue(benchmark::State &state) {
    initState(state_gmp);
    initRNG(&rng);
    NtatParams pp = Setup();
    ClientKeys ck = ClientKeyGen(pp);
    ServerKeys sk = ServerKeyGen(pp);
    ClientState st;

    // Prepare query in advance to exclude client-side time from the benchmark
    QueryPayload query = ClientQuery(pp, ck, st);

    for (auto _ : state) {
        ServerIssueResp resp = ServerIssue(pp, sk, ck.pk_c, query);
    }
}

// ---------------------------------------------------------
// 5. Test Issuance Phase 3: ClientFinal
//    (Client unblinds and verifies bilinear pairing)
// ---------------------------------------------------------
static void BM_Ntat_ClientFinal(benchmark::State &state) {
    initState(state_gmp);
    initRNG(&rng);
    NtatParams pp = Setup();
    ClientKeys ck = ClientKeyGen(pp);
    ServerKeys sk = ServerKeyGen(pp);
    ClientState st;

    QueryPayload query = ClientQuery(pp, ck, st);
    ServerIssueResp resp = ServerIssue(pp, sk, ck.pk_c, query);

    for (auto _ : state) {
        NtatToken token = ClientFinal(pp, sk.pk_s, st, resp);
    }
}

// ---------------------------------------------------------
// 6. Test Redemption Phase 1: ClientProve
//    (Client generates non-interactive redemption proof)
// ---------------------------------------------------------
static void BM_Ntat_ClientProve(benchmark::State &state) {
    initState(state_gmp);
    initRNG(&rng);
    NtatParams pp = Setup();
    ClientKeys ck = ClientKeyGen(pp);
    ServerKeys sk = ServerKeyGen(pp);
    ClientState st;

    // Complete Issuance phase in advance to obtain the Token
    QueryPayload query = ClientQuery(pp, ck, st);
    ServerIssueResp resp = ServerIssue(pp, sk, ck.pk_c, query);
    NtatToken token = ClientFinal(pp, sk.pk_s, st, resp);

    for (auto _ : state) {
        RedeemPayload payload = ClientProve(pp, ck, sk.pk_s, token);
    }
}

// ---------------------------------------------------------
// 7. Test Redemption Phase 2: ServerVerify
//    (Server verifies redemption proof and bilinear pairing)
// ---------------------------------------------------------
static void BM_Ntat_ServerVerify(benchmark::State &state) {
    initState(state_gmp);
    initRNG(&rng);
    NtatParams pp = Setup();
    ClientKeys ck = ClientKeyGen(pp);
    ServerKeys sk = ServerKeyGen(pp);
    ClientState st;

    // Prepare all payloads in advance, only testing the server's verification overhead
    QueryPayload query = ClientQuery(pp, ck, st);
    ServerIssueResp resp = ServerIssue(pp, sk, ck.pk_c, query);
    NtatToken token = ClientFinal(pp, sk.pk_s, st, resp);
    RedeemPayload payload = ClientProve(pp, ck, sk.pk_s, token);

    for (auto _ : state) {
        bool res = ServerVerify(pp, sk.pk_s, payload);
    }
}

// ---------------------------------------------------------
// Register all Benchmark tests
// ---------------------------------------------------------
BENCHMARK(BM_Ntat_Setup);
BENCHMARK(BM_Ntat_KeyGen);
BENCHMARK(BM_Ntat_ClientQuery);
BENCHMARK(BM_Ntat_ServerIssue);
BENCHMARK(BM_Ntat_ClientFinal);
BENCHMARK(BM_Ntat_ClientProve);
BENCHMARK(BM_Ntat_ServerVerify);

// ---------------------------------------------------------
// Benchmark main entry point
// ---------------------------------------------------------
BENCHMARK_MAIN();