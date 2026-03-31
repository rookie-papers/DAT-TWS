#include "../include/dat-tws.h"
#include <iostream>
#include <vector>
#include <benchmark/benchmark.h>

using namespace std;

// ================= Main =================

/*
int main() {
    // 1. Initialize environment
    initState(DatTws::state_gmp);
    initRNG(&DatTws::rng);

    cout << "=== Running DAT-TWS Protocol ===" << endl;

    int t_num = 5; // Number of issuers per user

    // 2. Setup System Parameters
    auto pp = DatTws::Setup();
    DatTws::DatOpener opener;

    // =========================================================
    // (Single User Verification)
    // =========================================================
    cout << "\n--- Testing Single User Verification ---" << endl;
    vector<DatTws::DatIssuer> single_issuers;
    DatTws::DatUser single_user;

    DatTws::KeyGen(pp, opener, single_issuers, t_num, single_user);

    for(int i = 0; i < t_num; ++i) {
        auto tag = DatTws::TagGen(pp, single_issuers[i], single_user, opener);
        DatTws::WitGen(pp, single_issuers[i], single_user, tag, opener);
    }

    string single_msg = "Hello World";
    auto single_sig = DatTws::Sign(pp, single_user, single_msg);

    bool single_pass = DatTws::Verify(pp, single_sig, single_user.tags, single_msg);
    single_pass = single_pass && DatTws::parVerify(pp, single_sig, single_user.tags, single_msg);
    cout << "Single Verify Result: " << (single_pass ? "PASS" : "FAIL") << endl;


    // =========================================================
    // (Multi-User Batch Verification)
    // =========================================================
    cout << "\n--- Testing Multi-User Batch Verification ---" << endl;

    int num_users = 8; // Simulating 3 concurrent distinct users
    vector<DatTws::DatSignature> batch_sigs;
    vector<vector<DatTws::DatTag>> batch_tags;
    vector<string> batch_msgs;

    for (int j = 0; j < num_users; ++j) {
        DatTws::DatUser current_user;
        vector<DatTws::DatIssuer> current_issuers;
        DatTws::KeyGen(pp, opener, current_issuers, t_num, current_user);

        for(int i = 0; i < t_num; ++i) {
            auto tag = DatTws::TagGen(pp, current_issuers[i], current_user, opener);
            DatTws::WitGen(pp, current_issuers[i], current_user, tag, opener);
        }

        string current_msg = "Authorized Drone Deployment Request User#" + to_string(j);

        batch_sigs.push_back(DatTws::Sign(pp, current_user, current_msg));
        batch_tags.push_back(current_user.tags);
        batch_msgs.push_back(current_msg);
    }

    bool batch_pass = DatTws::batchVerifyAll(pp, batch_sigs, batch_tags, batch_msgs);
    cout << "Batch Verify Result (" << num_users << " Distinct Users):  " << (batch_pass ? "PASS" : "FAIL") << endl;

    return 0;
}
 */


// ---------------------------------------------------------
// Helper to initialize RNG for all benchmarks
// ---------------------------------------------------------
static void InitRNGs() {
    static bool initialized = false;
    if (!initialized) {
        initState(DatTws::state_gmp);
        // initRNG(&DatTws::rng);
        initialized = true;
    }
}

// ---------------------------------------------------------
// 1. Test Setup (System Initialization)
// ---------------------------------------------------------
static void BM_DatTws_Setup(benchmark::State &state) {
    InitRNGs();

    for (auto _ : state) {
        auto pp = DatTws::Setup();
    }
}

// ---------------------------------------------------------
// 2. Test KeyGen (Generates Opener, User, and N Issuers keys)
// ---------------------------------------------------------
static void BM_DatTws_KeyGen(benchmark::State &state) {
    InitRNGs();
    int t_num = state.range(0); // Number of issuers

    auto pp = DatTws::Setup();
    DatTws::DatOpener opener;
    DatTws::DatUser user;
    vector<DatTws::DatIssuer> issuers;

    for (auto _ : state) {
        issuers.clear(); // Clear vector for accurate memory/time measurement in loops
        DatTws::KeyGen(pp, opener, issuers, t_num, user);
    }
}

// ---------------------------------------------------------
// 3. Test TagGen & WitGen (Batch Processing for N Issuers)
// ---------------------------------------------------------
static void BM_DatTws_TagGen_WitGen(benchmark::State &state) {
    InitRNGs();
    int t_num = state.range(0);

    // Setup and Key Generation (Outside the timing loop)
    auto pp = DatTws::Setup();
    DatTws::DatOpener opener;
    DatTws::DatUser user;
    vector<DatTws::DatIssuer> issuers;
    DatTws::KeyGen(pp, opener, issuers, t_num, user);

    for (auto _ : state) {
        // Clear user collections to avoid infinite memory growth across iterations
        user.tags.clear();
        user.witnesses.clear();
        user.T_sk.clear();

        for(int i = 0; i < t_num; ++i) {
            auto tag = DatTws::TagGen(pp, issuers[i], user, opener);
            DatTws::WitGen(pp, issuers[i], user, tag, opener);
        }
    }
}

// ---------------------------------------------------------
// 4. Test Sign (Generating an aggregated signature for N tags)
// ---------------------------------------------------------
static void BM_DatTws_Sign(benchmark::State &state) {
    InitRNGs();
    int t_num = state.range(0);

    // Setup, KeyGen, and Tag/Witness generation
    auto pp = DatTws::Setup();
    DatTws::DatOpener opener;
    DatTws::DatUser user;
    vector<DatTws::DatIssuer> issuers;
    DatTws::KeyGen(pp, opener, issuers, t_num, user);

    for(int i = 0; i < t_num; ++i) {
        auto tag = DatTws::TagGen(pp, issuers[i], user, opener);
        DatTws::WitGen(pp, issuers[i], user, tag, opener);
    }

    string msg = "Hello World Benchmark";

    for (auto _ : state) {
        auto sig = DatTws::Sign(pp, user, msg);
    }
}

// ---------------------------------------------------------
// 5. Test Verify (Verifying the aggregated signature for N tags)
// ---------------------------------------------------------
static void BM_DatTws_Verify(benchmark::State &state) {
    InitRNGs();
    int t_num = state.range(0);

    // Complete entire protocol up to signing
    auto pp = DatTws::Setup();
    DatTws::DatOpener opener;
    DatTws::DatUser user;
    vector<DatTws::DatIssuer> issuers;
    DatTws::KeyGen(pp, opener, issuers, t_num, user);

    for(int i = 0; i < t_num; ++i) {
        auto tag = DatTws::TagGen(pp, issuers[i], user, opener);
        DatTws::WitGen(pp, issuers[i], user, tag, opener);
    }

    string msg = "Hello World Benchmark";
    auto sig = DatTws::Sign(pp, user, msg);

    for (auto _ : state) {
        bool pass = DatTws::Verify(pp, sig, user.tags, msg);
    }
}

// ---------------------------------------------------------
// 6. Test parVerify (Verifying the aggregated signature for N tags)
// ---------------------------------------------------------
static void BM_DatTws_parVerify(benchmark::State &state) {
    InitRNGs();
    int t_num = state.range(0);

    // Complete entire protocol up to signing
    auto pp = DatTws::Setup();
    DatTws::DatOpener opener;
    DatTws::DatUser user;
    vector<DatTws::DatIssuer> issuers;
    DatTws::KeyGen(pp, opener, issuers, t_num, user);

    for(int i = 0; i < t_num; ++i) {
        auto tag = DatTws::TagGen(pp, issuers[i], user, opener);
        DatTws::WitGen(pp, issuers[i], user, tag, opener);
    }

    string msg = "Hello World Benchmark";
    auto sig = DatTws::Sign(pp, user, msg);

    for (auto _ : state) {
        bool pass = DatTws::parVerify(pp, sig, user.tags, msg);
    }
}

// ---------------------------------------------------------
// 7. Test batchVerifyZK (Batch verifying ZK Proofs for M users)
// ---------------------------------------------------------
static void BM_DatTws_batchVerifyZK(benchmark::State &state) {
    InitRNGs();
    int M = state.range(0); // Number of signatures in the batch
    int t_num = 5;          // Assume 5 issuers per user

    auto pp = DatTws::Setup();
    DatTws::DatOpener opener;

    vector<DatTws::DatSignature> sigs;
    vector<vector<DatTws::DatTag>> all_tags;

    // Pre-generate M signatures
    for(int j = 0; j < M; ++j) {
        DatTws::DatUser user;
        vector<DatTws::DatIssuer> issuers;
        DatTws::KeyGen(pp, opener, issuers, t_num, user);
        for(int i = 0; i < t_num; ++i) {
            auto tag = DatTws::TagGen(pp, issuers[i], user, opener);
            DatTws::WitGen(pp, issuers[i], user, tag, opener);
        }
        sigs.push_back(DatTws::Sign(pp, user, "Batch Msg"));
        all_tags.push_back(user.tags);
    }

    for (auto _ : state) {
        bool pass = DatTws::batchVerifyZK(pp, sigs, all_tags);
    }
}

// ---------------------------------------------------------
// 8. Test batchParVerify (Batch verifying Message Sigs for M users)
// ---------------------------------------------------------
static void BM_DatTws_batchParVerify(benchmark::State &state) {
    InitRNGs();
    int M = state.range(0);
    int t_num = 5;

    auto pp = DatTws::Setup();
    DatTws::DatOpener opener;

    vector<DatTws::DatSignature> sigs;
    vector<vector<DatTws::DatTag>> all_tags;
    vector<string> msgs;

    for(int j = 0; j < M; ++j) {
        DatTws::DatUser user;
        vector<DatTws::DatIssuer> issuers;
        DatTws::KeyGen(pp, opener, issuers, t_num, user);
        for(int i = 0; i < t_num; ++i) {
            auto tag = DatTws::TagGen(pp, issuers[i], user, opener);
            DatTws::WitGen(pp, issuers[i], user, tag, opener);
        }
        string msg = "Batch Msg " + to_string(j);
        sigs.push_back(DatTws::Sign(pp, user, msg));
        all_tags.push_back(user.tags);
        msgs.push_back(msg);
    }

    for (auto _ : state) {
        bool pass = DatTws::batchParVerify(pp, sigs, all_tags, msgs);
    }
}

// ---------------------------------------------------------
// 9. Test batchVerifyAll (Complete Batch Verification for M users)
// ---------------------------------------------------------
static void BM_DatTws_batchVerifyAll(benchmark::State &state) {
    InitRNGs();
    int M = state.range(0);
    int t_num = 5;

    auto pp = DatTws::Setup();
    DatTws::DatOpener opener;

    vector<DatTws::DatSignature> sigs;
    vector<vector<DatTws::DatTag>> all_tags;
    vector<string> msgs;

    for(int j = 0; j < M; ++j) {
        DatTws::DatUser user;
        vector<DatTws::DatIssuer> issuers;
        DatTws::KeyGen(pp, opener, issuers, t_num, user);
        for(int i = 0; i < t_num; ++i) {
            auto tag = DatTws::TagGen(pp, issuers[i], user, opener);
            DatTws::WitGen(pp, issuers[i], user, tag, opener);
        }
        string msg = "Batch Msg " + to_string(j);
        sigs.push_back(DatTws::Sign(pp, user, msg));
        all_tags.push_back(user.tags);
        msgs.push_back(msg);
    }

    for (auto _ : state) {
        bool pass = DatTws::batchVerifyAll(pp, sigs, all_tags, msgs);
    }
}

// ---------------------------------------------------------
// Register all Benchmark tests
// ---------------------------------------------------------

// System setup doesn't scale with N, so no arguments needed
BENCHMARK(BM_DatTws_Setup);

// Protocol phases that scale with the number of issuers
// Testing typical scenarios: 4, 8, 16, and 32 aggregated issuers
BENCHMARK(BM_DatTws_KeyGen)->Arg(4)->Arg(8)->Arg(16)->Arg(32)->Iterations(66);
BENCHMARK(BM_DatTws_TagGen_WitGen)->Arg(4)->Arg(8)->Arg(16)->Arg(32)->Iterations(66);
BENCHMARK(BM_DatTws_Sign)->Arg(4)->Arg(8)->Arg(16)->Arg(32)->Iterations(66);
BENCHMARK(BM_DatTws_Verify)->Arg(4)->Arg(8)->Arg(16)->Arg(32)->Iterations(66);
BENCHMARK(BM_DatTws_parVerify)->Arg(4)->Arg(8)->Arg(16)->Arg(32)->Iterations(66);
// Batch verification scales with the number of USERS (M) in the batch.
// Assuming a fixed 5 issuers per user, testing for 4, 8, 16, 32, 64 concurrent Users.
BENCHMARK(BM_DatTws_batchVerifyZK)->Arg(4)->Arg(8)->Arg(16)->Arg(32)->Arg(64)->Iterations(20);
BENCHMARK(BM_DatTws_batchParVerify)->Arg(4)->Arg(8)->Arg(16)->Arg(32)->Arg(64)->Iterations(20);
BENCHMARK(BM_DatTws_batchVerifyAll)->Arg(4)->Arg(8)->Arg(16)->Arg(32)->Arg(64)->Iterations(20);

// ---------------------------------------------------------
// Benchmark main entry point
// ---------------------------------------------------------
//BENCHMARK_MAIN();