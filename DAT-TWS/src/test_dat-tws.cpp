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

    int t_num = 5; // Number of issuers for aggregation test

    // 2. Setup
    auto pp = DatTws::Setup();
    DatTws::DatOpener opener;
    vector<DatTws::DatIssuer> issuers;
    DatTws::DatUser user;

    // 3. KeyGen
    DatTws::KeyGen(pp, opener, issuers, t_num, user);

    // 4. TagGen & WitGen
    for(int i = 0; i < t_num; ++i) {
        auto tag = DatTws::TagGen(pp, issuers[i], user, opener);
        DatTws::WitGen(pp, issuers[i], user, tag, opener);
    }

    // 5. Sign
    string msg = "Hello World";
    auto sig = DatTws::Sign(pp, user, msg);

    // 6. Verify
    bool pass = DatTws::Verify(pp, sig, user.tags, msg);
    pass = pass && DatTws::parVerify(pp, sig, user.tags, msg);
    cout << "Verify Result: " << (pass ? "PASS" : "FAIL") << endl;

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
// Register all Benchmark tests
// ---------------------------------------------------------

// System setup doesn't scale with N, so no arguments needed
BENCHMARK(BM_DatTws_Setup);

// Protocol phases that scale with the number of issuers
// Testing typical scenarios: 5, 10, and 50 aggregated issuers
BENCHMARK(BM_DatTws_KeyGen)->Arg(5)->Arg(10)->Arg(50)->Iterations(66);
BENCHMARK(BM_DatTws_TagGen_WitGen)->Arg(5)->Arg(10)->Arg(50)->Iterations(66);
BENCHMARK(BM_DatTws_Sign)->Arg(5)->Arg(10)->Arg(50)->Iterations(66);
BENCHMARK(BM_DatTws_Verify)->Arg(5)->Arg(10)->Arg(50)->Iterations(66);
BENCHMARK(BM_DatTws_parVerify)->Arg(5)->Arg(10)->Arg(50)->Iterations(66);

// ---------------------------------------------------------
// Benchmark main entry point
// ---------------------------------------------------------
BENCHMARK_MAIN();