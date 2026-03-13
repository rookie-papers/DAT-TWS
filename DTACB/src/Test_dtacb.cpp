#include "../include/dtacb.h"
#include <iostream>
#include <vector>
#include <numeric>   // For std::iota
#include <algorithm> // For std::shuffle
#include <random>    // For random number generation
#include <benchmark/benchmark.h>

using namespace std;

//int main() {
//    // ============================================
//    // 1. Initialization
//    // ============================================
//    initState(Dtacb::state_gmp);
//    initRNG(&Dtacb::rng);
//
//    cout << "=== Running DTACB Full Protocol ===" << endl;
//
//    // ============================================
//    // 2. Configuration (Dynamic Settings)
//    // ============================================
//    int n_issuers = 10;                 // Total number of issuers in the system
//    int threshold = 7;                  // Dynamic threshold (number of required signatures)
//
//    int acc_capacity = 100;             // Maximum capacity of the accumulator (t)
//    int total_acc_elements = n_issuers; // Total number of valid credentials in the system (|D|)
//    int user_batch_size = threshold;    // Number of credentials the user wants to show in batch (|P|)
//
//    // Parameter validity checks
//    if (threshold > n_issuers) {
//        cerr << "Error: Threshold cannot exceed the total number of issuers!" << endl;
//        return -1;
//    }
//    if (total_acc_elements > acc_capacity) {
//        cerr << "Error: Total accumulator elements cannot exceed maximum capacity (t)!" << endl;
//        return -1;
//    }
//    if (user_batch_size > total_acc_elements) {
//        cerr << "Error: User's batch size cannot exceed the total number of system credentials!" << endl;
//        return -1;
//    }
//
//    // ============================================
//    // 3. System & Issuer Setup
//    // ============================================
//    Dtacb::DtacbParams pp = Dtacb::Setup(acc_capacity);
//    vector<Dtacb::Issuer> issuers;
//
//    Dtacb::IKGen(pp, issuers, n_issuers);
//    cout << "[Setup] Generated " << n_issuers << " Issuers and Accumulator parameters." << endl;
//
//    // Generate dynamic threshold bit vector (b)
//    vector<uint8_t> b(n_issuers, 0);
//    vector<int> indices(n_issuers);
//    iota(indices.begin(), indices.end(), 0);
//
//    random_device rd;
//    mt19937 g(rd());
//    shuffle(indices.begin(), indices.end(), g);
//
//    for(int i = 0; i < threshold; ++i) {
//        b[indices[i]] = 1;
//    }
//
//    cout << "[Config] Dynamic threshold bit vector b: [ ";
//    for(int val : b) cout << (int)val << " ";
//    cout << "] (Selected " << threshold << " issuers)" << endl;
//
//    // ============================================
//    // 4. User Registration (Obtain Phase)
//    // ============================================
//    Dtacb::User user;
//    mpz_class m = 12345; // User's hidden attribute/message
//    mpz_class l = 67890; // Random scalar for commitment
//
//    Dtacb::RegInfo reg = Dtacb::Obtain(pp, user, m, l);
//    cout << "[Obtain] User generated blinded registration data (c_m, Z, C1, C2)." << endl;
//
//    // Pre-compute base element h for subsequent unblinding
//    ECP h = Dtacb::H1(reg.c_m);
//
//    // ============================================
//    // 5. Credential Issuance & Unblinding
//    // ============================================
//    vector<Dtacb::PartialCred> partials;
//
//    for(int i = 0; i < n_issuers; ++i) {
//        if(b[i] == 1) { // Issue only from dynamically selected issuers
//            Dtacb::BlindedPartialCred b_cred = Dtacb::Issue(pp, issuers[i], reg);
//            Dtacb::PartialCred pcred = Dtacb::Unblind(pp, user, b_cred, h);
//            partials.push_back(pcred);
//        }
//    }
//    cout << "[Issue] Successfully obtained and unblinded " << partials.size() << " partial credentials." << endl;
//
//    // ============================================
//    // 6. Credential Aggregation
//    // ============================================
//    Dtacb::Credential cred = Dtacb::AggCred(partials);
//    cout << "[AggCred] Partial credentials successfully aggregated." << endl;
//
//    // ============================================
//    // 7. Credential Proving (ProveCred)
//    // ============================================
//    Dtacb::ProveToken tok = Dtacb::ProveCred(pp, cred, m, partials, issuers, b);
//    cout << "[Prove] Generated NIZK token embedded with dynamic bit vector b." << endl;
//
//    // ============================================
//    // 8. Credential Verification (VerCred)
//    // ============================================
//    bool pass = Dtacb::VerCred(pp, tok);
//    cout << ">>> Base Credential Verification Result: " << (pass ? "PASS" : "FAIL") << endl;
//
//    if (!pass) return -1; // Halt if base verification fails
//
//    // ============================================
//    // 9. Batch-Showing Setup (Dynamic Simulation)
//    // ============================================
//    cout << "\n=== Entering Batch-Showing & Verification Phase ===" << endl;
//
//    vector<mpz_class> D_set;      // Global accumulator set D
//    vector<mpz_class> P_set;      // User's valid credential subset P
//    vector<mpz_class> remain_set; // Credentials in D but not in P (D \ P)
//
//    // Extract the witness (sigma_1) from the recently verified credential
//    mpz_class sigma_1 = Dtacb::H2(tok.CRED_prime);
//    P_set.push_back(sigma_1);
//    D_set.push_back(sigma_1);
//
//    // Simulate remaining valid credentials owned by the user
//    for (int i = 1; i < user_batch_size; ++i) {
//        mpz_class sig = rand_mpz(Dtacb::state_gmp) % pp.q;
//        P_set.push_back(sig);
//        D_set.push_back(sig);
//    }
//
//    // Simulate other credentials in the system NOT owned by the user
//    for (int i = user_batch_size; i < total_acc_elements; ++i) {
//        mpz_class sig = rand_mpz(Dtacb::state_gmp) % pp.q;
//        remain_set.push_back(sig);
//        D_set.push_back(sig);
//    }
//
//    // ============================================
//    // 10. Accumulator & PFD Aggregation
//    // ============================================
//    // Judger evaluates the global accumulator Acc = g1^{\prod_{d \in D} (s+d)}
//    vector<mpz_class> D_coeffs = Dtacb::GetPolyCoeffs(pp.q, D_set);
//    ECP Acc; ECP_inf(&Acc);
//    for (size_t i = 0; i < D_coeffs.size(); ++i) {
//        ECP term;
//        if (i == 0) ECP_copy(&term, &pp.g1);
//        else ECP_copy(&term, &pp.acc_g1_s[i - 1]);
//        ECP_mul(term, D_coeffs[i]);
//        ECP_add(&Acc, &term);
//    }
//    cout << "[Accumulator] Judger computed global Acc (Total " << D_set.size() << " elements)." << endl;
//
//    // User aggregates membership proofs via PFD: Pi = g1^{\prod_{d \in D \setminus P} (s+d)}
//    vector<mpz_class> Pi_coeffs = Dtacb::GetPolyCoeffs(pp.q, remain_set);
//    ECP Pi; ECP_inf(&Pi);
//    for (size_t i = 0; i < Pi_coeffs.size(); ++i) {
//        ECP term;
//        if (i == 0) ECP_copy(&term, &pp.g1);
//        else ECP_copy(&term, &pp.acc_g1_s[i - 1]);
//        ECP_mul(term, Pi_coeffs[i]);
//        ECP_add(&Pi, &term);
//    }
//    cout << "[AggProof] User aggregated " << P_set.size() << " proofs into a single Pi via PFD." << endl;
//
//    // ============================================
//    // 11. ZK Batch-Showing (Prover)
//    // ============================================
//    Dtacb::BatchProof batch_proof = Dtacb::ZKBatchShow(pp, Acc, Pi, P_set);
//    cout << "[ZKBatchShow] User generated ZK batch proof (Hiding specific credentials, claiming " << P_set.size() << " valid credentials)." << endl;
//
//    // ============================================
//    // 12. ZK Batch-Verification (Verifier)
//    // ============================================
//    bool batch_pass = Dtacb::ZKBatchVer(pp, Acc, batch_proof, P_set.size());
//    cout << ">>> DTACB Batch Verify Result: " << (batch_pass ? "PASS" : "FAIL") << endl;
//
//    return 0;
//}



// ---------------------------------------------------------
// Helper to initialize RNG for all benchmarks
// ---------------------------------------------------------
static void InitRNGs() {
    static bool initialized = false;
    if (!initialized) {
        initState(Dtacb::state_gmp);
        initRNG(&Dtacb::rng);
        initialized = true;
    }
}

// ---------------------------------------------------------
// 1. Test Setup (System & Accumulator Initialization)
// ---------------------------------------------------------
static void BM_Dtacb_Setup(benchmark::State &state) {
    InitRNGs();
    int acc_capacity = state.range(0); // Test different accumulator capacities

    for (auto _ : state) {
        Dtacb::DtacbParams pp = Dtacb::Setup(acc_capacity);
    }
}

// ---------------------------------------------------------
// 2. Test IKGen (Issuer Key Generation)
// ---------------------------------------------------------
static void BM_Dtacb_IKGen(benchmark::State &state) {
    InitRNGs();
    int acc_capacity = 100;
    Dtacb::DtacbParams pp = Dtacb::Setup(acc_capacity);
    int n_issuers = state.range(0);
    vector<Dtacb::Issuer> issuers;

    for (auto _ : state) {
        issuers.clear();
        Dtacb::IKGen(pp, issuers, n_issuers);
    }
}

// ---------------------------------------------------------
// 3. Test Obtain (User Registration & Commitment)
// ---------------------------------------------------------
static void BM_Dtacb_Obtain(benchmark::State &state) {
    InitRNGs();
    int acc_capacity = 100;
    Dtacb::DtacbParams pp = Dtacb::Setup(acc_capacity);

    Dtacb::User user;
    mpz_class m = 12345;
    mpz_class l = 67890;

    for (auto _ : state) {
        Dtacb::RegInfo reg = Dtacb::Obtain(pp, user, m, l);
    }
}

// ---------------------------------------------------------
// 4. Test Issue & Unblind (Threshold Issuance Process)
// ---------------------------------------------------------
static void BM_Dtacb_Issue_Unblind(benchmark::State &state) {
    InitRNGs();
    int threshold = state.range(0);

    Dtacb::DtacbParams pp = Dtacb::Setup(100);
    vector<Dtacb::Issuer> issuers;
    Dtacb::IKGen(pp, issuers, threshold); // Just generate 'threshold' issuers for testing

    Dtacb::User user;
    mpz_class m = 12345, l = 67890;
    Dtacb::RegInfo reg = Dtacb::Obtain(pp, user, m, l);
    ECP h = Dtacb::H1(reg.c_m);

    for (auto _ : state) {
        vector<Dtacb::PartialCred> partials;
        for(int i = 0; i < threshold; ++i) {
            Dtacb::BlindedPartialCred b_cred = Dtacb::Issue(pp, issuers[i], reg);
            Dtacb::PartialCred pcred = Dtacb::Unblind(pp, user, b_cred, h);
            partials.push_back(pcred);
        }
    }
}

// ---------------------------------------------------------
// 5. Test AggCred (Aggregating Partial Credentials)
// ---------------------------------------------------------
static void BM_Dtacb_AggCred(benchmark::State &state) {
    InitRNGs();
    int threshold = state.range(0);

    Dtacb::DtacbParams pp = Dtacb::Setup(100);
    vector<Dtacb::Issuer> issuers;
    Dtacb::IKGen(pp, issuers, threshold);

    Dtacb::User user;
    mpz_class m = 12345, l = 67890;
    Dtacb::RegInfo reg = Dtacb::Obtain(pp, user, m, l);
    ECP h = Dtacb::H1(reg.c_m);

    vector<Dtacb::PartialCred> partials;
    for(int i = 0; i < threshold; ++i) {
        Dtacb::BlindedPartialCred b_cred = Dtacb::Issue(pp, issuers[i], reg);
        partials.push_back(Dtacb::Unblind(pp, user, b_cred, h));
    }

    for (auto _ : state) {
        Dtacb::Credential cred = Dtacb::AggCred(partials);
    }
}

// ---------------------------------------------------------
// 6. Test ProveCred (Generating NIZK Token with Bit Vector)
// ---------------------------------------------------------
static void BM_Dtacb_ProveCred(benchmark::State &state) {
    InitRNGs();
    int n_issuers = state.range(0);
    int threshold = state.range(1);

    Dtacb::DtacbParams pp = Dtacb::Setup(100);
    vector<Dtacb::Issuer> issuers;
    Dtacb::IKGen(pp, issuers, n_issuers);

    vector<uint8_t> b(n_issuers, 0);
    for(int i = 0; i < threshold; ++i) b[i] = 1; // Simplified continuous selection

    Dtacb::User user;
    mpz_class m = 12345, l = 67890;
    Dtacb::RegInfo reg = Dtacb::Obtain(pp, user, m, l);
    ECP h = Dtacb::H1(reg.c_m);

    vector<Dtacb::PartialCred> partials;
    for(int i = 0; i < n_issuers; ++i) {
        if (b[i] == 1) {
            Dtacb::BlindedPartialCred b_cred = Dtacb::Issue(pp, issuers[i], reg);
            partials.push_back(Dtacb::Unblind(pp, user, b_cred, h));
        }
    }
    Dtacb::Credential cred = Dtacb::AggCred(partials);

    for (auto _ : state) {
        Dtacb::ProveToken tok = Dtacb::ProveCred(pp, cred, m, partials, issuers, b);
    }
}

// ---------------------------------------------------------
// 7. Test VerCred (Judger Verifying the Credential)
// ---------------------------------------------------------
static void BM_Dtacb_VerCred(benchmark::State &state) {
    InitRNGs();
    int n_issuers = state.range(0);
    int threshold = state.range(1);

    Dtacb::DtacbParams pp = Dtacb::Setup(100);
    vector<Dtacb::Issuer> issuers;
    Dtacb::IKGen(pp, issuers, n_issuers);

    vector<uint8_t> b(n_issuers, 0);
    for(int i = 0; i < threshold; ++i) b[i] = 1;

    Dtacb::User user;
    mpz_class m = 12345, l = 67890;
    Dtacb::RegInfo reg = Dtacb::Obtain(pp, user, m, l);
    ECP h = Dtacb::H1(reg.c_m);

    vector<Dtacb::PartialCred> partials;
    for(int i = 0; i < n_issuers; ++i) {
        if (b[i] == 1) {
            Dtacb::BlindedPartialCred b_cred = Dtacb::Issue(pp, issuers[i], reg);
            partials.push_back(Dtacb::Unblind(pp, user, b_cred, h));
        }
    }
    Dtacb::Credential cred = Dtacb::AggCred(partials);
    Dtacb::ProveToken tok = Dtacb::ProveCred(pp, cred, m, partials, issuers, b);

    for (auto _ : state) {
        bool pass = Dtacb::VerCred(pp, tok);
    }
}

// ---------------------------------------------------------
// 8. Test ZKBatchShow (User generates Batch Proof)
// ---------------------------------------------------------
static void BM_Dtacb_ZKBatchShow(benchmark::State &state) {
    InitRNGs();
    int total_acc_elements = state.range(0);
    int user_batch_size = state.range(1);

    Dtacb::DtacbParams pp = Dtacb::Setup(total_acc_elements + 50); // Ensure capacity > total elements

    // Prepare simulated accumulator and subset data
    vector<mpz_class> D_set;
    vector<mpz_class> P_set;
    vector<mpz_class> remain_set;

    for (int i = 0; i < user_batch_size; ++i) {
        mpz_class sig = rand_mpz(Dtacb::state_gmp) % pp.q;
        P_set.push_back(sig);
        D_set.push_back(sig);
    }
    for (int i = user_batch_size; i < total_acc_elements; ++i) {
        mpz_class sig = rand_mpz(Dtacb::state_gmp) % pp.q;
        remain_set.push_back(sig);
        D_set.push_back(sig);
    }

    // Pre-compute Accumulator
    vector<mpz_class> D_coeffs = Dtacb::GetPolyCoeffs(pp.q, D_set);
    ECP Acc; ECP_inf(&Acc);
    for (size_t i = 0; i < D_coeffs.size(); ++i) {
        ECP term;
        if (i == 0) ECP_copy(&term, &pp.g1);
        else ECP_copy(&term, &pp.acc_g1_s[i - 1]);
        ECP_mul(term, D_coeffs[i]);
        ECP_add(&Acc, &term);
    }

    // Pre-compute PFD Aggregation (Pi)
    vector<mpz_class> Pi_coeffs = Dtacb::GetPolyCoeffs(pp.q, remain_set);
    ECP Pi; ECP_inf(&Pi);
    for (size_t i = 0; i < Pi_coeffs.size(); ++i) {
        ECP term;
        if (i == 0) ECP_copy(&term, &pp.g1);
        else ECP_copy(&term, &pp.acc_g1_s[i - 1]);
        ECP_mul(term, Pi_coeffs[i]);
        ECP_add(&Pi, &term);
    }

    for (auto _ : state) {
        Dtacb::BatchProof batch_proof = Dtacb::ZKBatchShow(pp, Acc, Pi, P_set);
    }
}

// ---------------------------------------------------------
// 9. Test ZKBatchVer (Judger verifies Batch Proof)
// ---------------------------------------------------------
static void BM_Dtacb_ZKBatchVer(benchmark::State &state) {
    InitRNGs();
    int total_acc_elements = state.range(0);
    int user_batch_size = state.range(1);

    Dtacb::DtacbParams pp = Dtacb::Setup(total_acc_elements + 50);

    vector<mpz_class> D_set, P_set, remain_set;
    for (int i = 0; i < user_batch_size; ++i) {
        mpz_class sig = rand_mpz(Dtacb::state_gmp) % pp.q;
        P_set.push_back(sig);
        D_set.push_back(sig);
    }
    for (int i = user_batch_size; i < total_acc_elements; ++i) {
        mpz_class sig = rand_mpz(Dtacb::state_gmp) % pp.q;
        remain_set.push_back(sig);
        D_set.push_back(sig);
    }

    vector<mpz_class> D_coeffs = Dtacb::GetPolyCoeffs(pp.q, D_set);
    ECP Acc; ECP_inf(&Acc);
    for (size_t i = 0; i < D_coeffs.size(); ++i) {
        ECP term;
        if (i == 0) ECP_copy(&term, &pp.g1);
        else ECP_copy(&term, &pp.acc_g1_s[i - 1]);
        ECP_mul(term, D_coeffs[i]);
        ECP_add(&Acc, &term);
    }

    vector<mpz_class> Pi_coeffs = Dtacb::GetPolyCoeffs(pp.q, remain_set);
    ECP Pi; ECP_inf(&Pi);
    for (size_t i = 0; i < Pi_coeffs.size(); ++i) {
        ECP term;
        if (i == 0) ECP_copy(&term, &pp.g1);
        else ECP_copy(&term, &pp.acc_g1_s[i - 1]);
        ECP_mul(term, Pi_coeffs[i]);
        ECP_add(&Pi, &term);
    }

    Dtacb::BatchProof batch_proof = Dtacb::ZKBatchShow(pp, Acc, Pi, P_set);

    for (auto _ : state) {
        bool batch_pass = Dtacb::ZKBatchVer(pp, Acc, batch_proof, P_set.size());
    }
}

// ---------------------------------------------------------
// Register all Benchmark tests
// ---------------------------------------------------------

// Single Argument tests
BENCHMARK(BM_Dtacb_Setup)->Arg(4)->Arg(8)->Arg(16)->Arg(32);
BENCHMARK(BM_Dtacb_IKGen)->Arg(4)->Arg(8)->Arg(16)->Arg(32);
BENCHMARK(BM_Dtacb_Obtain);
BENCHMARK(BM_Dtacb_Issue_Unblind)->Arg(4)->Arg(8)->Arg(16)->Arg(32);
BENCHMARK(BM_Dtacb_AggCred)->Arg(4)->Arg(8)->Arg(16)->Arg(32);

// Multiple Arguments tests (n_issuers, threshold)
// e.g., 4 issuers/4 threshold, 32 issuers/32 threshold
BENCHMARK(BM_Dtacb_ProveCred)->Args({4, 4})->Args({8, 8})->Args({16, 16})->Args({32, 32});
BENCHMARK(BM_Dtacb_VerCred)->Args({4, 4})->Args({8, 8})->Args({16, 16})->Args({32, 32});
BENCHMARK(BM_Dtacb_ZKBatchShow)->Args({4, 4})->Args({8, 8})->Args({16, 16})->Args({32, 32});
BENCHMARK(BM_Dtacb_ZKBatchVer)->Args({4, 4})->Args({8, 8})->Args({16, 16})->Args({32, 32});

// ---------------------------------------------------------
// Benchmark main entry point
// ---------------------------------------------------------
BENCHMARK_MAIN();