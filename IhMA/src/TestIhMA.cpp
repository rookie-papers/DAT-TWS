#include "../include/IhMA.h"
#include <iostream>
#include <string>

using namespace std;

int main() {
    // ============================================
    // 1. Initialization
    // ============================================

    // Initialize AtoSa RNG
    initState(AtoSa::state_gmp);
    initRNG(&AtoSa::rng);

    // Initialize Spseq RNG
    initState(Spseq::state_gmp);
    initRNG(&Spseq::rng);

    cout << "=== Running IhMA Full Protocol ===" << endl;

    // 2. Setup
    auto pp = IhMA::Setup();

    int n_issuers = 5; // Change this value to test performance (e.g., 5, 10, 50)

    // 3. Issuer Setup
    vector<IhMA::IhMAIssuerKey> issuers(n_issuers);
    vector<AtoSa::AtoSaVK> issuer_vks_only;
    cout << "[Setup] Generating " << n_issuers << " Issuers..." << endl;
    for(int i=0; i<n_issuers; ++i) {
        IhMA::IKeyGen(pp, issuers[i]);
        issuer_vks_only.push_back(issuers[i].ivk);
    }

    // 4. Regulator Setup (Gen-Policies)
    Spseq::SpseqSK reg_sk;
    Spseq::SpseqPK reg_pk;

    // 5. Regulator Signs Policies
    vector<IhMA::IhMAPolicy> policies;
    IhMA::GenPolicies(pp, issuers, policies, reg_sk, reg_pk);

    // 6. User Setup
    IhMA::IhMAUserKey uk;

    // Dynamically generate attribute list based on n_issuers
    vector<string> attributes;
    for(int i = 0; i < n_issuers; ++i) {
        attributes.push_back("Attribute_" + to_string(i));
    }

    IhMA::UKeyGen(pp, attributes, issuer_vks_only, uk);

    // 7. Issuance
    vector<IhMA::IhMACredential> credentials;
    for(int i=0; i<n_issuers; ++i) {
        IhMA::IhMACredential cred;
        IhMA::Issuance(pp, issuers[i], uk, attributes[i], cred);
        credentials.push_back(cred);
    }

    // 8. Show (Prover)
    // Dynamically generate disclosure set D (Revealing all attributes here)
    vector<int> D;
    for(int i = 0; i < n_issuers; ++i) {
        D.push_back(i);
    }

    auto proof = IhMA::Show(pp, uk, credentials, policies, D);

    // 9. Verify (Verifier)
    // Verifier reconstructs the list of revealed attribute values based on D
    vector<string> revealed_attributes;
    for(int idx : D) {
        revealed_attributes.push_back(attributes[idx]);
    }

    bool result = IhMA::CredVerify(pp, reg_pk, proof, revealed_attributes);

    if(result) {
        cout << ">>> IhMA Protocol Result: PASS" << endl;
    } else {
        cout << ">>> IhMA Protocol Result: FAIL" << endl;
    }

    return 0;
}













//#include "../include/SPSEQ.h"
//#include "../include/AtoSa.h"
//#include <iostream>
//#include <string>
//#include <vector>
//
//using namespace std;
//
//// Helper to generate random Group Element in G2
//ECP2 randG2(Spseq::SpseqParams pp) {
//    ECP2 P;
//    ECP2_copy(&P, &pp.P_hat);
//    mpz_class r = rand_mpz(Spseq::state_gmp);
//    ECP2_mul(P, r);
//    return P;
//}
//
//int main() {
//    // ------------------------------------------------------------------
//    // Part 1: AtoSa (Aggregate to Single) & Randomization Extensions
//    // ------------------------------------------------------------------
//
//    // 1. Initialize environment
//    initState(AtoSa::state_gmp);
//    initRNG(&AtoSa::rng);
//
//    cout << "=== Running AtoSa Protocol & Extensions ===" << endl;
//
//    // 2. Setup
//    auto pp = AtoSa::Setup();
//    cout << "[Setup] Parameters generated." << endl;
//
//    int num_users = 2; // Reduced for cleaner output
//    vector<AtoSa::AtoSaSK> sks(num_users);
//    vector<AtoSa::AtoSaVK> vks(num_users);
//    vector<string> msgs;
//
//    // 3. KeyGen
//    cout << "[KeyGen] Generating keys..." << endl;
//    for (int i = 0; i < num_users; ++i) {
//        AtoSa::KeyGen(pp, sks[i], vks[i]);
//        msgs.push_back("Message_" + to_string(i));
//    }
//
//    // 4. Tag Gen
//    cout << "[TagGen] Generating Tag..." << endl;
//    auto tag = AtoSa::GenAuxTag(pp, msgs, vks);
//
//    // 5. Sign (Individual)
//    cout << "[Sign] Generating signatures..." << endl;
//    vector<AtoSa::AtoSaSignature> sigs;
//    for (int i = 0; i < num_users; ++i) {
//        auto sig = AtoSa::Sign(pp, sks[i], tag, msgs[i]);
//        sigs.push_back(sig);
//    }
//
//    // 6. Aggregate
//    cout << "[AggrSign] Aggregating..." << endl;
//    auto agg_sig = AtoSa::AggrSign(sigs);
//
//    // 7. Verify Original Aggregation
//    cout << "[Verify] Verifying original aggregated signature..." << endl;
//    bool pass = AtoSa::VerifyAggr(pp, vks, tag, msgs, agg_sig);
//    cout << ">>> Result: " << (pass ? "PASS" : "FAIL") << endl;
//
//    if(!pass) return 1;
//
//    // --- AtoSa Extension Tests (IhMA required functions) ---
//    cout << "\n--- Testing AtoSa Randomization (RandSigTag / ConvertVK) ---" << endl;
//
//    // 8. Test RandSigTag (User randomization)
//    // Randomize Tag and Signature
//    mpz_class nu = rand_mpz(AtoSa::state_gmp) % pp.p;
//    AtoSa::AtoSaTag randomized_tag = tag;
//    AtoSa::AtoSaSignature randomized_sig = agg_sig;
//
//    // Call the function added in previous step
//    // Note: We pass vks[0] and msgs[0] just to satisfy signature, though only nu is used algebraically
//    AtoSa::RandSigTag(vks[0], randomized_tag, msgs[0], randomized_sig, nu);
//
//    // 9. Test Verification of Randomized Tag
//    // For verification to pass, the VKs must NOT change yet (only tag/sig randomized),
//    // BUT VerifyAggr checks e(T2, ...) vs e(sig, ...).
//    // T2' = T2^nu, s' = s^nu. Equation should still hold if everything is raised to nu.
//    cout << "[Verify] Verifying randomized tag/signature with original keys..." << endl;
//    bool pass_rand = AtoSa::VerifyAggr(pp, vks, randomized_tag, msgs, randomized_sig);
//    cout << ">>> Result: " << (pass_rand ? "PASS" : "FAIL") << endl;
//
//    // 10. Test Key Conversion (ConvertVK + ConvertSig)
//    // Simulate re-randomizing keys by a scalar omega
//    mpz_class omega = rand_mpz(AtoSa::state_gmp) % pp.p;
//
//    vector<AtoSa::AtoSaVK> converted_vks;
//    for(auto& vk : vks) {
//        converted_vks.push_back(AtoSa::ConvertVK(vk, omega));
//    }
//
//    // Signature must also be adapted: s'' = s'^omega
//    AtoSa::AtoSaSignature fully_randomized_sig = AtoSa::ConvertSig(randomized_sig, omega);
//
//    cout << "[Verify] Verifying fully randomized (Keys+Tag) proof..." << endl;
//    bool pass_full = AtoSa::VerifyAggr(pp, converted_vks, randomized_tag, msgs, fully_randomized_sig);
//    cout << ">>> Result: " << (pass_full ? "PASS" : "FAIL") << endl;
//
//    cout << "---------------------------------------------" << endl;
//
//
//    // ------------------------------------------------------------------
//    // Part 2: SPSEQ (Modified for G2 Messages)
//    // ------------------------------------------------------------------
//
//    cout << "\n=== Running SPSEQ Scheme (G2 Messages) ===" << endl;
//
//    // 1. Init
//    initState(Spseq::state_gmp);
//    initRNG(&Spseq::rng);
//
//    // 2. Setup
//    Spseq::SpseqParams ppp = Spseq::Setup();
//    cout << "[Setup] Done." << endl;
//
//    // 3. KeyGen
//    int l = 5; // Vector length
//    Spseq::SpseqSK sk;
//    Spseq::SpseqPK pk;
//    Spseq::KeyGen(ppp, l, sk, pk);
//    cout << "[KeyGen] Keys generated (PK in G1)." << endl;
//
//    // 4. Prepare Message (Vector of G2 points)
//    // CHANGED: Using ECP2 type for message
//    vector<ECP2> M(l);
//    cout << "[Message] Generating random G2 message vector..." << endl;
//    for (int i = 0; i < l; ++i) {
//        M[i] = randECP2(Spseq::rng);
//    }
//
//    // 5. Sign
//    cout << "[Sign] Signing G2 message..." << endl;
//    auto sig = Spseq::Sign(ppp, sk, M);
//
//    // 6. Verify Original
//    cout << "[Verify] Verifying original signature..." << endl;
//    pass = Spseq::Verify(ppp, pk, M, sig);
//    cout << ">>> Result: " << (pass ? "PASS" : "FAIL") << endl;
//
//    if (!pass) return 1;
//
//    // 7. Change Representative (ChgRep)
//    cout << "\n=== Testing SPSEQ ChgRep ===" << endl;
//
//    // Choose scalar mu
//    mpz_class mu = rand_mpz(Spseq::state_gmp) % pp.p;
//    cout << "Chosen randomization scalar mu." << endl;
//
//    // Transform Signature
//    cout << "[ChgRep] Transforming signature..." << endl;
//    auto new_sig = Spseq::ChgRep(ppp, pk, M, sig, mu);
//
//    // Transform Message M' = mu * M (Simulating equivalence class change in G2)
//    vector<ECP2> M_prime(l);
//    for (int i = 0; i < l; ++i) {
//        ECP2_copy(&M_prime[i], &M[i]);
//        ECP2_mul(M_prime[i], mu);
//    }
//
//    // 8. Verify Transformed
//    // The new signature should be valid for M' = mu * M
//    cout << "[Verify] Verifying transformed signature on M'..." << endl;
//    bool pass_chg = Spseq::Verify(ppp, pk, M_prime, new_sig);
//    cout << ">>> Result: " << (pass_chg ? "PASS" : "FAIL") << endl;
//
//    return 0;
//}