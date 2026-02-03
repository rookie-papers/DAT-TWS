#include "../include/IhMA.h"
#include <iostream>
#include <cstring>

using namespace std;

namespace IhMA {

    // Helper: Flatten AtoSaVK (3 G2 points) into a vector of G2 points for SPSEQ
    vector<ECP2> FlattenVK(const AtoSa::AtoSaVK& vk) {
        vector<ECP2> res;
        res.push_back(vk.Y1_hat);
        res.push_back(vk.Y2_hat);
        res.push_back(vk.X_hat);
        return res;
    }

    // ========================================================
    // ZKP Helper Functions (Fiat-Shamir with Optimization)
    // ========================================================

    // 1. Compute Alpha (Weight) alpha = H(h, T1, T2)
    mpz_class ComputeAlpha(ECP h, ECP T1, ECP T2) {
        octet hash_oct = getOctet(2048);
        octet temp = getOctet(1024);

        ECP_toOctet(&temp, &h, true); concatOctet(&hash_oct, &temp);
        ECP_toOctet(&temp, &T1, true); concatOctet(&hash_oct, &temp);
        ECP_toOctet(&temp, &T2, true); concatOctet(&hash_oct, &temp);

        BIG order_big, ret;
        BIG_rcopy(order_big, CURVE_Order);
        hashZp256(ret, &hash_oct, order_big);

        free(hash_oct.val); free(temp.val);
        return BIG_to_mpz(ret);
    }

    // 2. Compute Challenge e = H(h, T1, T2, alpha, R)
    mpz_class ComputeChallenge(ECP h, ECP T1, ECP T2, mpz_class alpha, ECP R) {
        octet hash_oct = getOctet(4096); // Larger buffer
        octet temp = getOctet(1024);

        // 1. Context (Statement)
        ECP_toOctet(&temp, &h, true);  concatOctet(&hash_oct, &temp);
        ECP_toOctet(&temp, &T1, true); concatOctet(&hash_oct, &temp);
        ECP_toOctet(&temp, &T2, true); concatOctet(&hash_oct, &temp);

        // 2. Weight (Alpha)
        ECP T_agg, T2_scaled;
        ECP_copy(&T_agg, &T1);
        ECP_copy(&T2_scaled, &T2);
        ECP_mul(T2_scaled, alpha);
        ECP_add(&T_agg, &T2_scaled);

        ECP_toOctet(&temp, &T_agg, true);
        concatOctet(&hash_oct, &temp);

        // 3. Commitment (R)
        ECP_toOctet(&temp, &R, true);
        concatOctet(&hash_oct, &temp);

        BIG order_big, ret;
        BIG_rcopy(order_big, CURVE_Order);
        hashZp256(ret, &hash_oct, order_big);

        free(hash_oct.val);
        free(temp.val);
        return BIG_to_mpz(ret);
    }

    IhMAZKProof ProveTag(IhMAParams pp, ECP h, ECP T1, ECP T2, mpz_class rho1, mpz_class rho2) {
        IhMAZKProof pi;

        // 1. Generate random weight alpha = H(h, T1, T2)
        mpz_class alpha = ComputeAlpha(h, T1, T2);

        // 2. Compute combined secret: x' = rho1 + alpha * rho2
        mpz_class combined_secret = (rho1 + alpha * rho2) % pp.pp_atosa.p;

        // 3. Schnorr Protocol
        // a. Commit: pick random k, R = k * h
        mpz_class k = rand_mpz(AtoSa::state_gmp) % pp.pp_atosa.p;
        ECP_copy(&pi.R, &h);
        ECP_mul(pi.R, k);

        // b. Challenge e = H(h, T1, T2, alpha, R)
        mpz_class e = ComputeChallenge(h, T1, T2, alpha, pi.R);

        // c. Response s = k + e * x'
        pi.s = (k + e * combined_secret) % pp.pp_atosa.p;

        return pi;
    }

    bool VerifyTag(ECP h, ECP T1, ECP T2, IhMAZKProof pi) {
        // 1. Recompute alpha
        mpz_class alpha = ComputeAlpha(h, T1, T2);

        // 2. Recompute Challenge e
        mpz_class e = ComputeChallenge(h, T1, T2, alpha, pi.R);

        // 3. Verify Equation: s * h ?= R + e * (T1 + alpha * T2)
        // Compute Combined Key T_agg = T1 + alpha * T2
        ECP T_agg, T2_scaled;
        ECP_copy(&T_agg, &T1);
        ECP_copy(&T2_scaled, &T2);
        ECP_mul(T2_scaled, alpha);
        ECP_add(&T_agg, &T2_scaled);

        // LHS = s * h
        ECP LHS;
        ECP_copy(&LHS, &h);
        ECP_mul(LHS, pi.s);

        // RHS = R + e * T_agg
        ECP RHS, T_agg_e;
        ECP_copy(&RHS, &pi.R);
        ECP_copy(&T_agg_e, &T_agg);
        ECP_mul(T_agg_e, e);
        ECP_add(&RHS, &T_agg_e);

        return ECP_equals(&LHS, &RHS);
    }

    // ========================================================
    // Main Implementation
    // ========================================================

    IhMAParams Setup() {
        IhMAParams pp;
        pp.pp_atosa = AtoSa::Setup();
        pp.pp_spseq = Spseq::Setup();
        return pp;
    }

    void IKeyGen(IhMAParams pp, IhMAIssuerKey& ik) {
        AtoSa::KeyGen(pp.pp_atosa, ik.isk, ik.ivk);
    }

    void UKeyGen(IhMAParams pp, const vector<string>& S, const vector<AtoSa::AtoSaVK>& issuers_vks, IhMAUserKey& uk) {
        AtoSa::AtoSaTag tag = AtoSa::GenAuxTag(pp.pp_atosa, S, issuers_vks);
        uk.T = tag;
        uk.aux = tag.aux;
        uk.tau_rho1 = tag.aux.rho1;
        uk.tau_rho2 = tag.aux.rho2;
    }

    bool Issuance(IhMAParams pp, IhMAIssuerKey ik, IhMAUserKey uk, string attr_val, IhMACredential& cred) {
        // --- 1. User Step: Generate ZK Proof pi ---
        // User proves knowledge of rho1, rho2 for Tag T with base h (from aux)
        IhMAZKProof pi = ProveTag(pp, uk.aux.h, uk.T.T1, uk.T.T2, uk.tau_rho1, uk.tau_rho2);

        // --- 2. Issuer Step: Verify ZK Proof pi ---
        // Issuer receives T, aux, pi. Extracts h from aux.
        if(!VerifyTag(uk.aux.h, uk.T.T1, uk.T.T2, pi)) {
            cout << "Issuance Failed: ZK Proof of Tag ownership invalid!" << endl;
            return false;
        }

        // --- 3. Issuer Step: Sign ---
        cred.attribute = attr_val;
        cred.sigma = AtoSa::Sign(pp.pp_atosa, ik.isk, uk.T, attr_val);
        return true;
    }

    void GenPolicies(IhMAParams pp, const vector<IhMAIssuerKey>& issuers,
                     vector<IhMAPolicy>& policies,
                     Spseq::SpseqSK& reg_sk, Spseq::SpseqPK& reg_pk) {
        int l = 3;
        Spseq::KeyGen(pp.pp_spseq, l, reg_sk, reg_pk);

        for(const auto& iss : issuers) {
            IhMAPolicy pol;
            pol.ivk = iss.ivk;
            vector<ECP2> msg_vec = FlattenVK(iss.ivk);
            pol.sigma_policy = Spseq::Sign(pp.pp_spseq, reg_sk, msg_vec);
            policies.push_back(pol);
        }
    }

    IhMAShowProof Show(IhMAParams pp, IhMAUserKey uk,
                       const vector<IhMACredential>& creds,
                       const vector<IhMAPolicy>& policies,
                       const vector<int>& D) {
        IhMAShowProof proof;

        // --- 1. Collect Data ---
        vector<AtoSa::AtoSaSignature> subset_sigs;
        vector<AtoSa::AtoSaVK> subset_vks;
        vector<Spseq::SpseqSignature> subset_policies;

        for(int idx : D) {
            subset_sigs.push_back(creds[idx].sigma);
            subset_vks.push_back(policies[idx].ivk);
            subset_policies.push_back(policies[idx].sigma_policy);
        }

        // --- 2. Randomization Scalars ---
        mpz_class omega = rand_mpz(AtoSa::state_gmp) % pp.pp_atosa.p;
        mpz_class nu = rand_mpz(AtoSa::state_gmp) % pp.pp_atosa.p;

        // --- 3. Process Policies & Keys ---
        for(size_t i = 0; i < subset_vks.size(); ++i) {
            // Randomize VK
            AtoSa::AtoSaVK rand_vk = AtoSa::ConvertVK(subset_vks[i], omega);
            proof.randomized_vks.push_back(rand_vk);

            // Randomize SPSEQ Sig (Simulating ChgRep logic manually)
            Spseq::SpseqSignature orig_sig = subset_policies[i];
            Spseq::SpseqSignature new_sig;

            mpz_class psi = rand_mpz(Spseq::state_gmp) % pp.pp_spseq.p;
            mpz_class psi_inv = invert_mpz(psi, pp.pp_spseq.p);

            mpz_class scalar_z = (psi * omega) % pp.pp_spseq.p;
            ECP2_copy(&new_sig.Z, &orig_sig.Z);
            ECP2_mul(new_sig.Z, scalar_z);

            ECP_copy(&new_sig.Y, &orig_sig.Y);
            ECP_mul(new_sig.Y, psi_inv);

            ECP2_copy(&new_sig.Y_hat, &orig_sig.Y_hat);
            ECP2_mul(new_sig.Y_hat, psi_inv);

            proof.randomized_policies.push_back(new_sig);
        }

        // --- 4. Process Credentials (AtoSa) ---
        AtoSa::AtoSaSignature agg_sig = AtoSa::AggrSign(subset_sigs);
        AtoSa::AtoSaSignature sig_omega = AtoSa::ConvertSig(agg_sig, omega);

        // Randomize Tag (Nym) and Sig
        proof.nym = uk.T;
        proof.sigma_agg_prime = sig_omega;
        AtoSa::AtoSaVK dummy_vk;
        AtoSa::RandSigTag(dummy_vk, proof.nym, "", proof.sigma_agg_prime, nu);

        // --- 5. Zero-Knowledge Proof for Nym (T') ---
        // Nym is T randomized by nu.
        // T1' = T1^nu = h^(rho1 * nu)
        // T2' = T2^nu = h^(rho2 * nu)
        // Secrets for Nym are (rho1*nu, rho2*nu).
        // Base h remains the same (from aux).

        mpz_class nym_rho1 = (uk.tau_rho1 * nu) % pp.pp_atosa.p;
        mpz_class nym_rho2 = (uk.tau_rho2 * nu) % pp.pp_atosa.p;

        // Generate ZK Proof
        proof.pi = ProveTag(pp, uk.aux.h, proof.nym.T1, proof.nym.T2, nym_rho1, nym_rho2);

        return proof;
    }

    bool CredVerify(IhMAParams pp,
                    Spseq::SpseqPK regulator_pk,
                    IhMAShowProof proof,
                    const vector<string>& revealed_attributes) {

        // 1. Verify SPSEQ on Randomized VKs
        if(proof.randomized_vks.size() != proof.randomized_policies.size()) return false;

        for(size_t i = 0; i < proof.randomized_vks.size(); ++i) {
            vector<ECP2> msg_vec = FlattenVK(proof.randomized_vks[i]);
            if(!Spseq::Verify(pp.pp_spseq, regulator_pk, msg_vec, proof.randomized_policies[i])) {
                cout << "CredVerify: SPSEQ Failed." << endl;
                return false;
            }
        }

        // 2. Verify AtoSa Aggregate Sig
        if(!AtoSa::VerifyAggr(pp.pp_atosa, proof.randomized_vks, proof.nym, revealed_attributes, proof.sigma_agg_prime)) {
            cout << "CredVerify: AtoSa Sig Failed." << endl;
            return false;
        }

        // 3. Verify ZK Proof of Nym ownership
        if(!VerifyTag(proof.nym.aux.h, proof.nym.T1, proof.nym.T2, proof.pi)) {
            cout << "CredVerify: ZK Proof of Nym Failed." << endl;
            return false;
        }

        return true;
    }

} // namespace IhMA