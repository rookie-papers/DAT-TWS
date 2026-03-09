#include "../include/dtacb.h"
#include <iostream>

namespace Dtacb {

    // ---------------- Accumulator & Batch Algorithms ----------------

    // Expands the polynomial P(s) = (s + r_1)(s + r_2)... to obtain the coefficient array [c_0, c_1, ..., c_n]
    // such that P(s) = c_0 + c_1*s + c_2*s^2 + ... + c_n*s^n
    vector<mpz_class> GetPolyCoeffs(mpz_class q, const vector<mpz_class>& roots) {
        vector<mpz_class> coeffs = {1}; // Initialize with 1 (coefficient of s^0)
        for (const auto& r : roots) {
            vector<mpz_class> next_coeffs(coeffs.size() + 1, 0);
            for (size_t i = 0; i < coeffs.size(); ++i) {
                // Multiply by s (shift coefficient to higher degree)
                next_coeffs[i + 1] = (next_coeffs[i + 1] + coeffs[i]) % q;
                // Multiply by r (multiply current coefficient by constant term)
                mpz_class term = (coeffs[i] * r) % q;
                next_coeffs[i] = (next_coeffs[i] + term) % q;
            }
            coeffs = next_coeffs;
        }
        return coeffs;
    }

    mpz_class Hash_Batch(ECP2 CM_P, ECP2 CM_f, ECP Pi_a, ECP Pi_b, ECP T1, ECP T2, FP12 T3) {
        octet hash = getOctet(4096);
        octet temp = getOctet(1024);

        // Append G2 elements
        ECP2* pts_g2[] = {&CM_P, &CM_f};
        for (int i = 0; i < 2; ++i) { ECP2_toOctet(&temp, pts_g2[i], true); concatOctet(&hash, &temp); }

        // Append G1 elements
        ECP* pts_g1[] = {&Pi_a, &Pi_b, &T1, &T2};
        for (int i = 0; i < 4; ++i) { ECP_toOctet(&temp, pts_g1[i], true); concatOctet(&hash, &temp); }

        // Append GT element
        FP12_toOctet(&temp, &T3);
        concatOctet(&hash, &temp);

        // Compute hash in Zp
        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);
        free(hash.val); free(temp.val);
        return BIG_to_mpz(ret);
    }

    BatchProof ZKBatchShow(DtacbParams& pp, ECP Acc, ECP Pi, const vector<mpz_class>& P_set) {
        BatchProof proof;
        int n = P_set.size();

        // 1. Compute the coefficients of the polynomial P(s) = s^n + f(s)
        vector<mpz_class> coeffs = GetPolyCoeffs(pp.q, P_set);

        // 2. Choose random blinding factors
        mpz_class tau1 = rand_mpz(state_gmp) % pp.q;
        mpz_class tau2 = rand_mpz(state_gmp) % pp.q;
        mpz_class j = rand_mpz(state_gmp) % pp.q;
        mpz_class delta1 = (tau1 * j) % pp.q;
        mpz_class delta2 = (tau2 * j) % pp.q;

        mpz_class w1 = rand_mpz(state_gmp) % pp.q;
        mpz_class w2 = rand_mpz(state_gmp) % pp.q;
        mpz_class w3 = rand_mpz(state_gmp) % pp.q;
        mpz_class w4 = rand_mpz(state_gmp) % pp.q;
        mpz_class w5 = rand_mpz(state_gmp) % pp.q;

        // 3. Compute commitment CM_P = \tilde{g}_2^j * g_2^{P(s)}
        ECP2_inf(&proof.CM_P);

        // Add \tilde{g}_2^j
        ECP2 t_g2_j; ECP2_copy(&t_g2_j, &pp.g2_tilde); ECP2_mul(t_g2_j, j);
        ECP2_add(&proof.CM_P, &t_g2_j);

        // Add g_2^{P(s)} = \prod (g_2^{s^k})^{c_k}
        for (int k = 0; k <= n; ++k) {
            ECP2 term;
            if (k == 0) ECP2_copy(&term, &pp.g2);
            else ECP2_copy(&term, &pp.acc_g2_s[k-1]);
            ECP2_mul(term, coeffs[k]);
            ECP2_add(&proof.CM_P, &term);
        }

        // 4. Compute remainder commitment CM_f = CM_P / g_2^{s^n}
        ECP2_copy(&proof.CM_f, &proof.CM_P);
        ECP2 sn_inv; ECP2_copy(&sn_inv, &pp.acc_g2_s[n-1]);
        ECP2_neg(&sn_inv); // Equivalent to inversion / subtraction in additive group
        ECP2_add(&proof.CM_f, &sn_inv);

        // 5. Randomize aggregated membership proof Pi to get Pi_a and Pi_b
        // Pi_a = g1^tau1 * \tilde{g}_1^tau2
        ECP t1; ECP_copy(&t1, &pp.g1); ECP_mul(t1, tau1);
        ECP t2; ECP_copy(&t2, &pp.g1_tilde); ECP_mul(t2, tau2);
        ECP_copy(&proof.Pi_a, &t1); ECP_add(&proof.Pi_a, &t2);

        // Pi_b = Pi * \tilde{g}_1^tau1
        ECP t3; ECP_copy(&t3, &pp.g1_tilde); ECP_mul(t3, tau1);
        ECP_copy(&proof.Pi_b, &Pi); ECP_add(&proof.Pi_b, &t3);

        // 6. Compute zero-knowledge components T1 and T2
        ECP_copy(&proof.T1, &pp.g1); ECP_mul(proof.T1, w1);
        ECP t4; ECP_copy(&t4, &pp.g1_tilde); ECP_mul(t4, w2);
        ECP_add(&proof.T1, &t4);

        ECP_copy(&proof.T2, &proof.Pi_a); ECP_mul(proof.T2, w3);
        ECP t5; ECP_copy(&t5, &pp.g1); ECP_mul(t5, (pp.q - w4) % pp.q);
        ECP t6; ECP_copy(&t6, &pp.g1_tilde); ECP_mul(t6, (pp.q - w5) % pp.q);
        ECP_add(&proof.T2, &t5); ECP_add(&proof.T2, &t6);

        // 7. Compute pairing-based zero-knowledge component T3
        // T3 = e(\tilde{g}_1, CM_P)^w1 * e(\tilde{g}_1, \tilde{g}_2)^{-w4} * e(Pi_b, \tilde{g}_2)^w3
        FP12 e1 = e(pp.g1_tilde, proof.CM_P); FP12_pow(e1, w1);
        FP12 e2 = e(pp.g1_tilde, pp.g2_tilde); FP12_pow(e2, (pp.q - w4) % pp.q);
        FP12 e3 = e(proof.Pi_b, pp.g2_tilde); FP12_pow(e3, w3);

        FP12_copy(&proof.T3, &e1);
        FP12_mulMy(proof.T3, e2); FP12_mulMy(proof.T3, e3);
        FP12_reduce(&proof.T3);

        // 8. Compute Fiat-Shamir challenge c
        mpz_class c = Hash_Batch(proof.CM_P, proof.CM_f, proof.Pi_a, proof.Pi_b, proof.T1, proof.T2, proof.T3);

        // 9. Compute shifted commitments CM and CM^u for degree bounding
        // CM = g_2^{f(s) * c * s^{t-n+1}} * \tilde{g}_2^{j * c * s^{t-n+1}}
        ECP2_inf(&proof.CM);
        ECP2_inf(&proof.CM_u);

        int shift = pp.t - n + 1;

        // Shift the remainder polynomial f(s) (degree up to n-1)
        for(int k = 0; k < n; ++k) {
            mpz_class exp_val = (coeffs[k] * c) % pp.q;
            int target_pow = k + shift; // Range shifts from [0, n-1] to [t-n+1, t]

            ECP2 term; ECP2_copy(&term, &pp.acc_g2_s[target_pow - 1]);
            ECP2_mul(term, exp_val);
            ECP2_add(&proof.CM, &term);

            ECP2 term_u; ECP2_copy(&term_u, &pp.acc_g2_us[target_pow - 1]);
            ECP2_mul(term_u, exp_val);
            ECP2_add(&proof.CM_u, &term_u);
        }

        // Add \tilde{g}_2 shift components using accumulator parameters
        mpz_class jc = (j * c) % pp.q;
        int shift_idx = shift - 1; // Array index is 0-based

        // Use \tilde{g}_2^{s^{t-n+1}}
        ECP2 t_g2_jc;
        ECP2_copy(&t_g2_jc, &pp.acc_g2_tilde_s[shift_idx]);
        ECP2_mul(t_g2_jc, jc);
        ECP2_add(&proof.CM, &t_g2_jc);

        // Use \tilde{g}_2^{u * s^{t-n+1}}
        ECP2 t_g2_jc_u;
        ECP2_copy(&t_g2_jc_u, &pp.acc_g2_tilde_us[shift_idx]);
        ECP2_mul(t_g2_jc_u, jc);
        ECP2_add(&proof.CM_u, &t_g2_jc_u);

        // 10. Compute zero-knowledge responses
        proof.W_j = (w3 + c * j) % pp.q;
        proof.W_tau1 = (w1 + c * tau1) % pp.q;
        proof.W_tau2 = (w2 + c * tau2) % pp.q;
        proof.W_delta1 = (w4 + c * delta1) % pp.q;
        proof.W_delta2 = (w5 + c * delta2) % pp.q;

        return proof;
    }

    bool ZKBatchVer(DtacbParams& pp, ECP Acc, BatchProof& pf, int n) {
        // Recompute Fiat-Shamir challenge
        mpz_class c = Hash_Batch(pf.CM_P, pf.CM_f, pf.Pi_a, pf.Pi_b, pf.T1, pf.T2, pf.T3);

        // Check 1: Verify T1 correctness
        // T1 ?= Pi_a^{-c} g1^{W_tau1} \tilde{g}_1^{W_tau2}
        ECP chk1; ECP_copy(&chk1, &pf.Pi_a); ECP_mul(chk1, (pp.q - c) % pp.q);
        ECP t1; ECP_copy(&t1, &pp.g1); ECP_mul(t1, pf.W_tau1);
        ECP t2; ECP_copy(&t2, &pp.g1_tilde); ECP_mul(t2, pf.W_tau2);
        ECP_add(&chk1, &t1); ECP_add(&chk1, &t2);
        if (!ECP_equals(&pf.T1, &chk1)) { cout << "[ZKBatchVer] Fail: T1 verification failed" << endl; return false; }

        // Check 2: Verify T2 correctness
        // T2 ?= Pi_a^{W_j} g1^{-W_delta1} \tilde{g}_1^{-W_delta2}
        ECP chk2; ECP_copy(&chk2, &pf.Pi_a); ECP_mul(chk2, pf.W_j);
        ECP t3; ECP_copy(&t3, &pp.g1); ECP_mul(t3, (pp.q - pf.W_delta1) % pp.q);
        ECP t4; ECP_copy(&t4, &pp.g1_tilde); ECP_mul(t4, (pp.q - pf.W_delta2) % pp.q);
        ECP_add(&chk2, &t3); ECP_add(&chk2, &t4);
        if (!ECP_equals(&pf.T2, &chk2)) { cout << "[ZKBatchVer] Fail: T2 verification failed" << endl; return false; }

        // Check 3: Verify T3 using bilinear pairings (Membership Check)
        FP12 e_Pib_CMP = e(pf.Pi_b, pf.CM_P);
        FP12 e_Acc_g2 = e(Acc, pp.g2);
        FP12_inv(e_Acc_g2);
        FP12 ratio; FP12_copy(&ratio, &e_Pib_CMP); FP12_mulMy(ratio, e_Acc_g2);
        FP12_pow(ratio, c);

        FP12 LHS; FP12_copy(&LHS, &pf.T3); FP12_mulMy(LHS, ratio); FP12_reduce(&LHS);

        FP12 RHS1 = e(pp.g1_tilde, pf.CM_P); FP12_pow(RHS1, pf.W_tau1);
        FP12 RHS2 = e(pp.g1_tilde, pp.g2_tilde); FP12_pow(RHS2, (pp.q - pf.W_delta1) % pp.q);
        FP12 RHS3 = e(pf.Pi_b, pp.g2_tilde); FP12_pow(RHS3, pf.W_j);

        FP12 RHS; FP12_copy(&RHS, &RHS1);
        FP12_mulMy(RHS, RHS2); FP12_mulMy(RHS, RHS3); FP12_reduce(&RHS);

        if (!FP12_equals(&LHS, &RHS)) { cout << "[ZKBatchVer] Fail: T3 pairings check failed" << endl; return false; }

        // Check 4: Verify degree bound to confirm exactly 'n' credentials
        // e(g1, CM_P) ?= e(g1, CM_f) * e(g1, g2^{s^n})
        FP12 chk4_L = e(pp.g1, pf.CM_P); FP12_reduce(&chk4_L);
        FP12 chk4_R1 = e(pp.g1, pf.CM_f);
        FP12 chk4_R2 = e(pp.g1, pp.acc_g2_s[n-1]);
        FP12 chk4_R; FP12_copy(&chk4_R, &chk4_R1); FP12_mulMy(chk4_R, chk4_R2); FP12_reduce(&chk4_R);
        if (!FP12_equals(&chk4_L, &chk4_R)) { cout << "[ZKBatchVer] Fail: Degree bound check failed" << endl; return false; }

        // Check 5 & 6: Verify shift and knowledge of exponent (unforgeability)
        // Checks e(g1, CM^u) == e(g1^u, CM)
        FP12 chk6_L = e(pp.g1, pf.CM_u); FP12_reduce(&chk6_L);
        FP12 chk6_R = e(pp.g1_u, pf.CM); FP12_reduce(&chk6_R);
        if (!FP12_equals(&chk6_L, &chk6_R)) { cout << "[ZKBatchVer] Fail: Knowledge of exponent (u) check failed" << endl; return false; }

        return true;
    }
}