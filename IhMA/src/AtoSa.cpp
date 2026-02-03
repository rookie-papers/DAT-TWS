#include "../include/AtoSa.h"
#include <iostream>
#include <vector>
#include <cstring>

using namespace std;

namespace AtoSa {

    csprng rng;
    gmp_randstate_t state_gmp;

    // ================= Helper Functions =================

    // Helper: H(m) -> Zp
    mpz_class HashMsgToZp(string msg) {
        octet hash = getOctet(2048);
        octet temp = getOctet(1024);

        if (msg.length() > 1024) {
            // Simple truncation for demo, strictly should hash large msgs first
            temp.len = 1024;
            memcpy(temp.val, msg.c_str(), 1024);
        } else {
            temp.len = msg.length();
            memcpy(temp.val, msg.c_str(), temp.len);
        }
        concatOctet(&hash, &temp);

        BIG order_big, ret;
        BIG_rcopy(order_big, CURVE_Order); // Assuming CURVE_Order is global from library
        hashZp256(ret, &hash, order_big);

        free(hash.val);
        free(temp.val);

        return BIG_to_mpz(ret);
    }

    // Helper: H(c) -> G1 ; where c = P^rho1 || P^rho2 || (mj, vkj)...
    ECP HashToG1(AtoSaParams pp, ECP part1, ECP part2, const vector<string>& msgs, const vector<AtoSaVK>& vks) {
        octet hash = getOctet(4096); // Large buffer
        octet temp = getOctet(1024);

        // 1. Append P^rho1
        ECP_toOctet(&temp, &part1, true);
        concatOctet(&hash, &temp);

        // 2. Append P^rho2
        ECP_toOctet(&temp, &part2, true);
        concatOctet(&hash, &temp);

        // 3. Append Pairs (m_j, vk_j)
        for(size_t i=0; i<msgs.size(); ++i) {
            // m_j
            string m = msgs[i];
            if(m.length() > 512) m = m.substr(0, 512);
            temp.len = m.length();
            memcpy(temp.val, m.c_str(), temp.len);
            concatOctet(&hash, &temp);

            // vk_j (Y1, Y2, X)
            ECP2_toOctet(&temp, (ECP2*)&vks[i].Y1_hat, true);
            concatOctet(&hash, &temp);
            ECP2_toOctet(&temp, (ECP2*)&vks[i].Y2_hat, true);
            concatOctet(&hash, &temp);
            ECP2_toOctet(&temp, (ECP2*)&vks[i].X_hat, true);
            concatOctet(&hash, &temp);
        }

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val);
        free(temp.val);

        // Map integer to G1: h = P * hash_val
        mpz_class h_exp = BIG_to_mpz(ret);
        ECP h;
        ECP_copy(&h, &pp.P);
        ECP_mul(h, h_exp);

        return h;
    }

    // ================= Core Algorithm =================

    AtoSaParams Setup() {
        AtoSaParams pp;
        BIG q_big;
        BIG_rcopy(q_big, CURVE_Order);
        pp.p = BIG_to_mpz(q_big);

        ECP_generator(&pp.P);
        ECP2_generator(&pp.P_hat);

        return pp;
    }

    void KeyGen(AtoSaParams pp, AtoSaSK &sk, AtoSaVK &vk) {
        // x, y1, y2 <- Zp
        sk.x = rand_mpz(state_gmp) % pp.p;
        sk.y1 = rand_mpz(state_gmp) % pp.p;
        sk.y2 = rand_mpz(state_gmp) % pp.p;

        // vk = (P_hat^y1, P_hat^y2, P_hat^x)
        ECP2_copy(&vk.Y1_hat, &pp.P_hat);
        ECP2_mul(vk.Y1_hat, sk.y1);

        ECP2_copy(&vk.Y2_hat, &pp.P_hat);
        ECP2_mul(vk.Y2_hat, sk.y2);

        ECP2_copy(&vk.X_hat, &pp.P_hat);
        ECP2_mul(vk.X_hat, sk.x);
    }

    AtoSaTag GenAuxTag(AtoSaParams pp, const vector<string>& msgs, const vector<AtoSaVK>& vks) {
        AtoSaTag tag;

        // 1. Choose rho1, rho2
        tag.aux.rho1 = rand_mpz(state_gmp) % pp.p;
        tag.aux.rho2 = rand_mpz(state_gmp) % pp.p;

        // 2. Compute commitment components for hashing
        // c part 1: P^rho1
        ECP P_rho1;
        ECP_copy(&P_rho1, &pp.P);
        ECP_mul(P_rho1, tag.aux.rho1);

        // c part 2: P^rho2
        ECP P_rho2;
        ECP_copy(&P_rho2, &pp.P);
        ECP_mul(P_rho2, tag.aux.rho2);

        // 3. Compute h = H(c)
        tag.aux.h = HashToG1(pp, P_rho1, P_rho2, msgs, vks);

        // 4. Compute Tag T = (h^rho1, h^rho2)
        ECP_copy(&tag.T1, &tag.aux.h);
        ECP_mul(tag.T1, tag.aux.rho1);

        ECP_copy(&tag.T2, &tag.aux.h);
        ECP_mul(tag.T2, tag.aux.rho2);

        return tag;
    }

    AtoSaSignature Sign(AtoSaParams pp, AtoSaSK sk, AtoSaTag tag, string msg) {
        AtoSaSignature sig;

        // 1. Set h' = T1 ,  because sigma_j = (h', s_j) where h' = h^rho1 = T1.
        ECP_copy(&sig.h_prime, &tag.T1);

        // 2. Compute message hash m_j as integer
        mpz_class m_val = HashMsgToZp(msg);

        // 3. Compute s_j = (h^rho1)^{x + y1*m} * (h^rho2)^{y2} = T1^{x + y1*m} * T2^{y2}

        // Part A exponent: expA = x + y1 * m
        mpz_class term = (sk.y1 * m_val) % pp.p;
        mpz_class expA = (sk.x + term) % pp.p;

        // Part A value: T1 ^ expA
        ECP partA;
        ECP_copy(&partA, &tag.T1);
        ECP_mul(partA, expA);

        // Part B value: T2 ^ y2
        ECP partB;
        ECP_copy(&partB, &tag.T2);
        ECP_mul(partB, sk.y2);

        // Combine: s = PartA + PartB
        ECP_copy(&sig.s, &partA);
        ECP_add(&sig.s, &partB);

        return sig;
    }

    AtoSaSignature AggrSign(vector<AtoSaSignature>& sigs) {
        AtoSaSignature aggSig;
        if (sigs.empty()) return aggSig;

        // 1. h' be same for all, because them have same tag T
        ECP_copy(&aggSig.h_prime, &sigs[0].h_prime);

        // 2. s' = Product(s_j) => Sum(s_j) in additive group
        ECP_copy(&aggSig.s, &sigs[0].s);

        for(size_t i=1; i<sigs.size(); ++i) {
            ECP_add(&aggSig.s, &sigs[i].s);
        }

        return aggSig;
    }

    bool VerifyAggr(AtoSaParams pp, vector<AtoSaVK>& avk, AtoSaTag tag, const vector<string>& msgs, AtoSaSignature sig) {
        // Equation: e(h', Sum(X_j * Y1_j^mj)) * e(T2, Sum(Y2_j)) == e(s, P_hat)

        if (avk.size() != msgs.size()) {
            cout << "Error: VK count and Msg count mismatch" << endl;
            return false;
        }

        // 1. Check T1 == h'
        if (!ECP_equals(&tag.T1, &sig.h_prime)) {
            cout << "Error: Tag T1 does not match signature h'" << endl;
            return false;
        }

        // 2. Compute Sum 1 = Sum( X_hat_j * Y1_hat_j ^ m_j )
        ECP2 sum1;
        ECP2_inf(&sum1);

        for(size_t i=0; i<avk.size(); ++i) {
            mpz_class m_val = HashMsgToZp(msgs[i]);

            // term = Y1_hat ^ m
            ECP2 term;
            ECP2_copy(&term, &avk[i].Y1_hat);
            ECP2_mul(term, m_val);

            // Add X_hat
            ECP2_add(&term, &avk[i].X_hat);

            // Accumulate
            ECP2_add(&sum1, &term);
        }

        // 3. Compute Sum 2 (in G2): Sum( Y2_hat_j )
        ECP2 sum2;
        ECP2_inf(&sum2);
        for(auto& vk : avk) {
            ECP2_add(&sum2, &vk.Y2_hat);
        }

        // 4. Compute Pairings
        // LHS1 = e(h', sum1) ; LHS2 = e(T2, sum2)  (Note: T2 = h^rho2)
        FP12 lhs1 = e(sig.h_prime, sum1);
        FP12 lhs2 = e(tag.T2, sum2);

        // LHS Total
        FP12 lhs;
        FP12_copy(&lhs, &lhs1);
        FP12_mulMy(lhs, lhs2);

        // RHS = e(s, P_hat)
        FP12 rhs = e(sig.s, pp.P_hat);

        // 5. Compare
        if (FP12_equals(&lhs, &rhs)) {
            return true;
        } else {
            return false;
        }
    }

    AtoSaVK ConvertVK(AtoSaVK& vk, const mpz_class& omega) {
        AtoSaVK new_vk;

        // Y1_hat' = Y1_hat * omega
        ECP2_copy(&new_vk.Y1_hat, &vk.Y1_hat);
        ECP2_mul(new_vk.Y1_hat, omega);

        // Y2_hat' = Y2_hat * omega
        ECP2_copy(&new_vk.Y2_hat, &vk.Y2_hat);
        ECP2_mul(new_vk.Y2_hat, omega);

        // X_hat' = X_hat * omega
        ECP2_copy(&new_vk.X_hat, &vk.X_hat);
        ECP2_mul(new_vk.X_hat, omega);

        return new_vk;
    }

    AtoSaSignature ConvertSig(AtoSaSignature& sig, const mpz_class& omega) {
        AtoSaSignature new_sig;

        // h' remains unchanged
        ECP_copy(&new_sig.h_prime, &sig.h_prime);

        // s' = s * omega, which ensures e(s', P_hat) == e(s, P_hat^omega) == e(s, P_hat')
        ECP_copy(&new_sig.s, &sig.s);
        ECP_mul(new_sig.s, omega);

        return new_sig;
    }

    void RandSigTag(AtoSaVK vk, AtoSaTag& tag, string msg, AtoSaSignature& sig, const mpz_class& nu) {
        // Tag T = (T1, T2) -> T' = (T1^nu, T2^nu)
        // Sig sigma = (h', s) -> sigma' = (h'^nu, s^nu)

        // 1. Randomize Tag
        ECP_mul(tag.T1, nu);
        ECP_mul(tag.T2, nu);

        // 2. Randomize Signature
        // Note: In AtoSa, sig.h_prime is actually a copy of tag.T1.
        // So h_prime must also be powered by nu.
        ECP_mul(sig.h_prime, nu);
        ECP_mul(sig.s, nu);

        (void)vk;
        (void)msg;
    }

} // namespace AtoSa