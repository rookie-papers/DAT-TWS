#include "../include/SPSEQ.h"

namespace Spseq {

    csprng rng;
    gmp_randstate_t state_gmp;

    // ================= Core Algorithm =================

    SpseqParams Setup() {
        SpseqParams pp;
        BIG q_big;
        BIG_rcopy(q_big, CURVE_Order);
        pp.p = BIG_to_mpz(q_big);

        // Generate generators P (in G1) and P_hat (in G2)
        ECP_generator(&pp.P);
        ECP2_generator(&pp.P_hat);

        return pp;
    }

    void KeyGen(SpseqParams pp, int l, SpseqSK &sk, SpseqPK &pk) {
        sk.x.resize(l);
        pk.X.resize(l);

        for(int i = 0; i < l; ++i) {
            // Choose x_i <- R Zp*
            sk.x[i] = rand_mpz(state_gmp) % pp.p;

            // Compute X_i = x_i * P (in G1)
            // Note: Unlike standard SPSEQ where PK is G2, here PK is G1 to pair with G2 messages.
            ECP_copy(&pk.X[i], &pp.P);
            ECP_mul(pk.X[i], sk.x[i]);
        }
    }

    SpseqSignature Sign(SpseqParams pp, SpseqSK sk, vector<ECP2>& M) {
        SpseqSignature sig;
        int l = sk.x.size();

        if(M.size() != (size_t)l) {
            cout << "Error: Message vector length mismatch." << endl;
            // Return empty/invalid (Caller should handle)
            return sig;
        }

        // 1. Choose y <- R Zp*
        mpz_class y = rand_mpz(state_gmp) % pp.p;

        // 2. Compute Z = y * Sum(x_i * M_i)
        // Since M_i is in G2, Z will be in G2.
        ECP2 Sum;
        ECP2_inf(&Sum); // Initialize to identity/infinity

        for(int i = 0; i < l; ++i) {
            ECP2 temp;
            ECP2_copy(&temp, &M[i]);
            ECP2_mul(temp, sk.x[i]);
            ECP2_add(&Sum, &temp);
        }
        // Z = y * Sum
        ECP2_copy(&sig.Z, &Sum);
        ECP2_mul(sig.Z, y);

        // 3. Compute Y = (1/y) * P (in G1)
        mpz_class y_inv = invert_mpz(y, pp.p);

        ECP_copy(&sig.Y, &pp.P);
        ECP_mul(sig.Y, y_inv);

        // 4. Compute Y_hat = (1/y) * P_hat (in G2)
        ECP2_copy(&sig.Y_hat, &pp.P_hat);
        ECP2_mul(sig.Y_hat, y_inv);

        return sig;
    }

    bool Verify(SpseqParams pp, SpseqPK pk, const vector<ECP2>& M, SpseqSignature sig) {
        int l = pk.X.size();
        if(M.size() != (size_t)l) return false;

        // Check 1: Prod( e(X_i, M_i) ) == e(Y, Z)
        FP12 LHS;
        FP12_one(&LHS);

        for(int i = 0; i < l; ++i) {
            // e(G1, G2)
            FP12 pair_res = e(pk.X[i], M[i]);
            FP12_mulMy(LHS, pair_res);
        }

        // RHS: e(Y, Z) where Y is G1, Z is G2
        FP12 RHS = e(sig.Y, sig.Z);

        // Compare
        FP12_reduce(&LHS);
        FP12_reduce(&RHS);
        if(!FP12_equals(&LHS, &RHS)) {
            cout << "Verify Failed: Equation 1 (Signature validity) mismatch." << endl;
            return false;
        }

        // Check 2: e(Y, P_hat) == e(P, Y_hat)
        // Ensures Y (G1) and Y_hat (G2) share the same discrete log
        FP12 check2_lhs = e(sig.Y, pp.P_hat);
        FP12 check2_rhs = e(pp.P, sig.Y_hat);

        FP12_reduce(&check2_lhs);
        FP12_reduce(&check2_rhs);

        if(!FP12_equals(&check2_lhs, &check2_rhs)) {
            cout << "Verify Failed: Equation 2 (Structure check) mismatch." << endl;
            return false;
        }

        return true;
    }

    SpseqSignature ChgRep(SpseqParams pp, SpseqPK pk, const vector<ECP2>& M, SpseqSignature sig, mpz_class mu) {
        SpseqSignature new_sig;

        // 0. Verify original signature first
        if(!Verify(pp, pk, M, sig)) {
            cout << "ChgRep Error: Input signature is invalid." << endl;
            return new_sig;
        }

        // 1. Pick psi <- R Zp*
        mpz_class psi = rand_mpz(state_gmp) % pp.p;
        mpz_class psi_inv = invert_mpz(psi, pp.p);

        // 2. Compute Z' = psi * mu * Z
        mpz_class scalar_z = (psi * mu) % pp.p;
        ECP2_copy(&new_sig.Z, &sig.Z);
        ECP2_mul(new_sig.Z, scalar_z);

        // 3. Compute Y' = (1/psi) * Y
        ECP_copy(&new_sig.Y, &sig.Y);
        ECP_mul(new_sig.Y, psi_inv);

        // 4. Compute Y_hat' = (1/psi) * Y_hat
        ECP2_copy(&new_sig.Y_hat, &sig.Y_hat);
        ECP2_mul(new_sig.Y_hat, psi_inv);

        return new_sig;
    }

} // namespace Spseq