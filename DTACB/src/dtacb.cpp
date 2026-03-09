#include "../include/dtacb.h"
#include <iostream>

namespace Dtacb {

    csprng rng;
    gmp_randstate_t state_gmp;

    // ================= Hash Functions =================

    ECP H1(ECP c_m) {
        // 1. Convert commitment c_m to a byte stream and hash it to a scalar
        octet hash = getOctet(1024);
        octet temp = getOctet(512);
        ECP_toOctet(&temp, &c_m, true);
        concatOctet(&hash, &temp);

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val); free(temp.val);

        mpz_class h_val = BIG_to_mpz(ret);

        // 2. Map the scalar to a valid curve point h on group G1
        ECP h;
        ECP_generator(&h);
        ECP_mul(h, h_val);
        return h;
    }

    mpz_class H2(RandomizedCred cred_prime) {
        // Hash the randomized credential (CRED') to a scalar in Zp
        octet hash = getOctet(1024);
        octet temp = getOctet(512);

        ECP_toOctet(&temp, &cred_prime.CRED_prime_1, true);
        concatOctet(&hash, &temp);

        ECP_toOctet(&temp, &cred_prime.CRED_prime_2, true);
        concatOctet(&hash, &temp);

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val); free(temp.val);
        return BIG_to_mpz(ret);
    }

    // ================= Core Algorithm =================

    DtacbParams Setup(int max_acc_capacity) {
        DtacbParams pp;
        BIG q_big;
        BIG_rcopy(q_big, CURVE_Order);
        pp.q = BIG_to_mpz(q_big);
        pp.t = max_acc_capacity;

        // 1. Generate base generators g1 (in G1) and g2 (in G2)
        ECP_generator(&pp.g1);
        ECP2_generator(&pp.g2);

        // 2. Choose random scalars r1, r2 <- R Zp* for alternate generators
        mpz_class r1 = rand_mpz(state_gmp) % pp.q;
        ECP_copy(&pp.g1_tilde, &pp.g1);
        ECP_mul(pp.g1_tilde, r1);

        mpz_class r2 = rand_mpz(state_gmp) % pp.q;
        ECP2_copy(&pp.g2_tilde, &pp.g2);
        ECP2_mul(pp.g2_tilde, r2);

        // 3. Generate secret trapdoors u, s <- R Zp* for the accumulator
        mpz_class u = rand_mpz(state_gmp) % pp.q;
        mpz_class s = rand_mpz(state_gmp) % pp.q;

        // 4. Compute and store global public parameters g1^u, g2^u, \tilde{g}_2^u
        ECP_copy(&pp.g1_u, &pp.g1);
        ECP_mul(pp.g1_u, u);

        ECP2_copy(&pp.g2_u, &pp.g2);
        ECP2_mul(pp.g2_u, u);

        ECP2_copy(&pp.g2_tilde_u, &pp.g2_tilde);
        ECP2_mul(pp.g2_tilde_u, u);

        // 5. Generate accumulator parameter arrays {g1^{s^i}, g2^{s^i}, g2^{u*s^i}, \tilde{g}_2^{s^i}, \tilde{g}_2^{u*s^i}}
        mpz_class s_pow = 1;
        for(int i = 1; i <= pp.t; ++i) {
            s_pow = (s_pow * s) % pp.q;

            ECP acc1; ECP_copy(&acc1, &pp.g1); ECP_mul(acc1, s_pow);
            pp.acc_g1_s.push_back(acc1);

            ECP2 acc2; ECP2_copy(&acc2, &pp.g2); ECP2_mul(acc2, s_pow);
            pp.acc_g2_s.push_back(acc2);

            mpz_class us_pow = (u * s_pow) % pp.q;
            ECP2 acc2_us; ECP2_copy(&acc2_us, &pp.g2); ECP2_mul(acc2_us, us_pow);
            pp.acc_g2_us.push_back(acc2_us);

            ECP2 acc_g2_tilde_s_val;
            ECP2_copy(&acc_g2_tilde_s_val, &pp.g2_tilde);
            ECP2_mul(acc_g2_tilde_s_val, s_pow);
            pp.acc_g2_tilde_s.push_back(acc_g2_tilde_s_val);

            ECP2 acc_g2_tilde_us_val;
            ECP2_copy(&acc_g2_tilde_us_val, &pp.g2_tilde);
            ECP2_mul(acc_g2_tilde_us_val, us_pow);
            pp.acc_g2_tilde_us.push_back(acc_g2_tilde_us_val);
        }

        return pp;
    }

    void IKGen(DtacbParams& pp, vector<Issuer>& issuers, int n) {
        for(int i = 0; i < n; ++i) {
            Issuer iss;
            // 1. Choose secret key x_i <- R Zp*
            iss.isk = rand_mpz(state_gmp) % pp.q;

            // 2. Compute public key ipk_i = g2^{x_i} (in G2)
            ECP2_copy(&iss.ipk, &pp.g2);
            ECP2_mul(iss.ipk, iss.isk);

            issuers.push_back(iss);
        }
    }

    // ---------------- Issue Phase ----------------

    RegInfo Obtain(DtacbParams& pp, User& user, mpz_class m, mpz_class l) {
        RegInfo reg;

        // 1. Compute commitment to the message c_m = g1^m * \tilde{g}_1^l
        ECP t1; ECP_copy(&t1, &pp.g1); ECP_mul(t1, m);
        ECP t2; ECP_copy(&t2, &pp.g1_tilde); ECP_mul(t2, l);
        ECP_copy(&reg.c_m, &t1);
        ECP_add(&reg.c_m, &t2);

        // 2. Compute base element h = H1(c_m)
        ECP h = H1(reg.c_m);

        // 3. Generate User's ElGamal key pair z <- R Zp*, Z = g1^z
        user.z = rand_mpz(state_gmp) % pp.q;
        ECP_copy(&user.Z, &pp.g1);
        ECP_mul(user.Z, user.z);
        ECP_copy(&reg.Z, &user.Z);

        // 4. Choose randomness o <- R Zp* and compute ciphertext C1 = g1^o, C2 = Z^o * h^m
        mpz_class o = rand_mpz(state_gmp) % pp.q;

        ECP_copy(&reg.C1, &pp.g1);
        ECP_mul(reg.C1, o);

        ECP c2_t1; ECP_copy(&c2_t1, &user.Z); ECP_mul(c2_t1, o);
        ECP c2_t2; ECP_copy(&c2_t2, &h); ECP_mul(c2_t2, m);

        ECP_copy(&reg.C2, &c2_t1);
        ECP_add(&reg.C2, &c2_t2);

        // 5. Generate non-interactive zero-knowledge proof Theta 1
        mpz_class o_val = o;
        reg.theta1 = Prove_Theta1(pp, h, user.z, m, l, o_val, reg);

        return reg;
    }

    BlindedPartialCred Issue(DtacbParams& pp, const Issuer& issuer, RegInfo& reg) {
        BlindedPartialCred b_cred;

        // 0. Verify the validity of the user's registration request
        ECP h = H1(reg.c_m);
        if (!Verify_Theta1(pp, h, reg)) {
            cout << "[Issue] Issuer Error: NIZK Theta 1 verification failed!" << endl;
            return b_cred;
        }

        // 1. Choose blinding randomness r_i <- R Zp*
        mpz_class r_i = rand_mpz(state_gmp) % pp.q;

        // 2. Compute R_i = g2^{r_i} (in G2)
        ECP2_copy(&b_cred.R_i, &pp.g2);
        ECP2_mul(b_cred.R_i, r_i);

        // 3. Compute blinded partial credential \tilde{C}_1 = C1^{r_i}
        ECP_copy(&b_cred.C1_tilde, &reg.C1);
        ECP_mul(b_cred.C1_tilde, r_i);

        // 4. Compute \tilde{C}_2 = h^{x_i} * C2^{r_i}
        ECP c2_t1; ECP_copy(&c2_t1, &h); ECP_mul(c2_t1, issuer.isk);
        ECP c2_t2; ECP_copy(&c2_t2, &reg.C2); ECP_mul(c2_t2, r_i);

        ECP_copy(&b_cred.C2_tilde, &c2_t1);
        ECP_add(&b_cred.C2_tilde, &c2_t2);

        return b_cred;
    }

    PartialCred Unblind(DtacbParams& pp, const User& user, BlindedPartialCred& b_cred, ECP h) {
        PartialCred pcred;

        // 1. Set the first component of the credential cred_1 = h
        ECP_copy(&pcred.cred_1, &h);
        ECP2_copy(&pcred.R_i, &b_cred.R_i);

        // 2. Unblind via ElGamal decryption: cred_2 = \tilde{C}_2 * (\tilde{C}_1)^{-z}
        mpz_class z_inv = (pp.q - user.z) % pp.q;
        ECP t1; ECP_copy(&t1, &b_cred.C1_tilde);
        ECP_mul(t1, z_inv);

        ECP_copy(&pcred.cred_2, &b_cred.C2_tilde);
        ECP_add(&pcred.cred_2, &t1);

        return pcred;
    }

    // ---------------- Prove Phase ----------------

    Credential AggCred(vector<PartialCred>& partials) {
        Credential cred;
        if(partials.empty()) return cred;

        // 1. Initialize the aggregated credential with the first partial credential
        ECP_copy(&cred.CRED_1, &partials[0].cred_1);
        ECP_copy(&cred.CRED_2, &partials[0].cred_2);

        // 2. Continuously multiply (point addition) the remaining partial credentials
        for(size_t i = 1; i < partials.size(); ++i) {
            ECP_add(&cred.CRED_2, &partials[i].cred_2);
        }
        return cred;
    }

    ProveToken ProveCred(DtacbParams& pp, Credential& cred, mpz_class m, vector<PartialCred>& partials, vector<Issuer>& all_issuers, const vector<uint8_t>& b) {
        ProveToken tok;
        tok.b = b;

        ECP2_inf(&tok.IPK);
        ECP2_inf(&tok.R);

        // 1. Aggregate public keys (IPK) and randomness (R) based on the bit vector b
        int partial_idx = 0;
        for(size_t i = 0; i < b.size(); ++i) {
            if(b[i] == 1) {
                ECP2_add(&tok.IPK, &all_issuers[i].ipk);
                ECP2_add(&tok.R, &partials[partial_idx].R_i);
                partial_idx++;
            }
        }

        // 2. Choose random blinding factors \alpha, \alpha' <- R Zp*
        mpz_class alpha = rand_mpz(state_gmp) % pp.q;
        mpz_class alpha_prime = rand_mpz(state_gmp) % pp.q;

        // 3. Randomize the credential CRED' = (CRED_1^{\alpha'}, CRED_2^{\alpha'})
        ECP_copy(&tok.CRED_prime.CRED_prime_1, &cred.CRED_1);
        ECP_mul(tok.CRED_prime.CRED_prime_1, alpha_prime);

        ECP_copy(&tok.CRED_prime.CRED_prime_2, &cred.CRED_2);
        ECP_mul(tok.CRED_prime.CRED_prime_2, alpha_prime);

        // 4. Compute auxiliary verification element \rho = IPK * R^m * g2^\alpha
        ECP2 t1; ECP2_copy(&t1, &tok.R); ECP2_mul(t1, m);
        ECP2 t2; ECP2_copy(&t2, &pp.g2); ECP2_mul(t2, alpha);

        ECP2_copy(&tok.rho, &tok.IPK);
        ECP2_add(&tok.rho, &t1);
        ECP2_add(&tok.rho, &t2);

        // 5. Compute auxiliary verification element \mu = (CRED'_1)^\alpha
        ECP_copy(&tok.mu, &tok.CRED_prime.CRED_prime_1);
        ECP_mul(tok.mu, alpha);

        // 6. Generate non-interactive zero-knowledge proof Theta 2
        tok.theta2 = Prove_Theta2(pp, m, alpha, tok.R, tok.IPK, tok.rho, tok.CRED_prime.CRED_prime_1, tok.mu);

        return tok;
    }

    bool VerCred(DtacbParams& pp, ProveToken& tok) {
        // 0. Judger first verifies the NIZK proof Theta 2
        if (!Verify_Theta2(pp, tok)) {
            cout << "[VerCred] Judger Error: NIZK Theta 2 verification failed!" << endl;
            return false;
        }

        // 1. Compute LHS = e(CRED'_1, \rho)
        FP12 LHS = e(tok.CRED_prime.CRED_prime_1, tok.rho);

        // 2. Compute RHS = e(CRED'_2 * \mu, g2)
        ECP RHS_G1; ECP_copy(&RHS_G1, &tok.CRED_prime.CRED_prime_2);
        ECP_add(&RHS_G1, &tok.mu);
        FP12 RHS = e(RHS_G1, pp.g2);

        // 3. Compare the pairing results
        if(!FP12_equals(&LHS, &RHS)) {
            cout << "[VerCred] Judger Error: Bilinear pairing equation mismatch!" << endl;
            return false;
        }

        // 4. If valid, Judger extracts the unique credential witness \sigma for the accumulator
        mpz_class sigma = H2(tok.CRED_prime);

        return true;
    }
}