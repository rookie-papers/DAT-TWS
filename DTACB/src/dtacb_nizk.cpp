#include "../include/dtacb.h"
#include <iostream>

namespace Dtacb {

    // ---------------- NIZK Theta 1 ----------------

    // Dedicated hash function for Theta 1 proof using the Fiat-Shamir heuristic
    mpz_class Hash_Theta1(ECP Z, ECP c_m, ECP C1, ECP C2, ECP R_Z, ECP R_cm, ECP R_C1, ECP R_C2) {
        octet hash = getOctet(4096);
        octet temp = getOctet(512);

        // Append all public parameters and commitments to the hash stream
        ECP* points[] = {&Z, &c_m, &C1, &C2, &R_Z, &R_cm, &R_C1, &R_C2};
        for (int i = 0; i < 8; ++i) {
            ECP_toOctet(&temp, points[i], true);
            concatOctet(&hash, &temp);
        }

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val); free(temp.val);
        return BIG_to_mpz(ret);
    }

    NIZK_Theta1 Prove_Theta1(DtacbParams& pp, ECP h, mpz_class z, mpz_class m, mpz_class l, mpz_class o, RegInfo& reg) {
        NIZK_Theta1 proof;

        // 1. Generate random blinding factors for each secret witness
        mpz_class r_z = rand_mpz(state_gmp) % pp.q;
        mpz_class r_m = rand_mpz(state_gmp) % pp.q;
        mpz_class r_l = rand_mpz(state_gmp) % pp.q;
        mpz_class r_o = rand_mpz(state_gmp) % pp.q;

        // 2. Compute commitments based on the target equations
        // R_Z = g1^{r_z}
        ECP R_Z; ECP_copy(&R_Z, &pp.g1); ECP_mul(R_Z, r_z);

        // R_cm = g1^{r_m} * g1_tilde^{r_l}
        ECP R_cm, t1;
        ECP_copy(&R_cm, &pp.g1); ECP_mul(R_cm, r_m);
        ECP_copy(&t1, &pp.g1_tilde); ECP_mul(t1, r_l);
        ECP_add(&R_cm, &t1);

        // R_C1 = g1^{r_o}
        ECP R_C1; ECP_copy(&R_C1, &pp.g1); ECP_mul(R_C1, r_o);

        // R_C2 = Z^{r_o} * h^{r_m}
        ECP R_C2, t2;
        ECP_copy(&R_C2, &reg.Z); ECP_mul(R_C2, r_o);
        ECP_copy(&t2, &h); ECP_mul(t2, r_m);
        ECP_add(&R_C2, &t2);

        // 3. Compute Fiat-Shamir challenge c
        proof.c = Hash_Theta1(reg.Z, reg.c_m, reg.C1, reg.C2, R_Z, R_cm, R_C1, R_C2);

        // 4. Compute zero-knowledge responses: s_i = (r_i - c * x_i) mod q
        auto calc_s = [&](mpz_class r, mpz_class x) {
            mpz_class s = (r - proof.c * x) % pp.q;
            if (s < 0) s += pp.q; // Ensure positive value within the finite field
            return s;
        };

        proof.s_z = calc_s(r_z, z);
        proof.s_m = calc_s(r_m, m);
        proof.s_l = calc_s(r_l, l);
        proof.s_o = calc_s(r_o, o);

        return proof;
    }

    bool Verify_Theta1(DtacbParams& pp, ECP h, RegInfo& reg) {
        const NIZK_Theta1& p = reg.theta1;

        // 1. Reconstruct commitments using the public parameters and the proof responses
        // Reconstruct R_Z' = g1^{s_z} * Z^c
        ECP R_Z_prime, t1;
        ECP_copy(&R_Z_prime, &pp.g1); ECP_mul(R_Z_prime, p.s_z);
        ECP_copy(&t1, &reg.Z); ECP_mul(t1, p.c);
        ECP_add(&R_Z_prime, &t1);

        // Reconstruct R_cm' = g1^{s_m} * g1_tilde^{s_l} * c_m^c
        ECP R_cm_prime, t2, t3;
        ECP_copy(&R_cm_prime, &pp.g1); ECP_mul(R_cm_prime, p.s_m);
        ECP_copy(&t2, &pp.g1_tilde); ECP_mul(t2, p.s_l);
        ECP_copy(&t3, &reg.c_m); ECP_mul(t3, p.c);
        ECP_add(&R_cm_prime, &t2);
        ECP_add(&R_cm_prime, &t3);

        // Reconstruct R_C1' = g1^{s_o} * C1^c
        ECP R_C1_prime, t4;
        ECP_copy(&R_C1_prime, &pp.g1); ECP_mul(R_C1_prime, p.s_o);
        ECP_copy(&t4, &reg.C1); ECP_mul(t4, p.c);
        ECP_add(&R_C1_prime, &t4);

        // Reconstruct R_C2' = Z^{s_o} * h^{s_m} * C2^c
        ECP R_C2_prime, t5, t6;
        ECP_copy(&R_C2_prime, &reg.Z); ECP_mul(R_C2_prime, p.s_o);
        ECP_copy(&t5, &h); ECP_mul(t5, p.s_m);
        ECP_copy(&t6, &reg.C2); ECP_mul(t6, p.c);
        ECP_add(&R_C2_prime, &t5);
        ECP_add(&R_C2_prime, &t6);

        // 2. Recompute the challenge hash and verify equality
        mpz_class c_prime = Hash_Theta1(reg.Z, reg.c_m, reg.C1, reg.C2, R_Z_prime, R_cm_prime, R_C1_prime, R_C2_prime);

        return c_prime == p.c;
    }


    // ---------------- NIZK Theta 2 ----------------

    // Dedicated hash function for Theta 2 proof using the Fiat-Shamir heuristic
    mpz_class Hash_Theta2(ECP2 IPK, ECP2 R, ECP2 rho, ECP CRED_prime_1, ECP mu, ECP2 R_rho, ECP R_mu) {
        octet hash = getOctet(4096);
        octet temp = getOctet(512);

        // Append G2 points
        ECP2* points_g2[] = {&IPK, &R, &rho, &R_rho};
        for (int i = 0; i < 4; ++i) {
            ECP2_toOctet(&temp, points_g2[i], true);
            concatOctet(&hash, &temp);
        }

        // Append G1 points
        ECP* points_g1[] = {&CRED_prime_1, &mu, &R_mu};
        for (int i = 0; i < 3; ++i) {
            ECP_toOctet(&temp, points_g1[i], true);
            concatOctet(&hash, &temp);
        }

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val); free(temp.val);
        return BIG_to_mpz(ret);
    }

    NIZK_Theta2 Prove_Theta2(DtacbParams& pp, mpz_class m, mpz_class alpha, ECP2 R, ECP2 IPK, ECP2 rho, ECP CRED_prime_1, ECP mu) {
        NIZK_Theta2 proof;

        // 1. Generate random blinding factors for m and alpha
        mpz_class r_m = rand_mpz(state_gmp) % pp.q;
        mpz_class r_alpha = rand_mpz(state_gmp) % pp.q;

        // 2. Compute commitments
        // R_rho = R^{r_m} * g2^{r_alpha} (computed over G2)
        ECP2 R_rho, t1;
        ECP2_copy(&R_rho, &R); ECP2_mul(R_rho, r_m);
        ECP2_copy(&t1, &pp.g2); ECP2_mul(t1, r_alpha);
        ECP2_add(&R_rho, &t1);

        // R_mu = (CRED'_1)^{r_alpha} (computed over G1)
        ECP R_mu;
        ECP_copy(&R_mu, &CRED_prime_1); ECP_mul(R_mu, r_alpha);

        // 3. Compute Fiat-Shamir challenge c
        proof.c = Hash_Theta2(IPK, R, rho, CRED_prime_1, mu, R_rho, R_mu);

        // 4. Compute zero-knowledge responses
        auto calc_s = [&](mpz_class r, mpz_class x) {
            mpz_class s = (r - proof.c * x) % pp.q;
            if (s < 0) s += pp.q;
            return s;
        };

        proof.s_m = calc_s(r_m, m);
        proof.s_alpha = calc_s(r_alpha, alpha);

        return proof;
    }

    bool Verify_Theta2(DtacbParams& pp, ProveToken& tok) {
        const NIZK_Theta2& p = tok.theta2;

        // 1. Reconstruct commitments
        // To reconstruct R_rho, we need (rho / IPK). In an additive group, this is (rho - IPK).
        ECP2 rho_minus_IPK;
        ECP2_copy(&rho_minus_IPK, &tok.rho);
        ECP2_sub(&rho_minus_IPK, &tok.IPK);

        // Reconstruct R_rho' = R^{s_m} * g2^{s_alpha} * (rho / IPK)^c
        ECP2 R_rho_prime, t1, t2;
        ECP2_copy(&R_rho_prime, &tok.R); ECP2_mul(R_rho_prime, p.s_m);
        ECP2_copy(&t1, &pp.g2); ECP2_mul(t1, p.s_alpha);
        ECP2_copy(&t2, &rho_minus_IPK); ECP2_mul(t2, p.c);

        ECP2_add(&R_rho_prime, &t1);
        ECP2_add(&R_rho_prime, &t2);

        // Reconstruct R_mu' = (CRED'_1)^{s_alpha} * mu^c
        ECP R_mu_prime, t3;
        ECP_copy(&R_mu_prime, &tok.CRED_prime.CRED_prime_1); ECP_mul(R_mu_prime, p.s_alpha);
        ECP_copy(&t3, &tok.mu); ECP_mul(t3, p.c);

        ECP_add(&R_mu_prime, &t3);

        // 2. Recompute the challenge hash and verify equality
        mpz_class c_prime = Hash_Theta2(tok.IPK, tok.R, tok.rho, tok.CRED_prime.CRED_prime_1, tok.mu, R_rho_prime, R_mu_prime);

        return c_prime == p.c;
    }
}