#include "../include/ntat.h"
#include <iostream>
#include <cstring>

using namespace std;

namespace Ntat {

    csprng rng;
    gmp_randstate_t state_gmp;

    // ================= Helper Functions =================

    mpz_class mod_sub(mpz_class a, mpz_class b, mpz_class q) {
        return ((a - b) % q + q) % q;
    }

    // ================= Hash Functions =================

    mpz_class H1(ECP X, ECP T, ECP comm1, ECP comm2) {
        // 1. Convert curve points (X, T, comm1, comm2) to a byte stream and hash them to a scalar
        octet hash = getOctet(2048);
        octet temp = getOctet(1024);

        ECP_toOctet(&temp, &X, true); concatOctet(&hash, &temp);
        ECP_toOctet(&temp, &T, true); concatOctet(&hash, &temp);
        ECP_toOctet(&temp, &comm1, true); concatOctet(&hash, &temp);
        ECP_toOctet(&temp, &comm2, true); concatOctet(&hash, &temp);

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val); free(temp.val);
        return BIG_to_mpz(ret);
    }

    mpz_class H3(mpz_class rho, ECP Q) {
        // 1. Hash the randomness rho and the commitment point Q to a scalar
        octet hash = getOctet(1024);
        octet temp = getOctet(512);

        mpzToOctet(rho); concatOctet(&hash, &temp);
        ECP_toOctet(&temp, &Q, true); concatOctet(&hash, &temp);

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val); free(temp.val);
        return BIG_to_mpz(ret);
    }

    mpz_class H_Challenge(mpz_class comm, ECP sigma_prime) {
        // 1. Fiat-Shamir heuristic: Hash the commitment and sigma_prime to generate the challenge c
        octet hash = getOctet(1024);
        octet temp = getOctet(512);

        mpzToOctet(comm); concatOctet(&hash, &temp);
        ECP_toOctet(&temp, &sigma_prime, true); concatOctet(&hash, &temp);

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val); free(temp.val);
        return BIG_to_mpz(ret);
    }

    // ================= Core Algorithm =================

    NtatParams Setup() {
        NtatParams pp;

        // 1. Initialize the system parameters and set the group order q
        BIG q_big;
        BIG_rcopy(q_big, CURVE_Order);
        pp.q = BIG_to_mpz(q_big);

        // 2. Generate base generators G1 (in G1) and G2 (in G2)
        ECP_generator(&pp.G1);
        ECP2_generator(&pp.G2);

        // 3. Choose random scalars r3, r4 <- R Zp* to generate alternate generators G3 and G4
        mpz_class r3 = rand_mpz(state_gmp) % pp.q;
        mpz_class r4 = rand_mpz(state_gmp) % pp.q;

        ECP_copy(&pp.G3, &pp.G1);
        ECP_mul(pp.G3, r3);

        ECP_copy(&pp.G4, &pp.G1);
        ECP_mul(pp.G4, r4);

        return pp;
    }

    ClientKeys ClientKeyGen(NtatParams pp) {
        ClientKeys keys;

        // 1. Choose secret key x <- R Zp*
        keys.sk_c = rand_mpz(state_gmp) % pp.q;

        // 2. Compute public key X = x * G1
        ECP_copy(&keys.pk_c, &pp.G1);
        ECP_mul(keys.pk_c, keys.sk_c);

        return keys;
    }

    ServerKeys ServerKeyGen(NtatParams pp) {
        ServerKeys keys;

        // 1. Choose secret key y <- R Zp*
        keys.sk_s = rand_mpz(state_gmp) % pp.q;

        // 2. Compute public key Y = y * G2
        ECP2_copy(&keys.pk_s, &pp.G2);
        ECP2_mul(keys.pk_s, keys.sk_s);

        return keys;
    }

    // ---------------- Issue Phase ----------------

    QueryPayload ClientQuery(NtatParams pp, ClientKeys keys, ClientState &st) {
        QueryPayload payload;

        // 1. Choose random scalars r, delta <- R Zp* (ensure delta is non-zero)
        st.r = rand_mpz(state_gmp) % pp.q;
        st.delta = rand_mpz(state_gmp) % pp.q;
        while(st.delta == 0) st.delta = rand_mpz(state_gmp) % pp.q;

        // 2. Compute the blinded commitment T = delta * (X + r*G3 + G4)
        ECP T_inner, rG3;
        ECP_copy(&T_inner, &keys.pk_c);
        ECP_copy(&rG3, &pp.G3); ECP_mul(rG3, st.r);

        ECP_add(&T_inner, &rG3);
        ECP_add(&T_inner, &pp.G4);

        ECP_copy(&payload.T, &T_inner);
        ECP_mul(payload.T, st.delta);
        ECP_copy(&st.T, &payload.T);

        // 3. Generate non-interactive zero-knowledge proof Pi_c
        // 3.1. Choose random blinding factors a, b, c <- R Zp*
        mpz_class a = rand_mpz(state_gmp) % pp.q;
        mpz_class b = rand_mpz(state_gmp) % pp.q;
        mpz_class c = rand_mpz(state_gmp) % pp.q;

        // 3.2. Compute commitments comm1 = a*G1 and comm2 = a*G1 + b*G3 + c*T
        ECP comm1; ECP_copy(&comm1, &pp.G1); ECP_mul(comm1, a);

        ECP comm2, bG3, cT;
        ECP_copy(&comm2, &comm1);
        ECP_copy(&bG3, &pp.G3); ECP_mul(bG3, b);
        ECP_copy(&cT, &payload.T); ECP_mul(cT, c);

        ECP_add(&comm2, &bG3);
        ECP_add(&comm2, &cT);

        // 3.3. Compute the Fiat-Shamir challenge ch = H1(X, T, comm1, comm2)
        mpz_class ch = H1(keys.pk_c, payload.T, comm1, comm2);
        mpz_class delta_inv = invert_mpz(st.delta, pp.q);

        // 3.4. Compute responses resp1, resp2, resp3
        payload.pi_c.ch = ch;
        payload.pi_c.resp1 = mod_sub(a, (ch * keys.sk_c) % pp.q, pp.q);
        payload.pi_c.resp2 = mod_sub(b, (ch * st.r) % pp.q, pp.q);
        payload.pi_c.resp3 = (c + (ch * delta_inv) % pp.q) % pp.q;

        return payload;
    }

    ServerIssueResp ServerIssue(NtatParams pp, ServerKeys sk, ECP pk_c, QueryPayload query) {
        ServerIssueResp resp;

        // Verify the validity of the client's NIZK proof Pi_c
        // 1. Reconstruct comm1_prime = resp1*G1 + ch*X
        ECP comm1_prime, chX, resp1G1;
        ECP_copy(&resp1G1, &pp.G1); ECP_mul(resp1G1, query.pi_c.resp1);
        ECP_copy(&chX, &pk_c); ECP_mul(chX, query.pi_c.ch);

        ECP_copy(&comm1_prime, &resp1G1);
        ECP_add(&comm1_prime, &chX);

        // 2. Reconstruct comm2_prime = resp1*G1 + resp2*G3 + resp3*T - ch*G4
        ECP comm2_prime, resp2G3, resp3T, chG4;
        ECP_copy(&comm2_prime, &resp1G1);

        ECP_copy(&resp2G3, &pp.G3); ECP_mul(resp2G3, query.pi_c.resp2);
        ECP_copy(&resp3T, &query.T); ECP_mul(resp3T, query.pi_c.resp3);

        ECP_copy(&chG4, &pp.G4);
        ECP_mul(chG4, mod_sub(0, query.pi_c.ch, pp.q)); // -ch*G4

        ECP_add(&comm2_prime, &resp2G3);
        ECP_add(&comm2_prime, &resp3T);
        ECP_add(&comm2_prime, &chG4);

        // 3. Verify if the computed challenge matches the provided challenge
        mpz_class ch_prime = H1(pk_c, query.T, comm1_prime, comm2_prime);
        if (ch_prime != query.pi_c.ch) {
            cout << "[ServerIssue] Error: Pi_C verification failed!" << endl;
            resp.s = -1;
            return resp;
        }

        // 4. Choose signing randomness s <- R Zp* \ {-y}
        resp.s = rand_mpz(state_gmp) % pp.q;
        mpz_class y_plus_s_inv = invert_mpz((sk.sk_s + resp.s) % pp.q, pp.q);

        // 5. Compute the issued credential component S = (1 / (y+s)) * T
        ECP_copy(&resp.S, &query.T);
        ECP_mul(resp.S, y_plus_s_inv);

        return resp;
    }

    NtatToken ClientFinal(NtatParams pp, ECP2 pk_s, ClientState st, ServerIssueResp resp) {
        NtatToken token;
        if(resp.s == -1) return token;

        // 1. Verify the validity of the server's response using bilinear pairing
        // LHS = e(S, Y + sG2), RHS = e(T, G2)
        ECP2 sG2, Y_plus_sG2;
        ECP2_copy(&sG2, &pp.G2); ECP2_mul(sG2, resp.s);

        ECP2_copy(&Y_plus_sG2, &pk_s);
        ECP2_add(&Y_plus_sG2, &sG2);

        FP12 LHS = e(resp.S, Y_plus_sG2);
        FP12 RHS = e(st.T, pp.G2);

        FP12_reduce(&LHS); FP12_reduce(&RHS);
        if (!FP12_equals(&LHS, &RHS)) {
            cout << "[ClientFinal] Error: Bilinear pairing equation mismatch!" << endl;
            return token;
        }

        // 2. Unblind the credential to obtain the final signature sigma = (1 / delta) * S
        mpz_class delta_inv = invert_mpz(st.delta, pp.q);

        ECP_copy(&token.sigma, &resp.S);
        ECP_mul(token.sigma, delta_inv);

        token.r = st.r;
        token.s = resp.s;

        return token;
    }

    // ---------------- Redeem Phase ----------------

    RedeemPayload ClientProve(NtatParams pp, ClientKeys keys, ECP2 pk_s, NtatToken token) {
        RedeemPayload payload;

        // 0. Include the original sigma for public pairing verification
        ECP_copy(&payload.sigma, &token.sigma);

        // 1. Compute the randomized token element sigma' = xG1 + rG3 + G4 - s*sigma
        ECP xG1, rG3, sSig;
        ECP_copy(&xG1, &pp.G1); ECP_mul(xG1, keys.sk_c);
        ECP_copy(&rG3, &pp.G3); ECP_mul(rG3, token.r);
        ECP_copy(&sSig, &token.sigma); ECP_mul(sSig, mod_sub(0, token.s, pp.q)); // -s*sigma

        ECP_copy(&payload.sigma_prime, &xG1);
        ECP_add(&payload.sigma_prime, &rG3);
        ECP_add(&payload.sigma_prime, &pp.G4);
        ECP_add(&payload.sigma_prime, &sSig);

        // 2. Choose random blinding factors alpha, beta, gamma <- R Zp*
        mpz_class alpha = rand_mpz(state_gmp) % pp.q;
        mpz_class beta = rand_mpz(state_gmp) % pp.q;
        mpz_class gamma = rand_mpz(state_gmp) % pp.q;

        // 3. Compute the commitment Q = alpha*G1 + beta*G3 + gamma*sigma
        ECP Q, aG1, bG3, cSig;
        ECP_copy(&aG1, &pp.G1); ECP_mul(aG1, alpha);
        ECP_copy(&bG3, &pp.G3); ECP_mul(bG3, beta);
        ECP_copy(&cSig, &token.sigma); ECP_mul(cSig, gamma);

        ECP_copy(&Q, &aG1);
        ECP_add(&Q, &bG3);
        ECP_add(&Q, &cSig);

        // 4. Generate a random scalar rho and compute the hash commitment comm = H3(rho, Q)
        payload.rho = rand_mpz(state_gmp) % pp.q;
        payload.comm = H3(payload.rho, Q);

        // 5. Generate the Fiat-Shamir challenge c = H_Challenge(comm, sigma')
        mpz_class c = H_Challenge(payload.comm, payload.sigma_prime);

        // 6. Compute the ZK responses v0, v1, v2
        payload.v0 = (alpha + (c * keys.sk_c) % pp.q) % pp.q;
        payload.v1 = (beta + (c * token.r) % pp.q) % pp.q;
        payload.v2 = mod_sub(gamma, (c * token.s) % pp.q, pp.q);

        return payload;
    }

    bool ServerVerify(NtatParams pp, ECP2 pk_s, RedeemPayload payload) {
        // 1. Verify the bilinear pairing equation: e(sigma, Y) ?= e(sigma', G2)
        FP12 LHS = e(payload.sigma, pk_s);
        FP12 RHS = e(payload.sigma_prime, pp.G2);

        FP12_reduce(&LHS); FP12_reduce(&RHS);

        if (!FP12_equals(&LHS, &RHS)) {
            cout << "[ServerVerify] Error: Pairing verification failed (sigma invalid)." << endl;
            return false;
        }

        // 2. Reconstruct the Fiat-Shamir challenge c = H_Challenge(comm, sigma')
        mpz_class c = H_Challenge(payload.comm, payload.sigma_prime);

        // 3. Reconstruct Q' = v0*G1 + v1*G3 + v2*sigma
        ECP Q_prime, v0G1, v1G3, v2Sig;
        ECP_copy(&v0G1, &pp.G1); ECP_mul(v0G1, payload.v0);
        ECP_copy(&v1G3, &pp.G3); ECP_mul(v1G3, payload.v1);
        ECP_copy(&v2Sig, &payload.sigma); ECP_mul(v2Sig, payload.v2);

        ECP_copy(&Q_prime, &v0G1);
        ECP_add(&Q_prime, &v1G3);
        ECP_add(&Q_prime, &v2Sig);

        // 4. Compute Q* = Q' - c*(sigma' - G4)
        ECP sigP_minus_G4, c_part, negG4;
        ECP_copy(&sigP_minus_G4, &payload.sigma_prime);

        ECP_copy(&negG4, &pp.G4);
        ECP_mul(negG4, mod_sub(0, 1, pp.q)); // Compute -G4

        ECP_add(&sigP_minus_G4, &negG4);

        ECP_copy(&c_part, &sigP_minus_G4);
        ECP_mul(c_part, mod_sub(0, c, pp.q)); // Compute -c*(sigma' - G4)

        ECP Q_star;
        ECP_copy(&Q_star, &Q_prime);
        ECP_add(&Q_star, &c_part);

        // 5. Verify the hash commitment comm* == comm
        mpz_class comm_star = H3(payload.rho, Q_star);
        if (comm_star != payload.comm) {
            cout << "[ServerVerify] Error: ZK Proof verification failed (comm mismatch)." << endl;
            return false;
        }

        return true;
    }

} // namespace Ntat