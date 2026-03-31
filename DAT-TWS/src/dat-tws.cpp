#include "dat-tws.h"

using namespace std;

namespace DatTws {

    csprng rng;
    gmp_randstate_t state_gmp;

// ================= Hash Functions =================

// f: Hash function for Regulator to compute H_u = X^{f(rsk, PK_U)}
    mpz_class f_hash(mpz_class rsk, ECP2 PK_U) {
        octet hash = getOctet(2048);
        octet temp = getOctet(1024);

        // Convert rsk to string/bytes
        string rsk_str = rsk.get_str(16);
        temp.len = rsk_str.length();
        memcpy(temp.val, rsk_str.c_str(), temp.len);
        concatOctet(&hash, &temp);

        ECP2_toOctet(&temp, &PK_U, true);
        concatOctet(&hash, &temp);

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val);
        free(temp.val);

        return BIG_to_mpz(ret);
    }

// H1: Hash for T_vk generation
    mpz_class H1(ECP Xt, ECP2 Yt, FP12 pairing_res) {
        octet hash = getOctet(2048);
        octet temp = getOctet(1024);

        ECP_toOctet(&temp, &Xt, true);
        concatOctet(&hash, &temp);

        ECP2_toOctet(&temp, &Yt, true);
        concatOctet(&hash, &temp);

        FP12_toOctet(&temp, &pairing_res);
        concatOctet(&hash, &temp);

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val);
        free(temp.val);

        return BIG_to_mpz(ret);
    }

    // H2: Message signature hash h = H4(msg, Z_x, {T_vk})
    mpz_class H2(string msg, FP12 hat_Z_x, vector<ECP> T_vks) {
        octet hash = getOctet(4096);
        octet temp = getOctet(1024);

        if (msg.length() > 1024) {
            cout << "Error: Message too long" << endl;
        } else {
            temp.len = msg.length();
            memcpy(temp.val, msg.c_str(), temp.len);
            concatOctet(&hash, &temp);
        }

        FP12_toOctet(&temp, &hat_Z_x);
        concatOctet(&hash, &temp);

        for(auto& tvk : T_vks) {
            ECP_toOctet(&temp, &tvk, true);
            concatOctet(&hash, &temp);
        }

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val);
        free(temp.val);

        return BIG_to_mpz(ret);
    }

    // H3: ZK Challenge hash c = H3(K_agg, H', sigma', R)
    mpz_class H3(ECP2 K_agg, ECP H_prime, ECP sigma_prime, FP12 R) {
        octet hash = getOctet(2048);
        octet temp = getOctet(1024);

        ECP2_toOctet(&temp, &K_agg, true);
        concatOctet(&hash, &temp);

        ECP_toOctet(&temp, &H_prime, true);
        concatOctet(&hash, &temp);

        ECP_toOctet(&temp, &sigma_prime, true);
        concatOctet(&hash, &temp);

        FP12_toOctet(&temp, &R);
        concatOctet(&hash, &temp);

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val);
        free(temp.val);

        return BIG_to_mpz(ret);
    }

    // H_Tag: Tag hash m_i = H(Tag)
    mpz_class H_Tag(const DatTag& tag) {
        octet hash = getOctet(2048);
        octet temp = getOctet(1024);

        mpzToOctet(tag.T_exp);
        concatOctet(&hash, &temp);

        ECP_toOctet(&temp, (ECP*)&tag.X_t, true);
        concatOctet(&hash, &temp);

        ECP2_toOctet(&temp, (ECP2*)&tag.Y_t_tilde, true);
        concatOctet(&hash, &temp);

        ECP_toOctet(&temp, (ECP*)&tag.T_vk, true);
        concatOctet(&hash, &temp);

        ECP2_toOctet(&temp, (ECP2*)&tag.A_tilde, true);
        concatOctet(&hash, &temp);

        ECP2_toOctet(&temp, (ECP2*)&tag.B_tilde, true);
        concatOctet(&hash, &temp);

        BIG order, ret;
        BIG_rcopy(order, CURVE_Order);
        hashZp256(ret, &hash, order);

        free(hash.val);
        free(temp.val);

        return BIG_to_mpz(ret);
    }

// ================= Core Algorithm =================

    DatParams Setup() {
        DatParams pp;
        BIG q_big;
        BIG_rcopy(q_big, CURVE_Order);
        pp.q = BIG_to_mpz(q_big);

        ECP_generator(&pp.X);
        ECP2_generator(&pp.Y_tilde);

        pp.hat_Z = e(pp.X, pp.Y_tilde);

        return pp;
    }

    void KeyGen(DatParams pp, DatOpener &opener, vector<DatIssuer> &issuers, int n_issuers, DatUser &user) {
        // Issuer KeyGen
        for(int i=0; i<n_issuers; ++i) {
            DatIssuer iss;
            iss.a = rand_mpz(state_gmp);
            iss.b = rand_mpz(state_gmp);

            ECP2_copy(&iss.A_tilde, &pp.Y_tilde);
            ECP2_mul(iss.A_tilde, iss.a);

            ECP2_copy(&iss.B_tilde, &pp.Y_tilde);
            ECP2_mul(iss.B_tilde, iss.b);

            issuers.push_back(iss);
        }

        // Opener KeyGen: rsk, PK_R = X^rsk
        opener.rsk = rand_mpz(state_gmp);
        ECP_copy(&opener.PK_R, &pp.X);
        ECP_mul(opener.PK_R, opener.rsk);

        // User KeyGen: usk, PK_U = Y^usk
        user.usk = rand_mpz(state_gmp);
        ECP2_copy(&user.PK_U, &pp.Y_tilde);
        ECP2_mul(user.PK_U, user.usk);
        user.H = randECP(rng); // User select H
    }

    DatTag TagGen(DatParams pp, DatIssuer issuer, DatUser user, DatOpener opener) {
        DatTag tag;
        time_t now = time(nullptr);
        time_t exp_seconds = now + (30 * 24 * 60 * 60); // +30 days
        tag.T_exp = (unsigned long)exp_seconds;

        // 1. Ephemeral Keys
        mpz_class t = rand_mpz(state_gmp);
        ECP_copy(&tag.X_t, &pp.X);
        ECP_mul(tag.X_t, t);        // X_t = X^t
        ECP2_copy(&tag.Y_t_tilde, &pp.Y_tilde);
        ECP2_mul(tag.Y_t_tilde, t); // Y_t = Y^t

        // 2. Compute T_vk
        // e(PK_R^t, PK_U)
        ECP PK_R_t;
        ECP_copy(&PK_R_t, &opener.PK_R);
        ECP_mul(PK_R_t,t);
        FP12 pair_val = e(PK_R_t, user.PK_U);

        // T_vk = X^h1
        mpz_class h1 = H1(tag.X_t, tag.Y_t_tilde, pair_val);
        ECP_copy(&tag.T_vk, &pp.X);
        ECP_mul(tag.T_vk, h1);

        // Copy Issuer PK parts
        ECP2_copy(&tag.A_tilde, &issuer.A_tilde);
        ECP2_copy(&tag.B_tilde, &issuer.B_tilde);

        return tag;
    }

    // WitGen: Generate Witness and store in User Vector
    void WitGen(DatParams pp, DatIssuer issuer, DatUser& user, DatTag tag, DatOpener opener) {
        DatWitness wit;

        // 1. Regulator computes H_u = f(rsk, PK_U)
        mpz_class h_u_val = f_hash(opener.rsk, user.PK_U);
        ECP H_u;
        ECP_copy(&H_u, &pp.X);
        ECP_mul(H_u, h_u_val); // H_u = X^{f(rsk, PK_U)}

        // User records H_u as their base H (Overwrites the random H from KeyGen)
        ECP_copy(&user.H, &H_u);

        // 2. Issuer computes certificate sigma_i = H_u^{a_i + b_i * H_Tag(T_i)}
        mpz_class m = H_Tag(tag);
        mpz_class sig_exp = (issuer.a + issuer.b * m) % pp.q;

        ECP sigma_i;
        ECP_copy(&sigma_i, &H_u);
        ECP_mul(sigma_i, sig_exp);

        // User gains witness sigma_i
        ECP_copy(&wit.sigma_prime, &sigma_i);

        // 3. User derive T_sk = T_vk ^ usk
        ECP tsk_temp;
        ECP_copy(&tsk_temp, &tag.T_vk);
        ECP_mul(tsk_temp, user.usk);

        // Store into vectors (Consistent Order)
        user.tags.push_back(tag);
        user.witnesses.push_back(wit);
        user.T_sk.push_back(tsk_temp);
    }

    DatSignature Sign(DatParams pp, DatUser user, string msg) {
        DatSignature sig;

        if (user.tags.empty()) {
            cout << "Error: No tags found." << endl;
            return sig;
        }

        int n = user.tags.size();

        // 1. Aggregate Witnesses & PKs
        ECP sigma_agg;
        ECP_inf(&sigma_agg);
        for(int i=0; i<n; ++i) {
            ECP_add(&sigma_agg, &user.witnesses[i].sigma_prime);
        }

        ECP2 K_agg;
        ECP2_inf(&K_agg);
        for(int i=0; i<n; ++i) {
            mpz_class m_i = H_Tag(user.tags[i]);
            ECP2 temp;
            ECP2_copy(&temp, &user.tags[i].B_tilde);
            ECP2_mul(temp, m_i);
            ECP2_add(&temp, &user.tags[i].A_tilde);
            ECP2_add(&K_agg, &temp); // Accumulate
        }

        // ---------------------------------------------
        // 2. Randomize & Commit (ZK Proof)
        // ---------------------------------------------
        mpz_class r = rand_mpz(state_gmp) % pp.q;
        mpz_class t = rand_mpz(state_gmp) % pp.q;

        // H' = H^r
        ECP_copy(&sig.H_prime, &user.H);
        ECP_mul(sig.H_prime, r);

        // sigma' = (sigma_agg + H^t)^r
        ECP temp;
        ECP_copy(&temp, &user.H);
        ECP_mul(temp, t);
        ECP_add(&temp, &sigma_agg);
        ECP_mul(temp, r);
        ECP_copy(&sig.sigma_prime, &temp);

        // hat_E = e(sigma', Y) * e(H', K_agg)^-1
        FP12 term1 = e(sig.sigma_prime, pp.Y_tilde);
        FP12 term2 = e(sig.H_prime, K_agg);
        FP12_inv(term2);
        FP12 hat_E;
        FP12_copy(&hat_E, &term1);
        FP12_mulMy(hat_E, term2);

        // hat_F = e(H', Y)
        FP12 hat_F = e(sig.H_prime, pp.Y_tilde);

        // Commitment R = hat_F^k
        mpz_class k = rand_mpz(state_gmp) % pp.q;
        FP12_copy(&sig.R, &hat_F);
        FP12_pow(sig.R, k);

        // Challenge c & Response s
        mpz_class c = H3(K_agg, sig.H_prime, sig.sigma_prime, sig.R);
        mpz_class prod = (c * t) % pp.q;
        sig.s = (k + prod) % pp.q;

        // ---------------------------------------------
        // 3. Message Signature
        // ---------------------------------------------
        mpz_class x = rand_mpz(state_gmp) % pp.q;

        // hat_Z_x = hat_Z ^ x
        FP12_copy(&sig.hat_Z_x, &pp.hat_Z);
        FP12_pow(sig.hat_Z_x, x);

        // Collect T_vks for Hash
        vector<ECP> T_vks;
        for(auto& tag : user.tags) T_vks.push_back(tag.T_vk);

        // h = H4(msg, Z_x, {T_vk})
        mpz_class h = H2(msg, sig.hat_Z_x, T_vks);

        // sigma_x = (prod T_sk)^{h*x} * X^x

        // 1. Sum T_sk
        ECP T_sk_agg;
        ECP_copy(&T_sk_agg, &user.T_sk[0]);
        for(int i=1; i<n; ++i) {
            ECP_add(&T_sk_agg, &user.T_sk[i]);
        }

        // 2. Multiply by h * x
        mpz_class hx = (h * x) % pp.q;
        ECP_mul(T_sk_agg, hx);

        // 3. X * x
        ECP X_x;
        ECP_copy(&X_x, &pp.X);
        ECP_mul(X_x, x);

        // 4. Add together
        ECP_copy(&sig.sigma_x, &T_sk_agg);
        ECP_add(&sig.sigma_x, &X_x);

        // 5. PK_U_tilde_r = PK_U^x
        ECP2_copy(&sig.PK_U_tilde_r,&user.PK_U);
        ECP2_mul(sig.PK_U_tilde_r, x);

        return sig;
    }

    bool Verify(DatParams pp, DatSignature sig, vector<DatTag> tags, string msg) {
        if (tags.empty()) {
            cout << "Verify Error: No tags provided." << endl;
            return false;
        }

        // ============================================
        // 0. Verify Timestamps
        // ============================================
        time_t now = time(nullptr);
        mpz_class current_time_mpz = (unsigned long)now;

        for(size_t i = 0; i < tags.size(); ++i) {
            if (current_time_mpz >= tags[i].T_exp) {
                cout << "Verify Error: Tag[" << i << "] has expired!" << endl;
                cout << "  Current Time: ";
                show_mpz(current_time_mpz.get_mpz_t());
                cout << "  Expire Time:  ";
                show_mpz(tags[i].T_exp.get_mpz_t());
                return false;
            }
        }
//        cout << "[Verify] 1. Timestamp Verification Passed." << endl;

        int n = tags.size();

        // 1. Reconstruct K_agg
        ECP2 K_agg;
        ECP2_inf(&K_agg);
        for(int i=0; i<n; ++i) {
            mpz_class m_i = H_Tag(tags[i]);
            ECP2 temp;
            ECP2_copy(&temp, &tags[i].B_tilde);
            ECP2_mul(temp, m_i);
            ECP2_add(&temp, &tags[i].A_tilde);
            ECP2_add(&K_agg, &temp);
        }
        ECP2_affine(&K_agg);

        // 2. Verify ZK Proof
        // hat_E = e(sigma', Y) * e(H', K_agg)^-1
        FP12 hat_E;
        FP12 t1 = e(sig.sigma_prime, pp.Y_tilde);
        FP12 t2 = e(sig.H_prime, K_agg);
        FP12_inv(t2);
        FP12_copy(&hat_E, &t1);
        FP12_mulMy(hat_E, t2);

        FP12 hat_F = e(sig.H_prime, pp.Y_tilde);

        mpz_class c = H3(K_agg, sig.H_prime, sig.sigma_prime, sig.R);

        FP12 LHS; FP12_copy(&LHS, &hat_F); FP12_pow(LHS, sig.s);
        FP12 RHS; FP12_copy(&RHS, &hat_E); FP12_pow(RHS, c);
        FP12_mulMy(RHS, sig.R);

        FP12_reduce(&LHS);
        FP12_reduce(&RHS);

        if (!FP12_equals(&LHS, &RHS)) {
            cout << "ZK Proof Verification Failed." << endl;
            return false;
        }
//        cout << "[Verify] 2. Zero-Knowledge Proof (ZK) Passed." << endl;

        // 3. Verify Message Signature
        // Equation: e(sigma_x, Y) == hat_Z_x * e( (Sum(T_vk))^h, PK_U' )
        vector<ECP> T_vks;
        for(auto& tag : tags) T_vks.push_back(tag.T_vk);

        mpz_class h = H2(msg, sig.hat_Z_x, T_vks);

        // 3.2 Compute LHS: e(sigma_x, Y)
        FP12 LHS_sig = e(sig.sigma_x, pp.Y_tilde);

        // 3.3 Compute RHS: hat_Z_x * e( T_vk_agg * h, PK_U' )

        // Step A: Sum(T_vk)
        ECP T_vk_agg;
        ECP_copy(&T_vk_agg, &tags[0].T_vk);
        for(int i=1; i<n; ++i) {
            ECP_add(&T_vk_agg, &tags[i].T_vk);
        }

        // Step B: (Sum(T_vk))^h
        ECP_mul(T_vk_agg, h);  // 使用计算出来的 h

        // Step C: Pairing e( ..., PK_U_tilde_r )
        FP12 pair_part = e(T_vk_agg, sig.PK_U_tilde_r);

        // Step D: hat_Z_x * Pairing
        FP12 RHS_sig;
        FP12_copy(&RHS_sig, &sig.hat_Z_x);
        FP12_mulMy(RHS_sig, pair_part);

        // 3.4 Compare
        FP12_reduce(&LHS_sig);
        FP12_reduce(&RHS_sig);

        if (!FP12_equals(&LHS_sig, &RHS_sig)) {
            cout << "Signature Verification Failed." << endl;
            return false;
        }
//        cout << "[Verify] 3. Message Signature Verification Passed." << endl;

        return true;
    }

    bool parVerify(DatParams pp, DatSignature sig, vector<DatTag> tags, string msg) {
        if (tags.empty()) {
            cout << "Verify Error: No tags provided." << endl;
            return false;
        }

        // ============================================
        // 0. Verify Timestamps
        // ============================================
        time_t now = time(nullptr);
        mpz_class current_time_mpz = (unsigned long)now;

        for(size_t i = 0; i < tags.size(); ++i) {
            if (current_time_mpz >= tags[i].T_exp) {
                cout << "Verify Error: Tag[" << i << "] has expired!" << endl;
                cout << "  Current Time: ";
                show_mpz(current_time_mpz.get_mpz_t());
                cout << "  Expire Time:  ";
                show_mpz(tags[i].T_exp.get_mpz_t());
                return false;
            }
        }

        // 1. Verify Message Signature
        // Equation: e(sigma_x, Y) == hat_Z_x * e( (Sum(T_vk))^h, PK_U' )
        vector<ECP> T_vks;
        for(auto& tag : tags) T_vks.push_back(tag.T_vk);

        mpz_class h = H2(msg, sig.hat_Z_x, T_vks);

        // 1.2 Compute LHS: e(sigma_x, Y)
        FP12 LHS_sig = e(sig.sigma_x, pp.Y_tilde);

        // 1.3 Compute RHS: hat_Z_x * e( T_vk_agg * h, PK_U' )

        // Step A: Sum(T_vk)
        ECP T_vk_agg;
        ECP_copy(&T_vk_agg, &tags[0].T_vk);
        for(int i=1; i<tags.size(); ++i) {
            ECP_add(&T_vk_agg, &tags[i].T_vk);
        }

        // Step B: (Sum(T_vk))^h
        ECP_mul(T_vk_agg, h);  // 使用计算出来的 h

        // Step C: Pairing e( ..., PK_U_tilde_r )
        FP12 pair_part = e(T_vk_agg, sig.PK_U_tilde_r);

        // Step D: hat_Z_x * Pairing
        FP12 RHS_sig;
        FP12_copy(&RHS_sig, &sig.hat_Z_x);
        FP12_mulMy(RHS_sig, pair_part);

        // 1.4 Compare
        FP12_reduce(&LHS_sig);
        FP12_reduce(&RHS_sig);

        if (!FP12_equals(&LHS_sig, &RHS_sig)) {
            cout << "Signature Verification Failed." << endl;
            return false;
        }

        return true;
    }

    // =========================================================================
    //    ZK Proof Batch Verification (Handles s, c, R, H', sigma')
    //    Overhead: M + 1 Pairings
    // =========================================================================
    bool batchVerifyZK(DatParams pp, vector<DatSignature> sigs, vector<vector<DatTag>> all_tags) {
        int M = sigs.size();
        if (M == 0 || all_tags.size() != M) return false;

        // 1. Generate random factors delta_j to prevent cancellation attacks (128-bit is sufficient)
        vector<mpz_class> deltas(M);
        for(int j = 0; j < M; ++j) {
            mpz_urandomb(deltas[j].get_mpz_t(), state_gmp, 128);
        }

        // Initialize accumulators
        ECP G1_agg; ECP_inf(&G1_agg);        // For LHS: sum( delta * (s*H' - c*sigma') )
        FP12 Mid_Pairings; FP12_one(&Mid_Pairings); // For LHS: prod( e(delta*c*H', K_agg) )
        FP12 RHS; FP12_one(&RHS);          // For RHS: prod( R^delta )

        for(int j = 0; j < M; ++j) {
            // A. Reconstruct K_agg_j for the j-th user
            ECP2 K_agg; ECP2_inf(&K_agg);
            for(auto& tag : all_tags[j]) {
                mpz_class m_i = H_Tag(tag);
                ECP2 temp; ECP2_copy(&temp, &tag.B_tilde);
                ECP2_mul(temp, m_i);
                ECP2_add(&temp, &tag.A_tilde);
                ECP2_add(&K_agg, &temp);
            }
            ECP2_affine(&K_agg);

            // B. Verifier MUST recompute the challenge c_j to prevent forgery
            mpz_class c_j = H3(K_agg, sigs[j].H_prime, sigs[j].sigma_prime, sigs[j].R);

            // C. Precompute combined scalars
            mpz_class s_delta = (sigs[j].s * deltas[j]) % pp.q;
            mpz_class c_delta = (c_j * deltas[j]) % pp.q;

            // D. Compute inner terms for G1_agg: (s_delta * H') - (c_delta * sigma')
            ECP part1; ECP_copy(&part1, &sigs[j].H_prime); ECP_mul(part1, s_delta);
            ECP part2; ECP_copy(&part2, &sigs[j].sigma_prime); ECP_mul(part2, c_delta);
            ECP_sub(&part1, &part2);
            ECP_add(&G1_agg, &part1); // Accumulate into global G1_agg

            // E. Compute intermediate Pairing: e(c_delta * H', K_agg_j)
            // Perform scalar multiplication in G1 first, which is much faster than exponentiation in GT
            ECP H_prime_cdelta; ECP_copy(&H_prime_cdelta, &sigs[j].H_prime);
            ECP_mul(H_prime_cdelta, c_delta);
            FP12 pair_j = e(H_prime_cdelta, K_agg);
            FP12_mulMy(Mid_Pairings, pair_j); // Accumulate product of pairings

            // F. Accumulate product for RHS: R_j ^ delta_j
            FP12 R_delta; FP12_copy(&R_delta, &sigs[j].R);
            FP12_pow(R_delta, deltas[j]);
            FP12_mulMy(RHS, R_delta);
        }

        // 2. Final Verification
        // LHS = e(G1_agg, Y_tilde) * Mid_Pairings
        FP12 LHS = e(G1_agg, pp.Y_tilde);
        FP12_mulMy(LHS, Mid_Pairings);

        if (!FP12_equals(&LHS, &RHS)) {
            cout << "[Batch Verify] ZK Proof Batch Verification Failed!" << endl;
            return false;
        }
        return true;
    }

    // =========================================================================
    //    Message Signature Batch Verification (Handles sigma_x, Z_x, PK_U')
    //    Overhead: M + 1 Pairings
    // =========================================================================
    bool batchParVerify(DatParams pp, vector<DatSignature> sigs, vector<vector<DatTag>> all_tags, vector<string> msgs) {
        int M = sigs.size();
        if (M == 0 || all_tags.size() != M || msgs.size() != M) return false;

        // 0. Verify expiration timestamps for all tags
        time_t now = time(nullptr);
        mpz_class current_time_mpz = (unsigned long)now;
        for(int j = 0; j < M; ++j) {
            for(auto& tag : all_tags[j]) {
                if (current_time_mpz >= tag.T_exp) {
                    cout << "[Batch Verify] Error: Tag expired for user " << j << endl;
                    return false;
                }
            }
        }

        // 1. Generate random factors delta_j for the Small Exponent Test
        vector<mpz_class> deltas(M);
        for(int j = 0; j < M; ++j) {
            mpz_urandomb(deltas[j].get_mpz_t(), state_gmp, 128);
        }

        // 2. Compute LHS: Compressed into 1 Pairing
        // LHS = e( sum(delta_j * sigma_x_j), Y_tilde )
        ECP G1_agg; ECP_inf(&G1_agg);
        for(int j = 0; j < M; ++j) {
            ECP temp; ECP_copy(&temp, &sigs[j].sigma_x);
            ECP_mul(temp, deltas[j]);
            ECP_add(&G1_agg, &temp);
        }
        FP12 LHS = e(G1_agg, pp.Y_tilde);

        // 3. Compute RHS: prod(Z_x^delta) * prod(e(delta * h * T_vk_agg, PK_U'))
        FP12 RHS_Z; FP12_one(&RHS_Z);
        FP12 RHS_Pairings; FP12_one(&RHS_Pairings);

        for(int j = 0; j < M; ++j) {
            // Accumulate product of Z_x^delta
            FP12 Z_temp; FP12_copy(&Z_temp, &sigs[j].hat_Z_x);
            FP12_pow(Z_temp, deltas[j]);
            FP12_mulMy(RHS_Z, Z_temp);

            // Extract all T_vks for Hash computation and accumulate them
            vector<ECP> T_vks;
            ECP T_vk_agg; ECP_copy(&T_vk_agg, &all_tags[j][0].T_vk);
            T_vks.push_back(all_tags[j][0].T_vk);
            for(int i = 1; i < all_tags[j].size(); ++i) {
                T_vks.push_back(all_tags[j][i].T_vk);
                ECP_add(&T_vk_agg, &all_tags[j][i].T_vk);
            }

            // Compute h_j = H2(msg, Z_x, {T_vk})
            mpz_class h_j = H2(msgs[j], sigs[j].hat_Z_x, T_vks);

            // Compute scalar multiplier: delta_j * h_j
            mpz_class h_delta = (h_j * deltas[j]) % pp.q;

            // Scale T_vk_agg by h_delta
            ECP_mul(T_vk_agg, h_delta);

            // Execute Pairing and accumulate the product
            FP12 pair_j = e(T_vk_agg, sigs[j].PK_U_tilde_r);
            FP12_mulMy(RHS_Pairings, pair_j);
        }

        // Combine RHS components: RHS = RHS_Z * RHS_Pairings
        FP12 RHS; FP12_copy(&RHS, &RHS_Z);
        FP12_mulMy(RHS, RHS_Pairings);

        FP12_reduce(&LHS); FP12_reduce(&RHS);

        if (!FP12_equals(&LHS, &RHS)) {
            cout << "[Batch Verify] Message Signature Batch Verification Failed!" << endl;
            return false;
        }
        return true;
    }

    // =========================================================================
    // 3. Unified Batch Verification Interface (Combines ZK + Sigs)
    //    Total Overhead: 2M + 2 Pairings (Down from 5M for sequential)
    // =========================================================================
    bool batchVerifyAll(DatParams pp, vector<DatSignature> sigs, vector<vector<DatTag>> all_tags, vector<string> msgs) {
        // Step 1: Batch verify Zero-Knowledge Proofs (Privacy & Unforgeability)
        if (!batchVerifyZK(pp, sigs, all_tags)) {
            return false;
        }

        // Step 2: Batch verify Authorized Message Signatures
        if (!batchParVerify(pp, sigs, all_tags, msgs)) {
            return false;
        }

        return true;
    }

} // namespace DatTws