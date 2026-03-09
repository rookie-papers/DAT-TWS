#ifndef DTACB_H
#define DTACB_H

#include "Tools.h"
#include <string>
#include <vector>
#include <cstdint> // Required for uint8_t

using namespace std;

namespace Dtacb {

    extern csprng rng;
    extern gmp_randstate_t state_gmp;

    // ------------------------------
    // System Parameters
    // ------------------------------

    /**
     * @brief System public parameters structure.
     * Contains the bilinear group parameters and the dynamic accumulator parameters.
     */
    struct DtacbParams {
        mpz_class q;                   ///< Prime order q of the group.
        ECP g1;                        ///< Generator point of group G1.
        ECP g1_tilde;                  ///< Alternate generator point of group G1.
        ECP2 g2;                       ///< Generator point of group G2.
        ECP2 g2_tilde;                 ///< Alternate generator point of group G2.
        ECP g1_u;                      ///< System parameter g1^u.
        ECP2 g2_u;                     ///< System parameter g2^u.
        ECP2 g2_tilde_u;               ///< System parameter \tilde{g}_2^u, used for CM^u verification.

        // Accumulator parameters
        int t;                         ///< Maximum capacity of the accumulator.
        vector<ECP> acc_g1_s;          ///< Accumulator parameter array: g1^{s^i}.
        vector<ECP2> acc_g2_s;         ///< Accumulator parameter array: g2^{s^i}.
        vector<ECP2> acc_g2_us;        ///< Accumulator parameter array: g2^{u * s^i}.

        // Accumulator shift parameters for batch verification
        vector<ECP2> acc_g2_tilde_s;   ///< Accumulator parameter array: \tilde{g}_2^{s^i}.
        vector<ECP2> acc_g2_tilde_us;  ///< Accumulator parameter array: \tilde{g}_2^{u * s^i}.
    };

    // ------------------------------
    // Entities Data Structures
    // ------------------------------

    /**
     * @brief Issuer's key structure.
     * Contains the secret signing key and the public verification key.
     */
    struct Issuer {
        mpz_class isk;   ///< Issuer's secret key x_i.
        ECP2 ipk;        ///< Issuer's public key g2^{x_i}.
    };

    /**
     * @brief User's state structure.
     * Contains the user's ElGamal key pair for blinding credentials.
     */
    struct User {
        mpz_class z;     ///< User's ElGamal secret key.
        ECP Z;           ///< User's ElGamal public key (g1^z).
    };

    // ------------------------------
    // Protocol Data Structures
    // ------------------------------

    /**
     * @brief NIZK Proof Theta 1 structure.
     * Proves the knowledge of user's registration secrets (z, m, l, o).
     */
    struct NIZK_Theta1 {
        mpz_class c;     ///< Challenge value c.
        mpz_class s_z;   ///< Response value s_z.
        mpz_class s_m;   ///< Response value s_m.
        mpz_class s_l;   ///< Response value s_l.
        mpz_class s_o;   ///< Response value s_o.
    };

    /**
     * @brief Registration info sent from User to Issuer.
     * Contains commitments, ciphertext, and the zero-knowledge proof Theta 1.
     */
    struct RegInfo {
        ECP c_m;            ///< Commitment to the message: g1^m * g1_tilde^l.
        ECP Z;              ///< User's ElGamal public key.
        ECP C1;             ///< Ciphertext part 1: g1^o.
        ECP C2;             ///< Ciphertext part 2: Z^o * h^m.
        NIZK_Theta1 theta1; ///< Non-interactive zero-knowledge proof Theta 1.
    };

    /**
     * @brief Blinded partial credential returned by Issuer to User.
     */
    struct BlindedPartialCred {
        ECP C1_tilde;    ///< Blinded component C1^{r_i}.
        ECP C2_tilde;    ///< Blinded component h^{x_i} * C2^{r_i}.
        ECP2 R_i;        ///< Randomness commitment g2^{r_i}.
    };

    /**
     * @brief Unblinded valid partial credential stored by the User.
     */
    struct PartialCred {
        ECP cred_1;      ///< Base credential component h.
        ECP cred_2;      ///< Signature component h^{x_i + r_i * m}.
        ECP2 R_i;        ///< Issuer's randomness commitment.
    };

    /**
     * @brief Final aggregated credential (CRED).
     */
    struct Credential {
        ECP CRED_1;      ///< Aggregated base component.
        ECP CRED_2;      ///< Aggregated signature component.
    };

    /**
     * @brief Randomized aggregated credential (CRED').
     * Used during the credential proving phase to preserve anonymity.
     */
    struct RandomizedCred {
        ECP CRED_prime_1; ///< Randomized base component.
        ECP CRED_prime_2; ///< Randomized signature component.
    };

    /**
     * @brief NIZK Proof Theta 2 structure.
     * Proves the validity of the randomized credential and knowledge of (m, alpha).
     */
    struct NIZK_Theta2 {
        mpz_class c;       ///< Challenge value c.
        mpz_class s_m;     ///< Response value s_m.
        mpz_class s_alpha; ///< Response value s_alpha.
    };

    /**
     * @brief Token sent to Judger during the ProveCred phase.
     * Contains the randomized credential, threshold bits, and the Theta 2 proof.
     */
    struct ProveToken {
        ECP2 R;                     ///< Aggregated randomness R.
        vector<uint8_t> b;          ///< Dynamic threshold bit vector indicating signing issuers.
        ECP2 IPK;                   ///< Aggregated public key of signing issuers.
        RandomizedCred CRED_prime;  ///< Randomized aggregated credential.
        ECP2 rho;                   ///< Verification helper element rho.
        ECP mu;                     ///< Verification helper element mu.
        NIZK_Theta2 theta2;         ///< Non-interactive zero-knowledge proof Theta 2.
    };

    /**
     * @brief Batch Proof structure (\Upsilon).
     * Used for batch-showing of multiple credentials via polynomial commitments.
     */
    struct BatchProof {
        ECP2 CM_P;           ///< Commitment to the polynomial P(s).
        ECP2 CM_f;           ///< Commitment to the remainder polynomial f(s).
        ECP2 CM_u;           ///< Commitment shifted by u for knowledge extraction.
        ECP2 CM;             ///< Shifted commitment for degree bounding.
        ECP Pi_a;            ///< Randomized component a of aggregated membership proof Pi.
        ECP Pi_b;            ///< Randomized component b of aggregated membership proof Pi.
        ECP T1;              ///< Zero-knowledge component T1.
        ECP T2;              ///< Zero-knowledge component T2.
        FP12 T3;             ///< Zero-knowledge pairing component T3.
        mpz_class W_j;       ///< Response for randomness j.
        mpz_class W_tau1;    ///< Response for randomness tau1.
        mpz_class W_tau2;    ///< Response for randomness tau2.
        mpz_class W_delta1;  ///< Response for randomness delta1.
        mpz_class W_delta2;  ///< Response for randomness delta2.
    };

    // ------------------------------
    // Core Algorithms
    // ------------------------------

    /**
     * @brief Setup algorithm to generate system public parameters.
     * @param max_acc_capacity Maximum capacity (t) of the dynamic accumulator.
     * @return The generated DtacbParams structure.
     */
    DtacbParams Setup(int max_acc_capacity);

    /**
     * @brief Issuer Key Generation algorithm.
     * Generates a public/private key pair for a specified number of issuers.
     * @param pp System public parameters.
     * @param issuers Output vector containing generated Issuer structures.
     * @param n Number of issuers to generate.
     */
    void IKGen(DtacbParams& pp, vector<Issuer>& issuers, int n);

    /**
     * @brief Registration data generation by the User (Obtain Phase).
     * @param pp System public parameters.
     * @param user The user initiating the request (generates internal ElGamal keys).
     * @param m The hidden message/attribute of the user.
     * @param l Random scalar used for the message commitment.
     * @return RegInfo structure containing blinded registration data and NIZK proof.
     */
    RegInfo Obtain(DtacbParams& pp, User& user, mpz_class m, mpz_class l);

    /**
     * @brief Credential issuance by the Issuer (Issue Phase).
     * The Issuer blindly signs the user's ciphertext after verifying Theta 1.
     * @param pp System public parameters.
     * @param issuer The issuer performing the blind signing.
     * @param reg The registration info provided by the user.
     * @return BlindedPartialCred structure containing the blinded signature components.
     */
    BlindedPartialCred Issue(DtacbParams& pp, const Issuer& issuer, RegInfo& reg);

    /**
     * @brief Unblinding algorithm by the User.
     * Recovers the true partial credential using the user's ElGamal secret.
     * @param pp System public parameters.
     * @param user The user holding the ElGamal secret.
     * @param blinded_cred The blinded credential received from the issuer.
     * @param h The base hash element generated from the message commitment.
     * @return PartialCred structure containing the unblinded valid partial credential.
     */
    PartialCred Unblind(DtacbParams& pp, const User& user, BlindedPartialCred& blinded_cred, ECP h);

    /**
     * @brief Credential Aggregation algorithm.
     * Aggregates a threshold number of partial credentials into a single credential.
     * @param partials Vector of partial credentials obtained from different issuers.
     * @return The aggregated Credential structure.
     */
    Credential AggCred(vector<PartialCred>& partials);

    /**
     * @brief Credential Proving algorithm.
     * Randomizes the aggregated credential and generates a token containing NIZK Theta 2.
     * @param pp System public parameters.
     * @param cred The aggregated credential to prove.
     * @param m The user's hidden message.
     * @param partials Vector of unblinded partial credentials used for aggregation.
     * @param all_issuers Vector of all issuers in the system.
     * @param b Bit vector (uint8_t) indicating which issuers participated.
     * @return ProveToken structure to be sent to the Judger.
     */
    ProveToken ProveCred(DtacbParams& pp, Credential& cred, mpz_class m, vector<PartialCred>& partials, vector<Issuer>& all_issuers, const vector<uint8_t>& b);

    /**
     * @brief Credential Verification algorithm by the Judger.
     * Verifies the ProveToken using pairings and zero-knowledge checks.
     * @param pp System public parameters.
     * @param tok The token provided by the user.
     * @return True if the credential is valid, false otherwise.
     */
    bool VerCred(DtacbParams& pp, ProveToken& tok);

    // ------------------------------
    // Accumulator & Batch Algorithms
    // ------------------------------

    /**
     * @brief Helper to compute the coefficients of the polynomial P(s) = \prod (s + \sigma_i).
     * @param q The field order.
     * @param roots Vector of roots (\sigma_i) to build the polynomial.
     * @return Vector of coefficients from lowest degree to highest degree.
     */
    vector<mpz_class> GetPolyCoeffs(mpz_class q, const vector<mpz_class>& roots);

    /**
     * @brief Hash function dedicated to the batch-showing proof.
     * @return Hash output mapped to a scalar in Zp.
     */
    mpz_class Hash_Batch(ECP2 CM_P, ECP2 CM_f, ECP Pi_a, ECP Pi_b, ECP T1, ECP T2, FP12 T3);

    /**
     * @brief Batch-Showing algorithm (ZKBatchShow).
     * Generates a batch proof demonstrating possession of a specific number of valid credentials.
     * @param pp System public parameters.
     * @param Acc The global accumulator value.
     * @param Pi The aggregated membership proof computed via PFD.
     * @param P_set Vector of valid credential witnesses (sigma) possessed by the user.
     * @return BatchProof structure containing the zero-knowledge batch proof.
     */
    BatchProof ZKBatchShow(DtacbParams& pp, ECP Acc, ECP Pi, const vector<mpz_class>& P_set);

    /**
     * @brief Batch Verification algorithm (ZKBatchVer).
     * Verifies the batch proof without revealing the exact credential subset.
     * @param pp System public parameters.
     * @param Acc The global accumulator value.
     * @param proof The batch proof provided by the user.
     * @param n The claimed number of valid credentials in the batch.
     * @return True if the batch proof is valid, false otherwise.
     */
    bool ZKBatchVer(DtacbParams& pp, ECP Acc, BatchProof& proof, int n);

    // ------------------------------
    // Hash Functions
    // ------------------------------

    /**
     * @brief Hash function H1.
     * Maps the commitment c_m to a point on curve G1 to serve as the base `h`.
     * @param c_m The message commitment point in G1.
     * @return A valid curve point in G1.
     */
    ECP H1(ECP c_m);

    /**
     * @brief Hash function H2.
     * Maps the randomized credential to Zp to generate the accumulator witness `sigma`.
     * @param cred_prime The randomized credential structure.
     * @return Hash output as a large integer in Zp.
     */
    mpz_class H2(RandomizedCred cred_prime);

    // ------------------------------
    // NIZK Theta 1 Algorithms
    // ------------------------------

    /**
     * @brief Dedicated hash function for Theta 1 proof generation.
     * Implements the Fiat-Shamir heuristic to compute the challenge for the NIZK proof.
     * @param Z User's ElGamal public key.
     * @param c_m Commitment to the message.
     * @param C1 Ciphertext component 1.
     * @param C2 Ciphertext component 2.
     * @param R_Z Commitment to the randomness of Z.
     * @param R_cm Commitment to the randomness of c_m.
     * @param R_C1 Commitment to the randomness of C1.
     * @param R_C2 Commitment to the randomness of C2.
     * @return Hash output serving as the challenge `c` in Zp.
     */
    mpz_class Hash_Theta1(ECP Z, ECP c_m, ECP C1, ECP C2, ECP R_Z, ECP R_cm, ECP R_C1, ECP R_C2);

    /**
     * @brief Prover (User) generation of Theta 1.
     * Generates a non-interactive zero-knowledge proof demonstrating the user's knowledge
     * of the secret keys and randomness (z, m, l, o) used during the registration phase.
     * @param pp System public parameters.
     * @param h Base hash element in G1 computed from the commitment.
     * @param z User's ElGamal secret key.
     * @param m The hidden message/attribute.
     * @param l Randomness used for the message commitment.
     * @param o Randomness used for the ElGamal encryption.
     * @param reg The RegInfo structure containing the public values (Z, c_m, C1, C2).
     * @return The generated NIZK_Theta1 proof structure.
     */
    NIZK_Theta1 Prove_Theta1(DtacbParams& pp, ECP h, mpz_class z, mpz_class m, mpz_class l, mpz_class o, RegInfo& reg);

    /**
     * @brief Verifier (Issuer) checking of Theta 1.
     * Verifies the validity of the NIZK proof Theta 1 before issuing a partial credential.
     * @param pp System public parameters.
     * @param h Base hash element in G1 computed from the commitment.
     * @param reg The RegInfo structure containing the public values and the Theta 1 proof.
     * @return True if the proof is valid, false otherwise.
     */
    bool Verify_Theta1(DtacbParams& pp, ECP h, RegInfo& reg);

    // ------------------------------
    // NIZK Theta 2 Algorithms
    // ------------------------------

    /**
     * @brief Dedicated hash function for Theta 2 proof generation.
     * Implements the Fiat-Shamir heuristic to compute the challenge for the credential showing proof.
     * @param IPK Aggregated public key of the signing issuers.
     * @param R Aggregated randomness from the issuers.
     * @param rho Verification helper element in G2.
     * @param CRED_prime_1 Randomized base component of the credential.
     * @param mu Verification helper element in G1.
     * @param R_rho Commitment to the randomness used in rho.
     * @param R_mu Commitment to the randomness used in mu.
     * @return Hash output serving as the challenge `c` in Zp.
     */
    mpz_class Hash_Theta2(ECP2 IPK, ECP2 R, ECP2 rho, ECP CRED_prime_1, ECP mu, ECP2 R_rho, ECP R_mu);

    /**
     * @brief Prover (User) generation of Theta 2.
     * Generates a non-interactive zero-knowledge proof demonstrating the user's knowledge
     * of the hidden message `m` and the blinding factor `alpha` used to randomize the credential.
     * @param pp System public parameters.
     * @param m The hidden message/attribute.
     * @param alpha The random scalar used to blind the aggregated credential.
     * @param R Aggregated randomness in G2.
     * @param IPK Aggregated public key in G2.
     * @param rho Verification helper element computed by the user.
     * @param CRED_prime_1 Randomized base component of the credential.
     * @param mu Verification helper element computed by the user.
     * @return The generated NIZK_Theta2 proof structure.
     */
    NIZK_Theta2 Prove_Theta2(DtacbParams& pp, mpz_class m, mpz_class alpha, ECP2 R, ECP2 IPK, ECP2 rho, ECP CRED_prime_1, ECP mu);

    /**
     * @brief Verifier (Judger) checking of Theta 2.
     * Verifies the NIZK proof Theta 2 to ensure the randomized credential is well-formed
     * and the user knows the underlying secrets.
     * @param pp System public parameters.
     * @param tok The ProveToken containing the public parameters, credential, and Theta 2 proof.
     * @return True if the proof is valid, false otherwise.
     */
    bool Verify_Theta2(DtacbParams& pp, ProveToken& tok);
}

#endif // DTACB_H