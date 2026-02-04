#ifndef SPSEQ_H
#define SPSEQ_H

#include "Tools.h"
#include <vector>
#include <iostream>

using namespace std;

namespace Spseq {

    extern csprng rng;
    extern gmp_randstate_t state_gmp;

    // ------------------------------
    // Data Structures
    // ------------------------------

    /**
     * @brief Bilinear Group Description (BG) structure.
     * Represents the bilinear group setting BG = (p, G1, G2, GT, P, P_hat, e).
     */
    typedef struct {
        mpz_class p;        ///< Prime order p of the group.
        ECP P;              ///< Generator point of group G1.
        ECP2 P_hat;         ///< Generator point of group G2.
    } SpseqParams;

    /**
     * @brief Secret Key (sk) structure.
     * Contains the vector of private key elements sk = (x_1, ..., x_l) where each x_i is in Zp.
     */
    typedef struct {
        vector<mpz_class> x; ///< Vector of private key scalars.
    } SpseqSK;

    /**
     * @brief Public Key (pk) structure.
     * Modified for G2-Message Signing:
     * Contains the vector of public key elements pk = (X_1, ..., X_l) where X_i = x_i * P (in G1).
     * Note: In standard SPSEQ, PK is usually in G2, but here it is in G1 to allow pairing with G2 messages.
     */
    typedef struct {
        vector<ECP> X;       ///< Vector of public key points in G1.
    } SpseqPK;

    /**
     * @brief Signature (sigma) structure.
     * Modified for G2-Message Signing:
     * Represents a signature sigma = (Z, Y, Y_hat).
     * - Z is the accumulated weighted sum of messages (in G2).
     * - Y and Y_hat are randomization components ensuring structure preservation.
     */
    typedef struct {
        ECP2 Z;          ///< Accumulated Message element in G2 (Z = y * Sum(x_i * M_i)).
        ECP Y;           ///< Randomizer element part 1 in G1 (Y = (1/y) * P).
        ECP2 Y_hat;      ///< Randomizer element part 2 in G2 (Y_hat = (1/y) * P_hat).
    } SpseqSignature;

    // ------------------------------
    // Core Algorithms
    // ------------------------------

    /**
     * @brief Setup algorithm to generate system public parameters.
     * Initializes the bilinear group environment and generators.
     * @return The generated SpseqParams structure containing group parameters.
     */
    SpseqParams Setup();

    /**
     * @brief Key Generation algorithm.
     * Generates a key pair for a message vector of length l.
     * @param pp System public parameters.
     * @param l The length of the message vector to be signed.
     * @param sk Output parameter for the generated Secret Key.
     * @param pk Output parameter for the generated Public Key.
     */
    void KeyGen(SpseqParams pp, int l, SpseqSK &sk, SpseqPK &pk);

    /**
     * @brief Signing algorithm.
     * Generates a signature for a vector of messages, where each message element is in G2.
     * @param pp System public parameters.
     * @param sk The signer's Secret Key.
     * @param M The vector of messages (in G2) to be signed.
     * @return The generated SpseqSignature structure.
     */
    SpseqSignature Sign(SpseqParams pp, SpseqSK sk, vector<ECP2>& M);

    /**
     * @brief Verification algorithm.
     * Verifies the validity of a signature on a vector of G2 messages.
     * @param pp System public parameters.
     * @param pk The signer's Public Key.
     * @param M The vector of messages (in G2) that was signed.
     * @param sig The signature to verify.
     * @return True if the signature is valid, false otherwise.
     */
    bool Verify(SpseqParams pp, SpseqPK pk, const vector<ECP2>& M, SpseqSignature sig);

    /**
     * @brief Change Representative (ChgRep) algorithm.
     * Adapts a valid signature on message M to be valid for a transformed message M' = mu * M.
     * This allows for randomization of the underlying message while maintaining a valid signature.
     * @param pp System public parameters.
     * @param pk The signer's Public Key.
     * @param M The original message vector (in G2).
     * @param sig The original signature on M.
     * @param mu The scalar multiplier for the message transformation.
     * @return A new SpseqSignature valid for the message mu * M.
     */
    SpseqSignature ChgRep(SpseqParams pp, SpseqPK pk, const vector<ECP2>& M, SpseqSignature sig, mpz_class mu);

} // namespace Spseq

#endif // SPSEQ_H