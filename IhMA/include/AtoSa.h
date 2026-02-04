#ifndef ATO_SA_H
#define ATO_SA_H

#include "Tools.h"
#include <string>
#include <vector>
#include <iostream>

using namespace std;

namespace AtoSa {

    extern csprng rng;
    extern gmp_randstate_t state_gmp;

    // ------------------------------
    // Data Structures
    // ------------------------------

    /**
     * @brief System public parameters structure.
     * Represents the bilinear group setting BG = (p, G1, G2, GT, P, P_hat, e).
     */
    typedef struct {
        mpz_class p;        ///< Prime order p of the group.
        ECP P;              ///< Generator point of group G1.
        ECP2 P_hat;         ///< Generator point of group G2.
        // H function is implemented as a method
    } AtoSaParams;

    /**
     * @brief Secret Key (sk) structure.
     * Contains the private components sk = (x, y1, y2).
     */
    typedef struct {
        mpz_class x;        ///< Private key component x.
        mpz_class y1;       ///< Private key component y1.
        mpz_class y2;       ///< Private key component y2.
    } AtoSaSK;

    /**
     * @brief Verification Key (vk) structure.
     * Contains the public components vk = (Y1_hat, Y2_hat, X_hat).
     */
    typedef struct {
        ECP2 Y1_hat;    ///< Public key component Y1_hat = P_hat ^ y1.
        ECP2 Y2_hat;    ///< Public key component Y2_hat = P_hat ^ y2.
        ECP2 X_hat;     ///< Public key component X_hat = P_hat ^ x.
    } AtoSaVK;

    /**
     * @brief Auxiliary Tag Information (aux) structure.
     * Holds the randomness and hash used during tag generation.
     */
    typedef struct {
        mpz_class rho1;     ///< Random scalar rho1.
        mpz_class rho2;     ///< Random scalar rho2.
        ECP h;              ///< Hash value h = H(c) in G1.
    } AtoSaAux;

    /**
     * @brief Tag (T) structure.
     * Represents the user's tag T = (T1, T2) along with auxiliary data.
     */
    typedef struct {
        ECP T1;         ///< Tag component T1 = h ^ rho1.
        ECP T2;         ///< Tag component T2 = h ^ rho2.
        AtoSaAux aux;   ///< Auxiliary information (rho1, rho2, h) stored for the signing process.
    } AtoSaTag;

    /**
     * @brief Signature (sigma) structure.
     * Represents a signature on a message, sigma = (h', s).
     */
    typedef struct {
        ECP h_prime;    ///< Signature base h' (which corresponds to T1).
        ECP s;          ///< Signature element s.
    } AtoSaSignature;

    // ------------------------------
    // Core Algorithms
    // ------------------------------

    /**
     * @brief Setup algorithm to generate system public parameters.
     * Initializes the bilinear group environment and generators.
     * @return The generated AtoSaParams structure containing group parameters.
     */
    AtoSaParams Setup();

    /**
     * @brief Key Generation algorithm.
     * Generates a public/private key pair for an entity.
     * @param pp System public parameters.
     * @param sk Output parameter for the generated Secret Key.
     * @param vk Output parameter for the generated Verification Key.
     */
    void KeyGen(AtoSaParams pp, AtoSaSK &sk, AtoSaVK &vk);

    /**
     * @brief Auxiliary Tag Generation algorithm.
     * Generates a Tag T and auxiliary information for a set of messages and verification keys.
     * @param pp System public parameters.
     * @param msgs Vector of messages (as strings) associated with the tag.
     * @param vks Vector of Verification Keys corresponding to the messages.
     * @return The generated AtoSaTag structure containing T and aux.
     */
    AtoSaTag GenAuxTag(AtoSaParams pp, const vector<string>& msgs, const vector<AtoSaVK>& vks);

    /**
     * @brief Signing algorithm.
     * Generates a signature for a single message using the secret key and tag.
     * @param pp System public parameters.
     * @param sk The signer's Secret Key.
     * @param tag The user's Tag.
     * @param msg The message string to be signed.
     * @return The generated AtoSaSignature structure.
     */
    AtoSaSignature Sign(AtoSaParams pp, AtoSaSK sk, AtoSaTag tag, string msg);

    /**
     * @brief Signature Aggregation algorithm.
     * Aggregates multiple signatures into a single signature.
     * @param sigs Vector of individual AtoSaSignature structures to aggregate.
     * @return The aggregated AtoSaSignature.
     */
    AtoSaSignature AggrSign(vector<AtoSaSignature>& sigs);

    /**
     * @brief Aggregated Verification algorithm.
     * Verifies an aggregated signature against a set of messages and verification keys.
     * Can also be used for single signature verification if vectors have size 1.
     * @param pp System public parameters.
     * @param avk Vector of Verification Keys corresponding to the messages.
     * @param tag The user's Tag.
     * @param msgs Vector of messages that were signed.
     * @param sig The aggregated signature to verify.
     * @return True if the signature is valid, false otherwise.
     */
    bool VerifyAggr(AtoSaParams pp, vector<AtoSaVK>& avk, AtoSaTag tag, const vector<string>& msgs, AtoSaSignature sig);

    /**
     * @brief Verification Key Conversion algorithm.
     * Transforms a verification key by exponentiating with a scalar omega (vk' = vk^omega).
     * Used for randomization purposes.
     * @param vk The Verification Key to convert (updated in place or returned as new).
     * @param omega The scalar value for transformation.
     * @return The transformed Verification Key.
     */
    AtoSaVK ConvertVK(AtoSaVK& vk, const mpz_class& omega);

    /**
     * @brief Signature Conversion algorithm.
     * Transforms a signature by exponentiating component s with scalar omega (s' = s^omega).
     * Matches the transformation applied to the Verification Key.
     * @param sig The signature to convert.
     * @param omega The scalar value for transformation.
     * @return The transformed AtoSaSignature.
     */
    AtoSaSignature ConvertSig(AtoSaSignature& sig, const mpz_class& omega);

    /**
     * @brief Randomized Signature and Tag generation algorithm.
     * Randomizes both the Tag (T) and the Signature (sigma) using a random scalar nu.
     * Computes T' = T^nu and sigma' = (h'^nu, s^nu).
     * @param vk The Verification Key (included for protocol consistency).
     * @param tag The Tag to be randomized (updated in place).
     * @param msg The message string (included for protocol consistency).
     * @param sig The Signature to be randomized (updated in place).
     * @param nu The random scalar used for randomization.
     */
    void RandSigTag(AtoSaVK vk, AtoSaTag& tag, string msg, AtoSaSignature& sig, const mpz_class& nu);


    // ------------------------------
    // Helper Functions
    // ------------------------------

    /**
     * @brief Hash function mapping commitment c to a point in G1.
     * Computes h = H(c) -> G1.
     * @param pp System public parameters.
     * @param part1 First part of commitment (ECP).
     * @param part2 Second part of commitment (ECP).
     * @param msgs Vector of messages involved in the commitment.
     * @param vks Vector of Verification Keys involved in the commitment.
     * @return The resulting point in G1.
     */
    ECP HashToG1(AtoSaParams pp, ECP part1, ECP part2, const vector<string>& msgs, const vector<AtoSaVK>& vks);

    /**
     * @brief Hash function mapping a string message to an integer in Zp.
     * @param msg The message string to hash.
     * @return The resulting large integer (mpz_class) in Zp.
     */
    mpz_class HashMsgToZp(string msg);

} // namespace AtoSa

#endif // ATO_SA_H