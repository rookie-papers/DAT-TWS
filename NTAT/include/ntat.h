#ifndef NTAT_H
#define NTAT_H

#include "Tools.h"
#include <string>
#include <vector>

using namespace std;

namespace Ntat {

    extern csprng rng;
    extern gmp_randstate_t state_gmp;

    // ------------------------------
    // System Parameters
    // ------------------------------

    /**
     * @brief System public parameters structure.
     * Contains the prime order and the required generators for the bilinear groups.
     */
    struct NtatParams {
        mpz_class q;       ///< Prime order q of the group.
        ECP G1;            ///< Generator point of group G1.
        ECP2 G2;           ///< Generator point of group G2.
        ECP G3;            ///< Alternate generator point of group G1.
        ECP G4;            ///< Alternate generator point of group G1.
    };

    // ------------------------------
    // Entities Data Structures
    // ------------------------------

    /**
     * @brief Client's key structure.
     * Contains the client's secret key and the corresponding public key.
     */
    struct ClientKeys {
        mpz_class sk_c;    ///< Client's secret key x.
        ECP pk_c;          ///< Client's public key X = x * G1.
    };

    /**
     * @brief Server's key structure.
     * Contains the server's secret signing key and the public verification key.
     */
    struct ServerKeys {
        mpz_class sk_s;    ///< Server's secret key y.
        ECP2 pk_s;         ///< Server's public verification key Y = y * G2.
    };

    // ------------------------------
    // Protocol Data Structures
    // ------------------------------

    /**
     * @brief NIZK Proof Pi_C structure.
     * Corresponds to Pi_REP3 in Figure 9. Proves the client's knowledge for the query.
     */
    struct ProofPiC {
        mpz_class ch;      ///< Challenge value ch.
        mpz_class resp1;   ///< Response value resp1.
        mpz_class resp2;   ///< Response value resp2.
        mpz_class resp3;   ///< Response value resp3.
    };

    /**
     * @brief Query payload sent from the Client to the Server.
     * Contains the blinded commitment and the non-interactive zero-knowledge proof.
     */
    struct QueryPayload {
        ECP T;             ///< Blinded commitment T.
        ProofPiC pi_c;     ///< Non-interactive zero-knowledge proof Pi_C.
    };

    /**
     * @brief Client's temporary state structure.
     * Stores intermediate randomness required to unblind the credential later.
     */
    struct ClientState {
        mpz_class r;       ///< Client's randomness r.
        mpz_class delta;   ///< Blinding factor delta.
        ECP T;             ///< Blinded commitment T.
    };

    /**
     * @brief Issuance response returned by the Server to the Client.
     * Contains the server's injected randomness and the issued credential component.
     */
    struct ServerIssueResp {
        mpz_class s;       ///< Server's injected randomness s.
        ECP S;             ///< Issued credential component S.
    };

    /**
     * @brief Final NTAT token (credential) structure obtained by the Client.
     */
    struct NtatToken {
        ECP sigma;         ///< Unblinded credential signature component.
        mpz_class r;       ///< Client's randomness r.
        mpz_class s;       ///< Server's injected randomness s.
    };

    /**
     * @brief Redemption payload sent from the Client to the Server.
     * Transforms the redemption phase into a non-interactive proof using Fiat-Shamir.
     */
    struct RedeemPayload {
        ECP sigma;         ///< Original token signature (required for pairing verification).
        ECP sigma_prime;   ///< Randomized token element \sigma'.
        mpz_class comm;    ///< Hash commitment H3(\rho, Q).
        mpz_class v0;      ///< Zero-knowledge response v0.
        mpz_class v1;      ///< Zero-knowledge response v1.
        mpz_class v2;      ///< Zero-knowledge response v2.
        mpz_class rho;     ///< Random factor \rho.
    };

    // ------------------------------
    // Core Algorithms
    // ------------------------------

    /**
     * @brief Setup algorithm to generate system public parameters.
     * @return The generated NtatParams structure.
     */
    NtatParams Setup();

    /**
     * @brief Client Key Generation algorithm.
     * @param pp System public parameters.
     * @return The generated ClientKeys structure.
     */
    ClientKeys ClientKeyGen(NtatParams pp);

    /**
     * @brief Server Key Generation algorithm.
     * @param pp System public parameters.
     * @return The generated ServerKeys structure.
     */
    ServerKeys ServerKeyGen(NtatParams pp);

    /**
     * @brief Client Query algorithm (Issuance Phase).
     * Initiates the credential issuance request by computing a blinded commitment and a NIZK proof.
     * @param pp System public parameters.
     * @param keys The client's key pair.
     * @param st The client's state to be updated and stored.
     * @return The QueryPayload containing the commitment T and the proof Pi_C.
     */
    QueryPayload ClientQuery(NtatParams pp, ClientKeys keys, ClientState &st);

    /**
     * @brief Server Issue algorithm (Issuance Phase).
     * Verifies the client's query proof and computes the blinded credential.
     * @param pp System public parameters.
     * @param sk The server's key pair.
     * @param pk_c The client's public key.
     * @param query The query payload provided by the client.
     * @return The ServerIssueResp structure containing the server's signature component.
     */
    ServerIssueResp ServerIssue(NtatParams pp, ServerKeys sk, ECP pk_c, QueryPayload query);

    /**
     * @brief Client Finalization algorithm (Issuance Phase).
     * Verifies the server's response using bilinear pairings and unblinds the credential.
     * @param pp System public parameters.
     * @param pk_s The server's public key.
     * @param st The client's stored state from the query phase.
     * @param resp The issuance response provided by the server.
     * @return The finalized NtatToken structure.
     */
    NtatToken ClientFinal(NtatParams pp, ECP2 pk_s, ClientState st, ServerIssueResp resp);

    /**
     * @brief Client Prove algorithm (Redemption Phase).
     * Generates a randomized redemption payload using a non-interactive zero-knowledge proof.
     * @param pp System public parameters.
     * @param keys The client's key pair.
     * @param pk_s The server's public key.
     * @param token The finalized NTAT token to be redeemed.
     * @return The RedeemPayload structure to be verified by the server.
     */
    RedeemPayload ClientProve(NtatParams pp, ClientKeys keys, ECP2 pk_s, NtatToken token);

    /**
     * @brief Server Verify algorithm (Redemption Phase).
     * Publicly verifies the redemption payload using pairings and zero-knowledge checks.
     * @param pp System public parameters.
     * @param pk_s The server's public key.
     * @param payload The redemption payload provided by the client.
     * @return True if the redemption payload is valid, false otherwise.
     */
    bool ServerVerify(NtatParams pp, ECP2 pk_s, RedeemPayload payload);

    // ------------------------------
    // Hash & Helper Functions
    // ------------------------------

    /**
     * @brief Helper function for safe modular subtraction.
     * @param a The minuend.
     * @param b The subtrahend.
     * @param q The modulus.
     * @return The result of (a - b) mod q.
     */
    mpz_class mod_sub(mpz_class a, mpz_class b, mpz_class q);

    /**
     * @brief Hash function H1 used for Pi_C proof generation.
     * @param X The client's public key.
     * @param T The blinded commitment.
     * @param comm1 The first commitment element.
     * @param comm2 The second commitment element.
     * @return Hash output serving as the challenge `ch` in Zp.
     */
    mpz_class H1(ECP X, ECP T, ECP comm1, ECP comm2);

    /**
     * @brief Hash function H3 used for the Redemption phase commitment.
     * @param rho The random factor \rho.
     * @param Q The commitment point.
     * @return Hash output in Zp.
     */
    mpz_class H3(mpz_class rho, ECP Q);

    /**
     * @brief Hash function used to generate the Fiat-Shamir challenge in the Redemption phase.
     * @param comm The hash commitment.
     * @param sigma_prime The randomized token element.
     * @return Hash output serving as the challenge `c` in Zp.
     */
    mpz_class H_Challenge(mpz_class comm, ECP sigma_prime);

} // namespace Ntat

#endif // NTAT_H