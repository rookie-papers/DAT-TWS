#ifndef IHMA_H
#define IHMA_H

#include "AtoSa.h"
#include "SPSEQ.h"
#include <vector>
#include <string>

using namespace std;

namespace IhMA {

    // --------------------------------------------------------
    // Data Structures
    // --------------------------------------------------------

    // Combined Public Parameters
    typedef struct {
        AtoSa::AtoSaParams pp_atosa;
        Spseq::SpseqParams pp_spseq;
    } IhMAParams;

    // Zero-Knowledge Proof Structure (Schnorr-like with optimization)
    // Proves knowledge of rho1, rho2 such that T1 = h^rho1, T2 = h^rho2
    // utilizing linear combination T_agg = T1 + alpha*T2 = h^(rho1 + alpha*rho2)
    typedef struct {
        ECP R;          ///< Commitment R = k * h
        mpz_class s;    ///< Response s = k + e * (rho1 + alpha * rho2)
    } IhMAZKProof;

    // User Keys
    typedef struct {
        mpz_class tau_rho1; // Secret rho1
        mpz_class tau_rho2; // Secret rho2
        AtoSa::AtoSaTag T;  // Public Tag
        AtoSa::AtoSaAux aux;
    } IhMAUserKey;

    // Issuer Keys
    typedef struct {
        AtoSa::AtoSaSK isk;
        AtoSa::AtoSaVK ivk;
    } IhMAIssuerKey;

    // Credential held by User
    typedef struct {
        AtoSa::AtoSaSignature sigma;
        string attribute;
    } IhMACredential;

    // Policy
    typedef struct {
        AtoSa::AtoSaVK ivk;
        Spseq::SpseqSignature sigma_policy;
    } IhMAPolicy;

    // The Proof shown to Verifier
    typedef struct {
        // Nym = T' (Randomized Tag)
        AtoSa::AtoSaTag nym;

        // Randomized Aggregate Signature
        AtoSa::AtoSaSignature sigma_agg_prime;

        // Randomized Issuer VKs
        vector<AtoSa::AtoSaVK> randomized_vks;

        // Randomized Policy Signatures
        vector<Spseq::SpseqSignature> randomized_policies;

        // Zero-Knowledge Proof of ownership of Nym
        // Proves knowledge of secrets underlying nym.T1 and nym.T2
        IhMAZKProof pi;
    } IhMAShowProof;

    // --------------------------------------------------------
    // Algorithms
    // --------------------------------------------------------

    IhMAParams Setup();
    void IKeyGen(IhMAParams pp, IhMAIssuerKey& ik);
    void UKeyGen(IhMAParams pp, const vector<string>& S, const vector<AtoSa::AtoSaVK>& issuers_vks, IhMAUserKey& uk);

    // Issuance now involves internal ZK proof generation and verification
    bool Issuance(IhMAParams pp, IhMAIssuerKey ik, IhMAUserKey uk, string attr_val, IhMACredential& cred);

    void GenPolicies(IhMAParams pp, const vector<IhMAIssuerKey>& issuers,
                     vector<IhMAPolicy>& policies,
                     Spseq::SpseqSK& reg_sk, Spseq::SpseqPK& reg_pk);

    IhMAShowProof Show(IhMAParams pp, IhMAUserKey uk,
                       const vector<IhMACredential>& creds,
                       const vector<IhMAPolicy>& policies,
                       const vector<int>& D);

    bool CredVerify(IhMAParams pp,
                    Spseq::SpseqPK regulator_pk,
                    IhMAShowProof proof,
                    const vector<string>& revealed_attributes);

    // --------------------------------------------------------
    // ZKP Helper Functions (Exposed for transparency/testing)
    // --------------------------------------------------------

    /**
     * @brief Generates ZK Proof for Tag ownership using linear combination optimization.
     * @param pp Params
     * @param h Base point (from tag.aux.h)
     * @param T1 Public Tag part 1
     * @param T2 Public Tag part 2
     * @param rho1 Secret scalar 1
     * @param rho2 Secret scalar 2
     * @return Generated Proof pi
     */
    IhMAZKProof ProveTag(IhMAParams pp, ECP h, ECP T1, ECP T2, mpz_class rho1, mpz_class rho2);

    /**
     * @brief Verifies ZK Proof for Tag ownership.
     * @param pp Params
     * @param h Base point
     * @param T1 Public Tag part 1
     * @param T2 Public Tag part 2
     * @param pi The proof
     * @return True if valid
     */
    bool VerifyTag(ECP h, ECP T1, ECP T2, IhMAZKProof pi);

} // namespace IhMA

#endif // IHMA_H