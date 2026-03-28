#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <string>
#include <vector>
#include <stdexcept>

// Core cryptographic tools (mpz_class, ECP, ECP2, FP12, etc.)
#include "Tools.h"
// DAT-TWS core structures
#include "dat-tws.h"

using namespace DatTws;

// ============================================================================
// DAT-TWS Core Structures Serialization
// ============================================================================

/**
 * @brief Serializes DatParams into a string for transmission.
 * @param pp The DatParams structure.
 * @return String representation of the public parameters.
 */
std::string DatParams_to_str(const DatParams& pp);

/**
 * @brief Deserializes a string into a DatParams structure.
 * @param str The string representation of DatParams.
 * @return The deserialized DatParams.
 */
DatParams str_to_DatParams(const std::string& str);

/**
 * @brief Serializes DatOpener (Regulator/Tracer keys) into a string.
 * @param opener The DatOpener structure.
 * @return String representation of the opener.
 */
std::string DatOpener_to_str(const DatOpener& opener);

/**
 * @brief Deserializes a string into a DatOpener structure.
 * @param str The string representation of DatOpener.
 * @return The deserialized DatOpener.
 */
DatOpener str_to_DatOpener(const std::string& str);

/**
 * @brief Serializes DatIssuer keys into a string.
 * @param issuer The DatIssuer structure.
 * @return String representation of the issuer keys.
 */
std::string DatIssuer_to_str(const DatIssuer& issuer);

/**
 * @brief Deserializes a string into a DatIssuer structure.
 * @param str The string representation of DatIssuer.
 * @return The deserialized DatIssuer.
 */
DatIssuer str_to_DatIssuer(const std::string& str);

/**
 * @brief Serializes a single DatTag into a string.
 * @param tag The DatTag structure.
 * @return String representation of the tag.
 */
std::string DatTag_to_str(const DatTag& tag);

/**
 * @brief Deserializes a string into a DatTag structure.
 * @param str The string representation of DatTag.
 * @return The deserialized DatTag.
 */
DatTag str_to_DatTag(const std::string& str);

/**
 * @brief Serializes a vector of DatTags into a string.
 * @param tags The vector of DatTags.
 * @return String representation of the tag array.
 */
std::string DatTagArr_to_str(const std::vector<DatTag>& tags);

/**
 * @brief Deserializes a string into a vector of DatTags.
 * @param str The string representation of the DatTag array.
 * @return The deserialized vector of DatTags.
 */
std::vector<DatTag> str_to_DatTagArr(const std::string& str);

/**
 * @brief Serializes a DatWitness into a string.
 * @param wit The DatWitness structure.
 * @return String representation of the witness.
 */
std::string DatWitness_to_str(const DatWitness& wit);

/**
 * @brief Deserializes a string into a DatWitness structure.
 * @param str The string representation of DatWitness.
 * @return The deserialized DatWitness.
 */
DatWitness str_to_DatWitness(const std::string& str);

/**
 * @brief Serializes a DatSignature (ZK Proof + Aggregated Signature) into a string.
 * @param sig The DatSignature structure.
 * @return String representation of the signature.
 */
std::string DatSignature_to_str(const DatSignature& sig);

/**
 * @brief Deserializes a string into a DatSignature structure.
 * @param str The string representation of DatSignature.
 * @return The deserialized DatSignature.
 */
DatSignature str_to_DatSignature(const std::string& str);


// ============================================================================
// Cryptographic Primitive Serialization
// ============================================================================

std::string mpz_to_str(const mpz_class& value);
mpz_class str_to_mpz(const std::string& str);

std::string ECP_to_str(ECP ecp);
ECP str_to_ECP(const std::string& str);

std::string ECP2_to_str(ECP2 ecp2, bool compressed = true);
ECP2 str_to_ECP2(const std::string& hex_string);

std::string FP12_to_str(FP12 fp12);
FP12 str_to_FP12(const std::string& hex_string);

std::string mpzArr_to_str(const std::vector<mpz_class>& mpzs);
std::vector<mpz_class> str_to_mpzArr(const std::string& str);

std::string ECPArr_to_str(const std::vector<ECP>& ecps);
std::vector<ECP> str_to_ECPArr(const std::string& str);

std::string ECP2Arr_to_str(const std::vector<ECP2>& ecp2s, bool compressed = true);
std::vector<ECP2> str_to_ECP2Arr(const std::string& str);

#endif // SERIALIZER_H