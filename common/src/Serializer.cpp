#include "../include/Serializer.h"
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <cstring>

using namespace std;
using namespace DatTws;

// ============================================================================
// Helpers
// ============================================================================
static std::string binToHex(const std::string& input) {
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();
    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

static std::string hexToBin(const std::string& input) {
    size_t len = input.length();
    if (len & 1) throw std::invalid_argument("Odd length in hex string");
    std::string output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        std::string byteString = input.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        output.push_back(byte);
    }
    return output;
}

// ============================================================================
// DAT-TWS Core Structures Serialization
// ============================================================================

std::string DatParams_to_str(const DatParams& pp) {
    std::ostringstream oss;
    oss << mpz_to_str(pp.q) << "#"
        << ECP_to_str(pp.X) << "#"
        << ECP2_to_str(pp.Y_tilde) << "#"
        << FP12_to_str(pp.hat_Z);
    return oss.str();
}

DatParams str_to_DatParams(const std::string& str) {
    DatParams pp;
    std::vector<std::string> fields;
    size_t start = 0, end;
    while ((end = str.find('#', start)) != std::string::npos) {
        fields.push_back(str.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(str.substr(start));

    if (fields.size() != 4) throw std::runtime_error("Invalid DatParams format.");

    pp.q = str_to_mpz(fields[0]);
    pp.X = str_to_ECP(fields[1]);
    pp.Y_tilde = str_to_ECP2(fields[2]);
    pp.hat_Z = str_to_FP12(fields[3]);
    return pp;
}

std::string DatOpener_to_str(const DatOpener& opener) {
    std::ostringstream oss;
    oss << mpz_to_str(opener.rsk) << "#" << ECP_to_str(opener.PK_R);
    return oss.str();
}

DatOpener str_to_DatOpener(const std::string& str) {
    DatOpener opener;
    size_t pos = str.find('#');
    if (pos == std::string::npos) throw std::runtime_error("Invalid DatOpener format.");
    opener.rsk = str_to_mpz(str.substr(0, pos));
    opener.PK_R = str_to_ECP(str.substr(pos + 1));
    return opener;
}

std::string DatIssuer_to_str(const DatIssuer& issuer) {
    std::ostringstream oss;
    oss << mpz_to_str(issuer.a) << "#"
        << mpz_to_str(issuer.b) << "#"
        << ECP2_to_str(issuer.A_tilde) << "#"
        << ECP2_to_str(issuer.B_tilde);
    return oss.str();
}

DatIssuer str_to_DatIssuer(const std::string& str) {
    DatIssuer issuer;
    std::vector<std::string> fields;
    size_t start = 0, end;
    while ((end = str.find('#', start)) != std::string::npos) {
        fields.push_back(str.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(str.substr(start));

    if (fields.size() != 4) throw std::runtime_error("Invalid DatIssuer format.");

    issuer.a = str_to_mpz(fields[0]);
    issuer.b = str_to_mpz(fields[1]);
    issuer.A_tilde = str_to_ECP2(fields[2]);
    issuer.B_tilde = str_to_ECP2(fields[3]);
    return issuer;
}

std::string DatTag_to_str(const DatTag& tag) {
    std::ostringstream oss;
    oss << mpz_to_str(tag.T_exp) << "#"
        << ECP_to_str(tag.X_t) << "#"
        << ECP2_to_str(tag.Y_t_tilde) << "#"
        << ECP_to_str(tag.T_vk) << "#"
        << ECP2_to_str(tag.A_tilde) << "#"
        << ECP2_to_str(tag.B_tilde);
    return oss.str();
}

DatTag str_to_DatTag(const std::string& str) {
    DatTag tag;
    std::vector<std::string> fields;
    size_t start = 0, end;
    while ((end = str.find('#', start)) != std::string::npos) {
        fields.push_back(str.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(str.substr(start));

    if (fields.size() != 6) throw std::runtime_error("Invalid DatTag format.");

    tag.T_exp = str_to_mpz(fields[0]);
    tag.X_t = str_to_ECP(fields[1]);
    tag.Y_t_tilde = str_to_ECP2(fields[2]);
    tag.T_vk = str_to_ECP(fields[3]);
    tag.A_tilde = str_to_ECP2(fields[4]);
    tag.B_tilde = str_to_ECP2(fields[5]);
    return tag;
}

std::string DatTagArr_to_str(const std::vector<DatTag>& tags) {
    std::ostringstream oss;
    for (size_t i = 0; i < tags.size(); ++i) {
        if (i != 0) oss << "&";
        oss << DatTag_to_str(tags[i]);
    }
    return oss.str();
}

std::vector<DatTag> str_to_DatTagArr(const std::string& str) {
    std::vector<DatTag> tags;
    if (str.empty()) return tags;

    size_t start = 0, end;
    while ((end = str.find('&', start)) != std::string::npos) {
        tags.push_back(str_to_DatTag(str.substr(start, end - start)));
        start = end + 1;
    }
    tags.push_back(str_to_DatTag(str.substr(start)));
    return tags;
}

std::string DatWitness_to_str(const DatWitness& wit) {
    return ECP_to_str(wit.sigma_prime);
}

DatWitness str_to_DatWitness(const std::string& str) {
    DatWitness wit;
    wit.sigma_prime = str_to_ECP(str);
    return wit;
}

std::string DatSignature_to_str(const DatSignature& sig) {
    std::ostringstream oss;
    oss << ECP_to_str(sig.H_prime) << "#"
        << ECP_to_str(sig.sigma_prime) << "#"
        << FP12_to_str(sig.R) << "#"
        << mpz_to_str(sig.s) << "#"
        << FP12_to_str(sig.hat_Z_x) << "#"
        << ECP_to_str(sig.sigma_x) << "#"
        << ECP2_to_str(sig.PK_U_tilde_r);
    return oss.str();
}

DatSignature str_to_DatSignature(const std::string& str) {
    DatSignature sig;
    std::vector<std::string> fields;
    size_t start = 0, end;
    while ((end = str.find('#', start)) != std::string::npos) {
        fields.push_back(str.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(str.substr(start));

    if (fields.size() != 7) throw std::runtime_error("Invalid DatSignature format.");

    sig.H_prime = str_to_ECP(fields[0]);
    sig.sigma_prime = str_to_ECP(fields[1]);
    sig.R = str_to_FP12(fields[2]);
    sig.s = str_to_mpz(fields[3]);
    sig.hat_Z_x = str_to_FP12(fields[4]);
    sig.sigma_x = str_to_ECP(fields[5]);
    sig.PK_U_tilde_r = str_to_ECP2(fields[6]);
    return sig;
}

// ============================================================================
// Cryptographic Primitive Serialization
// ============================================================================

std::string mpz_to_str(const mpz_class &value) {
    return value.get_str(16);
}

mpz_class str_to_mpz(const string &str) {
    return mpz_class(str, 16);
}

std::string ECP_to_str(ECP ecp) {
    char buffer[64];
    octet O;
    O.len = 0;
    O.max = sizeof(buffer);
    O.val = buffer;
    ECP_toOctet(&O, &ecp, true);
    std::string binaryData(O.val, O.len);
    return binToHex(binaryData);
}

ECP str_to_ECP(const std::string &str) {
    ECP ecp;
    std::string binaryData = hexToBin(str);
    char buffer[64];
    if(binaryData.size() > 64) throw std::runtime_error("ECP string too long");
    memcpy(buffer, binaryData.data(), binaryData.size());
    octet O;
    O.len = (int)binaryData.size();
    O.max = sizeof(buffer);
    O.val = buffer;
    if (ECP_fromOctet(&ecp, &O) != 1) {
        std::cerr << "[Error] Failed to deserialize ECP (point not on curve)." << std::endl;
        ECP_inf(&ecp);
    }
    return ecp;
}

std::string ECP2_to_str(ECP2 ecp2, bool compressed) {
    char buffer[2 * 48 * 2];
    octet S;
    S.val = buffer;
    S.max = sizeof(buffer);
    S.len = 0;
    ECP2_toOctet(&S, const_cast<ECP2 *>(&ecp2), compressed);
    std::string hex_string;
    for (int i = 0; i < S.len; i++) {
        char hex[3];
        sprintf(hex, "%02X", (unsigned char) S.val[i]);
        hex_string.append(hex);
    }
    return hex_string;
}

ECP2 str_to_ECP2(const std::string &hex_string) {
    ECP2 ecp2;
    size_t len = hex_string.length() / 2;
    // Using dynamic memory allocation instead of VLA for standard C++ compliance
    std::vector<char> buffer(len);
    for (size_t i = 0; i < len; i++) {
        sscanf(hex_string.substr(i * 2, 2).c_str(), "%2hhX", &buffer[i]);
    }
    octet S;
    S.val = buffer.data();
    S.max = len;
    S.len = len;
    if (ECP2_fromOctet(&ecp2, &S) != 1) {
        std::cerr << "[Error] Invalid ECP2 point representation." << std::endl;
    }
    return ecp2;
}

std::string FP12_to_str(FP12 fp12) {
    char buffer[24 * 48];
    octet S;
    S.val = buffer;
    S.max = sizeof(buffer);
    S.len = 0;
    FP12_toOctet(&S, const_cast<FP12 *>(&fp12));
    std::string hex_string;
    for (int i = 0; i < S.len; i++) {
        char hex[3];
        sprintf(hex, "%02X", (unsigned char) S.val[i]);
        hex_string.append(hex);
    }
    return hex_string;
}

FP12 str_to_FP12(const std::string &hex_string) {
    FP12 fp12;
    size_t len = hex_string.length() / 2;
    std::vector<char> buffer(len);
    for (size_t i = 0; i < len; i++) {
        sscanf(hex_string.substr(i * 2, 2).c_str(), "%2hhX", &buffer[i]);
    }
    octet S;
    S.val = buffer.data();
    S.max = len;
    S.len = len;
    FP12_fromOctet(&fp12, &S);
    return fp12;
}

std::string mpzArr_to_str(const std::vector<mpz_class> &mpzs) {
    string str;
    for (size_t i = 0; i < mpzs.size(); i++) {
        str += mpzs[i].get_str(16) + ",";
    }
    return str;
}

std::vector<mpz_class> str_to_mpzArr(const std::string &str) {
    vector<mpz_class> mpzs;
    if (str.empty()) return mpzs;
    stringstream ss(str);
    string item;
    while (getline(ss, item, ',')) {
        if (!item.empty()) {
            mpzs.push_back(mpz_class(item, 16));
        }
    }
    return mpzs;
}

std::string ECPArr_to_str(const std::vector<ECP> &ecps) {
    std::ostringstream oss;
    for (size_t i = 0; i < ecps.size(); ++i) {
        if (i != 0) oss << ";";
        oss << ECP_to_str(ecps[i]);
    }
    return oss.str();
}

std::vector<ECP> str_to_ECPArr(const std::string &str) {
    std::vector<ECP> ecps;
    if (str.empty()) return ecps;
    size_t start = 0;
    size_t end = str.find(';');
    while (end != std::string::npos) {
        ecps.emplace_back(str_to_ECP(str.substr(start, end - start)));
        start = end + 1;
        end = str.find(';', start);
    }
    if (start < str.size()) {
        ecps.emplace_back(str_to_ECP(str.substr(start)));
    }
    return ecps;
}

std::string ECP2Arr_to_str(const std::vector<ECP2> &ecp2s, bool compressed) {
    std::ostringstream oss;
    for (size_t i = 0; i < ecp2s.size(); ++i) {
        if (i != 0) oss << ";";
        oss << ECP2_to_str(ecp2s[i], compressed);
    }
    return oss.str();
}

vector<ECP2> str_to_ECP2Arr(const std::string &str) {
    std::vector<ECP2> ecp2s;
    if (str.empty()) return ecp2s;
    size_t start = 0;
    size_t end = str.find(';');
    while (end != std::string::npos) {
        ecp2s.emplace_back(str_to_ECP2(str.substr(start, end - start)));
        start = end + 1;
        end = str.find(';', start);
    }
    if (start < str.size()) {
        ecp2s.emplace_back(str_to_ECP2(str.substr(start)));
    }
    return ecp2s;
}