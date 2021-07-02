//
// Created by Rory McStay on 02/07/2021.
//

#include "auth_helpers.h"

bool shouldAuth(const utility::string_t &url_) {
    for (auto& needAuth : {"order", "position"}) {
        if (url_.find(needAuth) != utility::string_t::npos)
            return true;
    }
    return false;
}


long getExpires() {
    std::chrono::duration timeSince = (std::chrono::system_clock::now() + std::chrono::seconds(3600)).time_since_epoch();
    long expiresPer = timeSince.count();
    long expires = expiresPer* std::chrono::system_clock::period::num / std::chrono::system_clock::period::den;
    return expires;
}

std::string CalcHmacSHA256(const std::string &decodedKey, const std::string &msg) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash{};
    unsigned int hashLen;

    HMAC(
            EVP_sha256(),
            decodedKey.c_str(),
            static_cast<int>(decodedKey.size()),
            reinterpret_cast<unsigned char const*>(msg.c_str()),
            static_cast<int>(msg.size()),
            hash.data(),
            &hashLen
    );

    return std::string{reinterpret_cast<const char *>(hash.data()), hashLen};
}

std::string string2hex(const std::string &input) {

    /*
    auto hexStr = OPENSSL_buf2hexstr(reinterpret_cast<const unsigned char *>(input.c_str()), input.size());
    return hexStr;
     */
    std::string output;
    output.reserve(input.length() * 2);
    static const char hex_digits[] = "0123456789abcdef";
    for (unsigned char c : input)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

void doAuth(web::http::http_request &request, const std::string &apiKey_, const std::string &apiSecret_) {

    /// hex(HMAC_SHA256(apiSecret, verb + path + expires + data))
    std::stringstream signature;
    long expires;
    if (request.headers().find("api-expires") == request.headers().end()) {
        expires = getExpires();
    } else {
        expires = std::stoi(request.headers()["api-expires"]);
    }
    auto strBody = request.extract_string(true).get();
    signature << request.method() << request.relative_uri().path() << std::to_string(expires) << strBody;
    auto sigStr = signature.str();
    auto hexStr = hex_hmac_sha256(apiSecret_, sigStr);

    request.set_body(strBody, "application/json");
    request.headers()[utility::conversions::to_string_t("api-signature")] = utility::conversions::to_string_t(hexStr);
    request.headers()[utility::conversions::to_string_t("api-expires")] = utility::conversions::to_string_t(std::to_string(expires));
    request.headers()[utility::conversions::to_string_t("api-key")] = utility::conversions::to_string_t(apiKey_);

    for (auto & hdr : request.headers())
        std::cout << "Header='" << hdr.first << "' Value='" << hdr.second << "'\n";

}


std::string hex_hmac_sha256(const std::string &apiSecret_, const std::string &data_) {
    auto encodedSig = CalcHmacSHA256(apiSecret_, data_);
    auto hexStr = string2hex(encodedSig);
    return hexStr;
}
