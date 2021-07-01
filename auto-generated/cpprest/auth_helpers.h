//
// Created by rory on 30/06/2021.
//

#ifndef TRADINGO_AUTH_HELPERS_H
#define TRADINGO_AUTH_HELPERS_H

#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <string>
#include <string_view>
#include <array>

#include <cpprest/http_client.h>


bool shouldAuth(const utility::string_t& url_) {
    for (auto& needAuth : {"order", "position"}) {
        if (url_.find(needAuth) != utility::string_t::npos)
            return true;
    }
    return false;
}



std::string CalcHmacSHA256(const std::string& decodedKey, const std::string& msg) {
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

std::string string2hex(const std::string& input) {
    static const char hex_digits[] = "0123456789abcdef";

    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}


void doAuth(web::http::http_request& request, const std::string& apiKey_, const std::string& apiSecret_) {

    /// hex(HMAC_SHA256(apiSecret, verb + path + expires + data))
    std::stringstream signature;
    long expires;
    if (request.headers().find("api-expires") == request.headers().end()) {
        std::chrono::duration timeSince = (std::chrono::system_clock::now() + std::chrono::seconds(1)).time_since_epoch();
        expires = timeSince.count() % 10000;
    } else {
        expires = std::stoi(request.headers()["api-expires"]);
    }
    auto strBody = request.extract_string(true).get();
    signature << request.method() << request.relative_uri().path() << std::to_string(expires) << strBody;
    auto sigStr = signature.str();
    auto encodedSig = CalcHmacSHA256(apiSecret_, sigStr);
    auto hexStr = string2hex(encodedSig);
    request.set_body(strBody, "application/json");
    request.headers().add(utility::conversions::to_string_t("api-signature"), utility::conversions::to_string_t(hexStr));
    request.headers().add(utility::conversions::to_string_t("api-expires"), utility::conversions::to_string_t(std::to_string(expires)));
    request.headers().add(utility::conversions::to_string_t("api-key"), utility::conversions::to_string_t(apiKey_));

}

#endif //TRADINGO_AUTH_HELPERS_H
