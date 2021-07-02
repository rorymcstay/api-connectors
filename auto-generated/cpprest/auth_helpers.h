//
// Created by rory on 30/06/2021.
//

#ifndef TRADINGO_AUTH_HELPERS_H
#define TRADINGO_AUTH_HELPERS_H

#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <string>
#include <array>

#include <cpprest/http_client.h>


bool shouldAuth(const utility::string_t& url_);



std::string CalcHmacSHA256(const std::string& decodedKey, const std::string& msg);

std::string string2hex(const std::string& input);

std::string hex_hmac_sha256(const std::string& apiSecret_, const std::string& data_);


void doAuth(web::http::http_request& request, const std::string& apiKey_, const std::string& apiSecret_);

#endif //TRADINGO_AUTH_HELPERS_H
