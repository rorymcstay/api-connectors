//
// Created by rory on 30/06/2021.
//

#ifndef TRADINGO_AUTH_HELPERS_H
#define TRADINGO_AUTH_HELPERS_H

#include "cpprest/http_client.h"


bool shouldAuth(const utility::string_t& url_) {
    for (auto& needAuth : {"order", "position"}) {
        if (url_.find(needAuth) == utility::string_t::npos)
            return true;
    }
    return false;
}

void doAuth(web::http::http_request& request) {

    std::stringstream signature;
    auto expires = std::chrono::system_clock::now() + std::chrono::seconds(1);
    signature << std::hex << request.method() << request.relative_uri().path() << std::to_string(expires.time_since_epoch().count()) <<  request.body() ;

}

#endif //TRADINGO_AUTH_HELPERS_H
