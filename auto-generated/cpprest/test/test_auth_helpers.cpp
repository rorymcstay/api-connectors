//
// Created by rory on 30/06/2021.
//

#include "gtest/gtest.h"
#include "auth_helpers.h"
#include <cpprest/http_client.h>

std::string apiKey = "LAqUlngMIQkIUjXMUreyu3qn";
std::string apiSecret = "chNOOS4KvNXR_Xq4k4c9qsfoKWvnDecLATCRlcBwyKDYnWgO";

TEST(test_shouldAuth, smoke_test)
{
    utility::string_t uri = "position";
    bool res = shouldAuth(uri);
    ASSERT_FALSE(res);
}

TEST(test_testdoAuth, smoke_test)
{
    std::string verb = "POST";
    std::string path = "/api/v1/order";
    std::string expires = "1518064238"; // 2018-02-08T04:30:38Z
    std::string data = "{\"symbol\":\"XBTM15\",\"price\":219.0,\"clOrdID\":\"mm_bitmex_1a/oemUeQ4CAJZgP3fjHsA\",\"orderQty\":98}";
    web::http::http_request req;
    req.set_body(data);
    req.headers().add("api-key", apiKey);
    req.headers().add("expires", expires);
    req.set_request_uri(path);
    req.set_method(verb);

    doAuth(req);

}