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
    ASSERT_TRUE(res);
}

TEST(test_testdoAuth, smoke_test)
{
    std::string verb = "POST";
    std::string path = "/api/v1/order";
    std::string expires = "1518064238"; // 2018-02-08T04:30:38Z
    std::string data = R"({"symbol":"XBTM15","price":219.0,"clOrdID":"mm_bitmex_1a/oemUeQ4CAJZgP3fjHsA","orderQty":98})";
    auto jsonData = web::json::value::parse(data);
    auto strJson = jsonData.serialize();
    web::http::http_request req;
    req.set_body(data);
    req.headers().add("api-key", apiKey);
    req.headers().add("api-expires", expires);
    req.set_request_uri(path);
    req.set_method(verb);

    auto expected = "1749cd2ccae4aa49048ae09f0b95110cee706e0944e6a14ad0b3a8cb45bd336b";

    doAuth(req, apiKey, apiSecret);
    auto result = req.headers()["api-signature"];
    ASSERT_EQ(result, expected);
    ASSERT_EQ(std::stoi(req.headers()["Content-Length"]), data.size());

}

TEST(test_hex_hmax, smokeTest) {

    std::string apiKey = "-rqipjFxM43WSRKdC8keq83K";
    std::string apiSecret = "uaCYIiwpwpXNKuVGCBPWE3ThzvyhOzKs6F9mWFzc9LueG3yd";
    std::string data ="POST/order/bulk1625247548{\"orders\":[{\"clOrdID\":\"MCST0\",\"orderID\":\"\",\"orderQty\":50,\"price\":33709.5,\"side\":\"Buy\",\"symbol\":\"XBTUSD\"},{\"clOrdID\":\"MCST1\",\"orderID\":\"\",\"orderQty\":50,\"price\":33710,\"side\":\"Sell\",\"symbol\":\"XBTUSD\"}]}";
    auto res = hex_hmac_sha256(apiSecret, data);
    auto exp = "50afa5dd51b0190190712a49cd99c30d76c7f06ba357569edd915d37f58a1d77";
    ASSERT_EQ(res, exp);
}

TEST(getExpires, smoke_test)
{
    std::string exp = std::to_string(getExpires());
    ASSERT_EQ(exp.size(), 10);
}