find_package(GTest)
if(${GTest_FOUND} EQUAL "FALSE")
    message(FATAL "Gtest not found!")
endif(${GTest_FOUND} EQUAL "FALSE")

include_directories(${CPPREST_INCLUDE_DIR})
add_executable(test_swagger
        ./test_auth_helpers.cpp
        ./../auth_helpers.cpp
        ./main.cpp
        )

target_link_libraries(test_swagger 
    ${GTEST_LIBRARIES}
    pthread
    cpprest
    crypto)
