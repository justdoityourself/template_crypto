/* Copyright (C) 2020 D8DATAWORKS - All Rights Reserved */

#pragma once

#include <chrono>
#include <string_view>

#include "encrypt.hpp"
#include "decrypt.hpp"
#include "math.hpp"

#include "d8u/memory.hpp"
#include "d8u/random.hpp"
#include "d8u/crypto.hpp"

#include "hash/sse_int.hpp"

template < size_t H, typename T, size_t L > void test(std::array<T, L> g, std::array<T, L> sy)
{
    using namespace template_crypto::math;

    using A = std::array<T, L>;

    static PascalTriangle<T, L> pt;
    ElectiveTransform2<T, L> et(sy);
    ElectiveSymmetry < H+L, T, L > es(sy);

    A r{}, o1{};

    static std::array<T, H+L> f1{};

    ToPascal(g, r, pt);
    ToPolynomial2(r, o1, et);

    ToFunction(o1, f1, es);

    for (size_t i = 0; i < H; i++)
        std::cout << (int)f1[i] << " ";

    std::cout << std::endl << std::endl;

    static std::array<A, H> ga;

    for (size_t i = 0; i < H; i++)
    {
        ToPascal(*((A*) & (f1[i])), r, pt);
        ToPolynomial2(r, ga[i], et);
    }

    for (size_t j = 0; j < L; j++)
    {
        for (size_t i = 0; i < H; i++)
            std::cout << (int)ga[i][j] << " ";

        std::cout << std::endl << std::endl;
    }

    CHECK(true);
}

TEST_CASE("Function Alignment", "[tcrypt::]")
{
    using namespace template_crypto::math;

    test<256>(std::array<uint8_t, 2> { 14, 242 }, std::array<uint8_t, 2> { 7, 5 }); std::cout << std::endl << std::endl;

    test<256>(std::array<uint8_t, 3> { 16, 254, 244 }, std::array<uint8_t, 3> { 7, 5, 2 }); std::cout << std::endl << std::endl;

    test<256>(std::array<uint8_t, 4> {  108, 164, 90, 154 }, std::array<uint8_t, 4> { 7, 5, 2, 9 }); std::cout << std::endl << std::endl;

    test<256>(std::array<uint8_t, 5> { 57, 51, 113, 233, 177 }, std::array<uint8_t, 5> { 7, 5, 2, 9, 1 }); std::cout << std::endl << std::endl;
     


    test<256>(std::array<uint8_t, 4> { 73, 23, 63, 23 }, std::array<uint8_t, 4> { 7, 5, 2, 9 });

    //test<256/*64*1024*/>(std::array<uint16_t, 6> { 73, 23, 63, 23,63,99 }, std::array<uint16_t, 6> { 7, 5, 2, 9,93,111 });

    CHECK(true);
    /*ToPascal(g2, r, pt);
    ToPolynomial2(r, o2, et);

    ToFunction(o2, f2, es);

    std::cout << d8u::util::to_hex(f2) << std::endl << std::endl;*/
}

TEST_CASE("Encrypt Random", "[tcrypt::]")
{
    constexpr std::array<uint64_t, 4> key{ 73, 23, 63, 23 };
    constexpr std::array<uint64_t, 4> iv{ 46, 47, 47, 85 };

    template_crypto::encrypt::Long<uint64_t, 4> lec(key, iv);
    template_crypto::decrypt::Long<uint64_t, 4> ldc(key, iv);

    auto rv = d8u::random::Vector<uint8_t>(1024 * 1024 + 17);

    d8u::aligned_vector data(rv.begin(), rv.end());
    auto original = data;

    lec.Encrypt(data);
    ldc.Decrypt(data);

    CHECK(std::equal(data.begin(), data.end(), original.begin()));
}

TEST_CASE("bench", "[tcrypt::]")
{
    using namespace std::chrono;

    auto rv = d8u::random::Vector<uint8_t>(1024 * 1024 + 17);

    d8u::aligned_vector data(rv.begin(), rv.end());

    constexpr auto reps = 1000;


    d8u::transform::Password pw(std::string_view("testest"));

    constexpr std::array<uint64_t, 4> key{ 73, 23, 63, 23 };
    constexpr std::array<uint64_t, 4> iv{ 46, 47, 47, 85 };

    template_crypto::encrypt::Long<uint64_t, 4> lec(key, iv);
    template_crypto::decrypt::Long<uint64_t, 4> ldc(key, iv);

    constexpr std::array<uint64_t, 8> key2{ 73, 23, 63, 23,73, 23, 63, 23 };
    constexpr std::array<uint64_t, 8> iv2{ 46, 47, 47, 85,2772, 252, 267, 236 };

    template_crypto::encrypt::Long<uint64_t, 8> lec2(key2, iv2);
    template_crypto::decrypt::Long<uint64_t, 8> ldc2(key2, iv2);

    //alignas(16) std::array<sse_int::pint128_t, 8> key3{ 73, 23, 63, 23,73, 23, 63, 23 };
    //alignas(16) std::array<sse_int::pint128_t, 8> iv3{ 46, 47, 47, 85,2772, 252, 267, 236 };

    //alignas(16) template_crypto::encrypt::Long<sse_int::pint128_t, 8> lec3(key3, iv3);
    //alignas(16) template_crypto::decrypt::Long<sse_int::pint128_t, 8> ldc3(key3, iv3);

    //alignas(16) std::array<sse_int::pint128_t, 4> key4{ 73, 23, 63, 23 };
    //alignas(16) std::array<sse_int::pint128_t, 4> iv4{ 46, 47, 47, 85 };

    //alignas(16) template_crypto::encrypt::Long<sse_int::pint128_t, 4> lec4(key4, iv4);
    //alignas(16) template_crypto::decrypt::Long<sse_int::pint128_t, 4> ldc4(key4, iv4);

    //alignas(16) std::array<sse_int::pint128_t, 2> key5{ 73, 23 };
    //alignas(16) std::array<sse_int::pint128_t, 2> iv5{ 46, 47 };

    //alignas(16) template_crypto::encrypt::Long<sse_int::pint128_t, 2> lec5(key5, iv5);
    //alignas(16) template_crypto::decrypt::Long<sse_int::pint128_t, 2> ldc5(key5, iv5);

    constexpr std::array<uint32_t, 8> key6{ 73, 23, 63, 23,73, 23, 63, 23 };
    constexpr std::array<uint32_t, 8> iv6{ 46, 47, 47, 85,2772, 252, 267, 236 };

    template_crypto::encrypt::Long<uint32_t, 8> lec6(key6, iv6);
    template_crypto::decrypt::Long<uint32_t, 8> ldc6(key6, iv6);



    high_resolution_clock::time_point t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        lec.Encrypt(data);

    high_resolution_clock::time_point t2 = high_resolution_clock::now();

    std::cout << "E1 " << std::chrono::duration_cast<std::chrono::microseconds>(t2.time_since_epoch() - t1.time_since_epoch()).count() << std::endl;


    t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        ldc.Decrypt(data);

    t2 = high_resolution_clock::now();

    std::cout << "D1 " << std::chrono::duration_cast<std::chrono::microseconds>(t2.time_since_epoch() - t1.time_since_epoch()).count() << std::endl;



    t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        lec2.Encrypt(data);

    t2 = high_resolution_clock::now();

    std::cout << "E2 " << std::chrono::duration_cast<std::chrono::microseconds>(t2.time_since_epoch() - t1.time_since_epoch()).count() << std::endl;


    t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        ldc2.Decrypt(data);

    t2 = high_resolution_clock::now();

    std::cout << "D2 " << std::chrono::duration_cast<std::chrono::microseconds>(t2.time_since_epoch() - t1.time_since_epoch()).count() << std::endl;




    /*t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        lec3.Encrypt(data);

    t2 = high_resolution_clock::now();

    std::cout << "E3 " << std::chrono::duration_cast<std::chrono::microseconds>(t2.time_since_epoch() - t1.time_since_epoch()).count() << std::endl;


    t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        ldc3.Decrypt(data);

    t2 = high_resolution_clock::now();

    std::cout << "D3 " << std::chrono::duration_cast<std::chrono::microseconds>(t2.time_since_epoch() - t1.time_since_epoch()).count() << std::endl;


    t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        lec4.Encrypt(data);

    t2 = high_resolution_clock::now();

    std::cout << "E4 " << std::chrono::duration_cast<std::chrono::microseconds>(t2.time_since_epoch() - t1.time_since_epoch()).count() << std::endl;


    t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        ldc4.Decrypt(data);

    t2 = high_resolution_clock::now();

    std::cout << "D4 " << std::chrono::duration_cast<std::chrono::microseconds>(t2.time_since_epoch() - t1.time_since_epoch()).count() << std::endl;



    t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        lec5.Encrypt(data);

    t2 = high_resolution_clock::now();

    std::cout << "E5 " << std::chrono::duration_cast<std::chrono::microseconds>(t2.time_since_epoch() - t1.time_since_epoch()).count() << std::endl;


    t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        ldc5.Decrypt(data);

    t2 = high_resolution_clock::now();

    std::cout << "D5 " << std::chrono::duration_cast<std::chrono::microseconds>(t2.time_since_epoch() - t1.time_since_epoch()).count() << std::endl;*/

    t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        lec6.Encrypt(data);

    t2 = high_resolution_clock::now();

    std::cout << "E6 " << std::chrono::duration_cast<std::chrono::microseconds>(t2.time_since_epoch() - t1.time_since_epoch()).count() << std::endl;


    t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        ldc6.Decrypt(data);

    t2 = high_resolution_clock::now();

    std::cout << "D6 " << std::chrono::duration_cast<std::chrono::microseconds>(t2.time_since_epoch() - t1.time_since_epoch()).count() << std::endl;



    t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        d8u::transform::encrypt(data, pw);

    t2 = high_resolution_clock::now();

    std::cout << "AES256 " << (t2.time_since_epoch() - t1.time_since_epoch()).count() / 1000 << std::endl;


    t1 = high_resolution_clock::now();

    for (size_t i = 0; i < reps; i++)
        d8u::transform::decrypt(data, pw);

    t2 = high_resolution_clock::now();

    std::cout << "AES256 " << (t2.time_since_epoch() - t1.time_since_epoch()).count() / 1000 << std::endl;


    CHECK(true);
}


TEST_CASE("Encrypt Tail", "[tcrypt::]")
{
    constexpr std::array<uint64_t, 4> key{ 73, 23, 63, 23 };
    constexpr std::array<uint64_t, 4> iv{ 46, 47, 47, 85 };

    template_crypto::encrypt::Long<uint64_t, 4> lec(key, iv);
    template_crypto::decrypt::Long<uint64_t, 4> ldc(key, iv);

    d8u::aligned_vector data{ 1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,45,45,45 };
    auto original = data;

    lec.Encrypt(data);
    ldc.Decrypt(data);

    CHECK(std::equal(data.begin(), data.end(), original.begin()));
}

TEST_CASE("Encrypt Aligned", "[tcrypt::]")
{
    constexpr std::array<uint64_t, 4> key{ 73, 23, 63, 23 };
    constexpr std::array<uint64_t, 4> iv{ 46, 47, 47, 85 };

    template_crypto::encrypt::Long<uint64_t, 4> lec(key, iv);
    template_crypto::decrypt::Long<uint64_t, 4> ldc(key, iv);

    d8u::aligned_vector data{ 1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2 };
    auto original = data;

    lec.Encrypt(data);
    ldc.Decrypt(data);

    CHECK(std::equal(data.begin(), data.end(), original.begin()));
}