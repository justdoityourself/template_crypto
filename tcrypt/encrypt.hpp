/* Copyright (C) 2020 D8DATAWORKS - All Rights Reserved */

#pragma once

#include "block.hpp"

#include "d8u/buffer.hpp"

namespace template_crypto
{
    namespace encrypt
    {
        using namespace block;

        template < typename INT, size_t block > class Long
        {
        public:

            constexpr size_t block_bytes() { return sizeof(INT) * block; }

            constexpr Long(const std::array<INT, block>& _key, const std::array<INT, block>& _iv)
                : ecl(_key)
                , iv(_iv) {}

            ~Long()
            {
                std::memset(this,0,sizeof(this));
            }

            template <typename T> void Encrypt(T & _data)
            {
                auto data = d8u::byte_buffer(_data);

                size_t blocks = data.size() / block_bytes();
                size_t tail = data.size() % block_bytes();

                std::array<INT, block>* block_p = (std::array<INT, block>*)data.data();
                std::array<INT, block> _iv = iv;

                for (size_t i = 0; i < blocks; i++,block_p++)
                {
                    for (size_t j = 0; j < block; j++)
                        (*block_p)[j] ^= _iv[j];

                    _iv = *block_p;

                    ecl.Run(*block_p, temp, *block_p);
                }

                if (tail)
                {
                    std::array<INT, block> tb = {};
                    std::memcpy(&tb, data.data() + blocks * block_bytes(), tail);

                    // It is tricky to execute the function for a unit that is not the block size.
                    // Also doing so might reveal a weakened state.
                    // For now execute the masking only.
                    // Todo revisit the tail block.
                    //

                    for (size_t i = 0; i < block; i++)
                        tb[i] ^= _iv[i];

                    //Block(gsl::span<INT>(tb.data(), block), gsl::span<INT>(_iv.data(), block));

                    std::memcpy(data.data() + blocks * block_bytes(), &tb, tail);
                }

                std::memset(_iv.data(), 0, block_bytes());
            }

        private:

            EncodeContextLong2<INT,block> ecl;

            std::array<INT, block> iv;
            std::array<INT, block> temp;
        };
    }
}