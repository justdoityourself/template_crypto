/* Copyright (C) 2020 D8DATAWORKS - All Rights Reserved */

#pragma once

#include "math.hpp"

#include "../gsl-lite.hpp"

namespace template_crypto
{
    namespace block
    {
        using namespace math;

        template <typename T, size_t side> class EncodeContextLong
        {
        public:

            constexpr EncodeContextLong(const std::array<T, side>& symmetry) : et(symmetry) {}

            const auto& Pascal() const { return pt; }
            const auto& Transform() const { return et; }

            template <typename SRC, typename TMP, typename DEST> void Run(const SRC& source, TMP& scratch, DEST& dest)
            {
                ToPascal(source, scratch, Pascal());
                ToPolynomial(scratch, dest, Transform());
            }

        private:
            PascalTriangle<T,side> pt;            
            ElectiveTransform<T,side> et;
        };

        template <typename T, size_t side> class EncodeContextShort
        {
        public:
            constexpr EncodeContextShort(const std::array<T, side>& symmetry) : et(symmetry) {}

            const auto& Transform() const { return et; }

            template <typename SRC, typename DEST> void Run(const SRC& source, DEST & dest)
            {
                ToPolynomial(source, dest, Transform());
            }

        private:
            ElectiveTransform<T,side> et;
        };

        template <typename T, size_t side> class DecodeContextShort
        {
        public:
            constexpr DecodeContextShort(const std::array<T, side>& symmetry) : es(symmetry) { }

            const auto& Symmetry() const { return es; }

            template <typename SRC, typename DEST> void Run(const SRC& source, DEST& dest)
            {
                ToFunction(source, dest, Symmetry());
            }

        private:
            ElectiveSymmetry<side,T,side> es;
        };

        template <typename T, size_t side> class DecodeContextLong
        {
        public:
            constexpr DecodeContextLong(const std::array<T, side>& symmetry) : es(symmetry) { }

            const auto& Symmetry() const { return es; }
            const auto& Pascal() const { return pt; }

            template <typename SRC, typename TMP, typename DEST> void Run(const SRC& source, const TMP& scratch, DEST& dest)
            {
                ToFunction(source, scratch, Symmetry());
                ToPascal(scratch, dest, Pascal());
            }

        private:
            PascalTriangle<T,side> pt;
            ElectiveSymmetry<side,T,side> es;
        };
    }
}