/* Copyright (C) 2020 D8DATAWORKS - All Rights Reserved */

#pragma once

#include <array>

#include "scalar_t/int.hpp"

namespace template_crypto
{
    namespace math
    {
        constexpr size_t triangle_number(size_t n)
        {
            return n * (n + 1) / 2;
        }

        template < typename T, size_t height > constexpr auto make_pascal_triangle()
        {
            std::array<T, triangle_number(height) > data{};

            data[0] = 1;

            for (size_t i = 1, c = 1, pr = 0; i < height; pr += i, i++)
            {
                data[c++] = 1;

                for (size_t j = 1; j < i; j++)
                    data[c++] = data[pr + j - 1] + data[pr + j];

                data[c++] = 1;
            }

            return data;
        }

        template <typename T, size_t height> class PascalTriangle
        {
        public:
            using INT = T;

            constexpr PascalTriangle() : data(make_pascal_triangle<T, height>()) {}

            constexpr size_t size() const
            {
                return height;
            }

            constexpr const T* operator[](size_t row) const
            {
                return data.data() + triangle_number(row);
            }

        private:
            std::array<T, triangle_number(height)> data;
        };

        template <typename T> T GetInverse(T i)
        {
            if constexpr (std::is_class<T>())
                return i.MultiplicativeInverse();
            else
                //Use scalar_t to compute inverse and account for potential overflow.
                return (T)scalar_t::uintv_t<T, 1>(i).MultiplicativeInverse()[0];
        }

        template <typename T, size_t side> class ElectiveTransform
        {
        public:
            using INT = T;

            constexpr ElectiveTransform(const std::array<T, side> & symmetry)
            {
                auto first = symmetry[0];
                if (first % 2 == 0)
                    first++;

                for (size_t i = 0, c = 0; i < side; i++)
                {
                    data[c++] = first;
                    for (size_t j = 1; j < i + 1; j++)
                        data[c++] = symmetry[j];
                }

                if (data[0] != 1)
                    mul_inverse = GetInverse(data[0]);
                else
                    mul_inverse = 1;
            }

            constexpr size_t size() const { return side; }

            constexpr const T* operator[](size_t row) const
            {
                return data.data() + triangle_number(row);
            }

            T inverse() const { return mul_inverse; }

        private:
            T mul_inverse = 0;

            std::array<T, triangle_number(side)> data;
        };

        template <typename T, size_t side> class ElectiveTransform2
        {
        public:
            using INT = T;

            constexpr ElectiveTransform2(const std::array<T, side>& symmetry)
                : sym(symmetry)
            {
                if (sym[0] % 2 == 0)
                    sym[0]++;

                if (sym[0] != 1)
                    mul_inverse = GetInverse(sym[0]);
                else
                    mul_inverse = 1;
            }

            const T & inverse() const { return mul_inverse; }
            const auto& symmetry() const { return sym; }

        private:
            T mul_inverse = 0;
            std::array<T, side> sym;
        };

        template <size_t height, typename T, size_t side > class ElectiveSymmetry
        {
        public:
            using INT = T;

            ElectiveSymmetry(const std::array<T, side>& symmetry)
            {
                {
                    T add_inverse = T(0) - symmetry[0];

                    for (size_t i = 1; i < height; i++)
                        data[i * side] = (i % 2) ? add_inverse : symmetry[0];
                }  

                for (size_t i = 0; i < side; i++)
                    data[i] = symmetry[i];

                for (size_t i = 1; i < side; i++)
                {
                    for (size_t j = 1; j < height; j++)
                        data[j * side + i] = data[(j - 1) * side + i - 1] - data[(j - 1) * side + i];
                }
            }

            constexpr size_t size() const { return height; }

            constexpr const T* operator[](size_t dx) const { return data.data() + dx * side; }

        private:
            std::array<T, height * side> data;
        };

        template <typename I, typename O, typename PT> constexpr void ToPascal(const I& data, O& output, const PT & triangle)
        {
            for (size_t i = 0; i < data.size(); i++)
            {
                output[i] = 0;
                auto row = triangle[i];
                for (size_t j = 0; j < i+1; j++)
                    output[i] += row[j] * data[j];
            }
        }

        template<typename POLY, typename O, typename ES> constexpr void ToFunction(const POLY & polynomial, O& output, const ES& es)
        {
            for (size_t i = es.size() - output.size(), k = 0; i < es.size(); i++, k++)
            {
                output[k] = 0;

                for (size_t j = 0, p = polynomial.size() - 1; j < polynomial.size(); j++, p--)
                    output[k] += es[i][p] * polynomial[j];
            }
        }

        template <typename PASCAL_FORM, typename O, typename ET> constexpr void ToPolynomial(const PASCAL_FORM& _pascal, O& output, const ET& et)
        {
            for (size_t i = 0, k = _pascal.size() - 1; i < output.size(); i++, k--)
            {
                output[i] = _pascal[k]; output[i] *= et.inverse();

                for (size_t j = i, p = 0; j > 0; j--, p++)
                    output[i] += typename ET::INT(0) - (et[i][j] * output[p] * et.inverse());
            }
        }

        template <typename PASCAL_FORM, typename O, typename ET2> constexpr void ToPolynomial2(const PASCAL_FORM& _pascal, O& output, const ET2& et)
        {
            for (size_t i = 0, k = _pascal.size() - 1; i < output.size(); i++, k--)
            {
                output[i] = _pascal[k]; output[i] *= et.inverse();

                for (size_t j = i, p = 0; j > 0; j--, p++)
                    output[i] += typename ET2::INT(0) - (et.symmetry()[j] * output[p] * et.inverse());
            }
        }
    } 
}