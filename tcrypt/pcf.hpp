/* Copyright (C) 2020 D8DATAWORKS - All Rights Reserved */

#pragma once

#include <array>

#include "encrypt.hpp"
#include "decrypt.hpp"

namespace polynomial_custom_field_encryption
{
	template < typename T, typename P > void pcf256_enc(T & data, const P & p)
	{
		using B = std::array<uint64_t, 4>;
		template_crypto::encrypt::Long<uint64_t, 4> lec(*((B*)&p), *(((B*)&p)+1));

		lec.Encrypt(data);
	}

	template < typename T, typename P > auto pcf256_enc_copy(const T& data, const P& p)
	{
		auto copy = data;
		using B = std::array<uint64_t, 4>;
		template_crypto::encrypt::Long<uint64_t, 4> lec(*((B*)&p), *(((B*)&p) + 1));

		lec.Encrypt(copy);

		return copy;
	}

	template < typename T, typename P > void pcf256_dec(T& data, const P& p)
	{
		using B = std::array<uint64_t, 4>;
		template_crypto::decrypt::Long<uint64_t, 4> ldc(*((B*)&p), *(((B*)&p) + 1));

		ldc.Decrypt(data);
	}
}

