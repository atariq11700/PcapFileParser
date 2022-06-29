#pragma once
#include <iostream>
#include "immintrin.h"

template<typename type>
size_t freadi(const type* const buffer, FILE* stream) {
    return fread((void*)buffer, sizeof(type), 1, stream);
}

#ifdef linux

struct uint32_be {
    uint32_t val;
    inline operator uint32_t() const {
        return __bswap_32(val);
    } 
};

struct uint64_be {
    uint64_t val;
    inline operator uint64_t() const {
        return __bswap_64(val);
    }
};

struct uint16_be {
    uint16_t val;
    inline operator uint16_t() const {
        return __bswap_16(val);
    }
};

#endif

inline static uint8_t __bswap_8(uint8_t val) {
    uint8_t tophalf = 0xF0 & val;
    uint8_t bottomhalf = 0x0F & val;

    tophalf >>= 4;
    bottomhalf <<= 4;

    return tophalf | bottomhalf;
}


inline static void __bswap_16ptr(uint16_t* const val) {
    uint8_t* v2 = (uint8_t*)val;

    uint8_t first_byte = v2[0];
    uint8_t second_byte = v2[1];

    v2[0] = second_byte;
    v2[1] = first_byte;

}

inline static void __bswap_32ptr(uint32_t* const val) {
    uint8_t* v2 = (uint8_t*)val;

    uint8_t first_byte = v2[0];
    uint8_t second_byte = v2[1];
    uint8_t third_byte = v2[2];
    uint8_t fourth_byte = v2[3];

    v2[0] = fourth_byte;
    v2[1] = third_byte;
    v2[2] = second_byte;
    v2[3] = first_byte;

}