#pragma once
#include <iostream>

namespace network {
    namespace protocols {
        namespace dns {
            struct header {
                uint16_t id;
                uint16_t rcode: 4, cd: 1, ad: 1, z:1, ra: 1, rd: 1, tc: 1, aa:1, opcode: 4, qr:1;
                uint16_t total_questions;
                uint16_t total_answers_rr;
                uint16_t total_authority_rr;
                uint16_t total_additionals_rr;
            };
        }
    }
}