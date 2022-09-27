/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_test.h"

/*
 * return one bit in the data according to the mask
 *
 * @retval 0                if (data & mask) is 0.
 * @retval 0xFFFFFFFF       if (data & mask) includes more than one bit.
 * @return (data & mask)    if (data & mask) includes one bit.
 */
uint32_t spdm_test_get_one_bit (uint32_t data, uint32_t mask)
{
    uint32_t final;
    uint8_t index;

    data = data & mask;

    final = 0;
    for (index = 0; index < 32; index++) {
        if ((data & (1 << index)) != 0) {
            if (final == 0) {
                /* first bit, record it to final */
                final = (1 << index);
            } else {
                /* more than one bit */
                return 0xFFFFFFFF;
            }
        }
    }
    return final;
}
