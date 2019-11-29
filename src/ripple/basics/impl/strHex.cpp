//------------------------------------------------------------------------------
/*
    This file is part of rmcd: https://github.com/RussianMiningCoin/rmcd
    Copyright (c) 2019 Ripple Labs Inc.
    Copyright (c) 2019 RMC.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <ripple/basics/strHex.h>
#include <algorithm>
#include <string>

namespace ripple {

int charUnHex (unsigned char c)
{
    struct HexTab
    {
        int hex[256];

        HexTab ()
        {
            std::fill (std::begin (hex), std::end (hex), -1);
            for (int i = 0; i < 10; ++i)
                hex ['0'+i] = i;
            for (int i = 0; i < 6; ++i)
            {
                hex ['A'+i] = 10 + i;
                hex ['a'+i] = 10 + i;
            }
        }
        int operator[] (unsigned char c) const
        {
            return hex[c];
        }
    };

    static HexTab xtab;

    return xtab[c];
}

}
