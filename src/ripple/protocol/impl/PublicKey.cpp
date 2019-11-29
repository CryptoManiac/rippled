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

#include <ripple/protocol/PublicKey.h>
#include <ripple/protocol/digest.h>
#include <ripple/protocol/impl/secp256k1.h>
#include <ripple/basics/contract.h>
#include <ripple/basics/strHex.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <type_traits>

namespace ripple {

std::ostream&
operator<<(std::ostream& os, PublicKey const& pk)
{
    os << strHex(pk);
    return os;
}

template<>
boost::optional<PublicKey>
parseBase58 (TokenType type, std::string const& s)
{
    auto const result = decodeBase58Token(s, type);
    auto const pks = makeSlice(result);
    if (!isPublicKey(pks))
        return boost::none;
    return PublicKey(pks);
}

//------------------------------------------------------------------------------

// Parse a length-prefixed number
//  Format: 0x02 <length-byte> <number>
static
boost::optional<Slice>
sigPart (Slice& buf)
{
    if (buf.size() < 3 || buf[0] != 0x02)
        return boost::none;
    auto const len = buf[1];
    buf += 2;
    if (len > buf.size() || len < 1 || len > 33)
        return boost::none;
    // Can't be negative
    if ((buf[0] & 0x80) != 0)
        return boost::none;
    if (buf[0] == 0)
    {
        // Can't be zero
        if (len == 1)
            return boost::none;
        // Can't be padded
        if ((buf[1] & 0x80) == 0)
            return boost::none;
    }
    boost::optional<Slice> number = Slice(buf.data(), len);
    buf += len;
    return number;
}

static
std::string
sliceToHex (Slice const& slice)
{
    std::string s;
    if (slice[0] & 0x80)
    {
        s.reserve(2 * (slice.size() + 2));
        s = "0x00";
    }
    else
    {
        s.reserve(2 * (slice.size() + 1));
        s = "0x";
    }
    for(int i = 0; i < slice.size(); ++i)
    {
        s += "0123456789ABCDEF"[((slice[i]&0xf0)>>4)];
        s += "0123456789ABCDEF"[((slice[i]&0x0f)>>0)];
    }
    return s;
}

/** Determine whether a signature is canonical.
    Canonical signatures are important to protect against signature morphing
    attacks.
    @param vSig the signature data
    @param sigLen the length of the signature
    @param strict_param whether to enforce strictly canonical semantics

    @note For more details please see:
    https://ripple.com/wiki/Transaction_Malleability
    https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
    https://github.com/sipa/bitcoin/commit/58bc86e37fda1aec270bccb3df6c20fbd2a6591c
*/
boost::optional<ECDSACanonicality>
ecdsaCanonicality (Slice const& sig)
{
    using uint264 = boost::multiprecision::number<
        boost::multiprecision::cpp_int_backend<
            264, 264, boost::multiprecision::signed_magnitude,
            boost::multiprecision::unchecked, void>>;

    static uint264 const G(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    // The format of a signature should be:
    // <30> <len> [ <02> <lenR> <R> ] [ <02> <lenS> <S> ]
    if ((sig.size() < 8) || (sig.size() > 72))
        return boost::none;
    if ((sig[0] != 0x30) || (sig[1] != (sig.size() - 2)))
        return boost::none;
    Slice p = sig + 2;
    auto r = sigPart(p);
    auto s = sigPart(p);
    if (! r || ! s || ! p.empty())
        return boost::none;

    uint264 R(sliceToHex(*r));
    if (R >= G)
        return boost::none;

    uint264 S(sliceToHex(*s));
    if (S >= G)
        return boost::none;

    // (R,S) and (R,G-S) are canonical,
    // but is fully canonical when S <= G-S
    auto const Sp = G - S;
    if (S > Sp)
        return ECDSACanonicality::canonical;
    return ECDSACanonicality::fullyCanonical;
}

//------------------------------------------------------------------------------

PublicKey::PublicKey (Slice const& slice)
{
    if(! isPublicKey(slice))
        LogicError("PublicKey::PublicKey invalid public key");
    size_ = slice.size();
    std::memcpy(buf_, slice.data(), size_);
}

PublicKey::PublicKey (PublicKey const& other)
    : size_ (other.size_)
{
    if (size_)
        std::memcpy(buf_, other.buf_, size_);
};

PublicKey&
PublicKey::operator=(PublicKey const& other)
{
    size_ = other.size_;
    if (size_)
        std::memcpy(buf_, other.buf_, size_);
    return *this;
}

//------------------------------------------------------------------------------

bool
verifyDigest (PublicKey const& publicKey,
    uint256 const& digest,
    Slice const& sig,
    bool mustBeFullyCanonical)
{
    if (!isPublicKey(publicKey))
        LogicError("sign: secp256k1 public key required for digest signing");
    auto const canonicality = ecdsaCanonicality(sig);
    if (! canonicality)
        return false;
    if (mustBeFullyCanonical &&
        (*canonicality != ECDSACanonicality::fullyCanonical))
        return false;

    secp256k1_pubkey pubkey_imp;
    if(secp256k1_ec_pubkey_parse(
            secp256k1Context(),
            &pubkey_imp,
            reinterpret_cast<unsigned char const*>(
                publicKey.data()),
            publicKey.size()) != 1)
        return false;

    secp256k1_ecdsa_signature sig_imp;
    if(secp256k1_ecdsa_signature_parse_der(
            secp256k1Context(),
            &sig_imp,
            reinterpret_cast<unsigned char const*>(
                sig.data()),
            sig.size()) != 1)
        return false;
    if (*canonicality != ECDSACanonicality::fullyCanonical)
    {
        secp256k1_ecdsa_signature sig_norm;
        if(secp256k1_ecdsa_signature_normalize(
                secp256k1Context(),
                &sig_norm,
                &sig_imp) != 1)
            return false;
        return secp256k1_ecdsa_verify(
            secp256k1Context(),
            &sig_norm,
            reinterpret_cast<unsigned char const*>(
                digest.data()),
            &pubkey_imp) == 1;
    }
    return secp256k1_ecdsa_verify(
        secp256k1Context(),
        &sig_imp,
        reinterpret_cast<unsigned char const*>(
            digest.data()),
        &pubkey_imp) == 1;
}

bool
verify (PublicKey const& publicKey,
    Slice const& m,
    Slice const& sig,
    bool mustBeFullyCanonical)
{
    if (isPublicKey(publicKey))
    {
        return verifyDigest (publicKey,
            sha512Half(m), sig, mustBeFullyCanonical);
    }    
    return false;
}

NodeID
calcNodeID (PublicKey const& pk)
{
    ripesha_hasher h;
    h(pk.data(), pk.size());
    auto const digest = static_cast<
        ripesha_hasher::result_type>(h);
    static_assert(NodeID::bytes ==
        sizeof(ripesha_hasher::result_type), "");
    NodeID result;
    std::memcpy(result.data(),
        digest.data(), digest.size());
    return result;
}

} // ripple

