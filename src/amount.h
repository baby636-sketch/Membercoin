// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AMOUNT_H
#define BITCOIN_AMOUNT_H

#include "serialize.h"

#include <atomic>
#include <stdlib.h>
#include <string>

typedef int64_t CAmount;

static const CAmount COIN = 100000000;
static const CAmount CENT = 1000000;

extern const std::string CURRENCY_UNIT;

enum
{
    //! Minimum # of bytes to generate and spend a UTXO. 34 for the output, 148 for the input. Used in dust calculation
    TYPICAL_UTXO_LIFECYCLE_SIZE = 148 + 34,
};

/** No amount larger than this (in satoshi) is valid.
 *
 * Note that this constant is *not* the total money supply, which in Bitcoin
 * currently happens to be less than 21,000,000 BCH for various reasons, but
 * rather a sanity check. As this sanity check is used by consensus-critical
 * validation code, the exact value of the MAX_MONEY constant is consensus
 * critical; in unusual circumstances like a(nother) overflow bug that allowed
 * for the creation of coins out of thin air modification could lead to a fork.
 * */
static const CAmount MAX_MONEY = 1000000000 * COIN;
inline bool MoneyRange(const CAmount &nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
/** Type-safe wrapper class for fee rates
 * (how much to pay based on transaction size)
 */
class CFeeRate
{
private:
    std::atomic<int64_t> nSatoshisPerK; // unit is satoshis-per-1,000-bytes
public:
    CFeeRate() : nSatoshisPerK(0) {}
    explicit CFeeRate(const CAmount _nSatoshisPerK) : nSatoshisPerK(_nSatoshisPerK) {}
    CFeeRate(const CAmount &nFeePaid, size_t nSize);
    CFeeRate(const CFeeRate &other) { nSatoshisPerK = other.nSatoshisPerK.load(); }
    CFeeRate &operator=(const CFeeRate other)
    {
        nSatoshisPerK = other.nSatoshisPerK.load();
        return *this;
    }
    CAmount GetFee(size_t size) const; // unit returned is satoshis
    CAmount GetFeePerK() const { return GetFee(1000); } // satoshis-per-1000-bytes
    /** Dust is too small to be spendable.  It is either set via the txDust tweak or proportional to the cost to
        spend an output. */
    CAmount GetDust() const;

    friend bool operator<(const CFeeRate &a, const CFeeRate &b) { return a.nSatoshisPerK < b.nSatoshisPerK; }
    friend bool operator>(const CFeeRate &a, const CFeeRate &b) { return a.nSatoshisPerK > b.nSatoshisPerK; }
    friend bool operator==(const CFeeRate &a, const CFeeRate &b) { return a.nSatoshisPerK == b.nSatoshisPerK; }
    friend bool operator<=(const CFeeRate &a, const CFeeRate &b) { return a.nSatoshisPerK <= b.nSatoshisPerK; }
    friend bool operator>=(const CFeeRate &a, const CFeeRate &b) { return a.nSatoshisPerK >= b.nSatoshisPerK; }
    CFeeRate &operator+=(const CFeeRate &a)
    {
        nSatoshisPerK += a.nSatoshisPerK;
        return *this;
    }
    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nSatoshisPerK);
    }
};

/** A fee rate smaller than this is considered zero fee (for relaying, mining and transaction creation) */
extern CFeeRate minRelayTxFee;

#endif //  BITCOIN_AMOUNT_H
