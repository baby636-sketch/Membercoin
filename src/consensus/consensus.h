// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include "uint256.h"

/** The maximum allowed size for a serialized block, in bytes (network rule) */
// BU: this constant is deprecated but is still used in a few areas such as allocation of memory.  Removing it is a
// tradeoff between being perfect and changing more code. TODO: remove this entirely
// static const unsigned int BU_MAX_BLOCK_SIZE = 32000000;
static const unsigned int BLOCKSTREAM_CORE_MAX_BLOCK_SIZE = 1000000;
static const unsigned int ONE_MEGABYTE = 1000000;
/** The maximum allowed number of signature check operations in a 1MB block (network rule), and the suggested max sigops
 * per (MB rounded up) in blocks > 1MB. */
static const unsigned int MAX_BLOCK_SIGOPS_PER_MB = 20000;
static const unsigned int MAX_TX_SIGOPS_COUNT = 20000;
static const unsigned int MAY2020_MAX_TX_SIGCHECK_COUNT = 3000;
/** The maximum suggested length of a transaction.  If greater, the transaction is not relayed, and the > 1MB block is
   considered "excessive".
    For blocks < 1MB, there is no largest transaction so it is defacto 1MB.
*/
static const unsigned int DEFAULT_LARGEST_TRANSACTION = 1000000;
/** The minimum allowed size for a transaction, in bytes */
static const unsigned int MIN_TX_SIZE = 100;

/** This is the default max bloom filter size allowed on the member network.  In Bitcoin Unlimited we have the ability
 *  to communicate to our peer what max bloom filter size we will accept but still observe this value as a default.
 */
static const unsigned int SMALLEST_MAX_BLOOM_FILTER_SIZE = 36000; // bytes

/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 20;

/** per May, 15 '18 upgrade specification the min value for min value for max accepted block size, i.e. EB, is 32 MB
 * (github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/may-2018-hardfork.md#summary)
 */
// defaults for each chain are set in chainparams but defined here
static const unsigned int DEFAULT_EXCESSIVE_BLOCK_SIZE = 32 * ONE_MEGABYTE;
static const unsigned int DEFAULT_EXCESSIVE_BLOCK_SIZE_TESTNET4 = 2 * ONE_MEGABYTE;
static const unsigned int DEFAULT_EXCESSIVE_BLOCK_SIZE_SCALENET = 256 * ONE_MEGABYTE;

static const unsigned int MIN_EXCESSIVE_BLOCK_SIZE = 32000000;
static const unsigned int MIN_EXCESSIVE_BLOCK_SIZE_REGTEST = 1000;

/**
 * The ratio between the maximum allowable block size and the maximum allowable
 * SigChecks (executed signature check operations) in the block. (network rule).
 */
static const int BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO = 141;

static const unsigned int MAY2020_MAX_BLOCK_SIGCHECK_COUNT =
    DEFAULT_EXCESSIVE_BLOCK_SIZE / BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO;
static_assert(MAY2020_MAX_BLOCK_SIGCHECK_COUNT == 226950, "Max block sigcheck value differs from specification");

/** Allowed messages lengths will be this * the excessive block size */
static const unsigned int DEFAULT_MAX_MESSAGE_SIZE_MULTIPLIER = 2;

/** Compute the maximum sigops allowed in a block given the block size. */
inline uint64_t GetMaxBlockSigOpsCount(uint64_t nBlockSize)
{
    auto nMbRoundedUp = 1 + ((nBlockSize - 1) / 1000000);
    return nMbRoundedUp * MAX_BLOCK_SIGOPS_PER_MB;
}

/** Flags for nSequence and nLockTime locks */
enum
{
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

/**
 * Compute the maximum number of sigchecks that can be contained in a block
 * given the MAXIMUM block size as parameter. The maximum sigchecks scale
 * linearly with the maximum block size and do not depend on the actual
 * block size. The returned value is rounded down (there are no fractional
 * sigchecks so the fractional part is meaningless).
 */
inline uint64_t GetMaxBlockSigChecksCount(uint64_t maxBlockSize)
{
    return maxBlockSize / BLOCK_MAXBYTES_MAXSIGCHECKS_RATIO;
}

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
