// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "init.h"

#include "addrman.h"
#include "amount.h"
#include "blockstorage/blockstorage.h"
#include "blockstorage/sequential_files.h"
#include "chain.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "compat/sanity.h"
#include "config.h"
#include "connmgr.h"
#include "consensus/validation.h"
#include "dosman.h"
#include "electrum/electrumserver.h"
#include "forks_csv.h"
#include "fs.h"
#include "httprpc.h"
#include "httpserver.h"
#include "httpserver.h"
#include "index/txindex.h"
#include "key.h"
#include "main.h"
#include "miner.h"
#include "net.h"
#include "parallel.h"
#include "policy/fees.h"
#include "policy/mempool.h"
#include "policy/policy.h"
#include "requestManager.h"
#include "rpc/blockchain.h"
#include "rpc/register.h"
#include "rpc/server.h"
#include "script/sigcache.h"
#include "script/standard.h"
#include "threadgroup.h"
#include "torcontrol.h"
#include "txadmission.h"
#include "txdb.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "ui_interface.h"
#include "unlimited.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "validation/validation.h"
#include "validation/verifydb.h"
#include "validationinterface.h"

#ifdef ENABLE_WALLET
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif
#include <stdint.h>
#include <stdio.h>

#ifndef WIN32
#include <signal.h>
#endif

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/bind/bind.hpp>
#include <boost/function.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <openssl/crypto.h>
#include <thread>

#if ENABLE_ZMQ
#include <zmq/zmqnotificationinterface.h>
#include <zmq/zmqrpc.h>
#endif

using namespace std;

bool fFeeEstimatesInitialized = false;

/** Has the AppInit2() startup phase returned */
std::atomic<bool> fAppInit2{false};

#ifdef WIN32
// Win32 LevelDB doesn't use filedescriptors, and the ones used for
// accessing block files don't count towards the fd_set size limit
// anyway.
#define MIN_CORE_FILEDESCRIPTORS 0
#else
#define MIN_CORE_FILEDESCRIPTORS 150
#endif

/** Used to pass flags to the Bind() function */
enum BindFlags
{
    BF_NONE = 0,
    BF_EXPLICIT = (1U << 0),
    BF_REPORT_ERROR = (1U << 1),
    BF_WHITELIST = (1U << 2),
};

static const char *FEE_ESTIMATES_FILENAME = "fee_estimates.dat";

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

//
// Thread management and startup/shutdown:
//
// The network-processing threads are all part of a thread group
// created by AppInit() or the Qt main() function.
//
// A clean exit happens when StartShutdown() or the SIGTERM
// signal handler sets fRequestShutdown, which triggers
// the DetectShutdownThread(), which interrupts the main thread group.
// DetectShutdownThread() then exits, which causes AppInit() to
// continue (it .joins the shutdown thread).
// Shutdown() is then
// called to clean up database connections, and stop other
// threads that should only be stopped after the main network-processing
// threads have exited.
//
// Note that if running -daemon the parent process returns from AppInit2
// before adding any threads to the threadGroup, so .join_all() returns
// immediately and the parent exits from main().
//
// Shutdown for Qt is very similar, only it uses a QTimer to detect
// fRequestShutdown getting set, and then does the normal Qt
// shutdown thing.
//

std::atomic<bool> fRequestShutdown{false};
std::atomic<bool> fDumpMempoolLater{false};

void StartShutdown() { fRequestShutdown = true; }
bool ShutdownRequested() { return fRequestShutdown; }
class CCoinsViewErrorCatcher : public CCoinsViewBacked
{
public:
    CCoinsViewErrorCatcher(CCoinsView *view) : CCoinsViewBacked(view) {}
    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override
    {
        try
        {
            return CCoinsViewBacked::GetCoin(outpoint, coin);
        }
        catch (const std::runtime_error &e)
        {
            uiInterface.ThreadSafeMessageBox(
                _("Error reading from database, shutting down."), "", CClientUIInterface::MSG_ERROR);
            LOGA("Error reading from database: %s\n", e.what());
            // Starting the shutdown sequence and returning false to the caller would be
            // interpreted as 'entry not found' (as opposed to unable to read data), and
            // could lead to invalid interpretation. Just exit immediately, as we can't
            // continue anyway, and all writes should be atomic.
            abort();
        }
    }
    // Writes do not need similar protection, as failure to write is handled by the caller.
};

static CCoinsViewErrorCatcher *pcoinscatcher = nullptr;
static std::unique_ptr<ECCVerifyHandle> globalVerifyHandle;

void Interrupt()
{
    // Interrupt Parallel Block Validation threads if there are any running.
    if (PV)
    {
        PV->StopAllValidationThreads();
        PV->WaitForAllValidationThreadsToStop();
    }

    InterruptHTTPServer();
    InterruptHTTPRPC();
    InterruptRPC();
    InterruptREST();
    InterruptTorControl();
    threadGroup.interrupt_all();
    // stop TxAdmission needs to be done before threadGroup tries to join_all
    // we only join_all after Interrupt so call StopTxAdmission here
    StopTxAdmission();
    if (g_txindex)
    {
        g_txindex->Stop();
    }
}

void Shutdown()
{
    LOGA("%s: In progress...\n", __func__);
    static CCriticalSection cs_Shutdown;
    TRY_LOCK(cs_Shutdown, lockShutdown);
    if (!lockShutdown)
        return;

    /// Note: Shutdown() must be able to handle cases in which AppInit2() failed part of the way,
    /// for example if the data directory was found to be locked.
    /// Be sure that anything that writes files or flushes caches only does this if the respective
    /// module was initialized.
    RenameThread("shutoff");
    mempool.AddTransactionsUpdated(1);

    // Call every async stop function before flushing to disk
    StopHTTPRPC();
    StopREST();
    StopRPC();
    StopHTTPServer();
    StopTxAdmission();
    StopNode();
    PV.reset(nullptr); // clean up scriptcheck threads

    // This is the longest running shutdown procedure
    {
        LOCK(cs_main);
        if (pcoinsTip != nullptr)
        {
            // Flush state and clear cache completely to release as much memory as possible before continuing.
            FlushStateToDisk();
            pcoinsTip->Clear();
        }
    }

    electrum::ElectrumServer::Instance().Stop();
#ifdef ENABLE_WALLET
    if (pwalletMain)
        pwalletMain->Flush(false);
#endif
    GenerateBitcoins(false, 0, Params());

    if (g_txindex)
    {
        g_txindex.reset();
    }

    StopTorControl();
    UnregisterNodeSignals(GetNodeSignals());
    if (fDumpMempoolLater && GetArg("-persistmempool", DEFAULT_PERSIST_MEMPOOL))
    {
        DumpMempool();
        orphanpool.DumpOrphanPool();
    }

    if (fFeeEstimatesInitialized)
    {
        fs::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
        CAutoFile est_fileout(fsbridge::fopen(est_path, "wb"), SER_DISK, CLIENT_VERSION);
        if (!est_fileout.IsNull())
            mempool.WriteFeeEstimates(est_fileout);
        else
            LOGA("%s: Failed to write fee estimates to %s\n", __func__, est_path.string());
        fFeeEstimatesInitialized = false;
    }

    {
        LOCK(cs_main);
        if (pcoinsTip != nullptr)
        {
            FlushStateToDisk();
        }
        delete pcoinsTip;
        pcoinsTip = nullptr;
        delete pcoinscatcher;
        pcoinscatcher = nullptr;
        delete pcoinsdbview;
        pcoinsdbview = nullptr;
        delete pblocktree;
        pblocktree = nullptr;
        delete pblockdb;
        pblockdb = nullptr;
    }
#ifdef ENABLE_WALLET
    if (pwalletMain)
        pwalletMain->Flush(true);
#endif

#if ENABLE_ZMQ
    if (pzmqNotificationInterface)
    {
        UnregisterValidationInterface(pzmqNotificationInterface);
        delete pzmqNotificationInterface;
        pzmqNotificationInterface = nullptr;
    }
#endif

#ifndef WIN32
    try
    {
        fs::remove(GetPidFile());
    }
    catch (const std::exception &e)
    {
        LOGA("%s: Unable to remove pidfile: %s\n", __func__, e.what());
    }
#endif
    UnregisterAllValidationInterfaces();
#ifdef ENABLE_WALLET
    delete pwalletMain;
    pwalletMain = nullptr;
#endif
    globalVerifyHandle.reset();
    ECC_Stop();
    requester.Cleanup();
    NetCleanup();
    connmgr.reset(nullptr); // clean up connection manager
    MainCleanup();
    UnlimitedCleanup();
    LOGA("%s: done\n", __func__);
}

/**
 * Signal handlers are very limited in what they are allowed to do, so:
 */
void HandleSIGTERM(int) { fRequestShutdown = true; }
void HandleSIGHUP(int) { fReopenDebugLog = true; }
bool static Bind(const CService &addr, unsigned int flags)
{
    if (!(flags & BF_EXPLICIT) && IsLimited(addr))
        return false;
    std::string strError;
    if (!BindListenPort(addr, strError, (flags & BF_WHITELIST) != 0))
    {
        if (flags & BF_REPORT_ERROR)
            return InitError(strError);
        return false;
    }
    return true;
}

void OnRPCStopped()
{
    cvBlockChange.notify_all();
    LOG(RPC, "RPC stopped.\n");
}

void OnRPCPreCommand(const CRPCCommand &cmd)
{
    // Observe safe mode
    string strWarning = GetWarnings("rpc");
    if (strWarning != "" && !GetBoolArg("-disablesafemode", DEFAULT_DISABLE_SAFEMODE) && !cmd.okSafeMode)
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning);
}

// BU LicenseInfo() is moved to unlimited.cpp

static void BlockNotifyCallback(bool initialSync, const CBlockIndex *pBlockIndex, bool fHeader)
{
    if (initialSync || !pBlockIndex)
        return;

    std::string strCmd = GetArg("-blocknotify", "");

    boost::replace_all(strCmd, "%s", pBlockIndex->GetBlockHash().GetHex());
    boost::thread t(runCommand, strCmd); // thread runs free
}

static void NotifyElectrumCallback(bool initialSync, const CBlockIndex *pBlockIndex, bool)
{
    if (initialSync || !pBlockIndex)
        return;

    if (!GetArg("-electrum.blocknotify", true))
    {
        // When using with ElectrsCash < 2.0.0, this must be set to false, as
        // the signal is intepreted as "shutdown", rather than as block
        // notification.
        return;
    }

    electrum::ElectrumServer::Instance().NotifyNewBlock();
}

struct CImportingNow
{
    CImportingNow()
    {
        assert(fImporting == false);
        fImporting = true;
    }

    ~CImportingNow()
    {
        assert(fImporting == true);
        fImporting = false;
    }
};


// If we're using -prune with -reindex, then delete block files that will be ignored by the
// reindex.  Since reindexing works by starting at block file 0 and looping until a blockfile
// is missing, do the same here to delete any later block files after a gap.  Also delete all
// rev files since they'll be rewritten by the reindex anyway.  This ensures that vinfoBlockFile
// is in sync with what's actually on disk by the time we start downloading, so that pruning
// works correctly.
void CleanupBlockRevFiles()
{
    std::map<std::string, fs::path> mapBlockFiles;

    // Glob all blk?????.dat and rev?????.dat files from the blocks directory.
    // Remove the rev files immediately and insert the blk file paths into an
    // ordered map keyed by block file index.
    LOGA("Removing unusable blk?????.dat and rev?????.dat files for -reindex with -prune\n");
    fs::path blocksdir = GetDataDir() / "blocks";
    for (fs::directory_iterator it(blocksdir); it != fs::directory_iterator(); it++)
    {
        if (is_regular_file(*it) && it->path().filename().string().length() == 12 &&
            it->path().filename().string().substr(8, 4) == ".dat")
        {
            if (it->path().filename().string().substr(0, 3) == "blk")
                mapBlockFiles[it->path().filename().string().substr(3, 5)] = it->path();
            else if (it->path().filename().string().substr(0, 3) == "rev")
                remove(it->path());
        }
    }

    // Remove all block files that aren't part of a contiguous set starting at
    // zero by walking the ordered map (keys are block file indices) by
    // keeping a separate counter.  Once we hit a gap (or if 0 doesn't exist)
    // start removing block files.
    int nContigCounter = 0;
    for (const PAIRTYPE(std::string, fs::path) & item : mapBlockFiles)
    {
        if (atoi(item.first) == nContigCounter)
        {
            nContigCounter++;
            continue;
        }
        remove(item.second);
    }
}

static void ReconsiderChainOnStartup()
{
    if (!fReindex && !(avoidReconsiderMostWorkChain.Value()))
    {
        try
        {
            bool fOverride = false;
            ReconsiderMostWorkChain(fOverride);
        }
        catch (...)
        {
        }
    }
}

void ThreadImport(std::vector<fs::path> vImportFiles, uint64_t nTxIndexCache)
{
    const CChainParams &chainparams = Params();
    RenameThread("loadblk");
    ScheduleBatchPriority();

    // Allow the calling thread s little time to finish and redraw the QT wallet. For some reason
    // on windows the launching of this thread will prevent the main wallet window from redrawing, until
    // this thread has completed.
    //
    // TODO: investigate whether this is just a Windows issue.  It seems likely that it is given that this
    //       thread is scheduled at a lower priority on Linux systems and therefore may not have the issue.
    MilliSleep(500);

    // -reindex
    if (fReindex)
    {
        CImportingNow imp;
        int nFile = 0;
        while (true)
        {
            CDiskBlockPos pos(nFile, 0);
            if (!fs::exists(GetBlockPosFilename(pos, "blk")))
                break; // No block files left to reindex
            FILE *file = OpenBlockFile(pos, true);
            if (!file)
                break; // This error is logged in OpenBlockFile
            LOGA("Reindexing block file blk%05u.dat...\n", (unsigned int)nFile);
            LoadExternalBlockFile(chainparams, file, &pos);
            nFile++;

            if (fRequestShutdown)
                return;
        }
        pblocktree->WriteReindexing(false);
        fReindex = false;
        LOGA("Reindexing finished\n");
        // To avoid ending up in a situation without genesis block, re-try initializing (no-op if reindexing worked):
        InitBlockIndex(chainparams);
    }
    if (fRequestShutdown)
        return;

    // hardcoded $DATADIR/bootstrap.dat
    fs::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (fs::exists(pathBootstrap))
    {
        FILE *file = fsbridge::fopen(pathBootstrap, "rb");
        if (file)
        {
            fs::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LOGA("Importing bootstrap.dat...\n");
            LoadExternalBlockFile(chainparams, file);
            RenameOver(pathBootstrap, pathBootstrapOld);
        }
        else
        {
            LOGA("Warning: Could not open bootstrap file %s\n", pathBootstrap.string());
        }
    }
    if (fRequestShutdown)
        return;

    // -loadblock=
    for (const fs::path &path : vImportFiles)
    {
        FILE *file = fsbridge::fopen(path, "rb");
        if (file)
        {
            CImportingNow imp;
            LOGA("Importing blocks file %s...\n", path.string());
            LoadExternalBlockFile(chainparams, file);
        }
        else
        {
            LOGA("Warning: Could not open blocks file %s\n", path.string());
        }

        if (fRequestShutdown)
            return;
    }

    if (GetBoolArg("-stopafterblockimport", DEFAULT_STOPAFTERBLOCKIMPORT))
    {
        LOGA("Stopping after block import\n");
        StartShutdown();
        return;
    }

    // At this point the genesis block should have been loaded. We pause here and allow
    // the node to complete StartNode() before continuing with ActivateBestChain(). For some
    // reason QT will get hung while activating the chain if we don't do this wait, and it
    // may be some time before the node appears as up and running giving the operator the impression
    // that startup is very slow.
    while (!fAppInit2.load())
    {
        MilliSleep(100);
        if (fRequestShutdown)
            return;
    }

    // In case a previous shutdown left the chain in an incorrect state, reconsider
    // the most work chain. This needs to be done before we call ActivateBestChain() even
    // though it is invoked again after ActivateBestChain().
    ReconsiderChainOnStartup();

    // If we don't already have one, get an initial snapshot state to use for tx acceptance
    {
        TxAdmissionPause pause;
    }

#ifdef ENABLE_WALLET
    if (pwalletMain)
    {
        // Add wallet transactions that aren't already in a block to mapTransactions
        uiInterface.InitMessage(_("Reaccepting Wallet Transactions"));
        pwalletMain->ReacceptWalletTransactions();
    }
#endif
    if (fRequestShutdown)
        return;

    // Load the mempool if necessary
    if (GetArg("-persistmempool", DEFAULT_PERSIST_MEMPOOL))
    {
        uiInterface.InitMessage(_("Loading Mempool"));
        LoadMempool();

        uiInterface.InitMessage(_("Loading Orphanpool"));
        orphanpool.LoadOrphanPool();

        // Wait for transactions to finish loading but dont' wait forever
        size_t nInQ = 0;
        size_t nDeferQ = 0;
        size_t nCommitQ = 0;
        int nIterations = 0;
        while (1)
        {
            {
                LOCK(csTxInQ);
                nInQ = txInQ.size();
                nDeferQ = txDeferQ.size();
            }
            {
                boost::unique_lock<boost::mutex> lock(csCommitQ);
                nCommitQ = txCommitQ->size();
            }
            if (nInQ == 0 && nDeferQ == 0 && nCommitQ == 0)
                break;

            MilliSleep(1000);
            nIterations++;
            if (nIterations > 120)
            {
                LOGA("Clearing Queues because they are not empty: txInq %d, txDeferQ %d, txCommitQ %d\n", nInQ, nDeferQ,
                    nCommitQ);
                {
                    LOCK(csTxInQ);
                    while (!txInQ.empty())
                        txInQ.pop();
                    while (!txDeferQ.empty())
                        txDeferQ.pop();
                }
                {
                    boost::unique_lock<boost::mutex> lock(csCommitQ);
                    txCommitQ->clear();
                }
            }
        }
        fDumpMempoolLater = !fRequestShutdown;
    }
    if (fRequestShutdown)
        return;

    // scan for better chains in the block chain database, that are not yet connected in the active best chain
    uiInterface.InitMessage(_("Activating best chain..."));
    CValidationState state;
    if (!ActivateBestChain(state, chainparams))
    {
        LOGA("WARNING: ActivateBestChain failed on startup\n");
    }
    if (fRequestShutdown)
        return;

    // Reconsider the most work chain again here if we're not already synced. This is necessary
    // when switching from an ABC/BCHN client or when a operator failed to upgrade their BU
    // node before a hardfork. This must be done directly after ActivateBestChain() or
    // a switch from ABC/BCHN to a BU node may not work because some blocks may have been parked.
    ReconsiderChainOnStartup();
    if (fRequestShutdown)
        return;

    // Initialize the atomic flags used for determining whether we are in IBD or whether the chain
    // is almost synced.
    IsChainNearlySyncdInit();
    IsInitialBlockDownloadInit();

    // Startup txindex. If we start it earlier and before ActivateBestChain
    // we can end up grinding slowly through ActivateBestChain when txindex still has unfinished
    // compaction to do from a prior run.
    fTxIndex = GetBoolArg("-txindex", DEFAULT_TXINDEX);
    if (fTxIndex)
    {
        uiInterface.InitMessage(_("Starting txindex"));

        // When reindexing we want to wipe the previous txindex database however we don't want to
        // rely on the fReindex flag since it's possible that by the time we get to this point in the
        // node startup that the reindex is already completed (in the case of a very small reindex) and
        // therefore fReindex would already be false and the txindex would not get rebuilt.
        bool fWipeDatabase = GetBoolArg("-reindex", DEFAULT_REINDEX);
        auto txindex_db = new TxIndexDB(nTxIndexCache, false, fWipeDatabase);

        g_txindex = std::make_unique<TxIndex>(txindex_db);
        g_txindex->Start();
    }

    // This should be done last in init. If not, then RPC's could be allowed before the wallet
    // is ready.
    uiInterface.InitMessage(_("Done loading"));
    SetRPCWarmupFinished();
}

/** Sanity checks
 *  Ensure that Member is running in a usable environment with all
 *  necessary library support.
 */
bool InitSanityCheck(void)
{
    if (!ECC_InitSanityCheck())
    {
        InitError("Elliptic curve cryptography sanity check failure. Aborting.");
        return false;
    }

    if (!glibc_sanity_test() || !glibcxx_sanity_test())
        return false;

    if (!Random_SanityCheck())
    {
        InitError("OS cryptographic RNG sanity check failure. Aborting.");
        return false;
    }

    return true;
}

bool AppInitServers(int rpcport, const std::string &network)
{
    RPCServer::OnStopped(&OnRPCStopped);
    RPCServer::OnPreCommand(&OnRPCPreCommand);
    if (!InitHTTPServer())
        return false;
    if (!StartRPC())
        return false;
    if (!StartHTTPRPC())
        return false;
    if (GetBoolArg("-rest", DEFAULT_REST_ENABLE) && !StartREST())
        return false;
    if (!StartHTTPServer())
        return false;
    if (!electrum::ElectrumServer::Instance().Start(rpcport, network))
    {
        return false;
    }
    return true;
}

// Parameter interaction based on rules
void InitParameterInteraction()
{
    // when specifying an explicit binding address, you want to listen on it
    // even when -connect or -proxy is specified
    if (mapArgs.count("-bind"))
    {
        if (SoftSetBoolArg("-listen", true))
            LOGA("%s: parameter interaction: -bind set -> setting -listen=1\n", __func__);
    }
    if (mapArgs.count("-whitebind"))
    {
        if (SoftSetBoolArg("-listen", true))
            LOGA("%s: parameter interaction: -whitebind set -> setting -listen=1\n", __func__);
    }

    if (mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0)
    {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        if (SoftSetBoolArg("-dnsseed", false))
            LOGA("%s: parameter interaction: -connect set -> setting -dnsseed=0\n", __func__);
        if (SoftSetBoolArg("-listen", false))
            LOGA("%s: parameter interaction: -connect set -> setting -listen=0\n", __func__);
    }

    if (mapArgs.count("-proxy"))
    {
        // to protect privacy, do not listen by default if a default proxy server is specified
        if (SoftSetBoolArg("-listen", false))
            LOGA("%s: parameter interaction: -proxy set -> setting -listen=0\n", __func__);
        // to protect privacy, do not use UPNP when a proxy is set. The user may still specify -listen=1
        // to listen locally, so don't rely on this happening through -listen below.
        if (SoftSetBoolArg("-upnp", false))
            LOGA("%s: parameter interaction: -proxy set -> setting -upnp=0\n", __func__);
        // to protect privacy, do not discover addresses by default
        if (SoftSetBoolArg("-discover", false))
            LOGA("%s: parameter interaction: -proxy set -> setting -discover=0\n", __func__);
    }

    if (!GetBoolArg("-listen", DEFAULT_LISTEN))
    {
        // do not map ports or try to retrieve public IP when not listening (pointless)
        if (SoftSetBoolArg("-upnp", false))
            LOGA("%s: parameter interaction: -listen=0 -> setting -upnp=0\n", __func__);
        if (SoftSetBoolArg("-discover", false))
            LOGA("%s: parameter interaction: -listen=0 -> setting -discover=0\n", __func__);
        if (SoftSetBoolArg("-listenonion", false))
            LOGA("%s: parameter interaction: -listen=0 -> setting -listenonion=0\n", __func__);
    }

    if (mapArgs.count("-externalip"))
    {
        // if an explicit public IP is specified, do not try to find others
        if (SoftSetBoolArg("-discover", false))
            LOGA("%s: parameter interaction: -externalip set -> setting -discover=0\n", __func__);
    }

    if (GetBoolArg("-salvagewallet", false))
    {
        // Rewrite just private keys: rescan to find transactions
        if (SoftSetBoolArg("-rescan", true))
            LOGA("%s: parameter interaction: -salvagewallet=1 -> setting -rescan=1\n", __func__);
    }

    // -zapwallettx implies a rescan
    if (GetBoolArg("-zapwallettxes", false))
    {
        if (SoftSetBoolArg("-rescan", true))
            LOGA("%s: parameter interaction: -zapwallettxes=<mode> -> setting -rescan=1\n", __func__);
    }

    // disable walletbroadcast and whitelistrelay in blocksonly mode
    fBlocksOnly = GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY);
    if (fBlocksOnly)
    {
        if (SoftSetBoolArg("-whitelistrelay", false))
            LOGA("%s: parameter interaction: -blocksonly=1 -> setting -whitelistrelay=0\n", __func__);
#ifdef ENABLE_WALLET
        if (SoftSetBoolArg("-walletbroadcast", false))
            LOGA("%s: parameter interaction: -blocksonly=1 -> setting -walletbroadcast=0\n", __func__);
#endif
    }

    // Forcing relay from whitelisted hosts implies we will accept relays from them in the first place.
    if (GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY))
    {
        if (SoftSetBoolArg("-whitelistrelay", true))
            LOGA("%s: parameter interaction: -whitelistforcerelay=1 -> setting -whitelistrelay=1\n", __func__);
    }
}

void InitLogging()
{
    fPrintToConsole = GetBoolArg("-printtoconsole", DEFAULT_PRINTTOCONSOLE);

    // Some QA tests depend on debug.log being written to, so default
    // to always print to log file on regtest.
    const bool regtest = Params().NetworkIDString() == CBaseChainParams::REGTEST;
    fPrintToDebugLog = GetBoolArg("-printtologfile", !fPrintToConsole || regtest);

    fLogTimestamps = GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS);
    fLogTimeMicros = GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS);
    fLogIPs = GetBoolArg("-logips", DEFAULT_LOGIPS);
    Logging::LogInit();

    LOGA("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    std::string version_string = FormatFullVersion();
#ifdef DEBUG
    version_string += " (debug build)";
#else
    version_string += " (release build)";
#endif
    LOGA(PACKAGE_NAME " version %s (%s)\n", version_string, CLIENT_DATE);
}

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AppInit2(Config &config)
{
    // ********************************************************* Step 1: setup

    UnlimitedSetup();

#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
// Enable Data Execution Prevention (DEP)
// Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
// A failure is non-critical and needs no further attention!
#ifndef PROCESS_DEP_ENABLE
// We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
// which is not correct. Can be removed, when GCCs winbase.h is fixed!
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL(WINAPI * PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol =
        (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != nullptr)
        setProcDEPPol(PROCESS_DEP_ENABLE);
#endif

    if (!SetupNetworking())
        return InitError("Initializing networking failed");

#ifndef WIN32
    if (GetBoolArg("-sysperms", false))
    {
#ifdef ENABLE_WALLET
        if (!GetBoolArg("-disablewallet", false))
            return InitError("-sysperms is not allowed in combination with enabled wallet functionality");
#endif
    }
    else
    {
        umask(077);
    }

    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);

    // Reopen debug.log on SIGHUP
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, nullptr);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    signal(SIGPIPE, SIG_IGN);
#endif

    // ********************************************************* Step 2: parameter interactions
    // bip135 begin
    // changed from const to modifiable so that deployment params can be updated
    CChainParams &chainparams = ModifiableParams();
    // bip135 end

    // also see: InitParameterInteraction()

    if (chainparams.NetworkIDString() == "regtest")
    {
        max_blockfile_size = MAX_BLOCKFILE_SIZE_REGTEST;
    }

    // if using block pruning, then disable txindex
    if (GetArg("-prune", 0))
    {
        if (GetBoolArg("-txindex", DEFAULT_TXINDEX))
            return InitError(_("Prune mode is incompatible with -txindex."));
#ifdef ENABLE_WALLET
        if (GetBoolArg("-rescan", false))
        {
            return InitError(_("Rescans are not possible in pruned mode. You will need to use -reindex which will "
                               "download the whole blockchain again."));
        }
#endif
    }
    else
    {
        // raise preallocation size of block and undo files
        blockfile_chunk_size = max_blockfile_size;
        // multiply by 8 as this is the same difference between default and max blockfile size
        // we do not have a define max undofile size
        undofile_chunk_size = undofile_chunk_size * 8;
    }

    // Make sure enough file descriptors are available
    int nBind = std::max((int)mapArgs.count("-bind") + (int)mapArgs.count("-whitebind"), 1);
    int nUserMaxConnections = GetArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS);
    nMaxConnections = std::max(nUserMaxConnections, 0);

    // Trim requested connection counts, to fit into system limitations
    int nFD = RaiseFileDescriptorLimit(nMaxConnections + MIN_CORE_FILEDESCRIPTORS + nBind);
    if (nFD < MIN_CORE_FILEDESCRIPTORS)
        return InitError(_("Not enough file descriptors available."));

    nMaxConnections = std::min(nFD - MIN_CORE_FILEDESCRIPTORS - nBind, nMaxConnections);

    if (nMaxConnections < nUserMaxConnections)
        InitWarning(strprintf(_("Reducing -maxconnections from %d to %d because of file descriptor limitations (unix) "
                                "or winsocket fd_set limitations (windows). If you are a windows user there is a hard "
                                "upper limit of 1024 which cannot be changed by adjusting the node's configuration."),
            nUserMaxConnections, nMaxConnections));


    // make outbound conns modifiable by the user
    int nUserMaxOutConnections = GetArg("-maxoutconnections", DEFAULT_MAX_OUTBOUND_CONNECTIONS);
    nMaxOutConnections = std::max(nUserMaxOutConnections, 0);
    if (nMaxConnections < nMaxOutConnections)
    {
        LOGA(
            "Reducing -maxoutconnections from %d to %d, because this value is higher than max available connections.\n",
            nUserMaxOutConnections, nMaxConnections);
        nMaxOutConnections = nMaxConnections;
    }


    // ********************************************************* Step 3: parameter-to-internal-flags

    fDebug = !mapMultiArgs["-debug"].empty();
    // Special-case: if -debug=0/-nodebug is set, turn off debugging messages
    const vector<string> &categories = mapMultiArgs["-debug"];
    if (find(categories.begin(), categories.end(), string("0")) != categories.end())
        fDebug = false;

    // Checkmempool and checkblockindex default to true in regtest mode
    int ratio = std::min<int>(
        std::max<int>(GetArg("-checkmempool", chainparams.DefaultConsistencyChecks() ? 1 : 0), 0), 1000000);
    if (ratio != 0)
    {
        mempool.setSanityCheck(1.0 / ratio);
    }
    fCheckBlockIndex = GetBoolArg("-checkblockindex", chainparams.DefaultConsistencyChecks());
    fCheckpointsEnabled = GetBoolArg("-checkpoints", DEFAULT_CHECKPOINTS_ENABLED);

    connmgr->HandleCommandLine();
    dosMan.HandleCommandLine();

    // mempool limits
    int64_t nMempoolSizeMax = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    int64_t nMempoolSizeMin = 1 << 22;
    if (nMempoolSizeMax < 0 || nMempoolSizeMax < nMempoolSizeMin)
        return InitError(strprintf(_("-maxmempool must be at least %d MB"), std::ceil(nMempoolSizeMin / 1000000.0)));

    fServer = GetBoolArg("-server", true);

    // block pruning; get the amount of disk space (in MiB) to allot for block & undo files
    int64_t nSignedPruneTarget = GetArg("-prune", 0) * 1024 * 1024;
    if (nSignedPruneTarget < 0)
    {
        return InitError(_("Prune cannot be configured with a negative value."));
    }
    nPruneTarget = (uint64_t)nSignedPruneTarget;
    if (nPruneTarget)
    {
        if (nPruneTarget < MIN_DISK_SPACE_FOR_BLOCK_FILES)
        {
            return InitError(strprintf(_("Prune configured below the minimum of %d MiB.  Please use a higher number."),
                MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
        }
        LOGA("Prune configured to target %uMiB on disk for block and undo files.\n", nPruneTarget / 1024 / 1024);
        fPruneMode = true;
    }

    RegisterAllCoreRPCCommands(tableRPC);
#ifdef ENABLE_WALLET
    bool fDisableWallet = GetBoolArg("-disablewallet", false);
    if (!fDisableWallet)
        RegisterWalletRPCCommands(tableRPC);
#endif
#if ENABLE_ZMQ
    RegisterZMQRPCCommands(tableRPC);
#endif

    nConnectTimeout = GetArg("-timeout", DEFAULT_CONNECT_TIMEOUT);
    if (nConnectTimeout <= 0)
        nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;

    // Fee in satoshi per byte amount considered the same as "free"
    // If you are mining, be careful setting this:
    // if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    ::minRelayTxFee = CFeeRate((CAmount)(dMinLimiterTxFee.Value()) * 1000);

    // -minrelaytxfee is no longer a command line option however it is still used in Bitcon Core so we want to tell
    // any users that migrate from Core to BU that this option is not used.
    if (mapArgs.count("-minrelaytxfee"))
    {
        InitWarning(_("Config option -minrelaytxfee is no longer supported.  To set the limit "
                      "below which a transaction is considered zero fee please use -minlimitertxfee.  "
                      "To convert -minrelaytxfee, which is specified  in MEM/KB, to -minlimtertxfee, "
                      "which is specified in Satoshi/Byte, simply multiply the original -minrelaytxfee "
                      "by 100,000. For example, a -minrelaytxfee=0.00001000 will become -minlimitertxfee=1.000"));
    }


    bool fStandard = !GetBoolArg("-acceptnonstdtxn", !Params().RequireStandard());
    // If we specified an override but that override was not accepted then its an error
    if (fStandard != Params().RequireStandard())
        return InitError(
            strprintf("acceptnonstdtxn is not currently supported for %s chain", chainparams.NetworkIDString()));

    // Set Dust Threshold for outputs.
    nDustThreshold.Set(GetArg("-dustthreshold", DEFAULT_DUST_THRESHOLD));

    nBytesPerSigOp = GetArg("-bytespersigop", nBytesPerSigOp);

#ifdef ENABLE_WALLET
    if (!CWallet::ParameterInteraction())
        return false;
#endif // ENABLE_WALLET

    fIsBareMultisigStd = GetBoolArg("-permitbaremultisig", DEFAULT_PERMIT_BAREMULTISIG);
    fAcceptDatacarrier = GetBoolArg("-datacarrier", DEFAULT_ACCEPT_DATACARRIER);
    nMaxDatacarrierBytes = GetArg("-datacarriersize", nMaxDatacarrierBytes);
    if (nMaxDatacarrierBytes < MAX_OP_RETURN_RELAY)
    {
        InitWarning(strprintf(_("Increasing -datacarriersize from %d to %d due to new May 15th OP_RETURN size policy."),
            nMaxDatacarrierBytes, MAX_OP_RETURN_RELAY));
        nMaxDatacarrierBytes = MAX_OP_RETURN_RELAY;
    }

    // Option to startup with mocktime set (used for regression testing):
    SetMockTime(GetArg("-mocktime", 0)); // SetMockTime(0) is a no-op

    if (GetBoolArg("-peerbloomfilters", DEFAULT_PEERBLOOMFILTERS))
        nLocalServices |= NODE_BLOOM;

    // BUIP010 Xtreme Thinblocks: begin section Initialize XTHIN service
    if (GetBoolArg("-use-thinblocks", DEFAULT_USE_THINBLOCKS))
        nLocalServices |= NODE_XTHIN;
    // BUIP010 Xtreme Thinblocks: end section

    // BUIPXXX Graphene Blocks: begin section initialize Graphene service
    if (GetBoolArg("-use-grapheneblocks", DEFAULT_USE_GRAPHENE_BLOCKS))
        nLocalServices |= NODE_GRAPHENE;
    // BUIPXXX Graphene Blocks: end section

    // BitcoinCash service bit
    nLocalServices |= NODE_BITCOIN_CASH;
    // we use extversion by default
    if (GetBoolArg("-use-extversion", DEFAULT_USE_EXTVERSION))
        nLocalServices |= NODE_EXTVERSION;

    nMaxTipAge = GetArg("-maxtipage", DEFAULT_MAX_TIP_AGE);

    // xthin bloom filter limits
    nXthinBloomFilterSize = (uint32_t)GetArg("-xthinbloomfiltersize", SMALLEST_MAX_BLOOM_FILTER_SIZE);
    if (nXthinBloomFilterSize < SMALLEST_MAX_BLOOM_FILTER_SIZE)
        return InitError(
            strprintf(_("-xthinbloomfiltersize must be at least %d Bytes"), SMALLEST_MAX_BLOOM_FILTER_SIZE));

    // ********************************************************* Step 4: application initialization: dir lock,
    // daemonize, pidfile, debug log

    // Initialize elliptic curve code
    std::string sha256_algo = SHA256AutoDetect();
    RandomInit();
    LOGA("Using the '%s' SHA256 implementation\n", sha256_algo);
    ECC_Start();
    globalVerifyHandle.reset(new ECCVerifyHandle());

    // Sanity check
    if (!InitSanityCheck())
        return InitError(strprintf(_("Initialization sanity check failed. %s is shutting down."), _(PACKAGE_NAME)));

    std::string strDataDir = GetDataDir().string();

    // Make sure only a single Member process is using the data directory.
    fs::path pathLockFile = GetDataDir() / ".lock";
    FILE *file = fsbridge::fopen(pathLockFile, "a"); // empty lock file; created if it doesn't exist.
    if (file)
        fclose(file);

    try
    {
        static boost::interprocess::file_lock lock(pathLockFile.string().c_str());
        if (!lock.try_lock())
            return InitError(strprintf(_("Cannot obtain a lock on data directory %s. %s is probably already running."),
                strDataDir, _(PACKAGE_NAME)));
    }
    catch (const boost::interprocess::interprocess_exception &e)
    {
        return InitError(
            strprintf(_("Cannot obtain a lock on data directory %s. %s is probably already running.") + " %s.",
                strDataDir, _(PACKAGE_NAME), e.what()));
    }

#ifndef WIN32
    CreatePidFile(GetPidFile(), getpid());
#endif
    if (GetBoolArg("-shrinkdebugfile", !fDebug))
        ShrinkDebugFile();

    if (fPrintToDebugLog)
        OpenDebugLog();

#ifdef ENABLE_WALLET
    LOGA("Using BerkeleyDB version %s\n", DbEnv::version(0, 0, 0));
#endif
    if (!fLogTimestamps)
        LOGA("Startup time: %s\n", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()));
    LOGA("Default data directory %s\n", GetDefaultDataDir().string());
    LOGA("Using data directory %s\n", strDataDir);
    LOGA("Using config file %s\n", GetConfigFile(GetArg("-conf", BITCOIN_CONF_FILENAME)).string());
    LOGA("Using at most %i connections\n", nMaxConnections);
    std::ostringstream strErrors;

    // bip135 begin
    // check for fork deployment CSV file, read it
    string ForksCsvFile = GetForksCsvFile().string();

    if (boost::filesystem::exists(ForksCsvFile))
    {
        ifstream csvFile;
        bool CsvReadOk = true;
        try
        {
            csvFile.open(ForksCsvFile.c_str(), ios::in);
            if (csvFile.fail())
            {
                throw std::runtime_error("unable to open deployment file for reading");
            }

            LOGA("Reading deployment configuration CSV file at '%s'\n", ForksCsvFile);
            // read the CSV file and apply the parameters for current network
            CsvReadOk = ReadForksCsv(chainparams.NetworkIDString(), csvFile, chainparams.GetModifiableConsensus());
            csvFile.close();
        }
        catch (const std::exception &e)
        {
            LOGA("Unable to read '%s'\n", ForksCsvFile);
            // if unable to read file which is present: abort
            return InitError(strprintf(
                _("Warning: Could not open deployment configuration CSV file '%s' for reading"), ForksCsvFile));
        }
        // if the deployments data doesn't validate correctly, shut down for safety reasons.
        if (!CsvReadOk)
        {
            LOGA("Validation of '%s' failed\n", ForksCsvFile);
            return InitError(strprintf(
                _("Deployment configuration file '%s' contained invalid data - see debug.log"), ForksCsvFile));
        }
    }
    else
    {
        if (strcmp(GetArg("-forks", FORKS_CSV_FILENAME).c_str(), FORKS_CSV_FILENAME) == 0)
        {
            // Be noisy, but don't fail if file is absent - use built-in defaults.
            LOGA("No deployment configuration found at '%s' - using defaults\n", ForksCsvFile);
        }
        else
        {
            // Fail only when we've configured a file but it doesn't exit.
            return InitError(strprintf(_("Deployment configuration file '%s' not found"), ForksCsvFile));
        }
    }

    // assign votes based on the initial configuration of mining.vote
    ClearBip135Votes();
    AssignBip135Votes(bip135Vote, 1);

    // bip135 end

    // Setup the number of p2p message processing threads used to process incoming messages
    if (numMsgHandlerThreads.Value() == 0)
    {
        // Set the number of threads to half the available Cores.
        int nThreads = std::max(GetNumCores() / 2, 1);
        numMsgHandlerThreads.Set(nThreads);
    }
    LOGA("Using %d message handler threads\n", numMsgHandlerThreads.Value());

    // Setup the number of transaction mempool admission threads
    if (numTxAdmissionThreads.Value() == 0)
    {
        // Set the number of threads to half the available Cores.
        int nThreads = std::max(GetNumCores() / 2, 1);
        numTxAdmissionThreads.Set(nThreads);
    }
    LOGA("Using %d transaction admission threads\n", numTxAdmissionThreads.Value());

    InitSignatureCache();

    // Create the parallel block validator
    PV.reset(new CParallelValidation());

    /* Start the RPC server already.  It will be started in "warmup" mode
     * and not really process calls already (but it will signify connections
     * that the server is there and will be ready later).  Warmup mode will
     * be disabled when initialisation is finished.
     */
    if (fServer)
    {
        uiInterface.InitMessage.connect(SetRPCWarmupStatus);
        if (!AppInitServers(BaseParams().RPCPort(), chainparams.NetworkIDString()))
        {
            return InitError(_("Unable to start RPC services. See debug log for details."));
        }
    }

//Ensure rate data is the same across all systems
    string rateData=initRateTable();
    const std::vector<unsigned char> data2(rateData.begin(), rateData.end());
    int rateDataHash=MurmurHash3(1989,data2);
    //LOGA(rateData);
    LOGA("Rate Data Hash=%d\n",rateDataHash);
    assert(rateDataHash==-753007581);

    /*
    CAmount principal=100*COIN;
    int ONEDAY=1108;

    std::ostringstream ss;

    ss << "\n";
    for(int i=0;i<ONEDAY*1000;i=i+ONEDAY){
        ss << ((GetInterest(principal, i, i+(ONEDAY*1))-principal)*365*100.0)/principal << ","
        << ((GetInterest(principal, i, i+(ONEDAY*7))-principal)*52*100.0)/principal << ","
        << ((GetInterest(principal, i, i+(ONEDAY*28))-principal)*13*100.0)/principal << ","
        << ((GetInterest(principal, i, i+(ONEDAY*91))-principal)*4*100.0)/principal << ","
        << ((GetInterest(principal, i, i+(ONEDAY*182))-principal)*2*100.0)/principal << ","
        << ((GetInterest(principal, i, i+(ONEDAY*364))-principal)*100.0)/principal << ","
        << "\n";
    }

    //Make sure the interest rate table is the same across all systems
    string interestRateTable=ss.str();
    const std::vector<unsigned char> data(interestRateTable.begin(), interestRateTable.end());
    int rateTableHash=MurmurHash3(1989,data);
    LOGA("Rate Table Hash=%d\n",rateTableHash);
    assert(rateTableHash==-1013504577);
    */
    int64_t nStart;

// ********************************************************* Step 5: verify wallet database integrity
#ifdef ENABLE_WALLET
    if (!fDisableWallet)
    {
        if (!CWallet::Verify())
            return false;
    } // (!fDisableWallet)
#endif // ENABLE_WALLET
    // ********************************************************* Step 6: load block chain

    fReindex = GetBoolArg("-reindex", DEFAULT_REINDEX);
    int64_t requested_block_mode = GetArg("-useblockdb", DEFAULT_BLOCK_DB_MODE);
    if (requested_block_mode >= 0 && requested_block_mode < END_STORAGE_OPTIONS)
    {
        BLOCK_DB_MODE = static_cast<BlockDBMode>(requested_block_mode);
    }
    else
    {
        BLOCK_DB_MODE = DEFAULT_BLOCK_DB_MODE;
    }

    // Upgrading to 0.8; hard-link the old blknnnn.dat files into /blocks/
    if (BLOCK_DB_MODE == SEQUENTIAL_BLOCK_FILES)
    {
        fs::path blocksDir = GetDataDir() / "blocks";
        if (!fs::exists(blocksDir))
        {
            fs::create_directories(blocksDir);
            bool linked = false;
            for (unsigned int i = 1; i < 10000; i++)
            {
                fs::path source = GetDataDir() / strprintf("blk%04u.dat", i);
                if (!fs::exists(source))
                    break;
                fs::path dest = blocksDir / strprintf("blk%05u.dat", i - 1);
                try
                {
                    fs::create_hard_link(source, dest);
                    LOGA("Hardlinked %s -> %s\n", source.string(), dest.string());
                    linked = true;
                }
                catch (const fs::filesystem_error &e)
                {
                    // Note: hardlink creation failing is not a disaster, it just means
                    // blocks will get re-downloaded from peers.
                    LOGA("Error hardlinking blk%04u.dat: %s\n", i, e.what());
                    break;
                }
            }
            if (linked)
            {
                fReindex = true;
            }
        }
    }

    // Return the initial values for the various in memory caches.
    CacheConfig cacheConfig = DiscoverCacheConfiguration();
    LOGA("Cache configuration:\n");
    LOGA("* Using %.1fMiB for block database\n", cacheConfig.nBlockDBCache * (1.0 / 1024 / 1024));
    LOGA("* Using %.1fMiB for block undo database\n", cacheConfig.nBlockUndoDBCache * (1.0 / 1024 / 1024));
    LOGA("* Using %.1fMiB for block index database\n", cacheConfig.nBlockTreeDBCache * (1.0 / 1024 / 1024));
    LOGA("* Using %.1fMiB for txindex database\n", cacheConfig.nTxIndexCache * (1.0 / 1024 / 1024));
    LOGA("* Using %.1fMiB for chain state database\n", cacheConfig.nCoinDBCache * (1.0 / 1024 / 1024));
    LOGA("* Using %.1fMiB for in-memory UTXO set\n", nCoinCacheMaxSize * (1.0 / 1024 / 1024));

    bool fLoaded = false;

    while (!fLoaded)
    {
        bool fReset = fReindex;
        std::string strLoadError;

        nStart = GetTimeMillis();
        do
        {
            try
            {
                UnloadBlockIndex();
                delete pcoinsTip;
                delete pcoinsdbview;
                delete pcoinscatcher;
                delete pblocktree;
                delete pblocktreeother;
                delete pblockdb;

                uiInterface.InitMessage(_("Opening Block database..."));
                InitializeBlockStorage(
                    cacheConfig.nBlockTreeDBCache, cacheConfig.nBlockDBCache, cacheConfig.nBlockUndoDBCache);

                uiInterface.InitMessage(_("Opening UTXO database..."));
                COverrideOptions overridecache;
                overridecache.block_size = 4096;
                pcoinsdbview = new CCoinsViewDB(cacheConfig.nCoinDBCache, false, fReindex, true, &overridecache);

                pcoinscatcher = new CCoinsViewErrorCatcher(pcoinsdbview);
                uiInterface.InitMessage(_("Opening Coins Cache database..."));
                pcoinsTip = new CCoinsViewCache(pcoinscatcher);
                InitTxAdmission();

                if (fReindex)
                {
                    pblocktree->WriteReindexing(true);
                    // If we're reindexing in prune mode, wipe away unusable block files and all undo data files
                    if (fPruneMode)
                        CleanupBlockRevFiles();
                }
                else
                {
                    // If necessary, upgrade from older database format.
                    if (!pcoinsdbview->Upgrade())
                    {
                        strLoadError = _("Error upgrading chainstate database");
                        break;
                    }
                }

                uiInterface.InitMessage(_("Loading block index..."));
                if (!LoadBlockIndex())
                {
                    strLoadError = _("Error loading block database");
                    break;
                }

                {
                    READLOCK(cs_mapBlockIndex);
                    // If the loaded chain has a wrong genesis, bail out immediately
                    // (we're likely using a testnet datadir, or the other way around).
                    if (!mapBlockIndex.empty() && mapBlockIndex.count(chainparams.GetConsensus().hashGenesisBlock) == 0)
                        return InitError(_("Incorrect or no genesis block found. Wrong datadir for network?"));
                }

                // Initialize the block index (no-op if non-empty database was already loaded)
                if (!InitBlockIndex(chainparams))
                {
                    strLoadError = _("Error initializing block database");
                    break;
                }

                // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
                // in the past, but is now trying to run unpruned.
                if (fHavePruned && !fPruneMode)
                {
                    strLoadError = _("You need to rebuild the database using -reindex to go back to unpruned mode.  "
                                     "This will redownload the entire blockchain");
                    break;
                }

                uiInterface.InitMessage(_("Verifying blocks..."));
                if (fHavePruned && GetArg("-checkblocks", DEFAULT_CHECKBLOCKS) > MIN_BLOCKS_TO_KEEP)
                {
                    LOGA("Prune: pruned datadir may not have more than %d blocks; only checking available blocks",
                        MIN_BLOCKS_TO_KEEP);
                }
                CBlockIndex *tip = chainActive.Tip();
                // we intentionally do not check if tip is a nullptr here
                // ActivateBestChain has already been called in either LoadBlockIndex or InitBlockIndex, if tip
                // is nullptr here then there is a critical error somewhere
                if (tip->nTime > GetAdjustedTime() + 2 * 60 * 60)
                {
                    strLoadError = _("The block database contains a block which appears to be from the future. "
                                     "This may be due to your computer's date and time being set incorrectly. "
                                     "Only rebuild the block database if you are sure that your computer's date "
                                     "and time are correct");
                    break;
                }
                if (!CVerifyDB().VerifyDB(chainparams, pcoinsdbview, GetArg("-checklevel", DEFAULT_CHECKLEVEL),
                        GetArg("-checkblocks", DEFAULT_CHECKBLOCKS)))
                {
                    strLoadError = _("Corrupted block database detected");
                    break;
                }
            }
            catch (const std::exception &e)
            {
                if (fDebug)
                    LOGA("%s\n", e.what());
                strLoadError = _("Error opening block database");
                break;
            }

            fLoaded = true;
        } while (false);

        if (!fLoaded)
        {
            // first suggest a reindex
            if (!fReset)
            {
                bool fRet = uiInterface.ThreadSafeMessageBox(
                    strLoadError + ".\n\n" + _("Do you want to rebuild the block database now?"), "",
                    CClientUIInterface::MSG_ERROR | CClientUIInterface::BTN_ABORT);
                if (fRet)
                {
                    fReindex = true;
                    fRequestShutdown = false;
                }
                else
                {
                    LOGA("Aborted block database rebuild. Exiting.\n");
                    return false;
                }
            }
            else
            {
                return InitError(strLoadError);
            }
        }
    }

    StartTxAdmissionThreads();

    // As LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (fRequestShutdown)
    {
        LOGA("Shutdown requested. Exiting.\n");
        return false;
    }
    LOGA(" block index %15dms\n", GetTimeMillis() - nStart);

    fs::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
    CAutoFile est_filein(fsbridge::fopen(est_path, "rb"), SER_DISK, CLIENT_VERSION);
    // Allowed to fail as this file IS missing on first startup.
    if (!est_filein.IsNull())
        mempool.ReadFeeEstimates(est_filein);
    fFeeEstimatesInitialized = true;

    // Set fCanonicalTxsOrder for the BCH early in the bootstrap phase
    if (IsNov2018Activated(Params().GetConsensus(), chainActive.Tip()))
    {
        if (chainparams.NetworkIDString() != "regtest")
        {
            fCanonicalTxsOrder = true;
        }
    }
    else
    {
        if (chainparams.NetworkIDString() != "regtest")
        {
            fCanonicalTxsOrder = false;
        }
    }


// ********************************************************* Step 7: load wallet

#ifdef ENABLE_WALLET

    // Encoded addresses using cashaddr instead of base58
    // The default behaviour is to use this encoding. This will help
    // to avoid confusion with other currencies the base58 encoding
    config.SetCashAddrEncoding(GetBoolArg("-usecashaddr", true));

    if (fDisableWallet)
    {
        pwalletMain = nullptr;
        LOGA("Wallet disabled!\n");
    }
    else
    {
        CWallet::InitLoadWallet();
        if (!pwalletMain)
            return false;
    }
#else // ENABLE_WALLET
    LOGA("No wallet support compiled in!\n");
#endif // !ENABLE_WALLET

    // ********************************************************* Step 8: data directory maintenance

    // if pruning, unset the service bit and perform the initial blockstore prune
    // after any wallet rescanning has taken place.
    if (fPruneMode)
    {
        LOGA("Unsetting NODE_NETWORK on prune mode\n");
        nLocalServices &= ~NODE_NETWORK;
        LOGA("Setting NODE_NETWORK_LIMITED on prune mode\n");
        nLocalServices |= NODE_NETWORK_LIMITED;
        if (!fReindex)
        {
            uiInterface.InitMessage(_("Pruning blockstore..."));
            PruneAndFlush();
        }
    }

    // ********************************************************* Step 10: network initialization

    RegisterNodeSignals(GetNodeSignals());

    // sanitize comments per BIP-0014, format user agent and check total size
    std::vector<string> uacomments = {};
    for (string &cmt : mapMultiArgs["-uacomment"])
    {
        if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT))
            return InitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        uacomments.push_back(SanitizeString(cmt, SAFE_CHARS_UA_COMMENT));
    }

    std::string strSubVersion = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, BUComments);
    if (strSubVersion.size() == MAX_SUBVERSION_LENGTH)
    {
        InitWarning(
            strprintf(_("Total length of network version string with uacomments added exceeded "
                        "the maximum length (%i) and have been truncated.  Reduce the number or size of uacomments "
                        "to avoid truncation."),
                MAX_SUBVERSION_LENGTH));
    }

    if (mapArgs.count("-onlynet"))
    {
        std::set<enum Network> nets;
        for (const std::string &snet : mapMultiArgs["-onlynet"])
        {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet));
            nets.insert(net);
        }
        for (int n = 0; n < NET_MAX; n++)
        {
            enum Network net = (enum Network)n;
            if (!nets.count(net))
                SetLimited(net);
        }
    }

    if (mapArgs.count("-whitelist"))
    {
        for (const std::string &net : mapMultiArgs["-whitelist"])
        {
            CSubNet subnet(net);
            if (!subnet.IsValid())
                return InitError(strprintf(_("Invalid netmask specified in -whitelist: '%s'"), net));
            dosMan.AddWhitelistedRange(subnet);
        }
    }

    bool proxyRandomize = GetBoolArg("-proxyrandomize", DEFAULT_PROXYRANDOMIZE);
    // -proxy sets a proxy for all outgoing network traffic
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set a proxy, this is the default
    std::string proxyArg = GetArg("-proxy", "");
    SetLimited(NET_TOR);
    if (proxyArg != "" && proxyArg != "0")
    {
        proxyType addrProxy = proxyType(CService(proxyArg, 9050), proxyRandomize);
        if (!addrProxy.IsValid())
            return InitError(strprintf(_("Invalid -proxy address: '%s'"), proxyArg));

        SetProxy(NET_IPV4, addrProxy);
        SetProxy(NET_IPV6, addrProxy);
        SetProxy(NET_TOR, addrProxy);
        SetNameProxy(addrProxy);
        SetLimited(NET_TOR, false); // by default, -proxy sets onion as reachable, unless -noonion later
    }

    // -onion can be used to set only a proxy for .onion, or override normal proxy for .onion addresses
    // -noonion (or -onion=0) disables connecting to .onion entirely
    // An empty string is used to not override the onion proxy (in which case it defaults to -proxy set above, or none)
    std::string onionArg = GetArg("-onion", "");
    if (onionArg != "")
    {
        if (onionArg == "0")
        { // Handle -noonion/-onion=0
            SetLimited(NET_TOR); // set onions as unreachable
        }
        else
        {
            proxyType addrOnion = proxyType(CService(onionArg, 9050), proxyRandomize);
            if (!addrOnion.IsValid())
                return InitError(strprintf(_("Invalid -onion address: '%s'"), onionArg));
            SetProxy(NET_TOR, addrOnion);
            SetLimited(NET_TOR, false);
        }
    }

    // see Step 2: parameter interactions for more information about these
    fListen = GetBoolArg("-listen", DEFAULT_LISTEN);
    fDiscover = GetBoolArg("-discover", DEFAULT_DISCOVER);
    fNameLookup = GetBoolArg("-dns", DEFAULT_NAME_LOOKUP);

    bool fBindFailure = false; // will be set true for any failure to bind to a P2P port
    bool fBound = false;
    if (fListen)
    {
        if (mapArgs.count("-bind") || mapArgs.count("-whitebind"))
        {
            for (const std::string &strBind : mapMultiArgs["-bind"])
            {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false))
                    return InitError(strprintf(_("Cannot resolve -bind address: '%s'"), strBind));

                bool bound = Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR));
                fBindFailure |= !bound;
                fBound |= bound;
            }
            for (const std::string &strBind : mapMultiArgs["-whitebind"])
            {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, 0, false))
                    return InitError(strprintf(_("Cannot resolve -whitebind address: '%s'"), strBind));
                if (addrBind.GetPort() == 0)
                    return InitError(strprintf(_("Need to specify a port with -whitebind: '%s'"), strBind));
                bool bound = Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR | BF_WHITELIST));
                fBindFailure |= !bound;
                fBound |= bound;
            }
        }
        else
        {
            struct in_addr inaddr_any;
            inaddr_any.s_addr = INADDR_ANY;
            struct in6_addr inaddr6_any = IN6ADDR_ANY_INIT;
            bool bound = Bind(CService(inaddr6_any, GetListenPort()), BF_NONE);
            fBindFailure |= !bound;
            fBound |= bound;

            bound = Bind(CService(inaddr_any, GetListenPort()), !fBound ? BF_REPORT_ERROR : BF_NONE);
            fBindFailure |= !bound;
            fBound |= bound;
        }
        if (!fBound)
            return InitError(_("Failed to listen on any port. Use -listen=0 if you want this."));

        if (fBindFailure && GetBoolArg("-bindallorfail", false))
            return InitError(_("Failed to listen on all P2P ports. Failing as requested by -bindallorfail."));
    }

    if (mapArgs.count("-externalip"))
    {
        for (const std::string &strAddr : mapMultiArgs["-externalip"])
        {
            CService addrLocal;
            if (Lookup(strAddr.c_str(), addrLocal, GetListenPort(), fNameLookup) && addrLocal.IsValid())
                AddLocal(addrLocal, LOCAL_MANUAL);
            else
                return InitError(strprintf(_("Cannot resolve -externalip address: '%s'"), strAddr));
        }
    }

    for (const std::string &strDest : mapMultiArgs["-seednode"])
        AddOneShot(strDest);

#if ENABLE_ZMQ
    pzmqNotificationInterface = CZMQNotificationInterface::CreateWithArguments(mapArgs);

    if (pzmqNotificationInterface)
    {
        RegisterValidationInterface(pzmqNotificationInterface);
    }
#endif
    if (mapArgs.count("-maxuploadtarget"))
    {
        CNode::SetMaxOutboundTarget(GetArg("-maxuploadtarget", DEFAULT_MAX_UPLOAD_TARGET) * 1024 * 1024);
    }


    // Monitor the chain, and alert if we get blocks much quicker or slower than expected
    // The "bad chain alert" scheduler has been disabled because the current system gives far
    // too many false positives, such that users are starting to ignore them.
    // This code will be disabled for 0.12.1 while a fix is deliberated in #7568
    // this was discussed in the IRC meeting on 2016-03-31.
    //
    // --- disabled ---
    // int64_t nPowTargetSpacing = Params().GetConsensus().nPowTargetSpacing;
    // CScheduler::Function f = boost::bind(&PartitionCheck, &IsInitialBlockDownload,
    //                                     boost::ref(cs_main), boost::cref(pindexBestHeader), nPowTargetSpacing);
    // scheduler.scheduleEvery(f, nPowTargetSpacing);
    // --- end disabled ---


    // ********************************************************* Step 9: import blocks

    if (mapArgs.count("-blocknotify"))
        uiInterface.NotifyBlockTip.connect(BlockNotifyCallback);

    if (mapArgs.count("-electrum"))
    {
        uiInterface.NotifyBlockTip.connect(NotifyElectrumCallback);
    }

    std::vector<fs::path> vImportFiles;
    if (mapArgs.count("-loadblock"))
    {
        for (const std::string &strFile : mapMultiArgs["-loadblock"])
            vImportFiles.push_back(strFile);
    }
    threadGroup.create_thread(boost::bind(&ThreadImport, vImportFiles, cacheConfig.nTxIndexCache));

    uiInterface.InitMessage(_("Waiting for Genesis Block..."));
    CBlockIndex *tip = nullptr;
    while (!fRequestShutdown && !tip)
    {
        tip = chainActive.Tip();
        MilliSleep(10);

        if (fRequestShutdown)
            return false;
    }

    // ********************************************************* Step 10: start node

    if (!CheckDiskSpace())
        return false;

    if (!strErrors.str().empty())
        return InitError(strErrors.str());

    //// debug print
    {
        READLOCK(cs_mapBlockIndex);
        LOGA("mapBlockIndex.size() = %u\n", mapBlockIndex.size());
    }

    LOGA("nBestHeight = %d\n", chainActive.Height());
#ifdef ENABLE_WALLET
    LOGA("setKeyPool.size() = %u\n", pwalletMain ? pwalletMain->setKeyPool.size() : 0);
    LOGA("mapWallet.size() = %u\n", pwalletMain ? pwalletMain->mapWallet.size() : 0);
    LOGA("mapAddressBook.size() = %u\n", pwalletMain ? pwalletMain->mapAddressBook.size() : 0);
#endif

    if (GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION))
        StartTorControl();


    StartNode();

#ifdef ENABLE_WALLET
    if (pwalletMain)
    {
        // Run a thread to flush wallet periodically
        threadGroup.create_thread(&ThreadFlushWalletDB, boost::ref(pwalletMain->strWalletFile));
    }
#endif

    // Done with intialization. Set flag so that threadimport can begin.
    fAppInit2.store(true);

    return true;
}
