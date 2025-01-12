// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "base58.h"
#include "chainparams.h"
#include "clientversion.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "core_io.h"
#include "dstencode.h"
#include "keystore.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sign.h"
#include "sync.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include <univalue.h>

#include <stdio.h>

#include <boost/algorithm/string.hpp>
#include <boost/assign/list_of.hpp>

#ifdef DEBUG_LOCKORDER
std::atomic<bool> lockdataDestructed{false};
LockData lockdata;
#endif

using namespace std;

static bool fCreateBlank;
static map<string, UniValue> registers;
static const int CONTINUE_EXECUTION = -1;

//
// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
//
static int AppInitRawTx(int argc, char *argv[])
{
    //
    // Parameters
    //
    AllowedArgs::BitcoinTx allowedArgs;
    try
    {
        ParseParameters(argc, argv, allowedArgs);
    }
    catch (const std::exception &e)
    {
        fprintf(stderr, "Error parsing program options: %s\n", e.what());
        return EXIT_FAILURE;
    }

    // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
    try
    {
        SelectParams(ChainNameFromCommandLine());
    }
    catch (const std::exception &e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }

    fCreateBlank = GetBoolArg("-create", false);

    if (argc < 2 || mapArgs.count("-?") || mapArgs.count("-h") || mapArgs.count("-help") || mapArgs.count("-version"))
    {
        // First part of help message is specific to this utility
        std::string strUsage =
            strprintf(_("%s bitcoin-tx utility version"), _(PACKAGE_NAME)) + " " + FormatFullVersion() + "\n";

        fprintf(stdout, "%s", strUsage.c_str());

        if (mapArgs.count("-version"))
            return false;

        strUsage = "\n" + _("Usage:") + "\n" + "  bitcoin-tx [options] <hex-tx> [commands]  " +
                   _("Update hex-encoded member transaction") + "\n" + "  bitcoin-tx [options] -create [commands]   " +
                   _("Create hex-encoded member transaction") + "\n" + "\n";

        fprintf(stdout, "%s", strUsage.c_str());

        strUsage = allowedArgs.helpMessage();

        fprintf(stdout, "%s", strUsage.c_str());

        strUsage = AllowedArgs::HelpMessageGroup(_("Commands:"));
        strUsage += AllowedArgs::HelpMessageOpt("delin=N", _("Delete input N from TX"));
        strUsage += AllowedArgs::HelpMessageOpt("delout=N", _("Delete output N from TX"));
        strUsage += AllowedArgs::HelpMessageOpt("in=TXID:VOUT", _("Add input to TX"));
        strUsage += AllowedArgs::HelpMessageOpt("locktime=N", _("Set TX lock time to N"));
        strUsage += AllowedArgs::HelpMessageOpt("nversion=N", _("Set TX version to N"));
        strUsage += AllowedArgs::HelpMessageOpt("outaddr=VALUE:ADDRESS", _("Add address-based output to TX"));
        strUsage += AllowedArgs::HelpMessageOpt("outdata=[VALUE:]DATA", _("Add data-based output to TX"));
        strUsage += AllowedArgs::HelpMessageOpt("outscript=VALUE:SCRIPT[:FLAGS]",
            _("Add raw script output to TX") + ". " +
                _("Optionally add the \"S\" flag to wrap the script in a P2SH output."));

        strUsage += AllowedArgs::HelpMessageOpt("sign=SIGHASH-FLAGS",
            _("Add zero or more signatures to transaction") + ". " + _("This command requires JSON registers:") +
                _("prevtxs=JSON object") + ", " + _("privatekeys=JSON object") + ". " +
                _("See signrawtransaction docs for format of sighash flags, JSON objects."));
        fprintf(stdout, "%s", strUsage.c_str());

        strUsage = AllowedArgs::HelpMessageGroup(_("Register Commands:"));
        strUsage += AllowedArgs::HelpMessageOpt("load=NAME:FILENAME", _("Load JSON file FILENAME into register NAME"));
        strUsage += AllowedArgs::HelpMessageOpt("set=NAME:JSON-STRING", _("Set register NAME to given JSON-STRING"));
        fprintf(stdout, "%s", strUsage.c_str());

        if (argc < 2)
        {
            fprintf(stderr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
    return CONTINUE_EXECUTION;
}

static void RegisterSetJson(const string &key, const string &rawJson)
{
    UniValue val;
    if (!val.read(rawJson))
    {
        string strErr = "Cannot parse JSON for key " + key;
        throw runtime_error(strErr);
    }

    registers[key] = val;
}

static void RegisterSet(const string &strInput)
{
    // separate NAME:VALUE in string
    size_t pos = strInput.find(':');
    if ((pos == string::npos) || (pos == 0) || (pos == (strInput.size() - 1)))
        throw runtime_error("Register input requires NAME:VALUE");

    string key = strInput.substr(0, pos);
    string valStr = strInput.substr(pos + 1, string::npos);

    RegisterSetJson(key, valStr);
}

static void RegisterLoad(const string &strInput)
{
    // separate NAME:FILENAME in string
    size_t pos = strInput.find(':');
    if ((pos == string::npos) || (pos == 0) || (pos == (strInput.size() - 1)))
        throw runtime_error("Register load requires NAME:FILENAME");

    string key = strInput.substr(0, pos);
    string filename = strInput.substr(pos + 1, string::npos);

    FILE *f = fopen(filename.c_str(), "r");
    if (!f)
    {
        string strErr = "Cannot open file " + filename;
        throw runtime_error(strErr);
    }

    // load file chunks into one big buffer
    string valStr;
    while ((!feof(f)) && (!ferror(f)))
    {
        char buf[4096];
        int bread = fread(buf, 1, sizeof(buf), f);
        if (bread <= 0)
            break;

        valStr.insert(valStr.size(), buf, bread);
    }

    int error = ferror(f);
    fclose(f);

    if (error)
    {
        string strErr = "Error reading file " + filename;
        throw runtime_error(strErr);
    }

    // evaluate as JSON buffer register
    RegisterSetJson(key, valStr);
}

static CAmount ExtractAndValidateValue(const std::string &strValue)
{
    CAmount value;
    if (!ParseMoney(strValue, value))
        throw runtime_error("Invalid TX output value");

    return value;
}

static void MutateTxVersion(CMutableTransaction &tx, const string &cmdVal)
{
    int64_t newVersion = atoi64(cmdVal);
    if (newVersion < 1 || newVersion > CTransaction::CURRENT_VERSION)
        throw runtime_error("Invalid TX version requested");

    tx.nVersion = (int)newVersion;
}

static void MutateTxLocktime(CMutableTransaction &tx, const string &cmdVal)
{
    int64_t newLocktime = atoi64(cmdVal);
    if (newLocktime < 0LL || newLocktime > 0xffffffffLL)
        throw runtime_error("Invalid TX locktime requested");

    tx.nLockTime = (unsigned int)newLocktime;
}

static void MutateTxAddInput(CMutableTransaction &tx, const string &strInput)
{
    std::vector<std::string> vStrInputParts;
    boost::split(vStrInputParts, strInput, boost::is_any_of(":"));

    // separate TXID:VOUT in string
    if (vStrInputParts.size() < 2)
        throw runtime_error("TX input missing separator");

    // extract and validate TXID
    string strTxid = vStrInputParts[0];
    if ((strTxid.size() != 64) || !IsHex(strTxid))
        throw runtime_error("invalid TX input txid");
    uint256 txid(uint256S(strTxid));

    static const unsigned int minTxOutSz = 9;
    static const unsigned int maxVout = BLOCKSTREAM_CORE_MAX_BLOCK_SIZE / minTxOutSz;

    // extract and validate vout
    string strVout = vStrInputParts[1];
    int vout = atoi(strVout);
    // BU: be strict about what is generated.  TODO: BLOCKSTREAM_CORE_MAX_BLOCK_SIZE should be converted to a cmd line
    // parameter
    if ((vout < 0) || (vout > (int)maxVout))
        throw runtime_error("invalid TX input vout");

    // extract the optional sequence number
    uint32_t nSequenceIn = std::numeric_limits<unsigned int>::max();
    if (vStrInputParts.size() > 2)
        nSequenceIn = std::stoul(vStrInputParts[2]);

    // append to transaction input list
    CTxIn txin(txid, vout, CScript(), nSequenceIn);
    tx.vin.push_back(txin);
}

static void MutateTxAddOutAddr(CMutableTransaction &tx, const string &strInput)
{
    // separate VALUE:ADDRESS in string
    std::vector<std::string> vStrInputParts;
    boost::split(vStrInputParts, strInput, boost::is_any_of(":"));

    if (vStrInputParts.size() != 2 && vStrInputParts.size() != 3)
        throw runtime_error("TX output missing or too many separators");
    if (vStrInputParts.size() == 3)
    {
        if (vStrInputParts[1] != "bchreg" && vStrInputParts[1] != "bitcoincash" && vStrInputParts[1] != "bchnol" &&
            vStrInputParts[1] != "bchtest")
        {
            throw runtime_error(tfm::format("TX output unknown destination address type %s.", vStrInputParts[1]));
        }
        vStrInputParts.erase(vStrInputParts.begin() + 1);
    }

    // Extract and validate VALUE
    CAmount value = ExtractAndValidateValue(vStrInputParts[0]);

    // extract and validate ADDRESS
    std::string strAddr = vStrInputParts[1];
    CTxDestination destination = DecodeDestination(strAddr);
    if (!IsValidDestination(destination))
    {
        throw std::runtime_error("invalid TX output address");
    }
    CScript scriptPubKey = GetScriptForDestination(destination);

    // construct TxOut, append to transaction output list
    CTxOut txout(value, scriptPubKey);
    tx.vout.push_back(txout);
}

static void MutateTxAddOutData(CMutableTransaction &tx, const std::string &strInput)
{
    CAmount value = 0;

    // separate [VALUE:]DATA in string
    size_t pos = strInput.find(':');

    if (pos == 0)
        throw runtime_error("TX output value not specified");

    if (pos != string::npos)
    {
        // extract and validate VALUE
        string strValue = strInput.substr(0, pos);
        if (!ParseMoney(strValue, value))
            throw runtime_error("invalid TX output value");
    }

    // extract and validate DATA
    string strData = strInput.substr(pos + 1, string::npos);

    if (!IsHex(strData))
        throw runtime_error("invalid TX output data");

    std::vector<unsigned char> data = ParseHex(strData);

    CTxOut txout(value, CScript() << OP_RETURN << data);
    tx.vout.push_back(txout);
}

static void MutateTxAddOutScript(CMutableTransaction &tx, const string &strInput)
{
    // separate VALUE:SCRIPT in string
    std::vector<std::string> vStrInputParts;
    boost::split(vStrInputParts, strInput, boost::is_any_of(":"));
    if (vStrInputParts.size() < 2)
        throw runtime_error("TX output missing separator");

    // extract and validate VALUE
    CAmount value = ExtractAndValidateValue(vStrInputParts[0]);

    // extract and validate script
    std::string strScript = vStrInputParts[1];
    CScript scriptPubKey = ParseScript(strScript);

    // Extract FLAGS
    bool bScriptHash = false;
    if (vStrInputParts.size() > 2)
    {
        std::string flags = vStrInputParts.back();
        bScriptHash = (flags.find("S") != std::string::npos);
    }

    if (bScriptHash)
    {
        scriptPubKey = GetScriptForDestination(CScriptID(scriptPubKey));
    }

    // construct TxOut, append to transaction output list
    CTxOut txout(value, scriptPubKey);
    tx.vout.push_back(txout);
}

static void MutateTxDelInput(CMutableTransaction &tx, const string &strInIdx)
{
    // parse requested deletion index
    int inIdx = atoi(strInIdx);
    if (inIdx < 0 || inIdx >= (int)tx.vin.size())
    {
        string strErr = "Invalid TX input index '" + strInIdx + "'";
        throw runtime_error(strErr.c_str());
    }

    // delete input from transaction
    tx.vin.erase(tx.vin.begin() + inIdx);
}

static void MutateTxDelOutput(CMutableTransaction &tx, const string &strOutIdx)
{
    // parse requested deletion index
    int outIdx = atoi(strOutIdx);
    if (outIdx < 0 || outIdx >= (int)tx.vout.size())
    {
        string strErr = "Invalid TX output index '" + strOutIdx + "'";
        throw runtime_error(strErr.c_str());
    }

    // delete output from transaction
    tx.vout.erase(tx.vout.begin() + outIdx);
}


static bool findSighashFlags(int &flags, const string &flagStr)
{
    flags = 0;

    std::vector<string> strings;
    std::istringstream ss(flagStr);
    std::string s;
    while (getline(ss, s, '|'))
    {
        boost::trim(s);
        if (boost::iequals(s, "ALL"))
            flags = SIGHASH_ALL;
        else if (boost::iequals(s, "NONE"))
            flags = SIGHASH_NONE;
        else if (boost::iequals(s, "SINGLE"))
            flags = SIGHASH_SINGLE;
        else if (boost::iequals(s, "ANYONECANPAY"))
            flags |= SIGHASH_ANYONECANPAY;
        else if (boost::iequals(s, "FORKID"))
            flags |= SIGHASH_FORKID;
        else
        {
            return false;
        }
    }
    return true;
}

uint256 ParseHashUO(map<string, UniValue> &o, string strKey)
{
    if (!o.count(strKey))
        return uint256();
    return ParseHashUV(o[strKey], strKey);
}

vector<unsigned char> ParseHexUO(map<string, UniValue> &o, string strKey)
{
    if (!o.count(strKey))
    {
        vector<unsigned char> emptyVec;
        return emptyVec;
    }
    return ParseHexUV(o[strKey], strKey);
}

static CAmount AmountFromValue(const UniValue &value)
{
    if (!value.isNum() && !value.isStr())
        throw std::runtime_error("Amount is not a number or string");
    CAmount amount;
    if (!ParseFixedPoint(value.getValStr(), 8, &amount))
        throw std::runtime_error("Invalid amount");
    if (!MoneyRange(amount))
        throw std::runtime_error("Amount out of range");
    return amount;
}

static void MutateTxSign(CMutableTransaction &tx, const string &flagStr)
{
    int nHashType = SIGHASH_ALL;

    if (flagStr.size() > 0)
        if (!findSighashFlags(nHashType, flagStr))
            throw runtime_error("unknown sighash flag/sign option");

    vector<CTransaction> txVariants;
    txVariants.push_back(tx);

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the raw tx:
    CMutableTransaction mergedTx(txVariants[0]);
    bool fComplete = true;
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);

    if (!registers.count("privatekeys"))
        throw runtime_error("privatekeys register variable must be set.");
    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    UniValue keysObj = registers["privatekeys"];
    fGivenKeys = true;

    for (unsigned int kidx = 0; kidx < keysObj.size(); kidx++)
    {
        if (!keysObj[kidx].isStr())
            throw runtime_error("privatekey not a string");
        CBitcoinSecret vchSecret;
        bool fGood = vchSecret.SetString(keysObj[kidx].getValStr());
        if (!fGood)
            throw runtime_error("privatekey not valid");

        CKey key = vchSecret.GetKey();
        tempKeystore.AddKey(key);
    }

    // Add previous txouts given in the RPC call:
    if (!registers.count("prevtxs"))
        throw runtime_error("prevtxs register variable must be set.");
    UniValue prevtxsObj = registers["prevtxs"];
    {
        for (unsigned int previdx = 0; previdx < prevtxsObj.size(); previdx++)
        {
            UniValue prevOut = prevtxsObj[previdx];
            if (!prevOut.isObject())
                throw runtime_error("expected prevtxs internal object");

            map<string, UniValue::VType> types = boost::assign::map_list_of("txid", UniValue::VSTR)(
                "vout", UniValue::VNUM)("scriptPubKey", UniValue::VSTR);
            if (!prevOut.checkObject(types))
                throw runtime_error("prevtxs internal object typecheck fail");

            uint256 txid = ParseHashUV(prevOut["txid"], "txid");

            int nOut = atoi(prevOut["vout"].getValStr());
            if (nOut < 0)
                throw runtime_error("vout must be positive");

            COutPoint out(txid, nOut);
            std::vector<unsigned char> pkData(ParseHexUV(prevOut["scriptPubKey"], "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            Coin newcoin;
            {
                CoinAccessor coin(view, out);
                if (!coin->IsSpent() && coin->out.scriptPubKey != scriptPubKey)
                {
                    std::string err("Previous output scriptPubKey mismatch:\n");
                    err = err + ScriptToAsmStr(coin->out.scriptPubKey) + "\nvs:\n" + ScriptToAsmStr(scriptPubKey);
                    throw runtime_error(err);
                }

                newcoin.out.scriptPubKey = scriptPubKey;
                newcoin.out.nValue = 0;
                if (prevOut.exists("amount"))
                {
                    newcoin.out.nValue = AmountFromValue(prevOut["amount"]);
                }
                newcoin.nHeight = 1;
            }
            view.AddCoin(out, std::move(newcoin), true);

            // if redeemScript given and private keys given,
            // add redeemScript to the tempKeystore so it can be signed:
            if (fGivenKeys && scriptPubKey.IsPayToScriptHash() && prevOut.exists("redeemScript"))
            {
                UniValue v = prevOut["redeemScript"];
                vector<unsigned char> rsData(ParseHexUV(v, "redeemScript"));
                CScript redeemScript(rsData.begin(), rsData.end());
                tempKeystore.AddCScript(redeemScript);
            }
        }
    }

    const CKeyStore &keystore = tempKeystore;

    bool fHashSingle = ((nHashType & ~(SIGHASH_ANYONECANPAY | SIGHASH_FORKID)) == SIGHASH_SINGLE);

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++)
    {
        CTxIn &txin = mergedTx.vin[i];
        CoinModifier coin(view, txin.prevout);
        if (coin->IsSpent())
        {
            fComplete = false;
            continue;
        }
        const CScript &prevPubKey = coin->out.scriptPubKey;
        const CAmount &amount = coin->out.nValue;

        txin.scriptSig.clear();
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
            SignSignature(keystore, prevPubKey, mergedTx, i, amount, nHashType);

        // ... and merge in other signatures:
        for (const CTransaction &txv : txVariants)
        {
            txin.scriptSig = CombineSignatures(prevPubKey, MutableTransactionSignatureChecker(&mergedTx, i, amount),
                txin.scriptSig, txv.vin[i].scriptSig);
        }

        // Nothing we are capable of signing can be more than the original 201 ops so using it is fine.
        if (!VerifyScript(txin.scriptSig, prevPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, MAX_OPS_PER_SCRIPT,
                MutableTransactionSignatureChecker(&mergedTx, i, amount)))
            fComplete = false;
    }

    if (fComplete)
    {
        // do nothing... for now
        // perhaps store this for later optional JSON output
    }

    tx = mergedTx;
}

class Secp256k1Init
{
    ECCVerifyHandle globalVerifyHandle;

public:
    Secp256k1Init() { ECC_Start(); }
    ~Secp256k1Init() { ECC_Stop(); }
};

static void MutateTx(CMutableTransaction &tx, const string &command, const string &commandVal)
{
    std::unique_ptr<Secp256k1Init> ecc;

    if (command == "nversion")
        MutateTxVersion(tx, commandVal);
    else if (command == "locktime")
        MutateTxLocktime(tx, commandVal);

    else if (command == "delin")
        MutateTxDelInput(tx, commandVal);
    else if (command == "in")
        MutateTxAddInput(tx, commandVal);

    else if (command == "delout")
        MutateTxDelOutput(tx, commandVal);
    else if (command == "outaddr")
        MutateTxAddOutAddr(tx, commandVal);
    else if (command == "outdata")
        MutateTxAddOutData(tx, commandVal);
    else if (command == "outscript")
        MutateTxAddOutScript(tx, commandVal);

    else if (command == "sign")
    {
        ecc.reset(new Secp256k1Init());
        MutateTxSign(tx, commandVal);
    }

    else if (command == "load")
        RegisterLoad(commandVal);

    else if (command == "set")
        RegisterSet(commandVal);

    else
        throw runtime_error("unknown command");
}

static void OutputTxJSON(const CTransaction &tx)
{
    UniValue entry(UniValue::VOBJ);
    TxToUniv(tx, uint256(), entry);

    string jsonOutput = entry.write(4);
    fprintf(stdout, "%s\n", jsonOutput.c_str());
}

static void OutputTxHash(const CTransaction &tx)
{
    string strHexHash = tx.GetHash().GetHex(); // the hex-encoded transaction hash (aka the transaction id)

    fprintf(stdout, "%s\n", strHexHash.c_str());
}

static void OutputTxHex(const CTransaction &tx)
{
    string strHex = EncodeHexTx(tx);

    fprintf(stdout, "%s\n", strHex.c_str());
}

static void OutputTx(const CTransaction &tx)
{
    if (GetBoolArg("-json", false))
        OutputTxJSON(tx);
    else if (GetBoolArg("-txid", false))
        OutputTxHash(tx);
    else
        OutputTxHex(tx);
}

static string readStdin()
{
    char buf[4096];
    string ret;

    while (!feof(stdin))
    {
        size_t bread = fread(buf, 1, sizeof(buf), stdin);
        ret.append(buf, bread);
        if (bread < sizeof(buf))
            break;
    }

    if (ferror(stdin))
        throw runtime_error("error reading stdin");

    boost::algorithm::trim_right(ret);

    return ret;
}

static int CommandLineRawTx(int argc, char *argv[])
{
    string strPrint;
    int nRet = 0;
    try
    {
        // Skip switches; Permit common stdin convention "-"
        while (argc > 1 && IsSwitchChar(argv[1][0]) && (argv[1][1] != 0))
        {
            argc--;
            argv++;
        }

        CTransaction txDecodeTmp;
        int startArg;

        if (!fCreateBlank)
        {
            // require at least one param
            if (argc < 2)
                throw runtime_error("too few parameters");

            // param: hex-encoded member transaction
            string strHexTx(argv[1]);
            if (strHexTx == "-") // "-" implies standard input
                strHexTx = readStdin();

            if (!DecodeHexTx(txDecodeTmp, strHexTx))
                throw runtime_error("invalid transaction encoding");

            startArg = 2;
        }
        else
            startArg = 1;

        CMutableTransaction tx(txDecodeTmp);

        for (int i = startArg; i < argc; i++)
        {
            string arg = argv[i];
            string key, value;
            size_t eqpos = arg.find('=');
            if (eqpos == string::npos)
                key = arg;
            else
            {
                key = arg.substr(0, eqpos);
                value = arg.substr(eqpos + 1);
            }

            MutateTx(tx, key, value);
        }

        OutputTx(tx);
    }

    catch (const boost::thread_interrupted &)
    {
        throw;
    }
    catch (const std::exception &e)
    {
        strPrint = string("error: ") + e.what();
        nRet = EXIT_FAILURE;
    }
    catch (...)
    {
        PrintExceptionContinue(nullptr, "CommandLineRawTx()");
        throw;
    }

    if (strPrint != "")
    {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }
    return nRet;
}

int main(int argc, char *argv[])
{
    SetupEnvironment();

    try
    {
        int ret = AppInitRawTx(argc, argv);
        if (ret != CONTINUE_EXECUTION)
            return ret;
    }
    catch (const std::exception &e)
    {
        PrintExceptionContinue(&e, "AppInitRawTx()");
        return EXIT_FAILURE;
    }
    catch (...)
    {
        PrintExceptionContinue(nullptr, "AppInitRawTx()");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    try
    {
        ret = CommandLineRawTx(argc, argv);
    }
    catch (const std::exception &e)
    {
        PrintExceptionContinue(&e, "CommandLineRawTx()");
    }
    catch (...)
    {
        PrintExceptionContinue(nullptr, "CommandLineRawTx()");
    }
    return ret;
}
