//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2012, 2013 Ripple Labs Inc.

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


#include <ripple/basics/Log.h>
#include <ripple/protocol/digest.h>
#include <ripple/app/main/Application.h>
#include <ripple/app/main/DBInit.h>
#include <ripple/basics/contract.h>
#include <ripple/basics/StringUtilities.h>
#include <ripple/basics/Sustain.h>
#include <ripple/core/Config.h>
#include <ripple/core/ConfigSections.h>
#include <ripple/core/DatabaseCon.h>
#include <ripple/core/TimeKeeper.h>
#include <ripple/json/to_string.h>
#include <ripple/net/RPCCall.h>
#include <ripple/resource/Fees.h>
#include <ripple/rpc/RPCHandler.h>
#include <ripple/protocol/BuildInfo.h>
#include <ripple/beast/clock/basic_seconds_clock.h>
#include <ripple/beast/core/CurrentThreadName.h>

#include <google/protobuf/stubs/common.h>

#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <boost/program_options.hpp>
#include <boost/system/error_code.hpp>
#include <boost/version.hpp>

#include <cstdlib>
#include <iostream>
#include <utility>
#include <stdexcept>

#ifdef _MSC_VER
#include <sys/types.h>
#include <sys/timeb.h>
#endif

namespace po = boost::program_options;

namespace ripple {

bool
adjustDescriptorLimit(int needed, beast::Journal j)
{
#ifdef RLIMIT_NOFILE
    // Get the current limit, then adjust it to what we need.
    struct rlimit rl;

    int available = 0;

    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
    {
        // If the limit is infinite, then we are good.
        if (rl.rlim_cur == RLIM_INFINITY)
            available = needed;
        else
            available = rl.rlim_cur;

        if (available < needed)
        {
            // Ignore the rlim_max, as the process may
            // be configured to override it anyways. We
            // ask for the number descriptors we need.
            rl.rlim_cur = needed;

            if (setrlimit(RLIMIT_NOFILE, &rl) == 0)
                available = rl.rlim_cur;
        }
    }

    if (needed > available)
    {
        j.fatal() <<
            "Insufficient number of file descriptors: " <<
            needed << " are needed, but only " <<
            available << " are available.";

        std::cerr <<
            "Insufficient number of file descriptors: " <<
            needed << " are needed, but only " <<
            available << " are available.\n";

        return false;
    }
#endif

    return true;
}

void printHelp (const po::options_description& desc)
{
    std::cerr
        << systemName () << "d [options] <command> <params>\n"
        << desc << std::endl
        << "Commands: \n"
           "     account_currencies <account> [<ledger>] [strict]\n"
           "     account_info <account>|<seed>|<pass_phrase>|<key> [<ledger>] [strict]\n"
           "     account_lines <account> <account>|\"\" [<ledger>]\n"
           "     account_channels <account> <account>|\"\" [<ledger>]\n"
           "     account_objects <account> [<ledger>] [strict]\n"
           "     account_offers <account>|<account_public_key> [<ledger>]\n"
           "     account_tx accountID [ledger_min [ledger_max [limit [offset]]]] [binary] [count] [descending]\n"
           "     book_offers <taker_pays> <taker_gets> [<taker [<ledger> [<limit> [<proof> [<marker>]]]]]\n"
           "     can_delete [<ledgerid>|<ledgerhash>|now|always|never]\n"
           "     channel_authorize <private_key> <channel_id> <drops>\n"
           "     channel_verify <public_key> <channel_id> <drops> <signature>\n"
           "     connect <ip> [<port>]\n"
           "     consensus_info\n"
           "     deposit_authorized <source_account> <destination_account> [<ledger>]\n"
           "     download_shard [[<index> <url>]] <validate>\n"
           "     feature [<feature> [accept|reject]]\n"
           "     fetch_info [clear]\n"
           "     gateway_balances [<ledger>] <issuer_account> [ <hotwallet> [ <hotwallet> ]]\n"
           "     get_counts\n"
           "     json <method> <json>\n"
           "     ledger [<id>|current|closed|validated] [full]\n"
           "     ledger_accept\n"
           "     ledger_closed\n"
           "     ledger_current\n"
           "     ledger_request <ledger>\n"
           "     log_level [[<partition>] <severity>]\n"
           "     logrotate \n"
           "     peers\n"
           "     ping\n"
           "     random\n"
           "     peer_reservations_add <public_key> [<description>]\n"
           "     peer_reservations_del <public_key>\n"
           "     peer_reservations_list\n"
           "     ripple ...\n"
           "     ripple_path_find <json> [<ledger>]\n"
           "     server_info [counters]\n"
           "     server_state [counters]\n"
           "     sign <private_key> <tx_json> [offline]\n"
           "     sign_for <signer_address> <signer_private_key> <tx_json> [offline]\n"
           "     stop\n"
           "     submit <tx_blob>|[<private_key> <tx_json>]\n"
           "     submit_multisigned <tx_json>\n"
           "     tx <id>\n"
           "     validation_create [<seed>|<pass_phrase>|<key>]\n"
           "     validators\n"
           "     validator_list_sites\n"
           "     version\n"
           "     wallet_propose [<passphrase>]\n";
}

//------------------------------------------------------------------------------

int run (int argc, char** argv)
{
    using namespace std;

    beast::setCurrentThreadName ("rippled: main");

    po::variables_map vm;

    std::string importText;
    {
        importText += "Import an existing node database (specified in the [";
        importText += ConfigSection::importNodeDatabase ();
        importText += "] configuration file section) into the current ";
        importText += "node database (specified in the [";
        importText += ConfigSection::nodeDatabase ();
        importText += "] configuration file section).";
    }
    std::string shardsText;
    {
        shardsText += "Validate an existing shard database (specified in the [";
        shardsText += ConfigSection::shardDatabase();
        shardsText += "] configuration file section).";
    }

    // Set up option parsing.
    //
    po::options_description gen ("General Options");
    gen.add_options ()
    ("conf", po::value<std::string> (), "Specify the configuration file.")
    ("debug", "Enable normally suppressed debug logging")
    ("fg", "Run in the foreground.")
    ("help,h", "Display this message.")
    ("quorum", po::value <std::size_t> (),
        "Override the minimum validation quorum.")
    ("silent", "No output to the console after startup.")
    ("standalone,a", "Run with no peers.")
    ("verbose,v", "Verbose logging.")
    ("version", "Display the build version.")
    ;

    po::options_description data ("Ledger/Data Options");
    data.add_options ()
    ("import", importText.c_str ())
    ("ledger", po::value<std::string> (),
        "Load the specified ledger and start from the value given.")
    ("ledgerfile", po::value<std::string> (), "Load the specified ledger file.")
    ("load", "Load the current ledger from the local DB.")
    ("net", "Get the initial ledger from the network.")
    ("nodetoshard", "Import node store into shards")
    ("replay","Replay a ledger close.")
    ("start", "Start from a fresh Ledger.")
    ("vacuum", po::value<std::string>(),
        "VACUUM the transaction db. Mandatory string argument specifies "
        "temporary directory path.")
    ("valid", "Consider the initial ledger a valid network ledger.")
    ("validateShards", shardsText.c_str ())
    ;

    po::options_description rpc ("RPC Client Options");
    rpc.add_options()
    ("rpc",
        "Perform rpc command - see below for available commands. "
        "This is assumed if any positional parameters are provided.")
    ("rpc_ip", po::value <std::string> (),
        "Specify the IP address for RPC command. "
        "Format: <ip-address>[':'<port-number>]")
    ("rpc_port", po::value <std::uint16_t> (),
        "DEPRECATED: include with rpc_ip instead. "
        "Specify the port number for RPC command.")
    ;

    // These are hidden options, not intended to be shown in the usage/help message
    po::options_description hidden ("Hidden Options");
    hidden.add_options()
    ("parameters", po::value< vector<string> > (),
        "Specify rpc command and parameters. This option must be repeated "
        "for each command/param. Positional parameters also serve this purpose, "
        "so this option is not needed for users")
    ;

    // Interpret positional arguments as --parameters.
    po::positional_options_description p;
    p.add ("parameters", -1);

    po::options_description all;
    all.add(gen).add(rpc).add(data).add(hidden);

    po::options_description desc;
    desc.add(gen).add(rpc).add(data);

    // Parse options, if no error.
    try
    {
        po::store (po::command_line_parser (argc, argv)
            .options (all)                // Parse options.
            .positional (p)               // Remainder as --parameters.
            .run (),
            vm);
        po::notify (vm);                  // Invoke option notify functions.
    }
    catch (std::exception const&)
    {
        std::cerr << "rippled: Incorrect command line syntax." << std::endl;
        std::cerr << "Use '--help' for a list of options." << std::endl;
        return 1;
    }

    if (vm.count ("help"))
    {
        printHelp (desc);
        return 0;
    }

    if (vm.count ("version"))
    {
        std::cout << "rippled version " <<
            BuildInfo::getVersionString () << std::endl;
        return 0;
    }

    auto config = std::make_unique<Config>();

    auto configFile = vm.count ("conf") ?
            vm["conf"].as<std::string> () : std::string();

    // config file, quiet flag.
    config->setup (configFile, bool (vm.count ("quiet")),
        bool(vm.count("silent")), bool(vm.count("standalone")));

    if (vm.count("vacuum"))
    {
        if (config->standalone())
        {
            std::cerr << "vacuum not applicable in standalone mode.\n";
            return -1;
        }

        using namespace boost::filesystem;
        DatabaseCon::Setup dbSetup = setup_DatabaseCon(*config);
        path dbPath = dbSetup.dataDir / TxDBName;
        path tmpPath = vm["vacuum"].as<std::string>();

        try
        {
            uintmax_t const dbSize = file_size(dbPath);
            assert(dbSize != static_cast<uintmax_t>(-1));

            if (space(tmpPath).available < dbSize)
            {
                std::cerr << "A valid directory for vacuuming must be "
                             "specified on a filesystem with at least "
                             "as much free space as the size of "
                          << dbPath.string() << ", which is " << dbSize
                          << " bytes. The filesystem for " << tmpPath.string()
                          << " only has "
                          << space(tmpPath).available
                          << " bytes.\n";
                return -1;
            }

            auto txnDB = std::make_unique<DatabaseCon>(
                dbSetup, TxDBName, TxDBPragma, TxDBInit);
            auto& session = txnDB->getSession();
            std::uint32_t pageSize;

            session << "PRAGMA page_size;", soci::into(pageSize);

            std::cout << "VACUUM beginning. page_size: " <<
                pageSize << std::endl;

            session << "PRAGMA journal_mode=OFF;";
            session << "PRAGMA temp_store_directory=\"" <<
                tmpPath.string() << "\";";
            session << "VACUUM;";
            session << "PRAGMA journal_mode=WAL;";
            session << "PRAGMA page_size;", soci::into(pageSize);

            std::cout << "VACUUM finished. page_size: " <<
                pageSize << std::endl;
        }
        catch (std::exception const& e)
        {
            std::cerr << "exception " << e.what() <<
                " in function " << __func__ << std::endl;
            return -1;
        }

        return 0;
    }

    if (vm.count ("start"))
        config->START_UP = Config::FRESH;

    if (vm.count ("import"))
        config->doImport = true;

    if (vm.count("nodetoshard"))
        config->nodeToShard = true;

    if (vm.count ("validateShards"))
        config->validateShards = true;

    if (vm.count ("ledger"))
    {
        config->START_LEDGER = vm["ledger"].as<std::string> ();
        if (vm.count("replay"))
            config->START_UP = Config::REPLAY;
        else
            config->START_UP = Config::LOAD;
    }
    else if (vm.count ("ledgerfile"))
    {
        config->START_LEDGER = vm["ledgerfile"].as<std::string> ();
        config->START_UP = Config::LOAD_FILE;
    }
    else if (vm.count ("load"))
    {
        config->START_UP = Config::LOAD;
    }

    if (vm.count ("valid"))
    {
        config->START_VALID = true;
    }

    if (vm.count ("net"))
    {
        if ((config->START_UP == Config::LOAD) ||
            (config->START_UP == Config::REPLAY))
        {
            std::cerr <<
                "Net and load/reply options are incompatible" << std::endl;
            return -1;
        }

        config->START_UP = Config::NETWORK;
    }

    // Override the RPC destination IP address. This must
    // happen after the config file is loaded.
    if (vm.count ("rpc_ip"))
    {
        auto endpoint = beast::IP::Endpoint::from_string_checked(
            vm["rpc_ip"].as<std::string>());
        if (! endpoint)
        {
            std::cerr << "Invalid rpc_ip = " <<
                vm["rpc_ip"].as<std::string>() << "\n";
            return -1;
        }

        if (endpoint->port() == 0)
        {
            std::cerr << "No port specified in rpc_ip.\n";
            if (vm.count ("rpc_port"))
            {
                std::cerr << "WARNING: using deprecated rpc_port param.\n";
                try
                {
                    endpoint = endpoint->at_port(
                        vm["rpc_port"].as<std::uint16_t>());
                    if (endpoint->port() == 0)
                        throw std::domain_error("0");
                }
                catch(std::exception const& e)
                {
                    std::cerr << "Invalid rpc_port = " << e.what() << "\n";
                    return -1;
                }
            }
            else
                return -1;
        }

        config->rpc_ip = std::move(*endpoint);
    }

    if (vm.count ("quorum"))
    {
        try
        {
            config->VALIDATION_QUORUM = vm["quorum"].as <std::size_t> ();
            if (config->VALIDATION_QUORUM == std::size_t{})
            {
                throw std::domain_error("0");
            }
        }
        catch(std::exception const& e)
        {
            std::cerr << "Invalid value specified for --quorum ("
                      << e.what() << ")\n";
            return -1;
        }
    }

    // Construct the logs object at the configured severity
    using namespace beast::severities;
    Severity thresh = kInfo;

    if (vm.count ("quiet"))
        thresh = kFatal;
    else if (vm.count ("verbose"))
        thresh = kTrace;

    auto logs = std::make_unique<Logs>(thresh);

    // No arguments. Run server.
    if (!vm.count ("parameters"))
    {
        // We want at least 1024 file descriptors. We'll
        // tweak this further.
        if (!adjustDescriptorLimit(1024, logs->journal("Application")))
            return -1;

        if (HaveSustain() && !vm.count ("fg") && !config->standalone())
        {
            auto const ret = DoSustain ();

            if (!ret.empty ())
                std::cerr << "Watchdog: " << ret << std::endl;
        }

        if (vm.count ("debug"))
        {
            setDebugLogSink (logs->makeSink (
                "Debug", beast::severities::kTrace));
        }

        auto timeKeeper = make_TimeKeeper(
            logs->journal("TimeKeeper"));

        auto app = make_Application(
            std::move(config),
            std::move(logs),
            std::move(timeKeeper));

        if (!app->setup ())
        {
            StopSustain();
            return -1;
        }

        // With our configuration parsed, ensure we have
        // enough file descriptors available:
        if (!adjustDescriptorLimit(
            app->fdRequired(),
            app->logs().journal("Application")))
        {
            StopSustain();
            return -1;
        }

        // Start the server
        app->doStart(true /*start timers*/);

        // Block until we get a stop RPC.
        app->run();

        return 0;
    }

    // We have an RPC command to process:
    beast::setCurrentThreadName ("rippled: rpc");
    return RPCCall::fromCommandLine (
        *config,
        vm["parameters"].as<std::vector<std::string>>(),
        *logs);
}

} // ripple

// Must be outside the namespace for obvious reasons
//
int main (int argc, char** argv)
{
#ifdef _MSC_VER
    {
        // Work around for https://svn.boost.org/trac/boost/ticket/10657
        // Reported against boost version 1.56.0.  If an application's
        // first call to GetTimeZoneInformation is from a coroutine, an
        // unhandled exception is generated.  A workaround is to call
        // GetTimeZoneInformation at least once before launching any
        // coroutines.  At the time of this writing the _ftime call is
        // used to initialize the timezone information.
        struct _timeb t;
    #ifdef _INC_TIME_INL
            _ftime_s (&t);
    #else
            _ftime (&t);
    #endif
    }
    ripple::sha512_deprecatedMSVCWorkaround();
#endif

    atexit(&google::protobuf::ShutdownProtobufLibrary);

    auto const result (ripple::run (argc, argv));

    beast::basic_seconds_clock_main_hook();

    return result;
}
