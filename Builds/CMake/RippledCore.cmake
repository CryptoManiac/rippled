#[===================================================================[
   xrpl_core
   core functionality, useable by some client software perhaps
#]===================================================================]

file (GLOB_RECURSE rb_headers
  src/ripple/beast/*.h
  src/ripple/beast/*.hpp)

add_library (xrpl_core
  ${rb_headers}) ## headers added here for benefit of IDEs

#[===============================[
    beast/legacy FILES:
    TODO: review these sources for removal or replacement
#]===============================]
if (unity)
  target_sources (xrpl_core PRIVATE
    src/ripple/beast/core/core.unity.cpp
    src/ripple/beast/unity/beast_hash_unity.cpp
    src/ripple/beast/unity/beast_insight_unity.cpp
    src/ripple/beast/unity/beast_net_unity.cpp
    src/ripple/beast/unity/beast_utility_unity.cpp)
else ()
  target_sources (xrpl_core PRIVATE
    src/ripple/beast/core/CurrentThreadName.cpp
    src/ripple/beast/core/SemanticVersion.cpp
    src/ripple/beast/hash/impl/xxhash.cpp
    src/ripple/beast/insight/impl/Collector.cpp
    src/ripple/beast/insight/impl/Groups.cpp
    src/ripple/beast/insight/impl/Hook.cpp
    src/ripple/beast/insight/impl/Metric.cpp
    src/ripple/beast/insight/impl/NullCollector.cpp
    src/ripple/beast/insight/impl/StatsDCollector.cpp
    src/ripple/beast/net/impl/IPAddressConversion.cpp
    src/ripple/beast/net/impl/IPAddressV4.cpp
    src/ripple/beast/net/impl/IPAddressV6.cpp
    src/ripple/beast/net/impl/IPEndpoint.cpp
    src/ripple/beast/utility/src/beast_Journal.cpp
    src/ripple/beast/utility/src/beast_PropertyStream.cpp)
endif ()

#[===============================[
    core sources
#]===============================]
if (unity)
  target_sources (xrpl_core PRIVATE
    src/ripple/unity/basics1.cpp
    src/ripple/unity/json.cpp
    src/ripple/unity/protocol.cpp
    src/ripple/unity/crypto.cpp)
else ()
  target_sources (xrpl_core PRIVATE
    #[===============================[
      nounity, main sources:
        subdir: basics (partial)
    #]===============================]
    src/ripple/basics/impl/base64.cpp
    src/ripple/basics/impl/contract.cpp
    src/ripple/basics/impl/CountedObject.cpp
    src/ripple/basics/impl/FileUtilities.cpp
    src/ripple/basics/impl/Log.cpp
    src/ripple/basics/impl/strHex.cpp
    src/ripple/basics/impl/StringUtilities.cpp
    #[===============================[
      nounity, main sources:
        subdir: json
    #]===============================]
    src/ripple/json/impl/JsonPropertyStream.cpp
    src/ripple/json/impl/Object.cpp
    src/ripple/json/impl/Output.cpp
    src/ripple/json/impl/Writer.cpp
    src/ripple/json/impl/json_reader.cpp
    src/ripple/json/impl/json_value.cpp
    src/ripple/json/impl/json_valueiterator.cpp
    src/ripple/json/impl/json_writer.cpp
    src/ripple/json/impl/to_string.cpp
    #[===============================[
      nounity, main sources:
        subdir: protocol
    #]===============================]
    src/ripple/protocol/impl/AccountID.cpp
    src/ripple/protocol/impl/Book.cpp
    src/ripple/protocol/impl/BuildInfo.cpp
    src/ripple/protocol/impl/ErrorCodes.cpp
    src/ripple/protocol/impl/Feature.cpp
    src/ripple/protocol/impl/HashPrefix.cpp
    src/ripple/protocol/impl/IOUAmount.cpp
    src/ripple/protocol/impl/Indexes.cpp
    src/ripple/protocol/impl/InnerObjectFormats.cpp
    src/ripple/protocol/impl/Issue.cpp
    src/ripple/protocol/impl/Keylet.cpp
    src/ripple/protocol/impl/LedgerFormats.cpp
    src/ripple/protocol/impl/PublicKey.cpp
    src/ripple/protocol/impl/Quality.cpp
    src/ripple/protocol/impl/Rate2.cpp
    src/ripple/protocol/impl/SField.cpp
    src/ripple/protocol/impl/SOTemplate.cpp
    src/ripple/protocol/impl/STAccount.cpp
    src/ripple/protocol/impl/STAmount.cpp
    src/ripple/protocol/impl/STArray.cpp
    src/ripple/protocol/impl/STBase.cpp
    src/ripple/protocol/impl/STBlob.cpp
    src/ripple/protocol/impl/STInteger.cpp
    src/ripple/protocol/impl/STLedgerEntry.cpp
    src/ripple/protocol/impl/STObject.cpp
    src/ripple/protocol/impl/STParsedJSON.cpp
    src/ripple/protocol/impl/STPathSet.cpp
    src/ripple/protocol/impl/STTx.cpp
    src/ripple/protocol/impl/STValidation.cpp
    src/ripple/protocol/impl/STVar.cpp
    src/ripple/protocol/impl/STVector256.cpp
    src/ripple/protocol/impl/SecretKey.cpp
    src/ripple/protocol/impl/Seed.cpp
    src/ripple/protocol/impl/Serializer.cpp
    src/ripple/protocol/impl/Sign.cpp
    src/ripple/protocol/impl/TER.cpp
    src/ripple/protocol/impl/TxFormats.cpp
    src/ripple/protocol/impl/UintTypes.cpp
    src/ripple/protocol/impl/digest.cpp
    src/ripple/protocol/impl/tokens.cpp
    #[===============================[
      nounity, main sources:
        subdir: crypto
    #]===============================]
    src/ripple/crypto/impl/GenerateDeterministicKey.cpp
    src/ripple/crypto/impl/RFC1751.cpp
    src/ripple/crypto/impl/csprng.cpp
    src/ripple/crypto/impl/ec_key.cpp
    src/ripple/crypto/impl/openssl.cpp)
endif ()
add_library (Ripple::xrpl_core ALIAS xrpl_core)
target_include_directories (xrpl_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/ripple>
    # this one is for beast/legacy files:
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/beast/extras>
    $<INSTALL_INTERFACE:include>)
target_compile_options (xrpl_core
  PUBLIC
    $<$<BOOL:${is_gcc}>:-Wno-maybe-uninitialized>)
target_link_libraries (xrpl_core
  PUBLIC
    OpenSSL::Crypto
    NIH::secp256k1
    Ripple::syslibs
    Ripple::boost
    Ripple::opts)
#[=================================[
   main/core headers installation
#]=================================]
install (
  FILES
    src/ripple/basics/base64.h
    src/ripple/basics/Blob.h
    src/ripple/basics/Buffer.h
    src/ripple/basics/CountedObject.h
    src/ripple/basics/FileUtilities.h
    src/ripple/basics/LocalValue.h
    src/ripple/basics/Log.h
    src/ripple/basics/safe_cast.h
    src/ripple/basics/Slice.h
    src/ripple/basics/StringUtilities.h
    src/ripple/basics/ToString.h
    src/ripple/basics/UnorderedContainers.h
    src/ripple/basics/algorithm.h
    src/ripple/basics/base_uint.h
    src/ripple/basics/chrono.h
    src/ripple/basics/contract.h
    src/ripple/basics/date.h
    src/ripple/basics/hardened_hash.h
    src/ripple/basics/strHex.h
  DESTINATION include/ripple/basics)
install (
  FILES
    src/ripple/crypto/GenerateDeterministicKey.h
    src/ripple/crypto/RFC1751.h
    src/ripple/crypto/csprng.h
  DESTINATION include/ripple/crypto)
install (
  FILES
    src/ripple/crypto/impl/ec_key.h
    src/ripple/crypto/impl/openssl.h
  DESTINATION include/ripple/crypto/impl)
install (
  FILES
    src/ripple/json/JsonPropertyStream.h
    src/ripple/json/Object.h
    src/ripple/json/Output.h
    src/ripple/json/Writer.h
    src/ripple/json/json_forwards.h
    src/ripple/json/json_reader.h
    src/ripple/json/json_value.h
    src/ripple/json/json_writer.h
    src/ripple/json/to_string.h
  DESTINATION include/ripple/json)
install (
  FILES
    src/ripple/json/impl/json_assert.h
  DESTINATION include/ripple/json/impl)
install (
  FILES
    src/ripple/protocol/AccountID.h
    src/ripple/protocol/AmountConversions.h
    src/ripple/protocol/Book.h
    src/ripple/protocol/BuildInfo.h
    src/ripple/protocol/ErrorCodes.h
    src/ripple/protocol/Feature.h
    src/ripple/protocol/HashPrefix.h
    src/ripple/protocol/IOUAmount.h
    src/ripple/protocol/Indexes.h
    src/ripple/protocol/InnerObjectFormats.h
    src/ripple/protocol/Issue.h
    src/ripple/protocol/Keylet.h
    src/ripple/protocol/KnownFormats.h
    src/ripple/protocol/LedgerFormats.h
    src/ripple/protocol/Protocol.h
    src/ripple/protocol/PublicKey.h
    src/ripple/protocol/Quality.h
    src/ripple/protocol/Rate.h
    src/ripple/protocol/SField.h
    src/ripple/protocol/SOTemplate.h
    src/ripple/protocol/STAccount.h
    src/ripple/protocol/STAmount.h
    src/ripple/protocol/STArray.h
    src/ripple/protocol/STBase.h
    src/ripple/protocol/STBitString.h
    src/ripple/protocol/STBlob.h
    src/ripple/protocol/STExchange.h
    src/ripple/protocol/STInteger.h
    src/ripple/protocol/STLedgerEntry.h
    src/ripple/protocol/STObject.h
    src/ripple/protocol/STParsedJSON.h
    src/ripple/protocol/STPathSet.h
    src/ripple/protocol/STTx.h
    src/ripple/protocol/STValidation.h
    src/ripple/protocol/STVector256.h
    src/ripple/protocol/SecretKey.h
    src/ripple/protocol/Seed.h
    src/ripple/protocol/Serializer.h
    src/ripple/protocol/Sign.h
    src/ripple/protocol/SystemParameters.h
    src/ripple/protocol/TER.h
    src/ripple/protocol/TxFlags.h
    src/ripple/protocol/TxFormats.h
    src/ripple/protocol/UintTypes.h
    src/ripple/protocol/XRPAmount.h
    src/ripple/protocol/digest.h
    src/ripple/protocol/jss.h
    src/ripple/protocol/tokens.h
  DESTINATION include/ripple/protocol)
install (
  FILES
    src/ripple/protocol/impl/STVar.h
    src/ripple/protocol/impl/secp256k1.h
  DESTINATION include/ripple/protocol/impl)

#[===================================[
   beast/legacy headers installation
#]===================================]
install (
  FILES
    src/ripple/beast/clock/abstract_clock.h
    src/ripple/beast/clock/basic_seconds_clock.h
    src/ripple/beast/clock/manual_clock.h
  DESTINATION include/ripple/beast/clock)
install (
  FILES
    src/ripple/beast/core/Config.h
    src/ripple/beast/core/ConfigCheck.h
    src/ripple/beast/core/LexicalCast.h
    src/ripple/beast/core/List.h
    src/ripple/beast/core/PlatformConfig.h
    src/ripple/beast/core/SemanticVersion.h
    src/ripple/beast/core/StandardConfig.h
  DESTINATION include/ripple/beast/core)
install (
  FILES
    src/ripple/beast/crypto/detail/mac_facade.h
    src/ripple/beast/crypto/detail/ripemd_context.h
    src/ripple/beast/crypto/detail/sha2_context.h
    src/ripple/beast/crypto/ripemd.h
    src/ripple/beast/crypto/secure_erase.h
    src/ripple/beast/crypto/sha2.h
  DESTINATION include/ripple/beast/crypto)
install (
  FILES
    src/ripple/beast/cxx17/type_traits.h
  DESTINATION include/ripple/beast/cxx17)
install (
  FILES
    src/ripple/beast/hash/endian.h
    src/ripple/beast/hash/hash_append.h
    src/ripple/beast/hash/meta.h
    src/ripple/beast/hash/uhash.h
    src/ripple/beast/hash/xxhasher.h
  DESTINATION include/ripple/beast/hash)
install (
  FILES src/ripple/beast/hash/impl/xxhash.h
  DESTINATION include/ripple/beast/hash/impl)
install (
  FILES
    src/ripple/beast/rfc2616.h
    src/ripple/beast/type_name.h
    src/ripple/beast/xor_shift_engine.h
  DESTINATION include/ripple/beast)
install (
  FILES
    src/ripple/beast/utility/Journal.h
    src/ripple/beast/utility/PropertyStream.h
    src/ripple/beast/utility/Zero.h
    src/ripple/beast/utility/rngfill.h
  DESTINATION include/ripple/beast/utility)

#[===================================================================[
   rmcd executable
#]===================================================================]

#[=========================================================[
   this one header is added as source just to keep older
   versions of cmake happy. cmake 3.10+ allows
   add_executable with no sources
#]=========================================================]
add_executable (rmcd src/ripple/app/main/Application.h)
if (unity)
  target_sources (rmcd PRIVATE
    #[===============================[
       unity, main sources
    #]===============================]
    src/ripple/unity/app_consensus.cpp
    src/ripple/unity/app_ledger.cpp
    src/ripple/unity/app_ledger_impl.cpp
    src/ripple/unity/app_main1.cpp
    src/ripple/unity/app_main2.cpp
    src/ripple/unity/app_misc.cpp
    src/ripple/unity/app_misc_impl.cpp
    src/ripple/unity/app_paths.cpp
    src/ripple/unity/app_tx.cpp
    src/ripple/unity/conditions.cpp
    src/ripple/unity/consensus.cpp
    src/ripple/unity/core.cpp
    src/ripple/unity/basics2.cpp
    src/ripple/unity/ledger.cpp
    src/ripple/unity/net.cpp
    src/ripple/unity/nodestore.cpp
    src/ripple/unity/overlay1.cpp
    src/ripple/unity/overlay2.cpp
    src/ripple/unity/peerfinder.cpp
    src/ripple/unity/resource.cpp
    src/ripple/unity/rpcx1.cpp
    src/ripple/unity/rpcx2.cpp
    src/ripple/unity/shamap.cpp
    src/ripple/unity/server.cpp
    src/ripple/unity/soci_ripple.cpp)
else ()
  target_sources (rmcd PRIVATE
    #[===============================[
       nounity, main sources:
         subdir: app
    #]===============================]
    src/ripple/app/consensus/RCLConsensus.cpp
    src/ripple/app/consensus/RCLCxPeerPos.cpp
    src/ripple/app/consensus/RCLValidations.cpp
    src/ripple/app/ledger/AcceptedLedger.cpp
    src/ripple/app/ledger/AcceptedLedgerTx.cpp
    src/ripple/app/ledger/AccountStateSF.cpp
    src/ripple/app/ledger/BookListeners.cpp
    src/ripple/app/ledger/ConsensusTransSetSF.cpp
    src/ripple/app/ledger/Ledger.cpp
    src/ripple/app/ledger/LedgerHistory.cpp
    src/ripple/app/ledger/OrderBookDB.cpp
    src/ripple/app/ledger/TransactionStateSF.cpp
    src/ripple/app/ledger/impl/BuildLedger.cpp
    src/ripple/app/ledger/impl/InboundLedger.cpp
    src/ripple/app/ledger/impl/InboundLedgers.cpp
    src/ripple/app/ledger/impl/InboundTransactions.cpp
    src/ripple/app/ledger/impl/LedgerCleaner.cpp
    src/ripple/app/ledger/impl/LedgerMaster.cpp
    src/ripple/app/ledger/impl/LedgerReplay.cpp
    src/ripple/app/ledger/impl/LedgerToJson.cpp
    src/ripple/app/ledger/impl/LocalTxs.cpp
    src/ripple/app/ledger/impl/OpenLedger.cpp
    src/ripple/app/ledger/impl/TransactionAcquire.cpp
    src/ripple/app/ledger/impl/TransactionMaster.cpp
    src/ripple/app/main/Application.cpp
    src/ripple/app/main/BasicApp.cpp
    src/ripple/app/main/CollectorManager.cpp
    src/ripple/app/main/LoadManager.cpp
    src/ripple/app/main/Main.cpp
    src/ripple/app/main/NodeIdentity.cpp
    src/ripple/app/main/NodeStoreScheduler.cpp
    src/ripple/app/misc/CanonicalTXSet.cpp
    src/ripple/app/misc/FeeVoteImpl.cpp
    src/ripple/app/misc/HashRouter.cpp
    src/ripple/app/misc/NetworkOPs.cpp
    src/ripple/app/misc/SHAMapStoreImp.cpp
    src/ripple/app/misc/impl/AccountTxPaging.cpp
    src/ripple/app/misc/impl/AmendmentTable.cpp
    src/ripple/app/misc/impl/LoadFeeTrack.cpp
    src/ripple/app/misc/impl/Manifest.cpp
    src/ripple/app/misc/impl/Transaction.cpp
    src/ripple/app/misc/impl/TxQ.cpp
    src/ripple/app/misc/impl/ValidatorKeys.cpp
    src/ripple/app/misc/impl/ValidatorList.cpp
    src/ripple/app/misc/impl/ValidatorSite.cpp
    src/ripple/app/paths/AccountCurrencies.cpp
    src/ripple/app/paths/Credit.cpp
    src/ripple/app/paths/Flow.cpp
    src/ripple/app/paths/Node.cpp
    src/ripple/app/paths/PathRequest.cpp
    src/ripple/app/paths/PathRequests.cpp
    src/ripple/app/paths/PathState.cpp
    src/ripple/app/paths/Pathfinder.cpp
    src/ripple/app/paths/RippleCalc.cpp
    src/ripple/app/paths/RippleLineCache.cpp
    src/ripple/app/paths/RippleState.cpp
    src/ripple/app/paths/cursor/AdvanceNode.cpp
    src/ripple/app/paths/cursor/DeliverNodeForward.cpp
    src/ripple/app/paths/cursor/DeliverNodeReverse.cpp
    src/ripple/app/paths/cursor/EffectiveRate.cpp
    src/ripple/app/paths/cursor/ForwardLiquidity.cpp
    src/ripple/app/paths/cursor/ForwardLiquidityForAccount.cpp
    src/ripple/app/paths/cursor/Liquidity.cpp
    src/ripple/app/paths/cursor/NextIncrement.cpp
    src/ripple/app/paths/cursor/ReverseLiquidity.cpp
    src/ripple/app/paths/cursor/ReverseLiquidityForAccount.cpp
    src/ripple/app/paths/cursor/RippleLiquidity.cpp
    src/ripple/app/paths/impl/BookStep.cpp
    src/ripple/app/paths/impl/DirectStep.cpp
    src/ripple/app/paths/impl/PaySteps.cpp
    src/ripple/app/paths/impl/XRPEndpointStep.cpp
    src/ripple/app/tx/impl/ApplyContext.cpp
    src/ripple/app/tx/impl/BookTip.cpp
    src/ripple/app/tx/impl/CancelCheck.cpp
    src/ripple/app/tx/impl/CancelOffer.cpp
    src/ripple/app/tx/impl/CancelTicket.cpp
    src/ripple/app/tx/impl/CashCheck.cpp
    src/ripple/app/tx/impl/Change.cpp
    src/ripple/app/tx/impl/CreateCheck.cpp
    src/ripple/app/tx/impl/CreateOffer.cpp
    src/ripple/app/tx/impl/CreateTicket.cpp
    src/ripple/app/tx/impl/DeleteAccount.cpp
    src/ripple/app/tx/impl/DepositPreauth.cpp
    src/ripple/app/tx/impl/Escrow.cpp
    src/ripple/app/tx/impl/InvariantCheck.cpp
    src/ripple/app/tx/impl/OfferStream.cpp
    src/ripple/app/tx/impl/PayChan.cpp
    src/ripple/app/tx/impl/Payment.cpp
    src/ripple/app/tx/impl/SetAccount.cpp
    src/ripple/app/tx/impl/SetRegularKey.cpp
    src/ripple/app/tx/impl/SetSignerList.cpp
    src/ripple/app/tx/impl/SetTrust.cpp
    src/ripple/app/tx/impl/SignerEntries.cpp
    src/ripple/app/tx/impl/Taker.cpp
    src/ripple/app/tx/impl/Transactor.cpp
    src/ripple/app/tx/impl/apply.cpp
    src/ripple/app/tx/impl/applySteps.cpp
    #[===============================[
       nounity, main sources:
         subdir: basics (partial)
    #]===============================]
    src/ripple/basics/impl/Archive.cpp
    src/ripple/basics/impl/BasicConfig.cpp
    src/ripple/basics/impl/PerfLogImp.cpp
    src/ripple/basics/impl/ResolverAsio.cpp
    src/ripple/basics/impl/Sustain.cpp
    src/ripple/basics/impl/UptimeClock.cpp
    src/ripple/basics/impl/make_SSLContext.cpp
    src/ripple/basics/impl/mulDiv.cpp
    #[===============================[
       nounity, main sources:
         subdir: conditions
    #]===============================]
    src/ripple/conditions/impl/Condition.cpp
    src/ripple/conditions/impl/Fulfillment.cpp
    src/ripple/conditions/impl/error.cpp
    #[===============================[
       nounity, main sources:
         subdir: core
    #]===============================]
    src/ripple/core/impl/Config.cpp
    src/ripple/core/impl/DatabaseCon.cpp
    src/ripple/core/impl/Job.cpp
    src/ripple/core/impl/JobQueue.cpp
    src/ripple/core/impl/LoadEvent.cpp
    src/ripple/core/impl/LoadMonitor.cpp
    src/ripple/core/impl/SNTPClock.cpp
    src/ripple/core/impl/SociDB.cpp
    src/ripple/core/impl/Stoppable.cpp
    src/ripple/core/impl/TimeKeeper.cpp
    src/ripple/core/impl/Workers.cpp
    #[===============================[
       nounity, main sources:
         subdir: consensus
    #]===============================]
    src/ripple/consensus/Consensus.cpp
    #[===============================[
       nounity, main sources:
         subdir: ledger
    #]===============================]
    src/ripple/ledger/impl/ApplyStateTable.cpp
    src/ripple/ledger/impl/ApplyView.cpp
    src/ripple/ledger/impl/ApplyViewBase.cpp
    src/ripple/ledger/impl/ApplyViewImpl.cpp
    src/ripple/ledger/impl/BookDirs.cpp
    src/ripple/ledger/impl/CachedSLEs.cpp
    src/ripple/ledger/impl/CachedView.cpp
    src/ripple/ledger/impl/CashDiff.cpp
    src/ripple/ledger/impl/Directory.cpp
    src/ripple/ledger/impl/OpenView.cpp
    src/ripple/ledger/impl/PaymentSandbox.cpp
    src/ripple/ledger/impl/RawStateTable.cpp
    src/ripple/ledger/impl/ReadView.cpp
    src/ripple/ledger/impl/TxMeta.cpp
    src/ripple/ledger/impl/View.cpp
    #[===============================[
       nounity, main sources:
         subdir: net
    #]===============================]
    src/ripple/net/impl/HTTPClient.cpp
    src/ripple/net/impl/InfoSub.cpp
    src/ripple/net/impl/RPCCall.cpp
    src/ripple/net/impl/RPCErr.cpp
    src/ripple/net/impl/RPCSub.cpp
    src/ripple/net/impl/RegisterSSLCerts.cpp
    src/ripple/net/impl/SSLHTTPDownloader.cpp
    #[===============================[
       nounity, main sources:
         subdir: nodestore
    #]===============================]
    src/ripple/nodestore/backend/MemoryFactory.cpp
    src/ripple/nodestore/backend/NuDBFactory.cpp
    src/ripple/nodestore/backend/NullFactory.cpp
    src/ripple/nodestore/backend/RocksDBFactory.cpp
    src/ripple/nodestore/impl/BatchWriter.cpp
    src/ripple/nodestore/impl/Database.cpp
    src/ripple/nodestore/impl/DatabaseNodeImp.cpp
    src/ripple/nodestore/impl/DatabaseRotatingImp.cpp
    src/ripple/nodestore/impl/DatabaseShardImp.cpp
    src/ripple/nodestore/impl/DecodedBlob.cpp
    src/ripple/nodestore/impl/DummyScheduler.cpp
    src/ripple/nodestore/impl/EncodedBlob.cpp
    src/ripple/nodestore/impl/ManagerImp.cpp
    src/ripple/nodestore/impl/NodeObject.cpp
    src/ripple/nodestore/impl/Shard.cpp
    #[===============================[
       nounity, main sources:
         subdir: overlay
    #]===============================]
    src/ripple/overlay/impl/Cluster.cpp
    src/ripple/overlay/impl/ConnectAttempt.cpp
    src/ripple/overlay/impl/Message.cpp
    src/ripple/overlay/impl/OverlayImpl.cpp
    src/ripple/overlay/impl/PeerImp.cpp
    src/ripple/overlay/impl/PeerReservationTable.cpp
    src/ripple/overlay/impl/PeerSet.cpp
    src/ripple/overlay/impl/TMHello.cpp
    src/ripple/overlay/impl/TrafficCount.cpp
    #[===============================[
       nounity, main sources:
         subdir: peerfinder
    #]===============================]
    src/ripple/peerfinder/impl/Bootcache.cpp
    src/ripple/peerfinder/impl/Endpoint.cpp
    src/ripple/peerfinder/impl/PeerfinderConfig.cpp
    src/ripple/peerfinder/impl/PeerfinderManager.cpp
    src/ripple/peerfinder/impl/SlotImp.cpp
    src/ripple/peerfinder/impl/SourceStrings.cpp
    #[===============================[
       nounity, main sources:
         subdir: resource
    #]===============================]
    src/ripple/resource/impl/Charge.cpp
    src/ripple/resource/impl/Consumer.cpp
    src/ripple/resource/impl/Fees.cpp
    src/ripple/resource/impl/ResourceManager.cpp
    #[===============================[
       nounity, main sources:
         subdir: rpc
    #]===============================]
    src/ripple/rpc/handlers/AccountChannels.cpp
    src/ripple/rpc/handlers/AccountCurrenciesHandler.cpp
    src/ripple/rpc/handlers/AccountInfo.cpp
    src/ripple/rpc/handlers/AccountLines.cpp
    src/ripple/rpc/handlers/AccountObjects.cpp
    src/ripple/rpc/handlers/AccountOffers.cpp
    src/ripple/rpc/handlers/AccountTx.cpp
    src/ripple/rpc/handlers/AccountTxOld.cpp
    src/ripple/rpc/handlers/AccountTxSwitch.cpp
    src/ripple/rpc/handlers/BlackList.cpp
    src/ripple/rpc/handlers/BookOffers.cpp
    src/ripple/rpc/handlers/CanDelete.cpp
    src/ripple/rpc/handlers/Connect.cpp
    src/ripple/rpc/handlers/ConsensusInfo.cpp
    src/ripple/rpc/handlers/CrawlShards.cpp
    src/ripple/rpc/handlers/DepositAuthorized.cpp
    src/ripple/rpc/handlers/DownloadShard.cpp
    src/ripple/rpc/handlers/Feature1.cpp
    src/ripple/rpc/handlers/Fee1.cpp
    src/ripple/rpc/handlers/FetchInfo.cpp
    src/ripple/rpc/handlers/GatewayBalances.cpp
    src/ripple/rpc/handlers/GetCounts.cpp
    src/ripple/rpc/handlers/LedgerAccept.cpp
    src/ripple/rpc/handlers/LedgerCleanerHandler.cpp
    src/ripple/rpc/handlers/LedgerClosed.cpp
    src/ripple/rpc/handlers/LedgerCurrent.cpp
    src/ripple/rpc/handlers/LedgerData.cpp
    src/ripple/rpc/handlers/LedgerEntry.cpp
    src/ripple/rpc/handlers/LedgerHandler.cpp
    src/ripple/rpc/handlers/LedgerHeader.cpp
    src/ripple/rpc/handlers/LedgerRequest.cpp
    src/ripple/rpc/handlers/LogLevel.cpp
    src/ripple/rpc/handlers/LogRotate.cpp
    src/ripple/rpc/handlers/NoRippleCheck.cpp
    src/ripple/rpc/handlers/OwnerInfo.cpp
    src/ripple/rpc/handlers/PathFind.cpp
    src/ripple/rpc/handlers/PayChanClaim.cpp
    src/ripple/rpc/handlers/Peers.cpp
    src/ripple/rpc/handlers/Ping.cpp
    src/ripple/rpc/handlers/Print.cpp
    src/ripple/rpc/handlers/Random.cpp
    src/ripple/rpc/handlers/Reservations.cpp
    src/ripple/rpc/handlers/RipplePathFind.cpp
    src/ripple/rpc/handlers/ServerInfo.cpp
    src/ripple/rpc/handlers/ServerState.cpp
    src/ripple/rpc/handlers/SignFor.cpp
    src/ripple/rpc/handlers/SignHandler.cpp
    src/ripple/rpc/handlers/Stop.cpp
    src/ripple/rpc/handlers/Submit.cpp
    src/ripple/rpc/handlers/SubmitMultiSigned.cpp
    src/ripple/rpc/handlers/Subscribe.cpp
    src/ripple/rpc/handlers/TransactionEntry.cpp
    src/ripple/rpc/handlers/Tx.cpp
    src/ripple/rpc/handlers/TxHistory.cpp
    src/ripple/rpc/handlers/UnlList.cpp
    src/ripple/rpc/handlers/Unsubscribe.cpp
    src/ripple/rpc/handlers/ValidationCreate.cpp
    src/ripple/rpc/handlers/ValidatorListSites.cpp
    src/ripple/rpc/handlers/Validators.cpp
    src/ripple/rpc/handlers/WalletPropose.cpp
    src/ripple/rpc/impl/DeliveredAmount.cpp
    src/ripple/rpc/impl/Handler.cpp
    src/ripple/rpc/impl/LegacyPathFind.cpp
    src/ripple/rpc/impl/RPCHandler.cpp
    src/ripple/rpc/impl/RPCHelpers.cpp
    src/ripple/rpc/impl/Role.cpp
    src/ripple/rpc/impl/ServerHandlerImp.cpp
    src/ripple/rpc/impl/ShardArchiveHandler.cpp
    src/ripple/rpc/impl/Status.cpp
    src/ripple/rpc/impl/TransactionSign.cpp
    #[===============================[
       nounity, main sources:
         subdir: server
    #]===============================]
    src/ripple/server/impl/JSONRPCUtil.cpp
    src/ripple/server/impl/Port.cpp
    #[===============================[
       nounity, main sources:
         subdir: shamap
    #]===============================]
    src/ripple/shamap/impl/SHAMap.cpp
    src/ripple/shamap/impl/SHAMapDelta.cpp
    src/ripple/shamap/impl/SHAMapItem.cpp
    src/ripple/shamap/impl/SHAMapMissingNode.cpp
    src/ripple/shamap/impl/SHAMapNodeID.cpp
    src/ripple/shamap/impl/SHAMapSync.cpp
    src/ripple/shamap/impl/SHAMapTreeNode.cpp)
endif ()
target_link_libraries (rmcd
  Ripple::boost
  Ripple::opts
  Ripple::libs
  Ripple::xrpl_core)
exclude_if_included (rmcd)
# define a macro for tests that might need to
# be exluded or run differently in CI environment
if (is_ci)
  target_compile_definitions(rmcd PRIVATE RIPPLED_RUNNING_IN_CI)
endif ()