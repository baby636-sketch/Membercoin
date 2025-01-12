// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CLIENTMODEL_H
#define BITCOIN_QT_CLIENTMODEL_H

#include "blockrelay/compactblock.h"
#include "blockrelay/graphene.h"
#include "blockrelay/thinblock.h"

#include <QDateTime>
#include <QObject>

class AddressTableModel;
class BanTableModel;
class OptionsModel;
class UnlimitedModel;
class PeerTableModel;
class TransactionTableModel;

class CWallet;
class CBlockIndex;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

enum BlockSource
{
    BLOCK_SOURCE_NONE,
    BLOCK_SOURCE_REINDEX,
    BLOCK_SOURCE_DISK,
    BLOCK_SOURCE_NETWORK
};

enum NumConnections
{
    CONNECTIONS_NONE = 0,
    CONNECTIONS_IN = (1U << 0),
    CONNECTIONS_OUT = (1U << 1),
    CONNECTIONS_ALL = (CONNECTIONS_IN | CONNECTIONS_OUT),
};

/** Model for Member network client. */
class ClientModel : public QObject
{
    Q_OBJECT

public:
    explicit ClientModel(OptionsModel *optionsModel, UnlimitedModel *ul, QObject *parent = 0);
    ~ClientModel();

    OptionsModel *getOptionsModel();
    PeerTableModel *getPeerTableModel();
    BanTableModel *getBanTableModel();

    //! Return number of connections, default is in- and outbound (total)
    int getNumConnections(unsigned int flags = CONNECTIONS_ALL) const;
    int getNumBlocks() const;
    int getHeaderTipHeight() const;
    int64_t getHeaderTipTime() const;
    //! Return number of transactions in the mempool
    long getMempoolSize() const;

    //! Return number of transactions in the orphan pool
    long getOrphanPoolSize() const;

    //! Return the dynamic memory usage of the mempool
    size_t getMempoolDynamicUsage() const;

    quint64 getTotalBytesRecv() const;
    quint64 getTotalBytesSent() const;

    double getVerificationProgress(const CBlockIndex *tip) const;
    QDateTime getLastBlockDate() const;

    //! Return true if core is doing initial block download
    bool inInitialBlockDownload() const;
    //! Return true if core is importing blocks
    enum BlockSource getBlockSource() const;
    //! Return warnings to be displayed in status bar
    QString getStatusBarWarnings() const;

    QString formatFullVersion() const;
    QString formatSubVersion() const;
    bool isReleaseVersion() const;
    QString clientName() const;
    QString formatClientStartupTime() const;
    QString dataDir() const;
    UnlimitedModel *unlimitedModel;

    //! Cache last block time so that we can make fast updates (every 250 ms)
    //! to time since last block without having to take the cs_main lock every time
    mutable std::atomic<qint64> lastBlockTime;

private:
    OptionsModel *optionsModel;
    PeerTableModel *peerTableModel;
    BanTableModel *banTableModel;

    ThinBlockQuickStats thinStats;
    CompactBlockQuickStats compactStats;
    GrapheneQuickStats grapheneStats;

    QTimer *pollTimer1;
    QTimer *pollTimer2;
    QTimer *pollTimer3;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

Q_SIGNALS:
    void numConnectionsChanged(int count);
    void numBlocksChanged(int count, const QDateTime &blockDate, double nVerificationProgress, bool fHeader);
    void timeSinceLastBlockChanged(qint64 lastBlockTime);
    void mempoolSizeChanged(long count, size_t mempoolSizeInBytes);
    void orphanPoolSizeChanged(long count);
    void alertsChanged(const QString &warnings);
    void bytesChanged(quint64 totalBytesIn, quint64 totalBytesOut);
    void transactionsPerSecondChanged(double smoothedTps, double instantaneousTps, double peakTps);
    void thinBlockPropagationStatsChanged(const ThinBlockQuickStats &thin);
    void compactBlockPropagationStatsChanged(const CompactBlockQuickStats &compact);
    void grapheneBlockPropagationStatsChanged(const GrapheneQuickStats &graphene);

    //! Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);

    // Show progress dialog e.g. for verifychain
    void showProgress(const QString &title, int nProgress);

public Q_SLOTS:
    void updateTimer1();
    void updateTimer2();
    void updateTimerTransactionRate();
    void updateNumConnections(int numConnections);
    void updateAlert();
    void updateBanlist();
};

#endif // BITCOIN_QT_CLIENTMODEL_H
