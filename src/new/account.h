/*
 * Copyright (C) 2013 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 *
 * You may use this file under the terms of the BSD license as follows:
 *
 * "Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Nemo Mobile nor Jolla Ltd. nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
 */

#ifndef ACCOUNT_H
#define ACCOUNT_H

#include <QtCore/QObject>
#include <QtCore/QVariantMap>
#include <QtCore/QStringList>
#include <QtCore/QString>

#include <QtGlobal>
#if QT_VERSION_5
#include <QtQml>
#include <QQmlParserStatus>
#define QDeclarativeParserStatus QQmlParserStatus
#else
#include <qdeclarative.h>
#include <QDeclarativeParserStatus>
#endif

//libaccounts-qt
#include <Accounts/Account>
#include <Accounts/Error>

//libsignon-qt
#include <SignOn/Identity>
#include <SignOn/SessionData>
#include <SignOn/AuthSession>

class AccountPrivate;

/*
 * NOTE: if you construct one of these in C++ directly,
 * you MUST call classBegin() and componentCompleted()
 * directly after construction.
 */

class Account : public QObject, public QDeclarativeParserStatus
{
    Q_OBJECT
    Q_INTERFACES(QDeclarativeParserStatus)

    Q_PROPERTY(bool enabled READ enabled WRITE setEnabled NOTIFY enabledChanged)
    Q_PROPERTY(int identifier READ identifier WRITE setIdentifier NOTIFY identifierChanged)
    Q_PROPERTY(QString providerName READ providerName NOTIFY providerNameChanged)
    Q_PROPERTY(QString displayName READ displayName WRITE setDisplayName NOTIFY displayNameChanged)

    Q_PROPERTY(QStringList supportedServiceNames READ supportedServiceNames NOTIFY supportedServiceNamesChanged)
    Q_PROPERTY(QStringList enabledServiceNames READ enabledServiceNames NOTIFY enabledServiceNamesChanged)

    Q_PROPERTY(Status status READ status NOTIFY statusChanged)
    Q_PROPERTY(ErrorType error READ error NOTIFY errorChanged)
    Q_PROPERTY(QString errorMessage READ errorMessage NOTIFY errorMessageChanged)

    Q_ENUMS(Status)
    Q_ENUMS(ErrorType)

public:
    enum Status {
        Initialized = 0,
        Initializing,
        Synced,
        SyncInProgress,
        Modified,
        Error,
        Invalid
    };

    enum ErrorType {
        NoError                 = Accounts::Error::NoError,
        UnknownError            = Accounts::Error::Unknown,
        DatabaseError           = Accounts::Error::Database,
        DeletedError            = Accounts::Error::Deleted,
        DatabaseLockedError     = Accounts::Error::DatabaseLocked,
        AccountNotFoundError    = Accounts::Error::AccountNotFound,
        ConflictingProviderError,
        InitializationFailedError
    };

public:
    Account(QObject *parent = 0);
    ~Account();

    // QDeclarativeParserStatus
    void classBegin();
    void componentComplete();

    // database sync
    Q_INVOKABLE void sync();
    Q_INVOKABLE void remove();

    // invokable api.
    Q_INVOKABLE QVariantMap configurationValues(const QString &serviceName) const;
    Q_INVOKABLE void setConfigurationValues(const QString &serviceName, const QVariantMap &serviceValues);
    Q_INVOKABLE QString encodeConfigurationValue(const QString &value, const QString &scheme = QString(), const QString &key = QString()) const;
    Q_INVOKABLE QString decodeConfigurationValue(const QString &value, const QString &scheme = QString(), const QString &key = QString()) const;

    Q_INVOKABLE bool supportsServiceType(const QString &serviceType);
    Q_INVOKABLE void enableWithService(const QString &serviceName);
    Q_INVOKABLE void disableWithService(const QString &serviceName);

    Q_INVOKABLE SignInData *signInData(const QString &serviceName) const;
    Q_INVOKABLE bool haveSignInCredentials(const QString &applicationName,
                                           const QString &credentialsName = QString()) const;
    Q_INVOKABLE void createOAuthSignInCredentials(const QString &applicationName,
                                                  const QString &decodingKey,
                                                  const QString &mechanism,
                                                  const QVariantMap &sessionData,
                                                  const QString &credentialsName = QString());
    Q_INVOKABLE void createSignInCredentials(const QString &applicationName,
                                             const QString &decodingKey,
                                             const QString &method,
                                             const QString &mechanism,
                                             const QVariantMap &sessionData,
                                             const QString &username,
                                             const QString &password,
                                             const QString &credentialsName = QString());
    Q_INVOKABLE void removeSignInCredentials(const QString &applicationName,
                                             const QString &credentialsName = QString());
    Q_INVOKABLE void signIn(const QVariantMap &sessionData,
                            const QString &applicationName,
                            const QString &decodingKey,
                            const QString &credentialsName = QString());
    Q_INVOKABLE void signOut(const QString &applicationName,
                             const QString &credentialsName = QString());

    // property accessors.
    bool enabled() const;
    void setEnabled(bool e);
    int identifier() const;
    void setIdentifier(int id);
    QString displayName() const;
    void setDisplayName(const QString &dn);
    QString providerName() const;
    QStringList supportedServiceNames() const;
    QStringList enabledServiceNames() const;

    Status status() const;
    ErrorType error() const;
    QString errorMessage() const;

Q_SIGNALS:
    void enabledChanged();
    void identifierChanged();
    void displayNameChanged();
    void providerNameChanged();
    void supportedServiceNamesChanged();
    void enabledServiceNamesChanged();
    void statusChanged();
    void errorChanged();
    void errorMessageChanged();

    void signInCredentialsCreated(const QVariantMap &data);
    void signInResponse(const QVariantMap &data);

private:
    Account(Accounts::Account *account, QObject *parent = 0);
    Accounts::Account *account();
    friend class AccountManager;

private:
    AccountPrivate *d;
    friend class AccountPrivate;
};

#endif
