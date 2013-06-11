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

#include "account.h"
#include "account_p.h"
#include "accountvalueencoding_p.h"

#include <QtDebug>

//libaccounts-qt
#include <Accounts/Manager>
#include <Accounts/Account>
#include <Accounts/Service>

//libsignon-qt
#include <SignOn/Identity>
#include <SignOn/SessionData>
#include <SignOn/AuthSession>

#define CREDENTIALS_KEY QLatin1String("segregated_credentials")

AccountPrivate::AccountPrivate(Account *parent, Accounts::Account *acc)
    : QObject(parent)
    , q(parent)
    , account(0)
    , pendingSync(false)
    , pendingInitModifications(false)
    , identifier(0)
    , enabled(false)
    , identifierPendingInit(false)
    , enabledPendingInit(false)
    , displayNamePendingInit(false)
    , configurationValuesPendingInit(false)
    , enabledServiceNamesPendingInit(false)
    , status(Account::Initializing)
    , error(Account::NoError)
{
    if (acc)
        setAccount(acc);
}

AccountPrivate::~AccountPrivate()
{
}

void AccountPrivate::setAccount(Accounts::Account *acc)
{
    if (!acc) {
        qWarning() << "Account: setAccount() called with null account! Aborting operation.";
        return;
    }

    if (account) {
        qWarning() << "Account: setAccount() called but account already set! Aborting operation.";
        return;
    }

    account = acc;

    // connect up our signals.
    connect(account, SIGNAL(enabledChanged(QString,bool)), this, SLOT(enabledHandler(QString,bool)));
    connect(account, SIGNAL(displayNameChanged(QString)), this, SLOT(displayNameChangedHandler()));
    connect(account, SIGNAL(synced()), this, SLOT(handleSynced()));
    connect(account, SIGNAL(removed()), this, SLOT(invalidate()));
    connect(account, SIGNAL(destroyed()), this, SLOT(invalidate()));

    // first time read from db.  we should be in Initializing state to begin with.
    // QueuedConnection to ensure that clients have a chance to connect to state changed signals.
    QMetaObject::invokeMethod(this, "asyncQueryInfo", Qt::QueuedConnection);

    // NOTE: we can't escape the asyncQueryInfo (eg, via a "queryInfoOnInit: false" property
    // or similar, simply because the application-segregation requires the configuration settings
    // to be read for the account (and, presumably, the service enablement statuses).
}

void AccountPrivate::asyncQueryInfo()
{
    if (!account) {
        qWarning() << "Account: no account set!  Maybe you forgot to call componentComplete()?";
        setStatus(Account::Invalid);
        return;
    }

    // note that the account doesn't have a queryInfo() like Identity
    // so we just read the values directly.

    int newIdentifier = account->id();
    if (identifier != newIdentifier) {
        identifier = account->id();
        emit q->identifierChanged();
    }

    if (providerName != account->providerName()) {
        providerName = account->providerName();
        emit q->providerNameChanged();
    }

    // supported service names
    Accounts::ServiceList supportedServices = account->services();
    for (int i = 0; i < supportedServices.size(); ++i) {
        Accounts::Service currService = supportedServices.at(i);
        QString serviceName = currService.name();
        supportedServiceNames.append(serviceName);
    }
    emit q->supportedServiceNamesChanged();

    // enabled
    if (enabledPendingInit) {
        pendingInitModifications = true;
    } else if (enabled != account->enabled()) {
        enabled = account->enabled();
        emit q->enabledChanged();
    }

    // display name
    if (displayNamePendingInit) {
        pendingInitModifications = true;
    } else if (displayName != account->displayName()) {
        displayName = account->displayName();
        emit q->displayNameChanged();
    }

    // configuration values
    if (configurationValuesPendingInit) {
        pendingInitModifications = true;
    } else {
        // enumerate the global configuration values
        QVariantMap allValues;
        QStringList allKeys = account->allKeys();
        foreach (const QString &key, allKeys)
            allValues.insert(key, account->value(key, QVariant(), 0));

        // also enumerate configuration values for all supported services.
        for (int i = 0; i < supportedServices.size(); ++i) {
            Accounts::Service currService = supportedServices.at(i);
            account->selectService(currService);
            QVariantMap serviceValues;
            QStringList serviceKeys = account->allKeys();
            foreach (const QString &key, serviceKeys)
                serviceValues.insert(key, account->value(key, QVariant(), 0));
            QVariantMap existingServiceValues = serviceConfigurationValues.value(currService.name());
            if (serviceValues != existingServiceValues)
                serviceConfigurationValues.insert(currService.name(), serviceValues);
            account->selectService(Accounts::Service());
        }

        // emit change signal for global configuration values only.
        if (configurationValues != allValues) {
            configurationValues = allValues;
            emit q->configurationValuesChanged();
        }
    }

    // enabled services
    if (enabledServiceNamesPendingInit) {
        QStringList tmpList = enabledServiceNames;
        enabledServiceNames.clear(); // clear them all.  this is because of the sync() semantics of service names.
        foreach (const QString &sn, tmpList) {
            if (supportedServiceNames.contains(sn))
                q->enableWithService(sn);
        }
    } else {
        Accounts::ServiceList enabledServices = account->enabledServices();
        for (int i = 0; i < enabledServices.size(); ++i) {
            Accounts::Service currService = enabledServices.at(i);
            QString serviceName = currService.name();
            enabledServiceNames.append(serviceName);
        }
        if (enabledServiceNames.count() > 0) {
            emit q->enabledServiceNamesChanged();
        }
    }

    // do sync if required.
    if (status == Account::Invalid || status == Account::Error) {
        // error occurred during initialization, or was removed.
        // do nothing - the client will have already been notified.
    } else {
        // initialization completed successfully.
        setStatus(Account::Initialized);
        if (pendingInitModifications)
            setStatus(Account::Modified); // modifications occurred prior to initialization completion.
        if (pendingSync) {
            pendingSync = false;
            q->sync(); // the user requested sync() while we were initializing.
        }
    }
}

void AccountPrivate::enabledHandler(const QString &serviceName, bool newEnabled)
{
    // check to see if it's the "global" service name (generated by libaccounts-qt)
    // or an actual service name :-/
    if (serviceName.isEmpty() || serviceName == QString(QLatin1String("global"))) {
        if (!enabledPendingInit && newEnabled != enabled) {
            enabled = newEnabled;
            emit q->enabledChanged();
        }
    } else {
        // note: we can't cache the values on set, and check here,
        // because we can never know the complete set of enabled/disabled
        // service names at the same time :-/
        // So, the semantics of enabledServiceNames is a bit different: requires sync() to emit.
        if (newEnabled) {
            if (!enabledServiceNames.contains(serviceName)) {
                enabledServiceNames.append(serviceName);
            }
        } else {
            enabledServiceNames.removeAll(serviceName);
        }

        // note: we _always_ emit even if the content of enabledServiceNames
        // doesn't actually change as a result of this signal.
        // We simply cannot determine whether we need to or not, otherwise.
        emit q->enabledServiceNamesChanged();
    }
}

void AccountPrivate::displayNameChangedHandler()
{
    if (displayNamePendingInit)
        return; // ignore, we have local changes which will overwrite this.

    if (displayName != account->displayName()) {
        displayName = account->displayName();
        emit q->displayNameChanged();
    }
}

void AccountPrivate::invalidate()
{
    // NOTE: the Accounts::Manager instance ALWAYS owns the account pointer.
    // If the manager gets deleted while the Account instance is
    // alive, we need to ensure that invalidate() gets called also.
    // We also invalidate the interface if the account itself gets removed
    // from the accounts database.
    if (account)
        disconnect(account);
    account = 0;
    setStatus(Account::Invalid);
}

void AccountPrivate::handleSynced()
{
    if (status == Account::SyncInProgress) {
        if (!account) {
            qWarning() << Q_FUNC_INFO << "Account not valid";
            return;
        }

        // check to see if the id was updated
        int newIdentifier = account->id();
        if (identifier != newIdentifier) {
            identifier = account->id();
            emit q->identifierChanged();
        }

        // check to see if the providerName was updated
        if (providerName != account->providerName()) {
            providerName = account->providerName();
            emit q->providerNameChanged();
        }

        // check to see if the configuration values were updated
        QVariantMap allValues;
        QStringList allKeys = account->allKeys();
        foreach (const QString &key, allKeys)
            allValues.insert(key, account->value(key, QVariant(), 0));
        if (configurationValues != allValues) {
            configurationValues = allValues;
            emit q->configurationValuesChanged();
        }

        // and update our status.
        setStatus(Account::Synced);
    }
}

void AccountPrivate::setStatus(Account::Status newStatus)
{
    if (status == Account::Invalid)
        return; // once invalid, cannot be restored.

    if (status != newStatus) {
        status = newStatus;
        emit q->statusChanged();
    }
}

//-----------------------------------

/*!
    \qmltype Account
    \instantiates Account
    \inqmlmodule org.nemomobile.accounts 1
    \brief Used to create or modify an account for a service provider

    The Account type is a non-visual type which allows
    the details of an account to be specified, and saved to the system
    accounts database.

    Any modifications to any property of an account will have no effect
    until the modifications are saved to the database by calling sync().

    \qml
        import org.nemomobile.accounts 1.0

        Item {
            id: root

            Account {
                id: account
                identifier: 12 // retrieved from AccountManager or AccountModel

                // we will be updating the following two properties
                displayName: "inactive example account"
                enabled: false

                onStatusChanged: {
                    if (status == Account.Initialized) {
                        sync() // trigger database write
                    } else if (status == Account.Error) {
                        // handle error
                    } else if (status == Account.Synced) {
                        // successfully written to database
                        // for example purposes, we may want to remove the account.
                        remove() // trigger database write
                    } else if (status == Account.Invalid) {
                        // successfully removed from database.
                    }
                }
            }
        }
    \endqml

    An Account can be used to sign into a service.
    Each application must create signon credentials in the account,
    and may sign into the account using those credentials.

    \qml
        import org.nemomobile.accounts 1.0

        Account {
            id: account
            identifier: 12 // retrieved from AccountManager or AccountModel

            property bool creatingSignInCredentials: false

            onStatusChanged: {
                var siData = signInData("SomeService")
                if (status == Account.Initialized) {
                    if (!haveSignInCredentials("MyApp", "SecretKey", "MyCredentials")) {
                        // create sign in credentials
                        creatingSignInCredentials = true
                        createSignInCredentials("MyApp", "SecretKey",
                                                siData.method,
                                                siData.mechanism,
                                                siData.parameters,
                                                "MyCredentials)
                    } else {
                        signIn(siData.parameters, "MyApp", "SecretKey", "MyCredentials")
                    }
                } else if (status == Account.Synced && creatingSignInCredentials == true) {
                    creatingSignInCredentials = false
                    signIn(siData.parameters, "MyApp", "SecretKey", "MyCredentials")
                }
            }

            onSignInResponse: {
                console.log("Got back response: " + data)
            }
        }
    \endqml

    To create an account, use the AccountManager type:

    \qml
        import org.nemomobile.accounts 1.0

        QtObject {
            id: root

            AccountManager {
                id: manager
            }

            Account {
                id: account
                identifier: manager.createAccount("providerName")

                onStatusChanged: {
                    if (status == Account.Initialized) {
                        console.log("Successfully created account")
// ... createSignInCredentials
                    }
                }
            }
        }
    \endqml


        onCompleted: {
            var accId = manager.createAccount("facebook")
            manager.createSignInCredentials(accId, ...);
        }
*/

Account::Account(QObject *parent)
    : QObject(parent), d(new AccountPrivate(this, 0))
{
}

Account::~Account()
{
}


// QDeclarativeParserStatus
void Account::classBegin() { }
void Account::componentComplete()
{
    if (!d->account) {
        if (d->identifier == 0) {
            d->setStatus(Account::Invalid); // Set to invalid even though already set to error!  Since no account.
        } else {
            // loading an existing account
            Accounts::Account *existingAccount = d->manager->account(d->identifier);
            d->setAccount(existingAccount);
        }
    } else {
        // account was provided by AccountManager.
        // do nothing.
    }
}

// helpers for AccountManager only.
Account::Account(Accounts::Account *account, QObject *parent)
    : QObject(parent), d(new AccountPrivate(this, account)) { }
Accounts::Account *Account::account() { return d->account; }

/*!
    \qmlmethod void Account::sync()

    Writes any outstanding local modifications to the database.
    The operation may be either synchronous or asynchronous
    depending on whether the database is currently locked or
    open for writing.  The account will transition to the
    \c{SyncInProgress} status and remain with that status for
    the duration of the synchronisation operation.

    Calling this function will have no effect if the account is
    invalid or if a previous synchronisation operation is in
    progress.
*/
void Account::sync()
{
    if (d->status == Account::Initializing)
        d->pendingSync = true;

    if (d->status == Account::Invalid
            || d->status == Account::SyncInProgress
            || d->status == Account::Initializing)
        return;

    if (!d->account) { // initialization failed.
        d->error = Account::InitializationFailedError;
        emit errorChanged();
        d->setStatus(Account::Invalid);
        return;
    }

    if (d->pendingInitModifications) {
        // we have handled them by directly syncing.
        // after this sync, we will once again allow
        // change signals to cause modifications to the properties.
        d->pendingInitModifications = false;
        d->identifierPendingInit = false;
        d->enabledPendingInit = false;
        d->displayNamePendingInit = false;
        d->configurationValuesPendingInit = false;
        d->enabledServiceNamesPendingInit = false;
    }

    // remove any enabled services which aren't part of the supported services set.
    QStringList tmpESN = d->enabledServiceNames;
    QStringList improvedESN;
    foreach (const QString &esn, tmpESN) {
        if (d->supportedServiceNames.contains(esn))
            improvedESN.append(esn);
    }
    if (tmpESN != improvedESN) {
        d->enabledServiceNames = improvedESN;
        emit enabledServiceNamesChanged();
    }

    // set the global configuration values.
    QStringList allKeys = d->account->allKeys();
    QStringList setKeys = d->configurationValues.keys();
    QStringList doneKeys;
    foreach (const QString &key, allKeys) {
        // overwrite existing keys
        if (setKeys.contains(key)) {
            doneKeys.append(key);
            const QVariant &currValue = d->configurationValues.value(key);
            if (currValue.isValid()) {
                d->account->setValue(key, currValue);
            } else {
                d->account->remove(key);
            }
        } else {
            // remove removed keys
            d->account->remove(key);
        }
    }
    foreach (const QString &key, setKeys) {
        // add new keys
        if (!doneKeys.contains(key)) {
            const QVariant &currValue = d->configurationValues.value(key);
            d->account->setValue(key, currValue);
        }
    }

    // and the service-specific configuration values
    foreach (const QString &srvn, d->supportedServiceNames) {
        Accounts::Service srv = d->manager->service(srvn);
        if (srv.isValid()) {
            d->account->selectService(srv);

            QVariantMap setSrvValues = d->serviceConfigurationValues.value(srvn);
            QStringList setSrvKeys = setSrvValues.keys();
            QStringList srvKeys = d->account->allKeys();
            QStringList doneSrvKeys;

            foreach (const QString &key, srvKeys) {
                // overwrite existing keys
                if (setSrvKeys.contains(key)) {
                    doneSrvKeys.append(key);
                    const QVariant &currValue = setSrvValues.value(key);
                    if (currValue.isValid()) {
                        d->account->setValue(key, currValue);
                    } else {
                        d->account->remove(key);
                    }
                } else {
                    // remove removed keys
                    d->account->remove(key);
                }
            }
            foreach (const QString &key, setSrvKeys) {
                // add new keys
                if (!doneSrvKeys.contains(key)) {
                    const QVariant &currValue = setSrvValues.value(key);
                    d->account->setValue(key, currValue);
                }
            }

            d->account->selectService(Accounts::Service());
        }
    }

    // set the enabled services correctly.
    foreach (const QString &srvn, d->supportedServiceNames) {
        Accounts::Service srv = d->manager->service(srvn);
        if (srv.isValid()) {
            d->account->selectService(srv);
            if (d->enabledServiceNames.contains(srvn))
                d->account->setEnabled(true);
            else
                d->account->setEnabled(false);
            d->account->selectService(Accounts::Service());
        }
    }
    // enable or disable the global service
    d->account->selectService(Accounts::Service());
    d->account->setEnabled(d->enabled);

    // set the display name
    d->account->setDisplayName(d->displayName);

    // and write to database.
    d->setStatus(Account::SyncInProgress);
    d->account->sync();
}

/*!
    \qmlmethod void Account::remove()

    Removes the account.  A removed account becomes invalid.
*/
void Account::remove()
{
    if (!d->account)
        return;

    d->setStatus(Account::SyncInProgress);
    d->account->remove();
    d->account->sync();
}


/*!
    \qmlmethod QVariantMap Account::configurationValues(const QString &serviceName)

    Returns the configuration settings for the account which apply
    specifically to the service with the specified \a serviceName.
    Note that it won't include global configuration settings which
    may also be applied (as fallback settings) when the account is
    used with the service.

    Some default settings are usually specified in the \c{.service}
    file installed by the account provider plugin.  Other settings
    may be specified directly on an account for the service.

    If the specified \a serviceName is empty, the account's global
    configuration settings will be returned instead.
*/
QVariantMap Account::configurationValues(const QString &serviceName) const
{
    if (d->status == Account::Invalid)
        return QVariantMap();
    if (serviceName.isEmpty())
        return d->configurationValues;
    return d->serviceConfigurationValues.value(serviceName);
}


/*!
    \qmlmethod void Account::setConfigurationValues(const QVariantMap &values, const QString &serviceName)

    Sets the configuration settings for the account which apply
    specifically to the service with the specified \a serviceName.

    The \a serviceName must identify a service supported by the
    account, or be empty, else calling this function will have no effect.
    If the \a serviceName is empty, the global account configuration
    settings will updated instead.
*/
void Account::setConfigurationValues(const QString &serviceName, const QVariantMap &values)
{
    if (d->status == Account::Invalid || d->status == Account::SyncInProgress)
        return;

    if (d->status != Account::Initializing && !supportedServiceNames().contains(serviceName))
        return;

    QVariantMap validValues;
    QStringList vkeys = values.keys();
    foreach (const QString &key, vkeys) {
        QVariant currValue = values.value(key);
        if (currValue.type() == QVariant::Bool
                || currValue.type() == QVariant::Int
                || currValue.type() == QVariant::LongLong
                || currValue.type() == QVariant::ULongLong
                || currValue.type() == QVariant::String
                || currValue.type() == QVariant::StringList) {
            validValues.insert(key, currValue);
        } else if (currValue.type() == QVariant::List) {
            validValues.insert(key, currValue.toStringList());
        }
    }

    bool globalService = serviceName.isEmpty();
    if ((globalService && d->configurationValues == validValues)
            || (!globalService && d->serviceConfigurationValues.value(serviceName) == validValues)) {
        // no change.
        return;
    }

    if (globalService) {
        d->configurationValues = validValues;
        if (d->status == Account::Initializing) {
            d->configurationValuesPendingInit = true;
        } else {
            d->setStatus(Account::Modified);
        }
    } else {
        d->serviceConfigurationValues.insert(serviceName, validValues);
        if (d->status == Account::Initializing) {
            d->configurationValuesPendingInit = true;
        } else {
            d->setStatus(Account::Modified);
        }
    }
}

bool Account::supportsServiceType(const QString &serviceType)
{
    if (!d->account)
        return false;
    return d->account->supportsService(serviceType);
}


/*!
    \qmlmethod QString Account::encodeConfigurationValue(const QString &value, const QString &scheme = QString(), const QString &key = QString()) const

    Encodes the given \a value with the specified \a key using the specified \a scheme.
    If the \a scheme is empty or invalid, the value will be encoded with Base64 and the
    key will be ignored.

    The implementation of each scheme is non-standard and a value encoded with this
    method shouldn't be assumed to be decodable via a method other than calling
    \c decodeConfigurationValue().

    This method can be used to encode values which shouldn't be stored as plain text
    in an account configuration.  Note that this method does NOT provide any security,
    nor is it intended for use in cryptography or authentication; it exists merely as
    a convenience for application authors.

    Valid schemes are:
    \list
    \li "base64" - \a key is ignored
    \li "rot" - \a key is ignored
    \li "xor" - \a key is used if all characters are between 'a' and 'z', or "nemo" by default
    \endlist
*/
QString Account::encodeConfigurationValue(const QString &value, const QString &scheme, const QString &key) const
{
    return encodeValue(value, scheme, key); // from accountvalueencoding_p.h
}

/*!
    \qmlmethod QString Account::decodeConfigurationValue(const QString &value, const QString &scheme = QString(), const QString &key = QString()) const

    Decodes the given \a value with the specified \a key using the specified \a scheme.
    This method can be used to decode values which were previously encoded with encode().
*/
QString Account::decodeConfigurationValue(const QString &value, const QString &scheme, const QString &key) const
{
    return decodeValue(value, scheme, key); // from accountvalueencoding_p.h
}

/*!
    \qmlmethod void Account::enableWithService(const QString &serviceName)

    Enables the account with the service identified by the given \a serviceName.

    If the service does not exist, or this account does not support the service,
    or the status of the account is either Invalid or SyncInProgress, the operation
    will silently fail.

    Note: this method will have no effect until sync() is called!
*/
void Account::enableWithService(const QString &serviceName)
{
    if (d->status == Account::Invalid || d->status == Account::SyncInProgress)
        return;

    if (!d->enabledServiceNames.contains(serviceName)) {
        d->enabledServiceNames.append(serviceName);
        if (d->status == Account::Initializing)
            d->enabledServiceNamesPendingInit = true;
        else
            d->setStatus(Account::Modified);
        // we don't emit enabledServiceNamesChanged here; we re-emit the sigs after sync()
    }
}


/*!
    \qmlmethod void Account::disableWithService(const QString &serviceName)

    Disables the account with the service identified by the given \a serviceName.

    If the service does not exist, or this account does not support the service,
    or the status of the account is either Invalid or SyncInProgress, the operation
    will silently fail.

    Note: this method will have no effect until sync() is called!
*/
void Account::disableWithService(const QString &serviceName)
{
    if (d->status == Account::Invalid || d->status == Account::SyncInProgress)
        return;

    if (d->enabledServiceNames.contains(serviceName)) {
        d->enabledServiceNames.removeAll(serviceName);
        if (d->status == Account::Initializing)
            d->enabledServiceNamesPendingInit = true;
        else
            d->setStatus(Account::Modified);
        // we don't emit enabledServiceNamesChanged here; we re-emit the sigs after sync()
    }
}


SignInData *Account::signInData(const QString &serviceName) const
{
    // XXX TODO: patch accounts&sso so that Service provides accessors
    // for method/mechanism/parameters from <template>
    QString method;
    QString mechanism;
    QVariantMap parameters;

    // Note: we don't use service-segregation, but instead we use per-application segregation.
    // So, we use the ServiceAccount's AuthData only to get the method/mechanism/params.
    Accounts::Service srv = d->manager->service(srvn);
    if (srv.isValid()) {
        Accounts::AccountService as(d->account, srv);
        Accounts::AuthData authData(as.authData());
        method = authData.method();
        mechanism = authData.mechanism();
        parameters = authData.parameters();
    } else {
        qWarning() << Q_FUNC_INFO << "No such service:" << serviceName;
    }

    return new SignInData(method, mechanism, parameters, this);
}

/*!
    \qmlmethod Account::haveSignInCredentials(const QString &applicationName, const QString &credentialsName) const

    Returns true if the application named \a applicationName has created
    sign-in credentials with this account named \a credentialsName.  If
    \a credentialsName is empty, the function returns true if the "default"
    named credentials have been created by the application.
*/
bool Account::haveSignInCredentials(const QString &applicationName,
                                    const QString &credentialsName) const
{
    if (d->status == Account::Invalid || d->status == Account::SyncInProgress)
        return false; // unknown

    QString credName = credentialsName.isEmpty() ? QLatin1String("default") : credentialsName;
    QVariantMap credentialsMap = d->configurationValues.value(CREDENTIALS_KEY).toMap();
    QVariantMap applicationCredsMap = credentialsMap.value(applicationName).toMap();
    return applicationCredsMap.value(credentialsName, QVariant::fromValue<int>(0)).toInt() != 0;
}

/*!
    \qmlmethod Account::createOAuthSignInCredentials(const QString &applicationName, const QString &decodingKey, const QString &mechanism, const QVariantMap &sessionData, const QString &credentialsName)

    Creates sign-in credentials with this account for the application with
    the given \a applicationName named \a credentialsName (or named "default"
    if the \a credentialsName parameter is left empty).

    The credentials will use the OAuth method, and the specified \a mechanism
    (which must be one of "user_agent", "web_server", "HMAC-SHA1" or another
    support OAuth mechanism).  Sign-in will be attempted during credentials
    creation, using the specified \a sessionData.  The \a mechanism and
    \a sessionData can come from the \c signInData() for the appropriate
    service.

    If sign-in succeeds, the credentials will be encoded using the given
    \a decodingKey, and then stored and named the given
    \a credentialsName (or named "default" if no credentials name is given),
    and the \c signInResponseReceived() signal will be emitted.

    If sign-in fails, the credentials will be removed and the
    \c signInFailed() signal will be emitted.
*/
void Account::createOAuthSignInCredentials(const QString &applicationName,
                                           const QString &decodingKey,
                                           const QString &mechanism,
                                           const QVariantMap &sessionData,
                                           const QString &credentialsName = QString())
{
}

/*!
    \qmlmethod Account::createSignInCredentials(const QString &applicationName, const QString &decodingKey, const QString &method, const QString &mechanism, const QVariantMap &sessionData, const QString &userName, const QString &password, const QString &credentialsName)

    Creates sign-in credentials with this account for the application with
    the given \a applicationName named \a credentialsName (or named "default"
    if the \a credentialsName parameter is left empty).

    The credentials will use the specified \a method and \a mechanism (which
    can be read from the \c signInData() for the appropriate service.)

    The username and password will be encoded with the given \a decodingKey,
    and stored with the given \a credentialsName (or "default" if no
    \a credentialsName is given).

    If credentials creation succeeds, the \c signInResponseReceived() signal
    will be emitted.

    If credentials creation fails, the \c signInFailed() signal will be
    emitted.
*/
void Account::createSignInCredentials(const QString &applicationName,
                                      const QString &decodingKey,
                                      const QString &method,
                                      const QString &mechanism,
                                      const QVariantMap &sessionData,
                                      const QString &username,
                                      const QString &password,
                                      const QString &credentialsName = QString())
{
}

/*!
    \qmlmethod Account::removeSignInCredentials(const QString &applicationName, const QString &credentialsName)

    Removes the sign-in credentials for the application with the given
    \a applicationName from the account, where the credentials are
    named the given \a credentialsName (or named "default" if the
    \a credentialsName parameter is empty).
*/
void Account::removeSignInCredentials(const QString &applicationName,
                                      const QString &credentialsName = QString())
{
}

/*!
    \qmlmethod Account::signIn(const QVariantMap &sessionData, const QString &applicationName, const QString &decodingKey, const QString &credentialsName)

    Signs the application with the given \a applicationName into the account
    using the per-application credentials identified by the given
    \a credentialsName.  The credentials will be decoded using the given
    \a decodingKey, which means that if the decoding key given is incorrect,
    sign-in will fail.

    Emits \c signInResponseReceived() on success, or \c signInFailed() on
    failure.
*/
void Account::signIn(const QVariantMap &sessionData,
                     const QString &applicationName,
                     const QString &decodingKey,
                     const QString &credentialsName = QString())
{
}

/*!
    \qmlmethod Account::signOut(const QString &applicationName, const QString &credentialsName)

    Signs the application out of the account where it had previously been
    signed in using the credentials named the given \a credentialsName
    (or named "default" if no \a credentialsName is given).

    Client code should not need to call this method, as the account can
    remain signed in safely.
*/
void Account::signOut(const QString &applicationName,
                      const QString &credentialsName = QString())
{
}



/*!
    \qmlproperty bool Account::enabled
    This property will be true if the account can be used, or false if it cannot.

    The account should be enabled if the details specified for it are valid.
    An account may need valid credentials associated with it before it can be
    enabled.
*/

bool Account::enabled() const
{
    if (d->status == Account::Invalid)
        return false;
    return d->enabled;
}

void Account::setEnabled(bool e)
{
    if (d->status == Account::Invalid || d->status == Account::SyncInProgress)
        return;

    d->enabled = e;
    if (d->status == Account::Initializing)
        d->enabledPendingInit = true;
    else
        d->setStatus(Account::Modified);
    emit enabledChanged();
}

/*!
    \qmlproperty int Account::identifier
    This property contains the identifier of the Account.

    The value of the property will be zero if the Account is a new, unsynced
    account.  If the Account has been saved in the system accounts database,
    it will be non-zero.

    When declaring an Account you may supply an identifier to cause
    the account to reference an account that already exists in the
    system accounts database.  Otherwise, you must supply a \c providerName
    to allow the Account to reference a new, unsaved account with the
    specified provider.

    Specifying both \c identifier and \c providerName in the Account
    declaration is an error.

    You may only set the identifier of the account after initialization
    if the identifier property was never initialized and no provider
    name was given.  Attempting to set the identifier of a previously
    initialized, valid account will have no effect.  Attempting to set
    the identifier of a previously initialized, invalidated account
    may result in undefined behaviour (e.g., incorrect signal emission).
*/

int Account::identifier() const
{
    if (d->status == Account::Invalid)
        return 0;
    return d->identifier;
}

void Account::setIdentifier(int id)
{
    if (d->status == Account::Initializing) {
        d->identifierPendingInit = true;
        d->identifier = id;
    } else if (id != d->identifier && d->status == Account::Invalid) {
        // the client is setting the account identifier after initialization.
        d->deleteLater();
        d = new AccountPrivate(this, 0);
        d->identifierPendingInit = true;
        d->identifier = id;
        emit statusChanged(); // manually emit - initializing.
        componentComplete();
    }
}

/*!
    \qmlproperty string Account::providerName

    This property contains the name of the service provider with which
    the account is valid.

    An account provider plugin will provide a \c{.provider} file in
    \c{/usr/share/accounts/providers} which specifies the name of the
    provider.
*/

QString Account::providerName() const
{
    if (d->status == Account::Invalid)
        return QString();
    return d->providerName;
}

/*!
    \qmlproperty string Account::displayName
    This property contains the display name of the account

    The display name is the name of the account which should be
    displayed to users in selection lists, edit dialogues, and
    other user-interface contexts.
*/

QString Account::displayName() const
{
    if (d->status == Account::Invalid)
        return QString();
    return d->displayName;
}

void Account::setDisplayName(const QString &dn)
{
    if (d->status == Account::Invalid || d->status == Account::SyncInProgress)
        return;

    d->displayName = dn;
    if (d->status == Account::Initializing)
        d->displayNamePendingInit = true;
    else
        d->setStatus(Account::Modified);
    emit displayNameChanged();
}

/*!
    \qmlproperty QStringList Account::supportedServiceNames
    This property contains the names of services supported by the account

    Every service provided by a provider has a service name which is
    specified in the \c{.service} file located at
    \c{/usr/share/accounts/services} which is installed by the account
    provider plugin.
*/

QStringList Account::supportedServiceNames() const
{
    if (d->status == Account::Invalid)
        return QStringList();
    return d->supportedServiceNames;
}


/*!
    \qmlproperty QStringList Account::enabledServiceNames
    This property contains the names of services for which the account is
    enabled.

    An account may be enabled with any service it supports, by calling
    enableWithService().  It may be disabled with a service by
    calling disableWithService().

    During account creation, the account should be enabled with any
    service for which it is valid, or as specified by the user.
*/

QStringList Account::enabledServiceNames() const
{
    if (d->status == Account::Invalid)
        return QStringList();
    return d->enabledServiceNames;
}


/*!
    \qmlproperty Account::Status Account::status
    This property contains the current database-sync status of the account

    An account may have any of five statuses:
    \table
        \header
            \li Status
            \li Description
        \row
            \li Synced
            \li No outstanding local modifications to the account have occurred since last sync().  Any previous sync() calls have completed.
        \row
            \li SyncInProgress
            \li Any outstanding local modifications are currently being written to the database due to a call to sync().  No local property modifications may occur while the account has this status.
        \row
            \li Modified
            \li Local modifications to the account have occurred since last sync().  In order to persist the changes to the database, sync() must be called.  Note that if another process modifies the canonical (database) version of the account, no signal will be emitted and thus the status of the local account representation will NOT automatically change to Modified.
        \row
            \li Error
            \li An error occurred during account creation or synchronisation.
        \row
            \li Invalid
            \li The account has been removed from the database and is no longer valid.
    \endtable

    Connecting to the account's statusChanged() signal is the usual
    way to handle database synchronisation events.
*/

Account::Status Account::status() const
{
    return d->status;
}


/*!
    \qmlproperty Account::Error Account::error
    This property contains the most recent error which occurred during
    account creation or synchronisation.

    Note that the error will NOT automatically return to \c{NoError}
    if subsequent synchronisation operations succeed.
*/

Account::ErrorType Account::error() const
{
    return d->error;
}


/*!
    \qmlproperty string Account::errorMessage
    This property contains the error message associated with the most
    recent error which occurred during account creation or synchronisation.

    Note that the error message will NOT automatically return to
    being empty if subsequent synchronisation operations succeed.
*/

QString Account::errorMessage() const
{
    return d->errorMessage;
}
