/*
 * Copyright (C) 2012 Jolla Ltd. <chris.adams@jollamobile.com>
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
 *   * Neither the name of Nemo Mobile nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
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

#include "servicetypeinterface.h"

class ServiceTypeInterfacePrivate
{
public:
    Accounts::ServiceType serviceType;
};

/*!
    \qmltype ServiceType
    \instantiates ServiceTypeInterface
    \inqmlmodule org.nemomobile.accounts 1
    \brief Reports information about a particular service type

    This type provides information about a particular service type
    of a service provided by a provider.
*/

ServiceTypeInterface::ServiceTypeInterface(const Accounts::ServiceType &serviceType, QObject *parent)
    : QObject(parent), d(new ServiceTypeInterfacePrivate)
{
    d->serviceType = serviceType;
}

ServiceTypeInterface::~ServiceTypeInterface()
{
    delete d;
}

/*!
    \qmlproperty string Service::name
    This property holds the name of the service
*/

QString ServiceTypeInterface::name() const
{
    return d->serviceType.name();
}

/*!
    \qmlproperty string Service::displayName
    This property holds the display name of the service.
    This display name can be displayed in lists or
    dialogues in the UI of applications.
*/

QString ServiceTypeInterface::displayName() const
{
    return d->serviceType.displayName();
}

/*!
    \qmlproperty string Service::iconName
    This property holds the name of the icon associated with the service
*/

QString ServiceTypeInterface::iconName() const
{
    return d->serviceType.iconName();
}

/*!
    \qmlproperty QStringList Service::tags
    This property holds the tags which have been associated with the service.
*/

QStringList ServiceTypeInterface::tags() const
{
    return d->serviceType.tags().toList();
}

