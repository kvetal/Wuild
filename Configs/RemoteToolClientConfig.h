/*
 * Copyright (C) 2017 Smirnov Vladimir mapron1@gmail.com
 * Source code licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 or in file COPYING-APACHE-2.0.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.h
 */

#pragma once
#include "IConfig.h"
#include "CoordinatorClientConfig.h"

#include <FileUtils.h>

namespace Wuild
{
class RemoteToolClientConfig : public IConfig
{
public:
	TimePoint m_queueTimeout = 10.0;
	TimePoint m_requestTimeout = 240.0;
	int m_invocationAttempts = 2;
	int m_minimalRemoteTasks = 10;
	std::string m_clientId;
	CoordinatorClientConfig m_coordinator;
	CompressionInfo m_compression;
	bool m_resetConnectionOnFailure = true;
	int m_resetConnectionAttempts = 5;
	bool Validate(std::ostream * errStream = nullptr) const override;
};
}
