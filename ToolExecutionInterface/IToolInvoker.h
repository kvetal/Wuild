/*
 * Copyright (C) 2018 Smirnov Vladimir mapron1@gmail.com
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

#include "ToolInvocation.h"

#include <TimePoint.h>

#include <functional>

namespace Wuild
{
/// Interface for execution tasks on local host.
class IToolInvoker
{
public:
	/// Remote tool execution result.
	/// @todo: merge with LocalExecutorResult.
	struct TaskExecutionInfo
	{
		TimePoint m_toolExecutionTime;
		TimePoint m_networkRequestTime;
		std::string GetProfilingStr() const;

		std::string m_stdOutput;
		bool m_result = false;

		TaskExecutionInfo(const std::string & stdOutput = std::string()) : m_stdOutput(stdOutput) {}
	};

	using InvokeCallback = std::function<void(const TaskExecutionInfo& )>;
public:
	virtual ~IToolInvoker() = default;

	/// Starts new remote task.
	virtual void InvokeTool(const ToolInvocation & invocation, InvokeCallback callback) = 0;
};
}
