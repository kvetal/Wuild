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
#include "SocketFrameHandler.h"
#include "CoordinatorTypes.h"

/// Definition of coordinator service structures
namespace Wuild
{

class CoordinatorListRequest : public SocketFrameExt
{
public:
	static const uint8_t s_frameTypeId = s_minimalUserFrameId + 1;
	using Ptr = std::shared_ptr<CoordinatorListRequest>;

	uint8_t             FrameTypeId() const override { return s_frameTypeId;}
	void                LogTo(std::ostream& os) const override { os << " REQUEST"; }
	State               ReadInternal(ByteOrderDataStreamReader &) override { return stOk;}
	State               WriteInternal(ByteOrderDataStreamWriter &) const override {return stOk;}
};

class CoordinatorListResponse : public SocketFrameExt
{
public:
	static const uint8_t s_frameTypeId = s_minimalUserFrameId + 2;
	using Ptr = std::shared_ptr<CoordinatorListResponse>;

	CoordinatorInfo m_info;
	WorkerSessionInfo::List m_latestSessions;

	void                LogTo(std::ostream& os) const override { os << m_info.ToString(); }
	uint8_t             FrameTypeId() const override { return s_frameTypeId;}

	State               ReadInternal(ByteOrderDataStreamReader &stream) override;
	State               WriteInternal(ByteOrderDataStreamWriter &stream) const override;
};

class CoordinatorWorkerStatus : public SocketFrameExt
{
public:
	static const uint8_t s_frameTypeId = s_minimalUserFrameId + 3;
	using Ptr = std::shared_ptr<CoordinatorWorkerStatus>;

	CoordinatorWorkerInfo m_info;

	void                LogTo(std::ostream& os) const override { os << " STATUS:" << m_info.ToString(); }
	uint8_t             FrameTypeId() const override { return s_frameTypeId;}

	State               ReadInternal(ByteOrderDataStreamReader &stream) override;
	State               WriteInternal(ByteOrderDataStreamWriter &stream) const override;
};

class CoordinatorWorkerSession : public SocketFrameExt
{
public:
	static const uint8_t s_frameTypeId = s_minimalUserFrameId + 4;
	using Ptr = std::shared_ptr<CoordinatorWorkerSession>;

	WorkerSessionInfo m_session;

	void                LogTo(std::ostream& os) const override { os << " SESSION:" << m_session.ToString(); }
	uint8_t             FrameTypeId() const override { return s_frameTypeId;}

	State               ReadInternal(ByteOrderDataStreamReader &stream) override;
	State               WriteInternal(ByteOrderDataStreamWriter &stream) const override;
};

}
