#pragma once

#include "xmrstak/backend/pool_data.hpp"

#include <thread>
#include <atomic>
#include <mutex>
#include <cstdint>
#include <iostream>
#include <cassert>
#include <cstring>

namespace xmrstak
{
	struct miner_work
	{
		char        sJobID[64];
		uint8_t     bWorkBlob[112];
		uint32_t    iWorkSize;
		uint64_t    iTarget;
		bool        bNiceHash;
		bool        bStall;
		size_t      iPoolId;
		uint32_t    iMajorVersion;
		uint32_t    iMinorVersion;
		uint64_t	iBlockHeight;
		uint64_t    iMemory;
		uint32_t    iWindow;
		uint32_t    iMultiplier;
		uint8_t*	ref_ptr;

		miner_work() : iWorkSize(0), bNiceHash(false), bStall(true), iPoolId(invalid_pool_id), ref_ptr((uint8_t*)&iBlockHeight) { }

		miner_work(const char* sJobID, const uint8_t* bWork, uint32_t iWorkSize,
			uint64_t iTarget, bool bNiceHash, size_t iPoolId, uint32_t iMajorVersion, uint32_t iMinorVersion, uint64_t iBlockHeight, uint64_t iMemory, uint32_t iWindow, uint32_t iMultiplier) : iWorkSize(iWorkSize),
			iTarget(iTarget), bNiceHash(bNiceHash), bStall(false), iPoolId(iPoolId), iMajorVersion(iMajorVersion), iMinorVersion(iMinorVersion), iBlockHeight(iBlockHeight), iMemory(iMemory), iWindow(iWindow), iMultiplier(iMultiplier), ref_ptr((uint8_t*)&iBlockHeight)
		{
			assert(iWorkSize <= sizeof(bWorkBlob));
			memcpy(this->bWorkBlob, bWork, iWorkSize);
			memcpy(this->sJobID, sJobID, sizeof(miner_work::sJobID));
		}

		miner_work(miner_work&& from) : iWorkSize(from.iWorkSize), iTarget(from.iTarget),
			bStall(from.bStall), iPoolId(from.iPoolId), iMajorVersion(from.iMajorVersion), iMinorVersion(from.iMinorVersion), iBlockHeight(from.iBlockHeight), iMemory(from.iMemory), iWindow(from.iWindow), iMultiplier(from.iMultiplier), ref_ptr((uint8_t*)&iBlockHeight)
		{
			assert(iWorkSize <= sizeof(bWorkBlob));
			memcpy(bWorkBlob, from.bWorkBlob, iWorkSize);
			memcpy(this->sJobID, sJobID, sizeof(miner_work::sJobID));
		}

		miner_work(miner_work const&) = delete;

		miner_work& operator=(miner_work&& from)
		{
			assert(this != &from);

			iBlockHeight = from.iBlockHeight;
			iPoolId = from.iPoolId;
			bStall = from.bStall;
			iWorkSize = from.iWorkSize;
			bNiceHash = from.bNiceHash;
			iTarget = from.iTarget;
			iMajorVersion = from.iMajorVersion;
			iMinorVersion = from.iMinorVersion;
			iMemory = from.iMemory;
			iWindow = from.iWindow;
			iMultiplier = from.iMultiplier;

			assert(iWorkSize <= sizeof(bWorkBlob));
			memcpy(sJobID, from.sJobID, sizeof(sJobID));
			memcpy(bWorkBlob, from.bWorkBlob, iWorkSize);

			return *this;
		}

		miner_work& operator=(miner_work const& from)
		{
			assert(this != &from);

			iBlockHeight = from.iBlockHeight;
			iPoolId = from.iPoolId;
			bStall = from.bStall;
			iWorkSize = from.iWorkSize;
			bNiceHash = from.bNiceHash;
			iTarget = from.iTarget;
			iMajorVersion = from.iMajorVersion;
			iMinorVersion = from.iMinorVersion;
			iMemory = from.iMemory;
			iWindow = from.iWindow;
			iMultiplier = from.iMultiplier;

			//
			if(!ref_ptr)
				return *this;
			if (iMemory == 0 || iWindow == 0 || iMultiplier == 0) {
				for (size_t i = 0; i <= 7 && iPoolId; i++)
					ref_ptr[i] = from.ref_ptr[7 - i];
			}

			assert(iWorkSize <= sizeof(bWorkBlob));
			memcpy(sJobID, from.sJobID, sizeof(sJobID));
			memcpy(bWorkBlob, from.bWorkBlob, iWorkSize);

			return *this;
		}

		uint8_t getVersion() const
		{
			if (iMajorVersion != 0)
			{
				return (uint8_t)iMajorVersion;
			}
			return bWorkBlob[0];
		}

		uint64_t getHeight() const
		{
			return (uint64_t)iBlockHeight;
		}

		uint64_t getMemory() const
		{
			return (uint64_t)iMemory;
		}

		uint32_t getWindow() const
		{
			return (uint32_t)iWindow;
		}

		uint32_t getMultiplier() const
		{
			return (uint32_t)iMultiplier;
		}

	};
} // namespace xmrstak