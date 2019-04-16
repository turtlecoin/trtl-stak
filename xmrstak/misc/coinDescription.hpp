#pragma once

#include "xmrstak/backend/cryptonight.hpp"

#include <stdlib.h>
#include <string>
#include <vector>
#include <algorithm>

namespace xmrstak
{
	struct coinDescription
	{

		xmrstak_algo algo = { xmrstak_algo_id::invalid_algo };
		uint8_t fork_version = 0u;
		xmrstak_algo algo_root = { xmrstak_algo_id::invalid_algo };

		coinDescription() = default;

		coinDescription(
			const xmrstak_algo in_algo,
			const uint8_t in_fork_version = 0,
			xmrstak_algo in_algo_root = xmrstak_algo_id::invalid_algo
		) :
			algo(in_algo), algo_root(in_algo_root), fork_version(in_fork_version)
		{}

		inline xmrstak_algo GetMiningAlgo(uint32_t height = 0, uint64_t memory = 0, uint32_t window = 0, uint32_t multiplier = 0) const {
			if (height > 0 && algo.algo_name == cryptonight_gold)
			{
				uint32_t  CN_GOLD_ITER = memory / 2;
				uint32_t  CN_GOLD_PAD_MULTIPLIER = (window / multiplier);
				uint32_t  CN_GOLD_ITER_MULTIPLIER = (CN_GOLD_PAD_MULTIPLIER / 2);

				uint32_t base_offset = (height % window);
				int32_t offset = (height % (window * 2)) - (base_offset * 2);
				if (offset < 0) {
					offset = base_offset;
				}

				uint32_t scratchpad = (CN_MEMORY / 8) + (static_cast<uint32_t>(offset) * CN_GOLD_PAD_MULTIPLIER);
				scratchpad = (static_cast<uint64_t>(scratchpad / 128)) * 128;
				uint32_t iterations = CN_GOLD_ITER + (static_cast<uint32_t>(offset) * CN_GOLD_ITER_MULTIPLIER);
				uint32_t mask = ((((scratchpad / 2)) - 1u) / 16) * 16;

				xmrstak_algo algo_gold = { xmrstak_algo_id::cryptonight_gold, xmrstak_algo_id::cryptonight_monero_v8, iterations/2, scratchpad, mask }; //iterations are divided by 2 to account for "lite" algo variation
				return algo_gold;
			}
			return algo;

		}
		inline xmrstak_algo GetMiningAlgoRoot(uint32_t height = 0, uint64_t memory = 0, uint32_t window = 0, uint32_t multiplier = 0) const {
			if (height > 0 && algo_root.algo_name == cryptonight_gold)
			{
				uint32_t  CN_GOLD_ITER = memory / 2;
				uint32_t  CN_GOLD_PAD_MULTIPLIER = (window / multiplier);
				uint32_t  CN_GOLD_ITER_MULTIPLIER = (CN_GOLD_PAD_MULTIPLIER / 2);

				uint32_t base_offset = (height % window);
				int32_t offset = (height % (window * 2)) - (base_offset * 2);
				if (offset < 0) {
					offset = base_offset;
				}

				uint32_t scratchpad = (CN_MEMORY / 8) + (static_cast<uint32_t>(offset) * CN_GOLD_PAD_MULTIPLIER);
				scratchpad = (static_cast<uint64_t>(scratchpad / 128)) * 128;
				uint32_t iterations = CN_GOLD_ITER + (static_cast<uint32_t>(offset) * CN_GOLD_ITER_MULTIPLIER);
				uint32_t mask = ((((scratchpad / 2)) - 1u) / 16) * 16;

				xmrstak_algo algo_gold = { xmrstak_algo_id::cryptonight_gold, xmrstak_algo_id::cryptonight_monero_v8, iterations / 2, scratchpad, mask }; //iterations are divided by 2 to account for "lite" algo variation
				return algo_gold;
			}
			return algo_root;
		}
		inline uint8_t GetMiningForkVersion() const { return fork_version; }
	};

	struct coin_selection
	{
		const char* coin_name = nullptr;
		/* [0] -> user pool
		 * [1] -> dev pool
		 */
		coinDescription pool_coin[2];
		const char* default_pool = nullptr;

		coin_selection() = default;

		coin_selection(
			const char* in_coin_name,
			const coinDescription user_coinDescription,
			const coinDescription dev_coinDescription,
			const char* in_default_pool
		) :
			coin_name(in_coin_name), default_pool(in_default_pool)
		{
			pool_coin[0] = user_coinDescription;
			pool_coin[1] = dev_coinDescription;
		}

		/** get coin description for the pool
		 *
		 * @param poolId 0 select dev pool, else the user pool is selected
		 */
		inline coinDescription GetDescription(size_t poolId) const {
			coinDescription tmp = (poolId == 0 ? pool_coin[1] : pool_coin[0]);
			return tmp;
		}

		/** return all POW algorithm for the current selected currency
		 *
		 * @return required POW algorithms without duplicated entries
		 */
		inline std::vector<xmrstak_algo> GetAllAlgorithms()
		{
			std::vector<xmrstak_algo> allAlgos = {
				GetDescription(0).GetMiningAlgo(),
				GetDescription(0).GetMiningAlgoRoot(),
				GetDescription(1).GetMiningAlgo(),
				GetDescription(1).GetMiningAlgoRoot()
			};

			std::sort(allAlgos.begin(), allAlgos.end());
			std::remove(allAlgos.begin(), allAlgos.end(), invalid_algo);
			auto last = std::unique(allAlgos.begin(), allAlgos.end());
			// remove duplicated algorithms
			allAlgos.erase(last, allAlgos.end());

			return allAlgos;
		}
	};
} // namespace xmrstak
