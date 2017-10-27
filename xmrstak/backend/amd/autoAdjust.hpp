
#pragma once

#include "amd_gpu/gpu.hpp"
#include "autoAdjust.hpp"
#include "jconf.hpp"

#include "xmrstak/misc/console.hpp"
#include "xmrstak/misc/configEditor.hpp"
#include "xmrstak/params.hpp"
#include "xmrstak/backend/cryptonight.hpp"
#include "xmrstak/jconf.hpp"

#include <vector>
#include <cstdio>
#include <sstream>
#include <string>
#include <iostream>
#include  <algorithm>

#if defined(__APPLE__)
#include <OpenCL/cl.h>
#else
#include <CL/cl.h>
#endif


namespace xmrstak
{
namespace amd
{

class autoAdjust
{    
public:

    autoAdjust()
    {

    }

    /** print the adjusted values if needed
     *
     * Routine exit the application and print the adjusted values if needed else
     * nothing is happened.
     */
    bool printConfig()
    {
		int platformIndex = getAMDPlatformIdx();

		if(platformIndex == -1)
		{
			printer::inst()->print_msg(L0,"WARNING: No AMD OpenCL platform found. Possible driver issues or wrong vendor driver.");
			return false;
		}

		devVec = getAMDDevices(platformIndex);


		int deviceCount = devVec.size();

		if(deviceCount == 0)
		{
			printer::inst()->print_msg(L0,"WARNING: No AMD device found.");
			return false;
		}

        generateThreadConfig(platformIndex);
		return true;
    }

private:

    void generateThreadConfig(const int platformIndex)
    {
		// load the template of the backend config into a char variable
		const char *tpl =
			#include "./config.tpl"
		;

		configEditor configTpl{};
		configTpl.set( std::string(tpl) );

		constexpr size_t byteToMiB = 1024u * 1024u;

		size_t hashMemSize;
		if(::jconf::inst()->IsCurrencyMonero())
		{
			hashMemSize = MONERO_MEMORY;
		}
		else
		{
			hashMemSize = AEON_MEMORY;
		}

		std::string conf;
        int i = 0;
        for(auto& ctx : devVec)
        {
			// keep 128MiB memory free (value is randomly chosen)
			size_t availableMem = ctx.freeMem - (128u * byteToMiB);
			// 224byte extra memory is used per thread for meta data
			size_t perThread = hashMemSize + 224u;
			size_t max_intensity = availableMem / perThread;
			// 1000 is a magic selected limit \todo select max intensity depending of the gpu type
			size_t possibleIntensity = std::min( size_t(1000u) , max_intensity );
			// map intensity to a multiple of the compute unit count, 8 is the number of threads per work group
			size_t intensity = (possibleIntensity / (8 * ctx.computeUnits)) * ctx.computeUnits * 8;
			conf += std::string("  // gpu: ") + ctx.name + " memory:" + std::to_string(availableMem / byteToMiB) + "\n";
			conf += std::string("  // compute units: ") + std::to_string(ctx.computeUnits) + "\n";
			// set 8 threads per block (this is a good value for the most gpus)
            conf += std::string("  { \"index\" : ") + std::to_string(ctx.deviceIdx) + ",\n" +
                "    \"intensity\" : " + std::to_string(intensity) + ", \"worksize\" : " + std::to_string(8) + ",\n" +
                "    \"affine_to_cpu\" : false, \n"
                "  },\n";
            ++i;
        }

		configTpl.replace("PLATFORMINDEX",std::to_string(platformIndex));
		configTpl.replace("GPUCONFIG",conf);
		configTpl.write(params::inst().configFileAMD);
		printer::inst()->print_msg(L0, "AMD: GPU configuration stored in file '%s'", params::inst().configFileAMD.c_str());
    }

    std::vector<GpuContext> devVec;
};

} // namespace amd
} // namepsace xmrstak
