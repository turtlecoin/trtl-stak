#!/bin/sh

BUILD_DIRECTORY=`pwd`
echo "Checking Environment..."
echo "CUDA_ROOT=${CUDA_ROOT}"
echo "OpenCL_ROOT=${OpenCL_ROOT}"
echo "TRAVIS_OS_NAME=${TRAVIS_OS_NAME}"
echo ""
echo ""

if [ "${TRAVIS_OS_NAME}" != "osx" ]; then
  # CUDA SETUP
  echo -n "Looking for CUDA Toolkit... "
  if [ ! -e ${CUDA_ROOT}/bin/nvcc ]; then
    echo "Not found. Fetching..." && echo "" && echo ""
    mkdir -p $CUDA_ROOT &&
    cd $CUDA_ROOT &&
    wget https://developer.nvidia.com/compute/cuda/8.0/prod/local_installers/cuda_8.0.44_linux-run &&
    ls -la &&
    chmod u+x *-run &&
    ./cuda_8.0.44_linux-run --silent --toolkit --toolkitpath=$CUDA_ROOT &&
    rm -rf ./cuda_8.0.44_linux-run $CUDA_ROOT/{samples,jre,doc,share} &&
    cd -;
  else
    echo "Found" && echo "" && echo ""
  fi;
  
  # AMD SETUP
  echo -n "Looking for OpenCL Toolkit... "
  if [ ! -e $OpenCL_ROOT/lib/x86_64/libOpenCL.so ]; then
    echo "Not found. Fetching..." && echo "" && echo ""
    wget https://www.dropbox.com/s/kv4ctyx6pydodn3/AMD-APP-SDKInstaller-v3.0.130.136-GA-linux64.tar.bz2?dl=1  &&
    ls -la &&
    tar xvf AMD-APP-SDKInstaller-v3.0.130.136-GA-linux64.tar.bz2?dl=1 &&
    expect scripts/amdsdk/install.expect &&
    rm -rf AMD-APP* &&
    rm -rf $OpenCL_ROOT/lib/x86_64/libOpenCL.so &&
    ln -s $OpenCL_ROOT/lib/x86_64/sdk/libOpenCL.so.1 $OpenCL_ROOT/lib/x86_64/libOpenCL.so &&
    cd -;
  else
    echo "Found" && echo "" && echo ""
  fi;
else
  brew install hwloc
fi;
