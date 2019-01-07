# Build Instructions for Ubuntu 18.04 for Nvidia GPUs

## Install Dependencies

`sudo apt install libmicrohttpd-dev libssl-dev cmake build-essential libhwloc-dev`

## Download and install CUDA (for NVIDIA GPUs Only)

`wget https://developer.nvidia.com/compute/cuda/10.0/Prod/local_installers/cuda-repo-ubuntu1804-10-0-local-10.0.130-410.48_1.0-1_amd64`

`sudo dpkg -i cuda-repo-ubuntu1804-10-0-local-10.0.130-410.48_1.0-1_amd64`

`sudo apt-key add /var/cuda-repo-10-0-local-10.0.130-410.48/7fa2af80.pub`

`sudo apt-get update`

`sudo apt-get install cuda`

## clone the repo

`git clone https://github.com/turtlecoin/trtl-stak.git`

## set compiler to gcc-7

`export CC=gcc-7`

`export CXX=g++-7`

## make build directory and build (change -j threads to suit your processor)

`mkdir trtl-stak/build && cd $_ && cmake -DOpenCL_ENABLE=OFF .. && make -j8`
