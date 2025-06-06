#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright Contributors to the OpenColorIO Project.

set -ex

TAG="$1"

SUDO=$(command -v sudo >/dev/null 2>&1 && echo sudo || echo "")

git clone https://github.com/aous72/OpenJPH.git
cd OpenJPH

git checkout ${TAG}

cd build
cmake -DOJPH_ENABLE_TIFF_SUPPORT=OFF -DCMAKE_BUILD_TYPE=Release .. 
$SUDO cmake --build . \
      --target install \
      --config Release \
      --parallel 2

cd ../..
rm -rf OpenJPH
