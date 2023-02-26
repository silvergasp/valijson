#!/bin/bash -eu

git submodule update --init --depth 1 thirdparty

# This line causes an abort which breaks fuzzing:
sed -i '27d' include/valijson/utils/rapidjson_utils.hpp

mkdir build
cd build
cmake \
  -Dvalijson_BUILD_TESTS=FALSE \
  -Dvalijson_BUILD_EXAMPLES=FALSE \
	-Dvalijson_EXCLUDE_BOOST=TRUE \
	..

make -j"$(nproc)"

cd ../tests/fuzzing

# CXXFLAGS may contain spaces
# shellcheck disable=SC2086
"$CXX" $CXXFLAGS -DVALIJSON_USE_EXCEPTIONS=1 \
	-I/src/valijson/thirdparty/rapidjson/include \
	-I/src/valijson/thirdparty/rapidjson/include/rapidjson \
	-I/src/valijson/include \
	-I/src/valijson/include/valijson \
	-I/src/valijson/include/valijson/adapters \
	-c fuzzer.cpp -o fuzzer.o

# shellcheck disable=SC2086
"$CXX" $CXXFLAGS "$LIB_FUZZING_ENGINE" \
	-DVALIJSON_USE_EXCEPTIONS=1 \
	-rdynamic fuzzer.o \
	-o "${OUT}/fuzzer"

find ${SRC} -name '*.json' -exec zip ${OUT}/fuzzer_seed_corpus.zip {} \;
