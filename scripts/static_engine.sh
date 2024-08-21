#! /bin/sh

if [ -z "$ENGINE_PATH" ]  || [ -z "$RTE_SDK" ]; then
    echo "Please export ENGINE_PATH and RTE_SDK env variables"
    exit
fi

#Create dir for engine
mkdir -p crypto/dpdkcpt

#copy engine files
cp $ENGINE_PATH/e_dpdkcpt* crypto/dpdkcpt/

#export LIBRARY PATH
export LD_LIBRARY_PATH=$RTE_SDK/build/lib
export LDFLAGS=-L$RTE_SDK/build/lib
export LDLIBS="-lrte_mempool -lrte_eal -lrte_bus_vdev -lrte_mbuf -lrte_cryptodev -lrte_kvargs -lrte_ring"
export RTE_SDK_INCLUDE=$RTE_SDK/build/include

#apply static engine patch
patch -p1 < $ENGINE_PATH/patches/static_engine.patch --dry-run -t
if [ -n $? ]; then
   echo "Applying patch"
   patch -p1 < $ENGINE_PATH/patches/static_engine.patch -t
fi
