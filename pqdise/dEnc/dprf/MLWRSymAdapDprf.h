#pragma once

#include <map>
#include <dEnc/Defines.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "Dprf.h"
#include "LWR_helper.h"

namespace dEnc{
    class MLWRSymAdapDprf : public Dprf{
    public:
        
        MLWRSymAdapDprf()
            : mServerDone(mServerDoneProm.get_future())
        {}

        MLWRSymAdapDprf(MLWRSymAdapDprf&&) = default;

        virtual ~MLWRSymAdapDprf();

        // Callbacks that are used when a new DPRF evaluation
        // arrived over the network, i.e. mServerListenCallbacks[i]
        // is called when party i sends a request.
        std::vector<std::function<void()>> mServerListenCallbacks;

        // The index of this party
        int partyId;
        // The total number of parties in the DPRF protocol
        static int T;
        // The DPRF threshold. This many parties must be contacted.
        static int t;

        // Two moduli of LWR
        static const int logq = 64, logp = 10;
        // Modulus for partial evaluation
        static const int logq1 = 42;

        // length of MLWRKey vector
        static const int dim = 256;
        static const int rank = 4;
        // namespace NTL{
        
        // }
        // Random number generator
        oc::PRNG mPrng;
        // Internal flag that determines if the OPRF is currently closed.
        bool mIsClosed = true;
        

        // void init_modulus(u64 q);

        void init(int partyId, span<Channel> requestChls, span<Channel> listenChls);
        static NTL::Vec<NTL::ZZ_pX> MLWRKey;          
        static void KeyGen(int n, int m);
        NTL::Vec<NTL::ZZ_pX> getSubkey(int groupId);

        virtual void serveOne(span<u8>request, u64 outputPartyIdx)override;
        virtual block eval(block input)override;
        virtual AsyncEval asyncEval(block input)override;
        virtual AsyncEval asyncEval(span<block> input)override;

        virtual void close()override;
        
    private:
        static std::map<int, std::map<int, NTL::Vec<NTL::ZZ_pX>>> shared_key_repo_tT;
        static void shareSecrettTL(int T, int t);
        void startListening();

        // Buffers that are used to receive the client DPRF evaluation requests
        std::vector<std::vector<u8>> mRecvBuff;

        // A promise that is fulfilled when all of the server DPRF callbacks
        // have completed all of their work. This happens when all clients 
        // shut down the connections.
        std::promise<void> mServerDoneProm;

        // The future for mServerDoneProm.
        std::future<void> mServerDone;

        // The number of active callback loops. 
        std::atomic<u64> mListens;

        // Channels that the client should send their DPRF requests over.
        std::vector<Channel> mRequestChls;

        // Channels that the servers should listen to for DPRF requests.
        std::vector<Channel> mListenChls;
        
    };
}