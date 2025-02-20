#pragma once

#include <map>
#include <dEnc/Defines.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "Dprf.h"
#include "LWE_helper.h"

namespace dEnc{
	class LWEAdapDprf : public Dprf{
    public:
    	
        LWEAdapDprf()
            : mServerDone(mServerDoneProm.get_future())
        {}

        LWEAdapDprf(LWEAdapDprf&&) = default;

        virtual ~LWEAdapDprf();

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

        // Three moduli of LWE-based DPRF
        static const int logq = 64, logq1 = 30, logp = 10;

        // length of LWEKey vector
        static const int dim = 256;
        static const int dim_ = 2 * dim * logq;
        static const int l = 4, L = 7;

        static NTL::Vec<NTL::vec_ZZ_p> A0;
        static NTL::Vec<NTL::Vec<NTL::Vec<NTL::vec_ZZ_p>>> matrix_list;

        // Random number generator
        oc::PRNG mPrng;
        // Internal flag that determines if the OPRF is currently closed.
        bool mIsClosed = true;

        void init(int partyId, span<Channel> requestChls, span<Channel> listenChls);
        static std::vector<int> LWEKey;
        static void KeyGen(int n, int m);
        std::vector<int> getSubkey(int groupId);

        virtual void serveOne(span<u8>request, u64 outputPartyIdx)override;
        virtual block eval(block input)override;
        virtual AsyncEval asyncEval(block input)override;
		virtual AsyncEval asyncEval(span<block> input)override;

        virtual void close()override;

        private:
        static std::map<int, std::map<int, std::vector<int>>> shared_key_repo_tT;
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