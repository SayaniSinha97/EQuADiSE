// #pragma once

// #include <map>
// #include <dEnc/Defines.h>
// #include <cryptoTools/Common/Matrix.h>
// #include <cryptoTools/Crypto/PRNG.h>
// #include "Dprf.h"
// #include "LWR_helper.h"

// namespace dEnc{
// 	class LWRBaseDprf : public Dprf{
//     public:
    	
//         LWRBaseDprf()
//             : mServerDone(mServerDoneProm.get_future())
//         {}

//         LWRBaseDprf(LWRBaseDprf&&) = default;

//         virtual ~LWRBaseDprf();

//         // Callbacks that are used when a new DPRF evaluation
//         // arrived over the network, i.e. mServerListenCallbacks[i]
//         // is called when party i sends a request.
//         std::vector<std::function<void()>> mServerListenCallbacks;

//         // The index of this party
//         int partyId;
//         // The total number of parties in the DPRF protocol
//         static int T;
//         // The DPRF threshold. This many parties must be contacted.
//         static int t;

//         // Two moduli of LWR
//         // static const int logq = 64, logp = 10;
//         static const int logq = 32, logp = 10;
//         // static const u64 q = 4294967296, p = 256;
//         // Modulus for partial evaluation
//         // static const u64 q1 = 33554432;
//         // static const int logq1 = 30, logq2 = 61;

//         // length of LWRKey vector
//         // static const int dim = 256;
//         static const int dim = 512;
//         // namespace NTL{
        
//         // }
//         // Random number generator
//         oc::PRNG mPrng;
//         // Internal flag that determines if the OPRF is currently closed.
//         bool mIsClosed = true;

//         // static std::vector<u64> LWRKey;  
//         // static NTL::vec_ZZ_p LWRKey;          
//         // static void KeyGen(u64 n, u64 m);
//         // std::vector<u64> getSubkey(u64 groupId);
        

//         // void init_modulus(u64 q);

//         void init(int partyId, span<Channel> requestChls, span<Channel> listenChls);
//         // static NTL::vec_ZZ_p LWRKey;          
//         static void KeyGen(int n, int m);
//         // NTL::vec_ZZ_p getSubkey(int groupId);

//         virtual void serveOne(span<u8>request, u64 outputPartyIdx)override;
//         virtual block eval(block input)override;
//         virtual AsyncEval asyncEval(block input)override;
// 		virtual AsyncEval asyncEval(span<block> input)override;

//         virtual void close()override;
        
//     private:
//         // static std::map<int, std::map<int, std::vector<u64>>> shared_key_repo_tT;
//         static std::map<int, std::map<int, NTL::vec_ZZ_p>> shared_key_repo_tT;
//         static NTL::Vec<NTL::vec_ZZ_p> LWRBaseDprf::key_shares;
//         static std::vector<std::vector<int>> allocation_matrix;
//         // static void shareSecrettTL(int T, int t);
//     	void startListening();

//     	// Buffers that are used to receive the client DPRF evaluation requests
//         std::vector<std::vector<u8>> mRecvBuff;

//         // A promise that is fulfilled when all of the server DPRF callbacks
//         // have completed all of their work. This happens when all clients 
//         // shut down the connections.
//         std::promise<void> mServerDoneProm;

//         // The future for mServerDoneProm.
//         std::future<void> mServerDone;

//         // The number of active callback loops. 
//         std::atomic<u64> mListens;

//         // Channels that the client should send their DPRF requests over.
//         std::vector<Channel> mRequestChls;

//         // Channels that the servers should listen to for DPRF requests.
//         std::vector<Channel> mListenChls;
        
//     };
// }