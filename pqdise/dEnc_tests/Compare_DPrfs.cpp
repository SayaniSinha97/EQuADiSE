#include <math.h>
#include <time.h>
#include <omp.h>
#include <random>
#include <dEnc/dprf/Dprf.h>
#include <dEnc/dprf/LWRSymDprf.h>
#include <dEnc/dprf/LWRSymAdapDprf.h>
#include <dEnc/dprf/MLWRSymAdapDprf.h>
#include <dEnc/dprf/LWEAdapDprf.h>
// #include <dEnc/dprf/LWR_helper.h>
#include <dEnc/dprf/Npr03SymDprf.h>
#include <dEnc/dprf/Npr03AsymDprf.h>
#include <dEnc/dprf/AsymAdapDprf.h>
#include <dEnc/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/MatrixView.h>
#include "Compare_DPrfs.h"
#include <cryptoTools/Crypto/RCurve.h>
// #define THREADNUM 2
#define BATCHSIZE 20


namespace dEnc{
	std::random_device rd_;
	std::mt19937_64 eng_(rd_());
	std::uniform_int_distribution<u64> distr_;
	std::uniform_int_distribution<> distr1(0, 15);
	std::uniform_int_distribution<> distr1_(0, 63);
	using Num = oc::REccNumber;
    using Point = oc::REccPoint;
    using RandomOracle = oc::RandomOracle;

	// generate key shares on the fly for parties in a t-sized subset with group_id = group_id. Thus we avoid storing all the key-shares 
	// of all the parties beforehand for the performance evaluation purpose here.

    void generate_shares(std::vector<NTL::vec_ZZ_p> &key_shares, int t, int T, u64 q, int n, NTL::vec_ZZ_p key){
		using namespace NTL;
		VectorCopy(key_shares[0], key, n);
		for(int i = 1; i < t; i++){
			random(key_shares[i], n);
			key_shares[0] += key_shares[i];
		}
	}

	void generate_shares_base_adap(std::vector<NTL::vec_ZZ_p> &key_shares, int t, int T, int logq, int n, std::vector<std::vector<int>> &allocation_matrix){
		using namespace NTL;
	    ZZ_p::init(conv<ZZ>(pow(2,logq)));

		allocation_matrix.resize(T);
		std::vector<int> parties;
		int share_count = ncr(T, T-t+1);
		std::cout << share_count << "\n";
		key_shares.resize(share_count);
		// int per_party_share_count = nCr(T-1, T-t);
		
		for(int i = 0; i < share_count; i++){
			NTL::random(key_shares[i], n);
			findParties_adap(parties, i+1, T-t+1, T);
			// std::cout << "(T-t+1) sized set:\n";
			// for(int j = 0; j < parties.size(); j++){
			// 	std::cout << parties[j] << " ";
			// }
			// std::cout << "\n";
			for(int j = 0; j < T-t+1; j++){
				allocation_matrix[parties[j]-1].push_back(i);
			}
		}
		// std::cout << "allocation_matrix\n";
		// for(int i = 0; i < allocation_matrix.size(); i++){
		// 	for(int j = 0; j < allocation_matrix[i].size(); j++){
		// 		std::cout << allocation_matrix[i][j] << " ";
		// 	}
		// 	std::cout << "\n";
		// }
	}

	std::vector<int> get_key_ids_to_use(int cur_partyid, int gid, int t, int T, std::vector<std::vector<int>> allocation_matrix){
		std::vector<int> key_ids;
		std::vector<int> parties;
		findParties_adap(parties, gid, t, T);
		int share_count = ncr(T, T-t+1);
		int per_party_share_count = ncr(T-1, T-t);
		std::vector<int> ifAllocated;
		ifAllocated.resize(share_count, 0);
		for(int i = 0; i < t; i++){
			if(parties[i] != cur_partyid){
				for(int j = 0; j < per_party_share_count; j++){
					ifAllocated[allocation_matrix[parties[i]-1][j]] = 1;
				}
			}
			else{
				for(int j = 0; j < per_party_share_count; j++){
					if(ifAllocated[allocation_matrix[cur_partyid-1][j]] == 0){
						key_ids.push_back(allocation_matrix[cur_partyid-1][j]);
					}
				}
				break;
			}
		}	
		return key_ids;
	}

	void generate_shares_adap(std::vector<NTL::vec_ZZ_p> &key_shares, int t, int T, int n, NTL::vec_ZZ_p key){
		using namespace NTL;
		VectorCopy(key_shares[0], key, n);
		for(int i = 1; i < t; i++){
			random(key_shares[i], n);
			key_shares[0] += key_shares[i];
		}
	}
	void generate_shares_adap_mlwr(std::vector<NTL::Vec<NTL::ZZ_pX>> &key_shares, int t, int T, int dim, int rank, NTL::Vec<NTL::ZZ_pX> key){
		using namespace NTL;
		for(int i = 1; i <= rank; i++){
			key_shares[0](i) = key(i);
		}
		for(int i = 1; i < t; i++){
			for(int j = 1; j <= rank; j++){
				NTL::random(key_shares[i](j), dim);
				key_shares[0](j) += key_shares[i](j);
			}
		}
	}

	void generate_shares_adap_lwe(std::vector<std::vector<int>> &key_shares, int t, int T, int dim, std::vector<int> key){
		for(int i = 0; i < dim; i++){
			key_shares[0][i] = key[i];
		}
		for(int i = 1; i < t; i++){
			for(int j = 0; j < dim; j++){
				key_shares[i][j] = distr1_(eng_);
				key_shares[0][j] += key_shares[i][j];
			}
		}
	}

	// initialize a DPRF along with necessary member variables. we avoid initializing of party-to-party communication related variables here.
	// void init_dprf(Npr03SymDprf* dprf, int i, int t, int T, block seed, oc::Matrix<u64>& keyStructure, span<block> keys){
	void init_dprf(Npr03SymDprf* dprf, int i, int t, int T, block seed){
		dprf->mPartyIdx = i;
		dprf->mPrng.SetSeed(seed);
		dprf->mM = t;
		dprf->mN = T;
        auto subsetSize = dprf->mN - dprf->mM + 1;
        dprf->mD = ncr(dprf->mN, subsetSize);
		dprf->mDefaultKeys.resize(dprf->mN);
	}

	void init_dprf_Asym(Npr03AsymDprf* dprf, int i, int t, int T, block seed, Dprf::Type type, Num sk, span<Point> gSks){
		dprf->mPartyIdx = i;
        dprf->mM = t;
        dprf->mN = T;
        dprf->mType = type;
        dprf->mPrng.SetSeed(seed);
        if (gSks.size() != dprf->mN * (type == Dprf::Type::Malicious))
            throw std::runtime_error("Commitments to the secret keys is required for malicious security. " LOCATION);
        dprf->mSk = sk;
        dprf->mGSks = { gSks.begin(), gSks.end() };
        oc::REllipticCurve curve;
        dprf->mGen = curve.getGenerator();
        dprf->mDefaultLag.resize(dprf->mM);

        std::vector<Num> xi(dprf->mM);
        for (u64 i = 0, j = dprf->mPartyIdx; i < dprf->mM; ++i, ++j)
            xi[i] = (j % dprf->mN) + 1;
        for (i64 i = 0; i < dprf->mM; ++i){
            auto& l_i = dprf->mDefaultLag[i];
            l_i = 1;
            for (u64 j = 0; j < t; ++j)
                if (j != i) l_i *= xi[j] / (xi[j] - xi[i]);
        }
        dprf->mTempPoints.resize(6);
        dprf->mTempNums.resize(6);

	}

	// void init_dprf_AsymAdap(AsymAdapDprf* dprf, int i, int t, int T, block seed, Dprf::Type type, Num sk_left, Num sk_right, span<Point> gSks){
	void init_dprf_AsymAdap(AsymAdapDprf* dprf, int i, int t, int T, block seed, Dprf::Type type, Num sk_left, Num sk_right){
		dprf->mPartyIdx = i;
        dprf->mM = t;
        dprf->mN = T;
        dprf->mType = type;
        dprf->mPrng.SetSeed(seed);
        // if (gSks.size() != dprf->mN * (type == Dprf::Type::Malicious))
        //     throw std::runtime_error("Commitments to the secret keys is required for malicious security. " LOCATION);
        dprf->mSk_left = sk_left;
        dprf->mSk_right = sk_right;
        // dprf->mGSks = { gSks.begin(), gSks.end() };
        oc::REllipticCurve curve;
        dprf->mGen = curve.getGenerator();
        dprf->mDefaultLag.resize(dprf->mM);

        std::vector<Num> xi(dprf->mM);
        for (u64 i = 0, j = dprf->mPartyIdx; i < dprf->mM; ++i, ++j)
            xi[i] = (j % dprf->mN) + 1;
        for (i64 i = 0; i < dprf->mM; ++i){
            auto& l_i = dprf->mDefaultLag[i];
            l_i = 1;
            for (u64 j = 0; j < t; ++j)
                if (j != i) l_i *= xi[j] / (xi[j] - xi[i]);
        }
        dprf->mTempPoints.resize(6);
        dprf->mTempNums.resize(6);

	}

	void set_default_keys(Npr03SymDprf* dprf, int leader, u64 sz, PRNG &prng){
		std::vector<block> tmp_keys;
		tmp_keys.resize(sz);
		for(u64 j = 0; j < tmp_keys.size(); j++){
			tmp_keys[j] = prng.get<block>();
		}
		dprf->mDefaultKeys[leader].setKeys(tmp_keys);
		// std::vector<std::vector<block>> tmp_keys(sz, std::vector<block>(2));
		// // tmp_keys.resize(sz);
		// for(u64 j = 0; j < tmp_keys.size(); j++){
		// 	tmp_keys[j][0] = prng.get<block>();
		// 	tmp_keys[j][1] = prng.get<block>();
		// }
		// dprf->mDefaultKeys[leader].setKeys(tmp_keys);
	}

	void compare_partial_evaluations_NPRASym(int iters, int t, int T){
		std::cout << "inside compare_partial_evaluations NPRAsym:\n";

		// inp is the input block, on which PRF is evaluated, b is temporary block variable
		block inp;

		// number of possible t-sized subsets out of T parties
		int group_count = ncr(T,t);

		// if group_count is too big, we just go for 100000 t-sized subset and average the partial evaluation time over those values
		int iters2 = std::min(group_count, 1000);

		// a t-sized vector storing the party-ids in a t-sized subset
		std::vector<int> collaborators;
		collaborators.resize(t);

		// local variable to store current party id during iteration over t-sized subset
		int cur_party, leader;

		// this array stores the time required by each party of the t-sized subset to perform the partial evaluation
    	u64 *partial_eval_time = (u64*)calloc(t, sizeof(u64));

    	// stores the time required for combining the partial evaluations
    	u64 final_eval_time = 0;

    	// temporary variable to store partial/final evaluation time at some iteration
    	u64 part_reqd_time, final_reqd_time;

    	// declaring T DPRFs corresponding to T parties
		std::vector<Npr03AsymDprf> dprfs(T);

		// initializing PRNG, will be used to generate (pseudo)random block of input inp
		oc::PRNG prng(oc::sysRandomSeed());

		auto type = Dprf::Type::SemiHonest;

	    Npr03AsymDprf::MasterKey mk;
	    mk.KeyGen(T, t, prng, type);

	    // initialize all T DPRFs
		for (int i = 0; i < T; ++i){
			// init_dprf(u64 partyIdx, u64 m, span<Channel> requestChls, span<Channel> listChls, block seed, Type  type, Num sk, span<Point> gSks);
			init_dprf_Asym(&dprfs[i], i, t, T, prng.get<block>(), type, mk.mKeyShares[i], mk.mCommits);
    	}

    	std::vector<oc::REccPoint> part_evals;
    	part_evals.resize(t);

    	Point anypoint;
		Point zero = anypoint;
		zero = zero - anypoint; 

    	for(int it = 0; it < iters; it++){
    		inp = prng.get<block>();
    		std::cout << "Iter " << it << " starts.\n";
			for(int group_id = 1; group_id <= iters2; group_id++){
				findParties_adap(collaborators, group_id, t, T);
				Point final_res = zero;
				// std::cout << "initial value of final_res: " << final_res << "\n";
				struct timespec finaleval_start = {0, 0};
				struct timespec finaleval_end = {0, 0};
				for(int i = 0; i < t; i++){
					cur_party = collaborators[i]-1;
					leader = collaborators[0] - 1;
					struct timespec parteval_start = {0, 0};
					struct timespec parteval_end = {0, 0};
					clock_gettime(CLOCK_MONOTONIC, &parteval_start);
					oc::REccPoint v;
					v.randomize(inp);
					part_evals[i] = v * (dprfs[cur_party].mSk);
					clock_gettime(CLOCK_MONOTONIC, &parteval_end);
					// std::cout << "i: " << i << ", part eval: " << part_evals[i] << "\n";
					part_reqd_time = (((double)parteval_end.tv_nsec + 1.0e+9 * parteval_end.tv_sec) - ((double)parteval_start.tv_nsec + 1.0e+9 * parteval_start.tv_sec)) * 1.0e-3;
					partial_eval_time[i] += part_reqd_time;
				}
				clock_gettime(CLOCK_MONOTONIC, &finaleval_start);
				for(int i = 0; i < t; i++){
					cur_party = collaborators[i]-1;
					final_res += part_evals[i] * (dprfs[leader].mDefaultLag[cur_party]);
				}
				clock_gettime(CLOCK_MONOTONIC, &finaleval_end);
				final_reqd_time = ((double)finaleval_end.tv_nsec + 1.0e+9 * finaleval_end.tv_sec) - ((double)finaleval_start.tv_nsec + 1.0e+9 * finaleval_start.tv_sec);
				final_eval_time += final_reqd_time;
				// std::cout << "final res: " << final_res << "\n";
				final_res.~REccPoint();
			}
    	}
    	for(int i = 0; i < t; i++){
			// std::cout << "i: " << i << ", total part eval time (in microseconds): " << partial_eval_time[i] << "\n";
			partial_eval_time[i] = partial_eval_time[i] / (iters * iters2);
			std::cout << "i: " << i << ", avg part eval time (in microseconds): " << partial_eval_time[i] << "\n";
		}
		std::cout << "============== avg final eval time (in nanoseconds): " << final_eval_time / (iters * iters2) << "\n";
	}

	void compare_partial_evaluations_ASymAdap(int iters, int t, int T){
		std::cout << "inside compare_partial_evaluations AsymAdap:\n";

		// inp is the input block, on which PRF is evaluated, b is temporary block variable
		block inp;

		// number of possible t-sized subsets out of T parties
		int group_count = ncr(T,t);

		// if group_count is too big, we just go for 100000 t-sized subset and average the partial evaluation time over those values
		int iters2 = std::min(group_count, 500);

		// a t-sized vector storing the party-ids in a t-sized subset
		std::vector<int> collaborators;
		collaborators.resize(t);

		// local variable to store current party id during iteration over t-sized subset
		int cur_party, leader;

		// this array stores the time required by each party of the t-sized subset to perform the partial evaluation
    	u64 *partial_eval_time = (u64*)calloc(t, sizeof(u64));

    	// stores the time required for combining the partial evaluations
    	u64 final_eval_time = 0;

    	// temporary variable to store partial/final evaluation time at some iteration
    	u64 part_reqd_time, final_reqd_time;

    	// declaring T DPRFs corresponding to T parties
		std::vector<AsymAdapDprf> dprfs(T);

		// initializing PRNG, will be used to generate (pseudo)random block of input inp
		oc::PRNG prng(oc::sysRandomSeed());

		auto type = Dprf::Type::SemiHonest;

	    AsymAdapDprf::MasterKey mk;
	    mk.KeyGen(T, t, prng, type);

	    // initialize all T DPRFs
	    for (int i = 0; i < T; ++i){
			// init_dprf_AsymAdap(&dprfs[i], i, t, T, prng.get<block>(), type, mk.mKeyShares_left[i], mk.mKeyShares_right[i], mk.mCommits);
			init_dprf_AsymAdap(&dprfs[i], i, t, T, prng.get<block>(), type, mk.mKeyShares_left[i], mk.mKeyShares_right[i]);
    	}

    	std::vector<oc::REccPoint> part_evals;
    	part_evals.resize(t);

    	Point anypoint;
		Point zero = anypoint;
		zero = zero - anypoint; 

    	for(int it = 0; it < iters; it++){
    		inp = prng.get<block>();
    		std::vector<block> inp_;
    		inp_.resize(2);
    		RandomOracle Hash1(16);
			Hash1.Update(inp);
			Hash1.Update(1);
			Hash1.Final(inp_[0]);

			RandomOracle Hash2(16);
			Hash2.Update(inp);
			Hash2.Update(2);
			Hash2.Final(inp_[1]);

    		std::cout << "Iter " << it << " starts.\n";
			for(int group_id = 1; group_id <= iters2; group_id++){
				findParties_adap(collaborators, group_id, t, T);
				Point final_res = zero;
				struct timespec finaleval_start = {0, 0};
				struct timespec finaleval_end = {0, 0};
				for(int i = 0; i < t; i++){
					cur_party = collaborators[i]-1;
					leader = collaborators[0] - 1;
					struct timespec parteval_start = {0, 0};
					struct timespec parteval_end = {0, 0};
					clock_gettime(CLOCK_MONOTONIC, &parteval_start);
					oc::REccPoint v_left, v_right;
					v_left.randomize(inp_[0]);
					v_right.randomize(inp_[1]);
					part_evals[i] = v_left * (dprfs[cur_party].mSk_left);
					part_evals[i] += v_right * (dprfs[cur_party].mSk_right);
					clock_gettime(CLOCK_MONOTONIC, &parteval_end);
					part_reqd_time = (((double)parteval_end.tv_nsec + 1.0e+9 * parteval_end.tv_sec) - ((double)parteval_start.tv_nsec + 1.0e+9 * parteval_start.tv_sec)) * 1.0e-3;
					partial_eval_time[i] += part_reqd_time;
				}
				clock_gettime(CLOCK_MONOTONIC, &finaleval_start);
				for(int i = 0; i < t; i++){
					cur_party = collaborators[i]-1;
					final_res += part_evals[i] * (dprfs[leader].mDefaultLag[cur_party]);
				}
				clock_gettime(CLOCK_MONOTONIC, &finaleval_end);
				final_reqd_time = ((double)finaleval_end.tv_nsec + 1.0e+9 * finaleval_end.tv_sec) - ((double)finaleval_start.tv_nsec + 1.0e+9 * finaleval_start.tv_sec);
				final_eval_time += final_reqd_time;
				// std::cout << "final res: " << final_res << "\n";
				final_res.~REccPoint();
			}
    	}
    	for(int i = 0; i < t; i++){
			partial_eval_time[i] = partial_eval_time[i] / (iters * iters2);
			std::cout << "i: " << i << ", avg part eval time (in microseconds): " << partial_eval_time[i] << "\n";
		}
		std::cout << "============== avg final eval time (in nanoseconds): " << final_eval_time / (iters * iters2) << "\n";
	}

	void compare_partial_evaluations_NPRSym(int iters, int t, int T){
		std::cout << "inside compare_partial_evaluations NPRSym:\n";
		// inp is the input block, on which PRF is evaluated, b is temporary block variable
		block inp, b;

		// final_res stores the result after combining partial evals of t parties
		block final_res;

		// declaring T DPRFs corresponding to T parties
		std::vector<Npr03SymDprf> dprfs(T);

		// initializing PRNG, will be used to generate (pseudo)random block of input inp
		oc::PRNG prng(oc::sysRandomSeed());

    	// initialize all T DPRFs
    	for (int i = 0; i < T; ++i){
			// init_dprf(&dprfs[i], i, t, T, oc::toBlock(i), mk.keyStructure, mk.getSubkey(i));
			init_dprf(&dprfs[i], i, t, T, oc::toBlock(i));
    	}
	   	// std::vector<oc::AES> keys(dprfs[0].mD);
		// for (auto i = 0; i < keys.size(); ++i){
		// 	keys[i].setKey(mk.keys[i]);
		// }

		// this array stores the time required by each party of the t-sized subset to perform the partial evaluation
    	u64 *partial_eval_time = (u64*)calloc(t, sizeof(u64));

    	// stores the time required for combining the partial evaluations
    	u64 final_eval_time = 0;

    	// local variable to store current party id during iteration over t-sized subset
    	int cur_party, leader;

    	// temporary variable to store partial/final evaluation time at some iteration
    	u64 part_reqd_time, final_reqd_time;

    	// number of possible t-sized subsets out of T parties
		int group_count = ncr(T,t);

		// if group_count is too big, we just go for 100000 t-sized subset and average the partial evaluation time over those values
		int iters2 = std::min(group_count, 1000);
		std::cout << "iters2: " << iters2 << "\n";

		// a t-sized vector storing the party-ids in a t-sized subset
		std::vector<int> collaborators;
		collaborators.resize(t);

		std::vector<block> part_evals;
		part_evals.resize(t);
		// std::vector<block> mykey(2);
		// mykey[0] = prng.get<block>();
		// mykey[1] = prng.get<block>();

    	for(int it = 0; it < iters; it++){
    		inp = prng.get<block>();
    		std::cout << "Iter " << it << " starts.\n";
			for(int group_id = 1; group_id <= iters2; group_id++){
				// find the party-ids present in a t-sized subset with group id = group_id
				findParties_adap(collaborators, group_id, t, T);

				// assign key shares (to be used in partial evaluation) to parties in the particular t-sized subset
				for(int i = 0, r = (T - 1), s = (t - 1); i < t; i++, r--, s--){
					cur_party = collaborators[i] - 1;
					leader = collaborators[0] - 1;
					u64 keysize = ncr(r, s);

					set_default_keys(&dprfs[cur_party], leader, keysize, prng);
				}

				final_res = oc::ZeroBlock;
				struct timespec finaleval_start = {0, 0};
				struct timespec finaleval_end = {0, 0};

				for(int i = 0; i < t; i++){
					struct timespec parteval_start = {0, 0};
					struct timespec parteval_end = {0, 0};
					clock_gettime(CLOCK_MONOTONIC, &parteval_start);

					// the partial evaluation by i^th party on input inp
					cur_party = collaborators[i]-1;
					std::vector<block> buff(dprfs[cur_party].mDefaultKeys[collaborators[0]-1].mAESs.size());
        			dprfs[cur_party].mDefaultKeys[collaborators[0]-1].ecbEncBlock(inp, buff.data());
        			// mykey.ecbEncBlock(inp, buff.data());
        			b = oc::ZeroBlock;
					for (u64 i = 0; i < buff.size(); ++i){
						b = b ^ buff[i];
					}
					// std::cout << b << "\n";
					part_evals[i] = b;
        			clock_gettime(CLOCK_MONOTONIC, &parteval_end);
        			part_reqd_time = (((double)parteval_end.tv_nsec + 1.0e+9 * parteval_end.tv_sec) - ((double)parteval_start.tv_nsec + 1.0e+9 * parteval_start.tv_sec)) * 1.0e-3;
					partial_eval_time[i] += part_reqd_time;
				}
				clock_gettime(CLOCK_MONOTONIC, &finaleval_start);
				for(int i = 0; i < t; i++){
					final_res = final_res ^ part_evals[i];
				}
				clock_gettime(CLOCK_MONOTONIC, &finaleval_end);
				final_reqd_time = ((double)finaleval_end.tv_nsec + 1.0e+9 * finaleval_end.tv_sec) - ((double)finaleval_start.tv_nsec + 1.0e+9 * finaleval_start.tv_sec);
				final_eval_time += final_reqd_time;
				// std::cout << "final_res: " << final_res << "\n\n";
			}
    	}
    	for(int i = 0; i < t; i++){
			// std::cout << "i: " << i << ", total part eval time (in microseconds): " << partial_eval_time[i] << "\n";
			partial_eval_time[i] = partial_eval_time[i] / (iters * iters2);
			std::cout << "i: " << i << ", avg part eval time (in microseconds): " << partial_eval_time[i] << "\n";
		}
		std::cout << "============== avg final eval time (in nanoseconds): " << final_eval_time / (iters * iters2) << "\n";
		free(partial_eval_time);
	}

	void compare_partial_evaluations_LWR(int iters, int t, int T, u64 q, u64 q1){
		std::cout << "inside compare_partial_evaluations LWR:\n";
		int p = 1024;
		int n = 512;
		int logp = log2(p);
		int logq = log2(q);
		int logq1 = log2(q1);
		std::cout << logq << " " << logq1 << "\n";
		using namespace NTL;

		oc::PRNG prng(oc::sysRandomSeed());

		block inp;

		// Set ZZ_p modulus equal to q
		ZZ_p::init(conv<ZZ>(q));

		// Storage for extended input
		std::vector<vec_ZZ_p> extended_inp;;
		extended_inp.resize(13);
		for(int i = 0; i < 13; i++){
			extended_inp[i].SetLength(n);
		}

		// Storage for the key and key shares
		vec_ZZ_p key;
		std::vector<vec_ZZ_p> key_shares;
		key_shares.resize(t);
		for(auto &key_share: key_shares) key_share.SetLength(n);

		block outp;
		block dir_res;

		// Storage for combining partial evaluations from t parties
		std::vector<u32> combined_eval;
		combined_eval.resize(13);

		// Storage for modulo-p combined result, which further gets converted to block
		std::vector<u16> tmp_result;
		tmp_result.resize(13);

		// Storage for each of the partial evaluations of the DPRF by t parties
		std::vector<std::vector<u32>> part_evals;
		part_evals.resize(t);
		for(int i = 0; i < t; i++){
			part_evals[i].resize(13);
		}

		// this array stores the time required by each party of the t-sized subset to perform the partial evaluation
		u64 *partial_eval_time = (u64*)calloc(t, sizeof(u64));

		// time required for final combination
		u64 final_eval_time = 0;

		// temporary variable to store partial/final evaluation time at some iteration
		u64 part_reqd_time, final_reqd_time;

		// number of possible t-sized subsets out of T parties
		u64 group_count = ncr(T,t);

		// if group_count is too big, we just go for 100000 t-sized subset and average the partial evaluation time over those values
		u64 iters2 = std::min(group_count, (u64)1000);
		std::cout << "iters2: " << iters2 << "\n";
		for(int it = 0; it < iters; it++){
			std::cout << "Iter " << it << " starts.\n";

			// initialize a random ZZ_p key with modulus q
			random(key, n);

			// initialize the input block
			inp = prng.get<block>();

			convert_block_to_extended_lwr_input(inp, &(extended_inp));
			direct_eval_single(extended_inp, &dir_res, key, q, p);
			// std::cout << "dir_res: " << dir_res << "\n";
			// for(int i = 0; i < sz; i++){
			// 	std::cout << dir_res[i] << " ";
			// }
			// std::cout << "\n";

			for(u64 group_id = 1; group_id <= iters2; group_id++){
				generate_shares(key_shares, t, T, q, n, key);

				for(int i = 0; i < t; i++){
					struct timespec parteval_start = {0, 0};
					struct timespec parteval_end = {0, 0};
					clock_gettime(CLOCK_MONOTONIC, &parteval_start);
					// part_eval_extended_multiple2(inp_arr, &part_evals[i], key_shares[i], q, q1, t);
					part_eval_single(extended_inp, &part_evals[i], key_shares[i], q, q1);
					clock_gettime(CLOCK_MONOTONIC, &parteval_end);
					part_reqd_time = (((double)parteval_end.tv_nsec + 1.0e+9 * parteval_end.tv_sec) - ((double)parteval_start.tv_nsec + 1.0e+9 * parteval_start.tv_sec)) * 1.0e-3;
					// std::cout << part_reqd_time << "\n";
					partial_eval_time[i] += part_reqd_time;
				}
				// ZZ_p::init(conv<ZZ>(q1));
				struct timespec finaleval_start = {0, 0};
				struct timespec finaleval_end = {0, 0};
				clock_gettime(CLOCK_MONOTONIC, &finaleval_start);
				// #pragma omp parallel for num_threads(8) collapse(2)
				for(int j = 0; j < 13; j++){
					combined_eval[j] = part_evals[0][j];
					for(int k = 1; k < t; k++){
						combined_eval[j] -= part_evals[k][j];
						// combined_eval[j] = moduloL(combined_eval[j], q1);
						combined_eval[j] = moduloL_adap(combined_eval[j], logq1);
					}
					// tmp_result[j] = round_toL(combined_eval[j], q1, p);
					tmp_result[j] = round_toL_adap(combined_eval[j], logq1, logp);
				}
				outp = decimal_array_to_single_block(tmp_result);
				// std::cout << "dist eval: " << outp << "\n";
				clock_gettime(CLOCK_MONOTONIC, &finaleval_end);

				final_reqd_time = ((double)finaleval_end.tv_nsec + 1.0e+9 * finaleval_end.tv_sec) - ((double)finaleval_start.tv_nsec + 1.0e+9 * finaleval_start.tv_sec);
				final_eval_time += final_reqd_time;
				// std::cout << "dist_eval: " << outp << "\n";
				// for(int i = 0; i < sz; i++){
				// 	std::cout << outp[i] << " ";
				// }
				// std::cout << "\n";
			}
		}
		for(int i = 0; i < t; i++){
			// std::cout << "i: " << i << ", total part eval time: " << partial_eval_time[i] << "\n";
			partial_eval_time[i] = partial_eval_time[i] / (iters * iters2);
			std::cout << "i: " << i << ", avg part eval time (in microseconds): " << partial_eval_time[i] << "\n";
		}
		std::cout << "============== avg final eval time (in nanoseconds): " << final_eval_time / (iters * iters2) << "\n"; 
		free(partial_eval_time);
	}

	void compare_partial_evaluations_BaseLWR(int iters, int t, int T, int logq){
		std::cout << "inside compare_partial_evaluations BaseLWR:\n";
		int logp = 10;
		int n = 512;
		using namespace NTL;

		oc::PRNG prng(oc::sysRandomSeed());

		block inp, final_res;

		// Set ZZ_p modulus equal to q
		ZZ_p::init(conv<ZZ>(pow(2,logq)));

		// Storage for extended input
		std::vector<vec_ZZ_p> extended_inp;;
		extended_inp.resize(13);
		for(int i = 0; i < 13; i++){
			extended_inp[i].SetLength(n);
		}

		std::vector<int> collaborators;

		std::vector<NTL::vec_ZZ_p> key_shares;
		std::vector<std::vector<int>> allocation_matrix;

		std::vector<NTL::vec_ZZ_p> cur_key_list;

		generate_shares_base_adap(key_shares, t, T, logq, n, allocation_matrix);

		// Storage for each of the partial evaluations of the DPRF by t parties
		std::vector<block> part_evals;
		part_evals.resize(t);

		// this array stores the time required by each party of the t-sized subset to perform the partial evaluation
		u64 *partial_eval_time = (u64*)calloc(t, sizeof(u64));

		// time required for final combination
		u64 final_eval_time = 0;

		// temporary variable to store partial/final evaluation time at some iteration
		u64 part_reqd_time, final_reqd_time;

		// number of possible t-sized subsets out of T parties
		u64 group_count = ncr(T,t);

		// if group_count is too big, we just go for 100000 t-sized subset and average the partial evaluation time over those values
		u64 iters2 = std::min(group_count, (u64)1000);
		std::cout << "iters2: " << iters2 << "\n";
    	for(int it = 0; it < iters; it++){
    		std::cout << "Iter " << it << " starts.\n";

    		inp = prng.get<block>();
			convert_block_to_extended_lwr_input(inp, &(extended_inp));
    		
			for(int group_id = 1; group_id <= iters2; group_id++){
				// find the party-ids present in a t-sized subset with group id = group_id
				findParties_adap(collaborators, group_id, t, T);
				// std::cout << "collaborators: \n";
				// for(int i = 0; i < t; i++){
				// 	std::cout << collaborators[i] << " ";
				// }
				// std::cout << "\n";

				for(int i = 0; i < t; i++){
					struct timespec parteval_start = {0, 0};
					struct timespec parteval_end = {0, 0};
					std::vector<int> key_ids = get_key_ids_to_use(collaborators[i], group_id, t, T, allocation_matrix);
					// std::cout << "keyids of i = " << i << ":\n";
					// for(int l = 0; l < key_ids.size(); l++){
					// 	std::cout << key_ids[l] << " ";
					// }
					// std::cout << "\n";
					cur_key_list.clear();
					for(int j = 0; j < key_ids.size(); j++){
						cur_key_list.push_back(key_shares[key_ids[j]]);
					}
					clock_gettime(CLOCK_MONOTONIC, &parteval_start);
					part_eval_base_lwr(extended_inp, &part_evals[i], cur_key_list, logq, logp);
					clock_gettime(CLOCK_MONOTONIC, &parteval_end);
					part_reqd_time = (((double)parteval_end.tv_nsec + 1.0e+9 * parteval_end.tv_sec) - ((double)parteval_start.tv_nsec + 1.0e+9 * parteval_start.tv_sec)) * 1.0e-3;
					partial_eval_time[i] += part_reqd_time;
				}

				final_res = oc::ZeroBlock;
				struct timespec finaleval_start = {0, 0};
				struct timespec finaleval_end = {0, 0};

				clock_gettime(CLOCK_MONOTONIC, &finaleval_start);
				for(int i = 0; i < t; i++){
					final_res = final_res ^ part_evals[i];
				}
				clock_gettime(CLOCK_MONOTONIC, &finaleval_end);
				// std::cout << final_res << "\n";
				final_reqd_time = ((double)finaleval_end.tv_nsec + 1.0e+9 * finaleval_end.tv_sec) - ((double)finaleval_start.tv_nsec + 1.0e+9 * finaleval_start.tv_sec);
				final_eval_time += final_reqd_time;
			}
    	}
    	for(int i = 0; i < t; i++){
			// std::cout << "i: " << i << ", total part eval time (in microseconds): " << partial_eval_time[i] << "\n";
			partial_eval_time[i] = partial_eval_time[i] / (iters * iters2);
			std::cout << "i: " << i << ", avg part eval time (in microseconds): " << partial_eval_time[i] << "\n";
		}
		std::cout << "============== avg final eval time (in nanoseconds): " << final_eval_time / (iters * iters2) << "\n";
		free(partial_eval_time);
	}


	void compare_partial_evaluations_AdapLWR(int iters, int t, int T, int logq, int logq1){
		std::cout << "inside compare_partial_evaluations AdapLWR:\n";
		int logp = 10;
		int n = 1024;
		using namespace NTL;

		oc::PRNG prng(oc::sysRandomSeed());

		block inp;

		// Set ZZ_p modulus equal to q
		ZZ_p::init(conv<ZZ>(pow(2,logq)));

		// Storage for extended input
		std::vector<vec_ZZ_p> extended_inp;;
		extended_inp.resize(13);
		for(int i = 0; i < 13; i++){
			extended_inp[i].SetLength(n);
		}

		// Storage for the key and key shares
		vec_ZZ_p key;
		std::vector<vec_ZZ_p> key_shares;
		key_shares.resize(t);
		for(auto &key_share: key_shares) key_share.SetLength(n);

		block outp;
		block dir_res;

		// Storage for combining partial evaluations from t parties
		std::vector<u64> combined_eval;
		combined_eval.resize(13);

		// Storage for modulo-p combined result, which further gets converted to block
		std::vector<u16> tmp_result;
		tmp_result.resize(13);

		// Storage for each of the partial evaluations of the DPRF by t parties
		std::vector<std::vector<u64>> part_evals;
		part_evals.resize(t);
		for(int i = 0; i < t; i++){
			part_evals[i].resize(13);
		}

		// this array stores the time required by each party of the t-sized subset to perform the partial evaluation
		u64 *partial_eval_time = (u64*)calloc(t, sizeof(u64));

		// time required for final combination
		u64 final_eval_time = 0;

		// temporary variable to store partial/final evaluation time at some iteration
		u64 part_reqd_time, final_reqd_time;

		// number of possible t-sized subsets out of T parties
		int group_count = ncr(T,t);

		// if group_count is too big, we just go for 100000 t-sized subset and average the partial evaluation time over those values
		int iters2 = std::min(group_count, 1000);
		std::cout << "iters2: " << iters2 << "\n";
		for(int it = 0; it < iters; it++){
			std::cout << "Iter " << it << " starts.\n";

			// initialize a random ZZ_p key with modulus q
			random(key, n);

			// initialize the input block
			inp = prng.get<block>();

			convert_block_to_extended_lwr_input_adap(inp, &(extended_inp));
			direct_eval_single_adap(extended_inp, &dir_res, key, logq, logp);
			// std::cout << "dir_res: " << dir_res << "\n";
			// for(int i = 0; i < sz; i++){
			// 	std::cout << dir_res[i] << " ";
			// }
			// std::cout << "\n";

			for(u64 group_id = 1; group_id <= iters2; group_id++){
				generate_shares_adap(key_shares, t, T, n, key);

				for(int i = 0; i < t; i++){
					struct timespec parteval_start = {0, 0};
					struct timespec parteval_end = {0, 0};
					clock_gettime(CLOCK_MONOTONIC, &parteval_start);
					part_eval_single_adap(extended_inp, &part_evals[i], key_shares[i], logq, logq1);
					clock_gettime(CLOCK_MONOTONIC, &parteval_end);
					part_reqd_time = (((double)parteval_end.tv_nsec + 1.0e+9 * parteval_end.tv_sec) - ((double)parteval_start.tv_nsec + 1.0e+9 * parteval_start.tv_sec)) * 1.0e-3;
					partial_eval_time[i] += part_reqd_time;
				}
				struct timespec finaleval_start = {0, 0};
				struct timespec finaleval_end = {0, 0};
				clock_gettime(CLOCK_MONOTONIC, &finaleval_start);
				for(int j = 0; j < 13; j++){
					combined_eval[j] = part_evals[0][j];
					for(int k = 1; k < t; k++){
						combined_eval[j] -= part_evals[k][j];
						combined_eval[j] = moduloL_adap(combined_eval[j], logq1);
					}
					tmp_result[j] = round_toL_adap(combined_eval[j], logq1, logp);
				}
				outp = decimal_array_to_single_block(tmp_result);
				clock_gettime(CLOCK_MONOTONIC, &finaleval_end);

				final_reqd_time = ((double)finaleval_end.tv_nsec + 1.0e+9 * finaleval_end.tv_sec) - ((double)finaleval_start.tv_nsec + 1.0e+9 * finaleval_start.tv_sec);
				final_eval_time += final_reqd_time;
				// std::cout << "dist_eval: " << outp << "\n";
				// for(int i = 0; i < sz; i++){
				// 	std::cout << outp[i] << " ";
				// }
				// std::cout << "\n";
			}
		}
		for(int i = 0; i < t; i++){
			partial_eval_time[i] = partial_eval_time[i] / (iters * iters2);
			std::cout << "i: " << i << ", avg part eval time (in microseconds): " << partial_eval_time[i] << "\n";
		}
		std::cout << "============== avg final eval time (in nanoseconds): " << final_eval_time / (iters * iters2) << "\n"; 
		free(partial_eval_time);
	}

	// void compare_partial_evaluations_AdapMLWR(int iters, int t, int T, int logq, int logq1){
	// 	std::cout << "inside compare_partial_evaluations AdapLWR:\n";
	// 	int logp = 10;
	// 	// int dim = 256;
	// 	// int dim = 128;
	// 	// int rank = 2;
	// 	int dim = 256;
	// 	int rank = 4;
	// 	using namespace NTL;

	// 	oc::PRNG prng(oc::sysRandomSeed());

	// 	block inp;

	// 	// Set ZZ_p modulus equal to q
	// 	ZZ_p::init(conv<ZZ>(pow(2,logq)));

	// 	// Storage for extended input
	// 	NTL::Vec<NTL::ZZ_pX> extended_inp;;
	// 	extended_inp.SetLength(rank);
	// 	for(int i = 0; i < rank; i++){
	// 		extended_inp[i].SetLength(dim);
	// 	}

	// 	// Storage for the key and key shares
	// 	NTL::Vec<NTL::ZZ_pX> key;
	// 	std::vector<NTL::Vec<NTL::ZZ_pX>> key_shares;
	// 	key_shares.resize(t);
	// 	// for(auto &key_share: key_shares) key_share.SetLength(n);
	// 	for(int i = 0; i < t; i++){
	// 		key_shares[i].SetLength(rank);
	// 		for(int j = 0; j < rank; j++){
	// 			key_shares[i][j].SetLength(dim);
	// 		}
	// 	}

	// 	block outp;
	// 	block dir_res;

	// 	ZZ_pX f;
	// 	int n = 256;
	// 	// int n = 128;
	// 	f.SetLength(n+1);
	// 	for(int i = 0; i < n+1; i++){
	// 		SetCoeff(f, i, 0);
	// 	}
	// 	SetCoeff(f, n);
	// 	SetCoeff(f, 0);
	// 	ZZ_pXModulus F(f);

	// 	// Storage for combining partial evaluations from t parties
	// 	std::vector<u32> combined_eval;
	// 	combined_eval.resize(dim);

	// 	// Storage for modulo-p combined result, which further gets converted to block
	// 	std::vector<u16> tmp_result;
	// 	tmp_result.resize(dim);

	// 	// Storage for each of the partial evaluations of the DPRF by t parties
	// 	std::vector<std::vector<u32>> part_evals;
	// 	part_evals.resize(t);
	// 	for(int i = 0; i < t; i++){
	// 		part_evals[i].resize(dim);
	// 	}

	// 	// this array stores the time required by each party of the t-sized subset to perform the partial evaluation
	// 	u64 *partial_eval_time = (u64*)calloc(t, sizeof(u64));

	// 	// time required for final combination
	// 	u64 final_eval_time = 0;

	// 	// temporary variable to store partial/final evaluation time at some iteration
	// 	u64 part_reqd_time, final_reqd_time;

	// 	// number of possible t-sized subsets out of T parties
	// 	int group_count = ncr(T,t);

	// 	// if group_count is too big, we just go for 100000 t-sized subset and average the partial evaluation time over those values
	// 	int iters2 = std::min(group_count, 1000);
	// 	std::cout << "iters2: " << iters2 << "\n";
	// 	for(int it = 0; it < iters; it++){
	// 		std::cout << "Iter " << it << " starts.\n";

	// 		// initialize a random ZZ_p key with modulus q
	// 		key.SetLength(rank);
	// 		for(int i = 1; i <= rank; i++){
	// 			random(key(i), dim);
	// 		}

	// 		// initialize the input block
	// 		inp = prng.get<block>();

	// 		convert_block_to_extended_mlwr_input_adap(inp, &(extended_inp), rank);
	// 		direct_eval_single_adap_mlwr(extended_inp, &dir_res, key, logq, logp, F, dim, rank);
	// 		// std::cout << "dir_res: " << dir_res << "\n";
	// 		// for(int i = 0; i < sz; i++){
	// 		// 	std::cout << dir_res[i] << " ";
	// 		// }
	// 		// std::cout << "\n";

	// 		for(u64 group_id = 1; group_id <= iters2; group_id++){
	// 			generate_shares_adap_mlwr(key_shares, t, T, dim, rank, key);

	// 			for(int i = 0; i < t; i++){
	// 				struct timespec parteval_start = {0, 0};
	// 				struct timespec parteval_end = {0, 0};
	// 				clock_gettime(CLOCK_MONOTONIC, &parteval_start);
	// 				// part_eval_extended_multiple2(inp_arr, &part_evals[i], key_shares[i], q, q1, t);
	// 				part_eval_single_adap_mlwr(extended_inp, &part_evals[i], key_shares[i], logq, logq1, F, dim, rank);
	// 				clock_gettime(CLOCK_MONOTONIC, &parteval_end);
	// 				part_reqd_time = (((double)parteval_end.tv_nsec + 1.0e+9 * parteval_end.tv_sec) - ((double)parteval_start.tv_nsec + 1.0e+9 * parteval_start.tv_sec)) * 1.0e-3;
	// 				// std::cout << part_reqd_time << "\n";
	// 				partial_eval_time[i] += part_reqd_time;
	// 			}
	// 			// ZZ_p::init(conv<ZZ>(q1));
	// 			struct timespec finaleval_start = {0, 0};
	// 			struct timespec finaleval_end = {0, 0};
	// 			clock_gettime(CLOCK_MONOTONIC, &finaleval_start);
				
	// 			// #pragma omp parallel num_threads(THREADNUM)
	// 			// {
	// 				// #pragma omp for
	// 			for(int i = 0; i < dim; i++){
	// 				combined_eval[i] = part_evals[0][i];
	// 			}
	// 			// #pragma omp for collapse(2)
	// 			for(int i = 0; i < dim; i++){
	// 				// combined_eval[i] = part_evals[0][i];
	// 				for(int j = 1; j < t; j++){
	// 					combined_eval[i] -= part_evals[j][i];
	// 					combined_eval[i] = moduloL_adap(combined_eval[i], logq1);
	// 				}
	// 			}
	// 			// #pragma omp for
	// 			for(int i = 0; i < dim; i++){
	// 				tmp_result[i] = round_toL_adap(combined_eval[i], logq1, logp);
	// 			}
	// 			// }

	// 			outp = poln_to_single_block(tmp_result);
	// 			clock_gettime(CLOCK_MONOTONIC, &finaleval_end);
	// 			// std::cout << "dist eval: " << outp << "\n";
	// 			final_reqd_time = ((double)finaleval_end.tv_nsec + 1.0e+9 * finaleval_end.tv_sec) - ((double)finaleval_start.tv_nsec + 1.0e+9 * finaleval_start.tv_sec);
	// 			final_eval_time += final_reqd_time;
	// 			// std::cout << "dist_eval: " << outp << "\n";
	// 			// for(int i = 0; i < sz; i++){
	// 			// 	std::cout << outp[i] << " ";
	// 			// }
	// 			// std::cout << "\n";
	// 		}
	// 	}
	// 	for(int i = 0; i < t; i++){
	// 		// std::cout << "i: " << i << ", total part eval time: " << partial_eval_time[i] << "\n";
	// 		partial_eval_time[i] = partial_eval_time[i] / (iters * iters2);
	// 		std::cout << "i: " << i << ", avg part eval time (in microseconds): " << partial_eval_time[i] << "\n";
	// 	}
	// 	std::cout << "============== avg final eval time (in nanoseconds): " << final_eval_time / (iters * iters2) << "\n"; 
	// 	free(partial_eval_time);
	// }

	void compare_partial_evaluations_AdapMLWR_batch(int iters, int t, int T, int logq, int logq1){
		std::cout << "inside compare_partial_evaluations AdapMLWR:\n";
		int logp = 10;
		int dim = 256;
		int rank = 4;
		using namespace NTL;

		oc::PRNG prng(oc::sysRandomSeed());

		std::vector<block> inp;
		inp.resize(BATCHSIZE);

		// Set ZZ_p modulus equal to q
		ZZ_p::init(conv<ZZ>(pow(2,logq)));

		// Storage for extended input
		NTL::Vec<NTL::ZZ_pX> extended_inp;;
		extended_inp.SetLength(rank);
		for(int i = 0; i < rank; i++){
			extended_inp[i].SetLength(dim);
		}

		// Storage for the key and key shares
		NTL::Vec<NTL::ZZ_pX> key;
		std::vector<NTL::Vec<NTL::ZZ_pX>> key_shares;
		key_shares.resize(t);
		for(int i = 0; i < t; i++){
			key_shares[i].SetLength(rank);
			for(int j = 0; j < rank; j++){
				key_shares[i][j].SetLength(dim);
			}
		}

		std::vector<block> outp(BATCHSIZE);
		std::vector<block> dir_res(BATCHSIZE);

		ZZ_pX f;
		int n = 256;
		f.SetLength(n+1);
		for(int i = 0; i < n+1; i++){
			SetCoeff(f, i, 0);
		}
		SetCoeff(f, n);
		SetCoeff(f, 0);
		ZZ_pXModulus F(f);

		// Storage for combining partial evaluations from t parties
		std::vector<u64> combined_eval;
		combined_eval.resize(dim);

		// Storage for modulo-p combined result, which further gets converted to block
		std::vector<std::vector<u16>> tmp_result(1, std::vector<u16>(dim));

		// Storage for each of the partial evaluations of the DPRF by t parties
		std::vector<std::vector<u64>> part_evals;
		part_evals.resize(t);
		for(int i = 0; i < t; i++){
			part_evals[i].resize(dim);
		}

		// this array stores the time required by each party of the t-sized subset to perform the partial evaluation
		u64 *partial_eval_time = (u64*)calloc(t, sizeof(u64));

		// time required for final combination
		u64 final_eval_time = 0;

		// temporary variable to store partial/final evaluation time at some iteration
		u64 part_reqd_time, final_reqd_time;

		// number of possible t-sized subsets out of T parties
		int group_count = ncr(T,t);

		// if group_count is too big, we just go for 100000 t-sized subset and average the partial evaluation time over those values
		int iters2 = std::min(group_count, 1000);
		std::cout << "iters2: " << iters2 << "\n";
		for(int it = 0; it < iters; it++){
			std::cout << "Iter " << it << " starts.\n";

			// initialize a random ZZ_p key with modulus q
			key.SetLength(rank);
			for(int i = 1; i <= rank; i++){
				random(key(i), dim);
			}

			// initialize the input block
			for(int i = 0; i < BATCHSIZE; i++){
				inp[i] = prng.get<block>();
			}

			convert_block_to_extended_mlwr_input_adap_batch(inp, &(extended_inp), rank);
			direct_eval_single_adap_mlwr_batch(extended_inp, &dir_res, key, logq, logp, F, dim, rank);
			// std::cout << "dir_res:\n";
			// for(int i = 0; i < BATCHSIZE; i++){
			// 	std::cout << dir_res[i] << " ";
			// }
			// std::cout << "\n";

			for(u64 group_id = 1; group_id <= iters2; group_id++){
				generate_shares_adap_mlwr(key_shares, t, T, dim, rank, key);

				for(int i = 0; i < t; i++){
					struct timespec parteval_start = {0, 0};
					struct timespec parteval_end = {0, 0};
					clock_gettime(CLOCK_MONOTONIC, &parteval_start);
					part_eval_single_adap_mlwr(extended_inp, &part_evals[i], key_shares[i], logq, logq1, F, dim, rank);
					clock_gettime(CLOCK_MONOTONIC, &parteval_end);
					part_reqd_time = (((double)parteval_end.tv_nsec + 1.0e+9 * parteval_end.tv_sec) - ((double)parteval_start.tv_nsec + 1.0e+9 * parteval_start.tv_sec)) * 1.0e-3;
					// std::cout << part_reqd_time << "\n";
					partial_eval_time[i] += part_reqd_time;
				}
				struct timespec finaleval_start = {0, 0};
				struct timespec finaleval_end = {0, 0};
				clock_gettime(CLOCK_MONOTONIC, &finaleval_start);
				
				for(int i = 0; i < dim; i++){
					combined_eval[i] = part_evals[0][i];
				}
				#pragma omp for collapse(2)
				for(int i = 0; i < dim; i++){
					for(int j = 1; j < t; j++){
						combined_eval[i] -= part_evals[j][i];
						combined_eval[i] = moduloL_adap(combined_eval[i], logq1);
					}
				}
				for(int i = 0; i < dim; i++){
					tmp_result[0][i] = round_toL_adap(combined_eval[i], logq1, logp);
				}

				poln_to_multiple_blocks(outp, tmp_result);
				clock_gettime(CLOCK_MONOTONIC, &finaleval_end);
				final_reqd_time = ((double)finaleval_end.tv_nsec + 1.0e+9 * finaleval_end.tv_sec) - ((double)finaleval_start.tv_nsec + 1.0e+9 * finaleval_start.tv_sec);
				final_eval_time += final_reqd_time;

				// std::cout << "dist_eval:\n";
				// for(int i = 0; i < BATCHSIZE; i++){
				// 	std::cout << outp[i] << " ";
				// }
				// std::cout << "\n";
			}
		}
		for(int i = 0; i < t; i++){
			partial_eval_time[i] = partial_eval_time[i] / (iters * iters2 * BATCHSIZE);
			std::cout << "i: " << i << ", avg part eval time (in microseconds): " << partial_eval_time[i] << "\n";
		}
		std::cout << "============== avg final eval time (in nanoseconds): " << final_eval_time / (iters * iters2 * BATCHSIZE) << "\n"; 
		free(partial_eval_time);
	}

	void compare_partial_evaluations_AdapLWE(int iters, int t, int T, int logq, int logq1){
		std::cout << "inside compare_partial_evaluations AdapLWE:\n";
		int logp = 10;
		int dim = 256;
		int dim_ = 2 * dim * logq;
		int L = 7;
		using namespace NTL;

		oc::PRNG prng(oc::sysRandomSeed());

		block inp;

		// Set ZZ_p modulus equal to q
		ZZ_p::init(conv<ZZ>(pow(2,logq)));

		// Storage for extended input
		Vec<vec_ZZ_p> extended_inp;;
		extended_inp.SetLength(dim);
		for(int i = 0; i < dim; i++){
			extended_inp[i].SetLength(dim_);
		}

		NTL::Vec<NTL::vec_ZZ_p> A0;
        NTL::Vec<NTL::Vec<NTL::Vec<NTL::vec_ZZ_p>>> matrix_list;

        /* Initialize A0 */
		A0.SetLength(dim);
		for(int i = 0; i < dim; i++){
			random(A0[i], dim_);
		}

		/* Initialize matrices A_ij for all i\in[L], j\in{0,1} */
		matrix_list.SetLength(L);
		for(int i = 0; i < L; i++){
			matrix_list[i].SetLength(2);
			for(int j = 0; j < 2; j++){
				matrix_list[i][j].SetLength(dim);
				for(int k = 0; k < dim; k++){
					random(matrix_list[i][j][k], dim_);
				}
			}
		}

		// Storage for the key and key shares
		std::vector<int> key;
		std::vector<std::vector<int>> key_shares;
		key_shares.resize(t);
		for(auto &key_share: key_shares) key_share.resize(dim);

		block outp;
		block dir_res;

		// Storage for combining partial evaluations from t parties
		std::vector<u32> combined_eval;
		combined_eval.resize(dim_);

		// Storage for modulo-p combined result, which further gets converted to block
		std::vector<u16> tmp_result;
		tmp_result.resize(dim_);

		// Storage for each of the partial evaluations of the DPRF by t parties
		std::vector<std::vector<u32>> part_evals;
		part_evals.resize(t);
		for(int i = 0; i < t; i++){
			part_evals[i].resize(dim_);
		}

		// this array stores the time required by each party of the t-sized subset to perform the partial evaluation
		u64 *partial_eval_time = (u64*)calloc(t, sizeof(u64));

		// time required for final combination
		u64 final_eval_time = 0;

		// temporary variable to store partial/final evaluation time at some iteration
		u64 part_reqd_time, final_reqd_time;

		// number of possible t-sized subsets out of T parties
		int group_count = ncr(T,t);

		// if group_count is too big, we just go for 100000 t-sized subset and average the partial evaluation time over those values
		int iters2 = std::min(group_count, 1000);
		std::cout << "iters2: " << iters2 << "\n";
		for(int it = 0; it < iters; it++){
			std::cout << "Iter " << it << " starts.\n";

			key.resize(dim);
			for(int i = 0; i < dim; i++){
				key[i] = distr1(eng_);
			}

			// initialize the input block
			inp = prng.get<block>();
			convert_block_to_lwe_input(inp, extended_inp, matrix_list, A0, dim, dim_, logq);
			direct_eval_adap_single(extended_inp, &dir_res, key, dim, dim_, logq, logp);
			// std::cout << "dir_res: " << dir_res << "\n";
			// for(int i = 0; i < sz; i++){
			// 	std::cout << dir_res[i] << " ";
			// }
			// std::cout << "\n";

			for(u64 group_id = 1; group_id <= iters2; group_id++){
				generate_shares_adap_lwe(key_shares, t, T, dim, key);

				for(int i = 0; i < t; i++){
					struct timespec parteval_start = {0, 0};
					struct timespec parteval_end = {0, 0};
					clock_gettime(CLOCK_MONOTONIC, &parteval_start);
					part_eval_adap_single(extended_inp, &part_evals[i], key_shares[i], dim, dim_, logq, logq1);
					clock_gettime(CLOCK_MONOTONIC, &parteval_end);
					part_reqd_time = (((double)parteval_end.tv_nsec + 1.0e+9 * parteval_end.tv_sec) - ((double)parteval_start.tv_nsec + 1.0e+9 * parteval_start.tv_sec)) * 1.0e-3;
					partial_eval_time[i] += part_reqd_time;
				}
				struct timespec finaleval_start = {0, 0};
				struct timespec finaleval_end = {0, 0};
				clock_gettime(CLOCK_MONOTONIC, &finaleval_start);
				#pragma omp parallel num_threads(THREADNUM)
				{
					#pragma omp for
					for(int j = 0; j < dim_; j++){
						combined_eval[j] = part_evals[0][j];
						for(int k = 1; k < t; k++){
							combined_eval[j] -= part_evals[k][j];
							combined_eval[j] = moduloL_adap(combined_eval[j], logq1);
						}
						tmp_result[j] = round_toL_adap(combined_eval[j], logq1, logp);
					}
				}
				// for(int i = 0; i < 10; i++){
				// 	std::cout << tmp_result[i] << " ";
				// }
				// std::cout << "\n";
				outp = randomness_extractor(tmp_result);
				clock_gettime(CLOCK_MONOTONIC, &finaleval_end);

				final_reqd_time = ((double)finaleval_end.tv_nsec + 1.0e+9 * finaleval_end.tv_sec) - ((double)finaleval_start.tv_nsec + 1.0e+9 * finaleval_start.tv_sec);
				final_eval_time += final_reqd_time;
				// std::cout << "dist_eval: " << outp << "\n";
				// for(int i = 0; i < sz; i++){
				// 	std::cout << outp[i] << " ";
				// }
				// std::cout << "\n";
			}
		}
		for(int i = 0; i < t; i++){
			partial_eval_time[i] = partial_eval_time[i] / (iters * iters2);
			std::cout << "i: " << i << ", avg part eval time (in microseconds): " << partial_eval_time[i] << "\n";
		}
		std::cout << "============== avg final eval time (in nanoseconds): " << final_eval_time / (iters * iters2) << "\n"; 
		free(partial_eval_time);
	}

}