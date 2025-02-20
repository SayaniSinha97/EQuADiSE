#include "LWR_helper.h"
#include <cryptoTools/Common/Timer.h>
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/block.h"
#include <string>
#include <map>
#include <random>
#include <omp.h>

namespace dEnc{
	using RandomOracle = oc::RandomOracle;
	// RandomOracle H_tmp(64);
	typedef struct bytes64{
		u64 arr[8];
	}bytes64;

	std::map<std::pair<int, int>, int> ncr_cache;
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_real_distribution<> dist(0, 1);

	// u64 moduloL_adap(u64 x, int logq){
	// 	// u64 x_;
	// 	// if(x >= 0){
	// 	// 	x_ = x >> logq;
	// 	// 	return (x-x_);
	// 	// }
	// 	// else{
	// 	// 	x_ = (-x) >> logq;
	// 	// 	return (x_ ? ((1 << logq) - x_) : x_);
	// 	// }
	// 	// std::cout << x << "\n";
	// 	u64 x_ = x;
	// 	u64 y;
	// 	if(x >= 0){
	// 		y = x >> logq;
	// 		// std::cout << (x_ - (y << logq));
	// 		return (x_ - (y << logq));
	// 	}
	// 	else{
	// 		y = (-x) >> logq;
	// 		y = (-x_) - (y << logq);
	// 		return (y ? ((1 << logq) - y) : y);
	// 	}
	// }

	int ncr(int n, int r){
	    if (ncr_cache.find({n, r}) == ncr_cache.end()){
	        if (r > n || n < 0 || r < 0)
	            return 0;
	        else{
	            if (r == 0 || r == n){
	                ncr_cache[{n, r}] = 1;
	            }
	            else if (r == 1 || r == n - 1){
	                ncr_cache[{n, r}] = n;
	            }
	            else{
	                ncr_cache[{n, r}] = ncr(n - 1, r) + ncr(n - 1, r - 1);
	            }
	        }
	    }

	    return ncr_cache[{n, r}];
	}

	u64 round_off(NTL::ZZ_p x, int logq, int logp){
		NTL::ZZ x_ = NTL::conv<NTL::ZZ>(x);
		x_ /= pow(2, logq-logp-1);
		if(x_ % 2 == 0){
			x_ /= 2;
			return NTL::conv<ulong>(x_);
		}
		else{
			x_ /= 2;
			x_ += 1;
			x_ %= NTL::conv<NTL::ZZ>(pow(2,logp));
			return NTL::conv<ulong>(x_);
		}
	}


	// u64 moduloMultiplication(u64 a, u64 b, u64 q){
	//     u64 res = 0;
	//     a %= q;
	//     while (b) {
	//         if (b & 1)
	//             res = (res + a) % q;
	//         a = (2 * a) % q;
	//         b >>= 1;
	//     }
	//     res = moduloL(res, q);
	//     return res;
	// }

	void findParties(std::vector<u64>& pt, u64 gid, u64 t, u64 T){
		u64 mem = 0, tmp;
		pt.clear();
		for(u64 i = 1; i < T; i++){
			tmp = ncr(T - i, t - mem -1);
			if(gid > tmp){
				gid -= tmp;
			}
			else{
				pt.push_back(i);
				mem += 1;
			}
			if(mem + (T-i) == t){
				for(u64 j = i + 1; j <= T; j++){
					pt.push_back(j);
				}
				break;
			}
		}
	}


	void findParties_adap(std::vector<int>& pt, int gid, int t, int T){
		int mem = 0, tmp;
		pt.clear();
		for(int i = 1; i < T; i++){
			tmp = ncr(T - i, t - mem -1);
			if(gid > tmp){
				gid -= tmp;
			}
			else{
				pt.push_back(i);
				mem += 1;
			}
			if(mem + (T-i) == t){
				for(int j = i + 1; j <= T; j++){
					pt.push_back(j);
				}
				break;
			}
		}
	}

	u64 findGroupId(std::vector<u64> parties, u64 t, u64 T){
		u64 mem = 0;
		u64 group_count = 1;
		for(u64 i = 1; i <= T; i++){
			if(std::find(parties.begin(), parties.end(), i) != parties.end()){
				mem += 1;
			}
			else{
				group_count += ncr(T - i, t - mem - 1);
			}
			if(mem == t){
				break;
			}
		}
		return group_count;
	}

	int findGroupId_adap(std::vector<int> parties, int t, int T){
		int mem = 0;
		int group_count = 1;
		for(int i = 1; i <= T; i++){
			if(std::find(parties.begin(), parties.end(), i) != parties.end()){
				mem += 1;
			}
			else{
				group_count += ncr(T - i, t - mem - 1);
			}
			if(mem == t){
				break;
			}
		}
		return group_count;
	}

	void convert_block_to_extended_lwr_input(block x, std::vector<NTL::vec_ZZ_p>* y){
		using namespace NTL;
		std::vector<bytes64> hash_outputs;
		hash_outputs.resize(13 * 32);
		int section_length = 32;
		int sectionid, offset;
		
		// #pragma omp parallel for num_threads(4) private(sectionid, offset)
		for(int i = 0; i < 13 * section_length; i++){
			// std::cout << omp_get_thread_num() << " " << i << "\n";
			RandomOracle Hash(64);
			Hash.Update(x);
			Hash.Update(i+1);
			sectionid = i/section_length;
			offset = i % section_length;
			Hash.Final(hash_outputs[i]);
			for(int j = 0; j < 16; j++){
				(*y)[sectionid][(offset * 16) + j] = conv<ZZ_p>(hash_outputs[i].arr[j]);
			}
			// Hash.Reset();
		}
	}

	void convert_block_to_extended_lwr_input_adap(block x, std::vector<NTL::vec_ZZ_p>* y){
		using namespace NTL;
		std::vector<bytes64> hash_outputs;
		// hash_outputs.resize(13 * 32);
		hash_outputs.resize(13 * 128);
		// int section_length = 32;
		int section_length = 128;
		int sectionid, offset;
		
		// #pragma omp parallel for num_threads(4) private(sectionid, offset)
		for(int i = 0; i < 13 * section_length; i++){
			// std::cout << omp_get_thread_num() << " " << i << "\n";
			RandomOracle Hash(64);
			Hash.Update(x);
			Hash.Update(i+1);
			sectionid = i/section_length;
			offset = i % section_length;
			Hash.Final(hash_outputs[i]);
			for(int j = 0; j < 8; j++){
				(*y)[sectionid][(offset * 8) + j] = conv<ZZ_p>(hash_outputs[i].arr[j]);
			}
			// Hash.Reset();
		}
	}

	// void convert_block_to_extended_mlwr_input_adap(block x, NTL::Vec<NTL::ZZ_pX>* y, int rank){
	// 	using namespace NTL;
	// 	std::vector<bytes64> hash_outputs;
	// 	hash_outputs.resize(rank * 32);
	// 	int section_length = 32;
	// 	int sectionid, offset;
		
	// 	// #pragma omp parallel for num_threads(4) private(sectionid, offset)
	// 	for(int i = 0; i < rank * section_length; i++){
	// 		// std::cout << omp_get_thread_num() << " " << i << "\n";
	// 		RandomOracle Hash(64);
	// 		Hash.Update(x);
	// 		Hash.Update(i+1);
	// 		sectionid = i/section_length;
	// 		offset = i % section_length;
	// 		Hash.Final(hash_outputs[i]);
	// 		for(int j = 0; j < 8; j++){
	// 			(*y)[sectionid][(offset * 8) + j] = conv<ZZ_p>(hash_outputs[i].arr[j]);
	// 			// SetCoeff((*y)(sectionid+1), (offset * 8) + j, conv<ZZ_p>(hash_outputs[i].arr[j]));
	// 		}
	// 		// Hash.Reset();
	// 	}
	// }
	void convert_block_to_extended_mlwr_input_adap(block x, NTL::Vec<NTL::ZZ_pX>* y, int rank){
		using namespace NTL;
		std::vector<bytes64> hash_outputs;
		hash_outputs.resize(rank * 16);
		int section_length = 16;
		int sectionid, offset;
		
		// #pragma omp parallel for num_threads(4) private(sectionid, offset)
		for(int i = 0; i < rank * section_length; i++){
			// std::cout << omp_get_thread_num() << " " << i << "\n";
			RandomOracle Hash(64);
			Hash.Update(x);
			Hash.Update(i+1);
			sectionid = i/section_length;
			offset = i % section_length;
			Hash.Final(hash_outputs[i]);
			for(int j = 0; j < 8; j++){
				(*y)[sectionid][(offset * 8) + j] = conv<ZZ_p>(hash_outputs[i].arr[j]);
				// SetCoeff((*y)(sectionid+1), (offset * 8) + j, conv<ZZ_p>(hash_outputs[i].arr[j]));
			}
			// Hash.Reset();
		}
	}

	// void convert_block_to_extended_mlwr_input_adap_batch(std::vector<block> x, NTL::Vec<NTL::ZZ_pX>* y, int rank){
	// 	// std::cout << "inside batch convert\n";
	// 	using namespace NTL;
	// 	std::vector<bytes64> hash_outputs;
	// 	hash_outputs.resize(rank * 16);
	// 	int section_length = 16;
	// 	int sectionid, offset;
		
	// 	// #pragma omp parallel for num_threads(4) private(sectionid, offset)
	// 	for(int i = 0; i < rank * section_length; i++){
	// 		// std::cout << omp_get_thread_num() << " " << i << "\n";
	// 		RandomOracle Hash(64);
	// 		for(int j = 0; j < x.size(); j++){
	// 			Hash.Update(x[j]);
	// 		}
	// 		// Hash.Update(x);
	// 		Hash.Update(i+1);
	// 		sectionid = i/section_length;
	// 		offset = i % section_length;
	// 		Hash.Final(hash_outputs[i]);
	// 		for(int j = 0; j < 8; j++){
	// 			(*y)[sectionid][(offset * 8) + j] = conv<ZZ_p>(hash_outputs[i].arr[j]);
	// 			// SetCoeff((*y)(sectionid+1), (offset * 8) + j, conv<ZZ_p>(hash_outputs[i].arr[j]));
	// 		}
	// 		// Hash.Reset();
	// 	}
	// 	// std::cout << "exiting batch convert\n";
	// }
	void convert_block_to_extended_mlwr_input_adap_batch(std::vector<block> x, NTL::Vec<NTL::ZZ_pX>* y, int rank){
		// std::cout << "inside batch convert\n";
		using namespace NTL;
		std::vector<bytes64> hash_outputs;
		hash_outputs.resize(rank * 32);
		int section_length = 32;
		int sectionid, offset;
		
		// #pragma omp parallel for num_threads(4) private(sectionid, offset)
		for(int i = 0; i < rank * section_length; i++){
			// std::cout << omp_get_thread_num() << " " << i << "\n";
			RandomOracle Hash(64);
			for(int j = 0; j < x.size(); j++){
				Hash.Update(x[j]);
			}
			// Hash.Update(x);
			Hash.Update(i+1);
			sectionid = i/section_length;
			offset = i % section_length;
			Hash.Final(hash_outputs[i]);
			for(int j = 0; j < 8; j++){
				(*y)[sectionid][(offset * 8) + j] = conv<ZZ_p>(hash_outputs[i].arr[j]);
				// SetCoeff((*y)(sectionid+1), (offset * 8) + j, conv<ZZ_p>(hash_outputs[i].arr[j]));
			}
			// Hash.Reset();
		}
		// std::cout << "exiting batch convert\n";
	}


	block decimal_array_to_single_block(std::vector<u16> arr){
		block b;
		oc::BitIterator iter((u8*)&b, 0);
		for(int i = 0; i < 128; i++){
			*(iter + i) = (arr[(i/10)] >> (i%10)) & 1;
		}
		return b;
	}

	block poln_to_single_block(std::vector<u16> p){
		block res;
		RandomOracle hash_poln_to_block(16);
		for(int i = 0; i < p.size(); i++){
			hash_poln_to_block.Update(p[i]);
		}
		hash_poln_to_block.Final(res);
		return res;
	}

	void poln_to_multiple_blocks(std::vector<block> &out, std::vector<std::vector<u16>> in){
		std::vector<u16> interim;
		for(int i = 0; i < in.size(); i++){
			for(int j = 0; j < in[i].size(); j++){
				interim.push_back(in[i][j]);
			}
		}
		// std::cout << "in function\n";
		// for(int i = 0; i < interim.size(); i++){
		// 	std::cout << interim[i] << " ";
		// }
		// std::cout << "\n";
		for(int i = 0; i < out.size(); i++){
			oc::BitIterator iter((u8*)&(out[i]), 0);
			for(int j = 0; j < 128; j++){
				*(iter + j) = (interim[(128*i+j)/10] >> ((128*i+j)%10)) & 1;
			}
			// std::cout << out[i] << "\n";
		}
	}

	// int small_err(){
	// 	double r = dist(gen);
	// 	if(r < 0.33){
	// 		return 1;
	// 	}
	// 	else if(r < 0.67){
	// 		return -1;
	// 	}
	// 	else{
	// 		return 0;
	// 	}
	// }

	void part_eval(std::vector<std::vector<NTL::vec_ZZ_p>> inp, std::vector<std::vector<u32>> *outp, NTL::vec_ZZ_p keyshare, u64 q, u64 q1){
		int sz = inp.size();
		// std::cout << "sz: " << sz << "\n";
		// #pragma omp parallel num_threads(4) shared(sz, keyshare, inp, outp, q, q1)
		// {
			// #pragma omp taskloop num_tasks(2)
			for(int i = 0; i < sz; i++){
				// std::cout << "i: " << i << " " << omp_get_thread_num() << "\n";
				for(int j = 0; j < 13; j++){
					// std::cout << "j: " << j << " " << omp_get_thread_num() << "\n";
					NTL::ZZ_p outp_;
					// std::cout << "inp: " << inp[i][j][0] << " " << omp_get_thread_num() << "\n";
					NTL::InnerProduct(outp_, inp[i][j], keyshare);
					// std::cout << "i: " << outp_ << " " << omp_get_thread_num() << "\n";
					u64 interim = NTL::conv<ulong>(outp_);
					// std::cout << interim << "\n";
					(*outp)[i][j] = round_toL(interim, q, q1);
				}
				// std::cout << "i: " << i << "    " << omp_get_thread_num() << "\n";
			}
		// }
	}


	void part_eval_single(std::vector<NTL::vec_ZZ_p> inp, std::vector<u32> *outp, NTL::vec_ZZ_p keyshare, u64 q, u64 q1){
		for(int j = 0; j < 13; j++){
			NTL::ZZ_p outp_;
			NTL::InnerProduct(outp_, inp[j], keyshare);
			u64 interim = NTL::conv<ulong>(outp_);
			(*outp)[j] = round_toL(interim, q, q1);
		}
	}


	void direct_eval_single(std::vector<NTL::vec_ZZ_p> inp, block *outp, NTL::vec_ZZ_p key, u64 q, u64 p){
		std::vector<u16> outp_arr;
		outp_arr.resize(13);
		for(int i = 0; i < 13; i++){
			NTL::ZZ_p outp_;
			NTL::InnerProduct(outp_, inp[i], key);
			u64 interim = NTL::conv<ulong>(outp_);
			outp_arr[i] = round_toL(interim, q, p);
			// direct_eval_basic3(inp[i], &(outp_arr[i]), key, q, p, t);
		}
		*outp = decimal_array_to_single_block(outp_arr);
	}


	void direct_eval(std::vector<block> in, std::vector<block>* dir_out, NTL::vec_ZZ_p key, u64 q, u64 p){
		std::vector<std::vector<NTL::vec_ZZ_p>> inp;
		inp.resize(in.size());
		for(int i = 0; i < inp.size(); i++){
			inp[i].resize(13);
			std::vector<u16> outp_arr(13);
			for(int j = 0; j < 13; j++){
				inp[i][j].SetLength(512);
			}
			convert_block_to_extended_lwr_input(in[i], &(inp[i]));
			for(int j = 0; j < 13; j++){
				NTL::ZZ_p outp_;
				NTL::InnerProduct(outp_, inp[i][j], key);
				u64 interim = NTL::conv<ulong>(outp_);
				outp_arr[j] = round_toL(interim, q, p);
			}
			(*dir_out)[i] = decimal_array_to_single_block(outp_arr);
		}
	}

	void part_eval_base_lwr(std::vector<NTL::vec_ZZ_p> inp, block *outp, std::vector<NTL::vec_ZZ_p> key_list, int logq, int logp){
		block res = oc::ZeroBlock;
		for(int i = 0; i < key_list.size(); i++){
			std::vector<u16> interims;
			interims.resize(13);
			for(int j = 0; j < 13; j++){
				NTL::ZZ_p outp_;
				NTL::InnerProduct(outp_, inp[j], key_list[i]);
				interims[j] = (u16)round_off(outp_, logq, logp);
			}
			block b = decimal_array_to_single_block(interims);
			res = res ^ b;
		}
		*outp = res;
	}


	void part_eval_adap(std::vector<std::vector<NTL::vec_ZZ_p>> inp, std::vector<std::vector<u64>> *outp, NTL::vec_ZZ_p keyshare, int logq, int logq1){
		int sz = inp.size();
		// std::cout << "sz: " << sz << "\n";
		// #pragma omp parallel num_threads(4) shared(sz, keyshare, inp, outp, q, q1)
		// {
			// #pragma omp taskloop num_tasks(2)
			for(int i = 0; i < sz; i++){
				// std::cout << "i: " << i << " " << omp_get_thread_num() << "\n";
				for(int j = 0; j < 13; j++){
					// std::cout << "j: " << j << " " << omp_get_thread_num() << "\n";
					NTL::ZZ_p outp_;
					// std::cout << "inp: " << inp[i][j][0] << " " << omp_get_thread_num() << "\n";
					NTL::InnerProduct(outp_, inp[i][j], keyshare);
					(*outp)[i][j] = (u64)round_off(outp_, logq, logq1);
					// // std::cout << "i: " << outp_ << " " << omp_get_thread_num() << "\n";
					// u64 interim = NTL::conv<ulong>(outp_);
					// // std::cout << interim << "\n";
					// (*outp)[i][j] = round_toL(interim, q, q1) + small_err();
				}
				// std::cout << "i: " << i << "    " << omp_get_thread_num() << "\n";
			}
		// }
	}


	void part_eval_adap_mlwr(std::vector<NTL::Vec<NTL::ZZ_pX>> inp, std::vector<std::vector<u64>> *outp, NTL::Vec<NTL::ZZ_pX> keyshare, int logq, int logq1, int dim, int rank){
		int sz = inp.size();
		using namespace NTL;
		// std::cout << "inside part eval\n";

		ZZ_pX f;
		int n = 256;
		// int n = 128;
		f.SetLength(n+1);
		for(int i = 0; i < n+1; i++){
			SetCoeff(f, i, 0);
		}
		SetCoeff(f, n);
		SetCoeff(f, 0);
		ZZ_pXModulus F(f);

		ZZ_pX tmp;
		Vec<ZZ_pX> res;
		res.SetLength(sz);
		for(int i = 0; i < sz; i++){
			res[i].SetLength(dim);
			clear(res[i]);
		}
		
		for(int i = 0; i < inp.size(); i++){
			for(int j = 0; j < rank; j++){
				// std::cout << conv<ulong>(inp[i][0][1]) << " " << conv<ulong>(keyshare[j][1]) << "\n";
				// MulMod(tmp, inp[i][j], keyshare[j], F);
				// std::cout << tmp[1] << "\n";
				// for(int k = 0; k < dim; k++){
				// 	out[i][k] += conv<ulong>(tmp[k]);
				// 	// out[i][k] = moduloL_adap((*outp)[i][k], logq);
				// 	if(k == 0 | k == 1){
				// 		std::cout << out[i][k] << "\n";
				// 	}
				// 	out[i][k] = moduloL_adap(out[i][k], logq);
				// 	if(k == 0 | k == 1){
				// 		std::cout << out[i][k] << "\n";
				// 	}
				// }
				// std::cout << out[i][1] << "\n";
				MulMod(tmp, inp[i][j], keyshare[j], F);
				res[i] += tmp;
			}
		}

		for(int i = 0; i < sz; i++){
			for(int k = 0; k < dim; k++){
				// (*outp)[i][k] = round_toL_adap(out[i][k], logq, logq1);
				(*outp)[i][k] = (u64)round_off(res[i][k], logq, logq1);
			}
		}
	}

	void part_eval_single_adap(std::vector<NTL::vec_ZZ_p> inp, std::vector<u64> *outp, NTL::vec_ZZ_p keyshare, int logq, int logq1){
		for(int j = 0; j < 13; j++){
			NTL::ZZ_p outp_;
			NTL::InnerProduct(outp_, inp[j], keyshare);
			// u64 interim = NTL::conv<ulong>(outp_);
			// (*outp)[j] = (u32)round_off(outp_, logq, logq1);
			(*outp)[j] = (u64)round_off(outp_, logq, logq1);
		}
	}

	void part_eval_single_adap_mlwr(NTL::Vec<NTL::ZZ_pX> inp, std::vector<u64> *outp, NTL::Vec<NTL::ZZ_pX> keyshare, int logq, int logq1, NTL::ZZ_pXModulus F, int dim, int rank){
		// using namespace NTL;

		// std::vector<u64> out;
		// out.resize(dim);

		NTL::ZZ_pX tmp;
		NTL::ZZ_pX res;
		res.SetLength(dim);
		clear(res);
		// std::cout << inp[0][1] << " " << keyshare[0][1] << "\n";
		for(int j = 0; j < rank; j++){
			NTL::MulMod(tmp, inp[j], keyshare[j], F);
			res += tmp;
			// std::cout << res[1] << "\n";
			// for(int k = 0; k < dim; k++){
			// 	out[k] += conv<ulong>(tmp[k]);
			// 	out[k] = moduloL_adap(out[k], logq);
			// }
			// u64 interim = NTL::conv<ulong>(outp_);
			// (*outp)[j] = (u32)round_off(outp_, logq, logq1);
		}
		for(int k = 0; k < dim; k++){
			// (*outp)[k] = round_toL_adap(conv<ulong>(res[k]), logq, logq1);
			(*outp)[k] = (u64)round_off(res[k], logq, logq1);
			// std::cout << (*outp)[k] << "\n";
		}
	}


	void direct_eval_single_adap(std::vector<NTL::vec_ZZ_p> inp, block *outp, NTL::vec_ZZ_p key, int logq, int logp){
		std::vector<u16> outp_arr;
		outp_arr.resize(13);
		for(int i = 0; i < 13; i++){
			NTL::ZZ_p outp_;
			NTL::InnerProduct(outp_, inp[i], key);
			// u64 interim = NTL::conv<ulong>(outp_);
			outp_arr[i] = (u16)round_off(outp_, logq, logp);
			// direct_eval_basic3(inp[i], &(outp_arr[i]), key, q, p, t);
		}
		*outp = decimal_array_to_single_block(outp_arr);
	}


	void direct_eval_adap(std::vector<block> in, std::vector<block>* dir_out, NTL::vec_ZZ_p key, int logq, int logp){
		std::vector<std::vector<NTL::vec_ZZ_p>> inp;
		inp.resize(in.size());
		for(int i = 0; i < inp.size(); i++){
			inp[i].resize(13);
			std::vector<u16> outp_arr(13);
			for(int j = 0; j < 13; j++){
				// inp[i][j].SetLength(256);
				inp[i][j].SetLength(1024);
			}
			convert_block_to_extended_lwr_input_adap(in[i], &(inp[i]));
			for(int j = 0; j < 13; j++){
				NTL::ZZ_p outp_;
				NTL::InnerProduct(outp_, inp[i][j], key);
				// u64 interim = NTL::conv<ulong>(outp_);
				outp_arr[j] = (u16)round_off(outp_, logq, logp);
			}
			(*dir_out)[i] = decimal_array_to_single_block(outp_arr);
		}
	}

	void direct_eval_adap_mlwr(std::vector<block> in, std::vector<block>* dir_out, NTL::Vec<NTL::ZZ_pX> key, int logq, int logp, int dim, int rank){
		std::vector<NTL::Vec<NTL::ZZ_pX>> inp;
		inp.resize(in.size());
		using namespace NTL;

		// std::vector<std::vector<u64>> out;
		// out.resize(in.size());
		// for(int i = 0; i < in.size(); i++){
		// 	out[i].resize(dim);
		// }

		ZZ_pX f;
		int n = 256;
		// int n = 128;
		f.SetLength(n+1);
		for(int i = 0; i < n+1; i++){
			SetCoeff(f, i, 0);
		}
		SetCoeff(f, n);
		SetCoeff(f, 0);
		ZZ_pXModulus F(f);

		for(int i = 0; i < inp.size(); i++){
			inp[i].SetLength(rank);
			for(int j = 0; j < rank; j++){
				inp[i][j].SetLength(dim);
			}
		}

		for(int i = 0; i < inp.size(); i++){
        	convert_block_to_extended_mlwr_input_adap(in[i], &(inp[i]), rank);
        }

        ZZ_pX tmp;
        Vec<ZZ_pX> res;
        res.SetLength(in.size());
        for(int i = 0; i < in.size(); i++){
        	res[i].SetLength(dim);
        	clear(res[i]);
        }
		for(int i = 0; i < inp.size(); i++){
			for(int j = 0; j < rank; j++){
				MulMod(tmp, inp[i][j], key[j], F);
				// for(int k = 0; k < dim; k++){
				// 	out[i][k] += conv<ulong>(tmp[k]);
				// 	out[i][k] = moduloL_adap(out[i][k], logq);
				// }
				res[i] += tmp;
			}
		}

		std::vector<std::vector<u16>> temp;
		temp.resize(in.size());
		for(int i = 0; i < temp.size(); i++){
			temp[i].resize(dim);
		}
		for(int i = 0; i < inp.size(); i++){
			for(int k = 0; k < dim; k++){
				// temp[i][k] = round_toL_adap(out[i][k], logq, logp);
				temp[i][k] = (u16)round_off(res[i][k], logq, logp);
			}
			(*dir_out)[i] = poln_to_single_block(temp[i]);
		}
	}

	void direct_eval_single_adap_mlwr(NTL::Vec<NTL::ZZ_pX> inp, block *outp, NTL::Vec<NTL::ZZ_pX> key, int logq, int logp, NTL::ZZ_pXModulus F, int dim, int rank){
		std::vector<u64> outp_arr;
		outp_arr.resize(dim);

		using namespace NTL;

		ZZ_pX tmp;
		for(int i = 0; i < rank; i++){
			MulMod(tmp, inp[i], key[i], F);
			for(int k = 0; k < dim; k++){
				outp_arr[k] += conv<ulong>(tmp[k]);
				outp_arr[k] = moduloL_adap(outp_arr[k], logq);
			}
		}

		std::vector<u16> interim;
		interim.resize(dim);
		for(int i = 0; i < dim; i++){
			interim[i] = round_toL_adap(outp_arr[i], logq, logp);
		}
		*outp = poln_to_single_block(interim);
	}

	void direct_eval_single_adap_mlwr_batch(NTL::Vec<NTL::ZZ_pX> inp, std::vector<block> *outp, NTL::Vec<NTL::ZZ_pX> key, int logq, int logp, NTL::ZZ_pXModulus F, int dim, int rank){
		std::vector<u64> outp_arr;
		outp_arr.resize(dim);

		using namespace NTL;

		ZZ_pX tmp;
		ZZ_pX res;
		res.SetLength(dim);
		clear(res);

		for(int i = 0; i < rank; i++){
			MulMod(tmp, inp[i], key[i], F);
			// for(int k = 0; k < dim; k++){
			// 	outp_arr[k] += conv<ulong>(tmp[k]);
			// 	outp_arr[k] = moduloL_adap(outp_arr[k], logq);
			// }
			res += tmp;
		}

		std::vector<std::vector<u16>> interim(1, std::vector<u16>(dim));
		// interim.resize(dim);
		for(int i = 0; i < dim; i++){
			interim[0][i] = round_off(res[i], logq, logp);
		}
		poln_to_multiple_blocks(*outp, interim);
	}
}