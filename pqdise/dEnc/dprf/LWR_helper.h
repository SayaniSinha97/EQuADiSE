#pragma once

#include <dEnc/Defines.h>
#include "cryptoTools/Crypto/RandomOracle.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/vector.h>
#include <NTL/SmartPtr.h>
#include <NTL/ZZ_pE.h>
#include <NTL/vec_ZZ_pE.h>
#include <NTL/ZZ_pX.h>
#include <map>

namespace dEnc{

	/* calculates combinatorial value nCr */
	int ncr(int n, int r);

	/* This function calculates x modulo q */
	inline u64 moduloL(u64 x, u64 q){
		if(x >= 0){
			return x%q;
		}
		else{
			x = (-x)%q;
			return (x ? (q-x) : x);
		}
	};

	/* This function rounds an integer in modulo q to an integer in modulo p. Basically for x in Z_q the function maps
	it to the nearest integer of (x*p/q) */
	inline u64 round_toL(u64 x, u64 q, u64 p){
		x >>= (int)(log2(q) - log2(p) - 1);
		int flag = (x & 1) ? 1 : 0;
		x >>= 1;
		return (x + flag);
	};

	/* This function calculates x modulo q */
	inline u64 moduloL_adap(u64 x, int logq){
		u64 x_ = x;
		u64 y;
		if(x >= 0){
			y = x >> logq;
			return (x_ - (y << logq));
		}
		else{
			y = (-x) >> logq;
			y = (-x_) - (y << logq);
			return (y ? ((1 << logq) - y) : y);
		}
	};

	/* This function rounds an integer in modulo q to an integer in modulo p. Basically for x in Z_q the function maps
	it to the nearest integer of (x*p/q) */
	inline u64 round_toL_adap(u64 x, int logq, int logp){
		x >>= (logq - logp - 1);
		int flag = (x & 1) ? 1 : 0;
		x >>= 1;
		return (x + flag);
	};

	u64 round_off(NTL::ZZ_p x, int logq, int logp);

	// /* This function calculates multiplication (a * b) modulo q */
	// u64 moduloMultiplication(u64 a, u64 b, u64 q);

	// /* This function performs vector dot product modulo q */
	// u64 modular_dot_productL(u64 a[], u64 b[], u64 n, u64 q);

	// /* Given a group_id, find the party_ids present in (group_id)^th combination out of TCt combinations */
	void findParties(std::vector<u64>& pt, u64 gid, u64 t, u64 T);
	void findParties_adap(std::vector<int>& pt, int gid, int t, int T);

	// /* Given a t-sized list of party-ids compute its rank among total TCt combinations */
	u64 findGroupId(std::vector<u64> parties, u64 t, u64 T);
	int findGroupId_adap(std::vector<int> parties, int t, int T);

	block decimal_array_to_single_block(std::vector<u16> arr);
	block poln_to_single_block(std::vector<u16> p);
	void poln_to_multiple_blocks(std::vector<block> &out, std::vector<std::vector<u16>> in);
	void convert_block_to_extended_lwr_input(block x, std::vector<NTL::vec_ZZ_p>* y);
	void convert_block_to_extended_lwr_input_adap(block x, std::vector<NTL::vec_ZZ_p>* y);
	void convert_block_to_extended_mlwr_input_adap(block x, NTL::Vec<NTL::ZZ_pX>* y, int rank);
	void convert_block_to_extended_mlwr_input_adap_batch(std::vector<block> x, NTL::Vec<NTL::ZZ_pX>* y, int rank);

	// int small_err();
	/* the partial evaluation function of LWR-based DPRF */
	void part_eval(std::vector<std::vector<NTL::vec_ZZ_p>> inp, std::vector<std::vector<u32>> *outp, NTL::vec_ZZ_p keyshare, u64 q, u64 q1);
	void part_eval_single(std::vector<NTL::vec_ZZ_p> inp, std::vector<u32> *outp, NTL::vec_ZZ_p keyshare, u64 q, u64 q1);

	/* the direct evaluation function of LWR-based PRF */
	void direct_eval(std::vector<block> in, std::vector<block>* dir_out, NTL::vec_ZZ_p key, u64 q, u64 p);
	void direct_eval_single(std::vector<NTL::vec_ZZ_p> inp, block *outp, NTL::vec_ZZ_p key, u64 q, u64 p);

	/* partial evaluation for combinatorial base distributed construction of LWR-PRF */
	void part_eval_base_lwr(std::vector<NTL::vec_ZZ_p> inp, block *outp, std::vector<NTL::vec_ZZ_p> key_list, int logq, int logp);

	// /* the partial evaluation function of LWR-based Adaptive DPRF */
	void part_eval_adap(std::vector<std::vector<NTL::vec_ZZ_p>> inp, std::vector<std::vector<u64>> *outp, NTL::vec_ZZ_p keyshare, int logq, int logq1);
	void part_eval_single_adap(std::vector<NTL::vec_ZZ_p> inp, std::vector<u64> *outp, NTL::vec_ZZ_p keyshare, int logq, int logq1);

	// /* the direct evaluation function of LWR-based Adaptive PRF */
	void direct_eval_adap(std::vector<block> in, std::vector<block>* dir_out, NTL::vec_ZZ_p key, int logq, int logp);
	void direct_eval_single_adap(std::vector<NTL::vec_ZZ_p> inp, block *outp, NTL::vec_ZZ_p key, int logq, int logp);

	void part_eval_adap_mlwr(std::vector<NTL::Vec<NTL::ZZ_pX>> inp, std::vector<std::vector<u64>> *outp, NTL::Vec<NTL::ZZ_pX> keyshare, int logq, int logq1, int dim, int rank);
	void direct_eval_adap_mlwr(std::vector<block> in, std::vector<block>* dir_out, NTL::Vec<NTL::ZZ_pX> key, int logq, int logp, int dim, int rank);

	void part_eval_single_adap_mlwr(NTL::Vec<NTL::ZZ_pX> inp, std::vector<u64> *outp, NTL::Vec<NTL::ZZ_pX> keyshare, int logq, int logq1, NTL::ZZ_pXModulus F, int dim, int rank);
	void direct_eval_single_adap_mlwr(NTL::Vec<NTL::ZZ_pX> inp, block *outp, NTL::Vec<NTL::ZZ_pX> key, int logq, int logp, NTL::ZZ_pXModulus F, int dim, int rank);
	void direct_eval_single_adap_mlwr_batch(NTL::Vec<NTL::ZZ_pX> inp, std::vector<block> *outp, NTL::Vec<NTL::ZZ_pX> key, int logq, int logp, NTL::ZZ_pXModulus F, int dim, int rank);
}