#pragma once

#include <dEnc/Defines.h>
#include "cryptoTools/Crypto/RandomOracle.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/vector.h>
#include <NTL/SmartPtr.h>
#include "LWR_helper.h"
#include <omp.h>
#include <map>

#define THREADNUM 8

namespace dEnc{

	void compute_product_with_inverse(std::vector<std::vector<u8>>& acc1, std::vector<std::vector<u8>>& acc2, NTL::Vec<NTL::vec_ZZ_p> matrix, int n, int m, int logq);
	void compute_input_dependent_matrix(NTL::Vec<NTL::vec_ZZ_p>& A, NTL::Vec<NTL::vec_ZZ_p> A0, std::vector<std::vector<u8>> acc1, std::vector<std::vector<u8>> acc2, int n, int m, int logq);
	void convert_block_to_lwe_input(block x, NTL::Vec<NTL::vec_ZZ_p>& y, NTL::Vec<NTL::Vec<NTL::Vec<NTL::vec_ZZ_p>>> mat_list, NTL::Vec<NTL::vec_ZZ_p> A0, int n, int m, int logq);
	block randomness_extractor(std::vector<u16> v);

	/* the partial evaluation function of LWE-based Adaptive DPRF */
	void part_eval_adap(std::vector<NTL::Vec<NTL::vec_ZZ_p>> inp, std::vector<std::vector<u32>> *outp, std::vector<int> keyshare, int dim, int dim_, int logq, int logq1);
	void part_eval_adap_single(NTL::Vec<NTL::vec_ZZ_p> inp, std::vector<u32> *outp, std::vector<int> keyshare, int dim, int dim_, int logq, int logq1);

	// // /* the direct evaluation function of LWE-based Adaptive PRF */
	// void direct_eval_adap(std::vector<block> in, std::vector<block>* dir_out, NTL::vec_ZZ_p key, int logq, int logp);
	void direct_eval_adap_single(NTL::Vec<NTL::vec_ZZ_p> inp, block *outp, std::vector<int> key, int dim, int dim_, int logq, int logp);
}