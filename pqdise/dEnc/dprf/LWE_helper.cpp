#include "LWE_helper.h"
#include <cryptoTools/Common/Timer.h>
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/block.h"
#include <string>
#include <map>
#include <random>
#include <omp.h>

namespace dEnc{
	using RandomOracle = oc::RandomOracle;
	int hamming_code[16] = {0,13,23,26,35,46,52,57,70,75,81,92,101,104,114,127};

	int bin_to_dec(char *bin_arr){
		int num = 0;
		for(int i = 0; i < 4; i++){
			num += bin_arr[i] == '1' ? (int)pow(2,i) : 0;
		}
		return num;
	}

	void dec_to_bin(int num, char *bin_arr){
		// std::cout << "inside dec-to-bin " << num << "\n";
		for(int i = 0; i < 7; i++){
			bin_arr[i] = num%2 == 0 ? '0' : '1';
			num /= 2;
		}
	}

	void BAHF(char *input, char* output){
		int inp = bin_to_dec(input);
		// std::cout << inp << "\n";
		int outp = hamming_code[inp];
		// std::cout << outp << "\n";
		dec_to_bin(outp, output);
	}

	void compute_product_with_inverse(std::vector<std::vector<u8>>& acc1, std::vector<std::vector<u8>>& acc2, NTL::Vec<NTL::vec_ZZ_p> matrix, int n, int m, int logq){
		// std::cout << "inside compute-product-with-inverse " << THREADNUM << "\n";
		using namespace NTL;
		#pragma omp parallel num_threads(THREADNUM)
		{
			ZZ_p::init(conv<ZZ>(pow(2,logq)));
			#pragma omp for collapse(2)
			for(int i = 0; i < n; i++){
				for(int j = 0; j < m/2; j++){
					ZZ a = conv<ZZ>(matrix[i][j]);
					// std::cout << "a: " << a << "\n";
					for(int k = 0; k < logq; k++){
						// acc1[i*logq + k][j] = (u8)(acc1[i*logq + k][j] + a%2);
						acc1[i*logq + k][j] = (u8)(acc1[i*logq + k][j] + (a%2));
						a /= 2;
					}
				}
			}
			// std::cout << "between\n";
			#pragma omp for collapse(2)
			for(int i = 0; i < n; i++){
				for(int j = m/2; j < m; j++){
					ZZ b = conv<ZZ>(matrix[i][j]);
					// std::cout << "b: " << b << "\n";
					for(int k = 0; k < logq; k++){
						// acc2[i*logq + k][j-m/2] = (u8)(acc2[i*logq + k][j-m/2] + b%2);
						acc2[i*logq + k][j-m/2] = (u8)(acc2[i*logq + k][j-m/2] + b%2);
						b /= 2;
					}
				}
			}
		}
		// std::cout << "\n\n";
		// std::cout << "acc1\n";
		// for(int i = 0; i < 5; i++){
		// 	for(int j = 0; j < 5; j++){
		// 		std::cout << +acc1[i][j] << "  ";
		// 	}
		// 	std::cout << "\n";
		// }
		// std::cout << "\nacc2\n";
		// for(int i = 0; i < 5; i++){
		// 	for(int j = 0; j < 5; j++){
		// 		std::cout << +acc2[i][j] << "  ";
		// 	}
		// 	std::cout << "\n";
		// }
	}

	void compute_input_dependent_matrix(NTL::Vec<NTL::vec_ZZ_p>& A, NTL::Vec<NTL::vec_ZZ_p> A0, std::vector<std::vector<u8>> acc1, std::vector<std::vector<u8>> acc2, int n, int m, int logq){
		// std::cout << "in input dependent matrix computation\n";
		using namespace NTL;
		for(int i = 0; i < n; i++){
			#pragma omp parallel num_threads(THREADNUM)
			{
				ZZ_p::init(conv<ZZ>(pow(2,logq)));
				#pragma omp for collapse(2)
				for(int j = 0; j < m/2; j++){
					// A[i][j] = 0;
					for(int k = 0; k < m/2; k++){
						ZZ_p tmp = A0[i][k] * acc1[k][j];
						A[i][j] += tmp;
					}
				}

				#pragma omp for collapse(2)
				for(int j = m/2; j < m; j++){
					// A[i][j] = 0;
					for(int k = m/2; k < m; k++){
						ZZ_p tmp_ = A0[i][k] * acc2[k-m/2][j-m/2];
						A[i][j] += tmp_;
					}
				}
			}
			// std::cout << i << "\n";
		}
	}

	void convert_block_to_lwe_input(block x, NTL::Vec<NTL::vec_ZZ_p>& y, NTL::Vec<NTL::Vec<NTL::Vec<NTL::vec_ZZ_p>>> mat_list, NTL::Vec<NTL::vec_ZZ_p> A0, int n, int m, int logq){
		// std::cout << "inside convert-block-to-lwe-input\n";
		u8 hash_output;
		RandomOracle myHash(1);
		myHash.Update(x);
		myHash.Final(hash_output);
		// std::cout << "block: " << x << "\n";
		// std::cout << "hash_output: " << +hash_output << "\n";

		u8 hash_output0 = hash_output%16;
		u8 hash_output1 = hash_output/16;

		// std::cout << +hash_output0 << " " << +hash_output1 << "\n";

		char *bin_input0 = (char*)malloc(4*sizeof(char));
		dec_to_bin(hash_output0, bin_input0);
		char *bin_output0 = (char*)malloc(7*sizeof(char));
		BAHF(bin_input0, bin_output0);

		char *bin_input1 = (char*)malloc(4*sizeof(char));
		dec_to_bin(hash_output1, bin_input1);
		char *bin_output1 = (char*)malloc(7*sizeof(char));
		BAHF(bin_input1, bin_output1);

		char *bin_output = (char*)malloc(7*sizeof(char));
		for(int i = 0; i < 7; i++){
			bin_output[i] = (bin_output0[i] == bin_output1[i]) ? '0' : '1';
		}

		/* acc1 and acc2 are the accumulator matrices to store the left upper corner and bottom right corner of product of all G_inverse of A_{i,x[i]}  for i\in[L] */
		std::vector<std::vector<u8>> acc1;
		std::vector<std::vector<u8>> acc2;
		acc1.resize(m/2);
		for(int i = 0; i < m/2; i++){
			acc1[i].resize(m/2);
			for(int j = 0; j < m/2; j++){
				acc1[i][j] = 0;
			}
		}
		acc2.resize(m/2);
		for(int i = 0; i < m/2; i++){
			acc2[i].resize(m/2);
			for(int j = 0; j < m/2; j++){
				acc2[i][j] = 0;
			}
		}

		/* Update accumulator matrix with product of L matrices of the form A_{i,x_i} for i \in [L]*/
		int bit;
		for(int i = 0; i < 7; i++){
			bit = bin_output[i] == '0' ? 0 : 1;
			compute_product_with_inverse(acc1, acc2, mat_list[i][bit], n, m, logq);
		}

		// using namespace NTL;
		// Vec<vec_ZZ_p> A;
		// A.SetLength(n);
		// for(int i = 0; i < n; i++){
		// 	A[i].SetLength(m);
		// 	#pragma omp parallel num_threads(THREADNUM)
		// 	{
		// 		ZZ_p::init(conv<ZZ>(pow(2,logq)));
		// 		#pragma omp for
		// 		for(int j = 0; j < m; j++){
		// 			A[i][j] = 0;
		// 		}
		// 	}
		// }
		
		compute_input_dependent_matrix(y, A0, acc1, acc2, n, m, logq);
	}

	block randomness_extractor(std::vector<u16> v){
		block res;
		// for(int i = 0; i < 10; i++){
		// 	std::cout << v[i] << " ";
		// }
		// std::cout << "\n";
		RandomOracle hash_vector_to_block(16);
		for(int i = 0; i < 100; i++){
			hash_vector_to_block.Update(v[i]);
		}
		hash_vector_to_block.Final(res);
		return res;
	}

	void part_eval_adap(std::vector<NTL::Vec<NTL::vec_ZZ_p>> inp, std::vector<std::vector<u32>> *outp, std::vector<int> keyshare, int dim, int dim_, int logq, int logq1){
		// std::cout << "inside part_eval_adap LWE\n";
		int sz = inp.size();
		using namespace NTL;
		Vec<ulong> s;
		s.SetLength(dim);
		for(int i = 0; i < dim; i++){
			s[i] = conv<ulong>(keyshare[i]);
		}
		// std::cout << "the A(x) matrix\n";
		// for(int i = 0; i < 4; i++){
		// 	for(int j = 0; j < 4; j++){
		// 		for(int k = 0; k < 4; k++){
		// 			std::cout << inp[i][j][k] << " ";
		// 		}
		// 		std::cout << "\n";
		// 	}
		// 	std::cout << "\n";
		// }
		for(int i = 0; i < sz; i++){
			vec_ZZ_p res_modq;
			res_modq.SetLength(dim_);
			clear(res_modq);
			#pragma omp parallel num_threads(THREADNUM)
			{
				ZZ_p::init(conv<ZZ>(pow(2,logq)));
				#pragma omp for
				for(int j = 0; j < dim_; j++){
					for(int k = 0; k < dim; k++){
						res_modq[j] += (inp[i][k][j] * s[k]);
					}
				}
				#pragma omp for
				for(int j = 0; j < dim_; j++){
					(*outp)[i][j] = round_off(res_modq[j], logq, logq1);
				}
			}
		}
		// std::cout << "the A(x)s_i vector\n";
		// for(int i = 0; i < 4; i++){
		// 	for(int j = 0; j < 10; j++){
		// 		std::cout << (*outp)[i][j] << " ";
		// 	}
		// 	std::cout << "\n";
		// }
	}

	void part_eval_adap_single(NTL::Vec<NTL::vec_ZZ_p> inp, std::vector<u32> *outp, std::vector<int> keyshare, int dim, int dim_, int logq, int logq1){
		// std::cout << "inside part_eval_adap LWE\n";
		// int sz = inp.size();
		using namespace NTL;
		Vec<ulong> s;
		s.SetLength(dim);
		for(int i = 0; i < dim; i++){
			s[i] = conv<ulong>(keyshare[i]);
		}
		
		vec_ZZ_p res_modq;
		res_modq.SetLength(dim_);
		clear(res_modq);
		#pragma omp parallel num_threads(THREADNUM)
		{
			ZZ_p::init(conv<ZZ>(pow(2,logq)));
			#pragma omp for collapse(2)
			for(int j = 0; j < dim_; j++){
				for(int k = 0; k < dim; k++){
					res_modq[j] += (inp[k][j] * s[k]);
				}
			}
			#pragma omp for
			for(int j = 0; j < dim_; j++){
				(*outp)[j] = (u32)round_off(res_modq[j], logq, logq1);
			}
		}

		// std::cout << "inside part eval\n";
		// for(int j = 0; j < 10; j++){
		// 	std::cout << (*outp)[j] << " ";
		// }
		// std::cout << "\n";
	}

	void direct_eval_adap_single(NTL::Vec<NTL::vec_ZZ_p> inp, block *outp, std::vector<int> key, int dim, int dim_, int logq, int logp){
		using namespace NTL;
		std::vector<u16> out(dim_);

		Vec<ulong> s;
		s.SetLength(dim);
		for(int j = 0; j < dim; j++){
			s[j] = conv<ulong>(key[j]);
		}
		vec_ZZ_p res_modq;
		res_modq.SetLength(dim_);
		clear(res_modq);

		#pragma omp parallel num_threads(THREADNUM)
		{
			ZZ_p::init(conv<ZZ>(pow(2,logq)));
			#pragma omp for collapse(2)
			for (int i = 0; i < dim_; i++){
				for(int j = 0; j < dim; j++){
					res_modq[i] += inp[j][i] * s[j];
				}
			}
		
			#pragma omp for
			for(int i = 0; i < dim_; i++){
				out[i] = round_off(res_modq[i], logq, logp);
			}
		}
		// for(int i = 0; i < 10; i++){
		// 	std::cout << out[i] << " ";
		// }
		// std::cout << "\n";
		*outp = randomness_extractor(out);
	}
}