#include <vector>
#include <algorithm>
#include <fstream>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cmath>
#include <sys/time.h>
#include <bits/stdc++.h>

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <tfhe/lwe-functions.h>
#include <tfhe/numeric_functions.h>
#include <tfhe/tlwe_functions.h>
#include <tfhe/tfhe_garbage_collector.h>

#define MSIZE 2
using namespace std;

// Initialize AES parameters
int in_size = 128;
int out_size = 128;

int in_arr_size = 36663;
int out_arr_size = 36919;

TFheGateBootstrappingParameterSet *initialize_gate_bootstrapping_params() {
    static const int32_t N = 1024;
    static const int32_t k = 1;
    static const int32_t n = 1024;
    static const int32_t bk_l = 3;
    static const int32_t bk_Bgbit = 7;
    static const int32_t ks_basebit = 2;
    static const int32_t ks_length = 8;
    static const double ks_stdev = pow(2.,-15); //standard deviation
    static const double bk_stdev = pow(2.,-25);; //standard deviation
    static const double max_stdev = 0.012467; //max standard deviation for a 1/4 msg space

    LweParams *params_in = new_LweParams(n, ks_stdev, max_stdev);
    TLweParams *params_accum = new_TLweParams(N, k, bk_stdev, max_stdev);
    TGswParams *params_bk = new_TGswParams(bk_l, bk_Bgbit, params_accum);

    TfheGarbageCollector::register_param(params_in);
    TfheGarbageCollector::register_param(params_accum);
    TfheGarbageCollector::register_param(params_bk);

    return new TFheGateBootstrappingParameterSet(ks_length, ks_basebit, params_in, params_bk);
}

void share_secret(int t, int T, TLweKey *key, TLweParams *params, std::vector<TLweKey*> &key_shares){
    int k = key->params->k;
    int N = key->params->N;
    std::default_random_engine gen;
    std::uniform_int_distribution<int> dist(0, 1);
    for(int i = 0; i < k; i++){
        for(int j = 0; j < N; j++){
            (key_shares[0])->key[i].coefs[j] = key->key[i].coefs[j];
        }
    }
    for(int i = 1; i < t; i++){
        for(int j = 0; j < k; j++){
            for(int k = 0; k < N; k++){
                key_shares[i]->key[j].coefs[k] = dist(gen);
                key_shares[0]->key[j].coefs[k] += key_shares[i]->key[j].coefs[k];
            }
        }
    }
    // std::cout << "key shares\n";
    // for(int i = 0; i < t; i++){
    //     for(int j = 0; j < k; j++){
    //         for(int k = 0; k < 10; k++){
    //             std::cout << key_shares[i]->key[j].coefs[k] << " ";
    //         }
    //     }
    //     std::cout << "\n";
    // }
}

void TLweFromLwe(TLweSample *ring_cipher, LweSample *cipher, TLweParams *tlwe_params){
    int N = tlwe_params->N;
    ring_cipher->a[0].coefsT[0] = cipher->a[0];
    ring_cipher->b->coefsT[0] = cipher->b;
    for(int i = 1; i < N; i++){
        ring_cipher->a[0].coefsT[i] = -cipher->a[N-i];
    }
}

void TLweKeyFromLweKey(const LweKey *lwe_key, TLweKey *tlwe_key){
    int N = tlwe_key->params->N;
    tlwe_key->key[0].coefs[0] = lwe_key->key[0];
    for(int i = 0; i < N; i++){
        tlwe_key->key[0].coefs[i] = lwe_key->key[i];
    }
}

// Read AES netlist
std::vector<std::vector<int>> readNetlist(const std::string& filename) {
    std::ifstream file(filename);
    std::vector<std::vector<int>> result;

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::vector<int> temp;
        int val;
        while (iss >> val) {
            temp.push_back(val);
        }

        result.push_back(temp);
    }
    std::cout << result.size() << "\n";

    return result;
}

// Function to perform AES evaluation
void aesEval(LweSample* enc_aes_output, const std::vector<std::vector<int>>& netlist, const LweSample* enc_aes_msg, 
                                const LweSample* enc_aes_key, LweSample* aes_output_arr, const LweParams* params, const TFheGateBootstrappingCloudKeySet* bk) {


    // Fill first 256 bits of output array with 128 bit AES encrypted msg and 128 bit AES encrypted key
    for (int i = 0; i < in_size; ++i) {
        lweCopy(&aes_output_arr[i], &enc_aes_msg[i], params);
        lweCopy(&aes_output_arr[i + in_size], &enc_aes_key[i], params);
    }

    for (int i = 0; i < netlist.size(); ++i) {
        if (netlist[i].back() == 0 && netlist[i].front() == 2) { // XOR operation
            int in1 = netlist[i][2];
            int in2 = netlist[i][3];
            int out = netlist[i][4];

            bootsXOR(&aes_output_arr[out], &aes_output_arr[in1], &aes_output_arr[in2], bk);

        }
        else if (netlist[i].back() == 1 && netlist[i].front() == 2) { // AND operation
            int in1 = netlist[i][2];
            int in2 = netlist[i][3];
            int out = netlist[i][4];

            bootsAND(&aes_output_arr[out], &aes_output_arr[in1], &aes_output_arr[in2], bk);

        }
        else{ // NOT operation
            int in1 = netlist[i][2];
            int out = netlist[i][3];

            bootsNOT(&aes_output_arr[out], &aes_output_arr[in1], bk);
        }
    }

    for(int i = 0; i < out_size; i++){
        lweCopy(&enc_aes_output[out_size-1-i], &aes_output_arr[out_arr_size-1-i], params);
    }
}

int main(int argc, char *argv[]) {
    int t = atoi(argv[1]);
    int T = atoi(argv[2]);

    std::vector<std::vector<int>> inp(2, std::vector<int>(in_size));
    std::vector<int> outp(out_size);
    srand(time(0));
    for (int i= 0; i < in_size; i++)
    {
        inp[0][i]= rand() % 2; // Message
        inp[1][i]= rand() % 2; // Key
        // inp[0][i]= 0; // Message
        // inp[1][i]= 1; // Key
    }

    cout << "\n\nMessage: " << endl;

    for (int i=0; i < in_size; i++)
    {
        cout << inp[0][i] << " ";
    }

    cout << "\n\nKey: " << endl;

    for (int i=0; i < in_size; i++)
    {
        cout << inp[1][i] << " ";
    }

    cout << "\n";

    // 
    auto params = initialize_gate_bootstrapping_params();

    // Key generation
    auto sk = new_random_gate_bootstrapping_secret_keyset(params);
    auto bk = &sk->cloud;

    TLweParams *tlwe_params = new_TLweParams(1024, 1, 3e-8, 0.2);
    TLweKey *tlwe_key = new_TLweKey(tlwe_params);
    tLweKeyGen(tlwe_key);
    // Convert LWE key to TLWE key
    TLweKeyFromLweKey(sk->lwe_key, tlwe_key);

    std::vector<TLweKey*> key_shares(t);
    for(int i = 0; i < t; i++){
        key_shares[i] = new_TLweKey(tlwe_params);
    }
    share_secret(t, T, tlwe_key, tlwe_params, key_shares);

    // Read AES netlist
    cout << "\n\nLoading Circuit . . ." << endl;
    std::vector<std::vector<int>> aes_netlist = readNetlist("test/aes_2anf_128.txt");

    // Encrypt AES msg and AES key
    LweSample *enc_aes_msg = new_gate_bootstrapping_ciphertext_array(in_size, params);
    LweSample *enc_aes_key = new_gate_bootstrapping_ciphertext_array(in_size, params);

    for (int i = 0; i < in_size; ++i) {
        bootsSymEncrypt(&enc_aes_msg[i], inp[0][i], sk);
        bootsSymEncrypt(&enc_aes_key[i], inp[1][i], sk);
    }

    // Initialize an output array, where input, key and intermediate LWE samples are stored during aes operation
    LweSample *aes_output_arr = new_gate_bootstrapping_ciphertext_array(out_arr_size, params);
    LweSample *enc_aes_output = new_gate_bootstrapping_ciphertext_array(out_size, params);

    // Evaluate AES circuit
    cout << "\nEvaluating Circuit . . ." << endl;
    clock_t begin_eval = clock();
    aesEval(enc_aes_output, aes_netlist, enc_aes_msg, enc_aes_key, aes_output_arr, params->in_out_params, bk); 
    clock_t end_eval = clock();

    double time_eval = ((double) end_eval - begin_eval)/CLOCKS_PER_SEC;
    cout << "Finished Evaluation: " << time_eval << " seconds"<< endl;

    // Decrypt the AES output
    std::cout << "final decryption\n";
    std::vector<int> aes_clear_output(out_size);

    for (int i = 0; i < out_size; ++i) {
        // std::cout << i << " ";
        aes_clear_output[i] = bootsSymDecrypt(&enc_aes_output[i], sk);
    }

    // Print AES clear output
    for (int bit : aes_clear_output) {
        std::cout << bit << " ";
    }
    std::cout << "\n";

    int k = tlwe_params->k;
    int N = tlwe_params->N;
    double sd = 0.0078125;
    double part_dec_total_time = 0, final_dec_total_time = 0;
    double part_dec_avg_time, final_dec_avg_time;

    TorusPolynomial *direct_result_plaintext;
    int dbit;
    TLweSample *ciphertext;
    TorusPolynomial* acc = new_TorusPolynomial(N);
    TorusPolynomial **part_evals = (TorusPolynomial**)malloc(t * sizeof(TorusPolynomial*));
    for(int i = 0; i < t; i++){
        part_evals[i] = new_TorusPolynomial(N);
    }

    /* Threshold Decryption */
    std::cout << "Threshold Decryption:\n";
    for(int i = 0; i < out_size; i++){
        ciphertext = new_TLweSample(tlwe_params);
        TLweFromLwe(ciphertext, &enc_aes_output[i], tlwe_params);

        /* Direct Decryption using tlwe key for verification */
        direct_result_plaintext = new_TorusPolynomial(tlwe_params->N);
        tLwePhase(direct_result_plaintext, ciphertext, tlwe_key);
        dbit = (direct_result_plaintext->coefsT[0] > 0) ? 1 : 0;
        // std::cout << "dbit: " << dbit << " ";

        /* Distribted Decryrpion */
        for(int j = 0; j < N; j++){
            acc->coefsT[j] = 0;
        }
        for(int j = 0; j < t; j++){
            for(int k = 0; k < N; k++){
                part_evals[j]->coefsT[k] = 0;
            }
        }
        
        // std::cout << "here\n";
        for(int party = 0; party < t; party++){
            clock_t start_part_dec = clock();
            // TorusPolynomial *tmp = new_TorusPolynomial(N);
            // for(int j = 0; j < N; j++){
            //     tmp->coefsT[j] = 0;
            // }
            TorusPolynomial *err = new_TorusPolynomial(N);
            for(int j = 0; j < N; j++){
                err->coefsT[j] = gaussian32(0, sd);
            }
            auto key_share = key_shares[party];
            for(int j = 0; j < k; j++){
                torusPolynomialAddMulR(part_evals[party], &key_share->key[j], &ciphertext->a[j]);
            }
            torusPolynomialAddTo(part_evals[party], err);
            clock_t end_part_dec = clock();

            double interval_part = ((double) end_part_dec - start_part_dec)/CLOCKS_PER_SEC;
            part_dec_total_time += interval_part;
        }

        clock_t start_final_dec = clock();
        for(int j = 0; j < t; j++){           
            if(j == 0){
                torusPolynomialAddTo(acc, part_evals[j]);
            }
            else{
                torusPolynomialSubTo(acc, part_evals[j]);
            } 
        }
        torusPolynomialSubTo(acc, ciphertext->b);  
        int plain_bit = (acc->coefsT[0] <= 0) ? 1 : 0;
        clock_t end_final_dec = clock();
        double interval_final = ((double) end_final_dec - start_final_dec)/CLOCKS_PER_SEC;
        final_dec_total_time += interval_final;
        
        std::cout << plain_bit << " ";
    }
    std::cout << "\n";
    part_dec_avg_time = part_dec_total_time/t;
    final_dec_avg_time = final_dec_total_time;

    double part_eval_time = time_eval + part_dec_avg_time;
    double final_eval_time = final_dec_avg_time;

    std::cout << "\npart eval time: " << part_eval_time << " seconds, final eval time: " << final_eval_time << " seconds.\n";
    

    return 0;
}
