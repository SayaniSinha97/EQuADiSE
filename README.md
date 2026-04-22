# EQuADiSE
EQuADiSE is the abbreviation for Efficient Quantum-safe Adaptive Distributed Symmetric-key Encryption. It improves upon the existing DiSE protocol introduced by Agrawal et al. in CCS 2018 [1]. Distributed PRF (DPRF) is an important building block of DiSE. We use adaptively secure quantum-safe DPRF in order to obtain EQuADiSE from DiSE. Our proposed DPRF is based on Module Learning with Rounding (MLWR) assumption.

In our implementation, we provide DPRF instantiated with (i) AES-based DPRF (from [1]), (ii) DDH-based DPRF (from [1]), (iii) adaptive LWE-based DPRF (from [2]), (iv) adaptive DDH-based DPRF (from [3]), (v) our proposed adaptive LWR-based DPRF and, (vi) our proposed adaptive MLWR-based DPRF. We also provide DPRF implementation of threshold FHE-based DPRF (from [4]).

# pqdise
This is built over the existing DiSE library and has a dependency on cryptoTools library as well. After cloning the repository, go to the specific folder and then run the following commands on a Linux terminal.
```
cd pqdise
cmake --preset linux
cmake --build out/build/linux
cd out/build/linux/dEncFrontend
```
Now, to run the unit tests, run
```
./dEncFrontend -u
```
To see the DPRF performances, run
```
./dEncFrontend -comp -ld -thr 5 -total 8
```
Here, "-thr" option takes the value of the threshold number of parties, "-total" takes the value of the total number of parties. Use "-ld" option to see the performance of adaptive LWR-based DPRF. Replace it with "-md", "ss", "-sa", "-ad", "-ed" to see the performance comparison of "adaptive MLWR-based DPRF", "AES-based DPRF", "DDH-based DPRF", "adaptive DDH-based DPRF", "LWE-based DPRF", respectively.The option "-ld" can be replaced with other options to see the performance comparison of various DPRFs.</br></br>
To see the encryption performance, run
```
./dEncFrontend -ld -nStart 4 -nEnd 18 -nStep 2 -mf 0.5
```
This shows the performance of DiSE (i.e., throughput or #encs/sec) while using different DPRFs. The option "-ld" can be replaced with other options to see the performance w.r.t. other DPRFs. Here,  with 0 < mf < 1, (T * mf, T)-DPRFs are used when T varies in the range [nStart, nEnd] with a leap of nStep.<br/></br>

# TFHE_DPRF
This is built over TFHE library [4]. You can get the performance of TFHE-based DPRF for (t,T) = (3,5) by running the following command in this folder.
```
cd tfhe
make
sudo make install
rm -rf build
cd ..
make
./bin/ckt_dist_eval 3 5
```
Replace (3,5) with other (t,T) values to get the performane for other threshold parameters.

[1] Agrawal, S., Mohassel, P., Mukherjee, P., & Rindal, P. (2018, October). DiSE: distributed symmetric-key encryption. In Proceedings of the 2018 ACM SIGSAC conference on computer and communications security (pp. 1993-2010)</br>
[2] Libert, B., Stehlé, D., & Titiu, R. (2021). Adaptively secure distributed PRFs from LWE. Journal of Cryptology, 34(3), 29.</br>
[3] Mukherjee, P. (2020, December). Adaptively secure threshold symmetric-key encryption. In International Conference on Cryptology in India (pp. 465-487). Cham: Springer International Publishing.</br>
[4] Chillotti, I., Gama, N., Georgieva, M., & Izabachène, M. (2020). TFHE: fast fully homomorphic encryption over the torus. Journal of Cryptology, 33(1), 34-91.</br>
