# EQuADiSE
EQuADiSE is the abbreviation for Efficient Quantum-safe Adaptive Distributed Symmetric-key Encryption. It improves upon the existing DiSE protocol introduced by Agrawal et al. in CCS 2018 [1]. Distributed PRF (DPRF) is an important building block of DiSE. We use adaptively secure quantum-safe DPRF in order to obtain EQuADiSE from DiSE. Our proposed DPRF is based on Module Learning with Rounding (MLWR) assumption.

In our implementation, we provide DPRF instantiated with (i) LWR-based DPRF (from [2]), (ii) adaptive LWE-based DPRF (from [3]), (iii) adaptive DDH-based DPRF (from [4]), (iv) our proposed adaptive LWR-based DPRF and, (v) our proposed adaptive MLWR-based DPRF. We also provide DPRF implementation of threshold FHE -based DPRF (from [5]).

# pqdise
This is built over the existing DiSE library and has a dependency on cryptoTools library as well. Run the following commands on a Linux system.
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
To see the encryption performance, run
```
./dEncFrontend -sl -nStart 4 -nEnd 16 -nStep 2 -mf 0.5
```
Use "-sl" option to get encryption performance using adaptive LWR-based DPRF. Replace it with "-sa", "-ad", "-ld", "-md", "-ed" to get encryption performance using "DDH-based DPRF", "adaptive DDH-based DPRF", "adaptive LWR-based DPRF", "adaptive MLWR-based DPRF", "LWE-based DPRF", respectively.<br/>
To see just the DPRF performances, run
```
./dEncFrontend -comp -sl -thr 5 -total 8
```
"-thr" option takes the value of threshold number of parties, "-total" takes the value of total number of parties. The option "-sl" can be replaced with other options to see the performance comparison of various DPRFs.

# TFHE_DPRF
This is built over TFHE library [5]. You can get the performance of TFHE-based DPRF for (t,T) = (3,5) by running the following command in this folder.
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
[2] Sinha, S., Patranabis, S., & Mukhopadhyay, D. (2024, February). Efficient Quantum-Safe Distributed PRF and Applications: Playing DiSE in a Quantum World. In International Conference on Applied Cryptography and Network Security (pp. 47-78). Cham: Springer Nature Switzerland.</br>
[3] Libert, B., Stehlé, D., & Titiu, R. (2021). Adaptively secure distributed PRFs from LWE. Journal of Cryptology, 34(3), 29.</br>
[4] Mukherjee, P. (2020, December). Adaptively secure threshold symmetric-key encryption. In International Conference on Cryptology in India (pp. 465-487). Cham: Springer International Publishing.</br>
[5] Chillotti, I., Gama, N., Georgieva, M., & Izabachène, M. (2020). TFHE: fast fully homomorphic encryption over the torus. Journal of Cryptology, 33(1), 34-91.</br>
