#include "AsymAdapDprf.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Log.h"
#include <cryptoTools/Common/Timer.h>

namespace dEnc
{
    // std::map<std::pair<u64, u64>, u64> part_eval_time;
    AsymAdapDprf::~AsymAdapDprf()
    {
        close();

        if (mServerListenCallbacks.size())
            mServerDone.get();
    }


    std::function<AsymAdapDprf::Num(u64 i)> AsymAdapDprf::interpolate(span<Num> fx, span<Num> xi)
    {
        std::vector<Num> fxx(fx.begin(), fx.end());
        std::vector<Num> xxi(xi.begin(), xi.end());


        auto L = [fxx, xxi](u64 xx)
        {
            auto m = fxx.size();
            Num ret(0);
            Num x(xx);

            // Now compute the degree m-1 lagrange polynomial L(x) such that
            //       L(i) = fx[i]   for i \in {0,...,m}

            // The formula is
            //    L(x) = \sum_{i=0,...,m}   fx[i] * l_i(x)
            // where
            //    l_i(x) = \prod_{m=0,...,m;  m!=i}   (x - x_i) / (x_i - x_j)
            //           = \prod_{m=0,...,m;  m!=i}   (x - i) / (i - j)     since x_i = i
            std::vector<std::function<Num(const Num&)>> l(m);

            Num one(1);
            for (u64 i = 0; i < m; ++i)
            {
                //l[i] = [&,i](const Num& x)
                //{
                Num l_i(1);

                for (u64 j = 0; j < m; ++j)
                    if (j != i)
                        l_i *= (x - xxi[j]) / (xxi[i] - xxi[j]);

                //return l_i;
                //};

                ret += fxx[i] * l_i;// l[i](x);
            }
            return ret;
        };

        return L;
    }

    std::function<AsymAdapDprf::Num(u64 i)> AsymAdapDprf::interpolate(span<Num> fx)
    {
        std::vector<Num> xi; xi.reserve(fx.size());
        for (u64 i = 0; i < fx.size(); ++i)
            xi.emplace_back(i32(i));

        return interpolate(fx, xi);
    }



    void AsymAdapDprf::MasterKey::KeyGen(u64 n, u64 m, PRNG & prng, Type type)
    {
        oc::REllipticCurve curve;

        // gnerate m random points wich will define our m-1 degree polynomial
        std::vector<Num> fx_left(m);
        std::vector<Num> fx_right(m);
        for (u64 i = 0; i < m; ++i){
            fx_left[i].randomize(prng);
            fx_right[i].randomize(prng);
        }


        // interpolate these points. The 
        mKeyPoly_left = interpolate(fx_left);
        mKeyPoly_right = interpolate(fx_right);

        // The master key is the polynomial at zero.
        mMasterKey_left = fx_left[0]; /* == mKeyPoly(0) */;
        mMasterKey_right = fx_right[0];

        // The key shars are the polynomial at 1, 2, ..., n
        mKeyShares_left.resize(n);
        mKeyShares_right.resize(n);
        for (u64 i = 0; i < n; ++i)
        {
            mKeyShares_left[i] = mKeyPoly_left(i + 1);
            mKeyShares_right[i] = mKeyPoly_right(i + 1);
            // std::cout << "sk[" << i << "] " << mKeyShares[i] << std::endl;
        }
    }

    void AsymAdapDprf::init(
        u64 partyIdx,
        u64 m,
        span<Channel> requestChls,
        span<Channel> listChls,
        block seed,
        Type  type,
        Num sk_left,
        Num sk_right)
    {
        mPartyIdx = partyIdx;
        mM = m;
        mN = requestChls.size() + 1;
        mType = type;
        mPrng.SetSeed(seed);
        mIsClosed = false;

        mRequestChls = { requestChls.begin(), requestChls.end() };
        mListenChls = { listChls.begin(), listChls.end() };

        // Copy this parties secret key
        mSk_left = sk_left;
        mSk_right = sk_right;

        // Take a copy of the generator
        oc::REllipticCurve curve;
        mGen = curve.getGenerator();

        // Precompute the lagrange interpolation coefficients
        mDefaultLag.resize(mM);

        // pre compute a vector containing { mPartyIdx + 1, mPartyIdx + 2, ..., mPartyIdx + m}
        std::vector<Num> xi(mM);
        for (u64 i = 0, j = mPartyIdx; i < mM; ++i, ++j)
            xi[i] = j % mN + 1;


        // mDefaultLag[i] will hold the lagrange coefficient to use
        // with party i.
        for (i64 i = 0; i < mM; ++i)
        {
            auto& l_i = mDefaultLag[i];

            l_i = 1;
            for (u64 j = 0; j < m; ++j)
                if (j != i) l_i *= xi[j] / (xi[j] - xi[i]);
        }

        // cache some values that will be used as temporary storage
        mTempPoints.resize(6);
        mTempNums.resize(6);

        // Start the service that listens to OPRF evaluations requests 
        // from the other parties.
        startListening();
    }

    void AsymAdapDprf::serveOne(span<u8> request, u64 outputPartyIdx)
    {
        oc::REllipticCurve curve;
        int pointSize = mGen.sizeBytes();

        // Make sure that the requests are a 
        if (request.size() % sizeof(block))
            throw std::runtime_error(LOCATION);

        auto numRequests = request.size() / sizeof(block);

        auto sizePer = pointSize;
        std::vector<u8> response(numRequests * sizePer);

        auto sIter = (block*)request.data();
        auto dIter = response.data();

        for (u64 i = 0; i < numRequests; ++i)
        {
            serveOne(sIter[i], span<u8>(dIter, sizePer), outputPartyIdx);

            dIter += sizePer;
        }

        mListenChls[outputPartyIdx].asyncSend(std::move(response));
    }

    void AsymAdapDprf::serveOne(block in, span<u8> dest, u64 outputPartyIdx)
    {
        oc::REllipticCurve curve;

        // hash the input to two random points
        std::vector<block> in_;
        in_.resize(2);

        RandomOracle Hash1(16);
        Hash1.Update(in);
        Hash1.Update(1);
        Hash1.Final(in_[0]);

        RandomOracle Hash2(16);
        Hash2.Update(in);
        Hash2.Update(2);
        Hash2.Final(in_[1]);

        oc::REccPoint v_left, v_right, v;
        v_left.randomize(in_[0]);
        v_right.randomize(in_[1]);

        // std::cout << in << " " << v_left << " " << v_right << "\n";
        
        // Compute and serialize the output share
        v_left *= mSk_left;
        v_right *= mSk_right;
        v = v_left + v_right;
        v.toBytes(dest.data());
    }

    block AsymAdapDprf::eval(block input)
    {
        return asyncEval(input).get()[0];
    }

    AsyncEval AsymAdapDprf::asyncEval(block input)
    {
        return asyncEval({ &input, 1 });
    }

    // A struct that holds some intermidiate values using the async operation
    struct Workspace_
    {
        // An instance of a single evaluation
        struct W_ {
            // The input point  (w1, w2) = H(x)
            oc::REccPoint v_left, v_right;

            // The output share
            oc::REccPoint y;
        };

        // a vector to hold the temps for many (concurrent) evluations
        std::vector<W_> w;

        /**
         * Initialize another set of temporaries for a set of
         * n parallel evaluations of the DPRF
         * @param[in] n  - The number of parallel evluations to allocate
         */
        Workspace_(u64 n)
        {
            w.resize(n);
        }

        // a buffer to receive the DPRF output shares into.
        oc::Matrix<u8> buff2_;

        // a set of futures that will be fulfilled when the 
        // DPRF output shares have arrived.
        std::vector<std::future<void>> asyncs_;
    };

    AsyncEval AsymAdapDprf::asyncEval(span<block> in)
    {
        // create a shared copy of the input and send it to the other
        // parties as the OPRF input.
        auto sendBuff = std::make_shared<std::vector<block>>(in.begin(), in.end());
        for (u64 i = 1, j = mPartyIdx; i < mM; ++i, ++j)
        {
            mRequestChls[j % mRequestChls.size()].asyncSend(sendBuff);
        }

        oc::REllipticCurve curve;

        // This "Workspace" will hold all of the temporaries
        // until the operation has completed


        // oc::Timer ti;
        // auto begin = ti.setTimePoint("start");
        // std::cout << in.size() << "\n";
        auto w = std::make_shared<Workspace_>(in.size());

        auto pointSize = w->w[0].v_left.sizeBytes();

        for (u64 i = 0; i < in.size(); ++i)
        {
            auto& v_left = w->w[i].v_left;
            auto& v_right = w->w[i].v_right;
            auto& y = w->w[i].y;

            // Hash each of the inputs to two random points on the ceruve
            std::vector<block> in_;
            in_.resize(2);

            RandomOracle Hash1(16);
            Hash1.Update(in[i]);
            Hash1.Update(1);
            Hash1.Final(in_[0]);

            RandomOracle Hash2(16);
            Hash2.Update(in[i]);
            Hash2.Update(2);
            Hash2.Final(in_[1]);

            w->w[i].v_left.randomize(in_[0]);
            w->w[i].v_right.randomize(in_[1]);

            // Perform the interpolcation in the exponent y = w1^u_i * w2^v_i, where (u_i,v_i) is the key share of i^th party 
            y = v_left * (mDefaultLag[0] * mSk_left);
            y += v_right * (mDefaultLag[0] * mSk_right);
        }
        // auto finish = ti.setTimePoint("end");
        // u64 reqd_time = std::chrono::duration_cast<std::chrono::microseconds>(finish - begin).count();
        // // std::cout << "Time for partial evaluation by single party: " << reqd_time << "\n";
        // if(part_eval_time.find({mN,mM}) != part_eval_time.end()){
        //     part_eval_time[{mN,mM}] += reqd_time;
        // }
        // else{
        //     part_eval_time.insert({{mN, mM}, reqd_time});
        // }

        // The size in bytes that we expect to be returned
        auto size = pointSize;

        // allocate enough space to receive the OPRF output and proofs
        w->buff2_.resize((mM - 1), size * in.size());
        w->asyncs_.resize(mM - 1);
        for (u64 i = 1, j = mPartyIdx; i < mM; ++i, ++j)
        {
            auto& chl = mRequestChls[j % mRequestChls.size()];


            using myContainer = decltype(w->buff2_[i - 1]);

            static_assert(oc::is_container<myContainer>::value &&
                !oc::has_resize<myContainer, void(typename myContainer::size_type)>::value, "");

            // Schedule the OPRF output to be recieved and store it
            // in row i-1 of w->buff2_
            w->asyncs_[i - 1] = chl.asyncRecv(w->buff2_[i - 1]);
        }

        // Construct the completion event that is executed when the
        // user wants to complete the async eval.
        AsyncEval ae;
        ae.get = [this, w, pointSize]()->std::vector<block>
        {
            auto inSize = w->w.size();
            oc::REllipticCurve curve;

            Point vk, vz, gz, a1, a2;
            Num s;
            std::vector<block> ret(inSize);

            // Process the OPRF output shares one at a time
            for (u64 i = 1, j = mPartyIdx; i < mM; ++i, ++j)
            {
                // block for the data to arrive.
                w->asyncs_[i - 1].get();

                // pointer into the output share
                auto iter = w->buff2_[i - 1].data();

                for (u64 inIdx = 0; inIdx < inSize; ++inIdx)
                {
                    Point& y = w->w[inIdx].y;

                    // read in the output share = H(x)^k_i
                    vk.fromBytes(iter);
                    iter += vk.sizeBytes();

                    // y = SUM_i  H(x)^{\lambda_i * k_i}
                    y += vk * mDefaultLag[i];                   
                }
            }

            // Hash the output value to get a random string
            std::vector<u8> buff_(pointSize);
            for (u64 inIdx = 0; inIdx < inSize; ++inIdx)
            {
                oc::REccPoint& y = w->w[inIdx].y;
                y.toBytes(buff_.data());

                oc::RandomOracle H(sizeof(block));

                H.Update(buff_.data(), buff_.size());
                H.Final(ret[inIdx]);
            }

            return ret;
        };

        return ae;
    }


    void AsymAdapDprf::startListening()
    {
        mServerDone = (mServerDoneProm.get_future());
        mRecvBuff.resize(mRequestChls.size());
        mListens = mListenChls.size();
        mServerListenCallbacks.resize(mListenChls.size());

        for (u64 i = 0; i < mListenChls.size(); ++i)
        {
            // If the client sends more than one byte, interpret this
            // as a request to evaluate the DPRF.
            mServerListenCallbacks[i] = [&, i]()
            {
                if (mRecvBuff[i].size() > 1)
                {
                    // Evaluate the DPRF and send the result back.
                    serveOne(mRecvBuff[i], i);

                    // Eueue up another receive operation which will call 
                    // this callback when the request arrives.
                    mListenChls[i].asyncRecv(mRecvBuff[i], mServerListenCallbacks[i]);
                }
                else
                {
                    // One byte means that the cleint is done requiresting 
                    // DPRf evaluations. We can close down.
                    if (--mListens == 0)
                    {
                        // If this is the last callback to close, set
                        // the promise that denotes that the server
                        // callback loops have all completed.
                        mServerDoneProm.set_value();
                    }
                }
            };

            mListenChls[i].asyncRecv(mRecvBuff[i], mServerListenCallbacks[i]);
        }
    }

    void AsymAdapDprf::close()
    {
        if (mIsClosed == false)
        {
            mIsClosed = true;

            u8 close[1];
            close[0] = 0;

            // closing the channel is done by sending a single byte.
            for (auto& c : mRequestChls)
                c.asyncSendCopy(close, 1);
        }
    }
}
