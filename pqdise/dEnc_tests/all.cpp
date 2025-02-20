#include "all.h"
#include <iostream>
#include <string>
#include <functional>
#include <cryptoTools/Common/Log.h>
namespace dEnc_tests
{

    oc::TestCollection tests([](oc::TestCollection& tests)
	{
        tests.add("Npr03SymShDPRF_eval_test           ", Npr03SymShDPRF_eval_test);
		tests.add("Npr03AsymShDPRF_eval_test          ", Npr03AsymShDPRF_eval_test);
		tests.add("AsymShAdapDPRF_eval_test          ", AsymShAdapDPRF_eval_test);
		tests.add("Npr03AsymMalDPRF_eval_test         ", Npr03AsymMalDPRF_eval_test);
		tests.add("LWRSymDPRF_eval_test	    ", LWRSymDPRF_eval_test);
		tests.add("LWRSymAdapDPRF_eval_test	    ", LWRSymAdapDPRF_eval_test);
		tests.add("MLWRSymAdapDPRF_eval_test	    ", MLWRSymAdapDPRF_eval_test);
		tests.add("AmmrSymClient_encDec_test          ", AmmrSymClient_encDec_test);
		tests.add("AmmrAsymShClient_encDec_test       ", AmmrAsymShClient_encDec_test);
		tests.add("AsymShAdapClient_encDec_test       ", AsymShAdapClient_encDec_test);
		tests.add("AmmrAsymMalClient_encDec_test      ", AmmrAsymMalClient_encDec_test);
		tests.add("MyLWRSymClient_encDec_test		 ", MyLWRSymClient_encDec_test);
		tests.add("MyLWRSymAdapClient_encDec_test		 ", MyLWRSymAdapClient_encDec_test);
		tests.add("MyMLWRSymAdapClient_encDec_test		 ", MyMLWRSymAdapClient_encDec_test);
    });
}
