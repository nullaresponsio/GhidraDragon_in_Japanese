// tool.cpp  (unchanged except include Windows support)
#include "softtpm.hpp"
#include <iostream>
#include <nlohmann/json.hpp>
#include <vector>
using json = nlohmann::json;

int main(int argc, char** argv) {
    SoftTPM tpm;
    tpm.openTbsContext();
    if (argc<2) return std::cerr<<"cmd extend|quote|getrand|nvread|nvwrite|cnt\n",1;
    std::string c=argv[1];
    if(c=="extend"){
        std::string d=argv[2];
        tpm.extendPCR(0,std::vector<uint8_t>(d.begin(),d.end()));
    } else if(c=="quote"){
        auto nonce = tpm.getRandom(16);
        auto q=tpm.quote(nonce,{0});
        // emulate real TPM command round-trip
        json j; j["nonce"]=q.nonce; j["pcrs"]=q.pcrs; j["sig"]=q.sig;
        std::cout<<j.dump(2)<<"\n";
    } else if(c=="getrand"){
        auto r=tpm.getRandom(16);
        for(auto b:r)printf("%02x",b);printf("\n");
    } else if(c=="nvwrite"){
        std::string d=argv[2];
        tpm.nvWrite(1,std::vector<uint8_t>(d.begin(),d.end()));
    } else if(c=="nvread"){
        auto d=tpm.nvRead(1);
        std::cout<<std::string(d.begin(),d.end())<<"\n";
    } else if(c=="cnt"){
        std::cout<<tpm.incCounter()<<"\n";
    }
    return 0;
}
