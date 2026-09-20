// FuzzyDedup experimental implementation.
// Implements FuzzyMLE key reproduction, tag cutting/Hamming reduction and
// sampled 1-out-of-2 OT FuzzyPoW (the paper's P-FuzzyPoW optimization).
#include <pbc/pbc.h>
#include <chrono>
#include <iostream>
#include <memory>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#define main prefuzzdup_embedded_main
#include "prefuzzdup_core.cpp"
#undef main

namespace fuzzydedup_impl {
using Clock=std::chrono::steady_clock;
[[noreturn]] void fail_fd(const std::string&s){throw std::runtime_error(s);}
enum class Field{G1,ZR};
struct E{element_t v;E(pairing_t&p,Field f){if(f==Field::G1)element_init_G1(v,p);else element_init_Zr(v,p);}~E(){element_clear(v);}E(const E&)=delete;};using EP=std::unique_ptr<E>;EP mk(pairing_t&p,Field f){return std::make_unique<E>(p,f);}
struct Group{pbc_param_t par;pairing_t p;EP g;Group():g(nullptr){pbc_param_init_a_gen(par,160,512);pairing_init_pbc_param(p,par);g=mk(p,Field::G1);element_random(g->v);}~Group(){g.reset();pairing_clear(p);pbc_param_clear(par);}};

Bytes elem(element_t x){Bytes b(element_length_in_bytes(x));element_to_bytes(b.data(),x);return b;}
std::uint32_t word(std::span<const std::uint8_t>x){auto h=sha256(x);return(static_cast<std::uint32_t>(h[0])<<24)|(static_cast<std::uint32_t>(h[1])<<16)|(static_cast<std::uint32_t>(h[2])<<8)|h[3];}

struct OtStats{std::size_t transfers{};std::size_t bytes{};double micros{};};
// Naor-Pinkas/Simplest-OT style DH 1-out-of-2 transfer in G1.
std::uint32_t ot12(Group&gr,std::uint32_t m0,std::uint32_t m1,bool choice,OtStats&st){auto&p=gr.p;auto c=mk(p,Field::ZR),k=mk(p,Field::ZR),r0=mk(p,Field::ZR),r1=mk(p,Field::ZR);auto C=mk(p,Field::G1),pk0=mk(p,Field::G1),pk1=mk(p,Field::G1),u0=mk(p,Field::G1),u1=mk(p,Field::G1),shared0=mk(p,Field::G1),shared1=mk(p,Field::G1),chosen=mk(p,Field::G1),inv=mk(p,Field::G1);element_random(c->v);element_pow_zn(C->v,gr.g->v,c->v);element_random(k->v);if(!choice){element_pow_zn(pk0->v,gr.g->v,k->v);element_invert(inv->v,pk0->v);element_mul(pk1->v,C->v,inv->v);}else{element_pow_zn(pk1->v,gr.g->v,k->v);element_invert(inv->v,pk1->v);element_mul(pk0->v,C->v,inv->v);}element_random(r0->v);element_random(r1->v);element_pow_zn(u0->v,gr.g->v,r0->v);element_pow_zn(u1->v,gr.g->v,r1->v);element_pow_zn(shared0->v,pk0->v,r0->v);element_pow_zn(shared1->v,pk1->v,r1->v);const std::uint32_t e0=m0^word(elem(shared0->v)),e1=m1^word(elem(shared1->v));element_pow_zn(chosen->v,choice?u1->v:u0->v,k->v);const std::uint32_t out=(choice?e1:e0)^word(elem(chosen->v));st.transfers++;st.bytes+=elem(C->v).size()+elem(pk0->v).size()+elem(u0->v).size()+elem(u1->v).size()+8;return out;}

Bytes prg(std::span<const std::uint8_t>key,std::size_t n){Bytes out;out.reserve(n);for(std::uint32_t c=0;out.size()<n;++c){Bytes in(key.begin(),key.end());append_u32(in,c);auto block=sha256(in);append(out,block);}out.resize(n);return out;}
Bytes xor_encrypt(std::span<const std::uint8_t>key,std::span<const std::uint8_t>plain){auto pad=prg(key,plain.size());Bytes out(plain.size());for(std::size_t i=0;i<plain.size();++i)out[i]=plain[i]^pad[i];return out;}
int tag_distance_cut(std::span<const std::uint8_t>a,std::span<const std::uint8_t>b,int threshold){int d=0;for(std::size_t i=0;i<a.size();++i){d+=__builtin_popcount(static_cast<unsigned>(a[i]^b[i]));if(d>threshold)return d;}return d;}

struct PowResult{bool accepted{};double estimated_distance{};OtStats ot;};
PowResult sampled_fuzzy_pow(std::span<const std::uint8_t>stored,std::span<const std::uint8_t>claim,std::size_t samples,double max_distance){if(stored.size()!=claim.size()||stored.empty())return{};Group group;PowResult result;std::mt19937_64 rng(0x46555a5a59444544ULL);std::uniform_int_distribution<std::size_t>pos(0,stored.size()*8-1);std::uint64_t sr=0,st=0;const auto t0=Clock::now();for(std::size_t j=0;j<samples;++j){const auto bit=pos(rng);const bool qb=getbit(claim,bit),sb=getbit(stored,bit);const std::uint32_t r=static_cast<std::uint32_t>(rng()%1000000);const std::uint32_t m0=r+(qb?1:0),m1=r+(qb?0:1);const auto got=ot12(group,m0,m1,sb,result.ot);sr+=r;st+=got;}result.ot.micros=std::chrono::duration<double,std::micro>(Clock::now()-t0).count();const double mismatches=static_cast<double>(st-sr);result.estimated_distance=(stored.size()*8.0)*mismatches/static_cast<double>(samples);result.accepted=result.estimated_distance<=max_distance;return result;}

struct RunResult { std::size_t transfers{}, bytes{}; double ot_us{}; };

RunResult run_once(std::size_t samples) {
  const Bytes file=bytes("FuzzyDedup secure fuzzy message locked encryption and OT proof");
  const Bytes tag=simhash_text(file,"FuzzyDedup/tag/r1");
  if(tag_distance_cut(tag,tag,2)!=0)fail_fd("tag query failed");
  FuzzyExtractor fe;
  const Bytes fuzzy=simhash_text(file,"FuzzyDedup/key/r2");
  auto gen=fe.gen(fuzzy);
  auto rep=fe.rep(fuzzy,gen.P);
  if(!rep||!equal_ct(*rep,gen.R))fail_fd("fuzzy key reproduction failed");
  Bytes zero(32,0);
  const Bytes key=hkdf_extract(zero,*rep);
  const Bytes stored=xor_encrypt(key,file),claim=xor_encrypt(key,file);
  auto pow=sampled_fuzzy_pow(stored,claim,samples,0.0);
  if(!pow.accepted||pow.estimated_distance!=0)fail_fd("OT FuzzyPoW failed");
  const Bytes recovered=xor_encrypt(key,stored);
  if(!equal_ct(recovered,file))fail_fd("FuzzyMLE decryption failed");
  return {pow.ot.transfers,pow.ot.bytes,pow.ot.micros};
}

void self_test(){
  auto result=run_once(64);
  Bytes stored(64,0x00), false_claim(64,0xff);
  auto rejected=sampled_fuzzy_pow(stored,false_claim,32,0.0);
  if(rejected.accepted)fail_fd("false ownership claim was accepted");
  std::cout<<"FuzzyDedup self-test passed ot_transfers="<<result.transfers
           <<" ot_bytes="<<result.bytes<<" ot_us="<<result.ot_us
           <<" false_claim_rejection=passed\n";
}

void benchmark(int rounds,std::size_t samples){
  if(rounds<=0||samples==0)fail_fd("rounds and samples must be positive");
  RunResult total;
  for(int i=0;i<rounds;++i){
    auto r=run_once(samples);
    total.transfers+=r.transfers;
    total.bytes+=r.bytes;
    total.ot_us+=r.ot_us;
  }
  std::cout<<"scheme,rounds,samples,ot_transfers,ot_bytes,ot_us\n"
           <<"fuzzydedup,"<<rounds<<','<<samples<<','
           <<total.transfers/rounds<<','<<total.bytes/rounds<<','
           <<total.ot_us/rounds<<'\n';
}
}
int main(int argc,char**argv){
  try{
    if(argc==2&&std::string(argv[1])=="self-test"){
      fuzzydedup_impl::self_test();
      return 0;
    }
    if(argc>=2&&argc<=4&&std::string(argv[1])=="benchmark"){
      const int rounds=argc>=3?std::stoi(argv[2]):1;
      const auto samples=static_cast<std::size_t>(argc==4?std::stoul(argv[3]):64);
      fuzzydedup_impl::benchmark(rounds,samples);
      return 0;
    }
    std::cerr<<"usage: fuzzydedup self-test | fuzzydedup benchmark [rounds] [samples]\n";
    return 1;
  }catch(const std::exception&e){std::cerr<<"error: "<<e.what()<<'\n';return 2;}
}
