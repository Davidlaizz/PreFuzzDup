// SimLESS experimental implementation.
// Preserves the paper's CP-ABE-style key envelope and pairing FuzzyPoW.
#include <pbc/pbc.h>
#include <chrono>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#define main prefuzzdup_embedded_main
#include "prefuzzdup_core.cpp"
#undef main

namespace simless_impl {
using Clock = std::chrono::steady_clock;
[[noreturn]] void fail_sim(const std::string& s) { throw std::runtime_error(s); }

enum class Field { G1, GT, ZR };
struct E {
  element_t v;
  E(pairing_t& p, Field f) { if(f==Field::G1) element_init_G1(v,p); else if(f==Field::GT) element_init_GT(v,p); else element_init_Zr(v,p); }
  ~E(){ element_clear(v); }
  E(const E&)=delete; E& operator=(const E&)=delete;
};
using EP=std::unique_ptr<E>;
EP make_e(pairing_t& p,Field f){return std::make_unique<E>(p,f);}

class Pairing {
 public:
  Pairing(){pbc_param_init_a_gen(param_,160,512);pairing_init_pbc_param(p_,param_);}
  ~Pairing(){pairing_clear(p_);pbc_param_clear(param_);}
  pairing_t& get(){return p_;}
 private:pbc_param_t param_;pairing_t p_;
};

Bytes serialize(element_t e){Bytes b(element_length_in_bytes(e));element_to_bytes(b.data(),e);return b;}
void hash_zr(element_t out,std::span<const std::uint8_t> seed,int index){Bytes x(seed.begin(),seed.end());append_u32(x,index);auto h=sha256(x);element_from_hash(out,h.data(),h.size());}

struct Authority {
  Pairing ctx;
  EP g,alpha,beta,tau,egg,sk1,sk2;
  std::vector<std::string> attrs;
  std::vector<EP> ga,skat;
  explicit Authority(std::vector<std::string> a):g(make_e(ctx.get(),Field::G1)),alpha(make_e(ctx.get(),Field::ZR)),beta(make_e(ctx.get(),Field::ZR)),tau(make_e(ctx.get(),Field::ZR)),egg(make_e(ctx.get(),Field::GT)),sk1(make_e(ctx.get(),Field::G1)),sk2(make_e(ctx.get(),Field::G1)),attrs(std::move(a)){
    element_random(g->v);element_random(alpha->v);element_random(beta->v);element_random(tau->v);pairing_apply(egg->v,g->v,g->v,ctx.get());
    auto t1=make_e(ctx.get(),Field::G1),t2=make_e(ctx.get(),Field::G1),ab=make_e(ctx.get(),Field::ZR);
    element_pow_zn(t1->v,g->v,alpha->v);element_mul(ab->v,tau->v,beta->v);element_pow_zn(t2->v,g->v,ab->v);element_mul(sk1->v,t1->v,t2->v);element_pow_zn(sk2->v,g->v,tau->v);
    for(const auto&s:attrs){auto ag=make_e(ctx.get(),Field::G1),ak=make_e(ctx.get(),Field::G1);auto h=sha256(bytes(s));element_from_hash(ag->v,h.data(),h.size());element_pow_zn(ak->v,ag->v,tau->v);ga.push_back(std::move(ag));skat.push_back(std::move(ak));}
  }
};

struct AbeCipher { EP cm1,cm2;std::vector<EP> ca,cb; explicit AbeCipher(pairing_t&p):cm1(make_e(p,Field::GT)),cm2(make_e(p,Field::G1)){} };
struct AbeResult { Bytes key; double enc_us{},dec_us{}; };

bool contains_all(const std::vector<std::string>& owned,
                  const std::vector<std::string>& required) {
  return std::all_of(required.begin(), required.end(), [&](const auto& attr) {
    return std::find(owned.begin(), owned.end(), attr) != owned.end();
  });
}

AbeResult cpabe_roundtrip(Authority& a,const std::vector<std::string>& policy,
                         const std::vector<std::string>& user_attrs){
  if(policy.empty())fail_sim("empty policy");for(const auto&p:policy)if(std::find(a.attrs.begin(),a.attrs.end(),p)==a.attrs.end())fail_sim("unknown policy attribute");
  auto&p=a.ctx.get();AbeCipher c(p);auto ek=make_e(p,Field::GT),tk=make_e(p,Field::ZR),mask=make_e(p,Field::GT),exp=make_e(p,Field::ZR),share=make_e(p,Field::ZR),z=make_e(p,Field::ZR),g1tmp=make_e(p,Field::G1),g1tmp2=make_e(p,Field::G1);element_random(ek->v);element_random(tk->v);
  const auto t0=Clock::now();element_mul(exp->v,a.alpha->v,tk->v);element_pow_zn(mask->v,a.egg->v,exp->v);element_mul(c.cm1->v,ek->v,mask->v);element_pow_zn(c.cm2->v,a.g->v,tk->v);
  element_set0(share->v);std::vector<EP> shares;for(std::size_t i=0;i<policy.size();++i){auto s=make_e(p,Field::ZR);if(i+1==policy.size()){element_sub(s->v,tk->v,share->v);}else{element_random(s->v);element_add(share->v,share->v,s->v);}shares.push_back(std::move(s));}
  for(std::size_t i=0;i<policy.size();++i){auto ai=std::find(a.attrs.begin(),a.attrs.end(),policy[i])-a.attrs.begin();auto ca=make_e(p,Field::G1),cb=make_e(p,Field::G1);element_random(z->v);element_mul(exp->v,a.beta->v,shares[i]->v);element_pow_zn(ca->v,a.g->v,exp->v);element_pow_zn(g1tmp->v,a.ga[ai]->v,z->v);element_invert(g1tmp->v,g1tmp->v);element_mul(ca->v,ca->v,g1tmp->v);element_pow_zn(cb->v,a.g->v,z->v);c.ca.push_back(std::move(ca));c.cb.push_back(std::move(cb));}
  const auto t1=Clock::now();
  if (!contains_all(user_attrs, policy)) fail_sim("access policy not satisfied");
  auto numerator=make_e(p,Field::GT),den=make_e(p,Field::GT),pair1=make_e(p,Field::GT),pair2=make_e(p,Field::GT),pairprod=make_e(p,Field::GT),recovered=make_e(p,Field::GT);pairing_apply(numerator->v,c.cm2->v,a.sk1->v,p);element_set1(den->v);
  for(std::size_t i=0;i<policy.size();++i){auto ai=std::find(a.attrs.begin(),a.attrs.end(),policy[i])-a.attrs.begin();pairing_apply(pair1->v,c.ca[i]->v,a.sk2->v,p);pairing_apply(pair2->v,c.cb[i]->v,a.skat[ai]->v,p);element_mul(pairprod->v,pair1->v,pair2->v);element_mul(den->v,den->v,pairprod->v);}element_div(mask->v,numerator->v,den->v);element_div(recovered->v,c.cm1->v,mask->v);const auto t2=Clock::now();if(element_cmp(recovered->v,ek->v))fail_sim("CP-ABE recovery failed");
  return{sha256(serialize(ek->v)),std::chrono::duration<double,std::micro>(t1-t0).count(),std::chrono::duration<double,std::micro>(t2-t1).count()};
}

double fuzzy_pow(Authority&a,std::span<const std::uint8_t> seed,int degree){auto&p=a.ctx.get();std::vector<EP> coeff,commit;for(int i=0;i<=degree;++i){auto z=make_e(p,Field::ZR),c=make_e(p,Field::G1);hash_zr(z->v,seed,i);element_pow_zn(c->v,a.g->v,z->v);coeff.push_back(std::move(z));commit.push_back(std::move(c));}
  auto x1=make_e(p,Field::ZR),x2=make_e(p,Field::ZR),pow=make_e(p,Field::ZR),phi1=make_e(p,Field::ZR),phi2=make_e(p,Field::ZR),ztmp=make_e(p,Field::ZR);auto y1=make_e(p,Field::G1),y2=make_e(p,Field::G1),gtmp=make_e(p,Field::G1),proof=make_e(p,Field::G1);auto lhs=make_e(p,Field::GT),rhs=make_e(p,Field::GT);element_random(x1->v);element_random(x2->v);const auto t0=Clock::now();
  auto eval=[&](element_t x,element_t phi,element_t y){element_set0(phi);element_set1(y);element_set1(pow->v);for(int i=0;i<=degree;++i){element_mul(ztmp->v,coeff[i]->v,pow->v);element_add(phi,phi,ztmp->v);element_pow_zn(gtmp->v,commit[i]->v,pow->v);element_mul(y,y,gtmp->v);element_mul(pow->v,pow->v,x);}};eval(x1->v,phi1->v,y1->v);eval(x2->v,phi2->v,y2->v);element_mul(ztmp->v,phi1->v,phi2->v);element_pow_zn(proof->v,a.g->v,ztmp->v);pairing_apply(lhs->v,proof->v,a.g->v,p);pairing_apply(rhs->v,y1->v,y2->v,p);if(element_cmp(lhs->v,rhs->v))fail_sim("pairing FuzzyPoW failed");return std::chrono::duration<double,std::micro>(Clock::now()-t0).count();}

struct RunResult { double cpabe_enc_us{}, cpabe_dec_us{}, fpow_us{}; };

RunResult run_once(Authority& auth) {
  const std::vector<std::string> policy{"researcher", "project-x"};
  auto abe=cpabe_roundtrip(auth,policy,{"researcher", "project-x", "member"});
  const Bytes f=bytes("SimLESS similar media ownership self test");
  FuzzyExtractor fe;
  auto x=recovery_representation(f,"text");
  auto gen=fe.gen(x);
  auto rep=fe.rep(x,gen.P);
  if(!rep||!equal_ct(*rep,gen.R))fail_sim("fuzzy extractor failed");
  double pow=fuzzy_pow(auth,*rep,8);
  auto nonce=random_bytes(12);
  auto enc=aead_encrypt(abe.key,nonce,f,bytes("SimLESS"));
  auto dec=aead_decrypt(abe.key,nonce,enc.ciphertext,enc.tag,bytes("SimLESS"));
  if(!dec||!equal_ct(*dec,f))fail_sim("media encryption failed");
  return {abe.enc_us, abe.dec_us, pow};
}

void self_test(){
  Authority auth({"researcher","project-x","member"});
  auto result=run_once(auth);
  bool rejected=false;
  try {
    (void)cpabe_roundtrip(auth,{"researcher","project-x"},{"researcher"});
  } catch (const std::runtime_error&) {
    rejected=true;
  }
  if(!rejected) fail_sim("unsatisfied access policy was accepted");
  std::cout<<"SimLESS self-test passed cpabe_enc_us="<<result.cpabe_enc_us
           <<" cpabe_dec_us="<<result.cpabe_dec_us
           <<" fpow_us="<<result.fpow_us<<" access_denial=passed\n";
}

void benchmark(int rounds) {
  if (rounds <= 0) fail_sim("rounds must be positive");
  Authority auth({"researcher","project-x","member"});
  RunResult total;
  for (int i=0;i<rounds;++i) {
    auto r=run_once(auth);
    total.cpabe_enc_us+=r.cpabe_enc_us;
    total.cpabe_dec_us+=r.cpabe_dec_us;
    total.fpow_us+=r.fpow_us;
  }
  std::cout<<"scheme,rounds,cpabe_encrypt_us,cpabe_decrypt_us,fpow_us\n"
           <<"simless,"<<rounds<<','<<total.cpabe_enc_us/rounds<<','
           <<total.cpabe_dec_us/rounds<<','<<total.fpow_us/rounds<<'\n';
}
}
int main(int argc,char**argv){
  try{
    if(argc==2&&std::string(argv[1])=="self-test"){
      simless_impl::self_test();
      return 0;
    }
    if((argc==2||argc==3)&&std::string(argv[1])=="benchmark"){
      simless_impl::benchmark(argc==3?std::stoi(argv[2]):3);
      return 0;
    }
    std::cerr<<"usage: simless self-test | simless benchmark [rounds]\n";
    return 1;
  }catch(const std::exception&e){std::cerr<<"error: "<<e.what()<<'\n';return 2;}
}
