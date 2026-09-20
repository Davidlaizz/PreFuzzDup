// PreFuzzDup reference prototype.  It follows the Chapter 4 protocol flow,
// while deliberately keeping transport and identity-provider integration out
// of scope.  See README.md for its security and deployment boundaries.

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iterator>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#ifdef PREFUZZDUP_ENABLE_MEDIA
#include <opencv2/core.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/imgproc.hpp>
#ifdef PREFUZZDUP_ENABLE_VIDEO
#include <opencv2/videoio.hpp>
#endif
#endif

using Bytes = std::vector<std::uint8_t>;
namespace fs = std::filesystem;

namespace {
constexpr std::size_t kAeadTagBytes = 16;
constexpr std::size_t kBchN = 255, kBchK = 207, kBchT = 6;
constexpr std::size_t kHelperBytes = 32 + 64; // BCH sketch + Toeplitz seed

[[noreturn]] void fail(const std::string& msg) { throw std::runtime_error(msg); }

Bytes bytes(std::string_view s) { return Bytes(s.begin(), s.end()); }
void append(Bytes& out, std::span<const std::uint8_t> in) { out.insert(out.end(), in.begin(), in.end()); }
void append_u32(Bytes& out, std::uint32_t x) {
  for (int i = 3; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(x >> (8 * i)));
}
void append_field(Bytes& out, std::span<const std::uint8_t> in) {
  append_u32(out, static_cast<std::uint32_t>(in.size())); append(out, in);
}
void append_field(Bytes& out, std::string_view s) { append_field(out, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s.data()), s.size())); }

Bytes sha256(std::span<const std::uint8_t> in) {
  Bytes out(EVP_MAX_MD_SIZE); unsigned int n = 0;
  if (EVP_Digest(in.data(), in.size(), out.data(), &n, EVP_sha256(), nullptr) != 1) fail("SHA-256 failed");
  out.resize(n); return out;
}
Bytes hash_fields(std::string_view domain, const std::vector<Bytes>& fields) {
  Bytes buf; append_field(buf, domain); for (const auto& f : fields) append_field(buf, f); return sha256(buf);
}
Bytes random_bytes(std::size_t n) {
  Bytes r(n); if (RAND_bytes(r.data(), static_cast<int>(r.size())) != 1) fail("secure random generation failed"); return r;
}
std::string hex(std::span<const std::uint8_t> x) {
  std::ostringstream os; for (auto b : x) os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b); return os.str();
}
bool equal_ct(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
  return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
Bytes read_file(const fs::path& p) {
  std::ifstream f(p, std::ios::binary); if (!f) fail("cannot open input file: " + p.string());
  return Bytes(std::istreambuf_iterator<char>(f), {});
}
void write_file(const fs::path& p, std::span<const std::uint8_t> data) {
  std::ofstream f(p, std::ios::binary | std::ios::trunc); if (!f) fail("cannot write file: " + p.string());
  f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size())); if (!f) fail("write failed: " + p.string());
}

// RFC 5869 HKDF with SHA-256.  The salt is explicit in all protocol calls.
Bytes hmac256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
  Bytes out(EVP_MAX_MD_SIZE); unsigned int n = 0;
  if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(), &n)) fail("HMAC failed");
  out.resize(n); return out;
}
Bytes hkdf_extract(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm) { return hmac256(salt, ikm); }
Bytes hkdf_expand(std::span<const std::uint8_t> prk, std::string_view info, std::size_t length) {
  if (length > 255 * 32) fail("HKDF output too long");
  Bytes out, previous; out.reserve(length);
  for (std::uint8_t c = 1; out.size() < length; ++c) {
    Bytes b = previous; append(b, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(info.data()), info.size())); b.push_back(c);
    previous = hmac256(prk, b); append(out, previous);
  }
  out.resize(length); return out;
}

struct AeadCiphertext { Bytes ciphertext, tag; };
AeadCiphertext aead_encrypt(std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
                            std::span<const std::uint8_t> plain, std::span<const std::uint8_t> aad) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); if (!ctx) fail("AES context allocation failed");
  AeadCiphertext out; out.ciphertext.resize(plain.size()); out.tag.resize(kAeadTagBytes); int n = 0, total = 0;
  const bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1 &&
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
    (aad.empty() || EVP_EncryptUpdate(ctx, nullptr, &n, aad.data(), aad.size()) == 1) &&
    (plain.empty() || EVP_EncryptUpdate(ctx, out.ciphertext.data(), &n, plain.data(), plain.size()) == 1) &&
    ((total = n), EVP_EncryptFinal_ex(ctx, out.ciphertext.data() + total, &n) == 1) &&
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kAeadTagBytes, out.tag.data()) == 1;
  total += n; EVP_CIPHER_CTX_free(ctx); if (!ok) fail("AES-GCM encryption failed"); out.ciphertext.resize(total); return out;
}
std::optional<Bytes> aead_decrypt(std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
                                  std::span<const std::uint8_t> cipher, std::span<const std::uint8_t> tag,
                                  std::span<const std::uint8_t> aad) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); if (!ctx) fail("AES context allocation failed");
  Bytes out(cipher.size()); int n = 0, total = 0;
  bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) == 1 &&
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
    (aad.empty() || EVP_DecryptUpdate(ctx, nullptr, &n, aad.data(), aad.size()) == 1) &&
    (cipher.empty() || EVP_DecryptUpdate(ctx, out.data(), &n, cipher.data(), cipher.size()) == 1);
  total = n;
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<std::uint8_t*>(tag.data())) == 1 &&
    EVP_DecryptFinal_ex(ctx, out.data() + total, &n) == 1;
  total += n; EVP_CIPHER_CTX_free(ctx); if (!ok) return std::nullopt; out.resize(total); return out;
}

struct SigKey { Bytes seed, vk; };
EVP_PKEY* ed_private(std::span<const std::uint8_t> seed) {
  EVP_PKEY* key = EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr, seed.data(), seed.size());
  if (!key) fail("Ed25519 private-key derivation failed"); return key;
}
SigKey seed_keygen(std::span<const std::uint8_t> seed) {
  SigKey out{Bytes(seed.begin(), seed.end()), Bytes(32)}; EVP_PKEY* key = ed_private(seed); size_t n = out.vk.size();
  if (EVP_PKEY_get_raw_public_key(key, out.vk.data(), &n) != 1 || n != out.vk.size()) { EVP_PKEY_free(key); fail("Ed25519 public-key derivation failed"); }
  EVP_PKEY_free(key); return out;
}
Bytes sign_ed(std::span<const std::uint8_t> seed, std::span<const std::uint8_t> message) {
  EVP_PKEY* key = ed_private(seed); EVP_MD_CTX* ctx = EVP_MD_CTX_new(); size_t n = 0;
  if (!ctx || EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key) != 1 || EVP_DigestSign(ctx, nullptr, &n, message.data(), message.size()) != 1) { if(ctx) EVP_MD_CTX_free(ctx); EVP_PKEY_free(key); fail("Ed25519 signing setup failed"); }
  Bytes sig(n); const bool ok = EVP_DigestSign(ctx, sig.data(), &n, message.data(), message.size()) == 1;
  EVP_MD_CTX_free(ctx); EVP_PKEY_free(key); if (!ok) fail("Ed25519 signing failed"); sig.resize(n); return sig;
}
bool verify_ed(std::span<const std::uint8_t> vk, std::span<const std::uint8_t> msg, std::span<const std::uint8_t> sig) {
  EVP_PKEY* key = EVP_PKEY_new_raw_public_key_ex(nullptr, "ED25519", nullptr, vk.data(), vk.size()); if (!key) return false;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new(); const bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1 && EVP_DigestVerify(ctx, sig.data(), sig.size(), msg.data(), msg.size()) == 1;
  if (ctx) EVP_MD_CTX_free(ctx); EVP_PKEY_free(key); return ok;
}

// Bit convention: bit 0 is the low bit of byte 0 throughout tags, sketches and BCH codewords.
bool getbit(std::span<const std::uint8_t> b, std::size_t i) { return (b[i / 8] >> (i % 8)) & 1U; }
void setbit(Bytes& b, std::size_t i, bool v) { if (v) b[i / 8] |= static_cast<std::uint8_t>(1U << (i % 8)); else b[i / 8] &= static_cast<std::uint8_t>(~(1U << (i % 8))); }
int hamming(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
  if (a.size() != b.size()) fail("Hamming distance length mismatch"); int d = 0; for (std::size_t i = 0; i < a.size(); ++i) d += __builtin_popcount(static_cast<unsigned>(a[i] ^ b[i])); return d;
}

// Primitive binary BCH(255,207,t=6), using p(x)=x^8+x^4+x^3+x^2+1.
class Bch255 {
 public:
  Bch255() { init_gf(); init_generator(); }
  Bytes encode(std::span<const std::uint8_t> msg) const {
    if (msg.size() != 26) fail("BCH message must have 207 bits in 26 bytes"); Bytes out(32, 0);
    for (std::size_t i = 0; i < kBchK; ++i) if (getbit(msg, i)) for (std::size_t j = 0; j < gen_.size(); ++j) if (gen_[j]) setbit(out, i + j, !getbit(out, i + j));
    setbit(out, 255, false); return out;
  }
  std::optional<Bytes> decode(Bytes received) const {
    if (received.size() != 32) return std::nullopt; setbit(received, 255, false);
    std::array<std::uint8_t, 2 * kBchT> syn{}; bool clean = true;
    for (std::size_t s = 1; s <= 2 * kBchT; ++s) { std::uint8_t v = 0; for (std::size_t j = 0; j < kBchN; ++j) if (getbit(received, j)) v ^= alpha((s * j) % 255); syn[s - 1] = v; clean &= (v == 0); }
    if (clean) return received;
    std::array<std::uint8_t, 2 * kBchT + 1> c{}, b{}; c[0] = b[0] = 1; int L = 0, m = 1; std::uint8_t bb = 1;
    for (int n = 0; n < static_cast<int>(2 * kBchT); ++n) {
      std::uint8_t d = syn[n]; for (int i = 1; i <= L; ++i) d ^= mul(c[i], syn[n - i]);
      if (d == 0) { ++m; continue; }
      auto t = c; const auto coef = div(d, bb); for (int i = 0; i + m <= static_cast<int>(2 * kBchT); ++i) if (b[i]) c[i + m] ^= mul(coef, b[i]);
      if (2 * L <= n) { L = n + 1 - L; b = t; bb = d; m = 1; } else ++m;
    }
    if (L <= 0 || L > static_cast<int>(kBchT)) return std::nullopt;
    int roots = 0;
    for (int j = 0; j < static_cast<int>(kBchN); ++j) { std::uint8_t y = 0; const std::uint8_t x = alpha((255 - j) % 255); for (int i = L; i >= 0; --i) y = mul(y, x) ^ c[i]; if (y == 0) { setbit(received, j, !getbit(received, j)); ++roots; } }
    if (roots != L) return std::nullopt;
    for (std::size_t s = 1; s <= 2 * kBchT; ++s) { std::uint8_t v = 0; for (std::size_t j = 0; j < kBchN; ++j) if (getbit(received, j)) v ^= alpha((s * j) % 255); if (v) return std::nullopt; }
    return received;
  }
 private:
  std::array<std::uint8_t, 512> exp_{}; std::array<int, 256> log_{}; std::vector<std::uint8_t> gen_;
  void init_gf() { log_.fill(-1); std::uint16_t x = 1; for (int i = 0; i < 255; ++i) { exp_[i] = static_cast<std::uint8_t>(x); log_[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; } for (int i = 255; i < 512; ++i) exp_[i] = exp_[i - 255]; }
  std::uint8_t alpha(int e) const { return exp_[e % 255]; }
  std::uint8_t mul(std::uint8_t a, std::uint8_t b) const { return (!a || !b) ? 0 : exp_[log_[a] + log_[b]]; }
  std::uint8_t div(std::uint8_t a, std::uint8_t b) const { if (!b) fail("BCH division by zero"); return !a ? 0 : exp_[log_[a] + 255 - log_[b]]; }
  void init_generator() {
    std::set<int> roots; for (int e = 1; e <= 12; ++e) { int z = e; do { roots.insert(z); z = (z * 2) % 255; } while (z != e); }
    // Product of (x-alpha^e) over all conjugate roots has binary coefficients.
    std::vector<std::uint8_t> p{1}; for (int e : roots) { std::vector<std::uint8_t> q(p.size() + 1); const auto a = alpha(e); for (std::size_t i = 0; i < p.size(); ++i) { q[i] ^= mul(p[i], a); q[i + 1] ^= p[i]; } p = std::move(q); }
    gen_.resize(p.size()); for (std::size_t i = 0; i < p.size(); ++i) { if (p[i] != 0 && p[i] != 1) fail("BCH generator did not reduce to GF(2)"); gen_[i] = p[i] & 1U; }
    if (gen_.size() != 49) fail("unexpected BCH generator degree");
  }
};

Bytes toeplitz_hash(std::span<const std::uint8_t> x, std::span<const std::uint8_t> seed) {
  if (x.size() != 32 || seed.size() != 64) fail("Toeplitz input size mismatch"); Bytes out(32, 0);
  for (std::size_t row = 0; row < 256; ++row) { bool v = false; for (std::size_t col = 0; col < 256; ++col) v ^= (getbit(x, col) && getbit(seed, col + 255 - row)); if (v) setbit(out, row, true); }
  return out;
}
struct FeOutput { Bytes R, P; };
class FuzzyExtractor {
 public:
  FeOutput gen(std::span<const std::uint8_t> x) const {
    if (x.size() != 32) fail("fuzzy extractor input must be 256 bits"); Bytes msg = random_bytes(26); setbit(msg, 207, false); // unused high bit
    Bytes code = bch_.encode(msg), sketch(32, 0); for (std::size_t i = 0; i < 32; ++i) sketch[i] = x[i] ^ code[i]; setbit(sketch, 255, getbit(x, 255));
    Bytes seed = random_bytes(64), P = sketch; append(P, seed); return {toeplitz_hash(x, seed), P};
  }
  std::optional<Bytes> rep(std::span<const std::uint8_t> x, std::span<const std::uint8_t> P) const {
    if (x.size() != 32 || P.size() != kHelperBytes) return std::nullopt; Bytes sketch(P.begin(), P.begin() + 32), noisy(32, 0);
    for (std::size_t i = 0; i < 32; ++i) noisy[i] = x[i] ^ sketch[i]; setbit(noisy, 255, false); auto code = bch_.decode(noisy); if (!code) return std::nullopt;
    Bytes recovered(32, 0); for (std::size_t i = 0; i < 32; ++i) recovered[i] = sketch[i] ^ (*code)[i]; setbit(recovered, 255, getbit(sketch, 255));
    return toeplitz_hash(recovered, std::span<const std::uint8_t>(P.data() + 32, 64));
  }
 private: Bch255 bch_;
};

std::string normalize_text(std::span<const std::uint8_t> f) {
  std::string out; out.reserve(f.size()); bool space = true;
  for (auto c : f) { if (c < 128 && std::isalnum(c)) { out.push_back(static_cast<char>(std::tolower(c))); space = false; } else if (!space) { out.push_back(' '); space = true; } }
  if (!out.empty() && out.back() == ' ') out.pop_back(); return out;
}
Bytes simhash_text(std::span<const std::uint8_t> f, std::string_view domain) {
  const auto text = normalize_text(f); std::vector<std::string> w; std::istringstream is(text); for (std::string x; is >> x;) w.push_back(x);
  if (w.empty()) w.push_back("empty"); std::array<int, 256> score{};
  const std::size_t n = w.size() < 3 ? 1 : w.size() - 2;
  for (std::size_t i = 0; i < n; ++i) { std::string feature = w.size() < 3 ? w[i] : w[i] + "\x1f" + w[i+1] + "\x1f" + w[i+2]; Bytes h = hash_fields(domain, {bytes(feature)}); for (std::size_t b = 0; b < 256; ++b) score[b] += getbit(h, b) ? 1 : -1; }
  Bytes tag(32, 0); for (std::size_t b = 0; b < 256; ++b) if (score[b] >= 0) setbit(tag, b, true); return tag;
}
#ifdef PREFUZZDUP_ENABLE_MEDIA
Bytes phash_public(const cv::Mat& input) {
  cv::Mat gray, resized, f32, dctv;
  if (input.channels() == 1) gray = input; else cv::cvtColor(input, gray, cv::COLOR_BGR2GRAY);
  cv::resize(gray, resized, cv::Size(64,64), 0, 0, cv::INTER_AREA); resized.convertTo(f32, CV_32F); cv::dct(f32,dctv);
  std::vector<float> values; values.reserve(255); for(int y=0;y<16;++y)for(int x=0;x<16;++x)if(x||y)values.push_back(dctv.at<float>(y,x));
  auto middle=values.begin()+static_cast<long>(values.size()/2);std::nth_element(values.begin(),middle,values.end());const float med=*middle;Bytes out(32,0);
  for(int y=0;y<16;++y)for(int x=0;x<16;++x)setbit(out,static_cast<std::size_t>(y*16+x),dctv.at<float>(y,x)>=med);return out;
}
Bytes phash_private(const cv::Mat& input) {
  cv::Mat gray, resized, f32, dctv;
  if(input.channels()==1)gray=input;else cv::cvtColor(input,gray,cv::COLOR_BGR2GRAY);
  cv::resize(gray,resized,cv::Size(64,64),0,0,cv::INTER_AREA);resized.convertTo(f32,CV_32F);cv::dct(f32,dctv);
  std::array<float,1024> coeff{};float mean=0;for(int y=0;y<32;++y)for(int x=0;x<32;++x){coeff[y*32+x]=dctv.at<float>(y,x);mean+=coeff[y*32+x];}mean/=1024.0F;for(auto&v:coeff)v-=mean;
  Bytes out(32,0);
  for(int b=0;b<256;++b){auto h=hash_fields("PreFuzzDup/recovery/media-projection/v1",{bytes(std::to_string(b))});std::uint64_t state=0;for(int i=0;i<8;++i)state=(state<<8)|h[i];float sum=0;for(int k=0;k<24;++k){state^=state<<13;state^=state>>7;state^=state<<17;sum+=((state>>63)?1.0F:-1.0F)*coeff[state%1024];}if(sum>=0)setbit(out,b,true);}return out;
}
#ifdef PREFUZZDUP_ENABLE_VIDEO
Bytes video_hash(std::span<const std::uint8_t> raw,bool private_representation) {
  const fs::path tmp=fs::temp_directory_path()/("prefuzzdup-video-"+hex(random_bytes(8))+".bin");write_file(tmp,raw);std::vector<Bytes> frames;
  try { cv::VideoCapture cap(tmp.string());if(!cap.isOpened())fail("cannot decode video input");const int count=static_cast<int>(cap.get(cv::CAP_PROP_FRAME_COUNT));const int take=std::max(1,std::min(32,count>0?count:32));for(int i=0;i<take;++i){if(count>0)cap.set(cv::CAP_PROP_POS_FRAMES,(static_cast<double>(i)*count)/take);cv::Mat frame;if(!cap.read(frame))continue;frames.push_back(private_representation?phash_private(frame):phash_public(frame));}cap.release();std::error_code ec;fs::remove(tmp,ec); }
  catch(...){std::error_code ec;fs::remove(tmp,ec);throw;}
  if(frames.empty())fail("no decodable key frame in video input");Bytes out(32,0);for(int b=0;b<256;++b){int ones=0;for(const auto&f:frames)ones+=getbit(f,b);if(ones*2>=static_cast<int>(frames.size()))setbit(out,b,true);}return out;
}
#endif
#endif
Bytes make_tag(std::span<const std::uint8_t> f, const std::string& type) {
  if (type == "text") return simhash_text(f, "PreFuzzDup/tag/text/v1");
#ifdef PREFUZZDUP_ENABLE_MEDIA
  if(type=="image"){cv::Mat m=cv::imdecode(cv::Mat(1,static_cast<int>(f.size()),CV_8U,const_cast<std::uint8_t*>(f.data())),cv::IMREAD_COLOR);if(m.empty())fail("cannot decode image input");return phash_public(m);}
#ifdef PREFUZZDUP_ENABLE_VIDEO
  if(type=="video")return video_hash(f,false);
#endif
#endif
  fail("image/video adapters require a build with PREFUZZDUP_ENABLE_MEDIA=ON");
}
Bytes recovery_representation(std::span<const std::uint8_t> f, const std::string& type) {
  if (type == "text") return simhash_text(f, "PreFuzzDup/recovery/text/v1");
#ifdef PREFUZZDUP_ENABLE_MEDIA
  if(type=="image"){cv::Mat m=cv::imdecode(cv::Mat(1,static_cast<int>(f.size()),CV_8U,const_cast<std::uint8_t*>(f.data())),cv::IMREAD_COLOR);if(m.empty())fail("cannot decode image input");return phash_private(m);}
#ifdef PREFUZZDUP_ENABLE_VIDEO
  if(type=="video")return video_hash(f,true);
#endif
#endif
  fail("image/video adapters require a build with PREFUZZDUP_ENABLE_MEDIA=ON");
}

class PrefixFilter {
 public:
  PrefixFilter() = default;
  PrefixFilter(std::size_t capacity, double fpp) { reset(capacity, fpp); }
  void reset(std::size_t capacity, double fpp) {
    if (!capacity || !(fpp > 0 && fpp < 1)) fail("invalid Prefix Filter parameters");
    bits_ = std::max<std::size_t>(8, static_cast<std::size_t>(std::ceil(-static_cast<double>(capacity) * std::log(fpp) / (std::log(2) * std::log(2)))));
    hashes_ = std::max<std::size_t>(1, static_cast<std::size_t>(std::round(static_cast<double>(bits_) / capacity * std::log(2)))); data_.assign((bits_ + 7) / 8, 0);
  }
  void insert(std::span<const std::uint8_t> v) { for (std::size_t i = 0; i < hashes_; ++i) setbit(data_, index(v, i), true); }
  bool maybe_contains(std::span<const std::uint8_t> v) const { for (std::size_t i = 0; i < hashes_; ++i) if (!getbit(data_, index(v, i))) return false; return true; }
  std::size_t bytes_used() const { return data_.size(); }
 private:
  std::size_t bits_ = 0, hashes_ = 0; Bytes data_;
  std::size_t index(std::span<const std::uint8_t> v, std::size_t i) const { Bytes b(v.begin(), v.end()); append_u32(b, static_cast<std::uint32_t>(i)); auto h = sha256(b); std::uint64_t x = 0; for (int j = 0; j < 8; ++j) x = (x << 8) | h[j]; return x % bits_; }
};

Bytes segment(std::span<const std::uint8_t> tag, int j, int pieces) {
  const int start = j * 256 / pieces, end = (j + 1) * 256 / pieces; Bytes out((end - start + 7) / 8, 0);
  for (int b = start; b < end; ++b) if (getbit(tag, b)) setbit(out, b - start, true); return out;
}

class Db {
 public:
  explicit Db(const fs::path& p) { if (sqlite3_open_v2(p.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) fail("cannot open SQLite database: " + std::string(sqlite3_errmsg(db_))); sqlite3_busy_timeout(db_, 10000); }
  ~Db() { if (db_) sqlite3_close(db_); }
  Db(const Db&) = delete;
  void exec(const std::string& s) { char* e = nullptr; if (sqlite3_exec(db_, s.c_str(), nullptr, nullptr, &e) != SQLITE_OK) { std::string m = e ? e : sqlite3_errmsg(db_); sqlite3_free(e); fail("SQLite: " + m); } }
  sqlite3* raw() { return db_; }
 private: sqlite3* db_ = nullptr;
};
class Stmt {
 public:
  Stmt(Db& d, const char* sql) { if (sqlite3_prepare_v2(d.raw(), sql, -1, &s_, nullptr) != SQLITE_OK) fail("SQLite prepare: " + std::string(sqlite3_errmsg(d.raw()))); }
  ~Stmt() { sqlite3_finalize(s_); }
  void text(int i, const std::string& v) { if (sqlite3_bind_text(s_, i, v.c_str(), v.size(), SQLITE_TRANSIENT) != SQLITE_OK) fail("SQLite text bind failed"); }
  void blob(int i, std::span<const std::uint8_t> v) { if (sqlite3_bind_blob(s_, i, v.data(), v.size(), SQLITE_TRANSIENT) != SQLITE_OK) fail("SQLite blob bind failed"); }
  void integer(int i, std::int64_t v) { if (sqlite3_bind_int64(s_, i, v) != SQLITE_OK) fail("SQLite integer bind failed"); }
  bool step_row() { const int r = sqlite3_step(s_); if (r == SQLITE_ROW) return true; if (r == SQLITE_DONE) return false; fail("SQLite step: " + std::string(sqlite3_errmsg(sqlite3_db_handle(s_)))); }
  void done() { if (sqlite3_step(s_) != SQLITE_DONE) fail("SQLite step: " + std::string(sqlite3_errmsg(sqlite3_db_handle(s_)))); }
  std::string col_text(int i) const { const auto* p = sqlite3_column_text(s_, i); return p ? reinterpret_cast<const char*>(p) : ""; }
  Bytes col_blob(int i) const { const auto* p = static_cast<const std::uint8_t*>(sqlite3_column_blob(s_, i)); const int n = sqlite3_column_bytes(s_, i); return p ? Bytes(p, p + n) : Bytes{}; }
  std::int64_t col_int(int i) const { return sqlite3_column_int64(s_, i); }
 private: sqlite3_stmt* s_ = nullptr;
};

struct Record { std::string rid, type, path; Bytes tag, helper, vk, nfile, nwrap, ctag, wrap, wtag; };
struct Candidate { Record r; int distance; };
struct Challenge { Bytes token; };

class Server {
 public:
  Server(const fs::path& db_path, const fs::path& blob_dir) : db_(db_path), blobs_(blob_dir) { fs::create_directories(blobs_); }
  void setup(std::size_t capacity, double fpp, std::map<std::string,int> thresholds) {
    if (thresholds.empty()) fail("at least one threshold is required"); for (const auto& [t,d] : thresholds) if (d < 0 || d >= 256) fail("each search threshold must be in [0,255]");
    schema(); db_.exec("BEGIN IMMEDIATE"); put_meta("capacity", std::to_string(capacity)); put_meta("fpp", std::to_string(fpp));
    std::ostringstream os; bool first = true; for (const auto& [t,d] : thresholds) { if (!first) os << ','; os << t << '=' << d; first = false; } put_meta("thresholds", os.str()); db_.exec("COMMIT"); load_config(); rebuild_filters();
  }
  void open_existing() { schema(); load_config(); rebuild_filters(); }
  int threshold(const std::string& type) const { auto it = thresholds_.find(type); if (it == thresholds_.end()) fail("no threshold configured for type: " + type); return it->second; }
  std::vector<Candidate> candidates(const std::string& type, std::span<const std::uint8_t> tag) {
    const int pieces = threshold(type) + 1; std::unordered_set<std::string> ids;
    for (int j = 0; j < pieces; ++j) { Bytes s = segment(tag, j, pieces); auto fit = filters_.find(filter_key(type,j)); if (fit == filters_.end() || !fit->second.maybe_contains(s)) continue;
      Stmt q(db_, "SELECT rid FROM postings WHERE type=?1 AND seg=?2 AND value=?3"); q.text(1,type); q.integer(2,j); q.blob(3,s); while (q.step_row()) ids.insert(q.col_text(0)); }
    std::vector<Candidate> out; for (const auto& rid : ids) { auto r = get_record(rid); if (!r) continue; const int d = hamming(tag,r->tag); if (d <= threshold(type)) out.push_back({*r,d}); }
    std::sort(out.begin(), out.end(), [](const auto& a,const auto& b){ return a.distance != b.distance ? a.distance < b.distance : a.r.rid < b.r.rid; }); return out;
  }
  void insert_record(const Record& r) {
    if (r.tag.size()!=32 || r.helper.size()!=kHelperBytes || r.vk.size()!=32 || r.nfile.size()!=12 || r.nwrap.size()!=12 || r.ctag.size()!=16 || r.wtag.size()!=16) fail("malformed representative record");
    const int pieces = threshold(r.type)+1; for (int j=0;j<pieces;++j) filters_[filter_key(r.type,j)].insert(segment(r.tag,j,pieces)); // Insert before visibility: a crash may add a false positive, never a false negative.
    db_.exec("BEGIN IMMEDIATE"); try {
      Stmt q(db_, "INSERT INTO records(rid,type,tag,helper,vk,nfile,nwrap,cipher_path,ctag,wrap,wtag) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)");
      q.text(1,r.rid);q.text(2,r.type);q.blob(3,r.tag);q.blob(4,r.helper);q.blob(5,r.vk);q.blob(6,r.nfile);q.blob(7,r.nwrap);q.text(8,r.path);q.blob(9,r.ctag);q.blob(10,r.wrap);q.blob(11,r.wtag);q.done();
      for(int j=0;j<pieces;++j) { Stmt p(db_,"INSERT INTO postings(type,seg,value,rid) VALUES(?1,?2,?3,?4)"); p.text(1,r.type);p.integer(2,j); auto s=segment(r.tag,j,pieces);p.blob(3,s);p.text(4,r.rid);p.done(); }
      db_.exec("COMMIT");
    } catch (...) { try { db_.exec("ROLLBACK"); } catch (...) {} throw; }
  }
  std::optional<Record> get_record(const std::string& rid) {
    Stmt q(db_, "SELECT rid,type,tag,helper,vk,nfile,nwrap,cipher_path,ctag,wrap,wtag FROM records WHERE rid=?1"); q.text(1,rid); if(!q.step_row()) return std::nullopt;
    return Record{q.col_text(0),q.col_text(1),q.col_text(7),q.col_blob(2),q.col_blob(3),q.col_blob(4),q.col_blob(5),q.col_blob(6),q.col_blob(8),q.col_blob(9),q.col_blob(10)};
  }
  void bind(const std::string& uid, const std::string& rid) { Stmt q(db_, "INSERT OR IGNORE INTO refs(uid,rid,created) VALUES(?1,?2,unixepoch())"); q.text(1,uid);q.text(2,rid);q.done(); }
  Challenge issue_challenge(const std::string& uid, const std::string& rid, std::span<const std::uint8_t> query_tag) {
    Challenge c{random_bytes(32)}; Stmt q(db_, "INSERT INTO challenges(token,uid,rid,query_tag,expires,used) VALUES(?1,?2,?3,?4,unixepoch()+120,0)"); q.blob(1,c.token);q.text(2,uid);q.text(3,rid);q.blob(4,query_tag);q.done(); return c;
  }
  bool consume_verify(const std::string& uid, const Record& r, std::span<const std::uint8_t> query_tag, std::span<const std::uint8_t> token, std::span<const std::uint8_t> sig) {
    db_.exec("BEGIN IMMEDIATE"); bool permitted=false; try { Stmt q(db_, "SELECT uid,rid,query_tag,expires,used FROM challenges WHERE token=?1");q.blob(1,token);
      if(q.step_row()) { const bool binding=q.col_text(0)==uid && q.col_text(1)==r.rid && equal_ct(q.col_blob(2),query_tag) && q.col_int(3)>=std::time(nullptr) && q.col_int(4)==0; Stmt u(db_,"UPDATE challenges SET used=1 WHERE token=?1");u.blob(1,token);u.done(); permitted=binding; }
      db_.exec("COMMIT");
    } catch (...) { try{db_.exec("ROLLBACK");}catch(...){ } throw; }
    if(!permitted) return false; return verify_ed(r.vk, challenge_message(uid,r,query_tag,token),sig);
  }
  Bytes read_ciphertext(const Record& r) const { return read_file(blobs_ / r.path); }
  fs::path blob_path(const std::string& rid) const { return blobs_ / (rid + ".bin"); }
  std::string relative_blob_name(const std::string& rid) const { return rid + ".bin"; }
  std::vector<std::string> refs(const std::string& uid) { Stmt q(db_,"SELECT rid FROM refs WHERE uid=?1 ORDER BY created,rid");q.text(1,uid);std::vector<std::string> out;while(q.step_row())out.push_back(q.col_text(0));return out; }
  static Bytes record_hash(const Record& r) { return hash_fields("PreFuzzDup/record/v1", {bytes(r.rid),bytes(r.type),r.tag,sha256(r.helper)}); }
  static Bytes aad(const Record& r) { Bytes hr=record_hash(r); return hash_fields("PreFuzzDup/aad/v1", {hr,r.vk,r.nfile,r.nwrap}); }
  static Bytes challenge_message(const std::string& uid,const Record& r,std::span<const std::uint8_t> qtag,std::span<const std::uint8_t> c) { return hash_fields("PreFuzzDup/FuzzyPoW/v1", {bytes(uid),record_hash(r),Bytes(qtag.begin(),qtag.end()),Bytes(c.begin(),c.end())}); }
 private:
  Db db_; fs::path blobs_; std::size_t capacity_{}; double fpp_{}; std::map<std::string,int> thresholds_; std::unordered_map<std::string,PrefixFilter> filters_;
  static std::string filter_key(const std::string&t,int j){return t+"#"+std::to_string(j);} 
  void schema() { db_.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;"); db_.exec("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL); CREATE TABLE IF NOT EXISTS records(rid TEXT PRIMARY KEY,type TEXT NOT NULL,tag BLOB NOT NULL,helper BLOB NOT NULL,vk BLOB NOT NULL,nfile BLOB NOT NULL,nwrap BLOB NOT NULL,cipher_path TEXT NOT NULL,ctag BLOB NOT NULL,wrap BLOB NOT NULL,wtag BLOB NOT NULL,created INTEGER NOT NULL DEFAULT(unixepoch())); CREATE TABLE IF NOT EXISTS postings(type TEXT NOT NULL,seg INTEGER NOT NULL,value BLOB NOT NULL,rid TEXT NOT NULL REFERENCES records(rid),PRIMARY KEY(type,seg,value,rid)) WITHOUT ROWID; CREATE TABLE IF NOT EXISTS refs(uid TEXT NOT NULL,rid TEXT NOT NULL REFERENCES records(rid),created INTEGER NOT NULL,PRIMARY KEY(uid,rid)); CREATE TABLE IF NOT EXISTS challenges(token BLOB PRIMARY KEY,uid TEXT NOT NULL,rid TEXT NOT NULL,query_tag BLOB NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);"); }
  void put_meta(const std::string& k,const std::string& v){Stmt q(db_,"INSERT INTO meta(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=excluded.v");q.text(1,k);q.text(2,v);q.done();}
  std::string meta(const std::string& k){Stmt q(db_,"SELECT v FROM meta WHERE k=?1");q.text(1,k);if(!q.step_row())fail("database was not initialized; run setup first");return q.col_text(0);} 
  void load_config(){capacity_=std::stoull(meta("capacity"));fpp_=std::stod(meta("fpp"));thresholds_.clear();std::istringstream is(meta("thresholds"));for(std::string x;std::getline(is,x,',');){auto p=x.find('=');if(p==std::string::npos)fail("invalid threshold configuration");thresholds_[x.substr(0,p)]=std::stoi(x.substr(p+1));}}
  void rebuild_filters(){filters_.clear();for(const auto&[t,d]:thresholds_)for(int j=0;j<=d;++j)filters_.emplace(filter_key(t,j),PrefixFilter(capacity_,fpp_));Stmt q(db_,"SELECT type,tag FROM records");while(q.step_row()){auto t=q.col_text(0);auto tag=q.col_blob(1);auto it=thresholds_.find(t);if(it==thresholds_.end())continue;for(int j=0;j<=it->second;++j)filters_[filter_key(t,j)].insert(segment(tag,j,it->second+1));}}
};

struct ClientProof { Bytes Q, seed, vk, sig; };
Bytes proof_seed(std::span<const std::uint8_t> Q, const Record& r) { return hkdf_expand(Q, "PreFuzzDup/proof/v1:" + hex(Server::record_hash(r)), 32); }
Bytes wrap_key(std::span<const std::uint8_t> Q, const Record& r) { return hkdf_expand(Q, "PreFuzzDup/wrap/v1:" + hex(sha256(Server::aad(r))), 32); }

Record first_upload(Server& s, const std::string& uid, const std::string& type, std::span<const std::uint8_t> file, std::span<const std::uint8_t> tag, const FuzzyExtractor& fe) {
  Record r; r.rid=hex(random_bytes(16));r.type=type;r.tag.assign(tag.begin(),tag.end());auto feo=fe.gen(recovery_representation(file,type));r.helper=feo.P;
  Bytes zero(32,0),Q=hkdf_extract(zero,feo.R); r.nfile=random_bytes(12);r.nwrap=random_bytes(12);r.vk.resize(32); // compute identity-dependent proof key after immutable record fields are present
  Bytes provisional=hash_fields("PreFuzzDup/record/v1",{bytes(r.rid),bytes(r.type),r.tag,sha256(r.helper)}); Bytes seed=hkdf_expand(Q,"PreFuzzDup/proof/v1:"+hex(provisional),32);auto kp=seed_keygen(seed);r.vk=kp.vk;
  const Bytes ad=Server::aad(r),kd=random_bytes(32),kw=wrap_key(Q,r);auto fc=aead_encrypt(kd,r.nfile,file,ad);auto wc=aead_encrypt(kw,r.nwrap,kd,ad);r.ctag=fc.tag;r.wrap=wc.ciphertext;r.wtag=wc.tag;r.path=s.relative_blob_name(r.rid);
  // Local AEAD check makes an accidental bad upload fail before the record becomes visible.
  auto local_k=aead_decrypt(kw,r.nwrap,r.wrap,r.wtag,ad);auto local_f=local_k?aead_decrypt(*local_k,r.nfile,fc.ciphertext,r.ctag,ad):std::nullopt;if(!local_f||!equal_ct(*local_f,file))fail("local AEAD self-check failed");
  write_file(s.blob_path(r.rid),fc.ciphertext); try{s.insert_record(r);s.bind(uid,r.rid);}catch(...){std::error_code ec;fs::remove(s.blob_path(r.rid),ec);throw;} return r;
}

std::optional<Bytes> fuzzy_pow(Server& s,const std::string& uid,const Record&r,std::span<const std::uint8_t> file,std::span<const std::uint8_t> qtag,const FuzzyExtractor& fe) {
  auto R=fe.rep(recovery_representation(file,r.type),r.helper);if(!R)return std::nullopt;Bytes zero(32,0),Q=hkdf_extract(zero,*R),seed=proof_seed(Q,r);auto kp=seed_keygen(seed);if(!equal_ct(kp.vk,r.vk))return std::nullopt;
  auto c=s.issue_challenge(uid,r.rid,qtag);auto m=Server::challenge_message(uid,r,qtag,c.token);auto sig=sign_ed(kp.seed,m);if(!s.consume_verify(uid,r,qtag,c.token,sig))return std::nullopt;return Q;
}
std::optional<Bytes> recover(Server& s,const Record&r,std::span<const std::uint8_t> Q,std::span<const std::uint8_t> query_tag,const FuzzyExtractor& fe) {
  const auto ad=Server::aad(r);auto kd=aead_decrypt(wrap_key(Q,r),r.nwrap,r.wrap,r.wtag,ad);if(!kd)return std::nullopt;auto file=aead_decrypt(*kd,r.nfile,s.read_ciphertext(r),r.ctag,ad);if(!file)return std::nullopt;
  if(!equal_ct(make_tag(*file,r.type),r.tag) || hamming(query_tag,make_tag(*file,r.type))>s.threshold(r.type))return std::nullopt;auto Rr=fe.rep(recovery_representation(*file,r.type),r.helper);if(!Rr)return std::nullopt;Bytes zero(32,0);if(!equal_ct(hkdf_extract(zero,*Rr),Q))return std::nullopt;return file;
}

std::map<std::string,std::string> options(int argc,char**argv,int start){std::map<std::string,std::string>o;for(int i=start;i<argc;i++){std::string k=argv[i];if(!k.starts_with("--")||i+1>=argc)fail("expected --name value");o[k.substr(2)]=argv[++i];}return o;}
const std::string& need(const std::map<std::string,std::string>&o,const std::string&k){auto it=o.find(k);if(it==o.end())fail("missing --"+k);return it->second;}
std::map<std::string,int> parse_thresholds(const std::string&s){std::map<std::string,int>r;std::istringstream is(s);for(std::string x;std::getline(is,x,',');){auto p=x.find('=');if(p==std::string::npos)fail("threshold must be type=value");r[x.substr(0,p)]=std::stoi(x.substr(p+1));}return r;}
void usage(){std::cout<<"PreFuzzDup reference prototype\nCommands:\n  setup --db DB --blob-dir DIR --capacity N --fpp P --threshold text=6\n  upload --db DB --blob-dir DIR --uid UID --type text --file FILE\n  list-refs --db DB --blob-dir DIR --uid UID\n  bulk-upload --db DB --blob-dir DIR --manifest FILE\n  self-test\n";}
void self_test(){
  FuzzyExtractor fe;
  for(int e=0;e<=6;++e) for(int t=0;t<5;++t) { auto x=random_bytes(32);auto o=fe.gen(x);auto y=x;for(int j=0;j<e;++j)setbit(y,(j*37+t)%256,!getbit(y,(j*37+t)%256));auto rr=fe.rep(y,o.P);if(!rr||!equal_ct(*rr,o.R))fail("BCH fuzzy extractor self-test failed"); }
  auto k=random_bytes(32),n=random_bytes(12),m=bytes("aead test"),a=bytes("aad");auto c=aead_encrypt(k,n,m,a);auto p=aead_decrypt(k,n,c.ciphertext,c.tag,a);if(!p||!equal_ct(*p,m))fail("AEAD self-test failed");
  // This also checks that the proof seed is bound to the representative
  // record, the one-shot challenge is consumed, and recovery verifies tags.
  const fs::path root=fs::temp_directory_path()/("prefuzzdup-selftest-"+hex(random_bytes(6))); fs::create_directories(root);
  try { Server s(root/"state.sqlite",root/"blobs");s.setup(100,0.01,{{"text",6}});const Bytes f=bytes("A short message about encrypted cloud storage and fuzzy deduplication.");const Bytes tag=make_tag(f,"text");auto r=first_upload(s,"alice","text",f,tag,fe);auto q=fuzzy_pow(s,"bob",r,f,tag,fe);auto restored=q?recover(s,r,*q,tag,fe):std::nullopt;if(!restored||!equal_ct(*restored,f))fail("end-to-end protocol self-test failed");s.bind("bob",r.rid);if(s.refs("bob").size()!=1)fail("reference-binding self-test failed");std::error_code ec;fs::remove_all(root,ec); }
  catch (...) { std::error_code ec;fs::remove_all(root,ec);throw; }
  std::cout<<"self-test passed (BCH t=6, AES-GCM and end-to-end protocol)\n";
}
} // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2) { usage(); return 1; }
    const std::string cmd = argv[1];
    if (cmd == "self-test") { self_test(); return 0; }

    const auto o = options(argc, argv, 2);
    if (cmd == "setup") {
      Server s(need(o, "db"), need(o, "blob-dir"));
      s.setup(std::stoull(need(o, "capacity")), std::stod(need(o, "fpp")), parse_thresholds(need(o, "threshold")));
      std::cout << "initialized\n";
      return 0;
    }

    Server s(need(o, "db"), need(o, "blob-dir"));
    s.open_existing();
    if (cmd == "list-refs") {
      for (const auto& rid : s.refs(need(o, "uid"))) std::cout << rid << '\n';
      return 0;
    }

    FuzzyExtractor fe;
    if (cmd == "upload") {
      const Bytes file = read_file(need(o, "file"));
      const auto& type = need(o, "type");
      const auto& uid = need(o, "uid");
      const Bytes tag = make_tag(file, type);
      for (const auto& c : s.candidates(type, tag)) {
        auto Q = fuzzy_pow(s, uid, c.r, file, tag, fe);
        if (!Q) continue;
        auto restored = recover(s, c.r, *Q, tag, fe);
        if (!restored) continue;
        s.bind(uid, c.r.rid);
        std::cout << "reused " << c.r.rid << " distance=" << c.distance
                  << " recovered_bytes=" << restored->size() << '\n';
        return 0;
      }
      const auto r = first_upload(s, uid, type, file, tag, fe);
      std::cout << "stored " << r.rid << '\n';
      return 0;
    }

    if (cmd == "bulk-upload") {
      std::ifstream manifest(need(o, "manifest"));
      if (!manifest) fail("cannot open manifest");
      std::size_t n = 0, stored = 0, reused = 0;
      for (std::string line; std::getline(manifest, line); ) {
        if (line.empty()) continue;
        std::vector<std::string> row;
        std::istringstream fields(line);
        for (std::string field; std::getline(fields, field, ','); ) row.push_back(field);
        if (row == std::vector<std::string>{"uid", "type", "path"}) continue;
        if (row.size() != 3) fail("manifest line must be uid,type,path");
        const Bytes file = read_file(row[2]);
        const Bytes tag = make_tag(file, row[1]);
        bool reused_this = false;
        for (const auto& c : s.candidates(row[1], tag)) {
          auto Q = fuzzy_pow(s, row[0], c.r, file, tag, fe);
          if (Q && recover(s, c.r, *Q, tag, fe)) {
            s.bind(row[0], c.r.rid);
            ++reused;
            reused_this = true;
            break;
          }
        }
        if (!reused_this) { first_upload(s, row[0], row[1], file, tag, fe); ++stored; }
        ++n;
        if (n % 1000 == 0) std::cerr << "processed " << n << " records\n";
      }
      std::cout << "processed=" << n << " stored=" << stored << " reused=" << reused << '\n';
      return 0;
    }

    usage();
    return 1;
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << '\n';
    return 2;
  }
}
