#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>
#include <functional>
#include <optional>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

namespace fs = std::filesystem;

std::string read_file(fs::path pathfile) {
	std::ifstream ifile(pathfile, std::ios::binary);
	if (ifile)
		return std::string((std::istreambuf_iterator<char>(ifile)), std::istreambuf_iterator<char>());
	else
		throw std::runtime_error("unable to read file.");
}

std::string base64_encode(uint8_t* data, size_t length)
{
	static const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";
	std::string ret;
	int i = 0;
	int j = 0;
	uint8_t char_array_3[3];
	uint8_t char_array_4[4];

	while (length--) {
		char_array_3[i++] = *(data++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i < 4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';
	}
	return ret;
}
#define OSSL_TEST(name, v) {if (v<=0) {std::cerr << #name << " error " << v << " at " << __FILE__<<", l."<< __LINE__<<std::endl; throw std::runtime_error("openssl error"); }}
#define OSSL_CALL(func, ...) {int v = func (__VA_ARGS__); OSSL_TEST(#func, v)}

template<typename T>
struct deleter
{void operator()(T* ptr) const;};
// #define STRING(t) t
// #define DEFINE_DELETER(type) template<> void deleter<type>::operator()(type* ptr) const {STRING(type)_free(ptr);}
// DEFINE_DELETER(PKCS12)
// DEFINE_DELETER(EVP_PKEY)
// DEFINE_DELETER(EVP_PKEY_CTX)
// DEFINE_DELETER(EVP_MD_CTX)
// DEFINE_DELETER(X509)
template<> void deleter<PKCS12>::operator()(PKCS12* ptr) const {PKCS12_free(ptr);}
template<> void deleter<EVP_PKEY>::operator()(EVP_PKEY* ptr) const {EVP_PKEY_free(ptr);}
template<> void deleter<EVP_PKEY_CTX>::operator()(EVP_PKEY_CTX* ptr) const {EVP_PKEY_CTX_free(ptr);}
template<> void deleter<EVP_MD_CTX>::operator()(EVP_MD_CTX* ptr) const {EVP_MD_CTX_free(ptr);}
template<> void deleter<X509>::operator()(X509* ptr) const {X509_free(ptr);}

template<typename T>
using ossl_ptr = std::unique_ptr<T, deleter<T>>;

using md_t = std::vector<uint8_t>;
using sign_t = std::vector<uint8_t>;

ossl_ptr<PKCS12> load_pkcs12(fs::path p) {
	auto cert = read_file(p);
	PKCS12* tmp_pkcs12=nullptr;
	const uint8_t* t = (const uint8_t*)cert.data();
	if (!d2i_PKCS12(&tmp_pkcs12, &t, static_cast<long>(cert.size())))
		throw std::runtime_error("unable to read PKCS12 file.");
	return ossl_ptr<PKCS12>(tmp_pkcs12);
}
std::tuple<ossl_ptr<EVP_PKEY>, ossl_ptr<X509>> pkcs12_to_keycert(ossl_ptr<PKCS12>& pkcs12, std::optional<std::string> password) {
	EVP_PKEY* tmp_pkey=nullptr;
	X509* tmp_x509=nullptr;
	OSSL_CALL(PKCS12_parse, pkcs12.get(), password ? password->data() : nullptr, &tmp_pkey, &tmp_x509, nullptr);
	return {ossl_ptr<EVP_PKEY>(tmp_pkey), ossl_ptr<X509>(tmp_x509)};
}

void init_pkey_ctx(ossl_ptr<EVP_PKEY_CTX>& pkey_ctx) {
	OSSL_CALL(EVP_PKEY_sign_init, pkey_ctx.get());
	OSSL_TEST(EVP_PKEY_CTX_set_signature_md, EVP_PKEY_CTX_set_signature_md(pkey_ctx.get(), EVP_sha256()));
	OSSL_TEST(EVP_PKEY_CTX_set_rsa_padding,EVP_PKEY_CTX_set_rsa_padding(pkey_ctx.get(), RSA_PKCS1_PADDING));
}
template <typename T>
md_t digest(const T& data) {
	std::vector<uint8_t> md(EVP_MAX_MD_SIZE, ' ');
	uint32_t md_size=0;
	OSSL_CALL(EVP_Digest, data.data(), data.size(), md.data(), &md_size ,EVP_sha256(), nullptr);
	md.resize(md_size);
	return md;
}
sign_t sign_md(const ossl_ptr<EVP_PKEY_CTX>& pkey_ctx, const md_t& md) {
	size_t sign_size=0;
	OSSL_CALL(EVP_PKEY_sign,pkey_ctx.get(), nullptr, &sign_size, md.data(), md.size());
	sign_t sign(sign_size, ' ');
	OSSL_CALL(EVP_PKEY_sign,pkey_ctx.get(), sign.data(), &sign_size, md.data(), md.size());
	return sign;
}
int verify(const ossl_ptr<EVP_PKEY_CTX>& pubkey_ctx, const sign_t& sign, const md_t& md) {
	OSSL_CALL(EVP_PKEY_verify_init,pubkey_ctx.get());
	OSSL_TEST(EVP_PKEY_CTX_set_signature_md, EVP_PKEY_CTX_set_signature_md(pubkey_ctx.get(), EVP_sha256()));
	OSSL_TEST(EVP_PKEY_CTX_set_rsa_padding,EVP_PKEY_CTX_set_rsa_padding(pubkey_ctx.get(), RSA_PKCS1_PADDING));
	return EVP_PKEY_verify(pubkey_ctx.get(), sign.data(), sign.size(), md.data(), md.size());
}
template <typename T>
sign_t sign_data(const ossl_ptr<EVP_PKEY>& pkey, const T& value) {
	size_t sign_size=0;
	auto md_ctx = ossl_ptr<EVP_MD_CTX>(EVP_MD_CTX_new());
	EVP_PKEY_CTX* pkey_ctx=nullptr;
	OSSL_CALL(EVP_DigestSignInit,md_ctx.get(), &pkey_ctx, EVP_sha256(), nullptr, pkey.get());
	OSSL_TEST(EVP_PKEY_CTX_set_signature_md, EVP_PKEY_CTX_set_signature_md(pkey_ctx, EVP_sha256()));
	OSSL_TEST(EVP_PKEY_CTX_set_rsa_padding,EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING));
	OSSL_CALL(EVP_DigestSign,md_ctx.get(), nullptr, &sign_size, reinterpret_cast<const uint8_t*>(value.data()), value.size());
	sign_t sign(sign_size, ' ');
	OSSL_CALL(EVP_DigestSign,md_ctx.get(), sign.data(), &sign_size, reinterpret_cast<const uint8_t*>(value.data()), value.size());
	return sign;
}

struct Parameters {
	std::optional<fs::path> pkcs12_path=std::nullopt;
	std::optional<std::string> password=std::nullopt;
	std::vector<uint8_t> data_stdin;
	bool display_digest=false;
	bool display_sign=false;
	bool display_verify=false;
	bool display_digestsign=false;
	int displayers=0;
	
	void load(int argc, char** argv) {
		using namespace std::string_view_literals;
		for (int i=1;i<argc; ++i) {
			if (argv[i]=="--digest"sv)
				display_digest=true;
			else if (argv[i]=="--help"sv)
			{
				help();
				exit(0);
			}
			else if (argv[i]=="--digest-sign"sv)
				display_digestsign=true;
			else if (argv[i]=="--sign"sv)
				display_sign=true;
			else if (argv[i]=="--verify"sv)
				display_verify=true;
			else if (argv[i]=="--display-all"sv)
			{
				display_verify=true;
				display_digest=true;
				display_sign=true;
				display_digestsign=true;
			}
			else if (argv[i]=="--pkcs12"sv)
			{
				if (i<argc-1)
					pkcs12_path=argv[++i];
			}
			else if (argv[i]=="--password"sv)
			{
				if (i<argc-1)
					password=argv[++i];
			}
		}
		data_stdin = std::vector<uint8_t>((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
		
		displayers += display_verify + display_sign + display_digestsign + display_digest;
	}
	void check() {
		if (!pkcs12_path) 
			throw std::runtime_error("pkcs12 file is missing");
	}
	static void help()
	{
		std::cout << R"(signer --pkcs12 <pkcs12_file> [options]
--pkcs12 path			pkcs12 file path
--password passw		pkcs12 password (optional)
--digest				display digest (SHA256)
--sign					display signature (SHA256, RSA PKCS1 padding)
--verify				once sign done, display verify from public key
--digest-sign			display digest and sign via EVP_DigestSign
--display-all			display all things above)";
	}
};

int main(int argc, char** argv)
{
	try
	{
		Parameters params;
		params.load(argc, argv);
		params.check();

		ossl_ptr<PKCS12> pkcs12 = load_pkcs12(*params.pkcs12_path);
		ossl_ptr<EVP_PKEY> pkey;
		ossl_ptr<X509> cert;
		std::tie(pkey, cert) = pkcs12_to_keycert(pkcs12, params.password);
		ossl_ptr<EVP_PKEY_CTX> pkey_ctx = ossl_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new(pkey.get(), nullptr));

		init_pkey_ctx(pkey_ctx);

		auto pubkey = ossl_ptr<EVP_PKEY>(X509_get_pubkey(cert.get()));
		auto pubkey_ctx = ossl_ptr<EVP_PKEY_CTX>(EVP_PKEY_CTX_new(pubkey.get(), nullptr));

		auto md = digest(params.data_stdin);
		auto sign = sign_md(pkey_ctx, md);
		if (params.display_digest)
		{
			if (params.displayers>1)
				std::cout << "Digest: ";
			std::cout << base64_encode(md.data(), md.size()) << std::endl;
		}
		if (params.display_sign)
		{
			if (params.displayers>1)
				std::cout << "Sign: ";
			std::cout << base64_encode(sign.data(), sign.size()) << std::endl;
		}
		if (params.display_verify)
		{
			int verify_ret = verify(pubkey_ctx, sign, md);
			if (params.displayers>1)
				std::cout << "Verify: ";
			std::cout << (verify_ret <= 0 ? "NOK" : "OK") << std::endl;
		}
		if (params.display_digestsign)
		{
			auto sign_d = sign_data(pkey, params.data_stdin);
			if (params.displayers>1)
				std::cout << "Digest sign: ";
			std::cout << base64_encode(sign_d.data(), sign_d.size()) << std::endl;
		}
	}
	catch(std::runtime_error exc)
	{
		std::cerr <<"error: "<< exc.what() << std::endl;
		std::cerr << "[HELP]" << std::endl;
		Parameters::help();
		return 1;
	}
	return 0;
}