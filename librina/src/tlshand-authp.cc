//
// TLS Handshake authentication policy
//
//    Eduard Grasa <eduard.grasa@i2cat.net>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
// MA  02110-1301  USA
//

#include <time.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

//BERTA
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
 #include <openssl/hmac.h>



#define RINA_PREFIX "librina.tls-handshake"

#include "librina/logs.h"
#include "librina/tlshand-authp.h"
#include "auth-policies.pb.h"

namespace rina {

//TLSHandAuthOptions encoder and decoder operations
void decode_tls_hand_auth_options(const ser_obj_t &message,
		TLSHandAuthOptions &options)
{
	rina::auth::policies::googleprotobuf::authOptsTLSHandshake_t gpb_options;

	gpb_options.ParseFromArray(message.message_, message.size_);

	for(int i=0; i<gpb_options.cipher_suites_size(); i++) {
		options.cipher_suites.push_back(gpb_options.cipher_suites(i));
	}

	for(int i=0; i<gpb_options.compress_methods_size(); i++) {
		options.compress_methods.push_back(gpb_options.compress_methods(i));
	}

	options.random.utc_unix_time = gpb_options.utc_unix_time();

	if (gpb_options.has_random_bytes()) {
		options.random.random_bytes.data =
				new unsigned char[gpb_options.random_bytes().size()];
		memcpy(options.random.random_bytes.data,
				gpb_options.random_bytes().data(),
				gpb_options.random_bytes().size());
		options.random.random_bytes.length = gpb_options.random_bytes().size();
	}
}

void encode_tls_hand_auth_options(const TLSHandAuthOptions& options,
		ser_obj_t& result)
{
	rina::auth::policies::googleprotobuf::authOptsTLSHandshake_t gpb_options;

	for(std::list<std::string>::const_iterator it = options.cipher_suites.begin();
			it != options.cipher_suites.end(); ++it) {
		gpb_options.add_cipher_suites(*it);
	}

	for(std::list<std::string>::const_iterator it = options.compress_methods.begin();
			it != options.compress_methods.end(); ++it) {
		gpb_options.add_compress_methods(*it);
	}

	gpb_options.set_utc_unix_time(options.random.utc_unix_time);

	if (options.random.random_bytes.length > 0) {
		gpb_options.set_random_bytes(options.random.random_bytes.data,
				options.random.random_bytes.length);
	}

	int size = gpb_options.ByteSize();
	result.message_ = new unsigned char[size];
	result.size_ = size;
	gpb_options.SerializeToArray(result.message_, size);
}

void encode_server_hello_tls_hand(const TLSHandRandom& random,
		const std::string& cipher_suite,
		const std::string& compress_method,
		const std::string& version,
		ser_obj_t& result)
{
	rina::auth::policies::googleprotobuf::serverHelloTLSHandshake_t gpb_hello;

	gpb_hello.set_random_bytes(random.random_bytes.data,
			random.random_bytes.length);
	gpb_hello.set_utc_unix_time(random.utc_unix_time);
	gpb_hello.set_version(version);
	gpb_hello.set_cipher_suite(cipher_suite);
	gpb_hello.set_compress_method(compress_method);

	int size = gpb_hello.ByteSize();
	result.message_ = new unsigned char[size];
	result.size_ = size;
	gpb_hello.SerializeToArray(result.message_ , size);
}



void decode_server_hello_tls_hand(const ser_obj_t &message,
		TLSHandRandom& random,
		std::string& cipher_suite,
		std::string& compress_method,
		std::string& version)
{
	rina::auth::policies::googleprotobuf::serverHelloTLSHandshake_t gpb_hello;

	gpb_hello.ParseFromArray(message.message_, message.size_);

	if (gpb_hello.has_random_bytes()) {
		random.random_bytes.data =
				new unsigned char[gpb_hello.random_bytes().size()];
		memcpy(random.random_bytes.data,
				gpb_hello.random_bytes().data(),
				gpb_hello.random_bytes().size());
		random.random_bytes.length = gpb_hello.random_bytes().size();
	}

	random.utc_unix_time = gpb_hello.utc_unix_time();
	version = gpb_hello.version();
	cipher_suite = gpb_hello.cipher_suite();
	compress_method = gpb_hello.compress_method();
}


//Server certificate
void encode_server_certificate_tls_hand(const UcharArray& certificate_chain,
		ser_obj_t& result)
{
	rina::auth::policies::googleprotobuf::serverCertificateTLSHandshake_t gpb_scertificate;

	gpb_scertificate.set_certificate_chain(certificate_chain.data, certificate_chain.length);

	int size = gpb_scertificate.ByteSize();
	result.message_ = new unsigned char[size];
	result.size_ = size;
	gpb_scertificate.SerializeToArray(result.message_ , size);
}

void decode_server_certificate_tls_hand(const ser_obj_t &message,
		 UcharArray& certificate_chain)
{
	rina::auth::policies::googleprotobuf::serverCertificateTLSHandshake_t gpb_scertificate;

	gpb_scertificate.ParseFromArray(message.message_, message.size_);

	if (gpb_scertificate.has_certificate_chain()) {
		certificate_chain.data =  new unsigned char[gpb_scertificate.certificate_chain().size()];
		memcpy(certificate_chain.data,
				gpb_scertificate.certificate_chain().data(),
				gpb_scertificate.certificate_chain().size());
		certificate_chain.length = gpb_scertificate.certificate_chain().size();
	}
}

//Client certificate
void encode_client_certificate_tls_hand(const UcharArray& certificate_chain,
		ser_obj_t& result)
{
	rina::auth::policies::googleprotobuf::clientCertificateTLSHandshake_t gpb_ccertificate;

	gpb_ccertificate.set_certificate_chain(certificate_chain.data, certificate_chain.length);

	int size = gpb_ccertificate.ByteSize();
	result.message_ = new unsigned char[size];
	result.size_ = size;
	gpb_ccertificate.SerializeToArray(result.message_ , size);
}

void decode_client_certificate_tls_hand(const ser_obj_t &message,
		 UcharArray& certificate_chain)
{
	rina::auth::policies::googleprotobuf::clientCertificateTLSHandshake_t gpb_ccertificate;

	gpb_ccertificate.ParseFromArray(message.message_, message.size_);

	//certificate_chain = gpb_scertificate.certificate_chain().data();
	if (gpb_ccertificate.has_certificate_chain()) {
		certificate_chain.data =  new unsigned char[gpb_ccertificate.certificate_chain().size()];
		memcpy(certificate_chain.data,
				gpb_ccertificate.certificate_chain().data(),
				gpb_ccertificate.certificate_chain().size());
		certificate_chain.length = gpb_ccertificate.certificate_chain().size();
	}
}
//Client key_exchange
void encode_client_key_exchange_tls_hand(const UcharArray& enc_pmaster_secret,
		ser_obj_t& result)
{
	rina::auth::policies::googleprotobuf::clientKeyExchangeTLSHandshake_t gpb_key_exchange;

	gpb_key_exchange.set_enc_pmaster_secret(enc_pmaster_secret.data, enc_pmaster_secret.length);

	int size = gpb_key_exchange.ByteSize();
	result.message_ = new unsigned char[size];
	result.size_ = size;
	gpb_key_exchange.SerializeToArray(result.message_ , size);
}

void decode_client_key_exchange_tls_hand(const ser_obj_t &message,
		 UcharArray& enc_pmaster_secret)
{
	rina::auth::policies::googleprotobuf::clientKeyExchangeTLSHandshake_t gpb_key_exchange;

	gpb_key_exchange.ParseFromArray(message.message_, message.size_);

		if (gpb_key_exchange.has_enc_pmaster_secret()) {
			enc_pmaster_secret.data =  new unsigned char[gpb_key_exchange.enc_pmaster_secret().size()];
			memcpy(enc_pmaster_secret.data,
					gpb_key_exchange.enc_pmaster_secret().data(),
					gpb_key_exchange.enc_pmaster_secret().size());
			enc_pmaster_secret.length = gpb_key_exchange.enc_pmaster_secret().size();
		}
}



// Class TLSHandSecurityContext
const std::string TLSHandSecurityContext::CIPHER_SUITE = "cipherSuite";
const std::string TLSHandSecurityContext::COMPRESSION_METHOD = "compressionMethod";
const std::string TLSHandSecurityContext::KEYSTORE_PATH = "keystore";
const std::string TLSHandSecurityContext::KEYSTORE_PASSWORD = "keystorePass";

//Berta
const std::string TLSHandSecurityContext::CERTIFICATE_PATH = "myCredentials";
const std::string TLSHandSecurityContext::MY_CERTIFICATE = "certificate.pem";
const std::string TLSHandSecurityContext::PRIV_KEY_PATH = "myPrivKey";

TLSHandSecurityContext::~TLSHandSecurityContext()
{
	if (cert) {
		X509_free(cert);
		cert = NULL;
	}
}

CryptoState TLSHandSecurityContext::get_crypto_state(bool enable_crypto_tx,
		bool enable_crypto_rx)
{
	CryptoState result;
	result.enable_crypto_tx = enable_crypto_tx;
	result.enable_crypto_rx = enable_crypto_rx;
	//TODO
	result.port_id = id;

	return result;
}

TLSHandSecurityContext::TLSHandSecurityContext(int session_id,
		const AuthSDUProtectionProfile& profile)
: ISecurityContext(session_id)
{
	cipher_suite = profile.authPolicy.get_param_value_as_string(CIPHER_SUITE);
	compress_method = profile.authPolicy.get_param_value_as_string(COMPRESSION_METHOD);
	keystore_path = profile.authPolicy.get_param_value_as_string(KEYSTORE_PATH);
	if (keystore_path == std::string()) {
		//TODO set the configuration directory as the default keystore path
	}
	keystore_password = profile.authPolicy.get_param_value_as_string(KEYSTORE_PASSWORD);
	crcPolicy = profile.crcPolicy;
	ttlPolicy = profile.ttlPolicy;
	encrypt_policy_config = profile.encryptPolicy;
	con.port_id = session_id;

	//BERTA
	certificate_path = profile.authPolicy.get_param_value_as_string(CERTIFICATE_PATH);
	priv_key_path = profile.authPolicy.get_param_value_as_string(PRIV_KEY_PATH);

	timer_task = NULL;
	state = BEGIN;

	cert = NULL;
	other_cert = NULL;
	cert_received = false;
	hello_received = false;
}

TLSHandSecurityContext::TLSHandSecurityContext(int session_id,
		const AuthSDUProtectionProfile& profile,
		TLSHandAuthOptions * options)
: ISecurityContext(session_id)
{
	std::string option = options->cipher_suites.front();
	if (option != "TODO") {
		LOG_ERR("Unsupported cipher suite: %s",
				option.c_str());
		throw Exception();
	} else {
		cipher_suite = option;
	}

	option = options->compress_methods.front();
	if (option != "TODO") {
		LOG_ERR("Unsupported compression method: %s",
				option.c_str());
		throw Exception();
	} else {
		compress_method = option;
	}

	client_random = options->random;

	//BERTA
	certificate_path = profile.authPolicy.get_param_value_as_string(CERTIFICATE_PATH);
	priv_key_path = profile.authPolicy.get_param_value_as_string(PRIV_KEY_PATH);

	keystore_path = profile.authPolicy.get_param_value_as_string(KEYSTORE_PATH);
	if (keystore_path == std::string()) {
		//TODO set the configuration directory as the default keystore path
	}
	keystore_password = profile.authPolicy.get_param_value_as_string(KEYSTORE_PASSWORD);
	crcPolicy = profile.crcPolicy;
	ttlPolicy = profile.ttlPolicy;
	encrypt_policy_config = profile.encryptPolicy;
	con.port_id = session_id;
	timer_task = NULL;
	cert = NULL;
	other_cert = NULL;
	cert_received = false;
	hello_received = false;

	state = BEGIN;
}

//Class AuthTLSHandPolicySet
const int AuthTLSHandPolicySet::DEFAULT_TIMEOUT = 10000;
const std::string AuthTLSHandPolicySet::SERVER_HELLO = "Server Hello";
const std::string AuthTLSHandPolicySet::SERVER_CERTIFICATE = "Server Certificate";
const std::string AuthTLSHandPolicySet::CLIENT_CERTIFICATE = "Client Certificate";
const std::string AuthTLSHandPolicySet::CLIENT_KEY_EXCHANGE = "Client key exchange";

AuthTLSHandPolicySet::AuthTLSHandPolicySet(rib::RIBDaemonProxy * ribd,
		ISecurityManager * sm) :
				IAuthPolicySet(IAuthPolicySet::AUTH_TLSHAND)
{
	rib_daemon = ribd;
	sec_man = sm;
	timeout = DEFAULT_TIMEOUT;
}

AuthTLSHandPolicySet::~AuthTLSHandPolicySet()
{
}

cdap_rib::auth_policy_t AuthTLSHandPolicySet::get_auth_policy(int session_id,
		const AuthSDUProtectionProfile& profile)
{
	if (profile.authPolicy.name_ != type) {
		LOG_ERR("Wrong policy name: %s, expected: %s",
				profile.authPolicy.name_.c_str(),
				type.c_str());
		throw Exception();
	}

	ScopedLock sc_lock(lock);

	if (sec_man->get_security_context(session_id) != 0) {
		LOG_ERR("A security context already exists for session_id: %d",
				session_id);
		throw Exception();
	}

	LOG_DBG("Initiating authentication for session_id: %d", session_id);
	cdap_rib::auth_policy_t auth_policy;
	auth_policy.name = IAuthPolicySet::AUTH_TLSHAND;
	auth_policy.versions.push_back(profile.authPolicy.version_);

	TLSHandSecurityContext * sc = new TLSHandSecurityContext(session_id,
			profile);
	sc->client_random.utc_unix_time = (unsigned int) time(NULL);
	sc->client_random.random_bytes.data = new unsigned char[28];
	sc->client_random.random_bytes.length = 28;
	if (RAND_bytes(sc->client_random.random_bytes.data,
			sc->client_random.random_bytes.length) == 0) {
		LOG_ERR("Problems generating client random bytes: %s",
				ERR_error_string(ERR_get_error(), NULL));
		delete sc;
		throw Exception();
	}

	TLSHandAuthOptions options;
	options.cipher_suites.push_back(sc->cipher_suite);
	options.compress_methods.push_back(sc->compress_method);
	options.random = sc->client_random;

	encode_tls_hand_auth_options(options, auth_policy.options);

	//Store security context
	sc->state = TLSHandSecurityContext::WAIT_SERVER_HELLO_and_CERTIFICATE;
	sec_man->add_security_context(sc);

	//Initialized verify hash, used in certificate verify message
	sc->verify_hash.data = new unsigned char[32*5];
	sc->verify_hash.length = 32*5;

	//Get auth policy options to obtain first hash message [0,--31]
	unsigned char hash1[SHA256_DIGEST_LENGTH];
	if(!SHA256(auth_policy.options.message_, auth_policy.options.size_, hash1)){
		LOG_ERR("Could not has message");
		throw Exception();
	}
	//prepare verify_hash vector for posterior signing
	memcpy(sc->verify_hash.data, hash1, 32);
	LOG_DBG("verify hash1:" "%d", *sc->verify_hash.data);
	LOG_DBG("verify hash1:" "%s", sc->verify_hash.data);
	//end certificate verify hash


	return auth_policy;
}

IAuthPolicySet::AuthStatus AuthTLSHandPolicySet::initiate_authentication(const cdap_rib::auth_policy_t& auth_policy,
		const AuthSDUProtectionProfile& profile,
		int session_id)
{
	if (auth_policy.name != type) {
		LOG_ERR("Wrong policy name: %s", auth_policy.name.c_str());
		return IAuthPolicySet::FAILED;
	}

	if (auth_policy.versions.front() != RINA_DEFAULT_POLICY_VERSION) {
		LOG_ERR("Unsupported policy version: %s",
				auth_policy.versions.front().c_str());
		return IAuthPolicySet::FAILED;
	}

	ScopedLock sc_lock(lock);

	if (sec_man->get_security_context(session_id) != 0) {
		LOG_ERR("A security context already exists for session_id: %d", session_id);
		return IAuthPolicySet::FAILED;
	}

	LOG_DBG("Initiating authentication for session_id: %d", session_id);
	TLSHandAuthOptions options;
	decode_tls_hand_auth_options(auth_policy.options, options);

	TLSHandSecurityContext * sc;
	try {
		sc = new TLSHandSecurityContext(session_id, profile, &options);
	} catch (Exception &e){
		return IAuthPolicySet::FAILED;
	}

	//Initialized verify hash, used in certificate verify message
	sc->verify_hash.data = new unsigned char[32*5];
	sc->verify_hash.length = 32*5;
	//Get auth policy options to obtain first hash message [0,--31]
	unsigned char hash1[SHA256_DIGEST_LENGTH];
	if(!SHA256(auth_policy.options.message_, auth_policy.options.size_, hash1)){
		LOG_ERR("Coul not hash message");
		return IAuthPolicySet::FAILED;
	}
	//prepare verify_hash vector for posterior signing
	memcpy(sc->verify_hash.data, hash1, 32);
	LOG_DBG("verify hash1:" "%d", *sc->verify_hash.data);
	LOG_DBG("verify hash1:" "%s", sc->verify_hash.data);
	//end certificate verify hash


	//Generate server random
	sc->server_random.utc_unix_time = (unsigned int) time(NULL);
	sc->server_random.random_bytes.data = new unsigned char[28];
	sc->server_random.random_bytes.length = 28;
	if (RAND_bytes(sc->server_random.random_bytes.data,
			sc->server_random.random_bytes.length) == 0) {
		LOG_ERR("Problems generating server random bytes: %s",
				ERR_error_string(ERR_get_error(), NULL));
		delete sc;
		return IAuthPolicySet::FAILED;
	}

	//Send Server Hello
	cdap_rib::obj_info_t obj_info;
	try {
		cdap_rib::flags_t flags;
		cdap_rib::filt_info_t filt;
		//cdap_rib::obj_info_t obj_info;
		cdap::StringEncoder encoder;

		obj_info.class_ = SERVER_HELLO;
		obj_info.name_ = SERVER_HELLO;
		obj_info.inst_ = 0;
		encode_server_hello_tls_hand(sc->server_random,
				sc->cipher_suite,
				sc->compress_method,
				RINA_DEFAULT_POLICY_VERSION,
				obj_info.value_);

		rib_daemon->remote_write(sc->con, obj_info, flags, filt, NULL);

	} catch (Exception &e) {
		LOG_ERR("Problems encoding and sending CDAP message: %s", e.what());
		delete sc;
		return IAuthPolicySet::FAILED;
	}

	//Get auth policy options to obtain second hash message [0,--31]
	unsigned char hash2[SHA256_DIGEST_LENGTH];
	if(!SHA256(obj_info.value_.message_, obj_info.value_.size_, hash2)){
		LOG_DBG("Could not hash message");
		return IAuthPolicySet::FAILED;
	}
	//prepare verify_hash vector for posterior signing
	memcpy(sc->verify_hash.data+32, hash2, 32);
	LOG_DBG("verify hash2:" "%d", *sc->verify_hash.data);
	LOG_DBG("verify hash2:" "%s", sc->verify_hash.data);
	//end certificate verify hash


	load_authentication_certificate(sc);
	//convert x509
	UcharArray encoded_cert;
	encoded_cert.length = i2d_X509(sc->cert, &encoded_cert.data);
	if (encoded_cert.length < 0)
		LOG_ERR("Error converting certificate");

	//Send server certificate
	cdap_rib::obj_info_t obj_info1;
	try {
		cdap_rib::flags_t flags;
		cdap_rib::filt_info_t filt;
		//cdap_rib::obj_info_t obj_info;
		cdap::StringEncoder encoder;

		obj_info1.class_ = SERVER_CERTIFICATE;
		obj_info1.name_ = SERVER_CERTIFICATE;
		obj_info1.inst_ = 0;
		encode_server_certificate_tls_hand(encoded_cert,
				obj_info1.value_);

		rib_daemon->remote_write(sc->con,
				obj_info1,
				flags,
				filt,
				NULL);
	} catch (Exception &e) {
		LOG_ERR("Problems encoding and sending CDAP message: %s",
				e.what());
		delete sc;
		return IAuthPolicySet::FAILED;
	}
	sc->state = TLSHandSecurityContext::WAIT_CLIENT_CERTIFICATE_and_KEYS;
	sec_man->add_security_context(sc);

	//Get auth policy options to obtain third hash message [0,--31]
	unsigned char hash3[SHA256_DIGEST_LENGTH];
	if(!SHA256(obj_info1.value_.message_, obj_info1.value_.size_, hash3)){
		LOG_DBG("Could not hash message");
		return IAuthPolicySet::FAILED;
	}
	//prepare verify_hash vector for posterior signing
	memcpy(sc->verify_hash.data+64, hash3, 32);
	LOG_DBG("verify hash3:" "%d", *sc->verify_hash.data);
	LOG_DBG("verify hash3:" "%s", sc->verify_hash.data);
	//end certificate verify hash

	return IAuthPolicySet::IN_PROGRESS;
}

int AuthTLSHandPolicySet::process_incoming_message(const cdap::CDAPMessage& message,
		int session_id)
{
	if (message.op_code_ != cdap::CDAPMessage::M_WRITE) {
		LOG_ERR("Wrong operation type");
		return IAuthPolicySet::FAILED;
	}

	if (message.obj_class_ == SERVER_HELLO) {
		return process_server_hello_message(message, session_id);
	}
	if (message.obj_class_ == SERVER_CERTIFICATE) {
		return process_server_certificate_message(message, session_id);
	}
	if (message.obj_class_ == CLIENT_CERTIFICATE) {
		LOG_DBG("client CERTIFICATE oj¡bjecte class"); //ESBORRRRRRRRAAAARRR!!!!
		return process_client_certificate_message(message, session_id);
	}
	if (message.obj_class_ == CLIENT_KEY_EXCHANGE) {
		LOG_DBG("client key_echange OOOOBBBBBBBJJJJEEEE class"); //ESBORRRRRRRRAAAARRR!!!!
		return process_client_key_exchange_message(message, session_id);
	}

	return rina::IAuthPolicySet::FAILED;
}

int AuthTLSHandPolicySet::load_authentication_certificate(TLSHandSecurityContext * sc)
{
	BIO * certstore;
	LOG_DBG("Start loading certificate");
	std::stringstream ss;

	ss << sc->certificate_path.c_str() << "/" << TLSHandSecurityContext::MY_CERTIFICATE;

	certstore =  BIO_new_file(ss.str().c_str(),  "r");
	if (!certstore) {
		LOG_ERR("Problems opening certificate file at: %s", ss.str().c_str());
		return -1;
	}
	sc->cert = PEM_read_bio_X509(certstore, NULL, 0, NULL);
	BIO_free(certstore);
	if (!sc->cert) {
		LOG_ERR("Problems reading certificate %s", ERR_error_string(ERR_get_error(), NULL));
		return -1;

	}
	LOG_DBG("end load certificate");
	return 0;
}

int AuthTLSHandPolicySet::calculate_master_secret(TLSHandSecurityContext * sc, UcharArray& pre)
{
	LOG_DBG("calculating ms");
	LOG_DBG("client random: %d", sc->client_random.random_bytes.length);
	LOG_DBG("server random: %d", sc->server_random.random_bytes.length);

	unsigned char aux[14] = "master secret";
	LOG_DBG("aux: %d", aux);

	UcharArray ms;
	ms.length = 14;
	ms.data = new unsigned char[14];

	memcpy(ms.data, aux, ms.length);
	LOG_DBG("ms  %s", ms.data);
	LOG_DBG("ms  %d", &ms.data);


//calcul a0, a1, i a2
	UcharArray seed(ms, sc->client_random.random_bytes, sc->server_random.random_bytes);
	LOG_DBG("seed : %d", seed.length);

	UcharArray a0(32);
	memcpy(a0.data, seed.data, 32);
	LOG_DBG("a0.data: %s", a0.data);

	UcharArray a1(32);
	HMAC(EVP_sha256(),pre.data, pre.length, a0.data, a0.length, a1.data, (unsigned *)(&a1.length));
	if(a1.data == NULL)LOG_ERR("Error calculating master secret");
	LOG_DBG("a1 : %d", a1.data);
	LOG_DBG("a1 length : %d", a1.length);

	UcharArray a2(32);
	HMAC(EVP_sha256(),pre.data, pre.length, a1.data, a1.length, a2.data, (unsigned *)(&a2.length));
	if(a2.data == NULL)LOG_ERR("Error calculating master secret");
	LOG_DBG("a2 : %d", a2.data);
	LOG_DBG("a2 length : %d", a2.length);

//calcul 2 hmac finals de concatenacio
	UcharArray a10(a1,a0);
	UcharArray res1(32);
	HMAC(EVP_sha256(),pre.data, pre.length, a10.data, a10.length, res1.data, (unsigned *)(&res1.length));
	if(res1.data == NULL)LOG_ERR("Error calculating master secret");
	LOG_DBG("res1 : %d", res1.data);
	LOG_DBG("res1 length : %d", res1.length);

	UcharArray a20(a2,a0);
	UcharArray res2(32);
	HMAC(EVP_sha256(),pre.data, pre.length, a20.data, a20.length, res2.data, (unsigned *)(&res2.length));
	if(res2.data == NULL)LOG_ERR("Error calculating master secret");
	LOG_DBG("res2 : %d", res2.data);
	LOG_DBG("res2 length : %d", res2.length);

//fi calculs dos parts del master secret;
	UcharArray aux_master_secret(res1,res2);
	UcharArray master_secret(48);
	memcpy(master_secret.data, aux_master_secret.data, 48);
//borrar debugs
	LOG_DBG("ms length : %d", master_secret.length);
	for (int i=0; i< master_secret.length; i++) {
		LOG_DBG("ms data : %d %d", i, master_secret.data[i]);
	}

	sc->master_secret = master_secret;
	LOG_DBG("fin calculate");

	return 0;

}

int AuthTLSHandPolicySet::process_server_hello_message(const cdap::CDAPMessage& message,
		int session_id)
{
	LOG_DBG("entro a process server hello");
	TLSHandSecurityContext * sc;

	if (message.obj_value_.message_ == 0) {
		LOG_ERR("Null object value");
		return IAuthPolicySet::FAILED;
	}

	sc = dynamic_cast<TLSHandSecurityContext *>(sec_man->get_security_context(session_id));
	if (!sc) {
		LOG_ERR("Could not retrieve Security Context for session: %d", session_id);
		return IAuthPolicySet::FAILED;
	}

	ScopedLock sc_lock(lock);

	if (sc->state != TLSHandSecurityContext::WAIT_SERVER_HELLO_and_CERTIFICATE) {
		LOG_ERR("Wrong session state: %d", sc->state);
		sec_man->remove_security_context(session_id);
		delete sc;
		return IAuthPolicySet::FAILED;
	}

	//TIMER????
	/*sc->timer_task = new CancelAuthTimerTask(sec_man, session_id);
	timer.scheduleTask(sc->timer_task, timeout);*/

	sc->hello_received = true;

	decode_server_hello_tls_hand(message.obj_value_,
			sc->server_random,
			sc->cipher_suite,
			sc->compress_method,
			sc->version);

	//Get auth policy options to obtain third hash message [0,--31]
	unsigned char hash2[SHA256_DIGEST_LENGTH];
	if(!SHA256(message.obj_value_.message_, message.obj_value_.size_, hash2)){
		LOG_DBG("Could not hash message");
		return IAuthPolicySet::FAILED;
	}
	//prepare verify_hash vector for posterior signing
	memcpy(sc->verify_hash.data+32, hash2, 32);
	LOG_DBG("verify hash2:" "%d", *sc->verify_hash.data);
	LOG_DBG("verify hash2:" "%s", sc->verify_hash.data);
	//end certificate verify hash

	//if ha rebut server certificate-< canvi estat , enviar misatges client
	if(sc->cert_received) {
		sc->state = TLSHandSecurityContext::CLIENT_SENDING_DATA;
		LOG_DBG("if process server hello");
		return send_client_messages(sc);

	}
	LOG_DBG("end process server hello");

	return IAuthPolicySet::IN_PROGRESS;
}

int AuthTLSHandPolicySet::process_server_certificate_message(const cdap::CDAPMessage& message,
		int session_id)
{
	LOG_DBG("entro a process server certificate");

	TLSHandSecurityContext * sc;

	if (message.obj_value_.message_ == 0) {
		LOG_ERR("Null object value");
		return IAuthPolicySet::FAILED;
	}

	sc = dynamic_cast<TLSHandSecurityContext *>(sec_man->get_security_context(session_id));
	if (!sc) {
		LOG_ERR("Could not retrieve Security Context for session: %d", session_id);
		return IAuthPolicySet::FAILED;
	}

	ScopedLock sc_lock(lock);

	if (sc->state != TLSHandSecurityContext::WAIT_SERVER_HELLO_and_CERTIFICATE) {
		LOG_ERR("Wrong session state: %d", sc->state);
		sec_man->remove_security_context(session_id);
		delete sc;
		return IAuthPolicySet::FAILED;
	}

	//TIMER????
	/*sc->timer_task = new CancelAuthTimerTask(sec_man, session_id);
	timer.scheduleTask(sc->timer_task, timeout);*/

	sc->cert_received = true;

	UcharArray certificate_chain;
	decode_server_certificate_tls_hand(message.obj_value_,certificate_chain);

	//hash3 to concatenate for verify message
	unsigned char hash3[SHA256_DIGEST_LENGTH];
	if(!SHA256(message.obj_value_.message_, message.obj_value_.size_, hash3)){
		LOG_DBG("Could not hash message");
		return IAuthPolicySet::FAILED;
	}
	//prepare verify_hash vector for posterior signing
	memcpy(sc->verify_hash.data+64, hash3, 32);
	LOG_DBG("verify hash3:" "%d", *sc->verify_hash.data);
	LOG_DBG("verify hash3:" "%s", sc->verify_hash.data);
	//end certificate verify hash

	//transformar cert a x509 i guardar al context
	const unsigned char *aux;
	aux =  reinterpret_cast<const unsigned char*>(certificate_chain.data);
	const unsigned char** pointer;
	pointer = &aux;

	if(pointer ==NULL)
		LOG_ERR("Bad pointer :(");
	sc->other_cert = d2i_X509(NULL, pointer, certificate_chain.length);
	if(sc->other_cert  == NULL)
		LOG_ERR("Bad conversion to x509 :(");

	//if ha rebut server certificate-< canvi estat , enviar misatges client
	if(sc->hello_received) {
		sc->state = TLSHandSecurityContext::CLIENT_SENDING_DATA;
		LOG_DBG("if process server certificate");
		return send_client_messages(sc);
	}
	LOG_DBG("end process server certificate");
	return IAuthPolicySet::IN_PROGRESS;
}

int AuthTLSHandPolicySet::process_client_certificate_message(const cdap::CDAPMessage& message,
		int session_id)
{
	LOG_DBG("entro a process client certificate");

	TLSHandSecurityContext * sc;

	if (message.obj_value_.message_ == 0) {
		LOG_ERR("Null object value");
		return IAuthPolicySet::FAILED;
	}

	sc = dynamic_cast<TLSHandSecurityContext *>(sec_man->get_security_context(session_id));
	if (!sc) {
		LOG_ERR("Could not retrieve Security Context for session: %d", session_id);
		return IAuthPolicySet::FAILED;
	}

	ScopedLock sc_lock(lock);

	if (sc->state != TLSHandSecurityContext::WAIT_CLIENT_CERTIFICATE_and_KEYS) {
		LOG_ERR("Wrong session state: %d", sc->state);
		sec_man->remove_security_context(session_id);
		delete sc;
		return IAuthPolicySet::FAILED;
	}

	//TIMER????
	/*sc->timer_task = new CancelAuthTimerTask(sec_man, session_id);
		timer.scheduleTask(sc->timer_task, timeout);*/

	UcharArray certificate_chain;
	decode_client_certificate_tls_hand(message.obj_value_,certificate_chain);////canviar!!

	//preparation for certificate verify message
	unsigned char hash4[SHA256_DIGEST_LENGTH];
	if(!SHA256(message.obj_value_.message_, message.obj_value_.size_, hash4)){
		LOG_DBG("Could not hash message");
		return IAuthPolicySet::FAILED;
	}
	//prepare verify_hash vector for posterior signing
	memcpy(sc->verify_hash.data+96, hash4, 32);
	LOG_DBG("verify hash4:" "%d", *sc->verify_hash.data);
	LOG_DBG("verify hash4:" "%s", sc->verify_hash.data);
	//end certificate verify hash


	//transformar cert a x509 i guardar al context
	const unsigned char *aux;
	aux =  reinterpret_cast<const unsigned char*>(certificate_chain.data);
	const unsigned char** pointer;
	pointer = &aux;

	if(pointer ==NULL)
		LOG_ERR("Bad pointer :(");
	sc->other_cert = d2i_X509(NULL, pointer, certificate_chain.length);
	if(sc->other_cert  == NULL)
		LOG_ERR("Bad conversion to x509 :(");


	LOG_DBG("end process client certificate");

	return IAuthPolicySet::IN_PROGRESS;

}
int AuthTLSHandPolicySet::process_client_key_exchange_message(const cdap::CDAPMessage& message,
		int session_id)
{
	LOG_DBG("ini server decoding client keys");

	TLSHandSecurityContext * sc;

	if (message.obj_value_.message_ == 0) {
		LOG_ERR("Null object value");
		return IAuthPolicySet::FAILED;
	}

	sc = dynamic_cast<TLSHandSecurityContext *>(sec_man->get_security_context(session_id));
	if (!sc) {
		LOG_ERR("Could not retrieve Security Context for session: %d", session_id);
		return IAuthPolicySet::FAILED;
	}

	ScopedLock sc_lock(lock);

	if (sc->state != TLSHandSecurityContext::WAIT_CLIENT_CERTIFICATE_and_KEYS) {
		LOG_ERR("Wrong session state: %d", sc->state);
		sec_man->remove_security_context(session_id);
		delete sc;
		return IAuthPolicySet::FAILED;
	}

	//TIMER????
	/*sc->timer_task = new CancelAuthTimerTask(sec_man, session_id);
		timer.scheduleTask(sc->timer_task, timeout);*/


	UcharArray enc_pre_master_secret;
	decode_client_key_exchange_tls_hand(message.obj_value_, enc_pre_master_secret);

	//preparation for certificate verify message
	unsigned char hash5[SHA256_DIGEST_LENGTH];
	if(!SHA256(message.obj_value_.message_, message.obj_value_.size_, hash5)){
		LOG_DBG("Could not hash message");
		return IAuthPolicySet::FAILED;
	}
	//prepare verify_hash vector for posterior signing
	memcpy(sc->verify_hash.data+128, hash5, 32);
	LOG_DBG("verify hash5:" "%d", *sc->verify_hash.data);
	LOG_DBG("verify hash5:" "%s", sc->verify_hash.data);
	//end certificate verify hash

	EVP_PKEY *privkey = NULL;
	RSA *rsakey;
	BIO *key;

	key =  BIO_new_file(sc->priv_key_path.c_str(), "r");
	if (!key) {
		LOG_ERR("Problems opening key file at: %s",sc->priv_key_path.c_str());
		return -1;
	}

	privkey = PEM_read_bio_PrivateKey(key, NULL, 0, NULL);
	BIO_free(key);

	if (!privkey) {
		LOG_ERR("Problems reading  key",ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	rsakey = EVP_PKEY_get1_RSA(privkey);
	if(rsakey == NULL)
		LOG_ERR("EVP_PKEY_get1_RSA: failed.");

	UcharArray dec_pre_master_secret;
	dec_pre_master_secret.data = new unsigned char[256];

	LOG_DBG("encrypted pre_master_secret.data:" "%d", enc_pre_master_secret.data);

	if((dec_pre_master_secret.length =  RSA_private_decrypt(enc_pre_master_secret.length,
								enc_pre_master_secret.data,
								dec_pre_master_secret.data,
								rsakey,
								RSA_PKCS1_OAEP_PADDING)) == -1){
		LOG_ERR("Error decrypting pre-master secret");
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), NULL);
	}

	//EVP_PKEY_free(privkey); //necesrai?
	LOG_DBG("pre_master_secret.length:" "%d", dec_pre_master_secret.length);
	LOG_DBG("decrypted pre_master_secret.data:" "%d", *dec_pre_master_secret.data);
	LOG_DBG("decrypted pre_master_secret.data:" "%s", dec_pre_master_secret.data);


	//start computing MASTERSECRET
	calculate_master_secret(sc, dec_pre_master_secret);

	LOG_DBG("return from calculate ms");

	return IAuthPolicySet::IN_PROGRESS;

}

int AuthTLSHandPolicySet::send_client_certificate(TLSHandSecurityContext * sc)
{

	load_authentication_certificate(sc);
	//convert x509
	UcharArray encoded_cert;
	encoded_cert.length = i2d_X509(sc->cert, &encoded_cert.data);
	if (encoded_cert.length < 0)
		LOG_ERR("Error converting certificate");

	//Send client certificate
	cdap_rib::obj_info_t obj_info;
	try {
		cdap_rib::flags_t flags;
		cdap_rib::filt_info_t filt;
		//cdap_rib::obj_info_t obj_info;
		cdap::StringEncoder encoder;

		obj_info.class_ = CLIENT_CERTIFICATE;
		obj_info.name_ = CLIENT_CERTIFICATE;
		obj_info.inst_ = 0;
		encode_client_certificate_tls_hand(encoded_cert,
				obj_info.value_);

		rib_daemon->remote_write(sc->con,
				obj_info,
				flags,
				filt,
				NULL);
	} catch (Exception &e) {
		LOG_ERR("Problems encoding and sending CDAP message: %s",
				e.what());
		sec_man->destroy_security_context(sc->id);
		return IAuthPolicySet::FAILED;
	}

	//compute hash for certificate verify message
	unsigned char hash4[SHA256_DIGEST_LENGTH];
	if(!SHA256(obj_info.value_.message_, obj_info.value_.size_, hash4)){
		LOG_DBG("Could not hash message");
		return IAuthPolicySet::FAILED;
	}
	//prepare verify_hash vector for posterior signing
	memcpy(sc->verify_hash.data+96, hash4, 32);
	LOG_DBG("verify hash4:" "%d", *sc->verify_hash.data);
	LOG_DBG("verify hash4:" "%s", sc->verify_hash.data);
	//end certificate verify hash


	//sc->state = TLSHandSecurityContext::CLIENT_SENDING_DATA; //canviar a un de nou o no cal???
	return IAuthPolicySet::IN_PROGRESS;

}
int AuthTLSHandPolicySet::send_client_key_exchange(TLSHandSecurityContext * sc)
{

	LOG_DBG("enter to client key exchange");
	//generar 48bytes rand, extreure pubkey, rsa_encrypt i enviar!

	UcharArray pre_master_secret, enc_pre_master_secret;
	pre_master_secret.data = new unsigned char[48];
	pre_master_secret.length = 48;

	EVP_PKEY *pubkey = NULL;
	RSA *rsa_pubkey = NULL;

	if(RAND_bytes(pre_master_secret.data, pre_master_secret.length) != 1)
		LOG_ERR("Problems generating random bytes");

	//printar el random
	LOG_DBG("pre_master_secret.data:");
	LOG_DBG("pre_master_secret.data:" "%d", *pre_master_secret.data);
	LOG_DBG("pre_master_secret.data:" "%s \n", pre_master_secret.data);

	if(sc->other_cert == NULL)LOG_ERR("other cert mal guardat"); //aquesta comprovacio no cal, nomes es prova

	//extreurepubkey
	if ((pubkey = X509_get_pubkey(sc->other_cert)) == NULL)
		LOG_ERR("Error getting public key from certificate %s",
				ERR_error_string(ERR_get_error(), NULL));

	rsa_pubkey = EVP_PKEY_get1_RSA(pubkey);

	if(rsa_pubkey == NULL)
		LOG_ERR("EVP_PKEY_get1_RSA: failed. %s",
				ERR_error_string(ERR_get_error(), NULL));

	enc_pre_master_secret.data = new unsigned char[RSA_size(rsa_pubkey)];

	if((enc_pre_master_secret.length = RSA_public_encrypt(pre_master_secret.length,
								pre_master_secret.data,
								enc_pre_master_secret.data,
								rsa_pubkey,
								RSA_PKCS1_OAEP_PADDING)) == -1){
		LOG_ERR("Error encrypting pre-master secret");
		LOG_ERR("Error encrypting challenge with RSA public key: %s", ERR_error_string(ERR_get_error(), NULL));
		//return -1;
	}

	LOG_DBG("After encryting en_pre_master length %d" , enc_pre_master_secret.length);
	LOG_DBG("enc_pre_master_secret.data:" "%d", enc_pre_master_secret.data);

	//es necessari??? free pkey
	/*EVP_PKEY_free(pubkey);
	RSA_free(rsa_pubkey);*/

	//Send client key exchange
	cdap_rib::obj_info_t obj_info;
	try {
		cdap_rib::flags_t flags;
		cdap_rib::filt_info_t filt;
		//cdap_rib::obj_info_t obj_info;
		cdap::StringEncoder encoder;

		obj_info.class_ = CLIENT_KEY_EXCHANGE;
		obj_info.name_ = CLIENT_KEY_EXCHANGE;
		obj_info.inst_ = 0;
		encode_client_key_exchange_tls_hand(enc_pre_master_secret,
				obj_info.value_);

		rib_daemon->remote_write(sc->con,
				obj_info,
				flags,
				filt,
				NULL);
	} catch (Exception &e) {
		LOG_ERR("Problems encoding and sending CDAP message: %s",e.what());
		sec_man->destroy_security_context(sc->id);
		return IAuthPolicySet::FAILED;
	}

	//preparation for certificate verify message
	unsigned char hash5[SHA256_DIGEST_LENGTH];
	if(!SHA256(obj_info.value_.message_, obj_info.value_.size_, hash5)){
		LOG_DBG("Could not hash message");
		return IAuthPolicySet::FAILED;
	}
	//prepare verify_hash vector for posterior signing
	memcpy(sc->verify_hash.data+128, hash5, 32);
	LOG_DBG("verify hash5:" "%d", *sc->verify_hash.data);
	LOG_DBG("verify hash5:" "%s", sc->verify_hash.data);
	//end certificate verify hash


	//sc->state = TLSHandSecurityContext::CLIENT_SENDING_DATA; //canviar a un de nou o no cal???
	LOG_DBG("fi client key exchange");

	calculate_master_secret(sc, pre_master_secret);
	LOG_DBG("fi calc ms client");

	return IAuthPolicySet::IN_PROGRESS;
}

int AuthTLSHandPolicySet::send_client_messages(TLSHandSecurityContext * sc)
{
	//canviar estat, a wait el que sigui i fer tres funcions que cfacin dels tres misatges corresponents
	LOG_DBG("process_client_3messages FUNCTION");

	if (sc->state != TLSHandSecurityContext::CLIENT_SENDING_DATA) {
		LOG_ERR("Wrong state of policy");
		sec_man->destroy_security_context(sc->id);
		return IAuthPolicySet::FAILED;
	}

	//Send first message corresponding to the client_certificate
	send_client_certificate(sc);

	LOG_DBG("before calling send client_key exchange");
	//Send second message corresponding to client_key_exchange
	send_client_key_exchange(sc);
	LOG_DBG("after calling send client_key exchange");

	return IAuthPolicySet::IN_PROGRESS;
}

int AuthTLSHandPolicySet::set_policy_set_param(const std::string& name,
		const std::string& value)
{
	LOG_DBG("No policy-set-specific parameters to set (%s, %s)",
			name.c_str(), value.c_str());
	return -1;
}

IAuthPolicySet::AuthStatus AuthTLSHandPolicySet::crypto_state_updated(int port_id)
{
	TLSHandSecurityContext * sc;

	ScopedLock sc_lock(lock);

	sc = dynamic_cast<TLSHandSecurityContext *>(sec_man->get_security_context(port_id));
	if (!sc) {
		LOG_ERR("Could not retrieve TLS Handshake security context for port-id: %d",
				port_id);
		return IAuthPolicySet::FAILED;
	}

	//TODO
	return IAuthPolicySet::FAILED;
}

}
