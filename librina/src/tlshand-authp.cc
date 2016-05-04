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

//Client certificate verify
void encode_client_certificate_verify_tls_hand(const UcharArray& enc_verify_hash,
		ser_obj_t& result)
{
	rina::auth::policies::googleprotobuf::clientCertificateVerifyTLSHandshake_t gpb_cert_verify;

	gpb_cert_verify.set_enc_verify_hash(enc_verify_hash.data, enc_verify_hash.length);

	int size = gpb_cert_verify.ByteSize();
	result.message_ = new unsigned char[size];
	result.size_ = size;
	gpb_cert_verify.SerializeToArray(result.message_ , size);
}
void decode_client_certificate_verify_tls_hand(const ser_obj_t &message,
		 UcharArray& enc_verify_hash)
{
	rina::auth::policies::googleprotobuf::clientCertificateVerifyTLSHandshake_t gpb_cert_verify;

	gpb_cert_verify.ParseFromArray(message.message_, message.size_);

		if (gpb_cert_verify.has_enc_verify_hash()) {
			enc_verify_hash.data =  new unsigned char[gpb_cert_verify.enc_verify_hash().size()];
			memcpy(enc_verify_hash.data,
					gpb_cert_verify.enc_verify_hash().data(),
					gpb_cert_verify.enc_verify_hash().size());
			enc_verify_hash.length = gpb_cert_verify.enc_verify_hash().size();
		}
}

//Finish messages
void encode_finish_message_tls_hand(const UcharArray& opaque_verify_data,
		ser_obj_t& result)
{
	rina::auth::policies::googleprotobuf::FinishMessageTLSHandshake_t gpb_finish;

	gpb_finish.set_opaque_verify_data(opaque_verify_data.data, opaque_verify_data.length);

	int size = gpb_finish.ByteSize();
	result.message_ = new unsigned char[size];
	result.size_ = size;
	gpb_finish.SerializeToArray(result.message_ , size);
}
void decode_finsih_message_tls_hand(const ser_obj_t &message,
		UcharArray& opaque_verify_data)
{
	rina::auth::policies::googleprotobuf::FinishMessageTLSHandshake_t gpb_finish;

	gpb_finish.ParseFromArray(message.message_, message.size_);

	if (gpb_finish.has_opaque_verify_data()) {
		opaque_verify_data.data =  new unsigned char[gpb_finish.opaque_verify_data().size()];
		memcpy(opaque_verify_data.data,
				gpb_finish.opaque_verify_data().data(),
				gpb_finish.opaque_verify_data().size());
		opaque_verify_data.length = gpb_finish.opaque_verify_data().size();
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
	client_cert_received = false;
	client_keys_received = false;
	client_cert_verify_received = false;
	client_cipher_received = false;
	master_secret.length = 48;
	master_secret.data = new unsigned char[48];
	verify_data.length = 12;
	verify_data.data = new unsigned char[12];
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
	client_cert_received = false;
	client_keys_received = false;
	client_cert_verify_received = false;
	client_cipher_received = false;
	master_secret.length = 48;
	master_secret.data = new unsigned char[48];
	verify_data.length = 12;
	verify_data.data = new unsigned char[12];


	state = BEGIN;
}

//Class AuthTLSHandPolicySet
const int AuthTLSHandPolicySet::DEFAULT_TIMEOUT = 10000;
const std::string AuthTLSHandPolicySet::SERVER_HELLO = "Server Hello";
const std::string AuthTLSHandPolicySet::SERVER_CERTIFICATE = "Server Certificate";
const std::string AuthTLSHandPolicySet::CLIENT_CERTIFICATE = "Client Certificate";
const std::string AuthTLSHandPolicySet::CLIENT_KEY_EXCHANGE = "Client key exchange";
const std::string AuthTLSHandPolicySet::CLIENT_CERTIFICATE_VERIFY = "Client certificate verify";
const std::string AuthTLSHandPolicySet::CLIENT_CHANGE_CIPHER_SPEC = "Client change cipher spec";
const std::string AuthTLSHandPolicySet::SERVER_CHANGE_CIPHER_SPEC = "Server change cipher spec";
const std::string AuthTLSHandPolicySet::CLIENT_FINISH = "Client finish";
const std::string AuthTLSHandPolicySet::SERVER_FINISH = "Server finish";



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
	if (message.obj_class_ == CLIENT_CERTIFICATE_VERIFY) {
		LOG_DBG("client process verify OOOOBBBBBBBJJJJEEEE class"); //ESBORRRRRRRRAAAARRR!!!!
		return process_client_certificate_verify_message(message, session_id);
	}
	if (message.obj_class_ == CLIENT_CHANGE_CIPHER_SPEC) {
		LOG_DBG("server process client cipher OOOOBBBBBBBJJJJEEEE class"); //ESBORRRRRRRRAAAARRR!!!!
		return process_client_change_cipher_spec_message(message, session_id);
	}
	if (message.obj_class_ == SERVER_CHANGE_CIPHER_SPEC) {
		LOG_DBG("client process server cipher OOOOBBBBBBBJJJJEEEE class"); //ESBORRRRRRRRAAAARRR!!!!
		return process_server_change_cipher_spec_message(message, session_id);
	}
	if (message.obj_class_ == CLIENT_FINISH) {
		LOG_DBG("client process server cipher OOOOBBBBBBBJJJJEEEE class"); //ESBORRRRRRRRAAAARRR!!!!
		return process_client_finish_message(message, session_id);
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

int AuthTLSHandPolicySet::prf(UcharArray& generated_hash, UcharArray& secret,  const std::string& slabel, UcharArray& pre_seed)
{
	//convert label to UcharArray
	UcharArray label(slabel.length());
	memcpy(label.data, slabel.c_str(), slabel.length());

	//compute how many times we need to hask a(i)
	int it = (generated_hash.length/32);
	if (generated_hash.length%32 != 0)  it+=1;

	std::vector<UcharArray> vec(it+1);
	std::vector<UcharArray> vres(it+1);

	//calculate seed, v(0) = seed;
	UcharArray seed(label, pre_seed);
	LOG_DBG("seed data  %d", seed.data);
	vec[0].length=32;
	vec[0].data = new unsigned char[32];
	memcpy(vec[0].data, seed.data, seed.length);

	//compute a[i], for determined length and second hmac call
	for(int i = 1; i <= it; ++i){
		vec[i].length = 32;
		vec[i].data = new unsigned char[32];
		HMAC(EVP_sha256(),secret.data, secret.length, vec[i-1].data, vec[i-1].length, vec[i].data, (unsigned *)(&vec[i].length));
		if(vec[i].data == NULL)LOG_ERR("Error calculating master secret");

		UcharArray X0(vec[i], vec[0]);
		vres[i].length = 32;
		vres[i].data = new unsigned char[32];
		LOG_DBG("second hmac\n");
		HMAC(EVP_sha256(),secret.data, secret.length, X0.data, X0.length, vres[i].data, (unsigned *)(&vres[i].length));
		if(vres[i].data == NULL)LOG_ERR("Error calculating master secret");
	}
	UcharArray con(it*32);
	if(it == 1) memcpy(generated_hash.data, vres[1].data, generated_hash.length);
	//repassar!!!
	else {
		for(int i = 1; i <= it-1; ++i){
			UcharArray concatenate(vres[i], vres[i+1]);
			memcpy(con.data+((i-1)*concatenate.length), concatenate.data, concatenate.length);
			LOG_DBG("segon loop%",i);

		}
		memcpy(generated_hash.data, con.data, generated_hash.length);
	}
	//borrar debugs
	LOG_DBG("ms length : %d", generated_hash.length);
	for (int i=0; i< generated_hash.length; i++) {
		LOG_DBG("ms data : %d %d", i, generated_hash.data[i]);
	}
	return 0;

}

/*int AuthTLSHandPolicySet::calculate_master_secret(TLSHandSecurityContext * sc, UcharArray& pre)
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
*/

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

	sc->client_cert_received = true;

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

	//when client message received send server change cipher spec
	if(sc->client_keys_received and sc->client_cert_verify_received and sc->client_cipher_received){
		sc->state = TLSHandSecurityContext::SERVER_SENDING_CIPHER;
		return send_server_change_cipher_spec(sc);
	}
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
	sc->client_keys_received = true;

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
	//calculate_master_secret(sc, dec_pre_master_secret);
	std::string slabel = "master secret";
	LOG_DBG("slable: %d", &slabel);
	LOG_DBG("slable len: %d", slabel.length());

	UcharArray pre_seed(sc->client_random.random_bytes, sc->server_random.random_bytes);

	LOG_DBG("pre seed:" "%d", *pre_seed.data);
	prf(sc->master_secret,dec_pre_master_secret, slabel, pre_seed);


	LOG_DBG("return from calculate ms");

	if(sc->client_cert_received and sc->client_cert_verify_received and sc->client_cipher_received){
		sc->state = TLSHandSecurityContext::SERVER_SENDING_CIPHER;
		return send_server_change_cipher_spec(sc);
	}

	return IAuthPolicySet::IN_PROGRESS;

}

int AuthTLSHandPolicySet::process_client_certificate_verify_message(const cdap::CDAPMessage& message,
		int session_id)
{
	LOG_DBG("ini server decoding client certificate verify");

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


	UcharArray enc_verify_hash;	//Quin size ha de tenir? :/
	decode_client_certificate_verify_tls_hand(message.obj_value_, enc_verify_hash);
	sc->client_cert_verify_received = true;

	UcharArray dec_verify_hash;
	EVP_PKEY *pubkey = NULL;
	RSA *rsa_pubkey = NULL;

	if ((pubkey = X509_get_pubkey(sc->other_cert)) == NULL)
		LOG_ERR("Error getting public key from certificate %s",
				ERR_error_string(ERR_get_error(), NULL));

	rsa_pubkey = EVP_PKEY_get1_RSA(pubkey);

	if(rsa_pubkey == NULL)
		LOG_ERR("EVP_PKEY_get1_RSA: failed. %s",
				ERR_error_string(ERR_get_error(), NULL));

	dec_verify_hash.data = new unsigned char[RSA_size(rsa_pubkey)];

	if((dec_verify_hash.length = RSA_public_decrypt(enc_verify_hash.length,
			enc_verify_hash.data,
			dec_verify_hash.data,
			rsa_pubkey,
			RSA_PKCS1_PADDING)) == -1){
		LOG_ERR("Error decrypting certificate verify");
		LOG_ERR("Error decrypting certificate verify with RSA public key: %s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	//Compare calculated hash with received decrypted hash, should be the same if ok auth
	if (dec_verify_hash != sc->verify_hash) {
		LOG_ERR("Error authenticating server. Decrypted Hashed cv: %s, cv: %s",
				dec_verify_hash.toString().c_str(),
				sc->verify_hash.toString().c_str());
		return -1;
	}
	LOG_DBG("Authenticating server. Decrypted Hashed cv: %s, calculated cv: %s",
			dec_verify_hash.toString().c_str(),
			sc->verify_hash.toString().c_str());

	LOG_DBG("fi process client verify");

	if(sc->client_keys_received and sc->client_cert_received and sc->client_cipher_received){
		sc->state = TLSHandSecurityContext::SERVER_SENDING_CIPHER;
		return send_server_change_cipher_spec(sc);
	}

	return IAuthPolicySet::IN_PROGRESS;
}

int AuthTLSHandPolicySet::process_client_change_cipher_spec_message(const cdap::CDAPMessage& message,
		int session_id)
{
	TLSHandSecurityContext * sc;
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

	//TODO
	/*Server has received client change cipher spec,
	 * it needs to configure receive before sending its cipher
	 */

	sc->client_cipher_received = true;
	if(sc->client_keys_received and sc->client_cert_received and sc->client_cert_verify_received){
		sc->state = TLSHandSecurityContext::SERVER_SENDING_CIPHER;
		return send_server_change_cipher_spec(sc);
	}
	return IAuthPolicySet::IN_PROGRESS;
}

int AuthTLSHandPolicySet::process_server_change_cipher_spec_message(const cdap::CDAPMessage& message,
		int session_id)
{
	TLSHandSecurityContext * sc;
	sc = dynamic_cast<TLSHandSecurityContext *>(sec_man->get_security_context(session_id));
	if (!sc) {
		LOG_ERR("Could not retrieve Security Context for session: %d", session_id);
		return IAuthPolicySet::FAILED;
	}
	ScopedLock sc_lock(lock);

	if (sc->state != TLSHandSecurityContext::WAIT_SERVER_CIPHER) {
		LOG_ERR("Wrong session state: %d", sc->state);
		sec_man->remove_security_context(session_id);
		delete sc;
		return IAuthPolicySet::FAILED;
	}

	//TODO
	/*Client needs to configure receive (kernel) before sending its cipher
	 * join with record module
	 */


	sc->state = TLSHandSecurityContext::WAIT_SERVER_FINISH;
	return send_client_finish(sc);
}

int AuthTLSHandPolicySet::process_client_finish_message(const cdap::CDAPMessage& message,
		int session_id)
{
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

	if (sc->state != TLSHandSecurityContext::SERVER_SENDING_CIPHER) {
		LOG_ERR("Wrong session state: %d", sc->state);
		sec_man->remove_security_context(session_id);
		delete sc;
		return IAuthPolicySet::FAILED;
	}


	UcharArray client_finish;
	decode_finsih_message_tls_hand(message.obj_value_,client_finish);
	/*que es fa quan es rep un finish?????
	 * s'envia l'alte finish i que?
	 */

	std::string slabel ="finish label";
	prf(sc->verify_data,sc->master_secret, slabel, sc->verify_hash);

	//Send server finish message
	try {
		cdap_rib::flags_t flags;
		cdap_rib::filt_info_t filt;
		cdap_rib::obj_info_t obj_info;
		cdap::StringEncoder encoder;

		obj_info.class_ = SERVER_FINISH;
		obj_info.name_ = SERVER_FINISH;
		obj_info.inst_ = 0;
		encode_finish_message_tls_hand(sc->verify_data,
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

	sc->state = TLSHandSecurityContext::SERVER_SENDING_FINISH;
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

	//calculate_master_secret(sc, pre_master_secret);
	std::string slabel = "master secret";
	LOG_DBG("slable: %d", &slabel);
	LOG_DBG("slable len: %d", slabel.length());

	UcharArray pre_seed(sc->client_random.random_bytes, sc->server_random.random_bytes);
	LOG_DBG("pre seed:" "%d", *pre_seed.data);
	prf(sc->master_secret,pre_master_secret, slabel, pre_seed);

	LOG_DBG("fi calc ms client");

	return IAuthPolicySet::IN_PROGRESS;
}

int AuthTLSHandPolicySet::send_client_certificate_verify(TLSHandSecurityContext * sc)
{

	RSA *rsa_priv_key;
	BIO *key;

	key =  BIO_new_file(sc->priv_key_path.c_str(), "r");
	if (!key) {
		LOG_ERR("Problems opening key file at: %s",sc->priv_key_path.c_str());
		return -1;
	}
	rsa_priv_key = PEM_read_bio_RSAPrivateKey(key, NULL, 0, NULL);
	BIO_free(key);

	if (!rsa_priv_key) {
		LOG_ERR("Problems reading  key",ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	//encrypt the hash of all mesages with private rsa key IPCP A
	UcharArray enc_cert_verify(256);
	if((enc_cert_verify.length = RSA_private_encrypt(sc->verify_hash.length,
							sc->verify_hash.data,
							enc_cert_verify.data,
							rsa_priv_key,
							RSA_PKCS1_PADDING)) == -1){
		LOG_ERR("Error encrypting certificate verify hash");
		LOG_ERR("Error encrypting certificate verify hash with private key: %s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	LOG_DBG("After encryting cert verify length %d" , enc_cert_verify.length);

	//Send client key exchange
	try {
		cdap_rib::flags_t flags;
		cdap_rib::filt_info_t filt;
		cdap_rib::obj_info_t obj_info;
		cdap::StringEncoder encoder;

		obj_info.class_ = CLIENT_CERTIFICATE_VERIFY;
		obj_info.name_ = CLIENT_CERTIFICATE_VERIFY;
		obj_info.inst_ = 0;
		encode_client_certificate_verify_tls_hand(enc_cert_verify,
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
	return 0;

}
int AuthTLSHandPolicySet::send_client_change_cipher_spec(TLSHandSecurityContext * sc)
{
	//TODO
	/*record protocol configure send kernel
	 *
	 */
	try {
		cdap_rib::flags_t flags;
		cdap_rib::filt_info_t filt;
		cdap_rib::obj_info_t obj_info;
		cdap::StringEncoder encoder;

		obj_info.class_ = CLIENT_CHANGE_CIPHER_SPEC;
		obj_info.name_ = CLIENT_CHANGE_CIPHER_SPEC;
		obj_info.inst_ = 0;
		obj_info.value_.size_ = 1;
		obj_info.value_.message_ = new unsigned char[1];

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
	return 0;
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

	send_client_certificate_verify(sc);
	LOG_DBG("after calling send client certificate verify");

	send_client_change_cipher_spec(sc);

	sc->state = TLSHandSecurityContext::WAIT_SERVER_CIPHER;

	return IAuthPolicySet::IN_PROGRESS;
}

int AuthTLSHandPolicySet::send_server_change_cipher_spec(TLSHandSecurityContext * sc)
{
	//rebre i actualitzar el record de rebre a d'anar al kernel i etc
	if (sc->state != TLSHandSecurityContext::SERVER_SENDING_CIPHER) {
		LOG_ERR("Wrong state of policy");
		sec_man->destroy_security_context(sc->id);
		return IAuthPolicySet::FAILED;
	}

	//TODO
	/*configure send channel (record protocol)
	 *
	 */

	//Send server change cipher spec
	try {
		cdap_rib::flags_t flags;
		cdap_rib::filt_info_t filt;
		cdap_rib::obj_info_t obj_info;
		cdap::StringEncoder encoder;

		obj_info.class_ = SERVER_CHANGE_CIPHER_SPEC;
		obj_info.name_ = SERVER_CHANGE_CIPHER_SPEC;
		obj_info.inst_ = 0;
		obj_info.value_.size_ = 1;
		obj_info.value_.message_ = new unsigned char[1];

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
	return 0;
}

int AuthTLSHandPolicySet::send_client_finish(TLSHandSecurityContext * sc)
{
	if (sc->state != TLSHandSecurityContext::WAIT_SERVER_CIPHER) {
		LOG_ERR("Wrong state of policy");
		sec_man->destroy_security_context(sc->id);
		return IAuthPolicySet::FAILED;
	}

	std::string slabel ="finish label";
	prf(sc->verify_data,sc->master_secret, slabel, sc->verify_hash);

	//Send client finish message
	try {
		cdap_rib::flags_t flags;
		cdap_rib::filt_info_t filt;
		cdap_rib::obj_info_t obj_info;
		cdap::StringEncoder encoder;

		obj_info.class_ = CLIENT_FINISH;
		obj_info.name_ = CLIENT_FINISH;
		obj_info.inst_ = 0;
		encode_finish_message_tls_hand(sc->verify_data,
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

	sc->state = TLSHandSecurityContext::WAIT_SERVER_FINISH;
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
