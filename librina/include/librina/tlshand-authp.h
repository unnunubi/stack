/*
 * Authentication policy based on the TLS Handshake protocol
 *
 *    Eduard Grasa          <eduard.grasa@i2cat.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301  USA
 */

#ifndef LIBRINA_TLS_HANDSHAKE_H
#define LIBRINA_TLS_HANDSHAKE_H

#ifdef __cplusplus

#include "librina/security-manager.h"

namespace rina {

class TLSHandRandom {
public:
	TLSHandRandom() : utc_unix_time(0) {}

	~TLSHandRandom() { };

	// The current date and time in standard UNIX 32-bits format
	unsigned int utc_unix_time;

	/// 28 bytes generated by a secure random number generator
	UcharArray random_bytes;
};

/// Options that the TLS Handshake authentication policy has to negotiate with its peer
class TLSHandAuthOptions {
public:
	TLSHandAuthOptions() { };
	~TLSHandAuthOptions() { };

	TLSHandRandom random;

	/// Supported cipher suites, sorted by order of preference
	std::list<std::string> cipher_suites;

	/// Supported compression methods, sorted by order of preference
	std::list<std::string> compress_methods;
};

///Captures all data of the TLS HAndshake security context
class TLSHandSecurityContext : public ISecurityContext {
public:
	TLSHandSecurityContext(int session_id) : ISecurityContext(session_id),
			state(BEGIN), timer_task(NULL) { };
	TLSHandSecurityContext(int session_id, const AuthSDUProtectionProfile& profile);
	TLSHandSecurityContext(int session_id,
			       const AuthSDUProtectionProfile& profile,
			       TLSHandAuthOptions * options);
	~TLSHandSecurityContext();
	CryptoState get_crypto_state(bool enable_crypto_tx,
				     bool enable_crypto_rx);

	static const std::string CIPHER_SUITE;
	static const std::string COMPRESSION_METHOD;
	static const std::string KEYSTORE_PATH;
	static const std::string KEYSTORE_PASSWORD;

	//Berta
	static const std::string CERTIFICATE_PATH;
	static const std::string MY_CERTIFICATE;

	static const std::string PRIV_KEY_PATH;


        enum State {
        	BEGIN,
                WAIT_SERVER_HELLO_and_CERTIFICATE,
		WAIT_CLIENT_CERTIFICATE_and_KEYS,
		CLIENT_SENDING_DATA,
		SERVER_SENDING_CIPHER,
		WAIT_SERVER_CIPHER,
		WAIT_SERVER_FINISH,
		SERVER_SENDING_FINISH,
		//WAIT_SERVER_CERTIFICATE,
                DONE
        };

        State state;

        /// Negotiated version of the policy_set
        std::string version;

	/// Negotiated algorithms
	std::string cipher_suite;
	std::string compress_method;

	/// Authentication Keystore path and password
	std::string keystore_path;
	std::string keystore_password;

	//Authentication Certificates
	std::string certificate_path;
	std::string priv_key_path;


	//Master secret generated in key exchange
	UcharArray master_secret;

	//finished hash, 12Bytes;
	UcharArray verify_data;

	//hashed received/sent messages (5mess*32length);
	UcharArray verify_hash;



	//Berta certificates presence
	bool cert_received;
	bool hello_received;

	//Presence of received client messages
	bool client_cert_received;
	bool client_keys_received;
	bool client_cert_verify_received;
	bool client_cipher_received;


	/// Encryption policy configuration
	PolicyConfig encrypt_policy_config;

	///Client and server-generated randoms
	TLSHandRandom client_random;
	TLSHandRandom server_random;

	// Owned by a timer
	CancelAuthTimerTask * timer_task;

	X509 * cert;
	X509 *other_cert;

private:
	//return -1 if options are valid, 0 otherwise
	int validate_options(const TLSHandAuthOptions& options);
};

/// Authentication policy set that mimics TLS Hanshake protocol. It is associated to
/// a cryptographic SDU protection policy based on the TLS Record Protocol.
/// It uses the Open SSL crypto library to perform all its functions
class AuthTLSHandPolicySet : public IAuthPolicySet {
public:
	static const int DEFAULT_TIMEOUT;
	static const std::string EDH_EXCHANGE;
	static const int MIN_RSA_KEY_PAIR_LENGTH;
	static const std::string SERVER_HELLO;
	static const std::string SERVER_CERTIFICATE;
	static const std::string CLIENT_CERTIFICATE;
	static const std::string CLIENT_KEY_EXCHANGE;
	static const std::string CLIENT_CERTIFICATE_VERIFY;
	static const std::string CLIENT_CHANGE_CIPHER_SPEC;
	static const std::string SERVER_CHANGE_CIPHER_SPEC;
	static const std::string CLIENT_FINISH;
	static const std::string SERVER_FINISH;

	AuthTLSHandPolicySet(rib::RIBDaemonProxy * ribd,
			     ISecurityManager * sm);
	virtual ~AuthTLSHandPolicySet();
	cdap_rib::auth_policy_t get_auth_policy(int session_id,
				   	        const AuthSDUProtectionProfile& profile);
	AuthStatus initiate_authentication(const cdap_rib::auth_policy_t& auth_policy,
				           const AuthSDUProtectionProfile& profile,
					   int session_id);
	int process_incoming_message(const cdap::CDAPMessage& message, int session_id);
	int set_policy_set_param(const std::string& name,
	                         const std::string& value);

	//Called when encryption has been enabled on a certain port, if the call
	//to the Security Manager's "enable encryption" was asynchronous
	AuthStatus crypto_state_updated(int port_id);

private:
	int process_server_hello_message(const cdap::CDAPMessage& message,
					 int session_id);
	//BERTA
	int process_server_certificate_message(const cdap::CDAPMessage& message,
						 int session_id);
	int process_client_certificate_message(const cdap::CDAPMessage& message,
							 int session_id);
	int process_client_key_exchange_message(const cdap::CDAPMessage& message,
								 int session_id);
	int process_client_certificate_verify_message(const cdap::CDAPMessage& message,
									 int session_id);
	int process_client_change_cipher_spec_message(const cdap::CDAPMessage& message,
			int session_id);
	int process_server_change_cipher_spec_message (const cdap::CDAPMessage& message,
			int session_id);
	int process_client_finish_message(const cdap::CDAPMessage& message,
			int session_id);
	int send_client_messages(TLSHandSecurityContext * sc);
	int send_client_certificate(TLSHandSecurityContext * sc);
	int send_client_key_exchange(TLSHandSecurityContext * sc);
	int send_client_certificate_verify(TLSHandSecurityContext * sc);
	int send_client_change_cipher_spec(TLSHandSecurityContext * sc);
	int send_server_change_cipher_spec(TLSHandSecurityContext * sc);
	int send_client_finish(TLSHandSecurityContext * sc);
	//FI BERTA

	int load_credentials(TLSHandSecurityContext * sc);
	//int calculate_master_secret(TLSHandSecurityContext * sc, UcharArray& pre);
	int prf(UcharArray& generated_hash, UcharArray& secret, const std::string& slabel, UcharArray& pre_seed);

	//Load the authentication certificate required for this DIF from a file
	int load_authentication_certificate(TLSHandSecurityContext * sc);

	rib::RIBDaemonProxy * rib_daemon;
	ISecurityManager * sec_man;
	Lockable lock;
	Timer timer;
	int timeout;
};

}

#endif

#endif
