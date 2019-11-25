// Copyright 2019 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Functions for building partial transactions to be passed
//! around during an interactive wallet exchange

use crate::blake2::blake2b::blake2b;
use crate::error::{Error, ErrorKind};
use crate::grin_core::core::amount_to_hr_string;
use crate::grin_core::core::committed::Committed;
use crate::grin_core::core::transaction::{
	KernelFeatures, Output, TokenKernelFeatures, TokenKey, TokenTxKernel, Transaction, TxKernel,
	Weighting,
};
use crate::grin_core::core::verifier_cache::LruVerifierCache;
use crate::grin_core::libtx::{aggsig, build, proof::ProofBuild, secp_ser, tx_fee};
use crate::grin_core::map_vec;
use crate::grin_keychain::{BlindSum, BlindingFactor, Identifier, Keychain};
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::Commitment;
use crate::grin_util::secp::Signature;
use crate::grin_util::{self, secp, RwLock};
use failure::ResultExt;
use rand::rngs::mock::StepRng;
use rand::thread_rng;
use serde::ser::{Serialize, Serializer};
use serde_json;
use std::fmt;
use std::sync::Arc;
use uuid::Uuid;

use crate::slate_versions::v2::{CoinbaseV2, OutputV2, TxKernelV2};
use crate::slate_versions::v3::{ParticipantDataV3, SlateV3, VersionCompatInfoV3};
use crate::slate_versions::{CURRENT_SLATE_VERSION, GRIN_BLOCK_HEADER_VERSION};
use crate::types::CbData;

/// Public data for each participant in the slate
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantData {
	/// Id of participant in the transaction. (For now, 0=sender, 1=rec)
	#[serde(with = "secp_ser::string_or_u64")]
	pub id: u64,
	/// Public key corresponding to private blinding factor
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_blind_excess: PublicKey,
	/// Public key corresponding to private nonce
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_nonce: PublicKey,
	/// Public partial signature
	#[serde(with = "secp_ser::option_sig_serde")]
	pub part_sig: Option<Signature>,
	/// A message for other participants
	pub message: Option<String>,
	/// Signature, created with private key corresponding to 'public_blind_excess'
	#[serde(with = "secp_ser::option_sig_serde")]
	pub message_sig: Option<Signature>,
}

impl ParticipantData {
	/// A helper to return whether this participant
	/// has completed round 1 and round 2;
	/// Round 1 has to be completed before instantiation of this struct
	/// anyhow, and for each participant consists of:
	/// -Inputs added to transaction
	/// -Outputs added to transaction
	/// -Public signature nonce chosen and added
	/// -Public contribution to blinding factor chosen and added
	/// Round 2 can only be completed after all participants have
	/// performed round 1, and adds:
	/// -Part sig is filled out
	pub fn is_complete(&self) -> bool {
		self.part_sig.is_some()
	}
}

/// Public message data (for serialising and storage)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantMessageData {
	/// id of the particpant in the tx
	#[serde(with = "secp_ser::string_or_u64")]
	pub id: u64,
	/// Public key
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_key: PublicKey,
	/// Message,
	pub message: Option<String>,
	/// Signature
	#[serde(with = "secp_ser::option_sig_serde")]
	pub message_sig: Option<Signature>,
}

impl ParticipantMessageData {
	/// extract relevant message data from participant data
	pub fn from_participant_data(p: &ParticipantData) -> ParticipantMessageData {
		ParticipantMessageData {
			id: p.id,
			public_key: p.public_blind_excess,
			message: p.message.clone(),
			message_sig: p.message_sig.clone(),
		}
	}
}

impl fmt::Display for ParticipantMessageData {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		writeln!(f, "")?;
		write!(f, "Participant ID {} ", self.id)?;
		if self.id == 0 {
			writeln!(f, "(Sender)")?;
		} else {
			writeln!(f, "(Recipient)")?;
		}
		writeln!(f, "---------------------")?;
		let static_secp = grin_util::static_secp_instance();
		let static_secp = static_secp.lock();
		writeln!(
			f,
			"Public Key: {}",
			&grin_util::to_hex(self.public_key.serialize_vec(&static_secp, true).to_vec())
		)?;
		let message = match self.message.clone() {
			None => "None".to_owned(),
			Some(m) => m,
		};
		writeln!(f, "Message: {}", message)?;
		let message_sig = match self.message_sig.clone() {
			None => "None".to_owned(),
			Some(m) => grin_util::to_hex(m.to_raw_data().to_vec()),
		};
		writeln!(f, "Message Signature: {}", message_sig)
	}
}

/// A 'Slate' is passed around to all parties to build up all of the public
/// transaction data needed to create a finalized transaction. Callers can pass
/// the slate around by whatever means they choose, (but we can provide some
/// binary or JSON serialization helpers here).

#[derive(Deserialize, Debug, Clone)]
pub struct Slate {
	/// Versioning info
	pub version_info: VersionCompatInfo,
	/// The number of participants intended to take part in this transaction
	pub num_participants: usize,
	/// Unique transaction ID, selected by sender
	pub id: Uuid,
	/// The core transaction data:
	/// inputs, outputs, kernels, kernel offset
	pub tx: Transaction,
	/// base amount (excluding fee)
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount: u64,
	/// tx token type
	pub token_type: Option<String>,
	/// fee amount
	#[serde(with = "secp_ser::string_or_u64")]
	pub fee: u64,
	/// Block height for the transaction
	#[serde(with = "secp_ser::string_or_u64")]
	pub height: u64,
	/// Lock height
	#[serde(with = "secp_ser::string_or_u64")]
	pub lock_height: u64,
	/// Participant data, each participant in the transaction will
	/// insert their public data here. For now, 0 is sender and 1
	/// is receiver, though this will change for multi-party
	pub participant_data: Vec<ParticipantData>,
}

/// Versioning and compatibility info about this slate
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionCompatInfo {
	/// The current version of the slate format
	pub version: u16,
	/// Original version this slate was converted from
	pub orig_version: u16,
	/// The grin block header version this slate is intended for
	pub block_header_version: u16,
}

/// Helper just to facilitate serialization
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantMessages {
	/// included messages
	pub messages: Vec<ParticipantMessageData>,
}

impl Slate {
	/// Attempt to find slate version
	pub fn parse_slate_version(slate_json: &str) -> Result<u16, Error> {
		let probe: SlateVersionProbe =
			serde_json::from_str(slate_json).map_err(|_| ErrorKind::SlateVersionParse)?;
		Ok(probe.version())
	}

	/// Recieve a slate, upgrade it to the latest version internally
	pub fn deserialize_upgrade(slate_json: &str) -> Result<Slate, Error> {
		let version = Slate::parse_slate_version(slate_json)?;
		let v3: SlateV3 = match version {
			3 => serde_json::from_str(slate_json).context(ErrorKind::SlateDeser)?,
			// left as a reminder
			/*0 => {
				let v0: SlateV0 =
					serde_json::from_str(slate_json).context(ErrorKind::SlateDeser)?;
				let v1 = SlateV1::from(v0);
				SlateV2::from(v1)
			}*/
			_ => return Err(ErrorKind::SlateVersion(version).into()),
		};
		Ok(v3.into())
	}

	/// Create a new slate
	pub fn blank(num_participants: usize) -> Slate {
		Slate {
			num_participants: num_participants,
			id: Uuid::new_v4(),
			tx: Transaction::empty(),
			amount: 0,
			token_type: None,
			fee: 0,
			height: 0,
			lock_height: 0,
			participant_data: vec![],
			version_info: VersionCompatInfo {
				version: CURRENT_SLATE_VERSION,
				orig_version: CURRENT_SLATE_VERSION,
				block_header_version: GRIN_BLOCK_HEADER_VERSION,
			},
		}
	}

	/// Adds selected inputs and outputs to the slate's transaction
	/// Returns blinding factor
	pub fn add_transaction_elements<K, B>(
		&mut self,
		keychain: &K,
		builder: &B,
		elems: Vec<Box<build::Append<K, B>>>,
	) -> Result<(BlindingFactor, BlindingFactor), Error>
	where
		K: Keychain,
		B: ProofBuild,
	{
		self.update_kernel();
		self.update_token_kernel();
		let (tx, blind, token_bind) =
			build::partial_transaction(self.tx.clone(), elems, keychain, builder)?;
		self.tx = tx;
		Ok((blind, token_bind))
	}

	/// Update the tx kernel based on kernel features derived from the current slate.
	/// The fee may change as we build a transaction and we need to
	/// update the tx kernel to reflect this during the tx building process.
	pub fn update_kernel(&mut self) {
		self.tx = self
			.tx
			.clone()
			.replace_kernel(TxKernel::with_features(self.kernel_features()));
	}

	/// Update the tx token kernel based on token kernel features derived from the current slate.
	/// update the tx token kernel to reflect this during the tx building process.
	pub fn update_token_kernel(&mut self) {
		if self.token_type.is_some() {
			let token_type = TokenKey::from_hex(self.token_type.clone().unwrap().as_str()).unwrap();
			self.tx = self.tx.clone().replace_token_kernel(
				TokenTxKernel::with_features(self.token_kernel_features())
					.with_token_type(token_type),
			);
		}
	}

	/// Construct Issue Token tx Kernel
	pub fn construct_issue_token_kernel<K>(
		&mut self,
		keychain: &K,
		amount: u64,
		output_id: &Identifier,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		if self.token_type.is_some() {
			let feature = TokenKernelFeatures::IssueToken;
			let token_type = TokenKey::from_hex(self.token_type.clone().unwrap().as_str())?;
			let mut token_kernel =
				TokenTxKernel::with_features(feature).with_token_type(token_type.clone());

			let secp = keychain.secp();
			let value_commit = secp.commit_value(amount).unwrap();
			let out_commit = self.tx.token_outputs()[0].commit.clone();
			let excess = secp.commit_sum(vec![out_commit], vec![value_commit])?;
			let pubkey = excess.to_pubkey(&secp)?;
			let msg = feature.token_kernel_sig_msg(token_type.clone())?;
			let sig = aggsig::sign_from_key_id(
				&secp,
				keychain,
				&msg,
				amount,
				&output_id,
				None,
				Some(&pubkey),
			)?;

			token_kernel.excess = excess;
			token_kernel.excess_sig = sig;
			self.tx = self.tx.clone().replace_token_kernel(token_kernel);
		}

		Ok(())
	}

	/// Completes callers part of round 1, adding public key info
	/// to the slate
	pub fn fill_round_1<K>(
		&mut self,
		keychain: &K,
		sec_key: &mut SecretKey,
		token_sec_key: &SecretKey,
		sec_nonce: &SecretKey,
		participant_id: usize,
		message: Option<String>,
		use_test_rng: bool,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		// Whoever does this first generates the offset
		if self.tx.offset == BlindingFactor::zero() {
			self.generate_offset(keychain, sec_key, use_test_rng)?;
		}
		let key = match self.token_type.clone() {
			Some(_) => token_sec_key,
			None => sec_key,
		};
		self.add_participant_info(
			keychain,
			key,
			&sec_nonce,
			participant_id,
			None,
			message,
			use_test_rng,
		)?;
		Ok(())
	}

	// Construct the appropriate kernel features based on our fee and lock_height.
	// If lock_height is 0 then its a plain kernel, otherwise its a height locked kernel.
	fn kernel_features(&self) -> KernelFeatures {
		match self.lock_height {
			0 => KernelFeatures::Plain { fee: self.fee },
			_ => KernelFeatures::HeightLocked {
				fee: self.fee,
				lock_height: self.lock_height,
			},
		}
	}

	// This is the msg that we will sign as part of the tx kernel.
	// If lock_height is 0 then build a plain kernel, otherwise build a height locked kernel.
	fn msg_to_sign(&self) -> Result<secp::Message, Error> {
		let msg = self.kernel_features().kernel_sig_msg()?;
		Ok(msg)
	}

	fn token_kernel_features(&self) -> TokenKernelFeatures {
		match self.lock_height {
			0 => TokenKernelFeatures::PlainToken,
			_ => TokenKernelFeatures::HeightLockedToken {
				lock_height: self.lock_height,
			},
		}
	}

	fn token_msg_to_sign(&self) -> Result<secp::Message, Error> {
		let features = self.token_kernel_features();
		let token_type = TokenKey::from_hex(self.token_type.clone().unwrap().as_str())?;
		let msg = features.token_kernel_sig_msg(token_type)?;
		Ok(msg)
	}

	/// Completes caller's part of round 2, completing signatures
	pub fn fill_round_2<K>(
		&mut self,
		keychain: &K,
		sec_key: &SecretKey,
		token_sec_key: &SecretKey,
		sec_nonce: &SecretKey,
		participant_id: usize,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		self.check_fees()?;

		self.verify_part_sigs(keychain.secp())?;
		let (key, msg) = match self.token_type.clone() {
			Some(_) => (token_sec_key, self.token_msg_to_sign()?),
			None => (sec_key, self.msg_to_sign()?),
		};
		let sig_part = aggsig::calculate_partial_sig(
			keychain.secp(),
			key,
			sec_nonce,
			&self.pub_nonce_sum(keychain.secp())?,
			Some(&self.pub_blind_sum(keychain.secp())?),
			&msg,
		)?;
		for i in 0..self.num_participants {
			if self.participant_data[i].id == participant_id as u64 {
				self.participant_data[i].part_sig = Some(sig_part);
				break;
			}
		}
		Ok(())
	}

	/// Creates the final signature, callable by either the sender or recipient
	/// (after phase 3: sender confirmation)
	pub fn finalize<K>(&mut self, keychain: &K) -> Result<(), Error>
	where
		K: Keychain,
	{
		let final_sig = self.finalize_signature(keychain)?;
		if self.token_type.is_some() {
			self.finalize_token_transaction(keychain, &final_sig)
		} else {
			self.finalize_transaction(keychain, &final_sig)
		}
	}

	/// Return the participant with the given id
	pub fn participant_with_id(&self, id: usize) -> Option<ParticipantData> {
		for p in self.participant_data.iter() {
			if p.id as usize == id {
				return Some(p.clone());
			}
		}
		None
	}

	/// Return the sum of public nonces
	fn pub_nonce_sum(&self, secp: &secp::Secp256k1) -> Result<PublicKey, Error> {
		let pub_nonces = self
			.participant_data
			.iter()
			.map(|p| &p.public_nonce)
			.collect();
		match PublicKey::from_combination(secp, pub_nonces) {
			Ok(k) => Ok(k),
			Err(e) => Err(ErrorKind::Secp(e))?,
		}
	}

	/// Return the sum of public blinding factors
	fn pub_blind_sum(&self, secp: &secp::Secp256k1) -> Result<PublicKey, Error> {
		let pub_blinds = self
			.participant_data
			.iter()
			.map(|p| &p.public_blind_excess)
			.collect();
		match PublicKey::from_combination(secp, pub_blinds) {
			Ok(k) => Ok(k),
			Err(e) => Err(ErrorKind::Secp(e))?,
		}
	}

	/// Return vector of all partial sigs
	fn part_sigs(&self) -> Vec<&Signature> {
		self.participant_data
			.iter()
			.map(|p| p.part_sig.as_ref().unwrap())
			.collect()
	}

	/// Adds participants public keys to the slate data
	/// and saves participant's transaction context
	/// sec_key can be overridden to replace the blinding
	/// factor (by whoever split the offset)
	fn add_participant_info<K>(
		&mut self,
		keychain: &K,
		sec_key: &SecretKey,
		sec_nonce: &SecretKey,
		id: usize,
		part_sig: Option<Signature>,
		message: Option<String>,
		use_test_rng: bool,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		// Add our public key and nonce to the slate
		let pub_key = PublicKey::from_secret_key(keychain.secp(), &sec_key)?;
		let pub_nonce = PublicKey::from_secret_key(keychain.secp(), &sec_nonce)?;

		let test_message_nonce = SecretKey::from_slice(&keychain.secp(), &[1; 32]).unwrap();
		let message_nonce = match use_test_rng {
			false => None,
			true => Some(&test_message_nonce),
		};

		// Sign the provided message
		let message_sig = {
			if let Some(m) = message.clone() {
				let hashed = blake2b(secp::constants::MESSAGE_SIZE, &[], &m.as_bytes()[..]);
				let m = secp::Message::from_slice(&hashed.as_bytes())?;
				let res = aggsig::sign_single(
					&keychain.secp(),
					&m,
					&sec_key,
					message_nonce,
					Some(&pub_key),
				)?;
				Some(res)
			} else {
				None
			}
		};
		self.participant_data.push(ParticipantData {
			id: id as u64,
			public_blind_excess: pub_key,
			public_nonce: pub_nonce,
			part_sig: part_sig,
			message: message,
			message_sig: message_sig,
		});
		Ok(())
	}

	/// helper to return all participant messages
	pub fn participant_messages(&self) -> ParticipantMessages {
		let mut ret = ParticipantMessages { messages: vec![] };
		for ref m in self.participant_data.iter() {
			ret.messages
				.push(ParticipantMessageData::from_participant_data(m));
		}
		ret
	}

	/// Somebody involved needs to generate an offset with their private key
	/// For now, we'll have the transaction initiator be responsible for it
	/// Return offset private key for the participant to use later in the
	/// transaction
	pub fn generate_offset<K>(
		&mut self,
		keychain: &K,
		sec_key: &mut SecretKey,
		use_test_rng: bool,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		// Generate a random kernel offset here
		// and subtract it from the blind_sum so we create
		// the aggsig context with the "split" key
		self.tx.offset = match use_test_rng {
			false => {
				BlindingFactor::from_secret_key(SecretKey::new(&keychain.secp(), &mut thread_rng()))
			}
			true => {
				// allow for consistent test results
				let mut test_rng = StepRng::new(1234567890u64, 1);
				BlindingFactor::from_secret_key(SecretKey::new(&keychain.secp(), &mut test_rng))
			}
		};

		let blind_offset = keychain.blind_sum(
			&BlindSum::new()
				.add_blinding_factor(BlindingFactor::from_secret_key(sec_key.clone()))
				.sub_blinding_factor(self.tx.offset.clone()),
		)?;
		*sec_key = blind_offset.secret_key(&keychain.secp())?;
		Ok(())
	}

	/// Checks the fees in the transaction in the given slate are valid
	fn check_fees(&self) -> Result<(), Error> {
		// double check the fee amount included in the partial tx
		// we don't necessarily want to just trust the sender
		// we could just overwrite the fee here (but we won't) due to the sig
		let fee = tx_fee(
			self.tx.inputs().len(),
			self.tx.outputs().len(),
			self.tx.kernels().len(),
			self.tx.token_inputs().len(),
			self.tx.token_outputs().len(),
			self.tx.token_kernels().len(),
			None,
		);

		if fee > self.tx.fee() {
			return Err(ErrorKind::Fee(
				format!("Fee Dispute Error: {}, {}", self.tx.fee(), fee,).to_string(),
			))?;
		}

		if fee > self.amount + self.fee {
			let reason = format!(
				"Rejected the transfer because transaction fee ({}) exceeds received amount ({}).",
				amount_to_hr_string(fee, false),
				amount_to_hr_string(self.amount + self.fee, false)
			);
			info!("{}", reason);
			return Err(ErrorKind::Fee(reason.to_string()))?;
		}

		Ok(())
	}

	/// Verifies all of the partial signatures in the Slate are valid
	fn verify_part_sigs(&self, secp: &secp::Secp256k1) -> Result<(), Error> {
		let msg = match self.token_type.clone() {
			Some(_) => self.token_msg_to_sign()?,
			None => self.msg_to_sign()?,
		};
		// collect public nonces
		for p in self.participant_data.iter() {
			if p.is_complete() {
				aggsig::verify_partial_sig(
					secp,
					p.part_sig.as_ref().unwrap(),
					&self.pub_nonce_sum(secp)?,
					&p.public_blind_excess,
					Some(&self.pub_blind_sum(secp)?),
					&msg,
				)?;
			}
		}
		Ok(())
	}

	/// Verifies any messages in the slate's participant data match their signatures
	pub fn verify_messages(&self) -> Result<(), Error> {
		let secp = secp::Secp256k1::with_caps(secp::ContextFlag::VerifyOnly);
		for p in self.participant_data.iter() {
			if let Some(msg) = &p.message {
				let hashed = blake2b(secp::constants::MESSAGE_SIZE, &[], &msg.as_bytes()[..]);
				let m = secp::Message::from_slice(&hashed.as_bytes())?;
				let signature = match p.message_sig {
					None => {
						error!("verify_messages - participant message doesn't have signature. Message: \"{}\"",
						   String::from_utf8_lossy(&msg.as_bytes()[..]));
						return Err(ErrorKind::Signature(
							"Optional participant messages doesn't have signature".to_owned(),
						))?;
					}
					Some(s) => s,
				};
				if !aggsig::verify_single(
					&secp,
					&signature,
					&m,
					None,
					&p.public_blind_excess,
					Some(&p.public_blind_excess),
					false,
				) {
					error!("verify_messages - participant message doesn't match signature. Message: \"{}\"",
						   String::from_utf8_lossy(&msg.as_bytes()[..]));
					return Err(ErrorKind::Signature(
						"Optional participant messages do not match signatures".to_owned(),
					))?;
				} else {
					info!(
						"verify_messages - signature verified ok. Participant message: \"{}\"",
						String::from_utf8_lossy(&msg.as_bytes()[..])
					);
				}
			}
		}
		Ok(())
	}

	/// This should be callable by either the sender or receiver
	/// once phase 3 is done
	///
	/// Receive Part 3 of interactive transactions from sender, Sender
	/// Confirmation Return Ok/Error
	/// -Receiver receives sS
	/// -Receiver verifies sender's sig, by verifying that
	/// kS * G + e *xS * G = sS* G
	/// -Receiver calculates final sig as s=(sS+sR, kS * G+kR * G)
	/// -Receiver puts into TX kernel:
	///
	/// Signature S
	/// pubkey xR * G+xS * G
	/// fee (= M)
	///
	/// Returns completed transaction ready for posting to the chain

	fn finalize_signature<K>(&mut self, keychain: &K) -> Result<Signature, Error>
	where
		K: Keychain,
	{
		self.verify_part_sigs(keychain.secp())?;

		let part_sigs = self.part_sigs();
		let pub_nonce_sum = self.pub_nonce_sum(keychain.secp())?;
		let final_pubkey = self.pub_blind_sum(keychain.secp())?;
		// get the final signature
		let final_sig = aggsig::add_signatures(&keychain.secp(), part_sigs, &pub_nonce_sum)?;

		// Calculate the final public key (for our own sanity check)
		let msg = match self.token_type.clone() {
			Some(_) => self.token_msg_to_sign()?,
			None => self.msg_to_sign()?,
		};

		// Check our final sig verifies
		aggsig::verify_completed_sig(
			&keychain.secp(),
			&final_sig,
			&final_pubkey,
			Some(&final_pubkey),
			&msg,
		)?;

		Ok(final_sig)
	}

	/// return the final excess
	pub fn calc_excess<K>(&self, keychain: &K) -> Result<Commitment, Error>
	where
		K: Keychain,
	{
		let kernel_offset = &self.tx.offset;
		let tx = self.tx.clone();
		let overage = tx.fee() as i64;
		let tx_excess = tx.sum_commitments(overage)?;

		// subtract the kernel_excess (built from kernel_offset)
		let offset_excess = keychain
			.secp()
			.commit(0, kernel_offset.secret_key(&keychain.secp())?)?;
		Ok(keychain
			.secp()
			.commit_sum(vec![tx_excess], vec![offset_excess])?)
	}

	/// builds a final transaction after the aggregated sig exchange
	fn finalize_transaction<K>(
		&mut self,
		keychain: &K,
		final_sig: &secp::Signature,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		self.check_fees()?;
		// build the final excess based on final tx and offset
		let final_excess = self.calc_excess(keychain)?;

		debug!("Final Tx excess: {:?}", final_excess);

		let mut final_tx = self.tx.clone();

		// update the tx kernel to reflect the offset excess and sig
		assert_eq!(final_tx.kernels().len(), 1);
		final_tx.kernels_mut()[0].excess = final_excess.clone();
		final_tx.kernels_mut()[0].excess_sig = final_sig.clone();

		// confirm the kernel verifies successfully before proceeding
		debug!("Validating final transaction");
		final_tx.kernels()[0].verify()?;

		// confirm the overall transaction is valid (including the updated kernel)
		// accounting for tx weight limits
		let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));
		let _ = final_tx.validate(Weighting::AsTransaction, verifier_cache)?;

		self.tx = final_tx;
		Ok(())
	}

	/// builds a final transaction after the aggregated sig exchange
	pub fn finalize_token_parent_tx<K>(
		&mut self,
		keychain: &K,
		sec_key: &SecretKey,
		with_validate: bool,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		let kernel_offset = &self.tx.offset;

		self.check_fees()?;

		let mut final_tx = self.tx.clone();

		let secp = keychain.secp();

		// build the final excess based on final tx and offset
		let final_excess = {
			// sum the input/output commitments on the final tx
			let overage = final_tx.fee() as i64;
			let tx_excess = final_tx.sum_commitments(overage)?;

			// subtract the kernel_excess (built from kernel_offset)
			let offset_excess = secp.commit(0, kernel_offset.secret_key(secp)?)?;
			secp.commit_sum(vec![tx_excess], vec![offset_excess])?
		};
		let pubkey = final_excess.to_pubkey(&secp)?;

		let sig = aggsig::sign_single(secp, &self.msg_to_sign()?, sec_key, None, Some(&pubkey))?;

		// update the tx kernel to reflect the offset excess and sig
		assert_eq!(final_tx.kernels().len(), 1);
		final_tx.kernels_mut()[0].excess = final_excess.clone();
		final_tx.kernels_mut()[0].excess_sig = sig;

		// confirm the kernel verifies successfully before proceeding
		debug!("Validating final transaction");
		final_tx.kernels()[0].verify()?;

		// confirm the overall transaction is valid (including the updated kernel)
		// accounting for tx weight limits
		if with_validate {
			let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));
			let _ = final_tx.validate(Weighting::AsTransaction, verifier_cache)?;
		}

		self.tx = final_tx;
		Ok(())
	}

	/// builds a final transaction after the aggregated sig exchange
	fn finalize_token_transaction<K>(
		&mut self,
		keychain: &K,
		final_sig: &secp::Signature,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		self.check_fees()?;

		let token_type = TokenKey::from_hex(self.token_type.clone().unwrap().as_str())?;

		let mut final_tx = self.tx.clone();

		// build the final excess based on final tx and offset
		let final_excess = {
			let mut token_input_commit_map = final_tx.token_inputs_committed();
			let mut token_output_commit_map = final_tx.token_outputs_committed();
			let token_input_commit_vec = token_input_commit_map.entry(token_type).or_insert(vec![]);
			let token_output_commit_vec =
				token_output_commit_map.entry(token_type).or_insert(vec![]);
			keychain.secp().commit_sum(
				token_output_commit_vec.clone(),
				token_input_commit_vec.clone(),
			)?
		};

		// update the tx kernel to reflect the offset excess and sig
		assert_eq!(final_tx.token_kernels().len(), 1);
		final_tx.token_kernels_mut()[0].excess = final_excess.clone();
		final_tx.token_kernels_mut()[0].excess_sig = final_sig.clone();

		// confirm the kernel verifies successfully before proceeding
		debug!("Validating final transaction");
		final_tx.token_kernels_mut()[0].verify()?;

		// confirm the overall transaction is valid (including the updated kernel)
		// accounting for tx weight limits
		let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));
		let _ = final_tx.validate(Weighting::AsTransaction, verifier_cache)?;

		self.tx = final_tx;
		Ok(())
	}
}

impl Serialize for Slate {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		use serde::ser::Error;

		let v3 = SlateV3::from(self);
		match self.version_info.orig_version {
			3 => v3.serialize(serializer),
			// left as a reminder
			/*0 => {
				let v1 = SlateV1::from(v2);
				let v0 = SlateV0::from(v1);
				v0.serialize(serializer)
			}*/
			v => Err(S::Error::custom(format!("Unknown slate version {}", v))),
		}
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlateVersionProbe {
	#[serde(default)]
	version: Option<u64>,
	#[serde(default)]
	version_info: Option<VersionCompatInfo>,
}

impl SlateVersionProbe {
	pub fn version(&self) -> u16 {
		match &self.version_info {
			Some(v) => v.version,
			None => match self.version {
				Some(_) => 1,
				None => 0,
			},
		}
	}
}

// Coinbase data to versioned.
impl From<CbData> for CoinbaseV2 {
	fn from(cb: CbData) -> CoinbaseV2 {
		CoinbaseV2 {
			output: OutputV2::from(&cb.output),
			kernel: TxKernelV2::from(&cb.kernel),
			key_id: cb.key_id,
		}
	}
}

// Current slate version to versioned conversions

// Slate to versioned
impl From<Slate> for SlateV3 {
	fn from(slate: Slate) -> SlateV3 {
		let Slate {
			num_participants,
			id,
			tx,
			amount,
			token_type,
			fee,
			height,
			lock_height,
			participant_data,
			version_info,
		} = slate;
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV3::from(data));
		let version_info = VersionCompatInfoV3::from(&version_info);
		SlateV3 {
			num_participants,
			id,
			tx,
			amount,
			token_type,
			fee,
			height,
			lock_height,
			participant_data,
			version_info,
		}
	}
}

impl From<&Slate> for SlateV3 {
	fn from(slate: &Slate) -> SlateV3 {
		let Slate {
			num_participants,
			id,
			tx,
			amount,
			token_type,
			fee,
			height,
			lock_height,
			participant_data,
			version_info,
		} = slate;
		let num_participants = *num_participants;
		let id = *id;
		let tx = tx.clone();
		let amount = *amount;
		let token_type = token_type.to_owned();
		let fee = *fee;
		let height = *height;
		let lock_height = *lock_height;
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV3::from(data));
		let version_info = VersionCompatInfoV3::from(version_info);
		SlateV3 {
			num_participants,
			id,
			tx,
			amount,
			token_type,
			fee,
			height,
			lock_height,
			participant_data,
			version_info,
		}
	}
}

impl From<&ParticipantData> for ParticipantDataV3 {
	fn from(data: &ParticipantData) -> ParticipantDataV3 {
		let ParticipantData {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		} = data;
		let id = *id;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		let message: Option<String> = message.as_ref().map(|t| String::from(&**t));
		let message_sig = *message_sig;
		ParticipantDataV3 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		}
	}
}

impl From<&VersionCompatInfo> for VersionCompatInfoV3 {
	fn from(data: &VersionCompatInfo) -> VersionCompatInfoV3 {
		let VersionCompatInfo {
			version,
			orig_version,
			block_header_version,
		} = data;
		let version = *version;
		let orig_version = *orig_version;
		let block_header_version = *block_header_version;
		VersionCompatInfoV3 {
			version,
			orig_version,
			block_header_version,
		}
	}
}

impl From<&Output> for OutputV2 {
	fn from(output: &Output) -> OutputV2 {
		let Output {
			features,
			commit,
			proof,
		} = *output;
		OutputV2 {
			features,
			commit,
			proof,
		}
	}
}

impl From<&TxKernel> for TxKernelV2 {
	fn from(kernel: &TxKernel) -> TxKernelV2 {
		let (features, fee, lock_height) = match kernel.features {
			KernelFeatures::Plain { fee } => (CompatKernelFeatures::Plain, fee, 0),
			KernelFeatures::Coinbase => (CompatKernelFeatures::Coinbase, 0, 0),
			KernelFeatures::HeightLocked { fee, lock_height } => {
				(CompatKernelFeatures::HeightLocked, fee, lock_height)
			}
		};
		TxKernelV2 {
			features,
			fee,
			lock_height,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig,
		}
	}
}

// Versioned to current slate
impl From<SlateV3> for Slate {
	fn from(slate: SlateV3) -> Slate {
		let SlateV3 {
			num_participants,
			id,
			tx,
			amount,
			token_type,
			fee,
			height,
			lock_height,
			participant_data,
			version_info,
		} = slate;
		let participant_data = map_vec!(participant_data, |data| ParticipantData::from(data));
		let version_info = VersionCompatInfo::from(&version_info);
		let tx = Transaction::from(tx);
		Slate {
			num_participants,
			id,
			tx,
			amount,
			token_type,
			fee,
			height,
			lock_height,
			participant_data,
			version_info,
		}
	}
}

impl From<&ParticipantDataV3> for ParticipantData {
	fn from(data: &ParticipantDataV3) -> ParticipantData {
		let ParticipantDataV3 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		} = data;
		let id = *id;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		let message: Option<String> = message.as_ref().map(|t| String::from(&**t));
		let message_sig = *message_sig;
		ParticipantData {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		}
	}
}

impl From<&VersionCompatInfoV3> for VersionCompatInfo {
	fn from(data: &VersionCompatInfoV3) -> VersionCompatInfo {
		let VersionCompatInfoV3 {
			version,
			orig_version,
			block_header_version,
		} = data;
		let version = *version;
		let orig_version = *orig_version;
		let block_header_version = *block_header_version;
		VersionCompatInfo {
			version,
			orig_version,
			block_header_version,
		}
	}
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum CompatKernelFeatures {
	Plain,
	Coinbase,
	HeightLocked,
}
