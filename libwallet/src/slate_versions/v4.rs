// Copyright 2020 The Grin Developers
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

//! Contains V4 of the slate (grin-wallet 4.0.0)
//! Changes from V3:
//! /#### Top-Level Slate Struct

//! * The `version_info` struct is removed, and is replaced with `ver`, which has the format "[version]:[block header version]"
//! * `id` becomes a short-form base-64 encoding of the UUID binary
//! * `sta` is added, with possible values S1|S2|S3|I1|I2|I3|NA
//! * `num_participants` is renamed to `num_parts`
//! * `num_parts` may be omitted from the slate. If omitted its value is assumed to be 2.
//! * `amount` is renamed to `amt`
//! * `amt` may be removed from the slate on the S2 phase of a transaction.
//! * `fee` may be removed from the slate on the S2 phase of a transaction. It may also be ommited when intiating an I1 transaction, and added during the I2 phase.
//! * `lock_height` is removed
//! * `feat` is added to the slate denoting the Kernel feature set. May be omitted from the slate if kernel is plain (0)
//! * `ttl_cutoff_height` is renamed to `ttl`
//! * `ttl` may be omitted from the slate. If omitted its value is assumed to be 0 (no TTL).
//! *  The `participant_data` struct is renamed to `sigs`
//! * `tx` is removed
//! *  The `coms` (commitments) array is added, from which the final transaction object can be reconstructed
//! *  The `payment_proof` struct is renamed to `proof`
//! * The feat_args struct is added, which may be populated for non-Plain kernels
//! * `proof` may be omitted from the slate if it is None (null),
//! * `off` (offset) is added, and will be modified by every participant in the transaction with a random
//! value - the value of their inputs' blinding factors
//!
//! #### Participant Data (`sigs`)
//!
//! * `public_blind_excess` is renamed to `xs`
//! * `public_nonce` is renamed to `nonce`
//! * `part_sig` is renamed to `part`
//! * `part` may be omitted if it has not yet been filled out
//! * `xs` becomes Base64 encoded instead of a hex string
//! * `nonce` becomes Base64 encoded instead of a hex string
//! * `part` becomes Base64 encoded instead of a hex string
//! * `message` is removed
//! * `message_sig` is removed
//! * `id` is removed. Parties can identify themselves via the keys stored in their transaction context
//!
//! #### Payment Proof Data (`proof`)
//!
//! *  The `sender_address` field is renamed to `saddr`
//! *  The `receiver_address` field is renamed to `raddr`
//! *  The `receiver_signature` field is renamed to `rsig`
//! * `saddr` is Base64 encoded instead of a hex string
//! * `raddr` is Base64 encoded instead of a hex string
//! * `rsig` is Base64 encoded instead of a hex string
//! * `rsig` may be omitted if it has not yet been filled out

use crate::grin_core::core::transaction::{TokenKey, Transaction};
use crate::grin_core::libtx::secp_ser;
use crate::grin_core::map_vec;
use crate::grin_keychain::{BlindingFactor, Identifier};
use crate::grin_util::secp;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use crate::slate::CompatKernelFeatures;
use crate::slate::CompatTokenKernelFeatures;
use crate::slate_versions::ser;
use crate::{Error, ErrorKind};
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use std::convert::TryFrom;
use uuid::Uuid;

use crate::slate_versions::v3::{ParticipantDataV3, SlateV3, VersionCompatInfoV3};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlateV4 {
	// Required Fields
	/// Versioning info
	#[serde(with = "ser::version_info_v4")]
	pub ver: VersionCompatInfoV4,
	/// Unique transaction ID, selected by sender
	pub id: Uuid,
	/// Slate state
	#[serde(with = "ser::slate_state_v4")]
	pub sta: SlateStateV4,
	/// Offset, modified by each participant inserting inputs
	/// as the transaction progresses
	#[serde(
		serialize_with = "ser::as_base64",
		deserialize_with = "ser::blindingfactor_from_base64"
	)]
	#[serde(default = "default_offset_zero")]
	#[serde(skip_serializing_if = "offset_is_zero")]
	pub off: BlindingFactor,
	// Optional fields depending on state
	/// The number of participants intended to take part in this transaction
	#[serde(default = "default_num_participants_2")]
	#[serde(skip_serializing_if = "num_parts_is_2")]
	pub num_parts: u8,
	/// base amount (excluding fee)
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	#[serde(default = "default_u64_0")]
	pub amt: u64,
	/// tx token type
	#[serde(skip_serializing_if = "Option::is_none")]
	pub token_type: Option<TokenKey>,
	/// fee amount
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(default = "default_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	pub fee: u64,
	/// kernel features, if any
	#[serde(skip_serializing_if = "u8_is_blank")]
	#[serde(default = "default_u8_0")]
	pub feat: u8,
	/// kernel features, if any
	#[serde(skip_serializing_if = "u8_is_blank")]
	#[serde(default = "default_u8_0")]
	pub token_feat: u8,
	/// TTL, the block height at which wallets
	/// should refuse to process the transaction and unlock all
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	#[serde(default = "default_u64_0")]
	pub ttl: u64,
	// Structs always required
	/// Participant data, each participant in the transaction will
	/// insert their public data here. For now, 0 is sender and 1
	/// is receiver, though this will change for multi-party
	pub sigs: Vec<ParticipantDataV4>,
	// Situational, but required at some point in the tx
	/// Inputs/Output commits added to slate
	#[serde(default = "default_coms_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub coms: Option<Vec<CommitsV4>>,
	/// Inputs/Output commits added to slate
	#[serde(default = "default_token_coms_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub token_coms: Option<Vec<TokenCommitsV4>>,
	// Optional Structs
	/// Payment Proof
	#[serde(default = "default_payment_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub proof: Option<PaymentInfoV4>,
	/// Kernel features arguments
	#[serde(default = "default_kernel_features_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub feat_args: Option<KernelFeaturesArgsV4>,
	/// Kernel features arguments
	#[serde(default = "default_kernel_features_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub token_feat_args: Option<KernelFeaturesArgsV4>,
}

fn default_payment_none() -> Option<PaymentInfoV4> {
	None
}

fn default_offset_zero() -> BlindingFactor {
	BlindingFactor::zero()
}

fn offset_is_zero(o: &BlindingFactor) -> bool {
	*o == BlindingFactor::zero()
}

fn default_coms_none() -> Option<Vec<CommitsV4>> {
	None
}

fn default_token_coms_none() -> Option<Vec<TokenCommitsV4>> {
	None
}

fn default_u64_0() -> u64 {
	0
}

fn num_parts_is_2(n: &u8) -> bool {
	*n == 2
}

fn default_num_participants_2() -> u8 {
	2
}

fn default_kernel_features_none() -> Option<KernelFeaturesArgsV4> {
	None
}

/// Slate state definition
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SlateStateV4 {
	/// Unknown, coming from earlier versions of the slate
	Unknown,
	/// Standard flow, freshly init
	Standard1,
	/// Standard flow, return journey
	Standard2,
	/// Standard flow, ready for transaction posting
	Standard3,
	/// Invoice flow, freshly init
	Invoice1,
	///Invoice flow, return journey
	Invoice2,
	/// Invoice flow, ready for tranasction posting
	Invoice3,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Kernel features arguments definition
pub struct KernelFeaturesArgsV4 {
	/// Lock height, for HeightLocked
	pub lock_hgt: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VersionCompatInfoV4 {
	/// The current version of the slate format
	pub version: u16,
	/// Version of grin block header this slate is compatible with
	pub block_header_version: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ParticipantDataV4 {
	/// Public key corresponding to private blinding factor
	#[serde(with = "ser::pubkey_base64")]
	pub xs: PublicKey,
	/// Public key corresponding to private nonce
	#[serde(with = "ser::pubkey_base64")]
	pub nonce: PublicKey,
	/// Public partial signature
	#[serde(default = "default_part_sig_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "ser::option_sig_base64")]
	pub part: Option<Signature>,
}

fn default_part_sig_none() -> Option<Signature> {
	None
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct PaymentInfoV4 {
	#[serde(with = "ser::dalek_pubkey_base64")]
	pub saddr: DalekPublicKey,
	#[serde(with = "ser::dalek_pubkey_base64")]
	pub raddr: DalekPublicKey,
	#[serde(default = "default_receiver_signature_none")]
	#[serde(with = "ser::option_dalek_sig_base64")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub rsig: Option<DalekSignature>,
}

fn default_receiver_signature_none() -> Option<DalekSignature> {
	None
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CommitsV4 {
	/// Options for an output's structure or use
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
	pub f: OutputFeaturesV4,
	/// The homomorphic commitment representing the output amount
	#[serde(
		serialize_with = "ser::as_base64",
		deserialize_with = "ser::commitment_from_base64"
	)]
	pub c: Commitment,
	/// A proof that the commitment is in the right range
	/// Only applies for transaction outputs
	#[serde(with = "ser::option_rangeproof_base64")]
	#[serde(default = "default_range_proof")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p: Option<RangeProof>,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct TokenCommitsV4 {
	pub k: TokenKey,
	/// Options for an token output's structure or use
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
	pub f: OutputFeaturesV4,
	/// The homomorphic commitment representing the output amount
	#[serde(
		serialize_with = "ser::as_base64",
		deserialize_with = "ser::commitment_from_base64"
	)]
	pub c: Commitment,
	/// A proof that the commitment is in the right range
	/// Only applies for transaction outputs
	#[serde(with = "ser::option_rangeproof_base64")]
	#[serde(default = "default_range_proof")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p: Option<RangeProof>,
}

#[derive(Serialize, Deserialize, Copy, Debug, Clone, PartialEq, Eq)]
pub struct OutputFeaturesV4(pub u8);

/// A transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionV4 {
	/// The kernel "offset" k2
	/// excess is k1G after splitting the key k = k1 + k2
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::blind_from_hex"
	)]
	#[serde(default = "default_blinding_factor")]
	#[serde(skip_serializing_if = "blinding_factor_is_zero")]
	pub offset: BlindingFactor,
	/// The transaction body - inputs/outputs/kernels
	pub body: TransactionBodyV4,
}

fn default_blinding_factor() -> BlindingFactor {
	BlindingFactor::zero()
}

fn blinding_factor_is_zero(bf: &BlindingFactor) -> bool {
	*bf == BlindingFactor::zero()
}

/// TransactionBody is a common abstraction for transaction and block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionBodyV4 {
	/// List of inputs spent by the transaction.
	#[serde(default = "default_inputs")]
	#[serde(skip_serializing_if = "inputs_are_empty")]
	pub ins: Vec<InputV4>,
	#[serde(default = "default_token_inputs")]
	#[serde(skip_serializing_if = "token_inputs_are_empty")]
	pub token_ins: Vec<TokenInputV4>,
	/// List of outputs the transaction produces.
	#[serde(default = "default_outputs")]
	#[serde(skip_serializing_if = "outputs_are_empty")]
	pub outs: Vec<OutputV4>,
	/// List of outputs the transaction produces.
	#[serde(default = "default_token_outputs")]
	#[serde(skip_serializing_if = "token_outputs_are_empty")]
	pub token_outs: Vec<TokenOutputV4>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub kers: Vec<TxKernelV4>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub token_kers: Vec<TokenTxKernelV4>,
}

fn inputs_are_empty(v: &Vec<InputV4>) -> bool {
	v.len() == 0
}

fn token_inputs_are_empty(v: &Vec<TokenInputV4>) -> bool {
	v.len() == 0
}

fn default_inputs() -> Vec<InputV4> {
	vec![]
}

fn default_token_inputs() -> Vec<TokenInputV4> {
	vec![]
}

fn outputs_are_empty(v: &Vec<OutputV4>) -> bool {
	v.len() == 0
}

fn token_outputs_are_empty(v: &Vec<TokenOutputV4>) -> bool {
	v.len() == 0
}

fn default_outputs() -> Vec<OutputV4> {
	vec![]
}

fn default_token_outputs() -> Vec<TokenOutputV4> {
	vec![]
}

fn default_range_proof() -> Option<RangeProof> {
	None
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputV4 {
	/// The features of the output being spent.
	/// We will check maturity for coinbase output.
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
	pub features: OutputFeaturesV4,
	/// The commit referencing the output being spent.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct TokenInputV4 {
	/// The features of the output being spent.
	/// We will check maturity for coinbase output.
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
	pub features: OutputFeaturesV4,
	/// Token type
	pub token_type: TokenKey,
	/// The commit referencing the output being spent.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct OutputV4 {
	/// Options for an output's structure or use
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
	pub features: OutputFeaturesV4,
	/// The homomorphic commitment representing the output amount
	#[serde(
		serialize_with = "ser::as_base64",
		deserialize_with = "ser::commitment_from_base64"
	)]
	pub com: Commitment,
	/// A proof that the commitment is in the right range
	#[serde(
		serialize_with = "ser::as_base64",
		deserialize_with = "ser::rangeproof_from_base64"
	)]
	pub prf: RangeProof,
}

fn default_output_feature() -> OutputFeaturesV4 {
	OutputFeaturesV4(0)
}

fn output_feature_is_plain(o: &OutputFeaturesV4) -> bool {
	o.0 == 0
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct TokenOutputV4 {
	/// Options for an output's structure or use
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
	pub features: OutputFeaturesV4,
	/// Token type
	pub token_type: TokenKey,
	/// The homomorphic commitment representing the output amount
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
	/// A proof that the commitment is in the right range
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::rangeproof_from_hex"
	)]
	pub proof: RangeProof,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxKernelV4 {
	/// Options for a kernel's structure or use
	#[serde(default = "default_kernel_feature")]
	#[serde(skip_serializing_if = "kernel_feature_is_plain")]
	pub features: CompatKernelFeatures,
	/// Fee originally included in the transaction this proof is for.
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(default = "default_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	pub fee: u64,
	/// This kernel is not valid earlier than lock_height blocks
	/// The max lock_height of all *inputs* to this transaction
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(default = "default_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	pub lock_height: u64,
	/// Remainder of the sum of all transaction commitments. If the transaction
	/// is well formed, amounts components should sum to zero and the excess
	/// is hence a valid public key.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	#[serde(default = "default_commitment")]
	#[serde(skip_serializing_if = "commitment_is_blank")]
	pub excess: Commitment,
	/// The signature proving the excess is a valid public key, which signs
	/// the transaction fee.
	#[serde(with = "secp_ser::sig_serde")]
	#[serde(default = "default_sig")]
	#[serde(skip_serializing_if = "sig_is_blank")]
	pub excess_sig: secp::Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenTxKernelV4 {
	/// Options for a kernel's structure or use
	#[serde(default = "default_token_kernel_feature")]
	#[serde(skip_serializing_if = "token_kernel_feature_is_plain")]
	pub features: CompatTokenKernelFeatures,
	/// Token type
	pub token_type: TokenKey,
	/// This kernel is not valid earlier than lock_height blocks
	/// The max lock_height of all *inputs* to this transaction
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(default = "default_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	pub lock_height: u64,
	/// Remainder of the sum of all transaction commitments. If the transaction
	/// is well formed, amounts components should sum to zero and the excess
	/// is hence a valid public key.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	#[serde(default = "default_commitment")]
	#[serde(skip_serializing_if = "commitment_is_blank")]
	pub excess: Commitment,
	/// The signature proving the excess is a valid public key, which signs
	/// the transaction fee.
	#[serde(with = "secp_ser::sig_serde")]
	#[serde(default = "default_sig")]
	#[serde(skip_serializing_if = "sig_is_blank")]
	pub excess_sig: secp::Signature,
}

fn default_kernel_feature() -> CompatKernelFeatures {
	CompatKernelFeatures::Plain
}

fn default_token_kernel_feature() -> CompatTokenKernelFeatures {
	CompatTokenKernelFeatures::PlainToken
}

fn kernel_feature_is_plain(k: &CompatKernelFeatures) -> bool {
	match k {
		CompatKernelFeatures::Plain => true,
		_ => false,
	}
}

fn token_kernel_feature_is_plain(k: &CompatTokenKernelFeatures) -> bool {
	match k {
		CompatTokenKernelFeatures::PlainToken => true,
		_ => false,
	}
}

fn default_commitment() -> Commitment {
	Commitment::from_vec([0u8; 1].to_vec())
}

fn commitment_is_blank(c: &Commitment) -> bool {
	for b in c.0.iter() {
		if *b != 0 {
			return false;
		}
	}
	true
}

fn default_sig() -> secp::Signature {
	Signature::from_raw_data(&[0; 64]).unwrap()
}

fn sig_is_blank(s: &secp::Signature) -> bool {
	for b in s.to_raw_data().iter() {
		if *b != 0 {
			return false;
		}
	}
	true
}

fn default_u64() -> u64 {
	0
}

fn u64_is_blank(u: &u64) -> bool {
	*u == 0
}

fn default_u8_0() -> u8 {
	0
}

fn u8_is_blank(u: &u8) -> bool {
	*u == 0
}
/// A mining node requests new coinbase via the foreign api every time a new candidate block is built.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CoinbaseV4 {
	/// Output
	pub output: OutputV4,
	/// Kernel
	pub kernel: TxKernelV4,
	/// Key Id
	pub key_id: Option<Identifier>,
}

// V3 to V4 For Slate
impl From<SlateV3> for SlateV4 {
	fn from(slate: SlateV3) -> SlateV4 {
		let SlateV3 {
			version_info,
			num_participants,
			id,
			tx,
			amount,
			token_type,
			fee,
			height: _,
			lock_height,
			participant_data,
		} = slate.clone();
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV4::from(data));
		let ver = VersionCompatInfoV4::from(&version_info);

		let (feat, feat_args, token_feat, token_feat_args) = match (token_type.clone(), lock_height)
		{
			(None, 0) => (0, None, 0, None),
			(None, n) => (2, Some(KernelFeaturesArgsV4 { lock_hgt: n }), 0, None),
			(Some(_), 0) => (0, None, 0, None),
			(Some(_), n) => (0, None, 2, Some(KernelFeaturesArgsV4 { lock_hgt: n })),
		};
		let token_type = match token_type.clone() {
			Some(a) => Some(TokenKey::from_hex(a.as_str()).unwrap_or(TokenKey::new_zero_key())),
			None => None,
		};
		SlateV4 {
			ver,
			num_parts: num_participants as u8,
			id,
			sta: SlateStateV4::Unknown,
			coms: (&slate).into(),
			token_coms: (&slate).into(),
			amt: amount,
			token_type,
			fee,
			feat,
			token_feat,
			ttl: 0,
			off: tx.offset,
			sigs: participant_data,
			proof: None,
			feat_args,
			token_feat_args,
		}
	}
}

impl From<&SlateV3> for Option<Vec<CommitsV4>> {
	fn from(slate: &SlateV3) -> Option<Vec<CommitsV4>> {
		let mut ret_vec = vec![];
		for i in slate.tx.body.inputs.iter() {
			ret_vec.push(CommitsV4 {
				f: i.features.into(),
				c: i.commit,
				p: None,
			});
		}
		for o in slate.tx.body.outputs.iter() {
			ret_vec.push(CommitsV4 {
				f: o.features.into(),
				c: o.commit,
				p: Some(o.proof),
			});
		}
		Some(ret_vec)
	}
}

impl From<&SlateV3> for Option<Vec<TokenCommitsV4>> {
	fn from(slate: &SlateV3) -> Option<Vec<TokenCommitsV4>> {
		let mut ret_vec = vec![];
		for i in slate.tx.body.token_inputs.iter() {
			ret_vec.push(TokenCommitsV4 {
				k: i.token_type,
				f: i.features.into(),
				c: i.commit,
				p: None,
			});
		}
		for o in slate.tx.body.token_outputs.iter() {
			ret_vec.push(TokenCommitsV4 {
				k: o.token_type,
				f: o.features.into(),
				c: o.commit,
				p: Some(o.proof),
			});
		}
		Some(ret_vec)
	}
}

impl From<&ParticipantDataV3> for ParticipantDataV4 {
	fn from(data: &ParticipantDataV3) -> ParticipantDataV4 {
		let ParticipantDataV3 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		} = data;
		let _id = *id;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		let _message: Option<String> = message.as_ref().map(|t| String::from(&**t));
		let _message_sig = *message_sig;
		ParticipantDataV4 {
			xs: public_blind_excess,
			nonce: public_nonce,
			part: part_sig,
		}
	}
}

impl From<&VersionCompatInfoV3> for VersionCompatInfoV4 {
	fn from(data: &VersionCompatInfoV3) -> VersionCompatInfoV4 {
		let VersionCompatInfoV3 {
			version,
			orig_version,
			block_header_version,
		} = data;
		let version = *version;
		let _orig_version = *orig_version;
		let block_header_version = *block_header_version;
		VersionCompatInfoV4 {
			version,
			block_header_version,
		}
	}
}

// V4 to V3
#[allow(unused_variables)]
impl TryFrom<&SlateV4> for SlateV3 {
	type Error = Error;
	fn try_from(slate: &SlateV4) -> Result<SlateV3, Error> {
		let SlateV4 {
			num_parts: num_participants,
			id,
			sta: _,
			coms,
			token_coms,
			amt: amount,
			token_type,
			fee,
			feat,
			token_feat,
			ttl: ttl_cutoff_height,
			off: offset,
			sigs: participant_data,
			ver,
			proof: payment_proof,
			feat_args,
			token_feat_args,
		} = slate;
		let num_participants = match *num_participants {
			0 => 2,
			n => n,
		};
		let id = *id;
		let amount = *amount;
		let fee = *fee;

		// Match on kernel feature variant:
		// 0: plain
		// 1: coinbase (invalid)
		// 2: height locked (with associated lock_height)
		// 3: NRD (with associated relative_height)
		// Anything else is unknown.
		let lock_height = if token_type.is_some() {
			match token_feat {
				0 => 0,
				1 => return Err(ErrorKind::InvalidTokenKernelFeatures(1).into()),
				2 => match token_feat_args {
					None => {
						return Err(
							ErrorKind::TokenKernelFeaturesMissing("lock_hgt".to_owned()).into()
						)
					}
					Some(h) => h.lock_hgt,
				},
				n => return Err(ErrorKind::UnknownTokenKernelFeatures(*n).into()),
			}
		} else {
			match feat {
				0 => 0,
				1 => return Err(ErrorKind::InvalidKernelFeatures(1).into()),
				2 => match feat_args {
					None => {
						return Err(ErrorKind::KernelFeaturesMissing("lock_hgt".to_owned()).into())
					}
					Some(h) => h.lock_hgt,
				},
				3 => match feat_args {
					None => {
						return Err(ErrorKind::KernelFeaturesMissing("lock_hgt".to_owned()).into())
					}
					Some(h) => h.lock_hgt,
				},
				n => return Err(ErrorKind::UnknownKernelFeatures(*n).into()),
			}
		};

		let participant_data = map_vec!(participant_data, |data| ParticipantDataV3::from(data));
		let version_info = VersionCompatInfoV3::from(ver);
		if *ttl_cutoff_height != 0 {
			return Err(
				ErrorKind::SlateInvalidDowngrade("V3 do not Support TTL".to_owned()).into(),
			);
		}
		if payment_proof.is_some() {
			return Err(ErrorKind::SlateInvalidDowngrade(
				"V3 do not Support Payment Proof".to_owned(),
			)
			.into());
		}
		let token_type = match token_type {
			Some(a) => Some(a.to_hex()),
			None => None,
		};
		let tx: Option<Transaction> = slate.into();
		let tx = match tx {
			Some(t) => Transaction::from(t),
			None => {
				return Err(ErrorKind::SlateInvalidDowngrade(
					"Full transaction info required".to_owned(),
				)
				.into())
			}
		};

		let ttl_cutoff_height = *ttl_cutoff_height;
		Ok(SlateV3 {
			num_participants: num_participants as usize,
			id,
			tx,
			amount,
			token_type,
			fee,
			height: 0,
			lock_height,
			participant_data,
			version_info,
		})
	}
}

impl From<&ParticipantDataV4> for ParticipantDataV3 {
	fn from(data: &ParticipantDataV4) -> ParticipantDataV3 {
		let ParticipantDataV4 {
			xs: public_blind_excess,
			nonce: public_nonce,
			part: part_sig,
		} = data;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		ParticipantDataV3 {
			id: 0,
			public_blind_excess,
			public_nonce,
			part_sig,
			message: None,
			message_sig: None,
		}
	}
}

impl From<&VersionCompatInfoV4> for VersionCompatInfoV3 {
	fn from(data: &VersionCompatInfoV4) -> VersionCompatInfoV3 {
		let VersionCompatInfoV4 {
			version,
			block_header_version,
		} = data;
		let version = *version;
		let orig_version = version;
		let block_header_version = *block_header_version;
		VersionCompatInfoV3 {
			version,
			orig_version,
			block_header_version,
		}
	}
}
