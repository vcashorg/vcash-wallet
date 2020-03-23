// Copyright 2018 The Grin Developers
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
//! Functions to restore a wallet's outputs from just the master seed

use crate::api_impl::owner_updater::StatusMessage;
use crate::grin_core::libtx::proof;
use crate::grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::pedersen;
use crate::grin_util::Mutex;
use crate::internal::{keys, updater};
use crate::types::*;
use crate::{wallet_lock, Error, TokenOutputCommitMapping};
use std::cmp;
use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::sync::Arc;

/// Utility struct for return values from below
#[derive(Clone)]
struct TokenOutputResult {
	///
	pub commit: pedersen::Commitment,
	///
	pub token_type: String,
	///
	pub key_id: Identifier,
	///
	pub n_child: u32,
	///
	pub mmr_index: u64,
	///
	pub value: u64,
	///
	pub height: u64,
	///
	pub lock_height: u64,
	///
	pub is_token_issue: bool,
}

#[derive(Debug, Clone)]
/// Collect stats in case we want to just output a single tx log entry
/// for restored non-coinbase outputs
struct RestoredTxStats {
	///
	pub log_id: u32,
	///
	pub amount_credited: u64,
	///
	pub num_outputs: usize,
}

fn identify_utxo_token_outputs<'a, K>(
	keychain: &K,
	outputs: Vec<(
		pedersen::Commitment,
		pedersen::RangeProof,
		String,
		bool,
		u64,
		u64,
	)>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	percentage_complete: u8,
) -> Result<Vec<TokenOutputResult>, Error>
where
	K: Keychain + 'a,
{
	let mut wallet_outputs: Vec<TokenOutputResult> = Vec::new();

	let msg = format!(
		"Scanning {} token outputs in the current VCash utxo set",
		outputs.len(),
	);
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::Scanning(msg, percentage_complete));
	}

	let builder = proof::ProofBuilder::new(keychain);

	for output in outputs.iter() {
		let (commit, proof, token_type, is_token_issue, height, mmr_index) = output;
		// attempt to unwind message from the RP and get a value
		// will fail if it's not ours
		let info = { proof::rewind(keychain.secp(), &builder, *commit, None, *proof)? };

		let (amount, key_id, switch) = match info {
			Some(i) => i,
			None => {
				continue;
			}
		};

		if switch != SwitchCommitmentType::Regular {
			let msg = format!("Unexpected switch commitment type {:?}", switch);
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::UpdateWarning(msg));
			}
		}

		wallet_outputs.push(TokenOutputResult {
			commit: *commit,
			token_type: token_type.clone(),
			key_id: key_id.clone(),
			n_child: key_id.to_path().last_path_index(),
			value: amount,
			height: *height,
			lock_height: *height,
			is_token_issue: *is_token_issue,
			mmr_index: *mmr_index,
		});
	}
	Ok(wallet_outputs)
}

fn collect_chain_token_outputs<'a, C, K>(
	keychain: &K,
	client: C,
	start_index: u64,
	end_index: Option<u64>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<(Vec<TokenOutputResult>, u64), Error>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let batch_size = 1000;
	let start_index_stat = start_index;
	let mut start_index = start_index;
	let mut result_vec: Vec<TokenOutputResult> = vec![];
	let last_retrieved_return_index;
	loop {
		let (highest_index, last_retrieved_index, outputs) =
			client.get_token_outputs_by_pmmr_index(start_index, end_index, batch_size)?;

		let range = highest_index as f64 - start_index_stat as f64;
		let progress = last_retrieved_index as f64 - start_index_stat as f64;
		let perc_complete = cmp::min(((progress / range) * 100.0) as u8, 99);

		let msg = format!(
			"Checking {} token outputs, up to index {}. (Highest index: {})",
			outputs.len(),
			highest_index,
			last_retrieved_index,
		);
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Scanning(msg, perc_complete));
		}

		result_vec.append(&mut identify_utxo_token_outputs(
			keychain,
			outputs.clone(),
			status_send_channel,
			perc_complete as u8,
		)?);

		if highest_index <= last_retrieved_index {
			last_retrieved_return_index = last_retrieved_index;
			break;
		}
		start_index = last_retrieved_index + 1;
	}
	Ok((result_vec, last_retrieved_return_index))
}

///
fn restore_missing_token_output<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	output: TokenOutputResult,
	found_parents: &mut HashMap<Identifier, u32>,
	tx_stats: &mut Option<&mut HashMap<Identifier, HashMap<String, RestoredTxStats>>>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	let commit = w.calc_commit_for_cache(keychain_mask, output.value, &output.key_id)?;
	let mut batch = w.batch(keychain_mask)?;

	let parent_key_id = output.key_id.parent_path();
	if !found_parents.contains_key(&parent_key_id) {
		found_parents.insert(parent_key_id.clone(), 0);
		if let Some(ref mut s) = tx_stats {
			s.insert(parent_key_id.clone(), HashMap::new());
		}
	}

	let token_type = output.token_type.clone();

	let log_id = if tx_stats.is_none() || output.is_token_issue {
		let log_id = batch.next_tx_log_id(&parent_key_id)?;
		let entry_type = match output.is_token_issue {
			true => TokenTxLogEntryType::TokenIssue,
			false => TokenTxLogEntryType::TokenTxReceived,
		};
		let mut t = TokenTxLogEntry::new(parent_key_id.clone(), entry_type, log_id);
		t.confirmed = true;
		t.token_type = token_type;
		t.token_amount_credited = output.value;
		t.num_token_outputs = 1;
		t.update_confirmation_ts();
		batch.save_token_tx_log_entry(t, &parent_key_id)?;
		log_id
	} else if let Some(ref mut s) = tx_stats {
		let mut key_map = s.get(&parent_key_id).unwrap().clone();
		let ts = key_map
			.entry(token_type.clone())
			.or_insert(RestoredTxStats {
				log_id: batch.next_tx_log_id(&parent_key_id)?,
				amount_credited: 0,
				num_outputs: 0,
			});
		ts.num_outputs += 1;
		ts.amount_credited += output.value;
		ts.log_id
	} else {
		0
	};

	let _ = batch.save_token(TokenOutputData {
		root_key_id: parent_key_id.clone(),
		key_id: output.key_id,
		n_child: output.n_child,
		mmr_index: Some(output.mmr_index),
		commit: commit,
		token_type: output.token_type,
		value: output.value,
		status: OutputStatus::Unspent,
		height: output.height,
		lock_height: output.lock_height,
		is_token_issue: output.is_token_issue,
		tx_log_entry: Some(log_id),
	});

	let max_child_index = *found_parents.get(&parent_key_id).unwrap();
	if output.n_child >= max_child_index {
		found_parents.insert(parent_key_id, output.n_child);
	}

	batch.commit()?;
	Ok(())
}

///
fn cancel_token_tx_log_entry<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	output: &TokenOutputData,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = output.key_id.parent_path();
	wallet_lock!(wallet_inst, w);
	let updated_tx_entry = if output.tx_log_entry.is_some() {
		let entries = updater::retrieve_token_txs(
			&mut **w,
			output.tx_log_entry,
			None,
			Some(&parent_key_id),
			false,
		)?;
		if !entries.is_empty() {
			let mut entry = entries[0].clone();
			match entry.tx_type {
				TokenTxLogEntryType::TokenTxSent => {
					entry.tx_type = TokenTxLogEntryType::TokenTxSentCancelled
				}
				TokenTxLogEntryType::TokenTxReceived => {
					entry.tx_type = TokenTxLogEntryType::TokenTxReceivedCancelled
				}
				_ => {}
			}
			Some(entry)
		} else {
			None
		}
	} else {
		None
	};
	let mut batch = w.batch(keychain_mask)?;
	if let Some(t) = updated_tx_entry {
		batch.save_token_tx_log_entry(t, &parent_key_id)?;
	}
	batch.commit()?;
	Ok(())
}

/// Check / repair wallet contents
/// assume wallet contents have been freshly updated with contents
/// of latest block
pub fn token_scan<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	delete_unconfirmed: bool,
	start_height: u64,
	end_height: u64,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<ScannedBlockInfo, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// First, get a definitive list of outputs we own from the chain
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::Scanning(
			"Starting Token UTXO scan".to_owned(),
			0,
		));
	}
	let (client, keychain) = {
		wallet_lock!(wallet_inst, w);
		(w.w2n_client().clone(), w.keychain(keychain_mask)?)
	};

	// Retrieve the actual PMMR index range we're looking for
	let pmmr_range = client.height_range_to_token_pmmr_indices(start_height, Some(end_height))?;

	let (chain_outs, last_index) = collect_chain_token_outputs(
		&keychain,
		client,
		pmmr_range.0,
		Some(pmmr_range.1),
		status_send_channel,
	)?;
	let msg = format!(
		"Identified {} token wallet_outputs as belonging to this wallet",
		chain_outs.len(),
	);

	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::Scanning(msg, 99));
	}

	// Now, get all outputs owned by this wallet (regardless of account)
	let wallet_outputs = {
		wallet_lock!(wallet_inst, w);
		let res = updater::retrieve_token_outputs(&mut **w, keychain_mask, true, None, None)?;
		res
	};

	let mut missing_outs = vec![];
	let mut accidental_spend_outs = vec![];
	let mut locked_outs = vec![];

	// check all definitive outputs exist in the wallet outputs
	for deffo in chain_outs.into_iter() {
		let matched_out = wallet_outputs.iter().find(|wo| wo.commit == deffo.commit);
		match matched_out {
			Some(s) => {
				if s.output.status == OutputStatus::Spent {
					accidental_spend_outs.push((s.output.clone(), deffo.clone()));
				}
				if s.output.status == OutputStatus::Locked {
					locked_outs.push((s.output.clone(), deffo.clone()));
				}
			}
			None => missing_outs.push(deffo),
		}
	}

	// mark problem spent outputs as unspent (confirmed against a short-lived fork, for example)
	for m in accidental_spend_outs.into_iter() {
		let mut o = m.0;
		let msg = format!(
			"Token Output for {} with ID {} ({:?}) marked as spent but exists in UTXO set. \
			 Marking unspent and cancelling any associated transaction log entries.",
			o.value, o.key_id, m.1.commit,
		);
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Scanning(msg, 99));
		}
		o.status = OutputStatus::Unspent;
		// any transactions associated with this should be cancelled
		cancel_token_tx_log_entry(wallet_inst.clone(), keychain_mask, &o)?;
		wallet_lock!(wallet_inst, w);
		let mut batch = w.batch(keychain_mask)?;
		batch.save_token(o)?;
		batch.commit()?;
	}

	let mut found_parents: HashMap<Identifier, u32> = HashMap::new();

	// Restore missing outputs, adding transaction for it back to the log
	for m in missing_outs.into_iter() {
		let msg = format!(
			"Confirmed token output: token type:{}  amount:{} with ID {} ({:?}) exists in UTXO set but not in wallet. \
			 Restoring.",
			m.token_type, m.value, m.key_id, m.commit,
		);
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Scanning(msg, 99));
		}
		restore_missing_token_output(
			wallet_inst.clone(),
			keychain_mask,
			m,
			&mut found_parents,
			&mut None,
		)?;
	}

	if delete_unconfirmed {
		// Unlock locked outputs
		for m in locked_outs.into_iter() {
			let mut o = m.0;
			let msg = format!(
				"Confirmed token output for {} with ID {} ({:?}) exists in UTXO set and is locked. \
				 Unlocking and cancelling associated transaction log entries.",
				o.value, o.key_id, m.1.commit,
			);
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::Scanning(msg, 99));
			}
			o.status = OutputStatus::Unspent;
			cancel_token_tx_log_entry(wallet_inst.clone(), keychain_mask, &o)?;
			wallet_lock!(wallet_inst, w);
			let mut batch = w.batch(keychain_mask)?;
			batch.save_token(o)?;
			batch.commit()?;
		}

		let unconfirmed_outs: Vec<&TokenOutputCommitMapping> = wallet_outputs
			.iter()
			.filter(|o| o.output.status == OutputStatus::Unconfirmed)
			.collect();
		// Delete unconfirmed outputs
		for m in unconfirmed_outs.into_iter() {
			let o = m.output.clone();
			let msg = format!(
				"Unconfirmed output for {} with ID {} ({:?}) not in UTXO set. \
				 Deleting and cancelling associated transaction log entries.",
				o.value, o.key_id, m.commit,
			);
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::Scanning(msg, 99));
			}
			cancel_token_tx_log_entry(wallet_inst.clone(), keychain_mask, &o)?;
			wallet_lock!(wallet_inst, w);
			let mut batch = w.batch(keychain_mask)?;
			batch.delete(&o.key_id, &o.mmr_index)?;
			batch.commit()?;
		}
	}

	// restore labels, account paths and child derivation indices
	wallet_lock!(wallet_inst, w);
	let label_base = "account";
	let accounts: Vec<Identifier> = w.acct_path_iter().map(|m| m.path).collect();
	let mut acct_index = accounts.len();
	for (path, max_child_index) in found_parents.iter() {
		// Only restore paths that don't exist
		if !accounts.contains(path) {
			let label = format!("{}_{}", label_base, acct_index);
			let msg = format!("Setting account {} at path {}", label, path);
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::Scanning(msg, 99));
			}
			keys::set_acct_path(&mut **w, keychain_mask, &label, path)?;
			acct_index += 1;
		}
		let current_child_index = w.current_child_index(&path)?;
		if *max_child_index >= current_child_index {
			let mut batch = w.batch(keychain_mask)?;
			debug!("Next child for account {} is {}", path, max_child_index + 1);
			batch.save_child_index(path, max_child_index + 1)?;
			batch.commit()?;
		}
	}

	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::ScanningComplete(
			"Token Scanning Complete".to_owned(),
		));
	}

	Ok(ScannedBlockInfo {
		height: end_height,
		hash: "".to_owned(),
		start_pmmr_index: pmmr_range.0,
		last_pmmr_index: last_index,
	})
}
