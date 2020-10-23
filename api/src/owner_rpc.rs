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

//! JSON-RPC Stub generation for the Owner API
use uuid::Uuid;

use crate::config::{TorConfig, WalletConfig};
use crate::core::global;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::{
	AcctPathMapping, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient, NodeHeightResult,
	OutputCommitMapping, PaymentProof, Slate, SlateVersion, Slatepack, SlatepackAddress,
	StatusMessage, TxLogEntry, VersionedSlate, WalletInfo, WalletLCProvider,
};
use crate::util::logger::LoggingConfig;
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::{static_secp_instance, Mutex, ZeroingString};
use crate::{ECDHPubkey, Ed25519SecretKey, Owner, Token};
use easy_jsonrpc_mw;
use grin_wallet_util::OnionV3Address;
use rand::thread_rng;
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Duration;

/// Public definition used to generate Owner jsonrpc api.
/// Secure version containing wallet lifecycle functions. All calls to this API must be encrypted.
/// See [`init_secure_api`](#tymethod.init_secure_api) for details of secret derivation
/// and encryption.

#[easy_jsonrpc_mw::rpc]
pub trait OwnerRpc {
	/**
	Networked version of [Owner::accounts](struct.Owner.html#method.accounts).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				{
					"label": "default",
					"path": "0200000000000000000000000000000000"
				}
			]
		},
		"id": 1
	}
	# "#
	# , 4, false, false, false, false);
	```
	*/
	fn accounts(&self, token: Token) -> Result<Vec<AcctPathMapping>, ErrorKind>;

	/**
	Networked version of [Owner::create_account_path](struct.Owner.html#method.create_account_path).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_account_path",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"label": "account1"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": "0200000001000000000000000000000000"
		},
		"id": 1
	}
	# "#
	# , 4, false, false, false, false);
	```
	 */
	fn create_account_path(&self, token: Token, label: &String) -> Result<Identifier, ErrorKind>;

	/**
	Networked version of [Owner::set_active_account](struct.Owner.html#method.set_active_account).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_active_account",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"label": "default"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		},
		"id": 1
	}
	# "#
	# , 4, false, false, false, false);
	```
	 */
	fn set_active_account(&self, token: Token, label: &String) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_outputs](struct.Owner.html#method.retrieve_outputs).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_outputs",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"include_spent": false,
			"refresh_from_node": true,
			"tx_id": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				[
					{
						"commit": "083fbf6c559dd0d0220a155afcdd99c1320b56681d4dbfb7d0cd4f92b28f79c60b",
						"output": {
							"commit": "083fbf6c559dd0d0220a155afcdd99c1320b56681d4dbfb7d0cd4f92b28f79c60b",
							"height": "1",
							"is_coinbase": true,
							"key_id": "0300000000000000000000000000000000",
							"lock_height": "4",
							"mmr_index": null,
							"n_child": 0,
							"root_key_id": "0200000000000000000000000000000000",
							"status": "Unspent",
							"tx_log_entry": 0,
							"value": "50000000000"
						}
					},
					{
						"commit": "095a9fd054e3f5d63302c8e1d44e14be686b363b542204207f8db5958ac69aede2",
						"output": {
							"commit": "095a9fd054e3f5d63302c8e1d44e14be686b363b542204207f8db5958ac69aede2",
							"height": "2",
							"is_coinbase": true,
							"key_id": "0300000000000000000000000100000000",
							"lock_height": "5",
							"mmr_index": null,
							"n_child": 1,
							"root_key_id": "0200000000000000000000000000000000",
							"status": "Unspent",
							"tx_log_entry": 1,
							"value": "50000000000"
						}
					}
				]
			]
		}
	}
	# "#
	# , 2, false, false, false, false);
	```
	*/
	fn retrieve_outputs(
		&self,
		token: Token,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_txs](struct.Owner.html#method.retrieve_txs).

	# Json rpc example

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "retrieve_txs",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"refresh_from_node": true,
				"tx_id": null,
				"tx_slate_id": null
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
		"jsonrpc": "2.0",
	  "result": {
		"Ok": [
		  true,
		  [
			{
			  "amount_credited": "50000000000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-01-15T16:01:26Z",
			  "confirmed": true,
			  "creation_ts": "2019-01-15T16:01:26Z",
			  "fee": null,
			  "id": 0,
			  "kernel_excess": "08d665d28da3da9b1ebd88b1572208f069f4c7d16bfe9ba5c159caea9ab42edaf8",
			  "kernel_lookup_min_height": 1,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "ttl_cutoff_height": null,
			  "tx_slate_id": null,
			  "payment_proof": null,
			  "reverted_after": null,
			  "tx_type": "ConfirmedCoinbase"
			},
			{
			  "amount_credited": "50000000000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-01-15T16:01:26Z",
			  "confirmed": true,
			  "creation_ts": "2019-01-15T16:01:26Z",
			  "fee": null,
			  "id": 1,
			  "kernel_excess": "092e8ed0e28bf524ed0349f444a0d307dce47bfbd93bf12c2f5b005410f10c4c80",
			  "kernel_lookup_min_height": 2,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "ttl_cutoff_height": null,
			  "payment_proof": null,
			  "reverted_after": null,
			  "tx_slate_id": null,
			  "tx_type": "ConfirmedCoinbase"
			}
		  ]
		]
	  }
	}
	# "#
	# , 2, false, false, false, false);
	```
	*/

	fn retrieve_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_summary_info](struct.Owner.html#method.retrieve_summary_info).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_summary_info",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"refresh_from_node": true,
			"minimum_confirmations": 1
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
	"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				{
					"amount_awaiting_confirmation": "0",
					"amount_awaiting_finalization": "0",
					"amount_currently_spendable": "50000000000",
					"amount_immature": "150000000000",
					"amount_locked": "0",
					"amount_reverted": "0",
					"last_confirmed_height": "4",
					"minimum_confirmations": "1",
					"token_infos": [],
					"total": "200000000000"
				}
			]
		}
	}
	# "#
	# , 4, false, false, false, false);
	```
	 */

	fn retrieve_summary_info(
		&self,
		token: Token,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind>;

	/**
		Networked version of [Owner::init_send_tx](struct.Owner.html#method.init_send_tx).

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "init_send_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"args": {
					"src_acct_name": null,
					"amount": "6000000000",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy_is_use_all": true,
					"target_slate_version": null,
					"payment_proof_recipient_address": "tvcash10qlk22rxjap2ny8qltc2tl996kenxr3hhwuu6hrzs6tdq08yaqgqnrsy2l",
					"ttl_blocks": null,
					"send_args": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
			"jsonrpc": "2.0",
			"result": {
				"Ok": {
					"amt": "6000000000",
					"fee": "8000000",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"off": "d202964900000000d302964900000000d402964900000000d502964900000000",
					"proof": {
						"raddr": "783f6528669742a990e0faf0a5fca5d5b3330e37bbb9cd5c628696d03ce4e810",
						"saddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
					},
					"sigs": [
						{
							"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
							"xs": "02e050f9d3279b87d6513d218c3a254ef94c8d3733c77f81cf41422b0d36370e38"
						}
					],
					"sta": "S1",
					"ver": "4:2"
				}
			}
		}
		# "#
		# , 4, false, false, false, false);
	```
	*/

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind>;

	/**
		Networked version of [Owner::issue_invoice_tx](struct.Owner.html#method.issue_invoice_tx).

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "issue_invoice_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"args": {
					"amount": "6000000000",
					"dest_acct_name": null,
					"target_slate_version": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
			"id": 1,
			"jsonrpc": "2.0",
			"result": {
				"Ok": {
					"amt": "6000000000",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"off": "d202964900000000d302964900000000d402964900000000d502964900000000",
					"sigs": [
						{
							"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
							"xs": "028e95921cc0d5be5922362265d352c9bdabe51a9e1502a3f0d4a10387f1893f40"
						}
					],
					"sta": "I1",
					"ver": "4:2"
				}
			}
		}
		# "#
		# , 4, false, false, false, false);
	```
	*/

	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, ErrorKind>;

	/**
		 Networked version of [Owner::process_invoice_tx](struct.Owner.html#method.process_invoice_tx).

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "process_invoice_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"slate": {
					"amt": "6000000000",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"off": "d202964900000000d302964900000000d402964900000000d502964900000000",
					"sigs": [
						{
							"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
							"xs": "028e95921cc0d5be5922362265d352c9bdabe51a9e1502a3f0d4a10387f1893f40"
						}
					],
					"sta": "I1",
					"ver": "4:3"
				},
				"args": {
					"src_acct_name": null,
					"amount": "0",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy_is_use_all": true,
					"target_slate_version": null,
					"payment_proof_recipient_address": null,
					"ttl_blocks": null,
					"send_args": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"coms": [
					{
						"c": "083fbf6c559dd0d0220a155afcdd99c1320b56681d4dbfb7d0cd4f92b28f79c60b",
						"f": 1
					},
					{
						"c": "09f9a5605b2e5c7697ab8a6e5ca125e2feaed1c32294487771bb3e544a20847178",
						"p": "3f8b73a2d8de4737f8dca50f92e3e63cacc4bdf6fd4f65d05f6b9db4625e5a644c4300609b0283d87bb01b50864345f150689e66d1661ea59a8d55b63a45600f069496337e619e343ed238fd54563abcb77e38c924fdb628f9eb1b70e7b72d673db33872557142e04831402bbb2449deb070dddf0c4e04e77b3039d0d98de9ec5cabe95203563cc3919efe2e353348e560a948e361e3b05e76f80a6b1b672a3cc138d7891460b105b03f102cc962a0e554a07d725c35b3a93591249efdab2758077d0b8b192bbd8ca5393d8668d7eab02ee98c3441368b698ac558bceafa59f9d85a9b6b308023ae3263188a8cb535c180527ab6db19cf10d78e1e7d2d9eaa019d58b0068f4e3339922d3227cdd5a64fed640d47c47aa6ef03952ff8a394b125989084826fdf10cd731e0a22d9f6b309ef93c3eece89012abd97b479ba3c2f903610ee8d8086e476e81a68c41ba9010e223335d3a8c2744f56e4f1e0b070137650fc00ac33fbc35f80b7d709d4d24ae83a751cd2166ad9201d3d9054732b8c4e92bf32f9a1b7d149cfc32a2bc182ac4f8a95b27437eadcee6b7a4f74e635664e3f1715aad770115a8c0fe8c02176c3141e9a0a42b457f299f7546699419ccb2c02f7e52f3aebbbafb3dd06988113de6fbb6c534ede51886def92e64d24515984b9856a74410d769d80e30bccb69fb7663ef5a9fc38bcaa94ed3b9125a929f2c148336e03b8a35e073c86b8fb4cec559099604b325f4d77bc8ff55438e0fc9a13140eafbf116b803f33415f6f29ada0d400d508ca2804cd99157319d7c7186239fa61702c49b65fecf89ddd868efee7a90a5bfe2f587cd4256438763cedb3211e034bc15fcb76a3ad023f93883625ff81a52d2da5615cbb1bdb25dfb74d76289e98b27bf21d952e527a90b4c0add77a5eb901a15dcbf854f8b2dd0e99bc4819645e94b8"
					}
				],
				"fee": "8000000",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"off": "dbbb4697d03fe627370797ae2d37c18a8c9e47cef3a43da86881b542f0f1802a",
				"sigs": [
					{
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b24aa6e973189e4f62d0ef5d5ba8ce78de018967f2062c2b3285b3649cd3f76a0",
						"xs": "02e050f9d3279b87d6513d218c3a254ef94c8d3733c77f81cf41422b0d36370e38"
					}
				],
				"sta": "I2",
				"token_coms": [],
				"ver": "4:3"
			}
		}
	}
	# "#
	# , 4, false, false, false, false);
	```
	*/

	fn process_invoice_tx(
		&self,
		token: Token,
		slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::tx_lock_outputs](struct.Owner.html#method.tx_lock_outputs).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "tx_lock_outputs",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate": {
				"ver": "4:3",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"sta": "S1",
				"off": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"amt": "60000000000",
				"fee": "7000000",
				"sigs": [
					{
						"xs": "030152d2d72e2dba7c6086ad49a219d9ff0dfe0fd993dcaea22e058c210033ce93",
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				]
			}
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5 ,true, false, false, false);

	```
	 */
	fn tx_lock_outputs(&self, token: Token, slate: VersionedSlate) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::finalize_tx](struct.Owner.html#method.finalize_tx).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate":
			{
				"ver": "4:3",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"sta": "S2",
				"off": "a4052c9200000001a6052c9200000002ed564fab50b75fc5ea32ce052fc9bebf",
				"sigs": [
					{
						"xs": "033bbe2a419ea2e9d6810a8d66552e709d1783ca50759a44dbaf63fc79c0164c4c",
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b977dd98be29307b0fd322cff40437730a1007c7c0e7d0a2f05493531d1587812"
					}
				],
				"coms": [
					{
						"c": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
						"p": "29701ceae262cac77b79b868c883a292e61e6de8192b868edcd1300b0973d91396b156ace6bd673402a303de10ddd8a5e6b7f17ba6557a574a672bd04cc273ab04ed8e2ca80bac483345c0ec843f521814ce1301ec9adc38956a12b4d948acce71295a4f52bcdeb8a1c9f2d6b2da5d731262a5e9c0276ef904df9ef8d48001420cd59f75a2f1ae5c7a1c7c6b9f140e7613e52ef9e249f29f9340b7efb80699e460164324616f98fd4cde3db52497c919e95222fffeacb7e65deca7e368a80ce713c19de7da5369726228ee336f5bd494538c12ccbffeb1b9bfd5fc8906d1c64245b516f103fa96d9c56975837652c1e0fa5803d7ccf1147d8f927e36da717f7ad79471dbe192f5f50f87a79fc3fe030dba569b634b92d2cf307993cce545633af263897cd7e6ebf4dcafb176d07358bdc38d03e45a49dfa9c8c6517cd68d167ffbf6c3b4de0e2dd21909cbad4c467b84e5700be473a39ac59c669d7c155c4bcab9b8026eea3431c779cd277e4922d2b9742e1f6678cbe869ec3b5b7ef4132ddb6cdd06cf27dbeb28be72b949fa897610e48e3a0d789fd2eea75abc97b3dc7e00e5c8b3d24e40c6f24112adb72352b89a2bef0599345338e9e76202a3c46efa6370952b2aca41aadbae0ea32531acafcdab6dd066d769ebf50cf4f3c0a59d2d5fa79600a207b9417c623f76ad05e8cccfcd4038f9448bc40f127ca7c0d372e46074e334fe49f5a956ec0056f4da601e6af80eb1a6c4951054869e665b296d8c14f344ca2dc5fdd5df4a3652536365a1615ad9b422165c77bf8fe65a835c8e0c41e070014eb66ef8c525204e990b3a3d663c1e42221b496895c37a2f0c1bf05e91235409c3fe3d89a9a79d6c78609ab18a463311911f71fa37bb73b15fcd38143d1404fd2ce81004dc7ff89cf1115dcc0c35ce1c1bf9941586fb959770f2618ccb7118a7"
					}
				],
				"token_coms": []
			}
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": {
				"coms": [
					{
						"c": "095a9fd054e3f5d63302c8e1d44e14be686b363b542204207f8db5958ac69aede2",
						"f": 1
					},
					{
						"c": "083fbf6c559dd0d0220a155afcdd99c1320b56681d4dbfb7d0cd4f92b28f79c60b",
						"f": 1
					},
					{
						"c": "0878211b9c19f8cdaea542c24d9a248adb7b576e316cd21984cd183f2591baf613",
						"p": "9fac84b36daaadf5cecfdccbf3ac7aab6b31f7cb4e067aabd5c63f250d73fb0aa73255ee05d06c616e8358e88a19df66ea809027bee4e2f75ae76cc606707de40335063851c2566afa5ffcdda997669b074fe3b66e1f969e4f11b37968c05d0d7457183f4e07632a255d1666e750ad2ef3cb224c78adface67168276237ac9435892e2fe888664c53a49f4aaf63bd8bebbc777a844bec7e73d1f30cd22511a40ee5fc1ae1fe41466910f5298d41b47470aa6dcffd1322c8809419196c1df7c16fb5282221da80133ff945701a3d8805176a0f18233fa8a900e104be8c8419e1e3e9692771ff8444144ad093e1f64cc1684120fc5495b3ff0cc9bca11ca89fa15b5c94e0c852016a3507667da6e3aed2dddfb8a875beb7ce1e321f0c3bfb8a977ac302ee14c1061284f3b2a0409df52e3a7214da371014767daeee0b91e8966efa6e6e259e036f0ce3d089ee0f4af563da829bbd9a4106a0c2a9093def0d91da42df7011eaef24c2be1cd8fac9af49ec7c69f911653ca217faa0ef895ced28f823c469b9430bc04d4ab628d7d4e6cd65a8dd7a314313666f0b12f2d2e6f48a8b18e4f95f56efe51fa09e634df480da8e9856079d4dd24c666b8e08b7b4bace91787248f65f13ff42ea61223dedf9a0da7ee5051f30fac94728179be4cbf762b308e7bbee19fa1a905195a9de6d72b9e964cae1b0b4f95a78174e8368068c83d2e4d73951ead186ed2110c4427a4039e17cd77c2d6c51de430fcd34542b996628a339e21d66f7a9a9b5c98a8a81a9e7508f8ab03c4aef09919798fc4d722c1d81556ecc9a5cd1cf972a4dc6d60ea619174f8404daddefc8d03b229793f8208308885719b91d359e4ee94e57b0f69b76e5f500f13739b1dd79470f55bde81f6683d26a6c2e6aee6a26b29579c380426b6c6914906b93bd272d36eaea192b0e4454a06f68b"
					},
					{
						"c": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
						"p": "29701ceae262cac77b79b868c883a292e61e6de8192b868edcd1300b0973d91396b156ace6bd673402a303de10ddd8a5e6b7f17ba6557a574a672bd04cc273ab04ed8e2ca80bac483345c0ec843f521814ce1301ec9adc38956a12b4d948acce71295a4f52bcdeb8a1c9f2d6b2da5d731262a5e9c0276ef904df9ef8d48001420cd59f75a2f1ae5c7a1c7c6b9f140e7613e52ef9e249f29f9340b7efb80699e460164324616f98fd4cde3db52497c919e95222fffeacb7e65deca7e368a80ce713c19de7da5369726228ee336f5bd494538c12ccbffeb1b9bfd5fc8906d1c64245b516f103fa96d9c56975837652c1e0fa5803d7ccf1147d8f927e36da717f7ad79471dbe192f5f50f87a79fc3fe030dba569b634b92d2cf307993cce545633af263897cd7e6ebf4dcafb176d07358bdc38d03e45a49dfa9c8c6517cd68d167ffbf6c3b4de0e2dd21909cbad4c467b84e5700be473a39ac59c669d7c155c4bcab9b8026eea3431c779cd277e4922d2b9742e1f6678cbe869ec3b5b7ef4132ddb6cdd06cf27dbeb28be72b949fa897610e48e3a0d789fd2eea75abc97b3dc7e00e5c8b3d24e40c6f24112adb72352b89a2bef0599345338e9e76202a3c46efa6370952b2aca41aadbae0ea32531acafcdab6dd066d769ebf50cf4f3c0a59d2d5fa79600a207b9417c623f76ad05e8cccfcd4038f9448bc40f127ca7c0d372e46074e334fe49f5a956ec0056f4da601e6af80eb1a6c4951054869e665b296d8c14f344ca2dc5fdd5df4a3652536365a1615ad9b422165c77bf8fe65a835c8e0c41e070014eb66ef8c525204e990b3a3d663c1e42221b496895c37a2f0c1bf05e91235409c3fe3d89a9a79d6c78609ab18a463311911f71fa37bb73b15fcd38143d1404fd2ce81004dc7ff89cf1115dcc0c35ce1c1bf9941586fb959770f2618ccb7118a7"
					}
				],
				"fee": "7000000",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"off": "d143cbb0533b855eb509b29ce4510d04655b631b141961180a7d1bc435074c06",
				"sigs": [
					{
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b977dd98be29307b0fd322cff40437730a1007c7c0e7d0a2f05493531d1587812",
						"xs": "033bbe2a419ea2e9d6810a8d66552e709d1783ca50759a44dbaf63fc79c0164c4c"
					},
					{
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bd45d2dd4d6895d612b3c7e5a7fca80dd9214c77cec7c500b36ecac0f93e4124f",
						"xs": "035451e65b8b7987ff485785c2d32e278fa45c4bdd5a70d944c714e4a75048dd68"
					}
				],
				"sta": "S3",
				"token_coms": [],
				"ver": "4:3"
			}
		}
	}
	# "#
	# , 5, true, true, false, false);
	```
	 */
	fn finalize_tx(&self, token: Token, slate: VersionedSlate)
		-> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::post_tx](struct.Owner.html#method.post_tx).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "post_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate": {
				"ver": "4:2",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"sta": "S3",
				"off": "d143cbb0533b855eb509b29ce4510d04655b631b141961180a7d1bc435074c06",
				"fee": "7000000",
				"sigs": [
					{
						"xs": "033bbe2a419ea2e9d6810a8d66552e709d1783ca50759a44dbaf63fc79c0164c4c",
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b977dd98be29307b0fd322cff40437730a1007c7c0e7d0a2f05493531d1587812"
					},
					{
						"xs": "035451e65b8b7987ff485785c2d32e278fa45c4bdd5a70d944c714e4a75048dd68",
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bd45d2dd4d6895d612b3c7e5a7fca80dd9214c77cec7c500b36ecac0f93e4124f"
					}
				],
				"coms": [
					{
						"f": 1,
						"c": "095a9fd054e3f5d63302c8e1d44e14be686b363b542204207f8db5958ac69aede2"
					},
					{
						"f": 1,
						"c": "083fbf6c559dd0d0220a155afcdd99c1320b56681d4dbfb7d0cd4f92b28f79c60b"
					},
					{
						"c": "0878211b9c19f8cdaea542c24d9a248adb7b576e316cd21984cd183f2591baf613",
						"p": "9fac84b36daaadf5cecfdccbf3ac7aab6b31f7cb4e067aabd5c63f250d73fb0aa73255ee05d06c616e8358e88a19df66ea809027bee4e2f75ae76cc606707de40335063851c2566afa5ffcdda997669b074fe3b66e1f969e4f11b37968c05d0d7457183f4e07632a255d1666e750ad2ef3cb224c78adface67168276237ac9435892e2fe888664c53a49f4aaf63bd8bebbc777a844bec7e73d1f30cd22511a40ee5fc1ae1fe41466910f5298d41b47470aa6dcffd1322c8809419196c1df7c16fb5282221da80133ff945701a3d8805176a0f18233fa8a900e104be8c8419e1e3e9692771ff8444144ad093e1f64cc1684120fc5495b3ff0cc9bca11ca89fa15b5c94e0c852016a3507667da6e3aed2dddfb8a875beb7ce1e321f0c3bfb8a977ac302ee14c1061284f3b2a0409df52e3a7214da371014767daeee0b91e8966efa6e6e259e036f0ce3d089ee0f4af563da829bbd9a4106a0c2a9093def0d91da42df7011eaef24c2be1cd8fac9af49ec7c69f911653ca217faa0ef895ced28f823c469b9430bc04d4ab628d7d4e6cd65a8dd7a314313666f0b12f2d2e6f48a8b18e4f95f56efe51fa09e634df480da8e9856079d4dd24c666b8e08b7b4bace91787248f65f13ff42ea61223dedf9a0da7ee5051f30fac94728179be4cbf762b308e7bbee19fa1a905195a9de6d72b9e964cae1b0b4f95a78174e8368068c83d2e4d73951ead186ed2110c4427a4039e17cd77c2d6c51de430fcd34542b996628a339e21d66f7a9a9b5c98a8a81a9e7508f8ab03c4aef09919798fc4d722c1d81556ecc9a5cd1cf972a4dc6d60ea619174f8404daddefc8d03b229793f8208308885719b91d359e4ee94e57b0f69b76e5f500f13739b1dd79470f55bde81f6683d26a6c2e6aee6a26b29579c380426b6c6914906b93bd272d36eaea192b0e4454a06f68b"
					},
					{
						"c": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
						"p": "29701ceae262cac77b79b868c883a292e61e6de8192b868edcd1300b0973d91396b156ace6bd673402a303de10ddd8a5e6b7f17ba6557a574a672bd04cc273ab04ed8e2ca80bac483345c0ec843f521814ce1301ec9adc38956a12b4d948acce71295a4f52bcdeb8a1c9f2d6b2da5d731262a5e9c0276ef904df9ef8d48001420cd59f75a2f1ae5c7a1c7c6b9f140e7613e52ef9e249f29f9340b7efb80699e460164324616f98fd4cde3db52497c919e95222fffeacb7e65deca7e368a80ce713c19de7da5369726228ee336f5bd494538c12ccbffeb1b9bfd5fc8906d1c64245b516f103fa96d9c56975837652c1e0fa5803d7ccf1147d8f927e36da717f7ad79471dbe192f5f50f87a79fc3fe030dba569b634b92d2cf307993cce545633af263897cd7e6ebf4dcafb176d07358bdc38d03e45a49dfa9c8c6517cd68d167ffbf6c3b4de0e2dd21909cbad4c467b84e5700be473a39ac59c669d7c155c4bcab9b8026eea3431c779cd277e4922d2b9742e1f6678cbe869ec3b5b7ef4132ddb6cdd06cf27dbeb28be72b949fa897610e48e3a0d789fd2eea75abc97b3dc7e00e5c8b3d24e40c6f24112adb72352b89a2bef0599345338e9e76202a3c46efa6370952b2aca41aadbae0ea32531acafcdab6dd066d769ebf50cf4f3c0a59d2d5fa79600a207b9417c623f76ad05e8cccfcd4038f9448bc40f127ca7c0d372e46074e334fe49f5a956ec0056f4da601e6af80eb1a6c4951054869e665b296d8c14f344ca2dc5fdd5df4a3652536365a1615ad9b422165c77bf8fe65a835c8e0c41e070014eb66ef8c525204e990b3a3d663c1e42221b496895c37a2f0c1bf05e91235409c3fe3d89a9a79d6c78609ab18a463311911f71fa37bb73b15fcd38143d1404fd2ce81004dc7ff89cf1115dcc0c35ce1c1bf9941586fb959770f2618ccb7118a7"
					}
				],
				"token_coms": []
			},
		"fluff": false
		}
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5, true, true, true, false);
	```
	 */

	fn post_tx(&self, token: Token, slate: VersionedSlate, fluff: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::cancel_tx](struct.Owner.html#method.cancel_tx).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"tx_id": null,
			"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5, true, true, false, false);
	```
	 */
	fn cancel_tx(
		&self,
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::get_stored_tx](struct.Owner.html#method.get_stored_tx).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"id": null,
			"slate_id": "0436430c-2b02-624c-2032-570501212b00"
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": {
				"coms": [
					{
						"c": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
						"p": "29701ceae262cac77b79b868c883a292e61e6de8192b868edcd1300b0973d91396b156ace6bd673402a303de10ddd8a5e6b7f17ba6557a574a672bd04cc273ab04ed8e2ca80bac483345c0ec843f521814ce1301ec9adc38956a12b4d948acce71295a4f52bcdeb8a1c9f2d6b2da5d731262a5e9c0276ef904df9ef8d48001420cd59f75a2f1ae5c7a1c7c6b9f140e7613e52ef9e249f29f9340b7efb80699e460164324616f98fd4cde3db52497c919e95222fffeacb7e65deca7e368a80ce713c19de7da5369726228ee336f5bd494538c12ccbffeb1b9bfd5fc8906d1c64245b516f103fa96d9c56975837652c1e0fa5803d7ccf1147d8f927e36da717f7ad79471dbe192f5f50f87a79fc3fe030dba569b634b92d2cf307993cce545633af263897cd7e6ebf4dcafb176d07358bdc38d03e45a49dfa9c8c6517cd68d167ffbf6c3b4de0e2dd21909cbad4c467b84e5700be473a39ac59c669d7c155c4bcab9b8026eea3431c779cd277e4922d2b9742e1f6678cbe869ec3b5b7ef4132ddb6cdd06cf27dbeb28be72b949fa897610e48e3a0d789fd2eea75abc97b3dc7e00e5c8b3d24e40c6f24112adb72352b89a2bef0599345338e9e76202a3c46efa6370952b2aca41aadbae0ea32531acafcdab6dd066d769ebf50cf4f3c0a59d2d5fa79600a207b9417c623f76ad05e8cccfcd4038f9448bc40f127ca7c0d372e46074e334fe49f5a956ec0056f4da601e6af80eb1a6c4951054869e665b296d8c14f344ca2dc5fdd5df4a3652536365a1615ad9b422165c77bf8fe65a835c8e0c41e070014eb66ef8c525204e990b3a3d663c1e42221b496895c37a2f0c1bf05e91235409c3fe3d89a9a79d6c78609ab18a463311911f71fa37bb73b15fcd38143d1404fd2ce81004dc7ff89cf1115dcc0c35ce1c1bf9941586fb959770f2618ccb7118a7"
					}
				],
				"fee": "7000000",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"sigs": [],
				"sta": "S3",
				"token_coms": [],
				"ver": "4:3"
			}
		}
	}
	# "#
	# , 5, true, true, false, false);
	```
	 */
	fn get_stored_tx(
		&self,
		token: Token,
		id: Option<u32>,
		slate_id: Option<Uuid>,
	) -> Result<Option<VersionedSlate>, ErrorKind>;

	/**
	Networked version of [Owner::scan](struct.Owner.html#method.scan).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "scan",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"start_height": 1,
			"delete_unconfirmed": false
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 1, false, false, false, false);
	```
	 */
	fn scan(
		&self,
		token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::node_height](struct.Owner.html#method.node_height).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "node_height",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"header_hash": "d4b3d3c40695afd8c7760f8fc423565f7d41310b7a4e1c4a4a7950a66f16240d",
				"height": "5",
				"updated_from_node": true
			}
		}
	}
	# "#
	# , 5, false, false, false, false);
	```
	 */
	fn node_height(&self, token: Token) -> Result<NodeHeightResult, ErrorKind>;

	/**
		Initializes the secure JSON-RPC API. This function must be called and a shared key
		established before any other OwnerAPI JSON-RPC function can be called.

		The shared key will be derived using ECDH with the provided public key on the secp256k1 curve. This
		function will return its public key used in the derivation, which the caller should multiply by its
		private key to derive the shared key.

		Once the key is established, all further requests and responses are encrypted and decrypted with the
		following parameters:
		* AES-256 in GCM mode with 128-bit tags and 96 bit nonces
		* 12 byte nonce which must be included in each request/response to use on the decrypting side
		* Empty vector for additional data
		* Suffix length = AES-256 GCM mode tag length = 16 bytes
		*

		Fully-formed JSON-RPC requests (as documented) should be encrypted using these parameters, encoded
		into base64 and included with the one-time nonce in a request for the `encrypted_request_v3` method
		as follows:

		```
		# let s = r#"
		{
			 "jsonrpc": "2.0",
			 "method": "encrypted_request_v3",
			 "id": "1",
			 "params": {
					"nonce": "ef32...",
					"body_enc": "e0bcd..."
			 }
		}
		# "#;
		```

		With a typical response being:

		```
		# let s = r#"{
		{
			 "jsonrpc": "2.0",
			 "method": "encrypted_response_v3",
			 "id": "1",
			 "Ok": {
					"nonce": "340b...",
					"body_enc": "3f09c..."
			 }
		}
		# }"#;
		```

	*/

	fn init_secure_api(&self, ecdh_pubkey: ECDHPubkey) -> Result<ECDHPubkey, ErrorKind>;

	/**
	Networked version of [Owner::get_top_level_directory](struct.Owner.html#method.get_top_level_directory).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_top_level_directory",
		"params": {
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "/doctest/dir"
		}
	}
	# "#
	# , 5, false, false, false, false);
	```
	*/

	fn get_top_level_directory(&self) -> Result<String, ErrorKind>;

	/**
	Networked version of [Owner::set_top_level_directory](struct.Owner.html#method.set_top_level_directory).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_top_level_directory",
		"params": {
			"dir": "/home/wallet_user/my_wallet_dir"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5, false, false, false, false);
	```
	*/

	fn set_top_level_directory(&self, dir: String) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::create_config](struct.Owner.html#method.create_config).

	Both the `wallet_config` and `logging_config` parameters can be `null`, the examples
	below are for illustration. Note that the values provided for `log_file_path` and `data_file_dir`
	will be ignored and replaced with the actual values based on the value of `get_top_level_directory`
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_config",
		"params": {
			"chain_type": "Mainnet",
			"wallet_config": {
				"chain_type": null,
				"api_listen_interface": "127.0.0.1",
				"api_listen_port": 3415,
				"owner_api_listen_port": 3420,
				"api_secret_path": null,
				"node_api_secret_path": null,
				"check_node_api_http_addr": "http://127.0.0.1:3413",
				"owner_api_include_foreign": false,
				"data_file_dir": "/path/to/data/file/dir",
				"no_commit_cache": null,
				"tls_certificate_file": null,
				"tls_certificate_key": null,
				"dark_background_color_scheme": null,
				"keybase_notify_ttl": null
			},
			"logging_config": {
				"log_to_stdout": false,
				"stdout_log_level": "Info",
				"log_to_file": true,
				"file_log_level": "Debug",
				"log_file_path": "/path/to/log/file",
				"log_file_append": true,
				"log_max_size": null,
				"log_max_files": null,
				"tui_running": null
			},
			"tor_config" : {
				"use_tor_listener": true,
				"socks_proxy_addr": "127.0.0.1:9050",
				"send_config_dir": "."
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5, false, false, false, false);
	```
	*/
	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::create_wallet](struct.Owner.html#method.create_wallet).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_wallet",
		"params": {
			"name": null,
			"mnemonic": null,
			"mnemonic_length": 32,
			"password": "my_secret_password"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::open_wallet](struct.Owner.html#method.open_wallet).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "open_wallet",
		"params": {
			"name": null,
			"password": "my_secret_password"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "d096b3cb75986b3b13f80b8f5243a9edf0af4c74ac37578c5a12cfb5b59b1868"
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, ErrorKind>;

	/**
	Networked version of [Owner::close_wallet](struct.Owner.html#method.close_wallet).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "close_wallet",
		"params": {
			"name": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn close_wallet(&self, name: Option<String>) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::get_mnemonic](struct.Owner.html#method.get_mnemonic).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_mnemonic",
		"params": {
			"name": null,
			"password": ""
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "fat twenty mean degree forget shell check candy immense awful flame next during february bulb bike sun wink theory day kiwi embrace peace lunch"
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, ErrorKind>;

	/**
	Networked version of [Owner::change_password](struct.Owner.html#method.change_password).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "change_password",
		"params": {
			"name": null,
			"old": "",
			"new": "new_password"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/
	fn change_password(
		&self,
		name: Option<String>,
		old: String,
		new: String,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::delete_wallet](struct.Owner.html#method.delete_wallet).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "delete_wallet",
		"params": {
			"name": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/
	fn delete_wallet(&self, name: Option<String>) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::start_updated](struct.Owner.html#method.start_updater).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "start_updater",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"frequency": 30000
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn start_updater(&self, token: Token, frequency: u32) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::stop_updater](struct.Owner.html#method.stop_updater).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "stop_updater",
		"params": null,
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/
	fn stop_updater(&self) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::get_updater_messages](struct.Owner.html#method.get_updater_messages).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_updater_messages",
		"params": {
			"count": 1
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": []
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn get_updater_messages(&self, count: u32) -> Result<Vec<StatusMessage>, ErrorKind>;

	/**
	Networked version of [Owner::get_slatepack_address](struct.Owner.html#method.get_slatepack_address).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_slatepack_address",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"derivation_index": 0
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "tvcash1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfsk3qfya"
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn get_slatepack_address(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<SlatepackAddress, ErrorKind>;

	/**
	Networked version of [Owner::get_slatepack_secret_key](struct.Owner.html#method.get_slatepack_secret_key).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_slatepack_secret_key",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"derivation_index": 0
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "86cca2aedea7989dfcca62e54477301d098bac260656d11373e314c099f0b26f"
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn get_slatepack_secret_key(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<Ed25519SecretKey, ErrorKind>;

	/**
	Networked version of [Owner::create_slatepack_message](struct.Owner.html#method.create_slatepack_message).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_slatepack_message",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"sender_index": 0,
			"recipients": [],
			"slate": {
				"ver": "4:3",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"sta": "S1",
				"off": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"amt": "60000000000",
				"fee": "7000000",
				"sigs": [
					{
						"xs": "030152d2d72e2dba7c6086ad49a219d9ff0dfe0fd993dcaea22e058c210033ce93",
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				]
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "BEGINSLATEPACK. 6VGFf5zVSJioXMA zCBBDZuKsokhNWP CKtdb3wFU4XPigK yo23JsEAfWKMfzd RHAspKLrV2E7DWW zECeUAci35d16MC ZPxz1M7dUaLhTyP uLCm3J6H2xudaZ3 HKFnfkh2TjJcYoN sHdqBBDWhxWwnXg My8aVPCHdH48Eim uw6x1A6M8mjMMUa ZxSTmn4TcTogbHK CcHzpEC8zVMxwnX NncqPTUaN8KBVNW LjRKynSVyDFzRH9 MMunDb4Mvopvy9G bUe9ZdceDJV46h4 A6RKHzspDt1LcKa FtS69owgTLYWGEk ZskKGByxj. ENDSLATEPACK."
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn create_slatepack_message(
		&self,
		token: Token,
		slate: VersionedSlate,
		sender_index: Option<u32>,
		recipients: Vec<SlatepackAddress>,
	) -> Result<String, ErrorKind>;

	/**
	Networked version of [Owner::slate_from_slatepack_message](struct.Owner.html#method.slate_from_slatepack_message).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "slate_from_slatepack_message",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"secret_indices": [0],
			"message": "BEGINSLATEPACK. 8GQrdcwdLKJD28F 3a9siP7ZhZgAh7w BR2EiZHza5WMWmZ Cc8zBUemrrYRjhq j3VBwA8vYnvXXKU BDmQBN2yKgmR8mX UzvXHezfznA61d7 qFZYChhz94vd8Ew NEPLz7jmcVN2C3w wrfHbeiLubYozP2 uhLouFiYRrbe3fQ 4uhWGfT3sQYXScT dAeo29EaZJpfauh j8VL5jsxST2SPHq nzXFC2w9yYVjt7D ju7GSgHEp5aHz9R xstGbHjbsb4JQod kYLuELta1ohUwDD pvjhyJmsbLcsPei k5AQhZsJ8RJGBtY bou6cU7tZeFJvor 4LB9CBfFB3pmVWD vSLd5RPS75dcnHP nbXD8mSDZ8hJS2Q A9wgvppWzuWztJ2 dLUU8f9tLJgsRBw YZAs71HiVeg7. ENDSLATEPACK."
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"amt": "6000000000",
				"fee": "8000000",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"off": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"proof": {
					"raddr": "783f6528669742a990e0faf0a5fca5d5b3330e37bbb9cd5c628696d03ce4e810",
					"saddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
				},
				"sigs": [
					{
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"xs": "023878ce845727f3a4ec76ca3f3db4b38a2d05d636b8c3632108b857fed63c96de"
					}
				],
				"sta": "S1",
				"ver": "4:2"
			}
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn slate_from_slatepack_message(
		&self,
		token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::decode_slatepack_message](struct.Owner.html#method.decode_slatepack_message).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "decode_slatepack_message",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"secret_indices": [0],
			"message": "BEGINSLATEPACK. t9EcGgrKr1GFCQB SK2jPCxME6Hgpqx bntpQm3zKFycoPY nW4UeoL4KQ7ExNK At6EQsvpz6MjUs8 6WG8KHEbMfqufJQ ZJTw2gkcdJmJjiJ f29oGgYqqXDZox4 ujPSjrtoxCN4h3e i1sZ8dYsm3dPeXL 7VQLsYNjAefciqj ZJXPm4Pqd7VDdd4 okGBGBu3YJvYzT6 arAxeCEx66us31h AJLcDweFwyWBkW5 J1DLiYAjt5ftFTo CjpfW9KjiLq2LM5 jepXWEHJPSDAYVK 4macDZUhRbJiG6E hrQcPrJBVC716mb Hw5E1PFrE6on5wq oEmrS4j9vaB5nw8 Z9ZyXvPc2LN7tER yt6pSHZeY9EpYdY zv4bthzfRfF8ePT TMeMpV2gpgyRXQa CPD2TR. ENDSLATEPACK."
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"mode": 0,
				"payload": "AAQAAgQ2QwwrAmJMIDJXBQEhKwAB0gKWSQAAAADTApZJAAAAANQClkkAAAAA1QKWSQAAAAAGAAAAAWWgvAAAAAAAAHoSAAEAAjh4zoRXJ/Ok7HbKPz20s4otBdY2uMNjIQi4V/7WPJbeAxuExVZ7EmRAmV0+1aq6BWXXHhg0YEgZ/5wX9enV3QePAjLN1jkohU+LJiix3ORibdzfNdVst8/ffWTMpYIreNTTeD9lKGaXQqmQ4Prwpfyl1bMzDje7uc1cYoaW0Dzk6BAA",
				"sender": "tgrin1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfs9gm2lp",
				"slatepack": "1.0"
			}
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn decode_slatepack_message(
		&self,
		token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<Slatepack, ErrorKind>;

	/**
	Networked version of [Owner::retrieve_payment_proof](struct.Owner.html#method.retrieve_payment_proof).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_payment_proof",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"refresh_from_node": true,
			"tx_id": null,
			"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"amount": "60000000000",
				"excess": "09c7994f5187d34854d358a01f023ccb1391cd761cbd96d7e072d7aff5ef8003d3",
				"recipient_address": "tvcash10qlk22rxjap2ny8qltc2tl996kenxr3hhwuu6hrzs6tdq08yaqgqnrsy2l",
				"recipient_sig": "f6a5498d6ab6f118ad91ee86fa93afce235e098549505550b983a45fef9818c48933fdc0906b5791062eaf78d07731727d0167394636d694eaf90506831a650f",
				"sender_address": "tvcash1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfsk3qfya",
				"sender_sig": "c0dfcb8117275914a30caae0ec38e7bf2fda97bd4afd36e1f7a0ce3a1eb276350a58405c937232f5515e3791812388223ac116a2877bd71e13c893b956d4720e",
				"token_type": null
			}
		}
	}
	# "#
	# , 5, true, true, true, true);
	```
	*/

	fn retrieve_payment_proof(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, ErrorKind>;

	/**
	Networked version of [Owner::verify_payment_proof](struct.Owner.html#method.verify_payment_proof).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_payment_proof",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"proof": {
				"amount": "60000000000",
				"excess": "09c7994f5187d34854d358a01f023ccb1391cd761cbd96d7e072d7aff5ef8003d3",
				"recipient_address": "tvcash10qlk22rxjap2ny8qltc2tl996kenxr3hhwuu6hrzs6tdq08yaqgqnrsy2l",
				"recipient_sig": "f6a5498d6ab6f118ad91ee86fa93afce235e098549505550b983a45fef9818c48933fdc0906b5791062eaf78d07731727d0167394636d694eaf90506831a650f",
				"sender_address": "tvcash1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfsk3qfya",
				"sender_sig": "c0dfcb8117275914a30caae0ec38e7bf2fda97bd4afd36e1f7a0ce3a1eb276350a58405c937232f5515e3791812388223ac116a2877bd71e13c893b956d4720e"
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				false
			]
		}
	}
	# "#
	# , 5, true, true, true, true);
	```
	*/

	fn verify_payment_proof(
		&self,
		token: Token,
		proof: PaymentProof,
	) -> Result<(bool, bool), ErrorKind>;

	/**
	Networked version of [Owner::set_tor_config](struct.Owner.html#method.set_tor_config).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_tor_config",
		"params": {
			"tor_config": {
				"use_tor_listener": true,
				"socks_proxy_addr": "127.0.0.1:59050",
				"send_config_dir": "."
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/
	fn set_tor_config(&self, tor_config: Option<TorConfig>) -> Result<(), ErrorKind>;
}

impl<L, C, K> OwnerRpc for Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn accounts(&self, token: Token) -> Result<Vec<AcctPathMapping>, ErrorKind> {
		Owner::accounts(self, (&token.keychain_mask).as_ref()).map_err(|e| e.kind())
	}

	fn create_account_path(&self, token: Token, label: &String) -> Result<Identifier, ErrorKind> {
		Owner::create_account_path(self, (&token.keychain_mask).as_ref(), label)
			.map_err(|e| e.kind())
	}

	fn set_active_account(&self, token: Token, label: &String) -> Result<(), ErrorKind> {
		Owner::set_active_account(self, (&token.keychain_mask).as_ref(), label)
			.map_err(|e| e.kind())
	}

	fn retrieve_outputs(
		&self,
		token: Token,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind> {
		Owner::retrieve_outputs(
			self,
			(&token.keychain_mask).as_ref(),
			include_spent,
			refresh_from_node,
			tx_id,
		)
		.map_err(|e| e.kind())
	}

	fn retrieve_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind> {
		Owner::retrieve_txs(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node,
			tx_id,
			tx_slate_id,
		)
		.map_err(|e| e.kind())
	}

	fn retrieve_summary_info(
		&self,
		token: Token,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind> {
		Owner::retrieve_summary_info(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node,
			minimum_confirmations,
		)
		.map_err(|e| e.kind())
	}

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::init_send_tx(self, (&token.keychain_mask).as_ref(), args)
			.map_err(|e| e.kind())?;
		let version = SlateVersion::V4;
		Ok(VersionedSlate::into_version(slate, version).map_err(|e| e.kind())?)
	}

	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::issue_invoice_tx(self, (&token.keychain_mask).as_ref(), args)
			.map_err(|e| e.kind())?;
		let version = SlateVersion::V4;
		Ok(VersionedSlate::into_version(slate, version).map_err(|e| e.kind())?)
	}

	fn process_invoice_tx(
		&self,
		token: Token,
		in_slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, ErrorKind> {
		let out_slate = Owner::process_invoice_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(in_slate),
			args,
		)
		.map_err(|e| e.kind())?;
		let version = SlateVersion::V4;
		Ok(VersionedSlate::into_version(out_slate, version).map_err(|e| e.kind())?)
	}

	fn finalize_tx(
		&self,
		token: Token,
		in_slate: VersionedSlate,
	) -> Result<VersionedSlate, ErrorKind> {
		let out_slate = Owner::finalize_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(in_slate),
		)
		.map_err(|e| e.kind())?;
		let version = SlateVersion::V4;
		Ok(VersionedSlate::into_version(out_slate, version).map_err(|e| e.kind())?)
	}

	fn tx_lock_outputs(&self, token: Token, in_slate: VersionedSlate) -> Result<(), ErrorKind> {
		Owner::tx_lock_outputs(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(in_slate),
		)
		.map_err(|e| e.kind())
	}

	fn cancel_tx(
		&self,
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), ErrorKind> {
		Owner::cancel_tx(self, (&token.keychain_mask).as_ref(), tx_id, tx_slate_id)
			.map_err(|e| e.kind())
	}

	fn get_stored_tx(
		&self,
		token: Token,
		id: Option<u32>,
		slate_id: Option<Uuid>,
	) -> Result<Option<VersionedSlate>, ErrorKind> {
		let out_slate = Owner::get_stored_tx(
			self,
			(&token.keychain_mask).as_ref(),
			id,
			(&slate_id).as_ref(),
		)
		.map_err(|e| e.kind())?;
		match out_slate {
			Some(s) => {
				let version = SlateVersion::V4;
				Ok(Some(
					VersionedSlate::into_version(s, version).map_err(|e| e.kind())?,
				))
			}
			None => Ok(None),
		}
	}

	fn post_tx(&self, token: Token, slate: VersionedSlate, fluff: bool) -> Result<(), ErrorKind> {
		Owner::post_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(slate),
			fluff,
		)
		.map_err(|e| e.kind())
	}

	fn scan(
		&self,
		token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), ErrorKind> {
		Owner::scan(
			self,
			(&token.keychain_mask).as_ref(),
			start_height,
			delete_unconfirmed,
		)
		.map_err(|e| e.kind())
	}

	fn node_height(&self, token: Token) -> Result<NodeHeightResult, ErrorKind> {
		Owner::node_height(self, (&token.keychain_mask).as_ref()).map_err(|e| e.kind())
	}

	fn init_secure_api(&self, ecdh_pubkey: ECDHPubkey) -> Result<ECDHPubkey, ErrorKind> {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		let sec_key = SecretKey::new(&secp, &mut thread_rng());

		let mut shared_pubkey = ecdh_pubkey.ecdh_pubkey;
		shared_pubkey
			.mul_assign(&secp, &sec_key)
			.map_err(ErrorKind::Secp)?;

		let x_coord = shared_pubkey.serialize_vec(&secp, true);
		let shared_key = SecretKey::from_slice(&secp, &x_coord[1..]).map_err(ErrorKind::Secp)?;
		{
			let mut s = self.shared_key.lock();
			*s = Some(shared_key);
		}

		let pub_key = PublicKey::from_secret_key(&secp, &sec_key).map_err(ErrorKind::Secp)?;

		Ok(ECDHPubkey {
			ecdh_pubkey: pub_key,
		})
	}

	fn get_top_level_directory(&self) -> Result<String, ErrorKind> {
		Owner::get_top_level_directory(self).map_err(|e| e.kind())
	}

	fn set_top_level_directory(&self, dir: String) -> Result<(), ErrorKind> {
		Owner::set_top_level_directory(self, &dir).map_err(|e| e.kind())
	}

	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
	) -> Result<(), ErrorKind> {
		Owner::create_config(self, &chain_type, wallet_config, logging_config, tor_config)
			.map_err(|e| e.kind())
	}

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		let m = match mnemonic {
			Some(s) => Some(ZeroingString::from(s)),
			None => None,
		};
		Owner::create_wallet(self, n, m, mnemonic_length, ZeroingString::from(password))
			.map_err(|e| e.kind())
	}

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		let sec_key = Owner::open_wallet(self, n, ZeroingString::from(password), true)
			.map_err(|e| e.kind())?;
		Ok(Token {
			keychain_mask: sec_key,
		})
	}

	fn close_wallet(&self, name: Option<String>) -> Result<(), ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::close_wallet(self, n).map_err(|e| e.kind())
	}

	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		let res =
			Owner::get_mnemonic(self, n, ZeroingString::from(password)).map_err(|e| e.kind())?;
		Ok((&*res).to_string())
	}

	fn change_password(
		&self,
		name: Option<String>,
		old: String,
		new: String,
	) -> Result<(), ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::change_password(self, n, ZeroingString::from(old), ZeroingString::from(new))
			.map_err(|e| e.kind())
	}

	fn delete_wallet(&self, name: Option<String>) -> Result<(), ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::delete_wallet(self, n).map_err(|e| e.kind())
	}

	fn start_updater(&self, token: Token, frequency: u32) -> Result<(), ErrorKind> {
		Owner::start_updater(
			self,
			(&token.keychain_mask).as_ref(),
			Duration::from_millis(frequency as u64),
		)
		.map_err(|e| e.kind())
	}

	fn stop_updater(&self) -> Result<(), ErrorKind> {
		Owner::stop_updater(self).map_err(|e| e.kind())
	}

	fn get_updater_messages(&self, count: u32) -> Result<Vec<StatusMessage>, ErrorKind> {
		Owner::get_updater_messages(self, count as usize).map_err(|e| e.kind())
	}

	fn get_slatepack_address(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<SlatepackAddress, ErrorKind> {
		Owner::get_slatepack_address(self, (&token.keychain_mask).as_ref(), derivation_index)
			.map_err(|e| e.kind())
	}

	fn get_slatepack_secret_key(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<Ed25519SecretKey, ErrorKind> {
		let key = Owner::get_slatepack_secret_key(
			self,
			(&token.keychain_mask).as_ref(),
			derivation_index,
		)
		.map_err(|e| e.kind())?;
		Ok(Ed25519SecretKey { key })
	}

	fn create_slatepack_message(
		&self,
		token: Token,
		slate: VersionedSlate,
		sender_index: Option<u32>,
		recipients: Vec<SlatepackAddress>,
	) -> Result<String, ErrorKind> {
		let res = Owner::create_slatepack_message(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(slate),
			sender_index,
			recipients,
		)
		.map_err(|e| e.kind())?;
		Ok(res.trim().into())
	}

	fn slate_from_slatepack_message(
		&self,
		token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::slate_from_slatepack_message(
			self,
			(&token.keychain_mask).as_ref(),
			message,
			secret_indices,
		)
		.map_err(|e| e.kind())?;
		let version = SlateVersion::V4;
		Ok(VersionedSlate::into_version(slate, version).map_err(|e| e.kind())?)
	}

	fn decode_slatepack_message(
		&self,
		token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<Slatepack, ErrorKind> {
		Owner::decode_slatepack_message(
			self,
			(&token.keychain_mask).as_ref(),
			message,
			secret_indices,
		)
		.map_err(|e| e.kind())
	}

	fn retrieve_payment_proof(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, ErrorKind> {
		Owner::retrieve_payment_proof(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node,
			tx_id,
			tx_slate_id,
		)
		.map_err(|e| e.kind())
	}

	fn verify_payment_proof(
		&self,
		token: Token,
		proof: PaymentProof,
	) -> Result<(bool, bool), ErrorKind> {
		Owner::verify_payment_proof(self, (&token.keychain_mask).as_ref(), &proof)
			.map_err(|e| e.kind())
	}

	fn set_tor_config(&self, tor_config: Option<TorConfig>) -> Result<(), ErrorKind> {
		Owner::set_tor_config(self, tor_config);
		Ok(())
	}
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_owner(
	request: serde_json::Value,
	test_dir: &str,
	blocks_to_mine: u64,
	perform_tx: bool,
	lock_tx: bool,
	finalize_tx: bool,
	payment_proof: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc_mw::Handler;
	use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
	use grin_wallet_libwallet::{api_impl, WalletInst};
	use grin_wallet_util::grin_keychain::ExtKeychain;

	use crate::core::global::ChainTypes;
	use grin_wallet_util::grin_util as util;

	use std::{fs, thread};

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);

	let mut wallet_proxy: WalletProxy<
		DefaultLCProvider<LocalWalletClient, ExtKeychain>,
		LocalWalletClient,
		ExtKeychain,
	> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	let rec_phrase_1 = util::ZeroingString::from(
		"fat twenty mean degree forget shell check candy immense awful \
		 flame next during february bulb bike sun wink theory day kiwi embrace peace lunch",
	);
	let empty_string = util::ZeroingString::from("");

	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	let mut wallet1 =
		Box::new(DefaultWalletImpl::<LocalWalletClient>::new(client1.clone()).unwrap())
			as Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>;
	let lc = wallet1.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{}/wallet1", test_dir));
	lc.create_wallet(None, Some(rec_phrase_1), 32, empty_string.clone(), false)
		.unwrap();
	let mask1 = lc
		.open_wallet(None, empty_string.clone(), true, true)
		.unwrap();
	let wallet1 = Arc::new(Mutex::new(wallet1));

	if mask1.is_some() {
		println!("WALLET 1 MASK: {:?}", mask1.clone().unwrap());
	}

	wallet_proxy.add_wallet(
		"wallet1",
		client1.get_send_instance(),
		wallet1.clone(),
		mask1.clone(),
	);

	let mut slate_outer = Slate::blank(2, false);

	let rec_phrase_2 = util::ZeroingString::from(
		"hour kingdom ripple lunch razor inquiry coyote clay stamp mean \
		 sell finish magic kid tiny wage stand panther inside settle feed song hole exile",
	);
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	let mut wallet2 =
		Box::new(DefaultWalletImpl::<LocalWalletClient>::new(client2.clone()).unwrap())
			as Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>;
	let lc = wallet2.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{}/wallet2", test_dir));
	lc.create_wallet(None, Some(rec_phrase_2), 32, empty_string.clone(), false)
		.unwrap();
	let mask2 = lc.open_wallet(None, empty_string, true, true).unwrap();
	let wallet2 = Arc::new(Mutex::new(wallet2));

	if mask2.is_some() {
		println!("WALLET 2 MASK: {:?}", mask2.clone().unwrap());
	}

	wallet_proxy.add_wallet(
		"wallet2",
		client2.get_send_instance(),
		wallet2.clone(),
		mask2.clone(),
	);

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Mine a few blocks to wallet 1 so there's something to send
	for _ in 0..blocks_to_mine {
		let _ = test_framework::award_blocks_to_wallet(
			&chain,
			wallet1.clone(),
			(&mask1).as_ref(),
			1 as usize,
			false,
		);
		//update local outputs after each block, so transaction IDs stay consistent
		let (wallet_refreshed, _) = api_impl::owner::retrieve_summary_info(
			wallet1.clone(),
			(&mask1).as_ref(),
			&None,
			true,
			1,
		)
		.unwrap();
		assert!(wallet_refreshed);
	}

	if perform_tx {
		let amount = 60_000_000_000;
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let proof_address = match payment_proof {
			true => {
				let address = "783f6528669742a990e0faf0a5fca5d5b3330e37bbb9cd5c628696d03ce4e810";
				let address = OnionV3Address::try_from(address).unwrap();
				Some(SlatepackAddress::try_from(address).unwrap())
			}
			false => None,
		};
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			payment_proof_recipient_address: proof_address,
			..Default::default()
		};
		let mut slate =
			api_impl::owner::init_send_tx(&mut **w, (&mask1).as_ref(), args, true).unwrap();
		println!("INITIAL SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		{
			let mut w_lock = wallet2.lock();
			let w2 = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
			slate = api_impl::foreign::receive_tx(&mut **w2, (&mask2).as_ref(), &slate, None, true)
				.unwrap();
			w2.close().unwrap();
		}
		// Spit out slate for input to finalize_tx
		if lock_tx {
			println!("LOCKING TX");
			api_impl::owner::tx_lock_outputs(&mut **w, (&mask1).as_ref(), &slate).unwrap();
		}
		println!("RECEIPIENT SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		if finalize_tx {
			slate = api_impl::owner::finalize_tx(&mut **w, (&mask1).as_ref(), &slate).unwrap();
			error!("FINALIZED TX SLATE");
			println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		}
		slate_outer = slate;
	}

	if payment_proof {
		api_impl::owner::post_tx(&client1, slate_outer.tx_or_err().unwrap(), true).unwrap();
	}

	if perform_tx && lock_tx && finalize_tx {
		// mine to move the chain on
		let _ = test_framework::award_blocks_to_wallet(
			&chain,
			wallet1.clone(),
			(&mask1).as_ref(),
			3 as usize,
			false,
		);
	}

	let mut api_owner = Owner::new(wallet1, None);
	api_owner.doctest_mode = true;
	let owner_api = &api_owner as &dyn OwnerRpc;
	let res = owner_api.handle_request(request).as_option();
	let _ = fs::remove_dir_all(test_dir);
	Ok(res)
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_owner_assert_response {
	($request:expr, $expected_response:expr, $blocks_to_mine:expr, $perform_tx:expr, $lock_tx:expr, $finalize_tx:expr, $payment_proof:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.

		// These cause LMDB to run out of disk space on CircleCI
		// disable for now on windows
		// TODO: Fix properly
		#[cfg(not(target_os = "windows"))]
			{
			use grin_wallet_api::run_doctest_owner;
			use serde_json;
			use serde_json::Value;
			use tempfile::tempdir;

			let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
			let dir = dir
				.path()
				.to_str()
				.ok_or("Failed to convert tmpdir path to string.".to_owned())
				.unwrap();

			let request_val: Value = serde_json::from_str($request).unwrap();
			let expected_response: Value = serde_json::from_str($expected_response).unwrap();

			let response = run_doctest_owner(
				request_val,
				dir,
				$blocks_to_mine,
				$perform_tx,
				$lock_tx,
				$finalize_tx,
				$payment_proof,
				)
			.unwrap()
			.unwrap();

			if response != expected_response {
				panic!(
					"(left != right) \nleft: {}\nright: {}",
					serde_json::to_string_pretty(&response).unwrap(),
					serde_json::to_string_pretty(&expected_response).unwrap()
				);
				}
			}
	};
}
