#[cfg(test)]
mod tests {
    use crate::contract::{generate_keypair, handle, init};
    use crate::msg::{HandleAnswer, HandleMsg, InitMsg, Mint};
    use crate::rand::sha_256;
    use crate::state::{
        json_load, load, may_load, PREFIX_INFOS, PREFIX_MAP_TO_ID, PREFIX_MAP_TO_INDEX,
        PREFIX_PRIV_META, PREFIX_PUB_META, PRNG_SEED_KEY,
    };
    use crate::token::{Extension, Metadata, Token};
    use cosmwasm_std::{from_binary, Env, Extern, HumanAddr, InitResponse, StdResult};
    use cosmwasm_std::{testing::*, to_binary, Api, BlockInfo, MessageInfo};
    use cosmwasm_storage::ReadonlyPrefixedStorage;
    // Helper functions

    fn init_helper_default() -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
        Env,
    ) {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);
        let env_copy = mock_env("instantiator", &[]);

        let init_msg = InitMsg {
            name: "sec721".to_string(),
            symbol: "S721".to_string(),
            admin: Some(HumanAddr("admin".to_string())),
            entropy: "We're going to need a bigger boat".to_string(),
            royalty_info: None,
            config: None,
            post_init_callback: None,
        };

        (init(&mut deps, env, init_msg), deps, env_copy)
    }

    #[test]
    fn test_keygen_helpers() {
        let (init_result, deps, env) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // Test entropy init.
        let saved_prng_seed: Vec<u8> = may_load(&deps.storage, PRNG_SEED_KEY).unwrap().unwrap();
        let expected_prng_seed: Vec<u8> =
            sha_256(base64::encode("We're going to need a bigger boat".to_string()).as_bytes())
                .to_vec();
        assert_eq!(saved_prng_seed, expected_prng_seed);

        // Test adding key to metadata

        let meta = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
                ..Extension::default()
            }),
        };

        let pair = generate_keypair(&env, saved_prng_seed, None);

        let key_meta = meta.add_auth_key(pair.clone().0.as_bytes()).unwrap();

        let key_meta_expect = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
                auth_key: Some(pair.clone().0.as_bytes().clone()),
                ..Extension::default()
            }),
        };

        assert_eq!(key_meta, key_meta_expect);
    }

    #[test]
    fn test_mint() {
        let (init_result, mut deps, _env) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let pub_meta = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
                ..Extension::default()
            }),
        });
        let priv_meta = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFTpriv".to_string()),
                description: Some("Nifty".to_string()),
                image: Some("privuri".to_string()),
                ..Extension::default()
            }),
        });

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            entropy: None,
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: pub_meta.clone(),
            private_metadata: priv_meta.clone(),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };

        let pubkey_bytes = [
            223, 216, 66, 167, 222, 168, 156, 52, 25, 176, 145, 253, 195, 240, 51, 91, 188, 136,
            91, 34, 204, 32, 253, 237, 84, 136, 213, 172, 118, 162, 237, 43,
        ];
        let scrtkey_bytes = [
            48, 115, 18, 104, 195, 51, 92, 81, 158, 41, 136, 240, 110, 99, 143, 45, 205, 169, 50,
            7, 144, 193, 145, 103, 45, 245, 126, 213, 96, 204, 36, 75,
        ];

        let pub_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
                auth_key: Some(pubkey_bytes),
                ..Extension::default()
            }),
        });
        let priv_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFTpriv".to_string()),
                description: Some("Nifty".to_string()),
                image: Some("privuri".to_string()),
                auth_key: Some(scrtkey_bytes),
                ..Extension::default()
            }),
        });

        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        //let minted = extract_log(handle_result);
        //assert!(minted.contains("MyNFT"));

        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index: u32 = may_load(&map2idx, "MyNFT".to_string().as_bytes())
            .unwrap()
            .unwrap();
        let token_key = index.to_le_bytes();

        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &token_key).unwrap();
        assert_eq!(pub_meta, pub_expect.unwrap());

        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Metadata = load(&priv_store, &token_key).unwrap();
        assert_eq!(priv_meta, priv_expect.unwrap());

        // test mint batch

        let empty_metadata = Metadata {
            token_uri: None,
            extension: Some(Extension::default()),
        };

        let alice = HumanAddr("alice".to_string());
        let alice_raw = deps.api.canonical_address(&alice).unwrap();
        let admin = HumanAddr("admin".to_string());
        let admin_raw = deps.api.canonical_address(&admin).unwrap();

        let pub1 = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("NFT1".to_string()),
                description: Some("pub1".to_string()),
                image: Some("uri1".to_string()),
                ..Extension::default()
            }),
        };
        let priv2 = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("NFT2".to_string()),
                description: Some("priv2".to_string()),
                image: Some("uri2".to_string()),
                ..Extension::default()
            }),
        };
        let mints = vec![
            Mint {
                token_id: None,
                owner: Some(alice.clone()),
                public_metadata: Some(pub1.clone()),
                private_metadata: Some(empty_metadata.clone()),
                royalty_info: None,
                serial_number: None,
                transferable: None,
                memo: None,
            },
            Mint {
                token_id: Some("NFT2".to_string()),
                owner: None,
                public_metadata: Some(empty_metadata.clone()),
                private_metadata: Some(priv2.clone()),
                royalty_info: None,
                serial_number: None,
                transferable: None,
                memo: None,
            },
            Mint {
                token_id: Some("NFT3".to_string()),
                owner: Some(alice.clone()),
                public_metadata: Some(empty_metadata.clone()),
                private_metadata: Some(empty_metadata.clone()),
                royalty_info: None,
                transferable: None,
                serial_number: None,
                memo: None,
            },
            Mint {
                token_id: None,
                owner: Some(admin.clone()),
                public_metadata: Some(empty_metadata.clone()),
                private_metadata: Some(empty_metadata.clone()),
                royalty_info: None,
                transferable: None,
                serial_number: None,
                memo: Some("has id 3".to_string()),
            },
        ];

        let pub1_expect = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("NFT1".to_string()),
                description: Some("pub1".to_string()),
                image: Some("uri1".to_string()),
                auth_key: Some([
                    2, 150, 93, 115, 7, 33, 172, 31, 219, 91, 234, 185, 197, 245, 76, 43, 67, 25,
                    191, 62, 176, 230, 101, 128, 18, 211, 184, 141, 245, 195, 206, 111,
                ]),
                ..Extension::default()
            }),
        };
        let priv2_expect = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("NFT2".to_string()),
                description: Some("priv2".to_string()),
                image: Some("uri2".to_string()),
                auth_key: Some([
                    176, 111, 11, 80, 249, 177, 234, 33, 35, 227, 191, 85, 240, 45, 238, 236, 93,
                    85, 38, 203, 215, 164, 55, 170, 155, 60, 58, 162, 209, 229, 85, 80,
                ]),
                ..Extension::default()
            }),
        };

        // sanity check
        let handle_msg = HandleMsg::BatchMintNft {
            mints: mints.clone(),
            padding: None,
            entropy: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let minted_vec = vec![
            "1".to_string(),
            "NFT2".to_string(),
            "NFT3".to_string(),
            "4".to_string(),
        ];
        let handle_answer: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        match handle_answer {
            HandleAnswer::BatchMintNft { token_ids } => {
                assert_eq!(token_ids, minted_vec);
            }
            _ => panic!("unexpected"),
        }

        // verify the tokens are in the id and index maps
        let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, &deps.storage);
        let index1: u32 = load(&map2idx, "1".as_bytes()).unwrap();
        let token_key1 = index1.to_le_bytes();
        let index2: u32 = load(&map2idx, "NFT2".as_bytes()).unwrap();
        let token_key2 = index2.to_le_bytes();
        let index3: u32 = load(&map2idx, "NFT3".as_bytes()).unwrap();
        let token_key3 = index3.to_le_bytes();
        let index4: u32 = load(&map2idx, "4".as_bytes()).unwrap();
        let token_key4 = index4.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
        let id1: String = load(&map2id, &token_key1).unwrap();
        assert_eq!("1".to_string(), id1);
        let id2: String = load(&map2id, &token_key2).unwrap();
        assert_eq!("NFT2".to_string(), id2);
        let id3: String = load(&map2id, &token_key3).unwrap();
        assert_eq!("NFT3".to_string(), id3);
        let id4: String = load(&map2id, &token_key4).unwrap();
        assert_eq!("4".to_string(), id4);

        // verify all the token info
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token1: Token = json_load(&info_store, &token_key1).unwrap();
        assert_eq!(token1.owner, alice_raw);
        assert_eq!(token1.permissions, Vec::new());
        assert!(token1.unwrapped);
        let token2: Token = json_load(&info_store, &token_key2).unwrap();
        assert_eq!(token2.owner, admin_raw);
        assert_eq!(token2.permissions, Vec::new());
        assert!(token2.unwrapped);
        // verify the token metadata
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta1: Metadata = load(&pub_store, &token_key1).unwrap();
        //println!("{:?}",pub_meta1);
        assert_eq!(pub_meta1, pub1_expect);
        //let pub_meta2: Option<Metadata> = may_load(&pub_store, &token_key2).unwrap();
        //assert!(pub_meta2.is_none());
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        //let priv_meta1: Option<Metadata> = may_load(&priv_store, &token_key1).unwrap();
        //assert!(priv_meta1.is_none());
        let priv_meta2: Metadata = load(&priv_store, &token_key2).unwrap();
        assert_eq!(priv_meta2, priv2_expect);
    }

    #[test]
    fn test_regenerate_keys() {
        let (init_result, mut deps, _env) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let pub_meta = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
                ..Extension::default()
            }),
        });
        let priv_meta = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFTpriv".to_string()),
                description: Some("Nifty".to_string()),
                image: Some("privuri".to_string()),
                ..Extension::default()
            }),
        });

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            entropy: None,
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: pub_meta.clone(),
            private_metadata: priv_meta.clone(),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };

        let pubkey_bytes = [
            223, 216, 66, 167, 222, 168, 156, 52, 25, 176, 145, 253, 195, 240, 51, 91, 188, 136,
            91, 34, 204, 32, 253, 237, 84, 136, 213, 172, 118, 162, 237, 43,
        ];
        let scrtkey_bytes = [
            48, 115, 18, 104, 195, 51, 92, 81, 158, 41, 136, 240, 110, 99, 143, 45, 205, 169, 50,
            7, 144, 193, 145, 103, 45, 245, 126, 213, 96, 204, 36, 75,
        ];

        let pub_expect1 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
                auth_key: Some(pubkey_bytes),
                ..Extension::default()
            }),
        });
        let priv_expect1 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFTpriv".to_string()),
                description: Some("Nifty".to_string()),
                image: Some("privuri".to_string()),
                auth_key: Some(scrtkey_bytes),
                ..Extension::default()
            }),
        });

        // Test key regeneration

        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let map2idx = Some(ReadonlyPrefixedStorage::new(
            PREFIX_MAP_TO_INDEX,
            &deps.storage,
        ));
        let index1: u32 = load(&map2idx.unwrap(), "MyNFT".as_bytes()).unwrap();
        let token_key1 = index1.to_le_bytes();
        let pub_store = Some(ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage));
        let pub_meta1: Metadata = load(&pub_store.unwrap(), &token_key1).unwrap();
        assert_eq!(pub_meta1, pub_expect1.unwrap());
        let priv_store = Some(ReadonlyPrefixedStorage::new(
            PREFIX_PRIV_META,
            &deps.storage,
        ));
        let priv_meta1: Metadata = load(&priv_store.unwrap(), &token_key1).unwrap();
        assert_eq!(priv_meta1, priv_expect1.unwrap());

        // Test key regeneration (by admin)
        let regenerate_keys_msg = HandleMsg::GenerateAuthenticationKeys {
            token_id: "MyNFT".to_string(),
            entropy: Some("randomstring".to_string()),
        };

        let pub_expect2 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
                auth_key: Some([
                    244, 25, 110, 189, 96, 241, 252, 14, 255, 48, 84, 19, 131, 85, 130, 180, 60,
                    238, 94, 96, 202, 139, 226, 36, 15, 254, 180, 236, 109, 23, 171, 58,
                ]),
                ..Extension::default()
            }),
        });
        let priv_expect2 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFTpriv".to_string()),
                description: Some("Nifty".to_string()),
                image: Some("privuri".to_string()),
                auth_key: Some([
                    184, 13, 22, 46, 88, 53, 63, 6, 138, 58, 204, 22, 216, 89, 100, 77, 236, 122,
                    88, 21, 251, 118, 206, 139, 252, 98, 242, 147, 41, 52, 51, 107,
                ]),
                ..Extension::default()
            }),
        });

        let handle_result = handle(&mut deps, mock_env("admin", &[]), regenerate_keys_msg);
        match handle_result {
            Ok(_hr) => {}
            Err(_e) => {
                panic!("Key regeneration by admin failed.")
            }
        }

        let map2idx = Some(ReadonlyPrefixedStorage::new(
            PREFIX_MAP_TO_INDEX,
            &deps.storage,
        ));

        let index1: u32 = load(&map2idx.unwrap(), "MyNFT".as_bytes()).unwrap();
        let token_key1 = index1.to_le_bytes();
        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta2: Metadata = load(&pub_store, &token_key1).unwrap();
        assert_eq!(pub_meta2, pub_expect2.unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta2: Metadata = load(&priv_store, &token_key1).unwrap();
        assert_eq!(priv_meta2, priv_expect2.unwrap());

        // also test key regeneration by owner

        let regenerate_keys_msg2 = HandleMsg::GenerateAuthenticationKeys {
            token_id: "MyNFT".to_string(),
            entropy: Some("randomstring2".to_string()),
        };

        let handle_result = handle(&mut deps, mock_env("alice", &[]), regenerate_keys_msg2);
        match handle_result {
            Ok(_hr) => {}
            Err(_e) => {
                panic!("Key regeneration by owner failed.")
            }
        }
    }

    #[test]
    fn test_send() {
        // test if the authentication keys are updated after the NFT is transferred and/or sent.
        // the tests are not complete as I didn't test every send/transfer and batch transfer messages.
        // but most of these unwritten tests overlap with unittest_handles anyway.
        let (init_result, mut deps, _env) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let david_raw = deps
            .api
            .canonical_address(&HumanAddr("david".to_string()))
            .unwrap();

        let pub_meta = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
                ..Extension::default()
            }),
        });
        let priv_meta = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFTpriv".to_string()),
                description: Some("Nifty".to_string()),
                image: Some("privuri".to_string()),
                ..Extension::default()
            }),
        });

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            entropy: None,
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: pub_meta.clone(),
            private_metadata: priv_meta.clone(),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };

        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let map2idx = Some(ReadonlyPrefixedStorage::new(
            PREFIX_MAP_TO_INDEX,
            &deps.storage,
        ));

        let index1: u32 = load(&map2idx.unwrap(), "MyNFT".as_bytes()).unwrap();
        let token_key1 = index1.to_le_bytes();

        //  record the metadata of the NFT before sending it.

        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &token_key1).unwrap();

        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = may_load(&pub_store, &token_key1).unwrap().unwrap();
        let pub_meta_old = pub_meta.clone();

        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Metadata = load(&priv_store, &token_key1).unwrap();
        let priv_meta_old = priv_meta.clone();

        assert_ne!(token.owner, david_raw);

        // Send the NFT as the owner

        let send_msg = Some(
            to_binary(&HandleMsg::RevokeAll {
                operator: HumanAddr("alice".to_string()),
                padding: None,
            })
            .unwrap(),
        );

        let handle_msg = HandleMsg::SendNft {
            contract: HumanAddr("david".to_string()),
            receiver_info: None,
            token_id: "MyNFT".to_string(),
            msg: send_msg.clone(),
            memo: Some("Xfer it".to_string()),
            padding: None,
        };
        let _handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 1,
                    time: 100,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );

        // Confirm that the autherization keys have been altered.
        let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
        let token: Token = json_load(&info_store, &token_key1).unwrap();

        assert_eq!(token.owner, david_raw);

        let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
        let pub_meta: Metadata = load(&pub_store, &token_key1).unwrap();
        assert_ne!(
            pub_meta.extension.unwrap().auth_key,
            pub_meta_old.extension.unwrap().auth_key
        );
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Metadata = load(&priv_store, &token_key1).unwrap();
        assert_ne!(
            priv_meta.extension.unwrap().auth_key,
            priv_meta_old.extension.unwrap().auth_key
        );
    }
}
