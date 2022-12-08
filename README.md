This is a link to the frontend repo demonstrating NFT authorization: https://github.com/zorostang/nft-authorization-front-end

# SNIP-721 nft-authorization
This contract is a reference implementation using [Baedrik's SNIP-721 implementation](https://github.com/baedrik/snip721-reference-impl) as a framework, for web3 authentication by proving the ownership of the NFT via a public-private key pair.

The complimentary keys are stored in the extenision field of public and privite metadata respectively. Therefore, this implementation of the SNIP-721 does not allow minting NFTs with no metadata nor using `token_uri`. The public/private key is stored in the `auth_key: Option<[u8; 32]>` field of the `Extension` struct for public/private metadata.

Some changes have been made to the unit tests to ensure they pass. This includes addition of autherization keys to the metadata even before the autherization keys are generated in the contract.

## Changes to HandleMessages
No changes were made to query messsages or the init message. Only a few changes were made to the handle messages. A new optional `entropy: Option<String>`  field was added to `MintNft`, `BatchMintNft`, and `MintNftClones` handle messages to add randomness to the prng seed used for key generation. 

The only caveat is that Minting with no metadata or with no extenision field causes the program to create a default metadata with all fields inside its extension struct set to `None` except for `auth_key` which is generated upon minting.

A new handle message was added called `GenerateAuthenticationKeys`. This handle message is used to generate a new pair of public/private keys on demand and remove the previous keypair. The owner and the admin can use this, the minter can also use this if `minter_may_update_metadata: true` in the config.
```
GenerateAuthenticationKeys {
        token_id: String,
        entropy: Option<String>,
    },
```

## New Functions to understand
The most important new function to understand is `metadata_generate_keypair_impl()` in `contract.rs`
```
pub fn metadata_generate_keypair_impl<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    entropy: Option<String>,
    idx: u32,
) -> HandleResult {...
```
This function takes some optional entropy provided by the user and the NFT's index value, it then generates a new keypair to saves into the metadata of the specified token. The rest of the funtions added are helpers to this function.
