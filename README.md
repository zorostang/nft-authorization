# nft-authorization
This contract extends SNIP-721 standard to generate a public-private key pair that can be used by the owner for web3 authorization.

The keys are stored in public and privite metadata respectively. Therefore, this implementation of the SNIP-721 does not allow minting NFTs with an empty extension field in its metadata.

Some changes have been made to the unit tests to ensure they pass. This includes addition of autherization keys to the metadata even before the autherization keys are generated in the contract.