# nft-authorization
This contract extends SNIP-721 standard to generate a public-private key pair that can be used by the owner for web3 authorization.

The keys are stored in public and privite metadata respectively. Therefore, this implementation of the SNIP-721 does not allow minting NFTs with an empty extension field in its metadata.
