# Decentralized Password Vault (Encrypted OffChain)

A secure, decentralized password vault built on Stacks blockchain. This smart contract allows users to store encrypted password data with access controlled by NFTs.

## Overview

This contract implements a password vault system where:

1. Each vault is represented by an NFT
2. Only the NFT owner can access or modify the vault contents
3. All sensitive data is stored encrypted (encryption happens off-chain)
4. Vault ownership can be transferred by transferring the NFT

## Features

- Create personal password vaults
- Store encrypted password entries (the encryption happens client-side)
- Update and delete password entries
- Transfer vault ownership to another user
- Each vault has its own encryption details

## How It Works

1. Users register with the system
2. Users create a vault, which mints an NFT to them
3. The vault owner can add encrypted password entries
4. Only the vault NFT owner can read, update, or delete entries
5. Vault ownership can be transferred by transferring the NFT

## Contract Functions

### User Management
- `register-user`: Register a new user with the system

### Vault Management
- `create-vault`: Create a new password vault (mints an NFT)
- `get-vault-metadata`: Get metadata about a vault
- `get-vault-encryption-details`: Get encryption details for a vault
- `update-encryption-details`: Update the encryption details for a vault
- `transfer-vault`: Transfer vault ownership to another user

### Entry Management
- `add-vault-entry`: Add a new encrypted entry to a vault
- `update-vault-entry`: Update an existing entry
- `delete-vault-entry`: Delete an entry from a vault
- `get-vault-entry`: Get a specific entry from a vault
- `get-vault-entry-count`: Get the number of entries in a vault

## Security Model

- All sensitive data is encrypted client-side before being stored
- The contract only stores encrypted data - it never sees plaintext passwords
- Access control is enforced through NFT ownership
- Each vault can have its own encryption key and version

## Usage Example

1. Register as a user
2. Create a vault with your public key for encryption
3. Add encrypted password entries to your vault
4. Access your entries by querying the vault
5. Transfer ownership if needed

## Implementation Notes

The contract is designed to be minimal but complete. The actual encryption and decryption of password data happens off-chain in the client application.