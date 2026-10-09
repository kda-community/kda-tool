# `kda-tool` Changelog

## 1.3

### Bug Fixes

- Gives the correct hash in case of unsigned transactions


### Improvements

- Add the `hash` function which outputs the hash of one or several transactions
- Allow to poll using YAML (unsigned transactions)
- Add a system-wide config file (`/etc/kda/config.json`) and merge it with user config, and command line config.


## 1.2

First community version

### Improvements

- Build against Pact 5 instead of Pact 4
- Build on GHC 9.10
- Allow to use tge -s flags with the poll request
- Add the --preflight option
- Support KIP-0026 derivations (Loom / Koala / Linx) for 12/24 words mnemonics
- Add the -d option to the list-keys function to choose the derivation

## 1.1

### Improvements

*   Update to new signing API
*   Allow user to specify the node scheme (i.e. http/https)
*   Add logging verbosity controls, increased logging
*   Add ability to sign and verify arbitrary signatures
*   Allow transactions to be tested before signing with --no-verify-sigs
*   Add -s option to local that gives shortened status output
*   Return an error code if any local transaction doesn't have status "success".

### Bug Fixes

*   Fix handling of holes with a single element array
*   Fix bug in template array handling

## 1.0 (2022-11-09)

Initial release
