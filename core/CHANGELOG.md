# Changelog

## 1.4 - 2024-11-26

### Changed

- Improved error handling for cross-platform execution and settings file parsing
- Changed peer ports in default settings file to IANA unassigned range 9763-9799
- Upgraded to .NET 9.0 SDK
- Resolved buffer issues related to large message sizes

## 1.3 - 2024-11-25

### Changed

- Adjusted core to handle messages up to 1MB+1KB, up from 16KB
- Improved exception handling during message processing

## 1.2 - 2024-11-24

### Changed

- ConsoleAlert removed and changed into SynAck
- Ack and SynAck share the remote IP addresses each peer observes for the other for future NAT hole punching
- Updated core documentation to note the NoKeyContainerEncryption option
- Fixed header alignment issue in 'peers' console command output
- Renamed command 'close' to 'disconnect' to align with symmetric 'connect' command
- Using commands can now automatically start a loadable app's interactive mode

### Added

- Replaced simple thumbnail signature cache with Kademila distributed hash table structure
- Replaced 'cache' console command with 'dht' console command of equivilant output
- Added new 'quit' command to end console connection so user does not have to `^C` to exit
- Added short help descriptions for loadable app commands to the core "help" command

## 1.1 - 2024-11-23

### Added

- Added a loopback peer to allow for offline testing of apps by sending and receiving messages to oneself
- Exponential backoff for mutex acquisition for Bouncy Castle methods to improve start-up speeds
- Semantic versioning auto-incremented by build date.  First two version components, such as 1.1 in 1.1.234.5678 are defined in code and these release notes.
- Improved logging messages for tasks that include a descriptive task name
