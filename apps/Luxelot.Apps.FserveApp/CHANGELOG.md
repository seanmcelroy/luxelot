# Changelog

## 1.1 - 2024-11-24

### Changed

- Changed `fslogin` command to by default send ANONYMOUS if no username is specified

### Added

- Using the `fslogin` command now automatically start the `fs` client app interactive mode
- Added new `HideEmptyDirectories` configuration option
- Partially implemented `fsprepare` command to prepare for chunked downloads

### Fixed

- Subdirectory names were showing part of the relative path instead of just the directory name.