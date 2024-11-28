# Changelog

## 1.4 - 2024-11-27

### Changed

- `fslist` follows symbolic link targets, as applicable
- `fslist` no longer shows results to special device or other files without permission bits
- `fslist` no longer shows results with zero permissions set (mode=000 with any umask applied)
- `fsprepare` no longer allows preparing files for download if they lack mode o=r (others can read)

### Added

- `fslist` shows *nix mode permission bits and will show 'd' to indicate directories
- Umask configuration applied to display results

## 1.3 - 2024-11-26

### Changed

- Completed implementation of `fsdownload` command and multi-chunk file reassembly
- Modified the output of `fslist` for readability, more similiar to *nix `ls`
- Upgraded to .NET 9.0 SDK

### Added

- Command for `fslcd` to specify the download directory using a 'change local directory'/'lcd' paradigm

## 1.2 - 2024-11-25

### Changed

- Completed implementation of `fsprepare` command

### Added

- Added `fsdownload` command, partially implemented to download files up to 1 chunk (1MB)

## 1.1 - 2024-11-24

### Changed

- Changed `fslogin` command to by default send ANONYMOUS if no username is specified

### Added

- Using the `fslogin` command now automatically start the `fs` client app interactive mode
- Added new `HideEmptyDirectories` configuration option
- Partially implemented `fsprepare` command to prepare for chunked downloads

### Fixed

- Subdirectory names were showing part of the relative path instead of just the directory name.