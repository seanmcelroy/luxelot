# Changelog

## 1.1 - 2024-11-24

### Added

- Added a loopback peer to allow for offline testing of apps by sending and receiving messages to oneself
- Exponential backoff for mutex acquisition for Bouncy Castle methods to improve start-up speeds
- Semantic versioning auto-incremented by build date.  First two version components, such as 1.1 in 1.1.234.5678 are defined in code and these release notes.
- Improved logging messages for tasks that include a descriptive task name
