# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 28-05-2026

### Changed
- Secret authentication to certificate authentication

### Fixed
- Exchange users were grouped with the wrong property, changed from `DisplayName` to `Id`.
- Group memberships calculation didn't work.

## [1.0.1] - 28-05-2025

### Fixed
- Corrected verbose logging -eq true to write-verbose (#2)

## [1.0.0] - 08-05-2025
Initial commit with base functionality

