# Credits

STR Plugin Messaging API (STRPM) gives SKSE mods a shared messaging layer on top of the Skyrim Together Reborn
connection. This file lists everyone whose work it contains or depends on. It is also in the download as
`Docs/STRPluginMessagingAPI/CREDITS.txt`. If someone is missing or wrong, please open an issue and it will be fixed.

## Authors of this project

- **Caelvanost** (https://github.com/Caelvanost/STRPluginMessagingAPI): author of STRPM and of nearly all of its code,
  the relay resource, the FOMOD installer and the CI packaging. The git history of this repository shows 347 of 353 commits
  by Caelvanost, from the first prototype on 2026-08-13 to the unified multi-runtime 0.10.1 package.
- **Codex (OpenAI)**: an AI coding assistant, recorded as the author of the first three commits (2026-08-13: the initial
  prototype, the SKSE runtime shim and the UDP messaging broker).
- **the3venthoriz0n** (https://github.com/the3venthoriz0n): maintainer of this fork. Three commits: the tag-triggered GitHub
  release workflow, packaging that never overwrites earlier builds, and hardening of the native INT3/TF hooks in the bridge.
  Also the credits and source-archive work in this folder.
- **Claude (Anthropic)**: AI assistance with the three commits by the3venthoriz0n (each has a `Co-Authored-By: Claude`
  trailer).

## Libraries

STRPM links no third-party library. It is built with the Microsoft C++ toolchain against the Windows SDK (Windows.h,
Winsock2, bcrypt) and the C++ standard library, so there is nothing to list in a THIRD_PARTY_NOTICES file. It does not
link CommonLibSSE-NG or any other GPL code.

## What it works with (not included in the download)

- **Skyrim Together Reborn** by the **Tilted Phoques** team (https://skyrim-together.com/, code base
  https://github.com/tiltedphoques/TiltedEvolution). The bridge reads and hooks the STR 1.8.x client binary
  (see `docs/STR_INTERNAL_CONNECTION.md` and `docs/STR_1_8_0_BINARY_FINGERPRINT.md`); none of STR's code is included.
- **Skyrim Script Extender (SKSE)** by Ian Patterson, Stephen Abel, Paul Connelly and Brendan Borthwick (as credited on
  https://skse.silverlock.org/). STRPM is loaded as an SKSE plugin.
- **Skyrim Special Edition / Anniversary Edition** by **Bethesda Game Studios** (a ZeniMax Media company). The base game is
  required; no game data is included.

## Tools used to build it

- Microsoft Visual Studio / MSVC and CMake (Kitware); PowerShell for packaging.
- GitHub Actions for releases.

## Licence note

The relay manifest (`extras/str-server-resources/strpm-chat-relay/strpm-chat-relay.manifest`) declares `license = "MIT"`.
The repository has no separate LICENSE file, so no licence text is reproduced here (nothing is invented). Mods that vendor
the STRPM client header (Party Inventory, Sleep Together, TradeTogether) credit it as MIT for the same reason.
