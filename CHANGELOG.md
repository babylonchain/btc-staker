# Changelog

## [euphrates-0.1.0-rc.0](https://github.com/babylonchain/btc-staker/tree/euphrates-0.1.0-rc.0) (2024-03-26)

[Full Changelog](https://github.com/babylonchain/btc-staker/compare/v0.1.0...euphrates-0.1.0-rc.0)

**Closed issues:**

- restaking: support restaking to consumer chain FPs [\#126](https://github.com/babylonchain/btc-staker/issues/126)
- testing restaking support [\#124](https://github.com/babylonchain/btc-staker/issues/124)
- Faucet scarcity  [\#118](https://github.com/babylonchain/btc-staker/issues/118)
- Stakerd init fails if directory doesn't exist [\#108](https://github.com/babylonchain/btc-staker/issues/108)

**Merged pull requests:**

- e2e test for restaking [\#125](https://github.com/babylonchain/btc-staker/pull/125) ([SebastianElvis](https://github.com/SebastianElvis))
- Add cli command to verify whether tx is valid phase1 staking tx [\#123](https://github.com/babylonchain/btc-staker/pull/123) ([KonradStaniec](https://github.com/KonradStaniec))
- Bump babylon version [\#121](https://github.com/babylonchain/btc-staker/pull/121) ([KonradStaniec](https://github.com/KonradStaniec))
- Add possiblity to send concurrent transactions [\#117](https://github.com/babylonchain/btc-staker/pull/117) ([KonradStaniec](https://github.com/KonradStaniec))
- Add metrics [\#115](https://github.com/babylonchain/btc-staker/pull/115) ([KonradStaniec](https://github.com/KonradStaniec))
- Switch e2e test to use bitcoind instead of btcd/btcd wallet combo [\#114](https://github.com/babylonchain/btc-staker/pull/114) ([KonradStaniec](https://github.com/KonradStaniec))
- chore: Increase staking time in docs [\#113](https://github.com/babylonchain/btc-staker/pull/113) ([vitsalis](https://github.com/vitsalis))
- Add CHANGELOG [\#112](https://github.com/babylonchain/btc-staker/pull/112) ([maurolacy](https://github.com/maurolacy))
- Bitcoind tests [\#110](https://github.com/babylonchain/btc-staker/pull/110) ([KonradStaniec](https://github.com/KonradStaniec))
- docs: Incorporate validator feedback [\#109](https://github.com/babylonchain/btc-staker/pull/109) ([gusin13](https://github.com/gusin13))
- Bump staker to stable babylon version [\#106](https://github.com/babylonchain/btc-staker/pull/106) ([KonradStaniec](https://github.com/KonradStaniec))
- Bumps babylon to latest version [\#105](https://github.com/babylonchain/btc-staker/pull/105) ([KonradStaniec](https://github.com/KonradStaniec))
- bump babylon version [\#104](https://github.com/babylonchain/btc-staker/pull/104) ([KonradStaniec](https://github.com/KonradStaniec))
- docs: Add instructions to setup bitcoind signet node [\#103](https://github.com/babylonchain/btc-staker/pull/103) ([gusin13](https://github.com/gusin13))
- CI: Remove redundant SSH key logic [\#102](https://github.com/babylonchain/btc-staker/pull/102) ([filippos47](https://github.com/filippos47))
- docs: Remove btcd refs [\#101](https://github.com/babylonchain/btc-staker/pull/101) ([gusin13](https://github.com/gusin13))
- docs: Mention legacy wallet requirement [\#96](https://github.com/babylonchain/btc-staker/pull/96) ([filippos47](https://github.com/filippos47))
- docs: Include ZMQ endpoint config [\#94](https://github.com/babylonchain/btc-staker/pull/94) ([filippos47](https://github.com/filippos47))

## [v0.1.0](https://github.com/babylonchain/btc-staker/tree/v0.1.0) (2024-02-08)

[Full Changelog](https://github.com/babylonchain/btc-staker/compare/v0.1.0-rc.0...v0.1.0)

**Closed issues:**

- Improper handling of pending delegations upon restart [\#58](https://github.com/babylonchain/btc-staker/issues/58)

## [v0.1.0-rc.0](https://github.com/babylonchain/btc-staker/tree/v0.1.0-rc.0) (2024-01-22)

[Full Changelog](https://github.com/babylonchain/btc-staker/compare/263d857429d555e0772d104dbeee70ab4e4d8c89...v0.1.0-rc.0)

**Breaking changes:**

- Adjust data model to store confirmed block info [\#53](https://github.com/babylonchain/btc-staker/pull/53) ([KonradStaniec](https://github.com/KonradStaniec))
- Adapt spend stake endpoint to unbonding tx [\#48](https://github.com/babylonchain/btc-staker/pull/48) ([KonradStaniec](https://github.com/KonradStaniec))
- Introduce watched transactions  to enable staker to act as queuing service. [\#45](https://github.com/babylonchain/btc-staker/pull/45) ([KonradStaniec](https://github.com/KonradStaniec))
- use prod hint cache [\#40](https://github.com/babylonchain/btc-staker/pull/40) ([KonradStaniec](https://github.com/KonradStaniec))
- List all tracked transaction query [\#33](https://github.com/babylonchain/btc-staker/pull/33) ([KonradStaniec](https://github.com/KonradStaniec))
- Improve data model [\#32](https://github.com/babylonchain/btc-staker/pull/32) ([KonradStaniec](https://github.com/KonradStaniec))

**Closed issues:**

- Unable to dump configuration if parent directory doesn't exist [\#88](https://github.com/babylonchain/btc-staker/issues/88)
- Cannot withdraw expired delegation [\#81](https://github.com/babylonchain/btc-staker/issues/81)
- Unbonding request tx can't be sent to BTC [\#76](https://github.com/babylonchain/btc-staker/issues/76)
- Support for multiple validators when re-staking [\#68](https://github.com/babylonchain/btc-staker/issues/68)
- Add additional field `unbodningTime` to `BTCUndelegationInfo` in query `BTCDelegation` and use it in staker app [\#67](https://github.com/babylonchain/btc-staker/issues/67)
- Proper handling of restarts [\#27](https://github.com/babylonchain/btc-staker/issues/27)
- `StakeFunds` should check whether the btc validator exists  [\#20](https://github.com/babylonchain/btc-staker/issues/20)

**Merged pull requests:**

- chore: Upgrade bbn to 0.8.0-rc.0 [\#93](https://github.com/babylonchain/btc-staker/pull/93) ([vitsalis](https://github.com/vitsalis))
- license and public deps [\#92](https://github.com/babylonchain/btc-staker/pull/92) ([KonradStaniec](https://github.com/KonradStaniec))
- fix: Add BLS flags in make [\#91](https://github.com/babylonchain/btc-staker/pull/91) ([gusin13](https://github.com/gusin13))
- chore: restructure and improve docs [\#90](https://github.com/babylonchain/btc-staker/pull/90) ([gusin13](https://github.com/gusin13))
- create dir if not exists [\#89](https://github.com/babylonchain/btc-staker/pull/89) ([KonradStaniec](https://github.com/KonradStaniec))
- Fix signet support [\#87](https://github.com/babylonchain/btc-staker/pull/87) ([KonradStaniec](https://github.com/KonradStaniec))
- Handle lock time change output [\#86](https://github.com/babylonchain/btc-staker/pull/86) ([KonradStaniec](https://github.com/KonradStaniec))
- Fix dynamic fee estimation [\#85](https://github.com/babylonchain/btc-staker/pull/85) ([KonradStaniec](https://github.com/KonradStaniec))
- Bump babylon [\#84](https://github.com/babylonchain/btc-staker/pull/84) ([KonradStaniec](https://github.com/KonradStaniec))
- Fix withdrawing [\#83](https://github.com/babylonchain/btc-staker/pull/83) ([KonradStaniec](https://github.com/KonradStaniec))
- Bump babylon. Use min unbonding time [\#82](https://github.com/babylonchain/btc-staker/pull/82) ([KonradStaniec](https://github.com/KonradStaniec))
- Rename validator to finality provider [\#79](https://github.com/babylonchain/btc-staker/pull/79) ([KonradStaniec](https://github.com/KonradStaniec))
- Pre signed unbonding [\#78](https://github.com/babylonchain/btc-staker/pull/78) ([KonradStaniec](https://github.com/KonradStaniec))
- Fix unbonding witness building [\#77](https://github.com/babylonchain/btc-staker/pull/77) ([KonradStaniec](https://github.com/KonradStaniec))
- docs: Setup docs [\#75](https://github.com/babylonchain/btc-staker/pull/75) ([gusin13](https://github.com/gusin13))
- fix: Use the slashing change address flag [\#72](https://github.com/babylonchain/btc-staker/pull/72) ([vitsalis](https://github.com/vitsalis))
- Handle multiple validators [\#71](https://github.com/babylonchain/btc-staker/pull/71) ([KonradStaniec](https://github.com/KonradStaniec))
- Use unbonding time from bayblon [\#70](https://github.com/babylonchain/btc-staker/pull/70) ([KonradStaniec](https://github.com/KonradStaniec))
- Bump babylon and use new staking tx and unbonding tx [\#66](https://github.com/babylonchain/btc-staker/pull/66) ([KonradStaniec](https://github.com/KonradStaniec))
- feat: Utilize new slashing tx format [\#64](https://github.com/babylonchain/btc-staker/pull/64) ([gusin13](https://github.com/gusin13))
- Add support for ecdsa sig type [\#63](https://github.com/babylonchain/btc-staker/pull/63) ([KonradStaniec](https://github.com/KonradStaniec))
- Add criticial error channel and simplify unbodning send [\#62](https://github.com/babylonchain/btc-staker/pull/62) ([KonradStaniec](https://github.com/KonradStaniec))
- Bump babylon version [\#61](https://github.com/babylonchain/btc-staker/pull/61) ([KonradStaniec](https://github.com/KonradStaniec))
- Extract modules [\#60](https://github.com/babylonchain/btc-staker/pull/60) ([KonradStaniec](https://github.com/KonradStaniec))
- Fix restart bug [\#59](https://github.com/babylonchain/btc-staker/pull/59) ([KonradStaniec](https://github.com/KonradStaniec))
- Code cleanup [\#56](https://github.com/babylonchain/btc-staker/pull/56) ([KonradStaniec](https://github.com/KonradStaniec))
- Get withdrawable transactions endpoint [\#55](https://github.com/babylonchain/btc-staker/pull/55) ([KonradStaniec](https://github.com/KonradStaniec))
- Extend restart to unbonding tx [\#52](https://github.com/babylonchain/btc-staker/pull/52) ([KonradStaniec](https://github.com/KonradStaniec))
- fix restart [\#51](https://github.com/babylonchain/btc-staker/pull/51) ([KonradStaniec](https://github.com/KonradStaniec))
- Add handling of new pop type [\#47](https://github.com/babylonchain/btc-staker/pull/47) ([KonradStaniec](https://github.com/KonradStaniec))
- Unbonding flow [\#46](https://github.com/babylonchain/btc-staker/pull/46) ([KonradStaniec](https://github.com/KonradStaniec))
- chore: Update bbn version [\#44](https://github.com/babylonchain/btc-staker/pull/44) ([vitsalis](https://github.com/vitsalis))
- Force larger staking time [\#43](https://github.com/babylonchain/btc-staker/pull/43) ([KonradStaniec](https://github.com/KonradStaniec))
- chore: Update dn unstake operation help msg [\#42](https://github.com/babylonchain/btc-staker/pull/42) ([filippos47](https://github.com/filippos47))
- Imporve checking for best block [\#41](https://github.com/babylonchain/btc-staker/pull/41) ([KonradStaniec](https://github.com/KonradStaniec))
- Recovery after restart [\#39](https://github.com/babylonchain/btc-staker/pull/39) ([KonradStaniec](https://github.com/KonradStaniec))
- Fix bug in list\_transactions [\#36](https://github.com/babylonchain/btc-staker/pull/36) ([KonradStaniec](https://github.com/KonradStaniec))
- Add some missing daemon commands [\#35](https://github.com/babylonchain/btc-staker/pull/35) ([KonradStaniec](https://github.com/KonradStaniec))
- Improve e2e test [\#34](https://github.com/babylonchain/btc-staker/pull/34) ([KonradStaniec](https://github.com/KonradStaniec))
- Add check that validator exists before allowing for staking [\#31](https://github.com/babylonchain/btc-staker/pull/31) ([KonradStaniec](https://github.com/KonradStaniec))
- Improve slashing fee handling [\#30](https://github.com/babylonchain/btc-staker/pull/30) ([KonradStaniec](https://github.com/KonradStaniec))
- Only show active validators [\#29](https://github.com/babylonchain/btc-staker/pull/29) ([vitsalis](https://github.com/vitsalis))
- Stall when babylon node is not ready [\#26](https://github.com/babylonchain/btc-staker/pull/26) ([KonradStaniec](https://github.com/KonradStaniec))
- Add babylon to e2e test [\#25](https://github.com/babylonchain/btc-staker/pull/25) ([KonradStaniec](https://github.com/KonradStaniec))
- nit: Update Block Cache Size default and fix usage [\#24](https://github.com/babylonchain/btc-staker/pull/24) ([vitsalis](https://github.com/vitsalis))
- Fix delegation bug [\#23](https://github.com/babylonchain/btc-staker/pull/23) ([KonradStaniec](https://github.com/KonradStaniec))
- nit: Add default values for ZMQ messages [\#22](https://github.com/babylonchain/btc-staker/pull/22) ([vitsalis](https://github.com/vitsalis))
- nit: default to btcwallet for wallet backend type [\#21](https://github.com/babylonchain/btc-staker/pull/21) ([vitsalis](https://github.com/vitsalis))
- fix: Replace deprecated SignRawTransaction [\#19](https://github.com/babylonchain/btc-staker/pull/19) ([vitsalis](https://github.com/vitsalis))
- cli for staking BTC to Babylon [\#18](https://github.com/babylonchain/btc-staker/pull/18) ([SebastianElvis](https://github.com/SebastianElvis))
- fix: offset and limit params out of order [\#17](https://github.com/babylonchain/btc-staker/pull/17) ([vitsalis](https://github.com/vitsalis))
- Fix signers field in message [\#16](https://github.com/babylonchain/btc-staker/pull/16) ([KonradStaniec](https://github.com/KonradStaniec))
- makefile: Add build-docker command [\#15](https://github.com/babylonchain/btc-staker/pull/15) ([vitsalis](https://github.com/vitsalis))
- chore: Minor cleanup and nitpicks [\#14](https://github.com/babylonchain/btc-staker/pull/14) ([vitsalis](https://github.com/vitsalis))
- Add query for current babylon validators [\#13](https://github.com/babylonchain/btc-staker/pull/13) ([KonradStaniec](https://github.com/KonradStaniec))
- Add api to spend staking transaction after time lock [\#12](https://github.com/babylonchain/btc-staker/pull/12) ([KonradStaniec](https://github.com/KonradStaniec))
- Command to check wallets outputs [\#11](https://github.com/babylonchain/btc-staker/pull/11) ([KonradStaniec](https://github.com/KonradStaniec))
- Add fee estimation [\#10](https://github.com/babylonchain/btc-staker/pull/10) ([KonradStaniec](https://github.com/KonradStaniec))
- Improve handling of sending delegation to babylon [\#9](https://github.com/babylonchain/btc-staker/pull/9) ([KonradStaniec](https://github.com/KonradStaniec))
- Add dockerfile and push images to ECR [\#8](https://github.com/babylonchain/btc-staker/pull/8) ([KonradStaniec](https://github.com/KonradStaniec))
- Bump babylon to latest version [\#7](https://github.com/babylonchain/btc-staker/pull/7) ([KonradStaniec](https://github.com/KonradStaniec))
- Add admin commands [\#6](https://github.com/babylonchain/btc-staker/pull/6) ([KonradStaniec](https://github.com/KonradStaniec))
- Babylon communication and persistence [\#5](https://github.com/babylonchain/btc-staker/pull/5) ([KonradStaniec](https://github.com/KonradStaniec))
- Add initial stake command [\#4](https://github.com/babylonchain/btc-staker/pull/4) ([KonradStaniec](https://github.com/KonradStaniec))
- Add server and daemon mode [\#3](https://github.com/babylonchain/btc-staker/pull/3) ([KonradStaniec](https://github.com/KonradStaniec))
- Add core logic for funding, building, signing, sending staking transaciton [\#2](https://github.com/babylonchain/btc-staker/pull/2) ([KonradStaniec](https://github.com/KonradStaniec))
- Project skeleton with initial cli command [\#1](https://github.com/babylonchain/btc-staker/pull/1) ([KonradStaniec](https://github.com/KonradStaniec))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
