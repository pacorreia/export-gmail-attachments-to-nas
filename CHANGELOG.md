# Changelog

## [1.1.1](https://github.com/pacorreia/export-gmail-attachments-to-nas/compare/v1.1.0...v1.1.1) (2026-05-21)


### Bug Fixes

* **ci:** trigger Docker publish from release-please workflow output ([c287ef4](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/c287ef4a7dd05ca8f0a1f093ce71637d1327ef22))

## [1.1.0](https://github.com/pacorreia/export-gmail-attachments-to-nas/compare/1.0.0...v1.1.0) (2026-05-21)


### Features

* add attachment conversion feature with format selectors ([7b520d8](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/7b520d8d53d2d479fc8277d242f25a7c31146dcf))
* Go rewrite - multi-account Gmail attachment exporter with web UI ([0085466](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/0085466fb157272ba48892a38eaf07bcecda36de))
* Go rewrite with web UI, scheduler, checkpoint deduplication ([d5ea739](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/d5ea7399fd51341ff894c88f25aab2c77c9067fe))
* make convert option explicitly optional with enabled flag ([56ac245](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/56ac2454dedc2dfffdd92cd99d44cdcbaddf8418))


### Bug Fixes

* add comment documenting RELEASE_TOKEN PAT requirements ([d86c49e](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/d86c49ea67236a9385e77c4c5778ae5c9741f6bd))
* add last commit and license badges to README, fix clone URL ([dc96ef5](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/dc96ef5f55e5acf68dbb6721b069c657450183ed))
* address code review findings ([17e9be3](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/17e9be34a9726e467e53aaf15c5ba8833ef97fd3))
* address review comments - base64, auth, DTOs, error handling, typo ([c8c906a](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/c8c906ac428efda9a85352a9f79f6107cd478107))
* **ci:** set repo-checkout: false in govulncheck-action to prevent duplicate Authorization header ([c91c8e9](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/c91c8e9c4d013ca645de8340bb149278f80eae39))
* move release-please permissions to job level and use RELEASE_TOKEN ([8e7e875](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/8e7e875d7eaa47e453f04cbbcc558c6b8fdd7974))
* remove $schema from release-please manifest to fix version parse error ([3b96a00](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/3b96a00dcc6930a498de742b6c36329854db4ce6))
* replace dynamic license badge with static MIT badge and pin SARIF Courier action to commit SHA ([e995533](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/e995533d2989bfe29ba911170071da8e5689d4e2))
* update README to use correct package/CLI name export-gmail-attachments-to-nas ([c8e2970](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/c8e297035476425a3d9d6fdba9f38f7b2d659142))
* use continue instead of break for failed attachment fetch in walkParts ([3a658af](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/3a658afd79f04887645792c7a32a78dcbec7ff91))
* use PageImage struct in pdf converter, remove unused buffer in plugins handler ([e27eadc](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/e27eadc5e438156a6abd34625550f31d04f1e4b9))


### Reverts

* use default GITHUB_TOKEN now that repo settings allow workflow PRs ([68b6aa2](https://github.com/pacorreia/export-gmail-attachments-to-nas/commit/68b6aa2697ac18c79e0adcc1cfb1ed87f68c69ed))
