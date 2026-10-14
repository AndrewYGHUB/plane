## 2026-10-15 · DJS-8 首次仓库判定与 CI-only 证据模式

- Plane#3 backend首次精确SHA标签读取失败；认证Registry404精确repository NOT_FOUND投影已确认，原crane stderr未保留，不冒称该原日志。新分类器只接受精确manifest URL/repo/full40SHA缺失，认证/限流/5xx/网络拒绝；返回0/4/2合同保留。
- 原业务、测试、Dockerfile、依赖和信任根完整Git树不变时，允许独立审查CI-only回执模式。仅5个逐文件枚举路径可不同，每个CI mode/blob/SHA256须绑定固定可信作者回执；新CI控制需实时回读实际rc0/命令/新SHA/日志hash。无回执或任何漂移均拒绝，不由新脚本自行授权。
- 原PG62/Web5/Live3仍在9f93a7b4ebf12f73b2f42022081d6530a1fac02c执行，ev-a57cc79a0483保留。发布分别记录tested_source_sha/build_source_sha/tree_equivalence，full_unit_test_suite_executed=False。未重跑原suite，无新构建/制品/部署结论。

# Changelog

## 2026-10-14 · DJS-8 Jenkins Groovy escaping

- Escape the embedded Python regex and newline at the Groovy layer so Jenkins can compile the evidence-readback stage. The original Jenkinsfile is rejected by the actual Declarative compiler; the corrected Jenkinsfile validates (Plane evidence ev-ed88c165d57d).
- Preserve source/SHA and required-suite binding; build and production acceptance remain pending.

## 2026-10-14 · DJS-8 issue attachment Page preview

- Add an administrative issue-attachment to same-project Page mapping and safe derived Page previews for supported image and text attachments.
- Route mapped attachment clicks to the Plane Page; do not fall back to the original download URL when preview is unavailable or forbidden.
- Preserve the original FileAsset identity and source metadata, and enforce issue/Page permissions for browser and API-key paths.
- Build the web, API, and Live images from the controlled fork source and immutable Harbor base-image references; keep upstream admin/space images on their existing Harbor digests.
- Development evidence is tracked in Plane DJS-8. This entry records the current implementation scope; it does not claim a Jenkins build, Harbor publication, Flux deployment, or production browser acceptance.
