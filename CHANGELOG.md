## 2026-10-18 DJS-8 APK首审修订

- 单独校验cache/installed的普通单链接、大小、identity/hash及已安装非仓库header；安装前冻结，add/del后按数据库校验允许变化，其他文件继续拒绝。
- cache-max-age改60分钟，避免int乘60溢出；补受影响控制，独立复审待完成。

## DJS-8 APK diagnostic amendment (local candidate, 2026-10-17)

- Preserve the nine build constraints and original pip invocation in one RUN;
  use a private signed APK cache, exact frozen online/offline plans and state
  validation before/after installation, pip and planned deletion. All child
  streams are bounded in RAM; unknown errors stop the build without retry.
- Add a separate exact-eight-path APK receipt whose direct parent is 25bf24d,
  with the fixed prior frontend receipt and all historical validation sources.
  Original suite, frontend types/build and DJS-9 are not reexecuted.
- Draft controls passed: 13 (ev-f83fcc341495), 8 protocol (ev-8de48816b97c),
  revised 16 diagnostic + 9 protocol (ev-626ce9d9181e). Exact committed-source
  controls and independent diff/hash review remain outstanding.
  Receiver reaping errors now still close both pipes and clear RAM buffers;
  17 diagnostic controls passed (ev-f1f0f221eb65).
- Continue locally without subagents: reject preexisting Linux children, reap
  detached/double-fork children, use FD-relative flat-cache cleanup, and fail
  receipt verification under optimized Python. Acquisition signature/conflict/
  stream/cache-write failure boundaries stop before installation.
- New controls: local 23 (ev-a1e5862290f8), actual Linux Python 26
  (ev-ba736a7bc320), receipt protocol 10 (ev-2153b4d0de2a). The Linux
  failures ev-a0ba9871b6cd/ev-3f186a9804f2 exposed a test injection into
  Python's spawn pipe; corrected injection targets only receiver reads.
  Linux controls use synthetic subprocesses, not real APK installation.
  No new CI, artifact or deployment; build #8 remains FAILURE, cause unknown.

## DJS-8：rootfs 私钥材料识别修订

Plane #6 三镜像构建成功、Live Trivy secret/CRITICAL门通过，但额外rootfs规则把同文件无关BEGIN/PRIVATE KEY片段当私钥。实际归档报告确认dotenv16.4.7、react-doctor0.4.2进入Live镜像；本地相同dotenv文档含省略号占位示例、工具代码含匹配串。原rootfs归档未保留，不能断言实际命中路径。

只修额外private-key识别：匹配相邻PEM私钥头与至少16字符key material，支持OpenSSH、加密传统PEM元数据、CRLF、字符串转义换行、跨chunk；截断/错误END/坏base64尾部仍拒绝。文件名、已知secret前缀、扫描树/不可读失败、原certs/ssl例外、Trivy、TLS与三扫描先于canonical push全部保持。纯delimiter/占位文档不等于key material。无Dockerfile、依赖锁或业务改动。

独立rootfs10模式继承固定signing76真实ev-8754072a6d6f及Live46/ev-9705105277b5回执与可信GET，原CI5/Live7/signing9白名单未扩。新扫描/边界/证据绑定控制须clean执行、独立复审、原日志附件SHA回读后才一次正常后继构建；原PGWeb/Live业务验证不重跑，不宣称完整新SHA suite。失败6无可信制品或部署结论。

## DJS-8 · 签名前分范围证据绑定修订

Plane #5 在扫描前因旧 same-SHA 检查拒绝已验证的分范围证据。新增独立 signing-amendment 回执：固定 PG/Web 原 9f93 证据、Live 46aa 实际协议/类型/构建及其可信原回执；新候选只允许精确 CI 文件变化，完整其他 Git 树及 Live 字节不变。原 CI-only 五文件和 Live 七文件模式不扩大。开发证据实时回读、完整变更 blob 和独立审查仍是构建资格，历史测试不会重标为新源码执行。

签名前与包装/发布阶段复用同一严格 source/tree 绑定，记录三类真实验证来源。Plane canonical/staging 精确缺失分类单独限定三个仓库、40hex 或其固定 staging 后缀，认证、限流、TLS/网络错误均拒绝；原通用分类器入口不变。所有三组件扫描先完成再发布、固定根、TLS 与扫描策略保持。新增签名前绑定、模式路由、树漂移和标签正反控制及实际 Jenkins 编译；不重跑已通过的业务或 Live 测试。部署与 UI 验收尚未完成。

## 2026-10-15 DJS-8: locked Live authentication compatibility and scoped verification

Plane build #4 failed at Live TypeScript compilation: locked Hocuspocus 2.15.2 supplies `connection`, while the attachment Page authentication hook and its cast fixture used `connectionConfig`. Use the actual typed payload and mutate its shared readOnly configuration. New real WebSocket/ClientConnection controls prove derived Page updates are rejected, ordinary Page updates are accepted, and denied authentication creates no document connection or credential-bearing logs.

Introduce a separate scoped-live-amendment receipt with the original five CI paths plus exactly the two Live auth source/control paths. The original CI-only whitelist remains unchanged. Preserve original PG/Web evidence and label the old Live3 result historical; bind new affected Live controls/types/full build and every changed blob to a clean candidate and independent review. Dependencies, Dockerfiles, schema, Web/PG trees, test entrypoint and trust root stay protected. No repeated original suite, unsigned deployment, or successful artifact claim for build #4.

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
