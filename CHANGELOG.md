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
