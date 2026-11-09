# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo); the SHA-256 of each copy is in that directory's `SHA256SUMS`
(re-checked on 2026-11-09). The kernel.org and cve.org copies were fetched
again on 2026-11-09 (GET only) and compared with the earlier copies.

| Source | URL | Used for | SHA-256 of copy |
|---|---|---|---|
| Fix commit 0c054227479ed7e36ebccb3a558bc0ef698264f6 ("ksmbd: fix use-after-free of conn->preauth_info in concurrent SMB2 NEGOTIATE"; 1 file +7/-4; `Fixes: aa7253c2393f`) | https://git.kernel.org/stable/c/0c054227479ed7e36ebccb3a558bc0ef698264f6 | `smb2pdu.c` old 9371-9374, new 9371-9377; commit message, 2nd paragraph (handler under `conn_lock`) | 8114172fc0ebfef6181e97ce6813bb9b5faeb2b70a331bbb039078f4910a4c9d |
| Kernel CVE announcement, `vulns.git` `cve/published/2026/CVE-2026-72422.mbox` | https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/2026/CVE-2026-72422.mbox | introduced/fixed pairs: introduced in 6.0 by aa7253c2393f (5.15.61 by dd4e4c811898, 5.18.18 by 8a8315a5960b, 5.19.2 by ff20f1875889); fixed in 5.15.212 (c7bef84740d1), 6.1.178 (d0a469122e7b), 6.6.145 (7470511d085a), 6.12.97 (16a1ecf39c21), 6.18.40 (77bb0bbfcc4e), 7.1.5 (1c89da3baa2b), 7.2 (0c054227479e) | 114f6aa8144d1d67ed983582101709a74a00462662ab81f78c647ba3e9d84296 |
| Same, `CVE-2026-72422.sha1` (the fix commit id) | https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/2026/CVE-2026-72422.sha1 | fix id 0c054227479e | c0b4c3a34ee4cbc25cd88b96c970c9645e0da749167d9ff2bc9058378fb5eb81 |
| CVE record (cve.org, PUBLISHED, CNA Linux, 2026-08-15) | https://www.cve.org/CVERecord?id=CVE-2026-72422 | affected/unaffected ranges, references to the stable commits | 374ba5aba7e4ca25f322347f233f14a9a2ebec516007980e06cd96147d8db0d9 |
| NVD CVE-2026-72422 (**Received**) | https://nvd.nist.gov/vuln/detail/CVE-2026-72422 | status only | 0ef044898e2f59461192c446b9662262f2f54ba0681ed8039ee87d8ebdddb6b0 |

The patch served at `git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id=0c054227479e...`
on 2026-11-09 was byte-identical to the local copy. Names and addresses in
the commit trailers are not reproduced here. No source contained
instructions addressed to a tool or agent.
