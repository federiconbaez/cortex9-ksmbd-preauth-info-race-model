# Limitations

- **Record status, stated explicitly.** On NVD, CVE-2026-72422 is still
  **"Received"** (not analysed; local copy: published 2026-08-15,
  last modified 2026-08-17). This repo was built only because the record and
  the fix commit are published by primary kernel sources: the cve.org record
  (state PUBLISHED, CNA "Linux") and the kernel CVE team's announcement in
  `vulns.git` (`cve/published/2026/CVE-2026-72422.mbox` and `.sha1`) both
  name 0c054227479ed7e36ebccb3a558bc0ef698264f6 as the fix ("fixed in 7.2"),
  and git.kernel.org serves a patch for that commit that is byte-identical to
  the local copy. NVD's own analysis (CPEs, a primary score) does not exist
  yet: the CVSS 3.1 9.8 shown in both records was supplied by the CNA (NVD
  lists it as "Secondary").
- **A model, not a finding.** No kernel was built, booted or run, and no SMB
  traffic was sent. The model restates the patch and its commit message.
  The KASAN report mentioned in the message was not seen.
- **Steps are abstract.** `USE` stands for the reads and writes inside
  `ksmbd_gen_preauth_integrity_hash()`; their number and order, the SHA-512
  computation, and how `work->response_buf` is used are not modelled. One
  `USE` step per sender is a simplification: a longer use only widens the
  window.
- **The handler.** Only what the commit message says is modelled (allocation,
  `kfree` and NULL under `conn_lock`). Whether a new allocation frees or
  leaks a previous object, what makes `deassemble_neg_contexts()` fail, and
  how two NEGOTIATE requests reach two workers on one connection are **not
  verified**; the variants and the `null`/`live` start cover the choices.
- **Memory model.** Steps are sequentially consistent and atomic. Compiler
  reordering is reduced to the `reload`/`cached` choice; CPU memory ordering,
  `READ_ONCE`, RCU and slab reuse (a freed object being reallocated) are not
  modelled. The mutex is a plain owner field (no fairness, no sleeping).
- **Other fields and paths.** Other users of `conn->preauth_info`, the
  SESSION_SETUP branch below the hunk and the stable backports
  (c7bef847, d0a46912, 7470511d, 16a1ecf3, 77bb0bbf, 1c89da3b) were not
  read; their code may differ from the mainline patch.
- **Bounds.** 1-3 rounds and 1-2 senders; the enumeration is exhaustive only
  inside those bounds.
- Nothing is attributed beyond the commit and records in SOURCES.md.
