# FPIN Patch Series: dev/jesse/fpin_v12b vs fpin_v11a

## Overview

| Property | fpin_v11a | dev/jesse/fpin_v12b |
|---|---|---|
| Base kernel | Linux 6.18 (`7d0a66e4bb90`) | Linux 7.1-rc7 (`4549871118cf`) |
| FPIN patch count | 12 | 17 (12 core + 5 debug/WIP) |
| Author(s) | John Meneghini / Hannes Reinecke | Jesse Taube / John Meneghini / Hannes Reinecke |

---

## Patch-by-Patch Comparison

### Common patches (present in both, with modifications)

| # | fpin_v11a commit | dev/jesse/fpin_v12b commit | Subject | Changes in v12b |
|---|---|---|---|---|
| 1 | `dca5f9e2e995` | `d98e8b1b06fc` | fc_els: use 'union fc_tlv_desc' | Same logical change. v12b uses `__struct_group()` macro for `fc_df_desc_fpin_reg` instead of the Revert approach in v11a. Adds `_Static_assert` and `offsetof` includes. |
| 2 | `8f4d70b03fe3` | `2ff8171ce4db` | nvme: add NVME_CTRL_MARGINAL flag | Identical. |
| 3 | `1ec7fd8a7f3a` | `162e84c2e480` | nvme: sysfs: emit the marginal path state in show_state() | Identical. |
| 4 | `b27e63b8a9c7` | `9099d9700579` | nvme-multipath: queue-depth support for marginal paths | **Significant change** -- see details below. |
| 5 | `8d072fa92de8` | `fef49be1ea5a` | scsi_transport_fc: user support for clearing NVME_CTRL_MARGINAL | v12b uses `set_rport_marginal` callback instead of direct `nvme_fc_modify_rport_fpin_state()` calls with `#if IS_ENABLED(CONFIG_NVME_FC)` guards. |
| 6 | `63eeea46a154` | `eebfbbdce5c3` | scsi: lpfc: enable FPIN notification for NVMe | v12b implements `set_rport_marginal` callback (`lpfc_set_rport_marginal`) in `fc_function_template` using `nvme_fc_set_remoteport_fpin()`. v11a called `fc_host_fpin_set_nvme_rport_marginal()` from the FPIN receive path. |
| 7 | `c503e53b5266` | `5308c3e5950e` | scsi: qla2xxx: enable FPIN notification for NVMe | Same architectural change as lpfc -- v12b implements `set_rport_marginal` callback (`qla2x00_set_rport_marginal`) using `nvme_fc_set_remoteport_fpin()`. |
| 8 | `183686131f07` | `85df4ff72502` | scsi: qla2xxx: Fix 2 memcpy field-spanning write issue | Identical. |

### Structurally different patches (same goal, different implementation)

| fpin_v11a | dev/jesse/fpin_v12b | Description |
|---|---|---|
| `e216cb9441b8` scsi_transport_fc: add `fc_host_fpin_set_nvme_rport_marginal()` | `4c54478dfe6d` scsi_transport_fc: Add `set_rport_marginal` to `fc_function_template` | **Major architectural change.** See details below. |
| `0341c5bc8d17` nvme-fc: add `nvme_fc_modify_rport_fpin_state()` | `6db91ca56462` nvme-fc: add `nvme_fc_set_remoteport_fpin()` | **Simplified API.** See details below. |
| `5e755bfde0b8` nvme-fc: marginal path handling (single patch) | `554e1289ea96` nvme-fc: marginal path handling for numa policy + `59120450a4f8` nvme-multipath: round-robin support for marginal paths | **Split into two patches** with different marginal path priority logic. See details below. |

### Patches only in fpin_v11a

| Commit | Subject | Notes |
|---|---|---|
| `2c5ca23321ac` | Revert "scsi: fc: Avoid -Wflex-array-member-not-at-end warnings" | Not needed in v12b; the 7.1-rc7 base uses `__struct_group()` macro approach instead. |

### Patches only in dev/jesse/fpin_v12b

| Commit | Subject | Notes |
|---|---|---|
| `59120450a4f8` | nvme-multipath: round-robin support for marginal paths | New patch adding round-robin awareness of marginal paths. |
| `15e632ba31e7` | Add debug statements to show fpin packets | **Debug/WIP** -- adds `fpin_dump_buffer()` hex dump and `pr_warn` trace statements in `fc_host_fpin_rcv()`. Marked for investigation of qla2xxx truncated FPIN packets. |
| `b174df9248c4` | scsi: qla2xxx: fix qla27xx_copy_ fpin functions | Replaces `sizeof(item->iocb.iocb)` with `QLA_DEFAULT_PAYLOAD_SIZE` (both 64 bytes) in `qla27xx_copy_multiple_pkt()` and `qla27xx_copy_fpin_pkt()`. |
| `e6c933e56770` | scsi: lpfc: makefile change | **WIP -- do not commit.** |
| `7ad1db7148fb` | NVME_CTRL_MARGINAL_Analysis.md update | **WIP -- do not commit.** |
| `e2de0cb2e578` | NVME_CTRL_MARGINAL_Analysis.md | **WIP -- do not commit.** |

---

## Key Architectural Differences

### 1. FPIN-to-NVMe Marginal State Propagation (Major Change)

**fpin_v11a approach:**
- `scsi_transport_fc.c` exports `fc_host_fpin_set_nvme_rport_marginal()`, a standalone function that parses FPIN TLV descriptors, finds affected rports, sets `FC_PORTSTATE_MARGINAL`, and directly calls `nvme_fc_modify_rport_fpin_state()` with `#if IS_ENABLED(CONFIG_NVME_FC)` guards.
- `nvme_fc_modify_rport_fpin_state()` (in `fc.c`) looks up lport/rport by WWPN, then sets/clears `NVME_CTRL_MARGINAL` on all controllers.
- The SCSI FC transport directly calls into NVMe-FC code, creating a compile-time dependency.

**dev/jesse/fpin_v12b approach:**
- Adds a `set_rport_marginal` callback to `fc_function_template` (the standard SCSI FC transport callback mechanism).
- `scsi_transport_fc.c` adds `fc_fpin_set_marginal()` which is called inline during FPIN processing. It sets `FC_PORTSTATE_MARGINAL` on the rport and calls the `set_rport_marginal` callback.
- `fc_host_fpin_set_nvme_rport_marginal()` is **removed entirely**.
- Each HBA driver (lpfc, qla2xxx) implements the callback, calling `nvme_fc_set_remoteport_fpin()`.
- `nvme_fc_set_remoteport_fpin()` takes a `struct nvme_fc_remote_port *` directly (no WWPN lookup needed) and sets/clears `NVME_CTRL_MARGINAL`.

**Impact:** The v12b approach is cleaner -- it uses the existing FC transport callback pattern, eliminates the `#if IS_ENABLED(CONFIG_NVME_FC)` compile-time coupling, and avoids redundant WWPN-based rport lookups.

### 2. FPIN Statistics and Marginal State Integration

**fpin_v11a approach:**
- FPIN LI/peer-congestion stats updates and marginal state setting are separate code paths.
- `fc_host_fpin_set_nvme_rport_marginal()` iterates pname_list independently of `fc_fpin_li_stats_update()`.

**dev/jesse/fpin_v12b approach:**
- Introduces `fc_fpin_pname_stats_update()`, a common helper that iterates pname_list once, updates stats **and** calls `fc_fpin_set_marginal()` for each affected rport in the same loop.
- This helper is used by both `fc_fpin_li_stats_update()` and `fc_fpin_peer_congn_stats_update()`, removing duplicated iteration code.
- The helper also adds bounds-checking on `pname_count` relative to `desc_len`, preventing out-of-bounds reads on malformed FPIN TLVs.

### 3. Multipath Marginal Path Handling (Significant Behavioral Change)

**fpin_v11a approach (single patch `5e755bfde0b8`):**
- In NUMA path selection (`__nvme_find_path`): marginal optimized paths fall through to be treated as non-optimized (via `fallthrough` in switch).
- In queue-depth policy: marginal paths are skipped entirely (`if (nvme_ctrl_is_marginal(ns->ctrl)) continue`).
- No changes to round-robin policy.

**dev/jesse/fpin_v12b approach (two patches):**

**Patch 1 -- `554e1289ea96` (NUMA policy):**
- Introduces `is_best_distance()` helper function that considers both marginal status and NUMA distance.
- Non-marginal paths are always preferred over marginal ones, regardless of NUMA distance.
- If only marginal paths are available, picks the closest one.
- A non-marginal non-optimized path is preferred over a marginal optimized path (`if (found_is_marginal && !fallback_is_marginal) found = fallback`).

**Patch 2 -- `59120450a4f8` (round-robin policy):**
- Adds marginal path awareness to `nvme_round_robin_path()`.
- Non-marginal optimized paths are preferred and short-circuit via `goto out`.
- Marginal optimized paths are collected but not preferred.
- Falls back to current (old) path if it's non-marginal and the only other found paths are marginal.

**Queue-depth policy (`9099d9700579`):**
- Uses `is_best_distance()` helper (shared with NUMA policy) instead of skipping marginal paths entirely.
- Marginal paths participate in depth comparison but lose to non-marginal ones.
- Removes the fallback to `__nvme_find_path()` when no queue-depth path is found.

**Impact:** v12b provides more nuanced marginal path handling across all three I/O policies. Marginal paths are demoted rather than excluded, and non-marginal non-optimized paths can be preferred over marginal optimized ones.

### 4. nvme_fc_set_remoteport_fpin() vs nvme_fc_modify_rport_fpin_state()

**fpin_v11a: `nvme_fc_modify_rport_fpin_state(u64 local_wwpn, u64 remote_wwpn, bool marginal)`**
- Takes two WWPNs as arguments.
- Looks up lport from `nvme_fc_lport_list` by WWPN.
- Then looks up rport from lport's `endp_list` by WWPN.
- Requires helper functions `nvme_fc_lport_from_wwpn()`, `nvme_fc_rport_from_wwpn()`, `nvme_fc_fpin_set_state()`.
- ~76 lines of code.

**dev/jesse/fpin_v12b: `nvme_fc_set_remoteport_fpin(struct nvme_fc_remote_port *portptr, bool marginal)`**
- Takes a direct remote port pointer.
- No lookup needed -- directly accesses the rport's controller list.
- ~14 lines of code.
- Much simpler because the HBA driver already has the remote port reference in its `set_rport_marginal` callback.

### 5. fc_els.h: Flexible Array Warning Fix

**fpin_v11a:**
- Uses a Revert commit (`2c5ca23321ac`) to undo a previous flex-array warning fix.
- Then applies the `union fc_tlv_desc` change.

**dev/jesse/fpin_v12b:**
- No revert needed (base kernel 7.1-rc7 handles it differently).
- Uses `__struct_group(fc_df_desc_fpin_reg_hdr, ...)` macro for `struct fc_df_desc_fpin_reg`.
- Adds `_Static_assert` to verify struct layout correctness.
- Adds conditional `#include` for `offsetof` (kernel vs userspace).
- Fixes typo: "caause" -> "cause" in comment.

---

## Debug / WIP Patches in v12b (Not for Upstream)

The following patches in v12b are marked "do not commit" or are debug aids:

1. **`15e632ba31e7` -- Add debug statements to show fpin packets**
   - Adds `fpin_dump_buffer()` hex dump function to `scsi_transport_fc.c`.
   - Adds `pr_warn` trace statements in `fc_host_fpin_rcv()` showing FPIN descriptor tags, sizes, and link integrity events.
   - Purpose: Debugging qla2xxx truncated FPIN packet issue.

2. **`b174df9248c4` -- scsi: qla2xxx: fix qla27xx_copy_ fpin functions**
   - Replaces `sizeof(item->iocb.iocb)` with `QLA_DEFAULT_PAYLOAD_SIZE` constant in `qla_isr.c`.
   - Related to the truncated FPIN packet investigation.

3. **`e6c933e56770` -- scsi: lpfc: makefile change** (do not commit)

4. **`e2de0cb2e578` / `7ad1db7148fb` -- NVME_CTRL_MARGINAL_Analysis.md** (do not commit)

---

## Upstream Kernel Changes (Not FPIN Related)

The v12b branch is rebased on 7.1-rc7 (vs 6.18 for v11a), so it includes many upstream changes in the NVMe, lpfc, and qla2xxx drivers unrelated to FPIN. Notable upstream changes visible in the diff:

- NVMe auth code refactored (`nvme_auth_generate_key` -> `nvme_auth_parse_key`, HKDF/HMAC replaced with `crypto/sha2.h` library functions).
- NVMe sysfs: new `quirks` attribute, `tls_mode` attribute, writable `tls_configured_key`.
- NVMe core: `awupf` field moved from `nvme_subsystem` to `nvme_ctrl`; new `from0based()` helper; `get_virt_boundary` ctrl_ops callback.
- NVMe multipath: `report_zones` signature changed to `struct blk_report_zones_args *`; `nvme_failover_req` simplified; `nvme_mpath_remove_disk` logic refactored.
- NVMe-FC: `kzalloc_obj`/`kzalloc_objs` macro usage; `list_for_each_entry_safe` fix; `nvme_remove_admin_tag_set` cleanup; `MODULE_ALIAS("nvme-fc")`.
- lpfc: copyright 2025->2026; NLP_DROPPED/NLP_FLOGI_DFR_ACC flag handling; encryption info reporting (`lpfc_check_encryption`, `lpfc_enc_info`); FLOGI error handling improvements; Auxiliary Parameter Data in FLOGI; removed class4 support.
- qla2xxx: MPI firmware state sysfs attribute; `qla28xx_get_srisc_addr`/`qla28xx_load_fw_template`; SFP info verbosity; firmware state array expanded from 6->16 entries; flash image validation BSG commands; various `kzalloc_obj`/`kzalloc_objs` conversions; FCP2 RSCN delay removed.
- scsi_transport_fc: workqueue `WQ_PERCPU` flag; encryption info attribute group; `kzalloc_obj` usage.
