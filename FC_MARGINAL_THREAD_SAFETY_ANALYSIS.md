# FC_PORTSTATE_MARGINAL Thread Safety Analysis

## Issue Summary

The code paths that set or clear `FC_PORTSTATE_MARGINAL` are **NOT thread safe**. There are significant race conditions between marginal state changes and other port state transitions.

## Thread Safety Problems

### 1. **Inconsistent Locking Pattern**

All other functions that access `rport->port_state` use `shost->host_lock` for synchronization, **except** the functions that set/clear marginal state:

**Functions WITHOUT locking (UNSAFE):**
- `fc_host_fpin_set_nvme_rport_marginal()` - line 928: `rport->port_state = FC_PORTSTATE_MARGINAL;`
- `fc_rport_set_marginal_state()` - lines 1312, 1326: `rport->port_state = port_state;`

**Functions WITH proper locking (SAFE):**
- `fc_remote_port_add()` - line 3308: sets `FC_PORTSTATE_ONLINE` under `shost->host_lock`
- `fc_remote_port_delete()` - line 3529: sets `FC_PORTSTATE_BLOCKED` under `shost->host_lock`
- `fc_timeout_deleted_rport()` - lines 3680, 3708: sets states under `shost->host_lock`
- `fc_host_remove_targets()` - lines 2964, 2971: sets `FC_PORTSTATE_DELETED` under `shost->host_lock`
- `fc_find_rport_by_wwpn()` - line 653: reads `port_state` under `shost->host_lock`
- `fc_user_scan_tgt()` - line 2628: reads `port_state` under `shost->host_lock`

### 2. **Race Condition Scenarios**

#### **Race 1: FPIN Processing vs Normal State Transitions**
```
Thread A (FPIN)                    Thread B (Normal operation)
----------------------------       ----------------------------
fc_host_fpin_set_nvme_rport_marginal()
  rport = fc_find_rport_by_wwpn()  
  // rport found, state = ONLINE
                                   fc_remote_port_delete()
                                     spin_lock(shost->host_lock)
                                     rport->port_state = BLOCKED
                                     spin_unlock(shost->host_lock)
  // NO LOCKING HERE!
  rport->port_state = MARGINAL  // OVERWRITES BLOCKED state!
```

#### **Race 2: Sysfs vs FPIN Processing** 
```
Thread A (Sysfs)                   Thread B (FPIN)
----------------------------       ----------------------------
fc_rport_set_marginal_state()     fc_host_fpin_set_nvme_rport_marginal()
  if (rport->port_state == ONLINE)  
                                     rport->port_state = MARGINAL
  rport->port_state = MARGINAL     // Both threads modify simultaneously!
```

#### **Race 3: Reader vs Marginal State Change**
```
Thread A (Reader)                  Thread B (Marginal setter)
----------------------------       ----------------------------
fc_user_scan_tgt()                fc_rport_set_marginal_state() 
  spin_lock(shost->host_lock)
  if (rport->port_state == ONLINE ||
                                     rport->port_state = MARGINAL
      rport->port_state == MARGINAL) // Reader sees torn/inconsistent state
  spin_unlock(shost->host_lock)
```

### 3. **Memory Ordering Issues**

Without proper locking, there are no memory barriers to ensure:
- The port_state write is visible to other CPUs immediately
- Compiler optimizations don't reorder the state check and assignment
- The NVME-FC state synchronization happens atomically with FC state change

## Proposed Fix

### **Add Proper Locking to Marginal State Functions**

The fix is to add `shost->host_lock` protection around all `rport->port_state` accesses in the marginal state functions, following the existing pattern used throughout the rest of the code.

#### **Patch 1: Fix fc_host_fpin_set_nvme_rport_marginal()**

```c
void
fc_host_fpin_set_nvme_rport_marginal(struct Scsi_Host *shost, u32 fpin_len, char *fpin_buf)
{
	struct fc_els_fpin *fpin = (struct fc_els_fpin *)fpin_buf;
	struct fc_rport *rport;
	union fc_tlv_desc *tlv;
	u64 local_wwpn = fc_host_port_name(shost);
	u64 wwpn, attached_wwpn;
	u32 bytes_remain;
	u32 dtag;
	u8 i;
+	unsigned long flags;

	/* Parse FPIN descriptors */
	tlv = &fpin->fpin_desc[0];
	bytes_remain = fpin_len - offsetof(struct fc_els_fpin, fpin_desc);
	bytes_remain = min_t(u32, bytes_remain, be32_to_cpu(fpin->desc_len));

	while (bytes_remain >= FC_TLV_DESC_HDR_SZ &&
	       bytes_remain >= FC_TLV_DESC_SZ_FROM_LENGTH(tlv)) {
		dtag = be32_to_cpu(tlv->hdr.desc_tag);
		switch (dtag) {
		case ELS_DTAG_LNK_INTEGRITY:
			struct fc_fn_li_desc *li_desc = &tlv->li;

			attached_wwpn = be64_to_cpu(li_desc->attached_wwpn);

			/* Set marginal state for WWPNs in pname_list */
			if (be32_to_cpu(li_desc->pname_count) > 0) {
				for (i = 0; i < be32_to_cpu(li_desc->pname_count); i++) {
					wwpn = be64_to_cpu(li_desc->pname_list[i]);
					if (wwpn != attached_wwpn) {
						rport = fc_find_rport_by_wwpn(shost, wwpn);
-						if (rport && rport->port_state == FC_PORTSTATE_ONLINE &&
-						     rport->roles & FC_PORT_ROLE_NVME_TARGET) {
-							rport->port_state = FC_PORTSTATE_MARGINAL;
+						if (rport && (rport->roles & FC_PORT_ROLE_NVME_TARGET)) {
+							spin_lock_irqsave(shost->host_lock, flags);
+							/* Only set marginal if currently online */
+							if (rport->port_state == FC_PORTSTATE_ONLINE) {
+								rport->port_state = FC_PORTSTATE_MARGINAL;
+								spin_unlock_irqrestore(shost->host_lock, flags);
 #if (IS_ENABLED(CONFIG_NVME_FC))
-							nvme_fc_modify_rport_fpin_state(local_wwpn, wwpn, true);
+								nvme_fc_modify_rport_fpin_state(local_wwpn, wwpn, true);
 #endif
+							} else {
+								spin_unlock_irqrestore(shost->host_lock, flags);
 							}
+						}
					}
				}
			}
			break;
		default:
			break;
		}
		bytes_remain -= FC_TLV_DESC_SZ_FROM_LENGTH(tlv);
		tlv = fc_tlv_next_desc(tlv);
	}
}
```

#### **Patch 2: Fix fc_rport_set_marginal_state()**

```c
static ssize_t fc_rport_set_marginal_state(struct device *dev,
						struct device_attribute *attr,
						const char *buf, size_t count)
{
	struct fc_rport *rport = transport_class_to_rport(dev);
	struct Scsi_Host *shost = rport_to_shost(rport);
	u64 local_wwpn = fc_host_port_name(shost);
	enum fc_port_state port_state;
+	unsigned long flags;
	int ret = 0;

	ret = get_fc_port_state_match(buf, &port_state);
	if (ret)
		return -EINVAL;
+
+	spin_lock_irqsave(shost->host_lock, flags);
+
	if (port_state == FC_PORTSTATE_MARGINAL) {
		/*
		 * Change the state to Marginal only if the
		 * current rport state is Online
		 * Allow only Online->Marginal
		 */
		if (rport->port_state == FC_PORTSTATE_ONLINE) {
			rport->port_state = port_state;
+			spin_unlock_irqrestore(shost->host_lock, flags);
 #if (IS_ENABLED(CONFIG_NVME_FC))
			nvme_fc_modify_rport_fpin_state(local_wwpn,
					rport->port_name, true);
 #endif
-		} else if (port_state != rport->port_state)
+		} else if (port_state != rport->port_state) {
+			spin_unlock_irqrestore(shost->host_lock, flags);
			return -EINVAL;
+		} else {
+			spin_unlock_irqrestore(shost->host_lock, flags);
+		}
	} else if (port_state == FC_PORTSTATE_ONLINE) {
		/*
		 * Change the state to Online only if the
		 * current rport state is Marginal
		 * Allow only Marginal->Online
		 */
		if (rport->port_state == FC_PORTSTATE_MARGINAL) {
			rport->port_state = port_state;
+			spin_unlock_irqrestore(shost->host_lock, flags);
 #if (IS_ENABLED(CONFIG_NVME_FC))
			nvme_fc_modify_rport_fpin_state(local_wwpn,
					rport->port_name, false);
 #endif
-		} else if (port_state != rport->port_state)
+		} else if (port_state != rport->port_state) {
+			spin_unlock_irqrestore(shost->host_lock, flags);
			return -EINVAL;
-	} else
+		} else {
+			spin_unlock_irqrestore(shost->host_lock, flags);
+		}
+	} else {
+		spin_unlock_irqrestore(shost->host_lock, flags);
		return -EINVAL;
+	}
	return count;
}
```

### **Alternative Approach: Reader-Writer Locks**

For better scalability, we could consider using a per-rport rwlock instead of the global shost->host_lock:

```c
struct fc_rport {
	/* existing fields */
+	rwlock_t state_lock;  /* protects port_state and related fields */
	enum fc_port_state port_state;
	/* ... */
};
```

However, this would require extensive changes throughout the FC transport layer and may not be worth the complexity since rport state changes are relatively infrequent.

## Benefits of the Fix

1. **Eliminates Race Conditions**: Ensures atomic state transitions
2. **Consistent Locking**: Follows the established pattern used throughout scsi_transport_fc.c
3. **Memory Ordering**: Provides proper memory barriers via spinlock acquire/release
4. **Minimal Performance Impact**: Only adds locking to infrequent administrative operations
5. **Maintains Backward Compatibility**: No changes to external interfaces

## Testing Recommendations

1. **Stress Test**: Run concurrent FPIN processing with manual sysfs state changes
2. **State Transition Test**: Verify all valid state transitions work correctly under load
3. **Race Detection**: Use lockdep and KASAN to verify no remaining races
4. **Performance Test**: Ensure no measurable impact on I/O performance

## Summary

The current implementation has serious thread safety issues that can lead to:
- Inconsistent port states
- Lost state transitions  
- Potential system instability

The proposed fix adds proper locking using the existing `shost->host_lock` pattern, ensuring thread-safe access to `rport->port_state` in all marginal state operations.
