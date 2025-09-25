# FPIN LI Support Changes: From fpin_v9 to fpin_v10

This document analyzes the difference between the `fpin_v9` and `fpin_v10` changes to implement improved FPIN (Fabric Performance Impact Notification) Link Integrity support for NVMe over Fibre Channel.

## Summary

The changes represent a significant architectural improvement in how FPIN Link Integrity events are processed for NVMe targets. The key improvement is moving FPIN processing from the NVMe FC layer to the SCSI FC transport layer, providing a more unified and maintainable approach.

## Key Architectural Changes

### 1. **Processing Location Migration**
- **Before**: FPIN processing was handled directly in the NVMe FC driver
- **After**: FPIN processing moved to SCSI FC transport layer, with callback into NVMe layer

### 2. **API Simplification**
- **Before**: Complex `nvme_fc_fpin_rcv()` function that parsed FPIN messages
- **After**: Simple `nvme_fc_modify_rport_fpin_state()` function with clean interface

### 3. **Thread Safety Improvements**
- **Before**: Missing locking in `nvme_fc_rport_from_wwpn()` and `fc_rport_set_marginal_state()`
- **After**: Proper locking added to prevent race conditions

### 4. **Enhanced Sysfs Integration**
- **Before**: Basic `fc_rport_set_marginal_state()` with no NVMe integration
- **After**: Full SCSI-NVMe state synchronization with proper locking

## Detailed Changes by File

### drivers/nvme/host/fc.c

#### 🔧 **Thread Safety Fix**
```c
// BEFORE: No locking around list traversal
static struct nvme_fc_rport *nvme_fc_rport_from_wwpn(struct nvme_fc_lport *lport, u64 rport_wwpn)
{
    struct nvme_fc_rport *rport;

    list_for_each_entry(rport, &lport->endp_list, endp_list) {
        // ... unsafe list traversal
    }
}

// AFTER: Proper locking added
static struct nvme_fc_rport *nvme_fc_rport_from_wwpn(struct nvme_fc_lport *lport, u64 rport_wwpn)
{
    struct nvme_fc_rport *rport;
    unsigned long flags;

    spin_lock_irqsave(&nvme_fc_lock, flags);
    list_for_each_entry(rport, &lport->endp_list, endp_list) {
        // ... safe list traversal with proper locking
        if (match_found) {
            spin_unlock_irqrestore(&nvme_fc_lock, flags);
            return rport;
        }
    }
    spin_unlock_irqrestore(&nvme_fc_lock, flags);
}
```

#### ➕ **New Functions Added**
1. **`nvme_fc_lport_from_wwpn()`** - Find local port by WWPN
   - Thread-safe lookup using `nvme_fc_lock`
   - Proper reference counting with `nvme_fc_lport_get()`

2. **`nvme_fc_fpin_set_state()`** - Set marginal state on controllers
   - Simplified logic compared to old `nvme_fc_fpin_li_lport_update()`
   - Supports both setting and clearing marginal state
   - Proper locking with `rport->lock`

3. **`nvme_fc_modify_rport_fpin_state()`** - Main API function
   - Clean interface: takes WWPNs and marginal flag
   - Exported with `EXPORT_SYMBOL_GPL`
   - Replaces complex `nvme_fc_fpin_rcv()` function

#### ❌ **Functions Removed**
1. **`nvme_fc_fpin_li_lport_update()`** - Complex FPIN processing logic
2. **`nvme_fc_fpin_rcv()`** - Direct FPIN message processing

### drivers/scsi/scsi_transport_fc.c

#### ➕ **New FPIN Processing Function**
**`fc_host_fpin_set_nvme_rport_marginal()`**
- Parses FPIN Link Integrity descriptors
- Identifies affected NVMe target ports
- Sets `FC_PORTSTATE_MARGINAL` on SCSI rports
- Calls into NVMe layer via `nvme_fc_modify_rport_fpin_state()`
- Proper locking with `shost->host_lock`

Key features:
```c
/* Parse FPIN descriptors */
while (bytes_remain >= FC_TLV_DESC_HDR_SZ) {
    switch (dtag) {
    case ELS_DTAG_LNK_INTEGRITY:
        // Process Link Integrity descriptor
        for (i = 0; i < pname_count; i++) {
            wwpn = be64_to_cpu(li_desc->pname_list[i]);
            rport = fc_find_rport_by_wwpn(shost, wwpn);

            if (rport && rport->roles & FC_PORT_ROLE_NVME_TARGET) {
                rport->port_state = FC_PORTSTATE_MARGINAL;
                // Call into NVMe layer
                nvme_fc_modify_rport_fpin_state(local_wwpn, wwpn, true);
            }
        }
        break;
    }
}
```

#### 🔧 **Enhancement: fc_rport_set_marginal_state() Function**

This function represents one of the most significant improvements in the fpin_v10 changes. It provides a sysfs interface for manually controlling remote port marginal states, with full integration into the NVMe layer.

**Call Graph:**
```
/sys/class/fc_remote_ports/rport-X:Y-Z/port_state (write)
    ↓
fc_rport_set_marginal_state(dev, attr, buf, count)
    ↓
get_fc_port_state_match(buf, &port_state)              // Parse user input
    ↓
spin_lock_irqsave(shost->host_lock, flags)             // Thread safety
    ↓
switch (port_state) {
    case FC_PORTSTATE_MARGINAL:
        rport->port_state = FC_PORTSTATE_MARGINAL       // Update SCSI state
        ↓
        spin_unlock_irqrestore(shost->host_lock, flags)
        ↓
        nvme_fc_modify_rport_fpin_state(local_wwpn, remote_wwpn, true)
            ↓
            nvme_fc_lport_from_wwpn(local_wwpn)         // Find NVMe local port
            ↓
            nvme_fc_fpin_set_state(lport, remote_wwpn, true)
                ↓
                nvme_fc_rport_from_wwpn(lport, remote_wwpn)  // Find NVMe remote port
                ↓
                spin_lock_irq(&rport->lock)             // NVMe-level locking
                ↓
                set_bit(NVME_CTRL_MARGINAL, &ctrl->ctrl.flags)  // Set marginal on all controllers
                ↓
                spin_unlock_irq(&rport->lock)
                ↓
                nvme_fc_rport_put(rport)                // Release reference
            ↓
            nvme_fc_lport_put(lport)                    // Release reference

    case FC_PORTSTATE_ONLINE: [Similar flow but clear_bit()]
}
```

**Before/After Comparison:**

**fpin_v9 version** (Basic and Unsafe):
```c
static ssize_t fc_rport_set_marginal_state(struct device *dev,
                                           struct device_attribute *attr,
                                           const char *buf, size_t count)
{
    struct fc_rport *rport = transport_class_to_rport(dev);
    enum fc_port_state port_state;
    int ret = 0;

    ret = get_fc_port_state_match(buf, &port_state);
    if (ret)
        return -EINVAL;

    // ❌ NO LOCKING - Race condition prone!
    if (port_state == FC_PORTSTATE_MARGINAL) {
        if (rport->port_state == FC_PORTSTATE_ONLINE)
            rport->port_state = port_state;  // ❌ Direct assignment without protection
        else if (port_state != rport->port_state)
            return -EINVAL;
    } else if (port_state == FC_PORTSTATE_ONLINE) {
        if (rport->port_state == FC_PORTSTATE_MARGINAL)
            rport->port_state = port_state;  // ❌ Direct assignment without protection
        else if (port_state != rport->port_state)
            return -EINVAL;
    } else
        return -EINVAL;

    // ❌ NO NVME INTEGRATION - SCSI and NVMe states become inconsistent!
    return count;
}
```

**fpin_v10 version** (Robust and Integrated):
```c
static ssize_t fc_rport_set_marginal_state(struct device *dev,
                                           struct device_attribute *attr,
                                           const char *buf, size_t count)
{
    struct fc_rport *rport = transport_class_to_rport(dev);
    struct Scsi_Host *shost = rport_to_shost(rport);      // ✅ Get host for WWPN
    u64 local_wwpn = fc_host_port_name(shost);            // ✅ Extract local WWPN
    enum fc_port_state port_state;
    int ret = 0;
    unsigned long flags;                                   // ✅ For proper locking

    ret = get_fc_port_state_match(buf, &port_state);
    if (ret)
        return -EINVAL;

    spin_lock_irqsave(shost->host_lock, flags);           // ✅ PROPER LOCKING

    switch (port_state) {                                 // ✅ Cleaner structure
    case FC_PORTSTATE_MARGINAL:
        if (rport->port_state == FC_PORTSTATE_ONLINE) {
            rport->port_state = port_state;               // ✅ Protected assignment
            spin_unlock_irqrestore(shost->host_lock, flags);
#if (IS_ENABLED(CONFIG_NVME_FC))
            nvme_fc_modify_rport_fpin_state(local_wwpn,   // ✅ NVME INTEGRATION
                            rport->port_name, true);
#endif
            return count;                                 // ✅ Early return on success
        }
        break;

    case FC_PORTSTATE_ONLINE:
        if (rport->port_state == FC_PORTSTATE_MARGINAL) {
            rport->port_state = port_state;               // ✅ Protected assignment
            spin_unlock_irqrestore(shost->host_lock, flags);
#if (IS_ENABLED(CONFIG_NVME_FC))
            nvme_fc_modify_rport_fpin_state(local_wwpn,   // ✅ NVME INTEGRATION
                            rport->port_name, false);
#endif
            return count;                                 // ✅ Early return on success
        }
        break;
    default:
        break;
    }

    // ✅ Unified error handling
    if (port_state != rport->port_state) {
        spin_unlock_irqrestore(shost->host_lock, flags);
        return -EINVAL;
    }

    spin_unlock_irqrestore(shost->host_lock, flags);
    return count;
}
```

**Key Improvements:**

1. **🔗 NVMe Integration**
   - Calls `nvme_fc_modify_rport_fpin_state()` to sync SCSI and NVMe states
   - Ensures both SCSI rport and NVMe controller reflect the same marginal state
   - Prevents inconsistency between FC layers

2. **🏗️ Better Code Structure**
   - Switch statement instead of complex if-else chains
   - Early returns for success cases reduce nesting
   - Unified error handling path

3. **📊 Enhanced State Management**
   - Bidirectional state transitions: Online ↔ Marginal
   - Both directions properly integrated with NVMe layer
   - Local WWPN extraction for proper NVMe port identification

4. **🛡️ Robustness**
   - Proper validation of state transitions
   - Lock held for minimal duration (released before NVMe calls)
   - Comprehensive error handling

**Impact:**
This enhancement enables administrators to manually control port marginal states via sysfs:
```bash
# Set port to marginal state
echo "Marginal" > /sys/class/fc_remote_ports/rport-4:0-1/port_state

# Clear marginal state (set to online)
echo "Online" > /sys/class/fc_remote_ports/rport-4:0-1/port_state
```

Both operations now properly synchronize the state across SCSI FC transport and NVMe FC layers, providing consistent behavior throughout the storage stack.

### include/linux/nvme-fc-driver.h

#### 🔄 **API Changes**
```c
// BEFORE: Complex FPIN message processing
void nvme_fc_fpin_rcv(struct nvme_fc_local_port *localport,
                     u32 fpin_len, char *fpin_buf);

// AFTER: Simple state modification interface
void nvme_fc_modify_rport_fpin_state(u64 local_wwpn, u64 remote_wwpn, bool marginal);
```

Benefits of new API:
- **Simpler**: No need to parse FPIN messages in NVMe layer
- **Cleaner**: Clear parameters indicating what action to take
- **More flexible**: Can be called from various contexts (FPIN, sysfs, etc.)

### include/scsi/scsi_transport_fc.h

#### ➕ **New Export Added**
```c
void fc_host_fpin_set_nvme_rport_marginal(struct Scsi_Host *shost, u32 fpin_len, char *fpin_buf);
```

### Driver Integration Changes

#### drivers/scsi/lpfc/lpfc_els.c
```c
// BEFORE: Direct call to NVMe layer
#if (IS_ENABLED(CONFIG_NVME_FC))
    if (vport->cfg_enable_fc4_type & LPFC_ENABLE_NVME)
        nvme_fc_fpin_rcv(vport->localport, fpin_length, (char *)fpin);
#endif

// AFTER: Call through SCSI transport layer
if (vport->cfg_enable_fc4_type & LPFC_ENABLE_NVME) {
    fc_host_fpin_set_nvme_rport_marginal(lpfc_shost_from_vport(vport),
                                         fpin_length, (char *)fpin);
}
```

#### drivers/scsi/qla2xxx/qla_isr.c
```c
// BEFORE: Direct NVMe call
#if (IS_ENABLED(CONFIG_NVME_FC))
    nvme_fc_fpin_rcv(vha->nvme_local_port, pkt_size, (char *)pkt);
#endif

// AFTER: SCSI transport layer call
fc_host_fpin_set_nvme_rport_marginal(vha->host, pkt_size, (char *)pkt);
```

#### drivers/scsi/qla2xxx/qla_os.c
Minor cleanup in `qla24xx_free_purex_item()` function for better code organization.

## Benefits of the Changes

### 1. **Improved Architecture** 🏗️
- **Separation of Concerns**: FPIN parsing in SCSI layer, state management in NVMe layer
- **Code Reuse**: FPIN parsing logic shared across all FC drivers
- **Maintainability**: Changes to FPIN processing only need to be made in one place

### 2. **Thread Safety** 🔒
- Proper locking throughout the call chain
- Reference counting prevents use-after-free scenarios

### 3. **API Simplification** 📋
- Clean, simple interface for NVMe state modification
- Reduced complexity in NVMe FC driver
- Better testability and debugging

### 4. **Enhanced Functionality** ⚡
- Support for both setting and clearing marginal state
- Integration with sysfs interface for manual control
- Better error handling and validation

### 5. **Driver Consistency** 🔄
- Consistent FPIN handling across LPFC and QLA drivers
- Unified approach eliminates driver-specific variations
- Easier to add support for new drivers

## Call Flow Comparison

### Before (fpin_v9)

**FPIN Processing Path:**
```
LPFC/QLA Driver
    ↓
nvme_fc_fpin_rcv()
    ↓
nvme_fc_fpin_li_lport_update()
    ↓
[Complex FPIN parsing and processing]
    ↓
Set NVME_CTRL_MARGINAL flags
```

**Sysfs Path (Limited):**
```
/sys/.../port_state (write)
    ↓
fc_rport_set_marginal_state()
    ↓
[Basic state change - NO locking]
    ↓
rport->port_state = new_state
[NO NVMe integration - states become inconsistent!]
```

### After (fpin_v10)

**FPIN Processing Path:**
```
LPFC/QLA Driver
    ↓
fc_host_fpin_set_nvme_rport_marginal()
    ↓
[FPIN parsing in SCSI transport layer]
    ↓
Set FC_PORTSTATE_MARGINAL on SCSI rport
    ↓
nvme_fc_modify_rport_fpin_state()
    ↓
nvme_fc_lport_from_wwpn()
    ↓
nvme_fc_fpin_set_state()
    ↓
Set/Clear NVME_CTRL_MARGINAL flags
```

**Enhanced Sysfs Path (Fully Integrated):**
```
/sys/.../port_state (write)
    ↓
fc_rport_set_marginal_state()
    ↓
spin_lock_irqsave(shost->host_lock)  [PROPER LOCKING]
    ↓
rport->port_state = new_state
    ↓
spin_unlock_irqrestore(shost->host_lock)
    ↓
nvme_fc_modify_rport_fpin_state()    [NVME INTEGRATION]
    ↓
nvme_fc_lport_from_wwpn()
    ↓
nvme_fc_fpin_set_state()
    ↓
Set/Clear NVME_CTRL_MARGINAL flags
[SCSI and NVMe states now fully synchronized!]
```

## Testing and Integration Points

### 1. **FPIN Reception Path**
- LPFC and QLA drivers receive FPIN messages
- SCSI transport layer processes and parses FPIN descriptors
- NVMe layer updates controller marginal state

### 2. **Enhanced Sysfs Interface**
- Manual control via `/sys/class/fc_remote_ports/*/port_state`
- **NEW**: Full SCSI-NVMe state synchronization
- Supports both Online ↔ Marginal state transitions
- **NEW**: Consistent behavior across all FC protocol layers
- **NEW**: Administrative control with immediate NVMe controller impact

### 3. **Error Recovery**
- Proper cleanup of references in error paths
- Thread-safe operations under concurrent access
- Graceful handling of non-existent ports/controllers

## Conclusion

The changes from `fpin_v9` to `fpin_v10` represent an **improvement** in the FPIN Link Integrity support for NVMe over Fibre Channel. The new architecture provides:

- **Better separation of concerns** between SCSI and NVMe layers
- **Simplified API** that's easier to use and maintain
- **Enhanced functionality** supporting both directions of state changes
- **Unified approach** across different FC HBA drivers
- **🆕 Sysfs integration** - the `fc_rport_set_marginal_state()` enhancement represents one of the most significant improvements, providing:
  - Thread-safe manual port state control
  - Complete SCSI-NVMe layer synchronization
  - Administrative control over multipath behavior
  - Consistent state management across all FC protocol layers

### Key Changes:

1. **🔒 Thread Safety**: Fixed critical race conditions that could cause system instability
2. **🔗 Layer Integration**: SCSI and NVMe states stay perfectly synchronized
3. **🛠️ Administrative Control**: Operations teams can now reliably manage port states
4. **📊 Consistent Behavior**: No more state mismatches between FC protocol layers
5. **🏗️ Maintainability**: Cleaner architecture that's easier to debug and enhance

