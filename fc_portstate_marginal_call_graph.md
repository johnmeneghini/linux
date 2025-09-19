# Call Graph: All Code That Sets or Clears FC_PORTSTATE_MARGINAL

## Overview
This document provides a comprehensive call graph showing all code paths in the Linux kernel that set or clear the `FC_PORTSTATE_MARGINAL` state for FC remote ports. The `FC_PORTSTATE_MARGINAL` state indicates a port that is experiencing performance degradation but is still functional.

**Location**: FC transport layer in SCSI subsystem  
**State Value**: `FC_PORTSTATE_MARGINAL` (defined in `include/scsi/scsi_transport_fc.h:70`)

## Complete Call Graph

### **Setting FC_PORTSTATE_MARGINAL (Online → Marginal)**

```
**PRIMARY PATH: User-Initiated via Sysfs**
Userspace
│
├── write() system call to /sys/class/fc_rport/rport-X:Y-Z/port_state
│   └── Value: "Marginal"
│
├── VFS/Sysfs Layer
│   ├── sysfs_kf_write()
│   ├── kernfs_fop_write_iter()
│   └── dev_attr_store()
│
└── SCSI FC Transport Layer
    └── device_attr_rport_port_state.store()
        └── fc_rport_set_marginal_state()  [drivers/scsi/scsi_transport_fc.c:1222]
            ├── transport_class_to_rport(dev)  [Get fc_rport from device]
            ├── get_fc_port_state_match(buf, &port_state)  [Parse "Marginal" string]
            ├── if (port_state == FC_PORTSTATE_MARGINAL)  [line 1240]
            ├── if (rport->port_state == FC_PORTSTATE_ONLINE)  [line 1246]
            │   └── **STATE CHANGE**: rport->port_state = port_state  [line 1247]
            │       └── **RESULT**: port_state = FC_PORTSTATE_MARGINAL
            │
            └── **NEW: Cross-Layer NVMe-FC Integration**  [line 1248-1254]
                ├── rport_to_shost(rport)  [Get SCSI host]
                ├── fc_host_port_name(shost)  [Get local WWPN] 
                ├── nvme_fc_lport_from_wwpn(local_wwpn)  [Find NVMe-FC lport]
                ├── nvme_fc_fpin_set_state(lport, rport->port_name, true)
                │   ├── nvme_fc_rport_from_wwpn(lport, wwpn)  [Find NVMe rport]
                │   ├── spin_lock_irq(&rport->lock)
                │   ├── list_for_each_entry(ctrl, &rport->ctrl_list, ctrl_list)
                │   │   └── set_bit(NVME_CTRL_MARGINAL, &ctrl->ctrl.flags)
                │   ├── spin_unlock_irq(&rport->lock)
                │   └── nvme_fc_rport_put(rport)
                └── nvme_fc_lport_put(lport)
```

### **Clearing FC_PORTSTATE_MARGINAL (Marginal → Online)**

```
**PRIMARY PATH: User-Initiated Recovery via Sysfs**
Userspace
│
├── write() system call to /sys/class/fc_rport/rport-X:Y-Z/port_state
│   └── Value: "Online"
│
├── VFS/Sysfs Layer
│   ├── sysfs_kf_write()
│   ├── kernfs_fop_write_iter()
│   └── dev_attr_store()
│
└── SCSI FC Transport Layer
    └── device_attr_rport_port_state.store()
        └── fc_rport_set_marginal_state()  [drivers/scsi/scsi_transport_fc.c:1222]
            ├── transport_class_to_rport(dev)  [Get fc_rport from device]
            ├── get_fc_port_state_match(buf, &port_state)  [Parse "Online" string]
            ├── if (port_state == FC_PORTSTATE_ONLINE)  [line 1256]
            ├── if (rport->port_state == FC_PORTSTATE_MARGINAL)  [line 1269]
            │   └── **STATE CHANGE**: rport->port_state = port_state  [line 1270]
            │       └── **RESULT**: port_state = FC_PORTSTATE_ONLINE
            │
            └── **NEW: Cross-Layer NVMe-FC Integration**  [line 1271-1277]
                ├── rport_to_shost(rport)  [Get SCSI host]
                ├── fc_host_port_name(shost)  [Get local WWPN]
                ├── nvme_fc_lport_from_wwpn(local_wwpn)  [Find NVMe-FC lport]
                ├── nvme_fc_fpin_set_state(lport, rport->port_name, false)
                │   ├── nvme_fc_rport_from_wwpn(lport, wwpn)  [Find NVMe rport]
                │   ├── spin_lock_irq(&rport->lock)
                │   ├── list_for_each_entry(ctrl, &rport->ctrl_list, ctrl_list)
                │   │   └── clear_bit(NVME_CTRL_MARGINAL, &ctrl->ctrl.flags)
                │   ├── spin_unlock_irq(&rport->lock)
                │   └── nvme_fc_rport_put(rport)
                └── nvme_fc_lport_put(lport)
```

### **Alternative/Future State Transition Paths**

```
**POTENTIAL PATHS (Currently Not Implemented)**

1. **Automatic FPIN-Driven Marginal Setting**:
   FC Fabric → FPIN → FC Driver → (Future Enhancement) → fc_rport_set_marginal_state()

2. **Driver-Initiated State Changes**:
   FC HBA Driver → (Future Enhancement) → fc_rport_state_change() → FC_PORTSTATE_MARGINAL

3. **Timeout/Recovery Logic**:
   Timer/Workqueue → (Future Enhancement) → Recovery Logic → FC_PORTSTATE_ONLINE
```

## State Validation and Checks

### **Functions That Check FC_PORTSTATE_MARGINAL**

```
**1. I/O Path Validations**
fc_remote_port_chkready()  [drivers/scsi/scsi_transport_fc.c:4278]
├── if ((rport->port_state != FC_PORTSTATE_ONLINE) &&
├──      (rport->port_state != FC_PORTSTATE_MARGINAL))
└── return BLK_STS_IOERR  [Block I/O if not Online or Marginal]

**2. SCSI Target Scanning**
fc_scsi_scan_rport()  [drivers/scsi/scsi_transport_fc.c:3751]
├── if (((rport->port_state == FC_PORTSTATE_ONLINE) ||
├──      (rport->port_state == FC_PORTSTATE_MARGINAL)) &&
├──     (rport->roles & FC_PORT_ROLE_FCP_TARGET))
└── scsi_scan_target()  [Allow scanning for both Online and Marginal]

**3. Target Lookup Functions**
fc_user_scan()  [drivers/scsi/scsi_transport_fc.c:2580]
├── if ((rport->port_state != FC_PORTSTATE_ONLINE) &&
├──     (rport->port_state != FC_PORTSTATE_MARGINAL))
├── continue  [Skip ports that aren't Online or Marginal]
└── [Process SCSI scanning for valid ports]

**4. Port Blocking/Unblocking**
fc_remote_port_delete()  [drivers/scsi/scsi_transport_fc.c:3463]
├── if ((rport->port_state != FC_PORTSTATE_ONLINE) &&
├──     (rport->port_state != FC_PORTSTATE_MARGINAL))
├── return  [Don't block if not Online or Marginal]
└── rport->port_state = FC_PORTSTATE_BLOCKED  [Block the port]

**5. SCSI Error Handling**
fc_eh_timed_out()  [drivers/scsi/scsi_transport_fc.c:2556]
├── if (rport->port_state == FC_PORTSTATE_BLOCKED)
└── return SCSI_EH_RESET_TIMER  [Reset timer for blocked ports]

**6. Sysfs Attribute Access Control**
fc_rport_show_function() macro  [drivers/scsi/scsi_transport_fc.c:985-987]
├── if (!((rport->port_state == FC_PORTSTATE_BLOCKED) ||
├──       (rport->port_state == FC_PORTSTATE_DELETED) ||
├──       (rport->port_state == FC_PORTSTATE_NOTPRESENT)))
└── [Allow attribute access for Online/Marginal states]

fc_rport_store_function() macro  [drivers/scsi/scsi_transport_fc.c:1003-1005]
├── if ((rport->port_state == FC_PORTSTATE_BLOCKED) ||
├──     (rport->port_state == FC_PORTSTATE_DELETED) ||
├──     (rport->port_state == FC_PORTSTATE_NOTPRESENT))
└── return -EBUSY  [Block modification for invalid states]
```

## State Transition Matrix

| **From State**        | **To State**          | **Trigger**           | **Code Path** | **Allowed?** |
|-----------------------|-----------------------|-----------------------|---------------|--------------|
| FC_PORTSTATE_ONLINE   | FC_PORTSTATE_MARGINAL | sysfs "Marginal"      | fc_rport_set_marginal_state():1247 | ✅ YES |
| FC_PORTSTATE_MARGINAL | FC_PORTSTATE_ONLINE   | sysfs "Online"        | fc_rport_set_marginal_state():1270 | ✅ YES |
| FC_PORTSTATE_MARGINAL | FC_PORTSTATE_MARGINAL | sysfs "Marginal"      | fc_rport_set_marginal_state():1241 | ✅ YES (No-op) |
| FC_PORTSTATE_ONLINE   | FC_PORTSTATE_ONLINE   | sysfs "Online"        | fc_rport_set_marginal_state():1256 | ✅ YES (No-op) |
| FC_PORTSTATE_OFFLINE  | FC_PORTSTATE_MARGINAL | sysfs "Marginal"      | fc_rport_set_marginal_state():1254 | ❌ NO (-EINVAL) |
| FC_PORTSTATE_BLOCKED  | FC_PORTSTATE_MARGINAL | sysfs "Marginal"      | fc_rport_set_marginal_state():1254 | ❌ NO (-EINVAL) |
| FC_PORTSTATE_MARGINAL | FC_PORTSTATE_OFFLINE  | sysfs "Offline"       | fc_rport_set_marginal_state():1279 | ❌ NO (-EINVAL) |
| Any Other State       | FC_PORTSTATE_MARGINAL | Any trigger           | N/A | ❌ NO |

## Data Structures and Constants

### **FC Port State Enumeration**
```c
// Location: include/scsi/scsi_transport_fc.h:58-71
enum fc_port_state {
    FC_PORTSTATE_UNKNOWN,      // 0
    FC_PORTSTATE_NOTPRESENT,   // 1  
    FC_PORTSTATE_ONLINE,       // 2  ← Valid source for Marginal
    FC_PORTSTATE_OFFLINE,      // 3
    FC_PORTSTATE_BLOCKED,      // 4
    FC_PORTSTATE_BYPASSED,     // 5
    FC_PORTSTATE_DIAGNOSTICS,  // 6
    FC_PORTSTATE_LINKDOWN,     // 7
    FC_PORTSTATE_ERROR,        // 8
    FC_PORTSTATE_LOOPBACK,     // 9
    FC_PORTSTATE_DELETED,      // 10
    FC_PORTSTATE_MARGINAL,     // 11 ← Target state
};
```

### **String-to-State Mapping Table**
```c
// Location: drivers/scsi/scsi_transport_fc.c:153-166
static struct {
    enum fc_port_state  value;
    char               *name;
    int                matchlen;
} fc_port_state_names[] = {
    { FC_PORTSTATE_UNKNOWN,     "Unknown", 7},
    { FC_PORTSTATE_NOTPRESENT,  "Not Present", 11 },
    { FC_PORTSTATE_ONLINE,      "Online", 6 },      ← Source state
    { FC_PORTSTATE_OFFLINE,     "Offline", 7 },
    { FC_PORTSTATE_BLOCKED,     "Blocked", 7 },
    { FC_PORTSTATE_BYPASSED,    "Bypassed", 8 },
    { FC_PORTSTATE_DIAGNOSTICS, "Diagnostics", 11 },
    { FC_PORTSTATE_LINKDOWN,    "Linkdown", 8 },
    { FC_PORTSTATE_ERROR,       "Error", 5 },
    { FC_PORTSTATE_LOOPBACK,    "Loopback", 8 },
    { FC_PORTSTATE_DELETED,     "Deleted", 7 },
    { FC_PORTSTATE_MARGINAL,    "Marginal", 8 },    ← Target state string
};
```

## Cross-Layer Impact Analysis

### **SCSI Layer Effects**
When `FC_PORTSTATE_MARGINAL` is set:
- **I/O Processing**: I/O requests continue to be processed (`fc_remote_port_chkready()` allows it)
- **SCSI Scanning**: Target scanning continues normally
- **Error Handling**: Standard SCSI error handling applies
- **Sysfs Access**: All sysfs attributes remain accessible

### **NVMe-FC Layer Effects** (NEW)
When `FC_PORTSTATE_MARGINAL` is set:
- **Controller Marking**: `NVME_CTRL_MARGINAL` bit set on affected NVMe controllers
- **Multipath Impact**: NVMe multipath layer can make path selection decisions
- **Performance Awareness**: Controllers marked for potential performance degradation
- **Recovery Coordination**: Clearing marginal state also clears NVMe controller flags

### **Operational Impact**
- **Monitoring**: Provides intermediate state between fully online and blocked
- **Maintenance**: Allows graceful degradation during maintenance windows  
- **Performance Management**: Enables performance-aware I/O routing
- **Diagnostics**: Clear indication of port health status

## Files Involved

1. **drivers/scsi/scsi_transport_fc.c**: 
   - Main state transition logic (`fc_rport_set_marginal_state()`)
   - State validation functions (`fc_remote_port_chkready()`, etc.)
   - String parsing and mapping functions

2. **include/scsi/scsi_transport_fc.h**:
   - `FC_PORTSTATE_MARGINAL` enumeration definition
   - FC rport structure definition
   - Macro definitions for sysfs functions

3. **drivers/nvme/host/fc.c** (NEW):
   - Cross-layer integration functions
   - NVMe controller marginal state management

4. **include/linux/nvme-fc-driver.h** (NEW):
   - Cross-layer function declarations

## Usage Examples

### **Setting Marginal State**
```bash
# Check current state
cat /sys/class/fc_rport/rport-2:0-1/port_state
# Output: Online

# Set to marginal (performance degraded but functional)
echo "Marginal" > /sys/class/fc_rport/rport-2:0-1/port_state

# Verify change
cat /sys/class/fc_rport/rport-2:0-1/port_state  
# Output: Marginal
```

### **Clearing Marginal State**
```bash
# Recover from marginal state
echo "Online" > /sys/class/fc_rport/rport-2:0-1/port_state

# Verify recovery
cat /sys/class/fc_rport/rport-2:0-1/port_state
# Output: Online
```

This comprehensive call graph shows that `FC_PORTSTATE_MARGINAL` is a carefully controlled state with limited, well-defined transition paths designed for performance-aware FC port management while maintaining system stability and cross-layer coordination.

