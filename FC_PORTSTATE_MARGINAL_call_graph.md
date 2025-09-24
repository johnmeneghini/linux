# FC_PORTSTATE_MARGINAL Call Graph

This document describes all code paths that set or clear the `FC_PORTSTATE_MARGINAL` flag in the Linux FC transport layer.

## Overview

`FC_PORTSTATE_MARGINAL` is defined in `include/scsi/scsi_transport_fc.h` as part of the `enum fc_port_state` and represents a port state indicating marginal performance or degraded connectivity.

## Paths that SET FC_PORTSTATE_MARGINAL

### 1. FPIN (Fabric Performance Impact Notification) Processing

**Main Function:** `fc_host_fpin_set_nvme_rport_marginal()`
- **Location:** `drivers/scsi/scsi_transport_fc.c:895`
- **Description:** Processes FPIN messages and sets marginal state on NVME target ports

**Call Path:**
```
FPIN Reception by Driver
└── fc_host_fpin_rcv()                           [scsi_transport_fc.c:956]
└── Driver-specific FPIN handler calls:
    ├── lpfc_els_rcv_fpin()                      [lpfc/lpfc_els.c]
    │   └── fc_host_fpin_set_nvme_rport_marginal() [scsi_transport_fc.c:928]
    │       └── nvme_fc_modify_rport_fpin_state()    [called if CONFIG_NVME_FC enabled]
    └── qla27xx_process_purex_fpin()             [qla2xxx/qla_isr.c:49]
        └── fc_host_fpin_set_nvme_rport_marginal() [scsi_transport_fc.c:928]
            └── nvme_fc_modify_rport_fpin_state()    [called if CONFIG_NVME_FC enabled]
```

**Specific Setting Location:**
- **File:** `drivers/scsi/scsi_transport_fc.c`
- **Line:** 928
- **Code:** `rport->port_state = FC_PORTSTATE_MARGINAL;`
- **Conditions:**
  - Port must be in `FC_PORTSTATE_ONLINE` state
  - Port must have `FC_PORT_ROLE_NVME_TARGET` role
  - WWPN must be in FPIN descriptor's pname_list

### 2. Sysfs Interface (User-initiated)

**Main Function:** `fc_rport_set_marginal_state()`
- **Location:** `drivers/scsi/scsi_transport_fc.c:1292`
- **Description:** Allows userspace to manually set marginal state via sysfs

**Call Path:**
```
User writes "Marginal" to sysfs
└── /sys/class/fc_remote_ports/rport-X:Y:Z/port_state
    └── fc_rport_set_marginal_state()           [scsi_transport_fc.c:1312]
        ├── rport->port_state = FC_PORTSTATE_MARGINAL
        └── nvme_fc_modify_rport_fpin_state()    [if CONFIG_NVME_FC enabled]
```

**Specific Setting Location:**
- **File:** `drivers/scsi/scsi_transport_fc.c`
- **Line:** 1312
- **Code:** `rport->port_state = port_state;`
- **Conditions:**
  - Port must be in `FC_PORTSTATE_ONLINE` state
  - Only allows `ONLINE -> MARGINAL` transition

## Paths that CLEAR FC_PORTSTATE_MARGINAL

### 1. Sysfs Interface (User-initiated clearing)

**Main Function:** `fc_rport_set_marginal_state()`
- **Location:** `drivers/scsi/scsi_transport_fc.c:1292`
- **Description:** Allows userspace to clear marginal state back to online via sysfs

**Call Path:**
```
User writes "Online" to sysfs
└── /sys/class/fc_remote_ports/rport-X:Y:Z/port_state
    └── fc_rport_set_marginal_state()           [scsi_transport_fc.c:1326]
        ├── rport->port_state = FC_PORTSTATE_ONLINE
        └── nvme_fc_modify_rport_fpin_state()    [if CONFIG_NVME_FC enabled, marginal=false]
```

**Specific Clearing Location:**
- **File:** `drivers/scsi/scsi_transport_fc.c`
- **Line:** 1326
- **Code:** `rport->port_state = port_state;`
- **Conditions:**
  - Port must be in `FC_PORTSTATE_MARGINAL` state
  - Only allows `MARGINAL -> ONLINE` transition

### 2. Implicit Clearing via State Transitions

The marginal state can be implicitly cleared when the port undergoes other state transitions (e.g., going offline/online, link down events, etc.). This happens through normal FC transport layer state management.

## NVME-FC Integration

When `FC_PORTSTATE_MARGINAL` is set or cleared, the code also updates the corresponding NVME-FC layer:

### Setting Marginal State:
```c
nvme_fc_modify_rport_fpin_state(local_wwpn, remote_wwpn, true)
└── nvme_fc_fpin_set_state()                    [drivers/nvme/host/fc.c:3770]
    └── set_bit(NVME_CTRL_MARGINAL, &ctrl->ctrl.flags)  [fc.c:3782]
```

### Clearing Marginal State:
```c
nvme_fc_modify_rport_fpin_state(local_wwpn, remote_wwpn, false)
└── nvme_fc_fpin_set_state()                    [drivers/nvme/host/fc.c:3770]
    └── clear_bit(NVME_CTRL_MARGINAL, &ctrl->ctrl.flags)  [fc.c:3784]
```

## Usage/Checking of FC_PORTSTATE_MARGINAL

The marginal state is checked in several locations:

1. **I/O Path Checks:**
   - `fc_user_scan_tgt()` - checks for online or marginal state (line 2628)
   - `fc_remote_port_add()` - handles marginal ports (line 3511)  
   - `fc_remote_port_rolechg()` - considers marginal as valid state (line 3655, 3799)
   - `fc_remote_port_chkready()` - allows I/O to marginal ports (line 4326)

2. **SCSI Eh and Error Handling:**
   - `fc_eh_should_retry_cmd()` - treats marginal ports as online for retry logic (line 778)

3. **Sysfs Display:**
   - `show_fc_rport_port_state()` - displays current state including "Marginal" (line 1349)

## Driver-Specific FPIN Handlers

### LPFC Driver:
- **File:** `drivers/scsi/lpfc/lpfc_els.c:10263`
- **Function:** Called from ELS processing when FPIN is received
- Sets marginal state for NVME-enabled ports

### QLA2XXX Driver:  
- **File:** `drivers/scsi/qla2xxx/qla_isr.c:49`
- **Function:** `qla27xx_process_purex_fpin()`
- Processes FPIN during interrupt handling

## Key Data Structures

- **fc_rport:** Main structure containing `port_state` field
- **fc_els_fpin:** FPIN message structure
- **fc_fn_li_desc:** Link Integrity descriptor containing affected WWPNs

## State Transition Rules

1. **Setting Marginal:**
   - Only `FC_PORTSTATE_ONLINE` → `FC_PORTSTATE_MARGINAL` is allowed
   - Must be NVME target port for FPIN-based setting
   
2. **Clearing Marginal:**
   - Only `FC_PORTSTATE_MARGINAL` → `FC_PORTSTATE_ONLINE` is allowed via sysfs
   - Other state transitions implicitly clear marginal state

## Summary

The `FC_PORTSTATE_MARGINAL` flag serves as an indicator for degraded port performance, primarily driven by:
- **Automated FPIN processing** from fabric notifications about link integrity issues
- **Manual administrative control** via sysfs interface
- **Integration with NVME-FC** for end-to-end marginal state management

The implementation ensures controlled state transitions and provides both automated fabric-driven and manual administrative paths for managing marginal port states.
