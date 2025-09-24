# FC_PORTSTATE_MARGINAL Visual Call Graph

## ASCII Call Graph - Setting FC_PORTSTATE_MARGINAL

```
SETTING FC_PORTSTATE_MARGINAL
════════════════════════════════

1. FPIN (Fabric Performance Impact Notification) Path:
   ────────────────────────────────────────────────────

   Hardware/Fabric
         │
         ▼
   ┌─────────────────┐
   │ Driver IRQ      │
   │ Handler         │
   └─────────────────┘
         │
         ▼
   ┌─────────────────┐     ┌─────────────────────┐
   │ LPFC Driver     │     │ QLA2XXX Driver      │
   │ lpfc_els_rcv_   │ OR  │ qla27xx_process_    │
   │ fpin()          │     │ purex_fpin()        │
   │ [lpfc_els.c:    │     │ [qla_isr.c:35]      │
   │  10258-10266]   │     │                     │
   └─────────────────┘     └─────────────────────┘
         │                           │
         └───────────┬───────────────┘
                     ▼
   ┌─────────────────────────────────────────────┐
   │ fc_host_fpin_set_nvme_rport_marginal()      │
   │ [scsi_transport_fc.c:895]                   │
   │                                             │
   │ • Parses FPIN descriptors                   │
   │ • Finds WWPNs in pname_list                 │
   │ • Checks if port is ONLINE + NVME_TARGET    │
   │                                             │
   │ Line 928: rport->port_state =               │
   │           FC_PORTSTATE_MARGINAL             │
   └─────────────────────────────────────────────┘
                     │
                     ▼
   ┌─────────────────────────────────────────────┐
   │ nvme_fc_modify_rport_fpin_state()           │
   │ [drivers/nvme/host/fc.c:3791]               │
   │                                             │
   │ • Sets NVME_CTRL_MARGINAL bit               │
   │ • Updates NVME controller flags             │
   └─────────────────────────────────────────────┘

2. Sysfs User Interface Path:
   ──────────────────────────

   Userspace
         │
         ▼
   ┌─────────────────────────────────────────────┐
   │ echo "Marginal" >                           │
   │ /sys/class/fc_remote_ports/rport-X:Y:Z/     │
   │ port_state                                  │
   └─────────────────────────────────────────────┘
         │
         ▼
   ┌─────────────────────────────────────────────┐
   │ fc_rport_set_marginal_state()               │
   │ [scsi_transport_fc.c:1292]                  │
   │                                             │
   │ • Validates ONLINE -> MARGINAL transition   │
   │                                             │
   │ Line 1312: rport->port_state = port_state   │
   │           (FC_PORTSTATE_MARGINAL)           │
   └─────────────────────────────────────────────┘
         │
         ▼
   ┌─────────────────────────────────────────────┐
   │ nvme_fc_modify_rport_fpin_state()           │
   │ [drivers/nvme/host/fc.c:3791]               │
   │ (marginal = true)                           │
   └─────────────────────────────────────────────┘
```

## ASCII Call Graph - Clearing FC_PORTSTATE_MARGINAL

```
CLEARING FC_PORTSTATE_MARGINAL
══════════════════════════════

1. Sysfs User Interface Path (Primary):
   ─────────────────────────────────────

   Userspace
         │
         ▼
   ┌─────────────────────────────────────────────┐
   │ echo "Online" >                             │
   │ /sys/class/fc_remote_ports/rport-X:Y:Z/     │
   │ port_state                                  │
   └─────────────────────────────────────────────┘
         │
         ▼
   ┌─────────────────────────────────────────────┐
   │ fc_rport_set_marginal_state()               │
   │ [scsi_transport_fc.c:1292]                  │
   │                                             │
   │ • Validates MARGINAL -> ONLINE transition   │
   │                                             │
   │ Line 1326: rport->port_state =              │
   │           FC_PORTSTATE_ONLINE               │
   └─────────────────────────────────────────────┘
         │
         ▼
   ┌─────────────────────────────────────────────┐
   │ nvme_fc_modify_rport_fpin_state()           │
   │ [drivers/nvme/host/fc.c:3791]               │
   │ (marginal = false)                          │
   │                                             │
   │ • Clears NVME_CTRL_MARGINAL bit             │
   └─────────────────────────────────────────────┘

2. Implicit Clearing via State Transitions:
   ─────────────────────────────────────────

   Various Events
   (Link Down, Port Offline, etc.)
         │
         ▼
   ┌─────────────────────────────────────────────┐
   │ FC Transport Layer State Machine            │
   │ (Various functions in scsi_transport_fc.c)  │
   │                                             │
   │ • Normal port state transitions             │
   │ • Implicitly overwrites marginal state      │
   └─────────────────────────────────────────────┘
```

## Usage/Check Points

```
FC_PORTSTATE_MARGINAL USAGE POINTS
═══════════════════════════════════

I/O Path Checks:
┌─────────────────────────────────────────────┐
│ fc_user_scan_tgt()                          │
│ [scsi_transport_fc.c:2628]                  │
│ • Allows scanning if ONLINE || MARGINAL     │
└─────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│ fc_remote_port_chkready()                   │
│ [scsi_transport_fc.c:4326]                  │
│ • Returns BLK_STS_OK for MARGINAL ports     │
│ • Allows I/O to continue                    │
└─────────────────────────────────────────────┘

Error Handling:
┌─────────────────────────────────────────────┐
│ fc_eh_should_retry_cmd()                    │
│ [include/scsi/scsi_transport_fc.h:778]      │
│ • Treats MARGINAL same as ONLINE            │
│ • Allows command retry                      │
└─────────────────────────────────────────────┘

Display/Monitoring:
┌─────────────────────────────────────────────┐
│ show_fc_rport_port_state()                  │
│ [scsi_transport_fc.c:1349]                  │
│ • Shows "Marginal" in sysfs                 │
└─────────────────────────────────────────────┘
```

## Data Flow Diagram

```
NVME-FC Integration Data Flow
═════════════════════════════

FC Transport Layer          NVME-FC Layer
┌─────────────────┐         ┌─────────────────────┐
│ fc_rport        │         │ nvme_fc_ctrl        │
│                 │         │                     │
│ port_state =    │◄────────┤ NVME_CTRL_MARGINAL  │
│ MARGINAL        │         │ flag                │
│                 │         │                     │
└─────────────────┘         └─────────────────────┘
         │                           │
         │                           │
         ▼                           ▼
┌─────────────────┐         ┌─────────────────────┐
│ I/O allowed     │         │ Path management     │
│ with marginal   │         │ decisions affected  │
│ performance     │         │ by marginal state   │
└─────────────────┘         └─────────────────────┘
```

## State Transition Matrix

```
STATE TRANSITIONS
═════════════════

FROM/TO │ ONLINE │ MARGINAL │ OFFLINE │ OTHER
────────┼────────┼──────────┼─────────┼───────
ONLINE  │   ✓    │    ✓     │    ✓    │   ✓
        │        │  (FPIN   │         │
        │        │ /sysfs)  │         │
────────┼────────┼──────────┼─────────┼───────
MARGINAL│   ✓    │    ✓     │    ✓    │   ✓
        │(sysfs  │          │         │
        │ only)  │          │         │
────────┼────────┼──────────┼─────────┼───────
OFFLINE │   ✓    │    ✗     │    ✓    │   ✓
        │        │ (blocked) │         │
────────┼────────┼──────────┼─────────┼───────
OTHER   │   ✓    │    ✗     │    ✓    │   ✓
        │        │ (blocked) │         │

Legend:
✓ = Transition allowed
✗ = Transition blocked/not implemented
```

## Key Implementation Details

### Conditions for Setting MARGINAL via FPIN:
1. Port must be in `FC_PORTSTATE_ONLINE` 
2. Port must have `FC_PORT_ROLE_NVME_TARGET` role
3. Port WWPN must be in FPIN Link Integrity descriptor pname_list
4. WWPN must not be the attached_wwpn (switch port)

### Conditions for Manual State Changes:
1. **To MARGINAL:** Must be in `FC_PORTSTATE_ONLINE`
2. **From MARGINAL:** Must be in `FC_PORTSTATE_MARGINAL` 
3. Only bidirectional ONLINE ↔ MARGINAL transitions via sysfs

### Driver Coverage:
- **LPFC:** Full FPIN support + sysfs
- **QLA2XXX:** Full FPIN support + sysfs  
- **Other FC drivers:** sysfs support only (no FPIN handling)
