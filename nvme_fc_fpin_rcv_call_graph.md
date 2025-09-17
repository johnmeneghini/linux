# Call Graph for nvme_fc_fpin_rcv Function

## Overview
`nvme_fc_fpin_rcv` is a function in the NVMe-FC host subsystem that processes FPIN (Fabric Performance Impact Notification) messages received from Fibre Channel switches/fabrics. FPINs are used to notify hosts about fabric performance degradation or link issues that could affect I/O performance.

**Location**: `drivers/nvme/host/fc.c:3789`  
**Export**: Exported symbol available to FC LLD drivers

## Call Graph

### Callers (Top-down)
```
FC Switch/Fabric (Hardware)
│
├── FC ELS FPIN Frame Reception
│
├── FC HBA Hardware/Firmware
│   │
│   ├── QLA2xxx Driver Path:
│   │   └── qla_isr.c (ISR/completion handling)
│   │       └── PUREX processing
│   │           └── qla27xx_process_purex_fpin()  [line 35]
│   │               ├── fc_host_fpin_rcv()        [line 48, SCSI layer]  
│   │               └── nvme_fc_fpin_rcv()        ← TARGET FUNCTION [line 50]
│   │
│   └── LPFC Driver Path:
│       └── lpfc_els.c (ELS processing)
│           └── lpfc_els_unsol_buffer() 
│               └── lpfc_els_rcv_fpin()           [line 10161]
│                   ├── fc_host_fpin_rcv()        [line 10261, SCSI layer]
│                   └── nvme_fc_fpin_rcv()        ← TARGET FUNCTION [line 10265]
```

### Function Implementation Analysis
```c
void nvme_fc_fpin_rcv(struct nvme_fc_local_port *localport,
                      u32 fpin_len, char *fpin_buf)
```

### Direct Function Calls (Callees)
```
nvme_fc_fpin_rcv()
├── localport_to_lport(localport)
│   └── container_of(localport, struct nvme_fc_lport, localport)  [line 191]
│
├── offsetof(struct fc_els_fpin, fpin_desc)                       [line 3802]
├── be32_to_cpu(fpin->desc_len)                                   [line 3803]  
├── min_t(u32, bytes_remain, be32_to_cpu(fpin->desc_len))         [line 3803]
├── be32_to_cpu(tlv->hdr.desc_tag)                                [line 3807]
├── nvme_fc_fpin_li_lport_update(lport, &tlv->li)                 [line 3810] ← Key handler
├── FC_TLV_DESC_SZ_FROM_LENGTH(tlv)                               [line 3816]
└── fc_tlv_next_desc(tlv)                                         [line 3817]
```

## Deep Dive: nvme_fc_fpin_li_lport_update Function
```
nvme_fc_fpin_li_lport_update()  [line 3744]
├── be32_to_cpu(li->pname_count)                                  [line 3746]
├── be64_to_cpu(li->attached_wwpn)                                [line 3747]  
├── be64_to_cpu(li->pname_list[i])                                [line 3752]
├── nvme_fc_rport_from_wwpn(lport, wwpn)                          [line 3754]
│   └── Search rport by WWPN in lport->endp_list                  [line 3732]
│       └── nvme_fc_rport_get(rport)                              [line 3733]
├── set_bit(NVME_CTRL_MARGINAL, &ctrl->ctrl.flags)               [line 3762, 3774]
├── spin_lock_irq(&rport->lock) / spin_unlock_irq(&rport->lock)   [line 3760, 3763]
└── nvme_fc_rport_put(rport)                                      [line 3765, 3776]
```

## Detailed Analysis

### 1. FPIN Processing Flow
```
1. FC Fabric detects performance issue/link degradation
2. FC Switch sends ELS FPIN frame to affected ports
3. FC HBA receives FPIN frame
4. FC Driver (QLA/LPFC) processes ELS frame
5. Driver calls both SCSI and NVMe-FC FPIN handlers:
   - fc_host_fpin_rcv() for SCSI transport layer
   - nvme_fc_fpin_rcv() for NVMe-FC layer
6. nvme_fc_fpin_rcv() processes FPIN descriptors
7. For Link Integrity events, marks affected controllers as MARGINAL
```

### 2. FPIN Structure Processing
```
struct fc_els_fpin {
    u8 fpin_cmd;           // ELS command (0x16)
    u8 fpin_zero[3];       // Reserved
    be32 desc_len;         // Length of descriptor list
    union fc_tlv_desc fpin_desc[];  // Variable length descriptors
};

union fc_tlv_desc {
    struct fc_tlv_desc hdr;        // Common header with desc_tag, desc_len
    struct fc_fn_li_desc li;       // Link Integrity descriptor
    struct fc_fn_deli_desc deli;   // Delivery descriptor  
    // ... other descriptor types
};
```

### 3. Link Integrity Descriptor Processing
```
struct fc_fn_li_desc {
    be32 desc_tag;          // ELS_DTAG_LNK_INTEGRITY (0x00020001)
    be32 desc_len;          // Descriptor length
    be64 detecting_wwpn;    // Port that detected the issue
    be64 attached_wwpn;     // Attached port having issues
    be16 event_type;        // Type of link integrity event
    // ... event-specific fields
    be32 pname_count;       // Count of affected port names
    be64 pname_list[];      // List of affected WWPNs
};
```

### 4. NVMe Controller State Management
The function marks affected NVMe controllers as **MARGINAL**, which:
- Indicates potential performance degradation
- May trigger path failover in multipath configurations
- Allows the NVMe subsystem to take corrective action

### 5. Driver Integration Points

#### QLA2xxx Driver Flow:
```
qla_isr.c
├── qla24xx_msix_default() [ISR]
└── qla24xx_process_response_queue()
    └── qla2x00_process_response_queue()
        └── qla2x00_status_entry() 
            └── qla24xx_els_ct_entry()
                └── qla24xx_process_purex_iocb()
                    └── qla27xx_process_purex_fpin()
```

#### LPFC Driver Flow:  
```
lpfc_els.c
├── lpfc_els_unsol_buffer()
└── ELS frame type processing
    └── case ELS_CMD_FPIN:
        └── lpfc_els_rcv_fpin()
```

## Function Behavior

### Supported FPIN Types
- **Link Integrity Notifications** (`ELS_DTAG_LNK_INTEGRITY`): Processed
- **Other FPIN types**: Ignored (default case in switch)

### Link Integrity Processing
1. **Parse descriptor**: Extract affected port WWPNs and attached WWPN
2. **Find rports**: Look up NVMe-FC remote ports by WWPN
3. **Mark controllers**: Set `NVME_CTRL_MARGINAL` flag on affected controllers
4. **Reference counting**: Properly get/put rport references

### Error Handling
- **NULL localport**: Return silently
- **Invalid lengths**: Stop processing when insufficient bytes remain
- **Missing rports**: Continue processing other WWPNs in the list

## Integration with NVMe-FC Subsystem

### Controller State Flags
- `NVME_CTRL_MARGINAL`: Indicates performance degradation
- Used by NVMe multipath layer for path selection
- May trigger path failover or load balancing adjustments

### Remote Port Management
- Searches lport->endp_list for matching WWPNs
- Uses proper locking (spin_lock_irq) for ctrl_list access
- Maintains reference counting with nvme_fc_rport_get/put

## Files Involved
1. **drivers/nvme/host/fc.c** - Main implementation
2. **include/linux/nvme-fc-driver.h** - Function declaration and interface
3. **drivers/scsi/qla2xxx/qla_isr.c** - QLA2xxx driver caller
4. **drivers/scsi/lpfc/lpfc_els.c** - LPFC driver caller  
5. **include/uapi/scsi/fc/fc_els.h** - FPIN structure definitions

## Hardware/Firmware Context
- **FC Switches/Directors**: Generate FPIN notifications
- **FC HBAs**: Receive and process FPIN frames in firmware/hardware
- **Driver**: Software processing of FPIN content
- **NVMe-FC**: Performance-aware path management based on fabric health

This function is critical for NVMe-FC performance management and provides fabric-aware intelligence for multipath I/O optimization.
