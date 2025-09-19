# Call Graph for fc_host_fpin_rcv Function

## Overview
`fc_host_fpin_rcv` is a function in the FC (Fibre Channel) transport layer that processes FPIN (Fabric Performance Impact Notification) messages received from FC switches/fabrics. FPINs notify hosts about fabric performance issues, link degradation, or congestion that may affect I/O performance.

**Location**: `drivers/scsi/scsi_transport_fc.c:893`  
**Export**: `EXPORT_SYMBOL(fc_host_fpin_rcv)`  
**Type**: FC transport layer function for SCSI subsystem

## ⚠️ Important Note: FC_PORTSTATE_MARGINAL Setting
**`fc_host_fpin_rcv` does NOT directly set `FC_PORTSTATE_MARGINAL`**. The `FC_PORTSTATE_MARGINAL` state is only set through the separate `fc_rport_set_marginal_state` function via sysfs interface. However, there is an **indirect relationship** where fabric performance notifications (FPINs) can inform about conditions that might later trigger manual marginal state setting.

## Call Graph

### Callers (Top-down)
```
FC Fabric/Switch Hardware
│
├── **FC FPIN ELS Frame Generation**
│   ├── Fabric performance monitoring detects degradation
│   ├── Switch generates FPIN ELS (0x16) frame
│   └── Frame sent to affected ports/hosts
│
├── **FC HBA Hardware/Firmware Reception**
│   ├── FC HBA receives FPIN ELS frame
│   ├── Firmware/hardware decodes ELS frame
│   └── Passes payload to driver software
│
├── **QLA2xxx Driver Path**
│   └── drivers/scsi/qla2xxx/qla_isr.c
│       └── qla27xx_process_purex_fpin()  [line 35]
│           └── fc_host_fpin_rcv(vha->host, pkt_size, (char *)pkt, 0)  [line 48] ← **CALLER**
│
├── **LPFC Driver Path**  
│   └── drivers/scsi/lpfc/lpfc_els.c
│       └── lpfc_els_rcv_fpin()  [line 10161]
│           └── fc_host_fpin_rcv(lpfc_shost_from_vport(vport), fpin_length, (char *)fpin, 0)  [line 10261] ← **CALLER**
│
└── **Other FC Drivers** (Potential)
    └── Any FC LLD driver receiving FPIN ELS frames
        └── fc_host_fpin_rcv() calls
```

### Function Signature
```c
void fc_host_fpin_rcv(struct Scsi_Host *shost, u32 fpin_len, char *fpin_buf,
                      u8 event_acknowledge)
```

**Parameters**:
- `shost`: SCSI host the FPIN was received on
- `fpin_len`: Length of FPIN payload in bytes
- `fpin_buf`: Pointer to FPIN payload buffer
- `event_acknowledge`: 1 if LLDD handles this event, 0 otherwise

### Direct Function Calls (Callees)

```
fc_host_fpin_rcv()  [line 893]
├── **Initial Setup & Parsing**
│   ├── struct fc_els_fpin *fpin = (struct fc_els_fpin *)fpin_buf  [line 896]
│   ├── union fc_tlv_desc *tlv                                     [line 897]
│   ├── enum fc_host_event_code event_code = event_acknowledge ?   [line 900]
│   │   FCH_EVT_LINK_FPIN_ACK : FCH_EVT_LINK_FPIN
│   │
│   ├── **Buffer Setup**
│   │   ├── tlv = &fpin->fpin_desc[0]                              [line 904]
│   │   ├── offsetof(struct fc_els_fpin, fpin_desc)                [line 905]
│   │   ├── be32_to_cpu(fpin->desc_len)                            [line 906]
│   │   └── min_t(u32, bytes_remain, be32_to_cpu(fpin->desc_len))  [line 906]
│   │
│   └── **TLV Processing Loop** [lines 908-927]
│       ├── while (bytes_remain >= FC_TLV_DESC_HDR_SZ)             [line 908]
│       ├── be32_to_cpu(tlv->hdr.desc_tag)                         [line 910]
│       └── switch (dtag)                                          [line 911]
│
├── **FPIN Descriptor Processing**
│   │   **Each FPIN descriptor type calls specific stats update functions**
│   │
│   ├── **Link Integrity Events** [line 912]
│   │   ├── case ELS_DTAG_LNK_INTEGRITY:                           [line 912]
│   │   └── fc_fpin_li_stats_update(shost, &tlv->li)               [line 913] ← **FUNCTION CALL**
│   │
│   ├── **Delivery Notification Events** [line 915]
│   │   ├── case ELS_DTAG_DELIVERY:                                [line 915]
│   │   └── fc_fpin_delivery_stats_update(shost, &tlv->deli)       [line 916] ← **FUNCTION CALL**
│   │
│   ├── **Peer Congestion Events** [line 918] 
│   │   ├── case ELS_DTAG_PEER_CONGEST:                            [line 918]
│   │   └── fc_fpin_peer_congn_stats_update(shost, &tlv->peer_congn) [line 919] ← **FUNCTION CALL**
│   │
│   └── **Congestion Events** [line 921]
│       ├── case ELS_DTAG_CONGESTION:                              [line 921]
│       └── fc_fpin_congn_stats_update(shost, &tlv->congn)         [line 922] ← **FUNCTION CALL**
│
├── **TLV Navigation** 
│   ├── FC_TLV_DESC_SZ_FROM_LENGTH(tlv)                            [line 925]
│   └── fc_tlv_next_desc(tlv)                                      [line 926]
│
└── **Event Posting**
    ├── fc_get_event_number()                                       [line 929] ← **FUNCTION CALL**
    └── fc_host_post_fc_event(shost, fc_get_event_number(),         [line 929] ← **FUNCTION CALL**
        event_code, fpin_len, fpin_buf, 0)
```

## Deep Dive: Statistics Update Functions

### 1. fc_fpin_li_stats_update() [line 913]
**Location**: `drivers/scsi/scsi_transport_fc.c:753`  
**Purpose**: Update Link Integrity event statistics

```c
static void fc_fpin_li_stats_update(struct Scsi_Host *shost, 
                                   struct fc_fn_li_desc *li_desc)
├── shost_to_fc_host(shost)                                        [Get FC host attrs]
├── be16_to_cpu(li_desc->event_type)                               [Extract event type]
├── be64_to_cpu(li_desc->attached_wwpn)                            [Extract WWPN]
│
├── **Remote Port Lookup**
│   ├── fc_find_rport_by_wwpn(shost, be64_to_cpu(li_desc->attached_wwpn)) [line 762] ← **FUNCTION CALL**
│   └── if (rport): fc_li_stats_update(event_type, &rport->fpin_stats) [line 775] ← **FUNCTION CALL**
│
├── **Process Port Name List** [lines 777-787]
│   ├── for (i = 0; i < be32_to_cpu(li_desc->pname_count); i++)     [line 777]
│   ├── be64_to_cpu(li_desc->pname_list[i])                        [Extract WWPN from list]
│   ├── fc_find_rport_by_wwpn(shost, wwpn)                         [Find each rport] ← **FUNCTION CALL**
│   └── fc_li_stats_update(event_type, &rport->fpin_stats)         [Update stats] ← **FUNCTION CALL**
│
└── **Local Port Update**
    └── if (fc_host->port_name == be64_to_cpu(li_desc->attached_wwpn))
        └── fc_li_stats_update(event_type, &fc_host->fpin_stats)    [line 789] ← **FUNCTION CALL**
```

### 2. fc_fpin_delivery_stats_update() [line 916]
**Location**: `drivers/scsi/scsi_transport_fc.c:800`  
**Purpose**: Update Delivery Notification event statistics

```c
static void fc_fpin_delivery_stats_update(struct Scsi_Host *shost,
                                         struct fc_fn_deli_desc *dn_desc)
├── shost_to_fc_host(shost)                                        [Get FC host attrs]
├── be32_to_cpu(dn_desc->deli_reason_code)                         [Extract reason code]
├── be64_to_cpu(dn_desc->attached_wwpn)                            [Extract WWPN]
│
├── **Remote Port Processing**
│   ├── fc_find_rport_by_wwpn(shost, be64_to_cpu(dn_desc->attached_wwpn)) [line 808] ← **FUNCTION CALL**
│   └── if (rport): fc_delivery_stats_update(reason_code, &rport->fpin_stats) [line 815] ← **FUNCTION CALL**
│
└── **Local Port Processing**
    └── if (fc_host->port_name == be64_to_cpu(dn_desc->attached_wwpn))
        └── fc_delivery_stats_update(reason_code, &fc_host->fpin_stats) [line 819] ← **FUNCTION CALL**
```

### 3. fc_fpin_peer_congn_stats_update() [line 919]
**Location**: `drivers/scsi/scsi_transport_fc.c:830`  
**Purpose**: Update Peer Congestion event statistics

```c
static void fc_fpin_peer_congn_stats_update(struct Scsi_Host *shost,
                                           struct fc_fn_peer_congn_desc *pc_desc)
├── shost_to_fc_host(shost)                                        [Get FC host attrs]
├── be16_to_cpu(pc_desc->event_type)                               [Extract event type]
├── be64_to_cpu(pc_desc->attached_wwpn)                            [Extract WWPN]
│
├── **Remote Port Processing**
│   ├── fc_find_rport_by_wwpn(shost, be64_to_cpu(pc_desc->attached_wwpn)) [line 839] ← **FUNCTION CALL**
│   └── if (rport): fc_pc_stats_update(event_type, &rport->fpin_stats) [line 846] ← **FUNCTION CALL**
│
├── **Port Name List Processing** [lines 848-862]
│   ├── for (i = 0; i < be32_to_cpu(pc_desc->pname_count); i++)     [line 848]
│   ├── be64_to_cpu(pc_desc->pname_list[i])                        [Extract WWPN]
│   ├── fc_find_rport_by_wwpn(shost, wwpn)                         [Find rport] ← **FUNCTION CALL**
│   └── fc_pc_stats_update(event_type, &rport->fpin_stats)         [Update stats] ← **FUNCTION CALL**
│
└── **Local Port Processing** (implied)
    └── Similar pattern for local port stats
```

### 4. fc_fpin_congn_stats_update() [line 922]
**Location**: `drivers/scsi/scsi_transport_fc.c:874`  
**Purpose**: Update Congestion event statistics

```c
static void fc_fpin_congn_stats_update(struct Scsi_Host *shost,
                                      struct fc_fn_congn_desc *congn)
├── shost_to_fc_host(shost)                                        [Get FC host attrs]
├── be16_to_cpu(congn->event_type)                                 [Extract event type]
└── fc_cn_stats_update(be16_to_cpu(congn->event_type),             [line 879] ← **FUNCTION CALL**
    &fc_host->fpin_stats)
```

## Event Posting Functions

### 1. fc_get_event_number() [line 929]
**Location**: `drivers/scsi/scsi_transport_fc.c:515`  
**Purpose**: Generate unique FC event sequence number

```c
u32 fc_get_event_number(void)
└── atomic_add_return(1, &fc_event_seq)                            [Atomic increment]
```

### 2. fc_host_post_fc_event() [line 929]
**Location**: `drivers/scsi/scsi_transport_fc.c:534`  
**Purpose**: Post FC event to userspace via netlink

```c
void fc_host_post_fc_event(struct Scsi_Host *shost, u32 event_number,
                          enum fc_host_event_code event_code,
                          u32 data_len, char *data_buf, u64 vendor_id)
├── **Netlink Message Creation**
│   ├── nlmsg_new(len, GFP_KERNEL)                                 [Create netlink skb]
│   ├── nlmsg_put(skb, 0, 0, SCSI_TRANSPORT_MSG, ...)              [Setup netlink header]
│   └── nla_put() calls for event data                             [Add event payload]
│
├── **Message Population**
│   ├── Event metadata (host number, event code, data length)
│   ├── Event data payload (FPIN buffer)
│   └── Vendor ID information
│
└── **Event Broadcast**
    ├── nlmsg_multicast(scsi_nl_sock, skb, 0, ...)                 [Send to userspace]
    └── Error handling and cleanup
```

## 🔍 FC_PORTSTATE_MARGINAL Connection Analysis

### **Direct Connection**: NONE
`fc_host_fpin_rcv` does **NOT** set `FC_PORTSTATE_MARGINAL` directly. The function only:
1. Updates FPIN statistics
2. Posts events to userspace

### **Indirect Relationship**: Fabric Performance Awareness
```
**Information Flow (Does NOT Trigger Automatic State Change)**

FC Fabric Performance Issue
│
├── FC Switch generates FPIN
├── fc_host_fpin_rcv() processes FPIN  
├── Updates statistics & posts events
│
├── **SEPARATE MANUAL PROCESS**
│   ├── Administrator/monitoring system notices performance degradation
│   ├── Manual decision to mark port as marginal
│   └── echo "Marginal" > /sys/class/fc_remote_ports/rport-X:Y-Z/port_state
│       └── Triggers fc_rport_set_marginal_state()  ← **THIS** sets FC_PORTSTATE_MARGINAL
│
└── **Future Enhancement Possibility**
    └── Automatic FPIN → Marginal state logic could be added here
```

### **Where FC_PORTSTATE_MARGINAL IS Actually Set**

```
**SINGLE POINT OF CONTROL: fc_rport_set_marginal_state()**

User/Script
│
├── echo "Marginal" > /sys/class/fc_remote_ports/rport-X:Y-Z/port_state
│
├── VFS/Sysfs Layer
│   ├── sysfs_kf_write()
│   └── dev_attr_store()
│
└── FC Transport Layer
    └── fc_rport_set_marginal_state()  [drivers/scsi/scsi_transport_fc.c:1222]
        ├── get_fc_port_state_match(buf, &port_state)              [Parse "Marginal"]
        ├── if (port_state == FC_PORTSTATE_MARGINAL)               [line 1240]
        ├── if (rport->port_state == FC_PORTSTATE_ONLINE)          [line 1246]  
        │   └── **STATE CHANGE**: rport->port_state = FC_PORTSTATE_MARGINAL [line 1247]
        │
        └── **Cross-Layer NVMe-FC Integration** [line 1248-1254]
            ├── rport_to_shost(rport)
            ├── fc_host_port_name(shost) → local_wwpn
            ├── nvme_fc_lport_from_wwpn(local_wwpn) → lport        ← **FUNCTION CALL**
            ├── nvme_fc_fpin_set_state(lport, rport->port_name, true) ← **FUNCTION CALL**
            └── nvme_fc_lport_put(lport)                           ← **FUNCTION CALL**
```

## FPIN Structure Analysis

### **FPIN ELS Frame Structure**
```c
struct fc_els_fpin {
    u8 fpin_cmd;           // ELS command (0x16 for FPIN)
    u8 fpin_zero[3];       // Reserved
    __be32 desc_len;       // Total length of all descriptors
    struct fc_tlv_desc fpin_desc[0];  // Variable number of TLV descriptors
};
```

### **TLV Descriptor Types Processed**
```c
// Descriptor tags processed in fc_host_fpin_rcv()
#define ELS_DTAG_LNK_INTEGRITY    0x00020001    // Link Integrity
#define ELS_DTAG_DELIVERY         0x00020002    // Delivery Notification  
#define ELS_DTAG_PEER_CONGEST     0x00020003    // Peer Congestion
#define ELS_DTAG_CONGESTION       0x00020004    // Congestion
```

## Statistics Impact

### **Statistics Updated by fc_host_fpin_rcv()**
Each FPIN descriptor type updates specific statistics counters:

1. **Link Integrity**: Affects both per-rport and per-host `fpin_stats.li` counters
2. **Delivery**: Updates `fpin_stats.delivery` counters  
3. **Peer Congestion**: Updates `fpin_stats.peer_congn` counters
4. **Congestion**: Updates `fpin_stats.congn` counters

### **Statistics Locations**
- **Per-Remote Port**: `struct fc_rport->fpin_stats`
- **Per-FC Host**: `struct fc_host_attrs->fpin_stats`

## Integration Points

### **FC Driver Integration**
- **QLA2xxx**: Calls via `qla27xx_process_purex_fpin()` in ISR context
- **LPFC**: Calls via `lpfc_els_rcv_fpin()` in ELS processing context
- **Other Drivers**: Any FC LLD can call to process received FPIN frames

### **Userspace Integration**
- **Netlink Events**: FPIN events posted to userspace via SCSI netlink
- **Statistics**: FPIN statistics available via sysfs (fc_host and fc_rport attributes)
- **Event Types**: `FCH_EVT_LINK_FPIN` or `FCH_EVT_LINK_FPIN_ACK` based on acknowledge flag

### **Cross-Layer Integration** 
- **SCSI Layer**: Statistics and event posting only
- **NVMe-FC Layer**: **NO direct integration** (separate `nvme_fc_fpin_rcv()` function)
- **Future Enhancement**: Could add automatic marginal state triggering based on FPIN patterns

## Files Involved

1. **drivers/scsi/scsi_transport_fc.c** - Main implementation
   - `fc_host_fpin_rcv()` - Target function
   - `fc_fpin_*_stats_update()` - Statistics update functions
   - `fc_host_post_fc_event()` - Event posting
   - `fc_rport_set_marginal_state()` - **Where FC_PORTSTATE_MARGINAL is actually set**

2. **include/scsi/scsi_transport_fc.h** - Function declarations and structures

3. **drivers/scsi/qla2xxx/qla_isr.c** - QLA2xxx driver caller  

4. **drivers/scsi/lpfc/lpfc_els.c** - LPFC driver caller

5. **include/uapi/scsi/fc/fc_els.h** - FPIN structure definitions

## Function Behavior Summary

### **Primary Responsibilities**
1. **Parse FPIN TLV Descriptors**: Iterate through variable-length TLV structures
2. **Update Statistics**: Call appropriate statistics update functions per descriptor type  
3. **Event Notification**: Post FPIN events to userspace via netlink
4. **Error Handling**: Robust parsing with bounds checking

### **Key Characteristics**  
- **No State Changes**: Does not modify FC port states
- **Statistics Only**: Updates performance/error counters
- **Event-Driven**: Reactive to fabric-generated notifications
- **Userspace Visible**: Posts events for monitoring/management tools

### **Performance Impact**
- **Minimal**: Lightweight statistics updates
- **Non-Blocking**: No I/O blocking or state changes
- **Scalable**: Per-port statistics prevent contention

## Summary

`fc_host_fpin_rcv` is a **pure notification processing function** that:
- ✅ Processes FPIN performance notifications from FC fabric
- ✅ Updates detailed statistics per descriptor type  
- ✅ Posts events to userspace monitoring systems
- ❌ **Does NOT set FC_PORTSTATE_MARGINAL**
- ❌ **Does NOT change any port states**
- ❌ **Does NOT block I/O or affect operations**

The `FC_PORTSTATE_MARGINAL` state is **exclusively controlled** by the separate `fc_rport_set_marginal_state()` function via sysfs interface. While FPIN notifications provide **information** about fabric performance issues, they do **not automatically trigger** marginal state transitions - this remains a **manual administrative decision**.
