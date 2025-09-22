# Call Graph for lpfc_nvme_info_show Function

## Overview
`lpfc_nvme_info_show` is a sysfs device attribute show function in the LPFC Fibre Channel driver that displays comprehensive NVMe-FC statistics and configuration information. It provides detailed information about NVMe initiator/target mode, remote ports, statistics, and operational status.

**Location**: `drivers/scsi/lpfc/lpfc_attr.c:464`  
**Type**: Sysfs device attribute show function  
**Export**: Static function called via device_attr_nvme_info sysfs interface

## Call Graph

### Callers (Top-down)
```
Userspace
│
├── read() system call to /sys/class/scsi_host/hostX/nvme_info
│
├── VFS/Sysfs Layer
│   ├── sysfs_kf_read()
│   ├── kernfs_fop_read_iter()  
│   └── dev_attr_show()
│
└── LPFC Driver
    └── device_attr_nvme_info.show()
        └── lpfc_nvme_info_show()  ← TARGET FUNCTION
```

### Function Signature
```c
static ssize_t lpfc_nvme_info_show(struct device *dev,
                                   struct device_attribute *attr,
                                   char *buf)
```

### Function Call Flow and Callees

```
lpfc_nvme_info_show()  [line 464]
├── **Initial Setup & Validation**
│   ├── class_to_shost(dev)                           [Get SCSI host from device]
│   ├── shost_priv(shost)                            [Get lpfc_vport from shost]
│   └── vport->phba                                  [Get lpfc_hba structure]
│
├── **Configuration Check**
│   └── if (!(vport->cfg_enable_fc4_type & LPFC_ENABLE_NVME))  [line 485]
│       └── scnprintf(buf, PAGE_SIZE, "NVME Disabled\n")      [line 486]
│
├── **NVME TARGET MODE PROCESSING** [line 489]
│   │   (if phba->nvmet_support is enabled)
│   │
│   ├── **Port Status Validation**
│   │   ├── if (!phba->targetport)                           [line 490]
│   │   │   ├── wwn_to_u64(vport->fc_portname.u.wwn)         [line 493]
│   │   │   └── scnprintf() - "Target not allocated"         [line 491]
│   │   │
│   │   └── **Port State Display**
│   │       ├── if (phba->targetport->port_id)               [line 497]
│   │       │   └── statep = "REGISTERED"                    [line 498]
│   │       └── else: statep = "INIT"                        [line 500]
│   │
│   ├── **Target Port Information**
│   │   ├── scnprintf() - "NVME Target Enabled State"        [line 501]
│   │   ├── strlcat(buf, tmp, PAGE_SIZE)                     [line 504]
│   │   ├── wwn_to_u64(vport->fc_portname.u.wwn)             [line 511]
│   │   ├── wwn_to_u64(vport->fc_nodename.u.wwn)             [line 512]
│   │   └── phba->targetport->port_id                        [line 513]
│   │
│   ├── **Target Statistics Collection**
│   │   ├── tgtp = (struct lpfc_nvmet_tgtport *)phba->targetport->private [line 521]
│   │   │
│   │   ├── **Link Service Statistics**
│   │   │   ├── atomic_read(&tgtp->rcv_ls_req_in)            [line 524]
│   │   │   ├── atomic_read(&tgtp->rcv_ls_req_drop)          [line 525]
│   │   │   ├── atomic_read(&tgtp->xmt_ls_abort)             [line 526]
│   │   │   ├── atomic_read(&tgtp->rcv_ls_req_out)           [line 534]
│   │   │   ├── atomic_read(&tgtp->xmt_ls_rsp)               [line 542]
│   │   │   ├── atomic_read(&tgtp->xmt_ls_drop)              [line 543]
│   │   │   ├── atomic_read(&tgtp->xmt_ls_rsp_cmpl)          [line 544]
│   │   │   ├── atomic_read(&tgtp->xmt_ls_rsp_aborted)       [line 550]
│   │   │   ├── atomic_read(&tgtp->xmt_ls_rsp_xb_set)        [line 551]
│   │   │   └── atomic_read(&tgtp->xmt_ls_rsp_error)         [line 552]
│   │   │
│   │   ├── **FCP Statistics**
│   │   │   ├── atomic_read(&tgtp->rcv_fcp_cmd_in)           [line 559]
│   │   │   ├── atomic_read(&tgtp->rcv_fcp_cmd_defer)        [line 560]
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_release)          [line 561]
│   │   │   ├── atomic_read(&tgtp->rcv_fcp_cmd_drop)         [line 562]
│   │   │   ├── atomic_read(&tgtp->rcv_fcp_cmd_out)          [line 570]
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_read)             [line 579]
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_read_rsp)         [line 580]
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_write)            [line 581]
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_rsp)              [line 582]
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_drop)             [line 583]
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_rsp_cmpl)         [line 589]
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_rsp_error)        [line 590]
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_rsp_drop)         [line 591]
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_rsp_aborted)      [line 597]
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_rsp_xb_set)       [line 598]
│   │   │   └── atomic_read(&tgtp->xmt_fcp_xri_abort_cqe)    [line 599]
│   │   │
│   │   ├── **Abort Statistics**
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_abort)            [line 605]
│   │   │   ├── atomic_read(&tgtp->xmt_fcp_abort_cmpl)       [line 606]
│   │   │   ├── atomic_read(&tgtp->xmt_abort_sol)            [line 612]
│   │   │   ├── atomic_read(&tgtp->xmt_abort_unsol)          [line 613]
│   │   │   ├── atomic_read(&tgtp->xmt_abort_rsp)            [line 614]
│   │   │   └── atomic_read(&tgtp->xmt_abort_rsp_error)      [line 615]
│   │   │
│   │   ├── **Delay Statistics**  
│   │   │   ├── atomic_read(&tgtp->defer_ctx)                [line 621]
│   │   │   ├── atomic_read(&tgtp->defer_fod)                [line 622]
│   │   │   └── atomic_read(&tgtp->defer_wqfull)             [line 623]
│   │   │
│   │   └── **I/O Context Statistics**
│   │       ├── phba->sli4_hba.nvmet_xri_cnt                 [line 635]
│   │       ├── phba->sli4_hba.nvmet_io_wait_cnt             [line 636]
│   │       ├── phba->sli4_hba.nvmet_io_wait_total           [line 637]
│   │       └── tot calculation (outstanding I/O)            [line 628-638]
│   │
│   └── goto buffer_done                                     [line 640]
│
├── **NVME INITIATOR MODE PROCESSING** [line 643]
│   │   (if not nvmet_support)
│   │
│   ├── **Local Port Validation**
│   │   ├── localport = vport->localport                     [line 643]
│   │   ├── if (!localport)                                  [line 644]
│   │   │   ├── wwn_to_u64(vport->fc_portname.u.wwn)         [line 647]
│   │   │   └── scnprintf() - "Initiator not allocated"      [line 645]
│   │   └── lport = (struct lpfc_nvme_lport *)localport->private [line 650]
│   │
│   ├── **XRI Distribution Information**
│   │   ├── phba->brd_no                                     [line 656]
│   │   ├── phba->sli4_hba.max_cfg_param.max_xri             [line 657]
│   │   ├── phba->sli4_hba.io_xri_max                        [line 658]
│   │   └── lpfc_sli4_get_els_iocb_cnt(phba)                [line 659] ← **FUNCTION CALL**
│   │
│   ├── **Local Port Status**
│   │   ├── if (localport->port_id): statep = "ONLINE"       [line 664-665]
│   │   ├── else: statep = "UNKNOWN"                         [line 667]
│   │   ├── wwn_to_u64(vport->fc_portname.u.wwn)             [line 673]
│   │   ├── wwn_to_u64(vport->fc_nodename.u.wwn)             [line 674]
│   │   └── localport->port_id                               [line 675]
│   │
│   ├── **Remote Port Enumeration** [line 679-753]
│   │   ├── spin_lock_irqsave(&vport->fc_nodes_list_lock, iflags) [line 679]
│   │   ├── list_for_each_entry(ndlp, &vport->fc_nodes, nlp_listp) [line 681]
│   │   │   ├── spin_lock(&ndlp->lock)                       [line 683]
│   │   │   ├── lpfc_ndlp_get_nrport(ndlp)                  [line 684] ← **MACRO CALL**
│   │   │   ├── spin_unlock(&ndlp->lock)                     [line 687]
│   │   │   │
│   │   │   ├── **Remote Port State Processing**
│   │   │   │   ├── switch (nrport->port_state)              [line 692]
│   │   │   │   ├── case FC_OBJSTATE_ONLINE: statep = "ONLINE"    [line 693-694]
│   │   │   │   ├── case FC_OBJSTATE_UNKNOWN: statep = "UNKNOWN"  [line 696-697]
│   │   │   │   └── default: statep = "UNSUPPORTED"               [line 700]
│   │   │   │
│   │   │   ├── **Remote Port Information Display**
│   │   │   │   ├── nrport->port_name                        [line 713]
│   │   │   │   ├── nrport->node_name                        [line 718]
│   │   │   │   ├── nrport->port_id                          [line 723]
│   │   │   │   │
│   │   │   │   └── **Role Processing**
│   │   │   │       ├── if (nrport->port_role & FC_PORT_ROLE_NVME_INITIATOR) [line 728]
│   │   │   │       ├── if (nrport->port_role & FC_PORT_ROLE_NVME_TARGET)    [line 732]
│   │   │   │       ├── if (nrport->port_role & FC_PORT_ROLE_NVME_DISCOVERY) [line 736]
│   │   │   │       └── Unknown role handling                [line 740-747]
│   │   │   │
│   │   │   └── Multiple strlcat() calls for formatting       [lines 705-751]
│   │   │
│   │   └── spin_unlock_irqrestore(&vport->fc_nodes_list_lock, iflags) [line 753]
│   │
│   ├── **Initiator Statistics Collection** [line 758-811]
│   │   ├── if (!lport): goto buffer_done                    [line 755]
│   │   │
│   │   ├── **Link Service Statistics**
│   │   │   ├── atomic_read(&lport->fc4NvmeLsRequests)       [line 763]
│   │   │   ├── atomic_read(&lport->fc4NvmeLsCmpls)          [line 764]
│   │   │   ├── atomic_read(&lport->xmt_ls_abort)            [line 765]
│   │   │   ├── atomic_read(&lport->xmt_ls_err)              [line 771]
│   │   │   ├── atomic_read(&lport->cmpl_ls_xb)              [line 772]
│   │   │   └── atomic_read(&lport->cmpl_ls_err)             [line 773]
│   │   │
│   │   ├── **FCP Statistics Loop** [line 779-787]
│   │   │   ├── for (i = 0; i < phba->cfg_hdw_queue; i++)    [line 779]
│   │   │   ├── cstat = &phba->sli4_hba.hdwq[i].nvme_cstat   [line 780]
│   │   │   ├── cstat->io_cmpls                              [line 781]
│   │   │   ├── cstat->input_requests                        [line 783]
│   │   │   ├── cstat->output_requests                       [line 784]
│   │   │   └── cstat->control_requests                      [line 785]
│   │   │
│   │   └── **Additional FCP Statistics**
│   │       ├── atomic_read(&lport->xmt_fcp_abort)           [line 798]
│   │       ├── atomic_read(&lport->xmt_fcp_noxri)           [line 799]
│   │       ├── atomic_read(&lport->xmt_fcp_bad_ndlp)        [line 800]
│   │       ├── atomic_read(&lport->xmt_fcp_qdepth)          [line 801]
│   │       ├── atomic_read(&lport->xmt_fcp_wqerr)           [line 802]
│   │       ├── atomic_read(&lport->xmt_fcp_err)             [line 803]
│   │       ├── atomic_read(&lport->cmpl_fcp_xb)             [line 809]
│   │       └── atomic_read(&lport->cmpl_fcp_err)            [line 810]
│   │
│   └── goto buffer_done                                     [line 814]
│
├── **Error Handling Paths**
│   ├── unlock_buf_done:                                     [line 816]
│   │   └── spin_unlock_irqrestore(&vport->fc_nodes_list_lock, iflags) [line 817]
│   │
│   └── buffer_done:                                         [line 819]
│
├── **Buffer Management & Overflow Protection** [line 820-830]
│   ├── strnlen(buf, PAGE_SIZE)                              [line 820]
│   ├── if (unlikely(len >= (PAGE_SIZE - 1)))                [line 822]
│   ├── lpfc_printf_log(phba, KERN_INFO, LOG_NVME, ...)     [line 823] ← **FUNCTION CALL**
│   └── strscpy(buf + PAGE_SIZE - 1 - sizeof(LPFC_INFO_MORE_STR), ...) [line 827]
│
└── return len                                               [line 832]
```

## Key Functions Called

### 1. **lpfc_sli4_get_els_iocb_cnt(phba)** [line 659]
**Location**: `drivers/scsi/lpfc/lpfc_init.c:14508`  
**Purpose**: Calculate the number of ELS/CT IOCBs to reserve  
**Returns**: Number of ELS IOCBs based on max_xri configuration

### 2. **lpfc_ndlp_get_nrport(ndlp)** [line 684]
**Location**: `drivers/scsi/lpfc/lpfc_nvme.h:37` (macro)  
**Purpose**: Get NVMe remote port from node structure  
**Implementation**: 
```c
#define lpfc_ndlp_get_nrport(ndlp) \
    ((!ndlp->nrport || (ndlp->fc4_xpt_flags & NVME_XPT_UNREG_WAIT)) \
    ? NULL : ndlp->nrport)
```

### 3. **lpfc_printf_log(phba, ...)** [line 823]
**Location**: Various LPFC files  
**Purpose**: LPFC driver logging function for buffer overflow warnings

## String Formatting Functions Used

### **Core String Functions**
- `scnprintf()` - Safe formatted string printing (used ~15 times)
- `strlcat()` - Safe string concatenation (used ~30 times)  
- `strnlen()` - Safe string length calculation
- `strscpy()` - Safe string copying for overflow protection

### **Utility Functions**
- `wwn_to_u64()` - Convert WWN to 64-bit integer (used 6 times)
- `atomic_read()` - Atomic variable reading (used ~40 times)

## Data Structures Accessed

### **Primary Structures**
```c
struct lpfc_vport *vport;          // LPFC virtual port
struct lpfc_hba *phba;             // LPFC HBA structure  
struct lpfc_nvmet_tgtport *tgtp;   // NVMe target port (if target mode)
struct lpfc_nvme_lport *lport;     // NVMe local port (if initiator mode)
struct lpfc_nvme_rport *rport;     // NVMe remote port
struct lpfc_nodelist *ndlp;        // FC node list entry
struct nvme_fc_remote_port *nrport; // NVMe-FC remote port
struct lpfc_fc4_ctrl_stat *cstat;  // Per-queue statistics
```

### **Statistics Fields Accessed**
**Target Mode** (~25 atomic counters):
- LS: `rcv_ls_req_in`, `rcv_ls_req_drop`, `xmt_ls_abort`, etc.
- FCP: `rcv_fcp_cmd_in`, `xmt_fcp_read`, `xmt_fcp_write`, etc.
- Abort: `xmt_fcp_abort`, `xmt_abort_sol`, etc.

**Initiator Mode** (~15 atomic counters):
- LS: `fc4NvmeLsRequests`, `fc4NvmeLsCmpls`, `xmt_ls_abort`, etc.
- FCP: `xmt_fcp_abort`, `xmt_fcp_noxri`, `cmpl_fcp_xb`, etc.

## Function Behavior Analysis

### **Execution Paths**
1. **NVMe Disabled**: Quick exit with "NVME Disabled" message
2. **Target Mode**: Comprehensive target statistics and configuration
3. **Initiator Mode**: Local port info + remote port enumeration + statistics
4. **Error Cases**: Graceful handling with appropriate error messages

### **Buffer Management**
- Uses `PAGE_SIZE` buffer with overflow protection
- Implements `strlcat()` with size checks throughout
- Has dedicated buffer overflow detection and truncation
- Uses temporary buffer (`tmp[LPFC_MAX_INFO_TMP_LEN]`) for formatting

### **Locking Strategy**
- `spin_lock_irqsave(&vport->fc_nodes_list_lock, iflags)` for node list traversal
- `spin_lock(&ndlp->lock)` for individual node access
- Proper unlock in error paths (`unlock_buf_done`)

## Sysfs Interface

**Path**: `/sys/class/scsi_host/hostX/nvme_info`  
**Permissions**: 0444 (read-only)  
**Usage**:
```bash
# Display NVMe-FC information for lpfc host 0
cat /sys/class/scsi_host/host0/nvme_info
```

**Sample Output Sections**:
- NVMe Target/Initiator status
- WWPN/WWNN information  
- XRI distribution
- Remote port enumeration
- Comprehensive statistics (LS, FCP, Abort, Delay counters)
- Outstanding I/O context information

## Integration Points

### **LPFC Driver Integration**
- **Device Model**: Integrated as sysfs device attribute
- **NVMe-FC Transport**: Accesses NVMe-FC specific structures and statistics
- **FC Transport**: Uses FC node list and WWN information
- **Statistics Framework**: Reads atomic counters from various subsystems

### **NVMe-FC Layer Integration** 
- Accesses `nvme_fc_local_port` and `nvme_fc_remote_port` structures
- Displays NVMe-specific role information (TARGET, INITIATOR, DISCOVERY)
- Shows NVMe-FC transport layer statistics

This function serves as a comprehensive diagnostic and monitoring interface for NVMe-FC operations in the LPFC driver, providing detailed visibility into both target and initiator mode operations, port status, remote port connectivity, and extensive statistical information for performance analysis and troubleshooting.

