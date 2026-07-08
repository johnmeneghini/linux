# NVMe Target FC Loopback Transport Driver (`fcloop.c`)

## Overview

The `fcloop` driver (`drivers/nvme/target/fcloop.c`) is a **virtual NVMe-oF Fibre Channel
loopback transport driver**. It creates a software-only FC transport that connects an NVMe
host (initiator) to an NVMe target on the same machine, without requiring any physical Fibre
Channel hardware. It achieves this by acting as both an FC Low-Level Device Driver (LLDD)
for the host side and a target-side transport, bridging the two through in-memory data
copies.

The driver was originally developed by Avago Technologies (now Broadcom) and is primarily
used for:

- **Testing and development** of NVMe-oF FC host and target subsystems without physical HBAs
- **Functional validation** of the `nvme-fc` host transport and `nvmet-fc` target transport
- **Fault injection testing** via command-drop capabilities

## Architecture

### Port Model

The driver implements a layered port model with three types of ports:

```
 ┌─────────────────────────────────────────────────────────────┐
 │                      fcloop module                          │
 │                                                             │
 │  ┌──────────────┐        ┌──────────────────────────────┐   │
 │  │  Local Port   │        │         NPort                │   │
 │  │  (fcloop_lport)│       │     (fcloop_nport)           │   │
 │  │              │        │  ┌────────┐  ┌────────────┐  │   │
 │  │  Registers   │        │  │ Remote │  │  Target    │  │   │
 │  │  with nvme-fc│        │  │  Port  │  │   Port     │  │   │
 │  │  as host LLDD│        │  │(rport) │  │  (tport)   │  │   │
 │  └──────────────┘        │  └────────┘  └────────────┘  │   │
 │                          └──────────────────────────────────┘│
 │         │                        │               │          │
 │         ▼                        ▼               ▼          │
 │    nvme_fc_local_port     nvme_fc_remote_port  nvmet_fc_     │
 │    (host transport)       (host transport)     target_port  │
 │                                                (target      │
 │                                                 transport)  │
 └─────────────────────────────────────────────────────────────┘
```

- **Local Port (`fcloop_lport`)**: Represents a virtual FC host adapter. Registers with
  the `nvme-fc` host transport layer via `nvme_fc_register_localport()`. Identified by
  WWNN + WWPN.

- **NPort (`fcloop_nport`)**: An internal nexus that ties together a remote port and a
  target port sharing the same WWNN/WWPN identity. The nport manages reference counting
  and lifecycle for both the remote and target sides. It ensures that when both an rport
  and a tport are created with the same identity, they are interconnected so I/O can flow
  through the loopback.

- **Remote Port (`fcloop_rport`)**: The host-side view of a remote FC port. Registers with
  the `nvme-fc` host transport via `nvme_fc_register_remoteport()`. Created under a local
  port. Contains work queues for processing link-service (LS) request completions.

- **Target Port (`fcloop_tport`)**: The target-side FC port. Registers with the `nvmet-fc`
  target transport via `nvmet_fc_register_targetport()`. Contains work queues for processing
  LS request completions from the target perspective.

### Data Flow

#### Host-to-Target (H2T) Path

1. **LS Requests** (`fcloop_h2t_ls_req`): When the host transport sends a link-service
   request (e.g., Create Association, Create Connection), `fcloop` forwards it directly to
   the target transport via `nvmet_fc_rcv_ls_req()`. If no target port is connected, the
   request completes with `-ECONNREFUSED`.

2. **LS Response** (`fcloop_h2t_xmt_ls_rsp`): When the target transport generates a
   response, `fcloop` copies the response buffer back to the host's request structure and
   completes it via the host done callback. Responses are queued to the rport's work queue
   for asynchronous completion.

3. **FCP I/O** (`fcloop_fcp_req`): NVMe commands are forwarded from the host transport to
   the target transport. Each I/O allocates an `fcloop_fcpreq` tracking structure that manages
   the lifetime and state machine of the command through both host and target sides. The I/O is
   submitted to a work queue (`fcloop_fcp_recv_work`) for processing.

4. **FCP Operations** (`fcloop_fcp_op`): Data transfer operations (read/write/response) use
   `fcloop_fcp_copy_data()` to perform direct memory copies between host and target scatter-
   gather lists, simulating DMA transfers.

#### Target-to-Host (T2H) Path

1. **LS Requests** (`fcloop_t2h_ls_req`): Target-initiated LS requests (e.g., disconnect
   association) are forwarded to the host transport via `nvme_fc_rcv_ls_req()`.

2. **LS Response** (`fcloop_t2h_xmt_ls_rsp`): Host-generated responses are copied back and
   completed via the target's done callback, queued through the tport's work queue.

3. **Discovery Events** (`fcloop_tgt_discovery_evt`): When the target transport signals a
   discovery event (e.g., subsystem change), `fcloop` converts it into an RSCN-like
   notification by calling `nvme_fc_rescan_remoteport()` on the associated remote port.

4. **Host Address Lookup** (`fcloop_t2h_host_traddr`): Returns the WWNN/WWPN of the host
   (local port) associated with a given host handle (rport).

### I/O State Machine

Each FCP I/O request goes through a state machine tracked in `fcloop_fcpreq.inistate`:

```
  INI_IO_START ──► INI_IO_ACTIVE ──► INI_IO_COMPLETED
       │                                    ▲
       │                                    │
       ▼                                    │
  INI_IO_ABORTED ──────────────────────────┘
```

- `INI_IO_START`: Initial state when the host submits an I/O
- `INI_IO_ACTIVE`: I/O has been received by the target-side work queue
- `INI_IO_ABORTED`: Host requested abort before target completed the I/O
- `INI_IO_COMPLETED`: Target has finished processing the I/O

### Command Drop (Fault Injection)

The driver includes a built-in fault injection mechanism for dropping (silently discarding)
specific NVMe commands. This is controlled by module-level variables:

- `drop_opcode`: The NVMe opcode to match (or `-1` to disable). If bit 8+ is set, the
  opcode is treated as a fabrics command fctype rather than a standard NVMe opcode.
- `drop_fabric_opcode`: Boolean flag indicating whether to match against the fabrics fctype
  field (true) or the standard command opcode (false).
- `drop_instance`: The occurrence count at which to begin dropping (0-based). For example,
  `drop_instance=3` starts dropping on the 4th matching command.
- `drop_amount`: The number of matching commands to drop after `drop_instance` is reached.
  Internally stored as `amount - 1` because the check uses `instance + count` as the end
  boundary.
- `drop_current_cnt`: Running counter of how many matching commands have been seen.

The `check_for_drop()` function inspects every incoming FCP command. When a match is found
and the instance/amount window is active, the command is silently dropped (never forwarded
to the target), simulating a lost command on the fabric.

### Transport Templates

The driver registers two transport templates:

**Host LLDD Template (`fctemplate`)**: Registered with `nvme-fc`, defines:
- Queue create/delete (no-op stubs)
- LS request/abort handlers (H2T direction)
- FCP I/O submission and abort
- LS response transmission (T2H direction)
- Hardware limits: 4 HW queues, 256 SGL segments, 4GB DMA boundary

**Target Template (`tgttemplate`)**: Registered with `nvmet-fc`, defines:
- LS response transmission (H2T direction)
- FCP operation handler and abort
- FCP request release (triggers completion callback)
- Discovery event handler
- LS request/abort handlers (T2H direction)
- Host release and address resolution callbacks
- Hardware limits: 4 HW queues, 256 SGL segments, 4GB DMA boundary

### Concurrency and Locking

- **`fcloop_lock`** (global spinlock): Protects the global `fcloop_lports` and
  `fcloop_nports` lists, and port linking/unlinking operations.
- **`rport->lock`** / **`tport->lock`**: Per-port spinlocks protecting LS request
  completion lists.
- **`tfcp_req->reqlock`**: Per-I/O spinlock protecting the I/O state machine
  (`inistate`, `active`, `aborted`, `fcpreq` pointer).
- **`inireq->inilock`**: Per-initiator-request spinlock protecting the link between
  the initiator request and the target-side tracking structure.
- **Reference counting**: Both `fcloop_lport` and `fcloop_nport` use `refcount_t` for
  safe lifecycle management. `fcloop_fcpreq` also uses `refcount_t` to handle the race
  between normal completion and abort.

All asynchronous work (LS completions, FCP receive, abort processing, target I/O done)
is dispatched through `nvmet_wq`, the NVMe target subsystem's shared work queue.

### SLAB Cache

The driver creates a dedicated SLAB cache (`lsreq_cache`) for `fcloop_lsreq` structures,
used for link-service request tracking on both H2T and T2H paths. This avoids frequent
small allocations from the general-purpose allocator during LS exchanges.

## Sysfs Interface

All sysfs attributes are **write-only** (permissions `0200`) and are exposed under:

```
/sys/devices/virtual/fcloop/ctl/
```

The `fcloop` module creates a virtual device class `fcloop` with a single control device
`ctl`. All port management and fault injection is done by writing formatted strings to
these attributes.

### `add_local_port`

**Path**: `/sys/devices/virtual/fcloop/ctl/add_local_port`
**Permissions**: Write-only (`0200`)
**Handler**: `fcloop_create_local_port()`

Creates a virtual FC local (host) port and registers it with the `nvme-fc` host transport.

**Parameters** (comma-separated key=value pairs):

| Parameter | Required | Format | Description |
|-----------|----------|--------|-------------|
| `wwnn`    | Yes      | `0x<16 hex digits>` | World Wide Node Name of the local port |
| `wwpn`    | Yes      | `0x<16 hex digits>` | World Wide Port Name of the local port |
| `roles`   | No       | decimal integer | FC port roles bitmask (e.g., FC_PORT_ROLE_FCP_INITIATOR) |
| `fcaddr`  | No       | hex integer | FC address / port ID |

**Example**:
```bash
echo "wwnn=0x20000090fae0b5cb,wwpn=0x10000090fae0b5cb" > \
    /sys/devices/virtual/fcloop/ctl/add_local_port
```

**Behavior**:
- Allocates an `fcloop_lport` structure
- Registers with `nvme_fc_register_localport()` using the provided port information
- Adds the port to the global `fcloop_lports` list
- Returns `-EINVAL` if `wwnn` or `wwpn` are missing
- Returns `-ENOMEM` on allocation failure

---

### `del_local_port`

**Path**: `/sys/devices/virtual/fcloop/ctl/del_local_port`
**Permissions**: Write-only (`0200`)
**Handler**: `fcloop_delete_local_port()`

Removes a previously created local port by unregistering it from the `nvme-fc` transport.

**Parameters** (comma-separated key=value pairs):

| Parameter | Required | Format | Description |
|-----------|----------|--------|-------------|
| `wwnn`    | Yes      | `0x<16 hex digits>` | WWNN of the local port to delete |
| `wwpn`    | Yes      | `0x<16 hex digits>` | WWPN of the local port to delete |

**Example**:
```bash
echo "wwnn=0x20000090fae0b5cb,wwpn=0x10000090fae0b5cb" > \
    /sys/devices/virtual/fcloop/ctl/del_local_port
```

**Behavior**:
- Looks up the local port by WWNN + WWPN
- Calls `nvme_fc_unregister_localport()` to unregister from the host transport
- The `fcloop_localport_delete` callback decrements the lport reference count
- Returns `-ENOENT` if no matching local port is found

---

### `add_remote_port`

**Path**: `/sys/devices/virtual/fcloop/ctl/add_remote_port`
**Permissions**: Write-only (`0200`)
**Handler**: `fcloop_create_remote_port()`

Creates a virtual FC remote port representing a target visible to the host. The remote port
is associated with a local port and optionally linked to an existing target port if one with
the same WWNN/WWPN has already been created.

**Parameters** (comma-separated key=value pairs):

| Parameter | Required | Format | Description |
|-----------|----------|--------|-------------|
| `wwnn`    | Yes      | `0x<16 hex digits>` | WWNN of the remote port |
| `wwpn`    | Yes      | `0x<16 hex digits>` | WWPN of the remote port |
| `lpwwnn`  | Yes      | `0x<16 hex digits>` | WWNN of the parent local port |
| `lpwwpn`  | Yes      | `0x<16 hex digits>` | WWPN of the parent local port |
| `roles`   | No       | decimal integer | FC port roles bitmask |
| `fcaddr`  | No       | hex integer | FC address / port ID |

**Example**:
```bash
echo "wwnn=0x20000090fae0b5cc,wwpn=0x10000090fae0b5cc,\
lpwwnn=0x20000090fae0b5cb,lpwwpn=0x10000090fae0b5cb,roles=0x60,fcaddr=0x010101" > \
    /sys/devices/virtual/fcloop/ctl/add_remote_port
```

**Behavior**:
- Calls `fcloop_alloc_nport()` which:
  - Validates that the WWNN/WWPN does **not** match an existing local port (prevents
    looping to self)
  - Validates that the parent local port (`lpwwnn`/`lpwwpn`) **does** exist
  - Looks for an existing nport with the same WWNN/WWPN; if found, reuses it (this
    allows creating a remote port and target port in either order)
  - If no existing nport, creates a new one and adds it to `fcloop_nports`
- Registers with `nvme_fc_register_remoteport()` under the parent local port
- If a target port already exists on the same nport, cross-links the remote port and
  target port so I/O can flow through the loopback
- Returns `-EIO` on nport allocation/lookup failure

---

### `del_remote_port`

**Path**: `/sys/devices/virtual/fcloop/ctl/del_remote_port`
**Permissions**: Write-only (`0200`)
**Handler**: `fcloop_delete_remote_port()`

Removes a previously created remote port.

**Parameters** (comma-separated key=value pairs):

| Parameter | Required | Format | Description |
|-----------|----------|--------|-------------|
| `wwnn`    | Yes      | `0x<16 hex digits>` | WWNN of the remote port to delete |
| `wwpn`    | Yes      | `0x<16 hex digits>` | WWPN of the remote port to delete |

**Example**:
```bash
echo "wwnn=0x20000090fae0b5cc,wwpn=0x10000090fae0b5cc" > \
    /sys/devices/virtual/fcloop/ctl/del_remote_port
```

**Behavior**:
- Looks up the nport by WWNN + WWPN
- Unlinks the remote port from the nport (also disconnects the cross-link to any
  associated target port's `remoteport` pointer)
- Calls `nvme_fc_unregister_remoteport()` to tear down the host-side registration
- The `fcloop_remoteport_delete` callback fires, which flushes pending LS work and
  decrements the nport reference count
- Returns `-ENOENT` if no matching nport or remote port is found

---

### `add_target_port`

**Path**: `/sys/devices/virtual/fcloop/ctl/add_target_port`
**Permissions**: Write-only (`0200`)
**Handler**: `fcloop_create_target_port()`

Creates a virtual FC target port and registers it with the `nvmet-fc` target transport.

**Parameters** (comma-separated key=value pairs):

| Parameter | Required | Format | Description |
|-----------|----------|--------|-------------|
| `wwnn`    | Yes      | `0x<16 hex digits>` | WWNN of the target port |
| `wwpn`    | Yes      | `0x<16 hex digits>` | WWPN of the target port |
| `roles`   | No       | decimal integer | FC port roles bitmask |
| `fcaddr`  | No       | hex integer | FC address / port ID |

**Example**:
```bash
echo "wwnn=0x20000090fae0b5cc,wwpn=0x10000090fae0b5cc" > \
    /sys/devices/virtual/fcloop/ctl/add_target_port
```

**Behavior**:
- Calls `fcloop_alloc_nport()` which validates the WWNN/WWPN does not match a local
  port, and either reuses an existing nport or creates a new one
- Registers with `nvmet_fc_register_targetport()` using the `tgttemplate`
- If a remote port already exists on the same nport, cross-links them
- Returns `-EIO` on nport failure, or the error code from `nvmet_fc_register_targetport()`

**Note**: The target port and remote port for a given loopback path must share the same
WWNN and WWPN. They can be created in any order; the driver will automatically link them
when both exist.

---

### `del_target_port`

**Path**: `/sys/devices/virtual/fcloop/ctl/del_target_port`
**Permissions**: Write-only (`0200`)
**Handler**: `fcloop_delete_target_port()`

Removes a previously created target port.

**Parameters** (comma-separated key=value pairs):

| Parameter | Required | Format | Description |
|-----------|----------|--------|-------------|
| `wwnn`    | Yes      | `0x<16 hex digits>` | WWNN of the target port to delete |
| `wwpn`    | Yes      | `0x<16 hex digits>` | WWPN of the target port to delete |

**Example**:
```bash
echo "wwnn=0x20000090fae0b5cc,wwpn=0x10000090fae0b5cc" > \
    /sys/devices/virtual/fcloop/ctl/del_target_port
```

**Behavior**:
- Looks up the nport by WWNN + WWPN
- Unlinks the target port from the nport (also clears the remote port's `targetport`
  pointer if cross-linked)
- Calls `nvmet_fc_unregister_targetport()` to tear down the target-side registration
- The `fcloop_targetport_delete` callback fires, which flushes pending LS work and
  decrements the nport reference count
- Returns `-ENOENT` if no matching nport or target port is found

---

### `set_cmd_drop`

**Path**: `/sys/devices/virtual/fcloop/ctl/set_cmd_drop`
**Permissions**: Write-only (`0200`)
**Handler**: `fcloop_set_cmd_drop()`

Configures the command-drop fault injection mechanism. When activated, specific NVMe
commands matching the configured opcode will be silently dropped (never delivered to
the target), simulating lost commands on a Fibre Channel fabric.

**Format**: `opcode:starting_instance:amount`

| Field | Format | Description |
|-------|--------|-------------|
| `opcode` | hex | NVMe opcode to match. If the value exceeds `0xFF`, bits above the low byte signal that this is a **fabrics command**, and the low byte is matched against the fabrics `fctype` field instead of the standard opcode. |
| `starting_instance` | decimal | The 0-based occurrence number at which to begin dropping. For example, `3` means the first 3 matching commands pass through and dropping starts on the 4th. |
| `amount` | decimal | The number of consecutive matching commands to drop. |

**Example**:
```bash
# Drop the 5th instance of opcode 0x06 (Write), dropping 2 commands total
echo "06:5:2" > /sys/devices/virtual/fcloop/ctl/set_cmd_drop

# Drop the 1st instance of fabrics command fctype 0x04 (Property Get),
# dropping 1 command. The 0x100 prefix signals fabrics matching.
echo "104:1:1" > /sys/devices/virtual/fcloop/ctl/set_cmd_drop
```

**Behavior**:
- Resets the running counter (`drop_current_cnt = 0`)
- If `opcode > 0xFF`, sets `drop_fabric_opcode = true` and matches against
  `sqe.fabrics.fctype`; otherwise matches against `sqe.common.opcode`
- The drop is checked in `fcloop_fcp_recv_work()` via `check_for_drop()` before
  forwarding each FCP command to the target
- Dropped commands are logged with `pr_info` and never forwarded; from the host's
  perspective the command is lost (will eventually time out)
- The drop mechanism auto-disables after the configured amount of commands have
  been dropped (sets `drop_opcode = -1`)
- Writing a new value overwrites any previous drop configuration
- Returns `-EBADRQC` if the format does not match `%x:%d:%d`

## Typical Usage Sequence

A complete loopback setup requires creating ports in the right order and also configuring
the NVMe target subsystem (subsystems, namespaces, ports) via configfs.

```bash
# 1. Load the modules
modprobe nvme-fc
modprobe nvmet-fc
modprobe nvme-fcloop

# 2. Create a local (host) port
echo "wwnn=0x20000090fae0b5cb,wwpn=0x10000090fae0b5cb" > \
    /sys/devices/virtual/fcloop/ctl/add_local_port

# 3. Create a target port (represents the target endpoint)
echo "wwnn=0x20000090fae0b5cc,wwpn=0x10000090fae0b5cc" > \
    /sys/devices/virtual/fcloop/ctl/add_target_port

# 4. Configure NVMe target subsystem via configfs
mkdir -p /sys/kernel/config/nvmet/subsystems/testnqn
echo 1 > /sys/kernel/config/nvmet/subsystems/testnqn/attr_allow_any_host
# ... configure namespace, bind to FC port, etc.

# 5. Create a remote port (triggers host-side discovery)
echo "wwnn=0x20000090fae0b5cc,wwpn=0x10000090fae0b5cc,\
lpwwnn=0x20000090fae0b5cb,lpwwpn=0x10000090fae0b5cb,\
roles=0x60,fcaddr=0x010101" > \
    /sys/devices/virtual/fcloop/ctl/add_remote_port

# 6. Connect from host (via nvme-cli)
nvme connect -t fc -a traddr=nn-0x20000090fae0b5cc:pn-0x10000090fae0b5cc \
    -w traddr=nn-0x20000090fae0b5cb:pn-0x10000090fae0b5cb -n testnqn

# -- Teardown (reverse order) --
# Disconnect host
nvme disconnect -n testnqn

# Remove ports
echo "wwnn=0x20000090fae0b5cc,wwpn=0x10000090fae0b5cc" > \
    /sys/devices/virtual/fcloop/ctl/del_remote_port
echo "wwnn=0x20000090fae0b5cc,wwpn=0x10000090fae0b5cc" > \
    /sys/devices/virtual/fcloop/ctl/del_target_port
echo "wwnn=0x20000090fae0b5cb,wwpn=0x10000090fae0b5cb" > \
    /sys/devices/virtual/fcloop/ctl/del_local_port
```

## Module Cleanup

On module unload (`fcloop_exit`), the driver automatically tears down all remaining ports:
1. Iterates `fcloop_nports`, unlinking and unregistering all target and remote ports
2. Iterates `fcloop_lports`, unregistering all local ports
3. Destroys the `fcloop` device and class
4. Destroys the `lsreq_cache` SLAB cache

## Module Metadata

| Field | Value |
|-------|-------|
| License | GPL v2 |
| Description | NVMe target FC loop transport driver |
| Source | `drivers/nvme/target/fcloop.c` |
