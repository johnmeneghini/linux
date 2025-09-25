# FPIN_LI Support for NVMe Multipath

See the changes at [PATCH v10 00/11 nvme-fc: FPIN link integrity handling](https://lore.kernel.org/linux-nvme/20250926000200.837025-1-jmeneghi@redhat.com/). [Draft MR](https://github.com/johnmeneghini/linux/pull/10).

These changes are based upon the proposed patchs [PATCH v9 0/8 nvme-fc: FPIN link integrity handling](https://lore.kernel.org/linux-nvme/20250813200744.17975-1-bgurney@redhat.com) with the following changes and improvements:

## New Functions Added
1. **`nvme_fc_lport_from_wwpn()`** - Find local port by WWPN

2. **`nvme_fc_fpin_set_state()`** - Set marginal state on controllers
   - replaces old `nvme_fc_fpin_li_lport_update()`
   - Supports both setting and clearing marginal state

3. **`nvme_fc_modify_rport_fpin_state()`** - Main API function
   - Clean interface: takes WWPNs and marginal flag
   - Exported with `EXPORT_SYMBOL_GPL`
   - Replaces complex `nvme_fc_fpin_rcv()` function

## Functions Removed
1. **`nvme_fc_fpin_li_lport_update()`** - Complex FPIN processing logic
2. **`nvme_fc_fpin_rcv()`** - Direct FPIN message processing

## Functions Modified

1. **`fc_rport_set_marginal_state`**
   - Added spin_lock to protect rport state changes
   - Calls `nvme_fc_modify_rport_fpin_state` to sync SCSI and NVMe states

This enhancement enables administrators to manually control port marginal states via sysfs:

```
# Set port to marginal state
echo "Marginal" > /sys/class/fc_remote_ports/rport-4:0-1/port_state

# Clear marginal state (set to online)
echo "Online" > /sys/class/fc_remote_ports/rport-4:0-1/port_state
```

For more information read: ![fpin_v16_changes_analysis.md](fpin_v16_changes_analysis.md)

# Testing

A description of how these FPIN_LI changes were tested is available at: ![fpin_li_testing.md.md](fpin_li_testing.md)

See the kernel bugzilla [220329](https://bugzilla.kernel.org/show_bug.cgi?id=220329) for more information.
