# Testing FPIN_LI Support for NVMe Multipath

# System Setup

To fully test FPIN LI functionaliy you'll need to use the `maintenance` account
on a Brocade FC switch running FabricOS 9.2 or later. The test command used to
send FPIN ELS frames from the swich is: `fosdbg_ftc`.

```
EWY4039N00N:FID128:maintenance> fosdbg_ftc --help
----------------------------------------

Usage:

  fosdbg_ftc --<option> {parameters}

    --help                       : Display usage

    --port-index-array {port index}
                                 : Display full array, or one specified entry
    --domain {domain id}         : Display all domains, or one specified domain
    --pid [PID]                  : Display all data for the specified device
    --mallocstats                : Display memory allocation statistics
    --hash -port [port index]    : Lookup and display PID entries by Port Index
    --hash -wwn [pwwn]           : Lookup and display PID entry by N_Port WWN
    --congprim -port [port] -state [state] -time [time]
                                 : Congestion primitive ioctl test
    --congprim -port [port] -num [iterations]
                                 : Congestion primitive ioctl perf test
    --inject [PID] -<condition> {opts}

    ... OR (for NPIV ports)

    --injectport [port index] -<condition> {opts}
                                 : Inject conditions for the specified device,
                                   where '-<condition>' can be:
                                     -li {li_opt} : Single Link Integrity Event
                                     -c {c_opt}   : Latched Congestion Condition

                                   and, '{li_opt}' can be:
                                     -unknown
                                     -link_failure
                                     -loss_sync
                                     -loss_signal
                                     -primitive_error
                                     -itw
                                     -crc
                                     -dev_specific

                                   and, '{c_opt}' can be:
                                     -clear
                                     -lost-credit
                                     -credit-stall
                                     -oversubscription

    --interval -<ELS> [interval in seconds (2s-300s)]
                                 : Set send interval for the specified ELS
    --rdf [PID]                  : Send empty RDF to specified device

Examples (Native Mode):

  fosdbg_ftc --domain
  fosdbg_ftc --domain 10

  fosdbg_ftc --pid 020300

  fosdbg_ftc --mallocstats

  fosdbg_ftc --hash -port 16
  fosdbg_ftc --hash -wwn 30:18:50:eb:1a:bb:6c:fd
  fosdbg_ftc --congprim -port 16 -state 1 -time 10
  fosdbg_ftc --inject 20000 -c -credit-stall
  fosdbg_ftc --inject 20000 -c -clear
  fosdbg_ftc --inject 20000 -li -crc
  fosdbg_ftc --injectport 44 -c -credit-stall
  fosdbg_ftc --injectport 44 -c -clear
  fosdbg_ftc --injectport 44 -li -crc
  fosdbg_ftc --interval -fpin 10
  fosdbg_ftc --port-index-array
  fosdbg_ftc --port-index-array 33
```

Note that with older versions of FabricOS you may need to use the `root` account
with the command `/fabos/cliexec/ftc test --fpin` instead.

## Host commands

The following commands should be used to test the FPIN with an nvme multipath
device `/dev/nvme5n1` which is exported to the host from a NetApp Storage
Array.  Note that these commands are all examples and your test bed may be
different.

### To discover the configuration

```
nvme list-subsys /dev/nvme5n1
nvme-subsys5 - NQN=nqn.1992-08.com.netapp:sn.c7818338359111f0ac34d039ea989119:subsystem.rhel-storage-106-fcqe1
               hostnqn=nqn.2014-08.org.nvmexpress:uuid:4c4c4544-0046-3710-8054-c6c04f593234
\
 +- nvme10 fc traddr=nn-0x2047d039ea98949e:pn-0x204ad039ea98949e,host_traddr=nn-0x200000109b9b7e4f:pn-0x100000109b9b7e4f live non-optimized
 +- nvme3 fc traddr=nn-0x2047d039ea98949e:pn-0x204ed039ea98949e,host_traddr=nn-0x200000109b9b7e4f:pn-0x100000109b9b7e4f live optimized
 +- nvme5 fc traddr=nn-0x2047d039ea98949e:pn-0x204cd039ea98949e,host_traddr=nn-0x200000109b9b7e4e:pn-0x100000109b9b7e4e live optimized
 +- nvme8 fc traddr=nn-0x2047d039ea98949e:pn-0x2048d039ea98949e,host_traddr=nn-0x200000109b9b7e4e:pn-0x100000109b9b7e4e live non-optimized

grep . /sys/class/nvme-subsystem/nvme-subsys5/iopolicy
queue-depth

grep . /sys/class/fc_host/host*/{port_name,port_id,port_state,port_type} | sort
/sys/class/fc_host/host12/port_id:0x020500
/sys/class/fc_host/host12/port_name:0x100000109b9b7e4e
/sys/class/fc_host/host12/port_state:Online
/sys/class/fc_host/host12/port_type:NPort (fabric via point-to-point)
/sys/class/fc_host/host13/port_id:0x020400
/sys/class/fc_host/host13/port_name:0x100000109b9b7e4f
/sys/class/fc_host/host13/port_state:Online
/sys/class/fc_host/host13/port_type:NPort (fabric via point-to-point)

grep . /sys/class/fc_remote_ports/rport-*/roles | grep Target
/sys/class/fc_remote_ports/rport-12:0-4/roles:NVMe Target, NVMe Discovery
/sys/class/fc_remote_ports/rport-12:0-5/roles:NVMe Target, NVMe Discovery
/sys/class/fc_remote_ports/rport-13:0-4/roles:NVMe Target, NVMe Discovery
/sys/class/fc_remote_ports/rport-13:0-8/roles:NVMe Target, NVMe Discovery

grep . /sys/class/fc_remote_ports/rport-12:0-{4,5}/{port_name,port_state,roles}; grep . /sys/class/fc_remote_ports/rport-13:0-{4,8}/{port_name,port_state,roles}
/sys/class/fc_remote_ports/rport-12:0-4/port_name:0x2048d039ea98949e
/sys/class/fc_remote_ports/rport-12:0-4/port_state:Online
/sys/class/fc_remote_ports/rport-12:0-4/roles:NVMe Target, NVMe Discovery
/sys/class/fc_remote_ports/rport-12:0-5/port_name:0x204cd039ea98949e
/sys/class/fc_remote_ports/rport-12:0-5/port_state:Online
/sys/class/fc_remote_ports/rport-12:0-5/roles:NVMe Target, NVMe Discovery
/sys/class/fc_remote_ports/rport-13:0-4/port_name:0x204ad039ea98949e
/sys/class/fc_remote_ports/rport-13:0-4/port_state:Online
/sys/class/fc_remote_ports/rport-13:0-4/roles:NVMe Target, NVMe Discovery
/sys/class/fc_remote_ports/rport-13:0-8/port_name:0x204ed039ea98949e
/sys/class/fc_remote_ports/rport-13:0-8/port_state:Online
/sys/class/fc_remote_ports/rport-13:0-8/roles:NVMe Target, NVMe Discovery
```
### To monitor your test

Now you can monitor your test with the following command:

```
watch "nvme list-subsys /dev/nvme5n1; grep . /sys/class/fc_remote_ports/rport-12:0-{4,5}/{port_name,port_state,roles}; grep . /sys/class/fc_remote_ports/rport-13:0-{4,8}/{port_name,port_state,roles};"
```

Now start IO to the NVMe namespace with the command:

```
fio --name=80Grandreadwrite --filename /dev/nvme5n1 --rw=randrw --bs=4096 --direct=1 --unlink=0 --iodepth=32 --ioengine=libaio --scramble_buffers=1 --randrepeat=1 --norandommap --size=80G --time_based=1 --runtime=86400s
```

You can monitor the behavior of multipath with the `iostat` command:

```
iostat -x ID $(cat /proc/diskstats | fgrep nvme5 | fgrep n1 | awk '{print $3}' | sort -r | uniq) 4
```

### Manually set and clear the marginal path status

```
echo "Marginal" > /sys/class/fc_remote_ports/rport-13:0-8/port_state
echo "Marginal" > /sys/class/fc_remote_ports/rport-13:0-4/port_state
echo "Marginal" > /sys/class/fc_remote_ports/rport-12:0-4/port_state
echo "Marginal" > /sys/class/fc_remote_ports/rport-12:0-5/port_state

echo "Online" > /sys/class/fc_remote_ports/rport-13:0-8/port_state
echo "Online" > /sys/class/fc_remote_ports/rport-13:0-4/port_state
echo "Online" > /sys/class/fc_remote_ports/rport-12:0-4/port_state
echo "Online" > /sys/class/fc_remote_ports/rport-12:0-5/port_state
```

### Send FPIN commands from the switch

Don't forget to `export SSHPASS=passwd` before running these commands... and
replace `qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com` with your switch name.

```
# Host port 0x020500

sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020500 -li -unknown"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020500 -li -primitive_error"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020500 -li -link_failure"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020500 -li -loss_sync"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020500 -li -loss_signal"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020500 -li -itw"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020500 -li -crc"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020500 -li -dev_specific"

# Host port 0x020400

sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020400 -li -unknown"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020400 -li -primitive_error"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020400 -li -link_failure"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020400 -li -loss_sync"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020400 -li -loss_signal"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020400 -li -itw"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020400 -li -crc"
sshpass -e ssh root@qebrocade-06.mgmt.fast.eng.rdu2.dc.redhat.com "/fabos/cliexec/ftc test --fpin 0x020400 -li -dev_specific"

```

Don't forget to clear the marginal condition with the following commands
between each `/fabos/cliexec/ftc test --fpin 0x020400` command.

```
echo "Online" > /sys/class/fc_remote_ports/rport-13:0-8/port_state
echo "Online" > /sys/class/fc_remote_ports/rport-13:0-4/port_state
echo "Online" > /sys/class/fc_remote_ports/rport-12:0-4/port_state
echo "Online" > /sys/class/fc_remote_ports/rport-12:0-5/port_state
```

### Check the FPIN statistics

```
grep . /sys/class/fc_host/host*/statistics/fpin_li*
/sys/class/fc_host/host12/statistics/fpin_li:0x9
/sys/class/fc_host/host12/statistics/fpin_li_device_specific:0x1
/sys/class/fc_host/host12/statistics/fpin_li_failure_unknown:0x1
/sys/class/fc_host/host12/statistics/fpin_li_invalid_crc_count:0x1
/sys/class/fc_host/host12/statistics/fpin_li_invalid_tx_word_count:0x1
/sys/class/fc_host/host12/statistics/fpin_li_link_failure_count:0x1
/sys/class/fc_host/host12/statistics/fpin_li_loss_of_signals_count:0x1
/sys/class/fc_host/host12/statistics/fpin_li_loss_of_sync_count:0x1
/sys/class/fc_host/host12/statistics/fpin_li_prim_seq_err_count:0x2
/sys/class/fc_host/host13/statistics/fpin_li:0x8
/sys/class/fc_host/host13/statistics/fpin_li_device_specific:0x1
/sys/class/fc_host/host13/statistics/fpin_li_failure_unknown:0x1
/sys/class/fc_host/host13/statistics/fpin_li_invalid_crc_count:0x1
/sys/class/fc_host/host13/statistics/fpin_li_invalid_tx_word_count:0x1
/sys/class/fc_host/host13/statistics/fpin_li_link_failure_count:0x1
/sys/class/fc_host/host13/statistics/fpin_li_loss_of_signals_count:0x1
/sys/class/fc_host/host13/statistics/fpin_li_loss_of_sync_count:0x1
/sys/class/fc_host/host13/statistics/fpin_li_prim_seq_err_count:0x1
```

### Clear the marginal condition by removing ths link

This can be done from the storage array.

Don't forget to `export SSHPASS=passwd` before running these commands... and
replace `netapp-a400c-storage.mgmt.fast.eng.rdu2.dc.redhat.com` with your
storage array. 

```
sshpass -e ssh admin@netapp-a400c-storage.mgmt.fast.eng.rdu2.dc.redhat.com "net int modify -vserver fcqe1 -lif fcqe1_01_5c -status-admin down"
sshpass -e ssh admin@netapp-a400c-storage.mgmt.fast.eng.rdu2.dc.redhat.com "net int modify -vserver fcqe1 -lif fcqe1_01_5d -status-admin down"
sshpass -e ssh admin@netapp-a400c-storage.mgmt.fast.eng.rdu2.dc.redhat.com "net int modify -vserver fcqe1 -lif fcqe1_02_5c -status-admin down"
sshpass -e ssh admin@netapp-a400c-storage.mgmt.fast.eng.rdu2.dc.redhat.com "net int modify -vserver fcqe1 -lif fcqe1_01_5d -status-admin down"

sshpass -e ssh admin@netapp-a400c-storage.mgmt.fast.eng.rdu2.dc.redhat.com "net int modify -vserver fcqe1 -lif fcqe1_01_5c -status-admin up"
sshpass -e ssh admin@netapp-a400c-storage.mgmt.fast.eng.rdu2.dc.redhat.com "net int modify -vserver fcqe1 -lif fcqe1_01_5d -status-admin up"
sshpass -e ssh admin@netapp-a400c-storage.mgmt.fast.eng.rdu2.dc.redhat.com "net int modify -vserver fcqe1 -lif fcqe1_02_5c -status-admin up"
sshpass -e ssh admin@netapp-a400c-storage.mgmt.fast.eng.rdu2.dc.redhat.com "net int modify -vserver fcqe1 -lif fcqe1_01_5d -status-admin up"
```

Note that you will need to wait for the dev timeout to remove the device before you can bring the link up again.

```
sshpass -e ssh admin@netapp-a400c-storage.mgmt.fast.eng.rdu2.dc.redhat.com "net int modify -vserver fcqe1 -lif fcqe1_01_5d -status-admin down"
sleep 30

[root@rhel-storage-106 ~]# [ 7817.748337] nvme nvme8: NVME-FC{5}: dev_loss_tmo (30) expired while waiting for remoteport connectivity.
[ 7817.757837] nvme nvme8: Removing ctrl: NQN "nqn.1992-08.com.netapp:sn.c7818338359111f0ac34d039ea989119:subsystem.rhel-storage-106-fcqe1"
[ 7818.003262]  rport-12:0-4: blocked FC remote port time out: removing rport

sshpass -e ssh admin@netapp-a400c-storage.mgmt.fast.eng.rdu2.dc.redhat.com "net int modify -vserver fcqe1 -lif fcqe1_02_5c -status-admin up"
```

### Multipathing policy

Run these tests with all of the different multipating policies and verify things work.

```
echo "numa" > /sys/class/nvme-subsystem/nvme-subsys5/iopolicy
echo "round-robin" > /sys/class/nvme-subsystem/nvme-subsys5/iopolicy
echo "queue-depth" > /sys/class/nvme-subsystem/nvme-subsys5/iopolicy
```

