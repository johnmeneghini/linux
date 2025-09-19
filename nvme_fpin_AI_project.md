# John Meneghini's NVMe FPIN AI project

The goal of this project was to see if I can use the Cursor IDE with claude-4-sonnet to write some ligitimate Linux drivers code.
I needed a set of changes that would enable the NVMe FPIN changes to set and clear the marginal path state in nvme-multipath via
sysfs.

## Setup:

1. Create a Cursor account, log into the web site and download/install the .rpm on a Fedora CSB.
2. Create a fork of the linux repository in Github/gitlab and checkout the latest branch with on FPIN LI changes.
3. Start Cursor on the desktop and create a new project pointing to my local linux repository.

## Prompt 1

`build a call graph for the fc_rport_set_marinal_state function.`

This produced [fc_rport_set_marginal_state_call_graph.md](https://github.com/johnmeneghini/linux/blob/fpin_v9/fc_rport_set_marginal_state_call_graph.md)

## Prompt 2

`build a call graph for the nvme_fc_fpin_rcv function.`

This produced [nvme_fc_fpin_rcv_call_graph.md](https://github.com/johnmeneghini/linux/blob/fpin_v9/nvme_fc_fpin_rcv_call_graph.md)

## Prompt 3

`Describe the struct nvme_fc_lport. List each element in this structure and explain how they are used.`

This produced [nvme_fc_lport_structure_analysis.md](https://github.com/johnmeneghini/linux/blob/fpin_v9/nvme_fc_lport_structure_analysis.md)

## Prompt 4

```
Create a new global function called nvme_fc_fpin_set_state with the following parameters

 void nvme_fc_fpin_set_state(struct nvme_fc_lport *lport, u64 wwpn, bool marginal)

Replace the folowing code in nvme_fc_fpin_li_lport_update with a call to the new function nvme_fc_fpin_set_state

               rport = nvme_fc_rport_from_wwpn(lport, wwpn);
                if (!rport)
                        continue;
                if (wwpn != attached_wwpn) {
                        struct nvme_fc_ctrl *ctrl;

                        spin_lock_irq(&rport->lock);
                        list_for_each_entry(ctrl, &rport->ctrl_list, ctrl_list)
                                set_bit(NVME_CTRL_MARGINAL, &ctrl->ctrl.flags);
                        spin_unlock_irq(&rport->lock);
                }
                nvme_fc_rport_put(rport);

Change the set_bit(NVME_CTRL_MARGINAL, &ctrl->ctrl.flags) operation so that it clears
the NVME_CTRL_MARGINAL bit when the boolean marginal is false.
```
This produced change [5a68964bec0f](https://github.com/torvalds/linux/commit/52d15de4ec9f3cdca2e3f9c1acab5a68964bec0f)

```
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        modified:   drivers/nvme/host/fc.c
        modified:   include/linux/nvme-fc-driver.h
```

These changes did not compile. Rather than fix it myself, I ask Cursor:

## Prompt 5

```
This code does not compile. Please fix it.

  CC [M]  host/fc.o
In file included from host/fc.c:15:/home/jmeneghi/repos/linux/include/linux/nvme-fc-driver.h:542:36: error: ‘struct nvme_fc_lport’ declared inside parameter list will not be visible outside of this definition or declaration [-Werror]
  542 | void nvme_fc_fpin_set_state(struct nvme_fc_lport *lport, u64 wwpn, bool marginal);
      |                                    ^~~~~~~~~~~~~
host/fc.c:3744:1: error: conflicting types for ‘nvme_fc_fpin_set_state’; have ‘void(struct nvme_fc_lport *, u64,  bool)’ {aka ‘void(struct nvme_fc_lport *, long long unsigned int,  _Bool)’}
 3744 | nvme_fc_fpin_set_state(struct nvme_fc_lport *lport, u64 wwpn, bool marginal)
      | ^~~~~~~~~~~~~~~~~~~~~~
/home/jmeneghi/repos/linux/include/linux/nvme-fc-driver.h:542:6: note: previous declaration of ‘nvme_fc_fpin_set_state’ with type void(struct nvme_fc_lport *, u64,  bool)’ {aka ‘void(struct nvme_fc_lport *, long long unsigned int,  _Bool)’}
  542 | void nvme_fc_fpin_set_state(struct nvme_fc_lport *lport, u64 wwpn, bool marginal);
      |      ^~~~~~~~~~~~~~~~~~~~~~
In file included from /home/jmeneghi/repos/linux/include/linux/linkage.h:7,
                 from /home/jmeneghi/repos/linux/include/linux/printk.h:8,
                 from /home/jmeneghi/repos/linux/include/asm-generic/bug.h:22,
                 from /home/jmeneghi/repos/linux/arch/x86/include/asm/bug.h:103,
                 from /home/jmeneghi/repos/linux/arch/x86/include/asm/alternative.h:9,
                 from /home/jmeneghi/repos/linux/arch/x86/include/asm/barrier.h:5,
                 from /home/jmeneghi/repos/linux/include/linux/list.h:11,
                 from /home/jmeneghi/repos/linux/include/linux/module.h:12,
                 from host/fc.c:6:
host/fc.c:3763:19: error: conflicting types for ‘nvme_fc_fpin_set_state’; have ‘void(struct nvme_fc_lport *, u64,  bool)’ {aka ‘void(struct nvme_fc_lport *, long long unsigned int,  _Bool)’}
 3763 | EXPORT_SYMBOL_GPL(nvme_fc_fpin_set_state);
      |                   ^~~~~~~~~~~~~~~~~~~~~~
/home/jmeneghi/repos/linux/include/linux/export.h:76:28: note: in definition of macro ‘__EXPORT_SYMBOL’
   76 |         extern typeof(sym) sym;                                 \
      |                            ^~~
/home/jmeneghi/repos/linux/include/linux/export.h:90:41: note: in expansion of macro ‘_EXPORT_SYMBOL’
   90 | #define EXPORT_SYMBOL_GPL(sym)          _EXPORT_SYMBOL(sym, "GPL")
      |                                         ^~~~~~~~~~~~~~
host/fc.c:3763:1: note: in expansion of macro ‘EXPORT_SYMBOL_GPL’
 3763 | EXPORT_SYMBOL_GPL(nvme_fc_fpin_set_state);
      | ^~~~~~~~~~~~~~~~~
/home/jmeneghi/repos/linux/include/linux/nvme-fc-driver.h:542:6: note: previous declaration of ‘nvme_fc_fpin_set_state’ with type void(struct nvme_fc_lport *, u64,  bool)’ {aka ‘void(struct nvme_fc_lport *, long long unsigned int,  _Bool)’}
  542 | void nvme_fc_fpin_set_state(struct nvme_fc_lport *lport, u64 wwpn, bool marginal);
      |      ^~~~~~~~~~~~~~~~~~~~~~
host/fc.c: In function ‘nvme_fc_fpin_li_lport_update’:
host/fc.c:3770:31: error: unused variable ‘attached_rport’ [-Werror=unused-variable]
 3770 |         struct nvme_fc_rport *attached_rport;
      |                               ^~~~~~~~~~~~~~
cc1: all warnings being treated as errors
make[4]: *** [/home/jmeneghi/repos/linux/scripts/Makefile.build:287: host/fc.o] Error 1
make[3]: *** [/home/jmeneghi/repos/linux/scripts/Makefile.build:556: host] Error 2
make[2]: *** [/home/jmeneghi/repos/linux/Makefile:2011: .] Error 2
make[1]: *** [/home/jmeneghi/repos/linux/Makefile:248: __sub-make] Error 2
make[1]: Leaving directory '/home/jmeneghi/repos/linux/drivers/nvme'
```
This produced the change [e51bdc649dc7ed](https://github.com/torvalds/linux/commit/34318281ee60533c95a7d602e1e51bdc649dc7ed)

This code compiles cleanly, but I had to fix one logic error.

Change [5d2e160928a2](https://github.com/torvalds/linux/commit/d04d456195b5267127f9f65b3c4d5d2e160928a2)

## Prompt 6

``` 
Modify the fc_rport_set_marginal_state function and make it call nvme_fc_fpin_set_state

Find the nvme_fc_lport *lport from the fc_rport *rport and pass it to nvme_fc_fpin_set_state

Pass the fc_rport rport->port_name in the wwpn parameter to nvme_fc_fpin_set_state

When rport->port_state changes to FC_PORTSTATE_MARGINAL pass true to nvme_fc_fpin_set_state

When rport->port_state changes to FC_PORTSTATE_ONLINE pass false to nvme_fc_fpin_set_state

Don't forget to bracket all calls to nvme_fc_fpin_set_state with #if (IS_ENABLED(CONFIG_NVME_FC))
```
This created change [d2f67e8bb058c](https://github.com/torvalds/linux/commit/fcf8adec88a0ef702310d384b79d2f67e8bb058c)

## Prompt 7

```
This code does not compile. Please fix it.

  CC [M]  host/fc.o
host/fc.c:263:1: error: static declaration of ‘nvme_fc_lport_put’ follows non-static declaration
  263 | nvme_fc_lport_put(struct nvme_fc_lport *lport)
      | ^~~~~~~~~~~~~~~~~
In file included from host/fc.c:15:
/home/jmeneghi/repos/linux/include/linux/nvme-fc-driver.h:544:6: note: previous declaration of ‘nvme_fc_lport_put’ with type ‘void(struct nvme_fc_lport *)’
  544 | void nvme_fc_lport_put(struct nvme_fc_lport *lport);
      |      ^~~~~~~~~~~~~~~~~
```

This created change [3c61f8c7fa99bc3e](https://github.com/torvalds/linux/commit/971b62c19939403c762289693c61f8c7fa99bc3e0)
which compiled cleanly

## Prompt 8

```
This doesn't compile.

You can't include nvme-fc-driver.h in scsi_transport_fc.c

Please fix this.

  CC [M]  scsi_transport_fc.o
In file included from scsi_transport_fc.c:26:
/home/jmeneghi/repos/linux/include/linux/nvme-fc-driver.h:706:33: error: field ‘ba_rjt’ has incomplete type
  706 |         struct fc_ba_rjt        ba_rjt;
      |                                 ^~~~~~
```
This created change [96ecc77a2b007](https://github.com/torvalds/linux/commit/464a5b3b2ef9e14c23dc9649b3396ecc77a2b007)

Now everything compiles cleanly.

## Prompt 9

`Please update fc_rport_set_marginal_state_call_graph.md with a new call graph and explain these changes.`

This created change [4b39bc27408c2](https://github.com/torvalds/linux/commit/1b0ccdd5f641cb6e7e8e55f60954b39bc27408c2)

[fc_rport_set_marginal_state_call_graph.md](https://github.com/johnmeneghini/linux/blob/fpin_v10/fc_rport_set_marginal_state_call_graph.md)

## Prompt 10

`Please update nvme_fc_fpin_rcv_call_graph.md with a new call graph and explain these changes.`

 This created change [fb0cd319680e14](https://github.com/torvalds/linux/commit/1787ac50fd15b79fb0613b94fefb0cd319680e14)

[nvme_fc_fpin_rcv_call_graph.md](https://github.com/johnmeneghini/linux/blob/fpin_v10/nvme_fc_fpin_rcv_call_graph.md)

## Prompt 11

`Build a call graph for all Code That Sets or Clears FC_PORTSTATE_MARGINAL`

[fc_portstate_marginal_call_graph.md](https://github.com/johnmeneghini/linux/blob/fpin_v10/fc_portstate_marginal_call_graph.md)

## Prompt 12

`Build a call graph for lpfc_nvme_info_show Function`

[lpfc_nvme_info_show_call_graph.md](https://github.com/johnmeneghini/linux/blob/fpin_v10/lpfc_nvme_info_show_call_graph.md)

## Prompt 13

`Please build a call graph for the function fc_host_fpin_rcv and point out where the FC_PORTSTATE_MARGINAL state is set in the call graph.`

[fc_host_fpin_rcv_call_graph.md](https://github.com/johnmeneghini/linux/blob/fpin_v10/fc_host_fpin_rcv_call_graph.md)

The AI was not able to answer this question.  It said:

```
This analysis shows that while FPIN messages provide valuable performance
information that could inform decisions about marking ports as marginal, the
actual state change is a separate administrative action. The system maintains
clear separation between notification/monitoring (FPIN processing) and state
management (marginal state setting).
```

## Prompt 14

```
I would like the nvme_fc_fpin_rcv function to set the FC_PORTSTATE_MARGINAL state on all rports that correspond to the FPIN ELS.
Please create a separate function that does this.  This function should be called by both qla27xx_process_purex_fpin and
lpfc_els_rcv_fpin prior to calling nvme_fc_fpin_rcv  when #if (IS_ENABLED(CONFIG_NVME_FC)) is true.

        modified:   drivers/scsi/lpfc/lpfc_els.c
        modified:   drivers/scsi/qla2xxx/qla_isr.c
        modified:   drivers/scsi/scsi_transport_fc.c
        modified:   include/scsi/scsi_transport_fc.h
```

change [a6c07764b16](https://github.com/torvalds/linux/commit/a6c07764b16a993c839a20a396be3821bfb3dd2d)
change [ebceb202daf7](https://github.com/torvalds/linux/commit/ebceb202daf7c53285c97cead6c90153316b86bd)

## Prompt 15

`Please create the file fc_host_fpin_set_rport_marginal.md and make it contain all of the above comments.`

[fc_host_fpin_set_rport_marginal.md](https://github.com/johnmeneghini/linux/blob/fpin_v10/fc_host_fpin_set_rport_marginal.md)


## End

These changes are ready for testing and refinement.

All changes can be seen in my [fpin_v10 branch](https://github.com/torvalds/linux/compare/master...johnmeneghini:linux:fpin_v10)

