// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe I/O cancel command implementation.
 * Copyright (c) 2023 Red Hat
 */

#include "nvmet.h"

void nvmet_execute_cancel(struct nvmet_req *req)
{
	u16 cid;
	__le16 sqid;
	__le32 nsid;
	struct nvmet_sq *sq;
	struct nvmet_ctrl *ctrl = req->sq->ctrl;
	struct nvmet_req *r, *next;
	unsigned long flags;
	int ret = 0;
	u16 imm_abrts = 0;
	u16 def_abrts = 0;
	bool mult_cmds;

	if (!nvmet_check_transfer_len(req, 0))
		return;

	cid  = req->cmd->cancel.cid;
	sqid = le16_to_cpu(req->cmd->cancel.sqid);
	nsid = le32_to_cpu(req->cmd->cancel.nsid);
	mult_cmds = le32_to_cpu(req->cmd->cancel.action) &
				NVME_CANCEL_ACTION_MUL_CMD;

	if (sqid > ctrl->subsys->max_qid) {
		ret = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		goto error;
	}

	sq = req->sq;

	if (cid == req->cmd->cancel.command_id && !mult_cmds) {
		ret = NVME_SC_INVALID_CID | NVME_SC_DNR;
		goto error;
	} else if ((cid != 0xFFFF && mult_cmds) || sqid != sq->qid) {
		ret = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
		goto error;
	}

	spin_lock_irqsave(&sq->state_lock, flags);
	list_for_each_entry_safe(r, next, &sq->state_list, state_list) {
		if (r == req) {
			/* Cancel command can't abort itself */
			continue;
		}

		if (mult_cmds) {
			if (r->cmd->common.nsid != NVME_NSID_ALL &&
			    r->cmd->common.nsid != nsid) {
				continue;
			}

			nvmet_req_abort(r);
			def_abrts++;
		} else {
			if (cid != r->cmd->common.command_id)
				continue;

			if (nsid != NVME_NSID_ALL && nsid != r->cmd->common.nsid) {
				ret = NVME_SC_INVALID_FIELD | NVME_SC_DNR;
				break;
			}

			nvmet_req_abort(r);
			def_abrts++;
			break;
		}
	}
	spin_unlock_irqrestore(&sq->state_lock, flags);

error:
	nvmet_set_result(req, (def_abrts << 16) | imm_abrts);
	nvmet_req_complete(req, ret);
}

