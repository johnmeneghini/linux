// SPDX-License-Identifier: GPL-2.0
#include <linux/compl_chain.h>

void compl_chain_init(struct compl_chain *chain)
{

	spin_lock_init(&chain->lock);
	INIT_LIST_HEAD(&chain->list);
}
EXPORT_SYMBOL_GPL(compl_chain_init);

void compl_chain_add(struct compl_chain *chain,
			struct compl_chain_entry *entry)
{

	init_completion(&entry->prev_finished);
	INIT_LIST_HEAD(&entry->list);

	entry->chain = chain;

	spin_lock(&chain->lock);
	if (list_empty(&chain->list))
		complete_all(&entry->prev_finished);
	list_add_tail(&entry->list, &chain->list);
	spin_unlock(&chain->lock);
}
EXPORT_SYMBOL_GPL(compl_chain_add);

void compl_chain_wait(struct compl_chain_entry *entry)
{

	WARN_ON(!entry->chain);

	wait_for_completion(&entry->prev_finished);
}
EXPORT_SYMBOL_GPL(compl_chain_wait);

void compl_chain_complete(struct compl_chain_entry *entry)
{

	struct compl_chain *chain = entry->chain;

	WARN_ON(!chain);

	wait_for_completion(&entry->prev_finished);

	spin_lock(&chain->lock);
	list_del(&entry->list);
	if (!list_empty(&chain->list)) {
		struct compl_chain_entry *next =
			list_first_entry(&chain->list,
					 struct compl_chain_entry, list);
		complete_all(&next->prev_finished);
	}
	spin_unlock(&chain->lock);

	entry->chain = NULL;
}
EXPORT_SYMBOL_GPL(compl_chain_complete);

bool compl_chain_empty(struct compl_chain *chain)
{

	bool r;

	spin_lock(&chain->lock);
	r = list_empty(&chain->list);
	spin_unlock(&chain->lock);

	return r;
}
EXPORT_SYMBOL_GPL(compl_chain_empty);
