#include <linux/vmalloc.h>
#include "ecryptfs_kernel.h"

int ecryptfs_submit_async_io(struct inode *lower_inode, void *data, loff_t offset, size_t size)
{
	/*Allocate todo_list_item space and create a req
	* The allocated space should be freed when the async io is handled*/
	int count = 0;
	struct todo_list_item *tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);

	struct file *lower_file = ecryptfs_inode_to_private(lower_inode)->lower_file;
	
	struct ecryptfs_inode_info *inode_info = ecryptfs_inode_to_private(lower_inode);
	
	
	atomic_long_inc(&lower_file->f_count);

	mutex_lock(&inode_info->lower_file_mutex);
	count = atomic_inc_return(&inode_info->lower_file_count);
	mutex_unlock(&inode_info->lower_file_mutex);
	//printk("*********%s, lower_file_count=%d**********\n\n", __FUNCTION__, count);

	tmp->req.lower_inode = lower_inode;
	tmp->req.data = data;
	tmp->req.offset = offset;
	tmp->req.size = size;

	mutex_lock(&async_io_ctx->todo_list.lock);
	list_add_tail(&tmp->__hook, &async_io_ctx->todo_list.list);
	mutex_unlock(&async_io_ctx->todo_list.lock);

	queue_work(async_io_ctx->ecryptfs_async_wq, &async_io_ctx->io_task);

	return 0;
}

static int ecryptfs_write_lower_with_async_req(struct ecryptfs_async_req *req)
{
	int rc = 0;
	int written = 0, copied = 0;
	//int retry_count = 0;
	int count = 0;
	struct file *lower_file = ecryptfs_inode_to_private(req->lower_inode)->lower_file;
	struct ecryptfs_inode_info *inode_info = ecryptfs_inode_to_private(req->lower_inode);

	do {
		copied = ecryptfs_write_lower(req->lower_inode, req->data + written, req->offset + written, req->size - written);
		//printk("In %s, retry_count=%d,copied=%d\n", __FUNCTION__, ++retry_count, copied);
		if (unlikely(copied < 0)) {
			printk("**********%s,Write error \n", __FUNCTION__);
			rc = copied;
			goto out;
		}
		written += copied;
	} while (written != req->size);

	mutex_lock(&inode_info->lower_file_mutex);
	count = atomic_dec_return(&inode_info->lower_file_count);
	mutex_unlock(&inode_info->lower_file_mutex);
	//printk("*********%s, lower_file_count=%d**********\n\n", __FUNCTION__, count);
	atomic_long_dec(&lower_file->f_count);
	rc = written;
out:
	return rc;
}

static void ecryptfs_async_io_routine(struct work_struct *work)
{
	struct ecryptfs_async_ctx *ctx = container_of(work, struct ecryptfs_async_ctx, io_task);
	struct todo_list_item *item = NULL, *item_safe = NULL;
	LIST_HEAD(tmp);

	/*Fetch all pending jobs into the temporary list*/
	mutex_lock(&ctx->todo_list.lock);
	list_cut_position(&tmp, &ctx->todo_list.list, ctx->todo_list.list.prev);
	mutex_unlock(&ctx->todo_list.lock);

	/*Handle each rquest locklessly*/
	list_for_each_entry_safe(item, item_safe, &tmp, __hook) {
		item->result = ecryptfs_write_lower_with_async_req(&item->req);
		if (unlikely(item->result != item->req.size)) {
			printk("Data not fully written\n");
		}
		/*Free the space allocated by previous step*/
		vfree(item->req.data);
		list_del(&item->__hook);
		/*The space is allocated in ecryptfs_submit_async_io*/
		kfree(item);
	}

}

int ecryptfs_init_async_ctx(struct ecryptfs_async_ctx *ctx)
{
	ctx->ecryptfs_async_wq = create_singlethread_workqueue("ecryptfs_async_io_queue");
	if (unlikely(!ctx->ecryptfs_async_wq)) {
		printk("Failed to allocate the ecryptfs async io workqueue!\n");
		return -EFAULT;
	}

	INIT_LIST_HEAD(&ctx->todo_list.list);

	mutex_init(&ctx->todo_list.lock);

	INIT_WORK(&ctx->io_task, ecryptfs_async_io_routine);

	return 0;
}


int ecryptfs_deinit_async_ctx(struct ecryptfs_async_ctx *ctx)
{
	struct todo_list_item *item = NULL, *item_safe = NULL;

	cancel_work_sync(&ctx->io_task);

	list_for_each_entry_safe(item, item_safe, &ctx->todo_list.list, __hook) {
		printk("Free item at %p\n", item);
		list_del(&item->__hook);
		kfree(item);//????
	}

	flush_workqueue(ctx->ecryptfs_async_wq);
	destroy_workqueue(ctx->ecryptfs_async_wq);
	mutex_destroy(&ctx->todo_list.lock);
	kfree(ctx);

	return 0;
}
