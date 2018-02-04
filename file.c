/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2004 Erez Zadok
 * Copyright (C) 2001-2004 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
 *   		Michael C. Thompson <mcthomps@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <linux/file.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/security.h>
#include <linux/compat.h>
#include <linux/fs_stack.h>

#include <linux/key.h>
#include <linux/vmalloc.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <asm/unaligned.h>

#include "ecryptfs_kernel.h"


/**
 * ecryptfs_read_update_atime
 *
 * generic_file_read updates the atime of upper layer inode.  But, it
 * doesn't give us a chance to update the atime of the lower layer
 * inode.  This function is a wrapper to generic_file_read.  It
 * updates the atime of the lower level inode if generic_file_read
 * returns without any errors. This is to be used only for file reads.
 * The function to be used for directory reads is ecryptfs_read.
 */
static ssize_t ecryptfs_read_update_atime(struct kiocb *iocb,
				struct iov_iter *to)
{
	ssize_t rc;
	struct path *path;
	struct file *file = iocb->ki_filp;

	rc = generic_file_read_iter(iocb, to);
	if (rc >= 0) {
		path = ecryptfs_dentry_to_lower_path(file->f_path.dentry);
		touch_atime(path);
	}
	return rc;
}

struct ecryptfs_getdents_callback {
	struct dir_context ctx;
	struct dir_context *caller;
	struct super_block *sb;
	int filldir_called;
	int entries_written;
};

/* Inspired by generic filldir in fs/readdir.c */
static int
ecryptfs_filldir(struct dir_context *ctx, const char *lower_name,
		 int lower_namelen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct ecryptfs_getdents_callback *buf =
		container_of(ctx, struct ecryptfs_getdents_callback, ctx);
	size_t name_size;
	char *name;
	int rc;

	buf->filldir_called++;
	rc = ecryptfs_decode_and_decrypt_filename(&name, &name_size,
						  buf->sb, lower_name,
						  lower_namelen);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to decode and decrypt "
		       "filename [%s]; rc = [%d]\n", __func__, lower_name,
		       rc);
		goto out;
	}
	buf->caller->pos = buf->ctx.pos;
	rc = !dir_emit(buf->caller, name, name_size, ino, d_type);
	kfree(name);
	if (!rc)
		buf->entries_written++;
out:
	return rc;
}

/**
 * ecryptfs_readdir
 * @file: The eCryptfs directory file
 * @ctx: The actor to feed the entries to
 */
static int ecryptfs_readdir(struct file *file, struct dir_context *ctx)
{
	int rc;
	struct file *lower_file;
	struct inode *inode = file_inode(file);
	struct ecryptfs_getdents_callback buf = {
		.ctx.actor = ecryptfs_filldir,
		.caller = ctx,
		.sb = inode->i_sb,
	};
	lower_file = ecryptfs_file_to_lower(file);
	rc = iterate_dir(lower_file, &buf.ctx);
	ctx->pos = buf.ctx.pos;
	if (rc < 0)
		goto out;
	if (buf.filldir_called && !buf.entries_written)
		goto out;
	if (rc >= 0)
		fsstack_copy_attr_atime(inode,
					file_inode(lower_file));
out:
	return rc;
}

struct kmem_cache *ecryptfs_file_info_cache;

static int read_or_initialize_metadata(struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat;
	struct ecryptfs_crypt_stat *crypt_stat;
	int rc;

	crypt_stat = &ecryptfs_inode_to_private(inode)->crypt_stat;
	mount_crypt_stat = &ecryptfs_superblock_to_private(
						inode->i_sb)->mount_crypt_stat;
	mutex_lock(&crypt_stat->cs_mutex);

	if (crypt_stat->flags & ECRYPTFS_POLICY_APPLIED &&
	    crypt_stat->flags & ECRYPTFS_KEY_VALID) {
		rc = 0;
		goto out;
	}

	rc = ecryptfs_read_metadata(dentry);
	if (!rc)
		goto out;

	if (mount_crypt_stat->flags & ECRYPTFS_PLAINTEXT_PASSTHROUGH_ENABLED) {
		crypt_stat->flags &= ~(ECRYPTFS_I_SIZE_INITIALIZED
				       | ECRYPTFS_ENCRYPTED);
		rc = 0;
		goto out;
	}

	if (!(mount_crypt_stat->flags & ECRYPTFS_XATTR_METADATA_ENABLED) &&
	    !i_size_read(ecryptfs_inode_to_lower(inode))) {
		rc = ecryptfs_initialize_file(dentry, inode);
		if (!rc)
			goto out;
	}

	rc = -EIO;
out:
	mutex_unlock(&crypt_stat->cs_mutex);
	return rc;
}

static int ecryptfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct file *lower_file = ecryptfs_file_to_lower(file);
	/*
	 * Don't allow mmap on top of file systems that don't support it
	 * natively.  If FILESYSTEM_MAX_STACK_DEPTH > 2 or ecryptfs
	 * allows recursive mounting, this will need to be extended.
	 */
	if (!lower_file->f_op->mmap)
		return -ENODEV;
	return generic_file_mmap(file, vma);
}

/**
 * ecryptfs_open
 * @inode: inode speciying file to open
 * @file: Structure to return filled in
 *
 * Opens the file specified by inode.
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_open(struct inode *inode, struct file *file)
{
	int rc = 0;
	struct ecryptfs_crypt_stat *crypt_stat = NULL;
	struct dentry *ecryptfs_dentry = file->f_path.dentry;
	/* Private value of ecryptfs_dentry allocated in
	 * ecryptfs_lookup() */
	struct ecryptfs_file_info *file_info;

	/* Released in ecryptfs_release or end of function if failure */
	file_info = kmem_cache_zalloc(ecryptfs_file_info_cache, GFP_KERNEL);
	ecryptfs_set_file_private(file, file_info);
	if (!file_info) {
		ecryptfs_printk(KERN_ERR,
				"Error attempting to allocate memory\n");
		rc = -ENOMEM;
		goto out;
	}
	crypt_stat = &ecryptfs_inode_to_private(inode)->crypt_stat;
	mutex_lock(&crypt_stat->cs_mutex);
	if (!(crypt_stat->flags & ECRYPTFS_POLICY_APPLIED)) {
		ecryptfs_printk(KERN_DEBUG, "Setting flags for stat...\n");
		/* Policy code enabled in future release */
		crypt_stat->flags |= (ECRYPTFS_POLICY_APPLIED
				      | ECRYPTFS_ENCRYPTED);
	}
	mutex_unlock(&crypt_stat->cs_mutex);
	rc = ecryptfs_get_lower_file(ecryptfs_dentry, inode);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to initialize "
			"the lower file for the dentry with name "
			"[%pd]; rc = [%d]\n", __func__,
			ecryptfs_dentry, rc);
		goto out_free;
	}
	if ((ecryptfs_inode_to_private(inode)->lower_file->f_flags & O_ACCMODE)
	    == O_RDONLY && (file->f_flags & O_ACCMODE) != O_RDONLY) {
		rc = -EPERM;
		printk(KERN_WARNING "%s: Lower file is RO; eCryptfs "
		       "file must hence be opened RO\n", __func__);
		goto out_put;
	}
	ecryptfs_set_file_lower(
		file, ecryptfs_inode_to_private(inode)->lower_file);
	rc = read_or_initialize_metadata(ecryptfs_dentry);
	if (rc)
		goto out_put;
	ecryptfs_printk(KERN_DEBUG, "inode w/ addr = [0x%p], i_ino = "
			"[0x%.16lx] size: [0x%.16llx]\n", inode, inode->i_ino,
			(unsigned long long)i_size_read(inode));
	goto out;
out_put:
	ecryptfs_put_lower_file(inode);
out_free:
	kmem_cache_free(ecryptfs_file_info_cache,
			ecryptfs_file_to_private(file));
out:
	return rc;
}

/**
 * ecryptfs_dir_open
 * @inode: inode speciying file to open
 * @file: Structure to return filled in
 *
 * Opens the file specified by inode.
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_dir_open(struct inode *inode, struct file *file)
{
	struct dentry *ecryptfs_dentry = file->f_path.dentry;
	/* Private value of ecryptfs_dentry allocated in
	 * ecryptfs_lookup() */
	struct ecryptfs_file_info *file_info;
	struct file *lower_file;

	/* Released in ecryptfs_release or end of function if failure */
	file_info = kmem_cache_zalloc(ecryptfs_file_info_cache, GFP_KERNEL);
	ecryptfs_set_file_private(file, file_info);
	if (unlikely(!file_info)) {
		ecryptfs_printk(KERN_ERR,
				"Error attempting to allocate memory\n");
		return -ENOMEM;
	}
	lower_file = dentry_open(ecryptfs_dentry_to_lower_path(ecryptfs_dentry),
				 file->f_flags, current_cred());
	if (IS_ERR(lower_file)) {
		printk(KERN_ERR "%s: Error attempting to initialize "
			"the lower file for the dentry with name "
			"[%pd]; rc = [%ld]\n", __func__,
			ecryptfs_dentry, PTR_ERR(lower_file));
		kmem_cache_free(ecryptfs_file_info_cache, file_info);
		return PTR_ERR(lower_file);
	}
	ecryptfs_set_file_lower(file, lower_file);
	return 0;
}

static int ecryptfs_flush(struct file *file, fl_owner_t td)
{
	struct file *lower_file = ecryptfs_file_to_lower(file);

	if (lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		return lower_file->f_op->flush(lower_file, td);
	}

	return 0;
}

static int ecryptfs_release(struct inode *inode, struct file *file)
{
	ecryptfs_put_lower_file(inode);
	kmem_cache_free(ecryptfs_file_info_cache,
			ecryptfs_file_to_private(file));
	return 0;
}

static int ecryptfs_dir_release(struct inode *inode, struct file *file)
{
	fput(ecryptfs_file_to_lower(file));
	kmem_cache_free(ecryptfs_file_info_cache,
			ecryptfs_file_to_private(file));
	return 0;
}

static loff_t ecryptfs_dir_llseek(struct file *file, loff_t offset, int whence)
{
	return vfs_llseek(ecryptfs_file_to_lower(file), offset, whence);
}

static int
ecryptfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	int rc;

	rc = filemap_write_and_wait(file->f_mapping);
	if (rc)
		return rc;

	return vfs_fsync(ecryptfs_file_to_lower(file), datasync);
}

static int ecryptfs_fasync(int fd, struct file *file, int flag)
{
	int rc = 0;
	struct file *lower_file = NULL;

	lower_file = ecryptfs_file_to_lower(file);
	if (lower_file->f_op->fasync)
		rc = lower_file->f_op->fasync(fd, lower_file, flag);
	return rc;
}

static long
ecryptfs_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct file *lower_file = ecryptfs_file_to_lower(file);
	long rc = -ENOTTY;

	if (!lower_file->f_op->unlocked_ioctl)
		return rc;

	switch (cmd) {
	case FITRIM:
	case FS_IOC_GETFLAGS:
	case FS_IOC_SETFLAGS:
	case FS_IOC_GETVERSION:
	case FS_IOC_SETVERSION:
		rc = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);
		fsstack_copy_attr_all(file_inode(file), file_inode(lower_file));

		return rc;
	default:
		return rc;
	}
}

#ifdef CONFIG_COMPAT
static long
ecryptfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct file *lower_file = ecryptfs_file_to_lower(file);
	long rc = -ENOIOCTLCMD;

	if (!lower_file->f_op->compat_ioctl)
		return rc;

	switch (cmd) {
	case FS_IOC32_GETFLAGS:
	case FS_IOC32_SETFLAGS:
	case FS_IOC32_GETVERSION:
	case FS_IOC32_SETVERSION:
		rc = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);
		fsstack_copy_attr_all(file_inode(file), file_inode(lower_file));

		return rc;
	default:
		return rc;
	}
}
#endif

const struct file_operations ecryptfs_dir_fops = {
	.iterate = ecryptfs_readdir,
	.read = generic_read_dir,
	.unlocked_ioctl = ecryptfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ecryptfs_compat_ioctl,
#endif
	.open = ecryptfs_dir_open,
	.release = ecryptfs_dir_release,
	.fsync = ecryptfs_fsync,
	.llseek = ecryptfs_dir_llseek,
};

ssize_t ecryptfs_new_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos){
	
	struct address_space *mapping;
	struct inode *inode;
	//void *xmem;
	//void *src_mem;
	void *dst_mem = NULL;
	//struct page *src_page, *dst_page;
	//struct scatterlist *src_sg,
	struct scatterlist *dst_sg = NULL;
	char extent_iv[ECRYPTFS_MAX_IV_BYTES];
//	char testdata[128];
	unsigned int ecrypt_data_len;
	struct ecryptfs_crypt_stat *crypt_stat; 
	size_t ret;
	size_t extent_size;
	loff_t lower_offset;
	int rc;
	int src_pagecount;
	//int i = 0;
	struct page **pages = NULL;
	struct scatterlist *sg = NULL;
	//int i;
	//printk("offset:%lu, len:%lu\n",(unsigned long)*ppos, (unsigned long)len);

	//pgoff_t index;
//	printk("This is ecryptfs write\n");
	ecrypt_data_len = len;
	if(ecrypt_data_len % 16 != 0){
		ecrypt_data_len = 16 * (ecrypt_data_len/16 + 1);
	}
//	printk("src_pagecount : %d\n",src_pagecount);
//	printk("ppos: %lu\n",(unsigned long)*ppos);
	/*Add by wujing*/
	

	src_pagecount = PAGECOUNT(buf, len);

	pages = kzalloc(src_pagecount * sizeof(struct page *), GFP_KERNEL);
	if(!pages){
		printk("kzalloc for pages error\n");
		goto out;
	}
	sg = kzalloc(src_pagecount * sizeof(struct scatterlist), GFP_KERNEL);
	if(!sg){
		printk("kzalloc for sg error\n");
		goto out;
	}
	rc = get_userbuf((void *)buf, ecrypt_data_len, src_pagecount, pages, sg);
	if (unlikely(rc)) {
		printk("Failed to get user pages for data input\n");
	}

	ret = 0;
	mapping = filp->f_mapping;
	inode = mapping->host;
	crypt_stat = &ecryptfs_inode_to_private(inode)->crypt_stat;
	
	//IV
	rc = ecryptfs_derive_iv(extent_iv, crypt_stat,0);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error attempting to derive IV for "
			"extent [0x%.16llx]; rc = [%d]\n",
			(unsigned long long)(1), rc);
		goto out;
	}
	// src buf ready
//	src_sg = (struct scatterlist*)vmalloc(src_pagecount * sizeof(struct scatterlist));
	dst_sg = (struct scatterlist*)vmalloc(src_pagecount * sizeof(struct scatterlist));
	if(!dst_sg){
		printk("vmalloc for dst_sg error\n");
		goto out;
	}
	extent_size = crypt_stat->extent_size;

//	xmem = vmalloc(extent_size*src_pagecount);
//	__copy_from_user_inatomic_nocache(xmem, buf, len);
	//src_page = virt_to_page(xmem);
//	printk("crypt_stat->key:\n");
//	for (i = 0; i < 16;i++) {
//		printk(" %x", crypt_stat->key[i]);
//	}
//	printk("\n");
	
	//printk("src_page : %p\n",src_page);
//	src_mem = xmem;
//	printk("ecryptfs_encrypt_buf\n");

	
	
	/*ecrypt_data_len = len;
	if(ecrypt_data_len % 16 != 0){
		ecrypt_data_len = 16 * (ecrypt_data_len/16 + 1);
		for(i = len; i < ecrypt_data_len ; i++){
			((char*)src_mem)[i] = '0';
		}
	}*/
/*	printk("src_mem:\n");
	for (i = 0; i < ecrypt_data_len;i++) {
		printk("%x ",*(char*)(src_mem+i));
	}
	printk("\n");
*/
	dst_mem = vmalloc(extent_size*src_pagecount); // malloc from nvmm
	if(!dst_mem){
		printk("vmalloc for dst_mem error\n");
		goto out;
	}
	//((char*)dst_mem)[0] = '1';
	
	//dst_page = virt_to_page(dst_mem);
	
	//encrypt data ready
	//sg_init_table(&src_sg, 1);
	//sg_init_table(&dst_sg, 1);
	//sg_set_page(&src_sg, src_page, extent_size, 0);
	//sg_set_page(&dst_sg, dst_page, extent_size, 0);
	
	//virt_to_scatterlist(src_mem, extent_size*src_pagecount, src_sg, src_pagecount);
	virt_to_scatterlist(dst_mem, extent_size*src_pagecount, dst_sg, src_pagecount);

//	printk("ecrypt_data_len: %lu\n",(unsigned long) ecrypt_data_len);
	ecryptfs_encrypt_buf(crypt_stat, dst_sg, sg, ecrypt_data_len, extent_iv); // encrypt size and offset
/*	if(src_pagecount > 1){
		printk("src_sg[0].page_link: %lu\n",src_sg[0].page_link);
		printk("src_sg[1].page_link: %lu\n",src_sg[1].page_link);
		printk("dst_sg[0].page_link: %lu\n",dst_sg[0].page_link);
		printk("dst_sg[1].page_link: %lu\n",dst_sg[1].page_link);

	}*/
	//ecryptfs_encrypt_buf(crypt_stat, &dst_sg, src_sg_2, len,
	//		       extent_iv);
	/*
	printk("******new_write****: dst_mem:\n");
	for (i = 0; i < 10; i++) {
		printk("%x ", *(char *)(dst_mem + i));
	}
	printk("\n");
	*/
	lower_offset = ecryptfs_lower_header_size(crypt_stat) + *ppos;
	//rc = ecryptfs_write_lower(inode, dst_mem, lower_offset, len); // write lower file size and offset
//	printk("%s lower_offset:%lu\n",__FUNCTION__,(unsigned long)lower_offset);
//	printk("inode %p\n",inode);
	set_crypto_len_by_offset(&crypt_stat->crypto_len_listhead, *ppos, ecrypt_data_len);
	//printk("set_crypto_len_by_offset: offset: %lld, len: %d\n",*ppos,ecrypt_data_len);
	/*printk("Encrypt data:\n");
    for (i = 0; i < 10; i++) {
		printk("%x ", *(char *)(dst_mem + i));
	}*/
    rc = ecryptfs_submit_async_io(inode, dst_mem, lower_offset, ecrypt_data_len);
	if (rc < 0) {
		ecryptfs_printk(KERN_ERR,
			"Error attempting to write lower page; rc = [%d]\n",
			rc);
		goto out;
	}
	*ppos = *ppos + len;
	if ( *ppos  > i_size_read(inode)) {
		i_size_write(inode, *ppos);
		ecryptfs_printk(KERN_DEBUG, "Expanded file size to "
			"[0x%.16llx]\n",
			(unsigned long long)i_size_read(inode));
	}
	rc = ecryptfs_write_inode_size_to_metadata(inode);
	if (rc)
		printk(KERN_ERR "Error writing inode size to metadata; "
		       "rc = [%d]\n", rc);
	//vfree(xmem);
	//vfree(dst_mem);
out:
	ret = len;
	
	/*Free pages and sg when encryption finishes*/
	//printk("Free pages\n");
	if(pages)
		kfree(pages);
	//printk("Free sg\n");
	if(sg)
		kfree(sg);
	//printk("Free dst_SG\n");
	if(dst_sg)
		vfree(dst_sg);
	return ret;
}

ssize_t ecryptfs_new_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	char *kernel_buf = NULL;
	unsigned long decrypt_data_len;
	loff_t  isize;
	struct scatterlist *src_sg = NULL, *dst_sg = NULL;
	struct ecryptfs_crypt_stat *crypt_stat; 
	char extent_iv[ECRYPTFS_MAX_IV_BYTES];
	int src_pagecount;

	struct inode *inode =  filp->f_inode;
	int rt = 0;
	int rc;
	int readden = 0, copied = 0;
	//int i;
	unsigned int llen = len;
	int retry_count = 0;

	struct ecryptfs_crypto_list thead;
	struct ecryptfs_crypto_list *listitem;
	int s_offset = 0, e_offset = 0;  
	struct list_head *pos, *next;
	struct ecryptfs_crypto_list *retlisthead, *retlistail;
	int decrypted = 0;
	//int i;
	init_crypto_len_list(&thead);

	//printk("Read\n");
	//printk("offset:%lu, len:%lu\n",(unsigned long)*ppos, (unsigned long)len);
	isize = i_size_read(inode);



	if(!isize)
		goto Out;

	crypt_stat = &ecryptfs_inode_to_private(inode)->crypt_stat;
	//IV
	rc = ecryptfs_derive_iv(extent_iv, crypt_stat,0);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error attempting to derive IV for "
			"extent [0x%.16llx]; rc = [%d]\n",
			(unsigned long long)(1), rc);
		goto Out;
	}
	//printk("********len:%lu\n",(unsigned long)len);
	//printk("********ppos:%lu\n",(unsigned long)*ppos);
	if(*ppos ==  isize)
		goto Out;
	get_crypto_idx_by_offset_and_len(&crypt_stat->crypto_len_listhead, *ppos, llen,  &retlisthead, &retlistail, &s_offset, &e_offset);
	//printk("get_crypto_idx_by_offset_and_len: start_offset: %d, end_offset: %d\n",s_offset, e_offset);
    
    

	if(llen > isize - *ppos)
		llen = isize - *ppos;
	if(llen % 16 != 0)
		decrypt_data_len = (llen/16 + 1) * 16;
	else
		decrypt_data_len = llen;
	//printk("decrypt_data_len:%ld\n",decrypt_data_len);
	kernel_buf = (char*)vmalloc(decrypt_data_len);
	if(!kernel_buf){
		printk("vmalloc for kenerl_buf error\n");
		goto Out;
	}
	do {
		copied = ecryptfs_read_lower(kernel_buf + readden, ecryptfs_lower_header_size(crypt_stat) + readden + *ppos, decrypt_data_len-readden, filp->f_inode);
		//copied = ecryptfs_write_lower(req->lower_inode, req->data + written, req->offset + written, req->size - written);
		//printk("In %s, retry_count=%d,copied=%d\n", __FUNCTION__, ++retry_count, copied);
		++retry_count;
		if (unlikely(copied < 0)) {
			printk("**********%s,Read error \n", __FUNCTION__);
			rt = copied;
			goto Out;
		}
		//printk("readden:%d, copied:%d,llen:%u\n",readden,copied,llen);
		readden += copied;
		if(retry_count >10)
			break;
	} while (readden != decrypt_data_len);
	rt = readden;
	//printk("readden:%d\n",readden);
	/*printk("******new_read****befor decrypt: kernel_buf:\n");
	for (i = 0; i < 10; i++) {
		printk("%x ", *(char *)(kernel_buf + i));
	}
	printk("\n");
	
	printk("********%s, read bytes:%d******\n\n", __FUNCTION__, rt);*/
	/*if(decrypt_data_len % 4096 != 0)
		src_pagecount = decrypt_data_len/4096 + 1;
	else
		src_pagecount = decrypt_data_len/4096;
	src_sg = (struct scatterlist*)vmalloc(src_pagecount * sizeof(struct scatterlist));
	virt_to_scatterlist(kernel_buf, decrypt_data_len, src_sg, src_pagecount);
	dst_sg = src_sg;
	*/
	list_for_each_head_tail(pos, next, &retlisthead->list, &retlistail->list)
    {
    	rc = ecryptfs_derive_iv(extent_iv, crypt_stat,0);
		if (rc) {
			ecryptfs_printk(KERN_ERR, "Error attempting to derive IV for "
				"extent [0x%.16llx]; rc = [%d]\n",
				(unsigned long long)(1), rc);
			goto Out;
		}
    	listitem = list_entry(pos,struct ecryptfs_crypto_list, list); 
    	//printk("offset: %d, len: %d\n",listitem->offset,listitem->len);
    	decrypt_data_len = listitem->len;
    	if(decrypt_data_len % 4096 != 0)
			src_pagecount = decrypt_data_len/4096 + 1;
		else
			src_pagecount = decrypt_data_len/4096;
		src_sg = (struct scatterlist*)vmalloc(src_pagecount * sizeof(struct scatterlist));
		if(!src_sg){
			printk("offset:%ld, len:%ld\n",(unsigned long)*ppos, (unsigned long)len);
			printk("listitem->offset: %ld, listitem->len: %ld\n",listitem->offset,listitem->len);
			printk("vmalloc for src_sg error, vmalloc size: src_pagecount*sizeof(struct scatterlist) :%ld\n",src_pagecount * sizeof(struct scatterlist));
			goto Out;
		}
		virt_to_scatterlist(kernel_buf+decrypted, decrypt_data_len, src_sg, src_pagecount);
		dst_sg = src_sg;
        /*printk("Encrypt data:\n");
        for (i = 0; i < 10; i++) {
			printk("%x ", *(char *)(kernel_buf + decrypted + i));
		}*/
        rc = ecryptfs_decrypt_buf(crypt_stat, dst_sg, src_sg, decrypt_data_len, extent_iv);
        
        /*printk("Decrypt data:\n");
        for (i = 0; i < 10; i++) {
			printk("%x ", *(char *)(kernel_buf + decrypted + i));
		}
		printk("\n");*/
        vfree(src_sg);
        src_sg = NULL;
        decrypted += decrypt_data_len;
    }   
	
	//printk("******new_read****after decrypt: kernel_buf:\n");
	if (rc < 0) {
		ecryptfs_printk(KERN_ERR,
			"Error attempting to ecryptfs_decrypt_buf; rc = [%d]\n",
			rc);
		goto Out;
	}
	/*
	for (i = 0; i < 10; i++) {
		printk("%x ", *(char *)(kernel_buf + i));
	}
	printk("\n");*/
	__copy_to_user(buf,kernel_buf+*ppos-s_offset, llen);
	//rt = isize;
	*ppos = *ppos + rt;
	if ( *ppos > isize) {
            *ppos = isize;
    }
	
Out:
	//printk("vfree(kernel_buf)\n");
	if(kernel_buf)
		vfree(kernel_buf);
	//printk("vfree(src_sg)\n");
	if(src_sg)
		vfree(src_sg);
	return rt;
}


const struct file_operations ecryptfs_main_fops = {
	.llseek = generic_file_llseek,
	.read_iter = ecryptfs_read_update_atime,
	//.write = ecryptfs_new_write,
	//.read = ecryptfs_new_read,
	.write_iter = generic_file_write_iter,
	.unlocked_ioctl = ecryptfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ecryptfs_compat_ioctl,
#endif
	.mmap = ecryptfs_mmap,
	.open = ecryptfs_open,
	.flush = ecryptfs_flush,
	.release = ecryptfs_release,
	.fsync = ecryptfs_fsync,
	.fasync = ecryptfs_fasync,
	.splice_read = generic_file_splice_read,
};
