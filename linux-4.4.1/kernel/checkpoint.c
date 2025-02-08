#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/hugetlb.h>
#include <linux/huge_mm.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/highmem.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/mmu_notifier.h>
#include <linux/page_idle.h>

#include <asm/elf.h>
#include <asm/uaccess.h>
#include <asm/tlbflush.h>

struct priv {
    struct file *file;
    unsigned long c;
};

//Incremental checkpoint

void mark_soft_clean(pte_t *pte, unsigned long addr, struct mm_walk *walk) {

    pte_t ptent; 
    ptent = *pte;

    if (pte_present(ptent)) {
        ptent = ptep_modify_prot_start(walk->mm, addr, pte);
        ptent = pte_wrprotect(ptent);
        ptent = pte_clear_soft_dirty(ptent);
        ptep_modify_prot_commit(walk->mm, addr, pte, ptent);
    } else if (is_swap_pte(ptent)) {
        ptent = pte_swp_clear_soft_dirty(ptent);
        set_pte_at(walk->mm, addr, pte, ptent);
    }
}

int do_inc_cp_range(pte_t *pte, unsigned long addr, unsigned long next, struct mm_walk *walk) 
{
    struct priv *p;
    struct page *page;

    page = pte_page(*pte);

    if(pte_none(*pte) || !pte_present(*pte) ||(pte_present(*pte) && page == ZERO_PAGE(0)))
        return 0;

    p = (struct priv*)walk->private;
    if(p->c) {
        if(pte_soft_dirty(*pte)) {
            mark_soft_clean(pte, addr, walk);
            vfs_write(p->file, (__force void __user *)addr, PAGE_SIZE, &p->file->f_pos);
        }
    }
    else {
        mark_soft_clean(pte, addr, walk);
        vfs_write(p->file, (__force void __user *)addr, PAGE_SIZE, &p->file->f_pos);
    }
    return 0;
}

SYSCALL_DEFINE3(inc_cp_range, unsigned long, start, unsigned long, end, unsigned long, cp_count)
{

    struct mm_walk inc_cp_walk = {0};
    char *path;
    struct priv priv = {0};

    if(start%PAGE_SIZE)
        start = (start/PAGE_SIZE)*PAGE_SIZE;

    if(end%PAGE_SIZE)
        end = ((end/PAGE_SIZE)+1)*PAGE_SIZE;

    
    path = kasprintf(GFP_KERNEL, "cp_%lu", cp_count);
    if(!path)
        return -ENOMEM;

    priv.c = cp_count;
    priv.file = filp_open(path, O_RDWR|O_CREAT, 0666);
    if(IS_ERR(priv.file))
        return -ENOMEM;

    inc_cp_walk = (struct mm_walk){
		.pte_entry = do_inc_cp_range,
		.mm = current->mm,
		.private = &priv,
	};

    down_read(&current->mm->mmap_sem);

    mmu_notifier_invalidate_range_start(current->mm, start, end);
    walk_page_range(start, end, &inc_cp_walk);
    mmu_notifier_invalidate_range_end(current->mm, start, end);

    flush_tlb_mm(current->mm);
    
    up_read(&current->mm->mmap_sem);
    
    kfree(path);
    filp_close(priv.file, NULL);

    return 0;
    
}
