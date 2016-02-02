/* Return a valid inode for a new file */
int inode_next(void)
{
    static int inode_seq=2 ;
    inode_seq++ ;
    return inode_seq ;
}

