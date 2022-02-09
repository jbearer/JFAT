/**
 * \file jfat.c
 * \author Jeb Bearer
 *
 * A user-space implementation of a FAT-like file system.
 */

#define FUSE_USE_VERSION 26

#include <arpa/inet.h>
#include <fuse.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>

static bool little_endian;
static const char *dev_path;

#define JFAT_UNIMPLEMENTED return -ENOSYS;

// Process exit codes
#define ERR_USAGE               1
#define ERR_MOUNT_FAILED        2
#define ERR_ASSERTION_FAILED    3

// Logging
typedef enum
{
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_ERROR = 3
} log_level_t;

static log_level_t log_level = LOG_LEVEL_INFO;

#define LOG_AT_LEVEL(l, fmt, ...) \
    { if (l >= log_level) fprintf(stderr, "%c: " fmt "\n", log_level_prefix(l), ##__VA_ARGS__); }

#define DEBUG(fmt, ...) LOG_AT_LEVEL(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) LOG_AT_LEVEL(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define WARN(fmt, ...) LOG_AT_LEVEL(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...) LOG_AT_LEVEL(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define ASSERT(cond) \
if (!(cond)) { \
    ERROR("%s:%d: assertion failed: %s", __FILE__, __LINE__, #cond); \
    exit(ERR_ASSERTION_FAILED); \
}

static char log_level_prefix(log_level_t level)
{
    switch (level) {
    case LOG_LEVEL_DEBUG:
        return 'D';
    case LOG_LEVEL_INFO:
        return 'I';
    case LOG_LEVEL_WARN:
        return 'W';
    case LOG_LEVEL_ERROR:
        return 'E';
    default:
        ERROR("invalid log level %d", (int)level);
        exit(ERR_ASSERTION_FAILED);
    }
}

#define MB  1048576
#define NSEC_PER_SEC 1000000000

uint64_t now()
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        WARN("cannot get time, timestamps may be inaccurate (%s)", strerror(errno));
        return 0;
    }

    return ts.tv_sec*NSEC_PER_SEC + ts.tv_nsec;
}

static uint16_t timespec_to_ns(struct timespec ts)
{
    return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

static struct timespec ns_to_timespec(uint64_t ns)
{
    return (struct timespec) {
        .tv_sec  = ns / NSEC_PER_SEC,
        .tv_nsec = ns % NSEC_PER_SEC
    };
}

typedef unsigned long hash_t;

// djb2, see http://www.cse.yorku.ca/~oz/hash.html
static hash_t path_hash(const char *str, size_t len)
{
    hash_t hash = 5381;

    size_t i;
    for (i = 0; i < len; ++i) {
        hash = ((hash << 5) + hash) + str[i]; // hash * 33 + str[i]
    }

    return hash;
}

#define MIN(x, y) ((x) < (y) ? (x) : (y))

/**
 * \defgroup fs_params File System Parameters
 *
 * @{
 */

/**
 * \defgroup fs_params_no_config Non-Configurable Parameters
 *
 * @{
 */

/**
 * \brief The size of the super block in bytes, including padding.
 */
#define SUPER_BLOCK_SIZE 512

/**
 * \brief Magic number identifying JFAT file systems.
 */
#define JFAT_MAGIC_NUMBER 0xDEADBEEF

/**
 * \brief The size of the in-memory LRU block cache, in blocks. Note that the actual size (in bytes)
 *        will be a function of this parameter and the file system block size, which is
 *        configurable.
 */
#define JFAT_MAX_OPEN_BLOCKS 16

/**
 * \brief JFAT will keep recently opened file instances in memory even if the file has been closed
 *        by all users. This is an optimization for temporal locality. However, JFAT will not do
 *        this if it would lead to more than `JFAT_OPEN_FILE_CACHE_THRESHOLD` files being open at
 *        once.
 */
#define JFAT_OPEN_FILE_CACHE_THRESHOLD 16

/// @}
// end fs_params_no_config

/**
 * \defgroup fs_params_config Configurable Parameters
 *
 * These parameters are format-time configurable in theory, in that file system software can
 * determine them by reading the super block of an existing file system. Currently, there is no
 * interface for configuring, and every JFAT file system formatted with this software uses the
 * default values.
 *
 * @{
 */

/**
 * \brief The total size of the volume in bytes.
 */
#define DEFAULT_FILE_SYSTEM_SIZE (10*MB)

/**
 * \brief The I/O block size in bytes.
 */
#define DEFAULT_BLOCK_SIZE       4096

/**
 * \brief The number of blocks allocated to the FAT.
 */
#define DEFAULT_FAT_BLOCKS       256

/**
 * \brief The number of blocks allocated for user data.
 */
#define DEFAULT_DATA_BLOCKS \
    (DEFAULT_FILE_SYSTEM_SIZE/DEFAULT_BLOCK_SIZE - DEFAULT_FAT_BLOCKS - 1)

/// @}
// end fs_params_config

/// @}
// end fs_params

/**
 * \defgroup on_disk_data_structures On-Disk Layout
 *
 * The on-disk layout of the JFAT file system is divided into the following high-level sections,
 * which are all contiguous on disk:
 *
 * Size                         | Section
 * -------------------------------------------------
 * 512                          | Super block
 * `block_size` - 512           | Padding
 * `block_size` * `fat_blocks`  | FAT
 * Remaining Space              | Data blocks
 *
 * Each data structure is described in detail below. In all data structures, multi-byte numeric
 * fields are represented on disk in little-endian byte order. The JFAT file system driver provides
 * serialization routines to convert between the on-disk endianness and the host endianness. The
 * capabilities of the serialization routines to accomodate future changes is limited, as all
 * serialization and deserialization is in-place, which means the size of the in-memory layout must
 * be the same as the size of the on-disk layout. This does not, for example, account for
 * differences in word size or padding. However, the strict use of fixed-width integer types for all
 * on-disk fields should mitigate this problem.
 *
 * @{
 */

/**
 * \defgroup super_block Super Block
 *
 * @{
 */

/**
 * \struct jfat_super_block
 * A data structure containing file system parameters.
 */
typedef struct jfat_super_block jfat_super_block;

/**
 * \union jfat_super_block_padded
 * Padding to make the super block exactly 512 bytes.
 */
typedef union jfat_super_block_padded jfat_super_block_padded;

/**
 * \defgroup super_block_serialization Super Block Serialization
 *
 * @{
 */

static void jfat_serialize_super_block(jfat_super_block_padded *psuper);
static void jfat_deserialize_super_block(jfat_super_block_padded *psuper);

/// @}
// end super_block_serialization

/// @}
// end super_block

/**
 * \defgroup block_addresses File Allocation Table
 *
 * The FAT is a linear array of block addresses, indexed by block address. These addresses refer
 * only to data blocks, so the entry 0 in the FAT corresponds to the first data block, which is
 * offset by `1 + fat_blocks` into the file system.
 *
 * The value associated with each address in the file system is the address of the block after the
 * index in whatever file contains the index block. If a block is the last block in a file, its
 * value is `JFAT_EOF`.
 *
 * There is a single pseudo-file containing all free blocks in the file system. No directory links
 * to the free file, but the address of the first block in the free list is stored in the super
 * block.
 *
 *@{
 */

/**
 * \brief An unsigned integer type large enough to hold the highest possible block address, plus
 *        two.
 */
typedef uint32_t blockaddr_t;

/**
 * \brief A reserved block address used in the FAT to indicate end-of-file
 */
static const blockaddr_t JFAT_EOF                 = (blockaddr_t)-1;

/**
 * \brief A reserved block address used in the FAT to indicate that a file has been unlinked and its
 *        data blocks should be freed when the last process using the file closes it.
 */
static const blockaddr_t JFAT_MARKED_FOR_DELETION = (blockaddr_t)-2;

/**
 * \brief Serialize a FAT (i.e. an array of `blockaddr_t`).
 *
 * \param[in,out]   fat     The table to serialize. Serialization is done in-place.
 * \param[in]       count   The number of blocks in the table.
 */
static void jfat_serialize_fat(blockaddr_t *fat, size_t count);

/**
 * \brief Inverse of `jfat_serialize_fat()`.
 */
static void jfat_deserialize_fat(blockaddr_t *fat, size_t count);

/// @}
//  end block_addresses

/**
 * \defgroup dirents Directories
 *
 * A directory is a file whose contents comprise a linked list of variable sized directory entries.
 * Each entry contains metadata about a file, the name of the file, the location of its data, and
 * the offset to find the next directory entry.
 *
 * Unlike regular files, the size of a directory is always a multiple of the block size. Extra space
 * at the end of the last block is absorbed into the last entry in the directory; this space will be
 * split apart and allocated to new entries as they are added.
 *
 * @{
 */

/**
 * \struct jfat_dirent
 *
 * An entry in a directory containing metadata about a child of the directory.
 *
 * Unlike good file systems, where directory entries map names to _pointers_ to metadata, JFAT
 * directory entries contain all of a file's metadata directly. (For this reason, JFAT does not
 * support hard links.)
 *
 * Otherwise, JFAT directory entries resemble those of the ext2 file system. They support (somewhat)
 * arbitrary name lengths. Each directory entry is a variably sized structure which contains it's
 * own length and the length of the name. The name consists of the first bytes after the rest of the
 * metadata. When a directory entry is deleted, it is simply absorbed into the previous entry by
 * increasing that entry's size.
 *
 * Directory entries cannot span multiple blocks, so the name size is limited to the size of a block
 * less the size of the rest of the file's metadata. This will typically be far longer than
 * supported by the operating system.
 */
typedef struct jfat_dirent jfat_dirent;

/**
 * \brief Assign unique identifiers to files, similar to inode numbers.
 *
 * \param[in]   super   The super block of the filesystem containing the entry.
 * \param[in]   block   The block containing the directory entry to identify.
 * \param[in]   offset  The byte offset from the start of `block` to the start of the entry.
 *
 * \details `jfat_dirent_id()` assigns a unique, stable identifier to each `jfat_dirent`-sized chunk
 *         of each data block in the file system, regardless of whether that block and chunk
 *         currently contains a directory entry.
 */
static uint64_t jfat_dirent_id(const jfat_super_block *super, blockaddr_t block, off_t offset);

/**
 * \defgroup timestamps Timestamps
 *
 * These functions can be used to convert nanosecond timestamps to POSIX timespec structures.
 *
 * @{
 */

static struct timespec jfat_access_time(const jfat_dirent *de);
static struct timespec jfat_modify_time(const jfat_dirent *de);
static struct timespec jfat_change_time(const jfat_dirent *de);

/// @}
// end timestamps

/**
 * \defgroup permissions Permissions
 *
 * These functions determine if the process acting on behalf of the specified user and group has
 * various access permissions to a file, based on the mode of the file.
 *
 * @{
 */

static bool jfat_can_read(const jfat_dirent *de, uid_t uid, gid_t gid);
static bool jfat_can_write(const jfat_dirent *de, uid_t uid, gid_t gid);
static bool jfat_can_execute(const jfat_dirent *de, uid_t uid, gid_t gid);

/// @}
// end permissions

/**
 * \defgroup dirent_serialization Directory Entry Serialization
 *
 * @{
 */

static void jfat_serialize_dirent(jfat_dirent *ent);
static void jfat_deserialize_dirent(jfat_dirent *ent);

/// @}
// end dirent_serialization

/// @}
// end dirents

/// @}
// End on-disk data structures

/**
 * \defgroup in_memory_data_structures In-Memory Data Structures
 *
 * The following data structures are used by the JFAT driver software to represent transient file
 * system state in memory. They do not correspond directly to any on-disk data structures.
 *
 * @{
 */

/**
 * \defgroup context Global State
 *
 * @{
 */

/**
 * \struct jfat_context
 * Global state for a mounted file system.
 */
typedef struct jfat_context jfat_context;

/**
 * \brief Get the global state for the running file system.
 *
 * \details This function access FUSE's global state (via `fuse_get_context()`) and thus can only be
 *         called during handling of a FUSE request.
 */
static jfat_context *jfat_get_context();

/**
 * \brief Mark the super block dirty.
 *
 * \details Subsequent calls to `jfat_flush_super()` or `jfat_fs_sync()` will write the super block
 *         to disk.
 */
static void jfat_touch_super(jfat_context *cxt);

/**
 * \brief Get the value associated with the given block in the FAT.
 */
static blockaddr_t jfat_get_fat(jfat_context *cxt, blockaddr_t block);

/**
 * \brief Set the value associated with the given block in the FAT.
 *
 * \param[in,out]   cxt     File system state.
 * \param[in]       key     The index in the FAT to update.
 * \param[in]       value   The new value to associate with `key`.
 *
 * \return 0 on success, of a negative error code if one occurred.
 */
static int jfat_set_fat(jfat_context *cxt, blockaddr_t key, blockaddr_t value);

/// @}
// end context

/**
 * \defgroup open_files Open Files
 *
 * @{
 */

/**
 * \struct jfat_open_file_key
 *
 * Structure containing identifying information for a file.
 */
typedef struct jfat_open_file_key jfat_open_file_key;

/**
 * \struct jfat_open_file
 *
 * A representation of an open file.
 *
 * All users editing or reading a file at any given time refer to it via a pointer to the same open
 * file instance. This ensures that updates to the files metadata are all written to the same in-
 * memory structure, so that when the data is flushed to disk all of the udpates are accounted for.
 *
 * This design also allows us to implement POSIX delete-after-close semantics: if a file is deleted
 * (via `unlink` or `rmdir`) it is marked deleted, its name is removed from its parent directory,
 * and future processes are forbidden from opening the file. However, as long as some processes
 * still maintain an open instance, the files data will not be deallocated. This is made possible by
 * a reference count in the `jfat_open_file` structure. When the reference count goes to 0, the file
 * is finally deleted.
 */
typedef struct jfat_open_file jfat_open_file;

/**
 * \brief Stage an open file for writing to disk.
 *
 * \details Serializes the directory entry stored in `f` and prepares to write it to disk. This
 *         function _does not_ write changes to the data of the file -- metadata only. Nor does this
 *         function perform any I/O. The actual disk writes will be carried out when
 *         `jfat_fs_sync()` is called.
 */
static int jfat_touch_open_file(jfat_context *cxt, const jfat_open_file *f);

/**
 * \brief Initialize the open file cache of the given file system instance.
 */
static void jfat_init_open_files(jfat_context *cxt);

/**
 * \brief Destroy the open file cache of the given file system instance.
 *
 * \details All files _regardless of reference count_ are removed from the cache and flushed to disk
 *         if necessary. If any files are marked for deletion, their blocks are freed and the
 *         resulting changes are flushed to disk. Finally, the cache itself is destroyed.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_destroy_open_files(jfat_context *cxt);

/**
 * \brief Get a pointer to an open file instance, or open the file if its not currently open.
 *
 * \param[in]   cxt     In-memory context. The open_files field may be modified if the request file
 *                      is not currently open.
 * \param[in]   path    The path to the requested file.
 *
 * \return A pointer to the open file instance, or `NULL` if the path does not exist or an error
 *         occurred. If the return value is `NULL`, `errno` is set appropriately.
 */
static jfat_open_file *jfat_get_open_file(jfat_context *cxt, const char *path);

/**
 * \brief Same as `jfat_get_open_file()`, but `path` is treated not as a null-terminated string but
 *        as a string of the given length.
 */
static jfat_open_file *jfat_get_open_file_n(jfat_context *cxt, const char *path, size_t path_len);

/**
 * \brief Get the size of the last block in a file.
 *
 * \return There are three possibilities:
 *          * The file is empty, in which case the result is 0.
 *          * The size of the file is a multiple of the block size, in which case the result is the
 *            block size.
 *          * The size of the file is not a multiple of the block size, in which case the result is
 *            the size of the partial last block (that is, the size of the file modulo the block
 *            size).
 */
static size_t jfat_last_block_size(const jfat_context *cxt, const jfat_open_file *f);

/**
 * \defgroup open_files_navigation Navigation
 *
 * @{
 */

/**
 * \struct jfat_file_traversal_state
 *
 * Structure used by `jfat_traverse_file()` to maintain state between calls.
 */
typedef struct jfat_file_traversal_state jfat_file_traversal_state;

/**
 * \brief Value of `jfat_file_traversal_state` that indicates the start of a new traversal.
 */
#define JFAT_FILE_TRAVERSAL_INIT \
    ((jfat_file_traversal_state) { \
        .init = true \
    })

/**
 * \brief Iterate over the blocks in a file.
 *
 * \param[in]       cxt     In-memory context.
 * \param[in]       f       An open instance of the file to be traversed.
 * \param[in,out]   state   Memory used by jfat_traverse_file() to save state between calls.
 * \param[out]      block   The address of the next block in the file being traversed.
 *
 * \details The first time jfat_traverse_file() is called, `state` should point to a variable with
 *         the value `JFAT_FILE_TRAVERSAL_INIT`. For each subsequent call with the same state
 *         pointer, the address of the next block in the file will be stored in `block`.
 *
 *         In addition to private informtaion used by `jfat_traverse_file()`, the state
 *         structure contains the following public fields:
 *
 *         * `block_size`: the number valid bytes in the block. For all blocks except a possible
 *           partial last block, this will be the block size of the file system.
 *         * `offset`: the logical byte offset into the file of the start of the current block.
 *
 * \return A positive integer if the memory pointed at by `block` is valid. If there are no more
 *         blocks to be read, 0 is returned and `block` is invalid. Similarly, if an error occurs, a
 *         negative error code is returned and `block` is invalid. Once `jfat_traverse_file()`
 *         returns a non- positive integer, subsequent calls with the same state pointer are
 *         undefined.
 */
static int jfat_traverse_file(jfat_context *cxt, const jfat_open_file *f,
                              jfat_file_traversal_state *state, blockaddr_t *block);

/**
 * \struct jfat_directory_traversal_state
 *
 * Structure used by `jfat_traverse_directory()` to maintain state between calls.
 */
typedef struct jfat_directory_traversal_state jfat_directory_traversal_state;

/**
 * \brief Value of `jfat_directory_traversal_state` that indicates the start of a new traversal.
 */
#define JFAT_DIRECTORY_TRAVERSAL_INIT \
    ((jfat_directory_traversal_state) { \
        .init = true \
    })

/**
 * \brief Iterate over the entries in a directory.
 *
 * \param[in]       cxt     In-memory context.
 * \param[in]       dir     An open instance of the desired directory.
 * \param[in,out]   state   Memory used by `jfat_traverse_directory()` to save state between calls.
 * \param[out]      child   A pointer to the next child of the directory being traversed.
 *
 * \details The first time `jfat_traverse_directory()` is called, state should point to a variable
 *         with the value `JFAT_DIRECTORY_TRAVERSAL_INIT`. For each subsequent call with the same
 *         state pointer, a pointer to the next entry in the directory will be stored in `child`.
 *
 *         In addition to private informtaion used by `jfat_traverse_directory()`, the state
 *         structure contains the following public fields:
 *
 *         * `block`: the address of the data block containing `child`
 *         * `offset`: the offset into `block` to the start of `child`
 *         * `last_block`: the address of the block containing the entry before `child`, or
 *           `JFAT_EOF` if child is the first entry.
 *         * `last_offset`: the offset into `last_block` of the previous entry. Valid only if
 *           `last_offset != JFAT_EOF`.
 *
 * \return A positive integer if the memory pointed at by `child` is valid. If there are no more
 *         blocks to be read, 0 is returned and `child` is invalid. Similarly, if an error occurs, a
 *         negative error code is returned and `child` is invalid. Once `jfat_traverse_directory()`
 *         returns a non-positive integer, subsequent calls with the same state pointer are
 *         undefined.
 */
static int jfat_traverse_directory(jfat_context *cxt, const jfat_open_file *dir,
                                   jfat_directory_traversal_state *state, jfat_dirent *child);

/**
 * Type of a function which `jfat_nftw()` applies to each node in a file tree.
 *
 * The first argument is the instance of the file system being traversed.
 *
 * The second argument is an open instance of the current file. The instance will be closed
 * automatically by `jfat_nftw()` after the callback returns, except for the root instance, which
 * was opened by the caller of `jfat_nftw()` and likewise should be closed by the caller.
 *
 * The third argument is a pointer to arbitrary data which the user can pass through `jfat_nftw()`
 * to the callback.
 */
typedef int (*jfat_nftw_callback)(jfat_context *, jfat_open_file *, void *);

/**
 * \brief Walk a file tree.
 *
 * \param[in]   cxt         In-memory context.
 * \param[in]   root        File or directory at the root of the tree to walk.
 * \param[in]   callback    Function to apply to each file in the tree.
 * \param[in]   arg         Data to be passed as the second argument to `callback`.
 *
 * \details Traversal of the subtree rooted at `root` proceeds in a depth-first manner. `callback`
 *         is applied to each file or directory in the tree, in an order that guarantees it is
 *         applied to each file before it is applied to that file's parent. At each file, `callback`
 *         is passed an open instance of the file, _which will be closed automatically_ when
 *         `callback` returns.
 *
 * \return If the traversal successfully exhausts the file tree, 0 is returned. If an internal error
 *         is encountered, the traversal is stopped immediately and a negative error code is
 *         returned. If `callback` returns a nonzero value, the traversal is stopped immediately and
 *         that value is returned.
 */
static int jfat_nftw(
    jfat_context *cxt, jfat_open_file *root, jfat_nftw_callback callback, void *arg);

/// @}
// end open_files_navigation

/**
 * \brief Release a reference to an open file.
 *
 * \details The file's reference count is decremented. If the reference count becomes 0, the file is
 *         closed and its in-core resources are deallocated. If the file is marked for deletion, its
 *         data blocks on disk are freed.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_release_open_file(jfat_context *cxt, jfat_open_file *f);

/// @}
// end open_files

/**
 * \defgroup open_blocks Open Blocks
 *
 * The following data structures are used to represent blocks that currently reside in memory.
 * Together with the accompanying functions, they implement a least-recently-used write-back cache
 * for disk blocks. In addition to potentially improving latency, this greatly simplifies I/O for
 * clients of the cache, as they don't need to worry about allocating block-sized chunks of memory
 * and performing I/O in multiples of the block size. The cache provides an interface similar to
 * POSIX I/O, where clients can read at any offset within a block.
 *
 * @{
 */

/**
 * \struct jfat_open_block
 *
 * Metadata about a cached block.
 *
 * This structure acts as a header for a cached data block. These are always allocated in chunks of
 * size `sizeof(jfat_open_block) + block_size`, and the data for the block is stored immediately
 * after the header.
 */
typedef struct jfat_open_block jfat_open_block;

/**
 * \brief Initialize the open block cache of the given file system instance.
 */
static void jfat_init_open_blocks(jfat_context *cxt);

/**
 * \brief Destroy the open block cache of the given file system instance.
 *
 * \details All blocks are removed from the cache, and dirty ones are flushed to disk. The cache
 *         itself is destroyed.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_destroy_open_blocks(jfat_context *cxt);

/**
 * \brief Read a portion of a data block.
 *
 * \param[in]   cxt     File system state.
 * \param[in]   block   The address of the block to read from.
 * \param[in]   offset  The offset within `block` at which to start reading.
 * \param[in]   size    The amount of data (in bytes) to read. `offset + size` must not exceed the
 *                      file system block size.
 * \param[out]  buf     A contiguous writable buffer of at leasat `size` bytes, where the requested
 *                      data will be stored.
 *
 * \return      0 on success, or a negative error code if one ocurred.
 */
static int jfat_bread(jfat_context *cxt, blockaddr_t block, off_t offset, size_t size, void *buf);

/**
 * \brief Write a portion of a data block.
 *
 * \param[in]   cxt     File system state.
 * \param[in]   block   The address of the block to write to.
 * \param[in]   offset  The offset within `block` at which to start writing.
 * \param[in]   size    The amount of data (in bytes) to write. `offset + size` must not exceed the
 *                      file system block size.
 * \param[in]   buf     A contiguous readble buffer of at least `size` bytes, which will be written
 *                      to the requested block.
 *
 * \details `jfat_bwrite()` writes the data into the block cache and marks the written block dirty,
 *         but the data will _not_ be persisted to disk until `jfat_bflush_all()` is called.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_bwrite(
    jfat_context *cxt, blockaddr_t block, off_t offset, size_t size, const void *buf);

/**
 * \brief Flush all dirty blocks to disk.
 *
 * \details The state of the cache is not changed.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_bflush_all(jfat_context *cxt);

/// @}
// end open_blocks

/**
 * \defgroup lru A Generic LRU Cache
 *
 * This module implements a least recently used associative cache that provides the following
 * operations efficiently:
 *
 * * Access to a cached element (more efficient for more recently accessed elements)
 * * Traversal in approximately least to most recently used order
 * * Retrieval of new elements (as efficient as the underlying medium will allow)
 * * Eviction of a specified element
 *
 * @{
 */

/**
 * \defgroup lru_types Types
 *
 * @{
 */

/**
 * \struct jfat_lru
 *
 * Opaque data type containing private LRU state.
 */
typedef struct jfat_lru jfat_lru;

/**
 * \struct jfat_lru_entry
 *
 * Opaque data type representing an element in the cache.
 */
typedef struct jfat_lru_entry jfat_lru_entry;

/**
 * \struct jfat_lru_iterator
 *
 * Opaque data type which refers to a specific element in the cache. Can be incremented to traverse
 * the collection (with `jfat_lru_next()`) and dereferenced to get the underlying element (with
 * `jfat_lru_get()`).
 */
typedef jfat_lru_entry *jfat_lru_iterator;

/**
 * Type of comparison function used by the LRU to implement searches. Either argument may be an
 * element in the container or a key currently being searched for (as in `jfat_lru_find()` and
 * `jfat_lru_retrieve()`). Therefore, if the key type is different from the value type, a pointer
 * to the value type must be convertible to a pointer to the key type or vice versa. This can be
 * implemented, for example, by having the key type be the first element of a structure which is the
 * value type.
 */
typedef int (*jfat_lru_compare_t)(void *o1, void *o2);

/**
 * Type of a function used to resolve cache misses. The first argument is a key which was passed to
 * `jfat_lru_retrieve()` but was not found in the container. The second argument is an arbitrary
 * pointer that can be specified at container construction time.
 *
 * This function should use the key to retrieve the corresponding element from the underlying
 * storage and return a pointer to that element. The function may return `NULL` to indicate that an
 * error occurred or the object was unable to be located.
 *
 * If the return value `r` is not `NULL`, then it should satisfy `compare(key, r) == 0`.
 */
typedef void *(*jfat_lru_filler_t)(void *key, void *arg);

/// @}
// end lru_types

/**
 * \defgroup lru_lifecycle Lifecycle
 *
 * @{
 */

/**
 * \brief Initialize an empty LRU cache.
 *
 * \param[out]  c           The cache to initialize.
 * \param[in]   compare     The comparison function.
 * \param[in]   filler      The filler function.
 * \param[in]   filler_arg  Arbitrary data which will be passed to the filler function on every
 *                          cache miss.
 */
static void jfat_lru_init(
    jfat_lru *c, jfat_lru_compare_t compare, jfat_lru_filler_t filler, void *filler_arg);

/**
 * \brief Empty and destroy a cache.
 *
 * \details This function empties the cache as if by calling `jfat_lru_erase()` on every element,
 *         and then release any resources held by the cache itself.
 */
static void jfat_lru_destroy(jfat_lru *m);

/// @}
// end lru_lifecycle

/**
 * \defgroup lru_iterators Iterators
 *
 * @{
 */

/**
 * \brief An iterator pointing to the least recently used element.
 *
 * \details This will be equal to `jfat_lru_end()` if the cache is empty.
 */
static jfat_lru_iterator jfat_lru_begin(const jfat_lru *m);

/**
 * \brief An iterator pointing one past the end of the container, as if obtained by incrementing
 *        with `jfat_lru_next()` an iterator pointing to the last (most recently used) element.
 */
static jfat_lru_iterator jfat_lru_end(const jfat_lru *m);

/**
 * \brief Obtain an iterator pointing to the element after the given iterator.
 */
static jfat_lru_iterator jfat_lru_next(jfat_lru_iterator it);

/**
 * \brief Access the element referred to by an iterator.
 *
 * \return A pointer which was early returned by the filler function.
 */
static void *jfat_lru_get(jfat_lru_iterator it);

/// @}
// end lru_iterators

/**
 * \defgroup lru_inspectors Inspectors
 *
 * @{
 */

/**
 * \brief Get the number of elements in an LRU.
 */
static size_t jfat_lru_size(const jfat_lru *c);

/**
 * \brief Search for an element in an LRU.
 *
 * \param[in]   c       The cache to search.
 * \param[in]   key     Key for the desired object.
 *
 * \details This function is similar to `jfat_lru_retrieve()` in that it searches for an object `o`
 *         in the cache such that `compare(key, o) == 0`. It only differs in that if such an object
 *         is not found, it is not inserted with `filler`; instead, the function simply returns a
 *         value indicating that the object was not found.
 *
 *         If `jfat_lru_find()` is successful, the found object is marked most recently used.
 *
 * \return An iterator pointing to the desired object if it is found, otherwise `jfat_lru_end(m)`.
 */
static jfat_lru_iterator jfat_lru_find(jfat_lru *c, void *key);

/// @}
// end lru_inspectors

/**
 * \defgroup lru_modifiers Modifiers
 *
 * @{
 */

/**
 * \brief Retrieve an object from the cache.
 *
 * \param[in]       c   The cache to retrieve from.
 * \param[in,out]   key Key for the object to retrieve.
 *
 * \details  This function first searches the cache for an object matching the given key (that is,
 *          an object `o` such that `compare(key, o) == 0`, where `compare` is the comparison
 *          function that was used to initialize the cache). If such an object is found, then the
 *          function marks the object as being most recently used and returns an iterator to the
 *          found object. If the object is not found, then the cache calls `filler(key, filler_arg)`
 *          to create a new object, which is then inserted into the cache and marked most recently
 *          used. An iterator to the newly inserted object is then returned.
 *
 * \return  If the requested object was found or inserted successfully, the return value is an
 *          iterator to the inserted object. If an internal error occurs, the return value is equal
 *          to `jfat_lru_end(c)`, and `errno` is set appropriately. If `filler` returns `NULL`, the
 *          return value is `jfat_lru_end(c)`, but `errno` is not changed (except possibly by
 *          `filler`).
 *
 *          If `jfat_lru_retrieve()` returns `NULL`, the following conditions are guaranteed to
 *          hold:
 *              * The state of the cache has not changed
 *              * All internal resources allocated in preparation to fulfill the retrieve request
 *                are freed.
 *              * The reason for the failure was that `filler` failed, or `filler` has not been
 *                called.
 */
static jfat_lru_iterator jfat_lru_retrieve(jfat_lru *c, void *key);

/**
 * \brief Remove an object from the cache.
 *
 * \param[in]   c   The cache from which to erase.
 * \param[in]   it  An iterator pointing to the object to remove.
 *
 * \details      `jfat_lru_erase()` frees any per-element memory that was used to store the erased
 *              element. It does not, however, make any attempt to destroy resources allocated by
 *              the filler function that retrieved the element. This is the job of the higher-level
 *              policy.
 *
 * \return      An iterator to the element just after the one removed, or `jfat_lru_end(c)` if there
 *              is no such element.
 */
static jfat_lru_iterator jfat_lru_erase(jfat_lru *c, jfat_lru_iterator it);

/// @}
// end lru_modifiers

/// @}
// end lru

/**
 * \defgroup block_set An Ordered Set of Block Addresses
 *
 * This module implements an ordered set of block addresses which supports the following operations
 * efficiently:
 *
 *  * Inserting a new block address.
 *  * Finding a block address in the set.
 *  * Erasing a block address from the set.
 *  * Observing the size of the set.
 *  * Iterating over the members of the set in order of increasing address.
 *
 * @{
 */

/**
 * \defgroup block_set_types Types
 *
 * @{
 */

/**
 * \struct jfat_block_set
 *
 * Opaque data type containing private state used by the set.
 */
typedef struct jfat_block_set jfat_block_set;

/**
 * \struct jfat_block_set_entry
 *
 * Opaque data type representing an element in the set.
 */
typedef struct jfat_block_set_entry jfat_block_set_entry;

/**
 * \struct jfat_lru_iterator
 *
 * Opaque data type which refers to a specific element in the set. Can be incremented to traverse
 * the collection (with `jfat_block_set_next()`) and dereferenced to get the underlying element
 * (with `jfat_block_set_get()`).
 */
typedef jfat_block_set_entry *jfat_block_set_iterator;

/// @}
// end block_set_types

/**
 * \defgroup block_set_lifecycle Lifecycle
 *
 * @{
 */

/**
 * \brief Initialize an empty block set.
 *
 * \detail Must be called before any other uses of the set.
 */
static void jfat_block_set_init(jfat_block_set *set);

/**
 * \brief Empty and destroy a set.
 *
 * \detail Each block is removed from the set as if by `jfat_block_set_erase()`, and then resources
 *         owned by the set itself are released. Subsequent uses of the set are undefined.
 */
static void jfat_block_set_destroy(jfat_block_set *set);

/// @}
// end block_set_lifecycle

/**
 * \defgroup block_set_iterators Iterators
 *
 * @{
 */

/**
 * \brief An iterator pointing to the block in the set with the smallest address.
 *
 * \detail If the set is empty, the return value is equal to `jfat_block_set_end(set)`.
 */
static jfat_block_set_iterator jfat_block_set_begin(const jfat_block_set *set);

/**
 * \brief An iterator pointing one element past the end of the set.
 *
 * \detail This iterator acts as if it were obtained by calling `jfat_block_set_next()` on an
 *         iterator pointing to the element of the set with the highest address.
 */
static jfat_block_set_iterator jfat_block_set_end(const jfat_block_set *set);

/**
 * \brief Access the block address referred to by an iterator.
 */
static blockaddr_t jfat_block_set_get(jfat_block_set_iterator it);

/// @}
// end block_set_iterators

/**
 * \defgroup block_set_inspectors Inspectors
 *
 * @{
 */

/**
 * \brief Get the number of elements in a block set.
 */
static size_t jfat_block_set_size(const jfat_block_set *set);

/**
 * \brief Search for an element in a block set.
 *
 * \param[in]   set     The set to search.
 * \param[in]   block   Address of the desired block.
 *
 * \return An iterator pointing to the desired object if it is found, otherwise
 *         `jfat_block_set_end(set)`.
 */
static jfat_block_set_iterator jfat_block_set_find(const jfat_block_set *set, blockaddr_t block);

/// @}
// end block_set_inspectors

/**
 * \defgroup block_set_modifiers Modifiers
 *
 * @{
 */

/**
 * \brief Add an elment to the set.
 *
 * \param[in,out]   set     The block set into which to insert.
 * \param[in]       block   The block address to insert.
 *
 * \detail If `block` is not currently a member of the set, it is added and the size of the set is
 *         increased by one. Otherwise, the set is unchanged.
 *
 * \return 0 if the element was successfully inserted, or a negative error code if one occurred.
 */
static int jfat_block_set_insert(jfat_block_set *set, blockaddr_t block);

/**
 * \brief Remove an element from the set.
 *
 * \param[in,out]   set     The set from which to erase.
 * \param[in]       it      An iterator referring to the element to erase. Must refer to a valid
 *                          element of the set, otherwise the behaviour is undefined.
 *
 * \detail The specified element is removed from the set and the size of the set is decreased by
 *         one.
 *
 * \return An iterator to the element immediately after `it`, or `jfat_block_set_end(set)` if `it`
 *         referred to the last element in the set.
 */
static jfat_block_set_iterator jfat_block_set_erase(
    jfat_block_set *set, jfat_block_set_iterator it);

/// @}
// end block_set_modifiers

/// @}
// end block_set

/// @}
// end in_memory_data_structures

/**
 * \defgroup io I/O
 *
 * @{
 */

/**
 * \defgroup low_level_io Low-Level I/O
 *
 * @{
 */

/**
 * \brief Write a section of data to disk.
 *
 * \param[in]   fd      File descriptor to write to.
 * \param[in]   buf     A contiguous readable buffer of at least `count` bytes, which will be
 *                      written to the disk.
 * \param[in]   count   The amount of bytes to write. Should be a multiple of the I/O block size.
 * \param[in]   offset  The offset into the disk. Should be a multiple of the I/O block size.
 *
 * \details Unlike `pwrite`, `jfat_pwrite()` blocks until exactly the requested amount of data has
 *         been written.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_pwrite(int fd, const void *buf, size_t count, off_t offset);

/**
 * \brief Write a series of contiguous blocks to disk.
 *
 * \param[in]   fd      The file descriptor to write to.
 * \param[in]   super   The super block describing file system I/O paramters.
 * \param[in]   start   The address of the first block to write.
 * \param[in]   count   The number of blocks to write.
 * \param[in]   buf     A contiguous readable buffer containing at least `count` blocks.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_write_blocks(
    int fd, const jfat_super_block *super, blockaddr_t start, size_t count, const void *buf);

/**
 * \brief Write a single block to disk.
 *
 * \param[in]   fd      The file descriptor to write to.
 * \param[in]   super   The super block describing file system I/O paramters.
 * \param[in]   addr    The address of the block to write. Address is computed relative to the
 *                      beginning of the file system, so 0 corresponds to the super block.
 * \param[in]   buf     A contiguous readable buffer at least as large as the block size.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_write_block(
    int fd, const jfat_super_block *super, blockaddr_t addr, const void *block);

/**
 * \brief Write a single data block to disk.
 *
 * \param[in]   fd      The file descriptor to write to.
 * \param[in]   super   The super block describing file system I/O paramters.
 * \param[in]   addr    The address of the block to write. Address is computed relative to the
 *                      beginning of the data segment, so 0 corresponds to the first block after the
 *                      FAT.
 * \param[in]   buf     A contiguous readable buffer at least as large as the block size.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_write_data_block(
    int fd, const jfat_super_block *super, blockaddr_t addr, const void *block);

/**
 * \brief Read a section of data from disk.
 *
 * \param[in]   fd      File descriptor to read from.
 * \param[in]   buf     A contiguous writable buffer of at least `count` bytes, where the data will
 *                      be stored.
 * \param[in]   count   The amount of bytes to read. Should be a multiple of the I/O block size.
 * \param[in]   offset  The offset into the disk. Should be a multiple of the I/O block size.
 *
 * \details Unlike `pread`, `jfat_pread()` blocks until exactly the requested amount of data has
 *         been read.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_pread(int fd, void *buf, size_t count, off_t offset);

/**
 * \brief Read a series of contiguous blocks from disk.
 *
 * \param[in]   fd      The file descriptor to read from.
 * \param[in]   super   The super block describing file system I/O paramters.
 * \param[in]   start   The address of the first block to read.
 * \param[in]   count   The number of blocks to read.
 * \param[in]   buf     A contiguous writable buffer at least as large as `count` blocks.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_read_blocks(
    int fd, const jfat_super_block *super, blockaddr_t start, size_t count, void *buf);

/**
 * \brief Read a single block from disk.
 *
 * \param[in]   fd      The file descriptor to write to.
 * \param[in]   super   The super block describing file system I/O paramters.
 * \param[in]   addr    The address of the block to read. Address is computed relative to the
 *                      beginning of the file system, so 0 corresponds to the super block.
 * \param[in]   buf     A contiguous writable buffer at least as large as the block size.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_read_block(int fd, const jfat_super_block *super, blockaddr_t addr, void *block);

/**
 * \brief Read a single data block from disk.
 *
 * \param[in]   fd      The file descriptor to write to.
 * \param[in]   super   The super block describing file system I/O paramters.
 * \param[in]   addr    The address of the block to read. Address is computed relative to the
 *                      beginning of the data segment, so 0 corresponds to the first block after the
 *                      FAT.
 * \param[in]   buf     A contiguous writable buffer at least as large as the block size.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_read_data_block(
    int fd, const jfat_super_block *super, blockaddr_t addr, void *block);

/// @}
// end low_level_io

/**
 * \defgroup metadata_io Flushing Metadata
 *
 * @{
 */

/**
 * \brief Flush in-memory changes to the super block.
 *
 * \details If the super block stored in `cxt` is dirty, serialize it and write it to disk.
 *         Otherwise, do nothing.
 *
 * \return 0 on success, or a negative error code if one ocurred.
 */
static int jfat_flush_super_block(jfat_context *cxt);

/**
 * \brief Flush in-memory changes to the FAT.
 *
 * \details Serialize each dirty block in the FAT stored in `cxt` and write it to disk.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_flush_fat(jfat_context *cxt);

/**
 * \brief Synchronize all in-memory state with the disk.
 *
 * \details Flushes all dirty blocks including the super, the FAT, and data blocks to disk.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_fs_sync(jfat_context *cxt);

/// @}
// end metadata_io

/**
 * \defgroup file_io File I/O
 *
 * @{
 */

typedef enum
{
    TRANSFER_FROM,
    TRANSFER_TO
} transfer_type;

static int jfat_transfer_data(
    jfat_context *cxt, jfat_open_file *f, void *buf, size_t size, off_t offset, transfer_type type);

/// @}
// end file_io

/// @}
// end io

/**
 * \defgroup block_management Block Management
 *
 * @{
 */

/**
 * \brief Claim a block from the free list.
 *
 * \details The allocated block will be removed from the free list, at which point it can safely be
 *         used as a data block for a file. When the file no longer needs the block, it must be
 *         returned to the free list with `jfat_free_block()`.
 *
 * \return The address of the allocated block, of `JFAT_EOF` if an error occurred, in which case
 *         `errno` will be set appropriately.
 */
static blockaddr_t jfat_alloc_block(jfat_context *cxt);

/**
 * \brief Return a block to the free list.
 */
static void jfat_free_block(jfat_context *cxt, blockaddr_t block);

/// @}
// end block_management

/**
 * \defgroup fs_modifiers File System Modifiers
 *
 * @{
 */

/**
 * \brief Free all blocks after a given block in a file.
 *
 * \param[in]       cxt         Global state.
 * \param[in,out]   f           A pointer to the file containing `last_block`.
 * \param[in]       last_block  The block which will become the new end of file.
 *
 * \details  This function uses a stack (_the_ stack, in the current implementation) to free blocks
 *          starting from the current end-of-file and working backwards towards `last_block`. File
 *          system metadata including the FAT and the file size are consistent after each block is
 *          freed; thus, if an error ocurrs after freeing some but not all blocks, the file has been
 *          shortened by the amount of blocks successfully freed, and those blocks have been
 *          returned to the free list.
 *
 *          Updates to all data and metadata are staged and will be sent to disk when
 *         `jfat_fs_sync()` is called.
 *
 * \return  0 on success, or a negative error code if one occurred.
 */
static int jfat_free_blocks_after(jfat_context *cxt, jfat_open_file *f, blockaddr_t last_block);

/**
 * \brief Extend a file.
 *
 * \param[in]       cxt     Global state.
 * \param[in,out]   f       A pointer to the file to shrink. The open instance is modified with the
 *                          new size.
 * \param[in]       size    The new size of the file in bytes. Must be less than the current size.
 *
 * \details The end of the file is deleted, and blocks are freed as appropriate.
 *
 *         Updates to all data and metadata are staged and will be sent to disk when
 *         `jfat_fs_sync()` is called.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_shrink_file(jfat_context *cxt, jfat_open_file *f, size_t size);

/**
 * \brief Extend a file.
 *
 * \param[in]       cxt     Global state.
 * \param[in,out]   f       A pointer to the file to extend. The open instance is modified with the
 *                          new size.
 * \param[in]       size    The new size of the file in bytes. Must be greater than the current
 *                          size.
 *
 * \details The file is extended with zeros, and new blocks are allocated as needed.
 *
 *         Updates to all data and metadata are staged and will be sent to disk when
 *         `jfat_fs_sync()` is called.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_grow_file(jfat_context *cxt, jfat_open_file *f, size_t size);

/**
 * \brief Resize a file.
 *
 * \param[in]       cxt     Global state.
 * \param[in,out]   f       A pointer to the file to truncate. The open instance is modified with
 *                          the new size.
 * \param[in]       size    The new size of the file in bytes.
 *
 * \details This is a convenience function which dispatches to `jfat_shrink_file()` or
 *         `jfat_grow_file()` as appropriate.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_truncate_file(jfat_context *cxt, jfat_open_file *f, size_t size);

/**
 * \brief Create a new, empty file.
 *
 * \param[in]       cxt     Global state.
 * \param[in,out]   parent  A pointer to the directory which will contain the new file. The
 *                          directory is modified to reflect the changes.
 * \param[in]       name    The null-terminated name of the file to create.
 * \param[in]       mode    The mode of the new file.
 * \param[in]       uid     The user ID of the owner of the new file.
 * \param[in]       gid     The group ID of the owner of the new file.
 *
 * \details `jfat_new_file()` does not perform existence checks. The caller must ensure that a file
 *         with the given name does not already exist. Updates to all data and metadata are staged
 *         and will be sent to disk when `jfat_fs_sync()` is called.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_new_file(jfat_context *cxt, jfat_open_file *parent,
                         const char *name, mode_t mode, uid_t uid, gid_t gid);

/**
 * \brief Add a directory entry to a parent directory.
 *
 * \param[in]       cxt     Global state.
 * \param[in,out]   parent  A pointer to the directory which will contain the new file. The
 *                          directory is modified to reflect the changes.
 * \param[in]       child   The entry to add. `child` must point to a valid directory entry,
 *                          _including the name of the file_ in the memory at `child +
 *                          sizeof(jfat_dirent)`.
 *
 * \details `jfat_add_child()` does not perform existence checks. The caller must ensure that a file
 *         with the given name does not already exist. Updates to all data and metadata are staged
 *         and will be sent to disk when `jfat_fs_sync()` is called.
 *
 * \return 0 on success, or a negative error code if one occurred.
 */
static int jfat_add_child(
    jfat_context *cxt, jfat_open_file *parent, const jfat_dirent *child);

/// @}
// end fs_modifiers

/**
 * \defgroup management File System Management
 *
 * @{
 */

/**
 * \brief Format an empty JFAT file system with the default parameters.
 *
 * \param[in]   dev_fd  A file descriptor open to the backing storage device.
 *
 * \details The backing storage should already have been truncated to `DEFAULT_FILE_SYSTEM_SIZE`,
 *         and should be zeroed out. jfat_format() will write an appropriate super block to the
 *         backing file, initialize the FAT, and create the root directory. The FAT is initially a
 *         monotonic linked list of free blocks, except for the first block, which corresponds to
 *         the root directory. The root directory will be empty except for '.' and '..'.
 *
 * \return 0 on success, or a negative error code.
 */
static int jfat_format(int dev_fd);

/**
 * \brief Attempt to recover from an unclean shutdown.
 *
 * \details Errors that can be detected:
 *          * Files with too few blocks for their size.
 *          * Blocks which are contained in two files, or twice on the free list, or on the free
 *            list and in a file.
 *          * Discrepancies between the number of data blocks recorded in the super block and the
 *            number of data blocks observed.
 *
 *         Errors that can be corrected:
 *          * Orphaned blocks (they are placed on the free list).
 *          * Discrepancies between the number of files recorded in the super block and the number
 *            of files observed (the observed number is recorded in the super block).
 *          * Discrepancies between the number of free blocks recorded in the super block and the
 *            number of free blocks observed (the observed number is recorded in the super block).
 *
 * \return 0 if recovery was successful, or a negative error code if not.
 */
static int jfat_recover(jfat_context *cxt);

/**
 * \brief Write a human-readable representation of the file system state to a file.
 *
 * \param[in]   cxt     The file system to output.
 * \param[in]   out     The file to write to.
 *
 * \details Prints each file in the file system and the list of data blocks allocated to the file,
 *          as well as the free list pseudo-file.
 *
 * \return  0 on success, or a negative error code if one occurred.
 */
static int jfat_print_fs(jfat_context *cxt, FILE *out);

/// @}
// end management

////////////////////////////////////////////////////////////////////////////////////////////////////
// On-Disk Data Structures Types
////////////////////////////////////////////////////////////////////////////////////////////////////

struct jfat_dirent
{
    /// The size of the file in bytes.
    uint64_t        size;

    /**
     * \defgroup jfat_dirent_timestamps
     *
     * Timestamps, representing nanoseconds since the epoch. Good till Sunday July 21, 2554.
     *
     * @{
     */
    uint64_t        accessed;
    uint64_t        modified;
    uint64_t        changed;
    /// @}

    /// The address of the first data block in the files. For empty files, this is `JFAT_EOF`.
    blockaddr_t     data;

    /// The user ID of the owner of the file.
    uint32_t        uid;

    /// The group ID of the owner of the file.
    uint32_t        gid;

    /// The mode of the file, including type and permission information.
    uint32_t        mode;

    /// The size of the name (with no terminating null character).
    uint16_t        name_size;

    /// The size of the entire entry, including the metadata, the name, and free space after the name.
    uint16_t        ent_size;
};

struct jfat_super_block
{
    /**
     * \brief The number of blocks in the FAT.
     *
     * \details This field is set at format time and cannot be changed. The number of FAT blocks
     *         determines the maximum amount of data that can be stored in the file system, storage
     *         permitting. The relationship is
     *         `data_blocks = fat_blocks * block_size / sizeof(blockaddr_t)`.
     */
    uint32_t        fat_blocks;

    /**
     * \brief The number of data blocks in the file system.
     *
     * \details This field is set at format time and, in the current implementation, cannot be
     *         changed. However, it would be possible to allow extending the data segment after the
     *         file system has been created, as long as storage and the size of the FAT can
     *         accomodate.
     */
    uint32_t        data_blocks;

    /**
     * \brief The number of allocated files in the file system.
     *
     * \details This is a convenience field which speeds up operations such as `statfs`. It is
     *         updated in memory each time a file is created or deleted, and flushed to disk on
     *         file system shutdown. In the case of an unclean shutdown, it can be reconstructed
     *         by traversing the directory hierarchy.
     */
    uint32_t        num_files;

    /**
     * \brief The number of free data blocks in the file system.
     *
     * \details This is a convenience field which speeds up operations such as `statfs`. It is
     *         updated in memory each time a block is allocated or freed, and flushed to disk on
     *         file system shutdown. In the case of an unclean shutdown, it can be reconstructed
     *         by traversing the FAT.
     */
    uint32_t        free_data_blocks;

    /**
     * \brief Magic number identifying this as a JFAT file system.
     */
    uint32_t        magic_number;

    /**
     * \brief The size of file system blocks in bytes.
     *
     * \details This field is set at format time and cannot be changed.
     */
    uint16_t        block_size;

    /**
     * \brief The address of the first free block in the free block pseudo-file, or `JFAT_EOF` if
     *        there are no free blocks.
     */
    blockaddr_t     first_free_block;

    /**
     * \brief Metadata for the root directory.
     */
    jfat_dirent     root_dir;

    /**
     * \brief Flag indicating whether the file system shut down cleanly.
     *
     * \details This flag is inspected at mount time. If it is not set, a cleanup operation is
     *         performed that uses redundant information to reconstruct data that may have been lost
     *         or corrupted at shutdown. The last step in the mount process is to unset this flag on
     *         disk. It will be set again as the last step of a successful unmount.
     */
    bool            clean_shutdown;
};

union jfat_super_block_padded
{
    jfat_super_block    super;
    char                padding[SUPER_BLOCK_SIZE];
};

////////////////////////////////////////////////////////////////////////////////////////////////////
// In-Memory Data Structures Types
////////////////////////////////////////////////////////////////////////////////////////////////////

struct jfat_open_file_key
{
    /// The full, absolute path of the file.
    const char        *path;

    /// The length in bytes of `path`.
    size_t             len;

    /// Hash of the file path. Used to speed up lookups. Strings are only compared if the hashes are
    /// equal.
    hash_t             hash;
};

struct jfat_open_file
{
    jfat_open_file_key key;

    size_t             refcount;
    bool               marked_for_deletion;

    /// The file's metadata, not including the name.
    jfat_dirent       *de;

    /// The address of the data block containing the directory entry for this file.
    blockaddr_t        de_block;

    /// The offset within `de_block` of the directory entry.
    off_t              de_offset;
};

struct jfat_file_traversal_state
{
    /// The amount of data (in bytes) of the block currently being processed.
    size_t      block_size;

    /// The logical byte offset into the file of the start of the current block.
    off_t       offset;

#ifndef DOXYGEN
    bool        init;
#endif
};

struct jfat_directory_traversal_state
{
    /// The address of the block containing the current entry.
    blockaddr_t                 block;

    /// The offset into `block` of the start of the current entry.
    off_t                       offset;

    /**
     * \brief The address of the block containing the previous entry, or JFAT_EOF if this is the
     * first entry.
     */
    blockaddr_t                 last_block;

    /**
     * \brief The offset into `last_block` of the setart of the previous entry. Undefined if
     * `last_block == JFAT_EOF`.
     */
    off_t                       last_offset;

#ifndef DOXYGEN
    blockaddr_t                 next_block;
    size_t                      next_offset;
    size_t                      block_size;
    bool                        init;
#endif
};

struct jfat_open_block
{
    /// The address of the block in the data segment of the file system.
    blockaddr_t         address;

    /// Whether the block has been written to and needs to be flushed to disk.
    bool                dirty;
};

struct jfat_lru_entry
{
#ifndef DOXYGEN
    void *val;
    jfat_lru_iterator   next;
    jfat_lru_iterator   prev;
#endif
};

struct jfat_lru
{
#ifndef DOXYGEN
    size_t              size;

    size_t              hits;
    size_t              misses;

    jfat_lru_iterator   first;
    jfat_lru_iterator   last;

    jfat_lru_compare_t  compare;
    jfat_lru_filler_t   filler;
    void               *filler_arg;
#endif
};

struct jfat_block_set_entry
{
#ifndef DOXYGEN
    blockaddr_t             block;
    jfat_block_set_entry   *next;
    jfat_block_set_entry   *prev;
#endif
};

struct jfat_block_set
{
#ifndef DOXYGEN
    jfat_block_set_entry    *first;
    jfat_block_set_entry    *last;
    size_t                   size;
#endif
};

struct jfat_context
{
    /// File descriptor for the backing storage device.
    int                 dev_fd;

    /// The FAT.
    blockaddr_t        *fat;

    /// List of FAT blocks which need to be flushed to disk.
    jfat_block_set      fat_dirty;

    /// The super block.
    jfat_super_block    super;

    /// Whether the super block needs to be flushed to disk.
    bool                super_dirty;

    /// The open block cache.
    jfat_lru            open_blocks;

    // The set of open files.
    jfat_lru            open_files;
};

////////////////////////////////////////////////////////////////////////////////////////////////////
// On-Disk Data Structures Definitions
////////////////////////////////////////////////////////////////////////////////////////////////////

static void jfat_serialize_dirent(jfat_dirent *ent)
{
    (void)ent;
    ASSERT(little_endian);
}

static void jfat_deserialize_dirent(jfat_dirent *ent)
{
    (void)ent;
    ASSERT(little_endian);
}

static uint64_t jfat_dirent_id(const jfat_super_block *super, blockaddr_t block, off_t offset)
{
    // +2 because FUSE doesn't like inode numbers 0 and 1
    return block*(super->block_size / sizeof(jfat_dirent)) + offset / sizeof(jfat_dirent) + 2;
}

static struct timespec jfat_access_time(const jfat_dirent *de)
{
    return ns_to_timespec(de->accessed);
}

static struct timespec jfat_modify_time(const jfat_dirent *de)
{
    return ns_to_timespec(de->modified);
}

static struct timespec jfat_change_time(const jfat_dirent *de)
{
    return ns_to_timespec(de->changed);
}

static bool jfat_can_read(const jfat_dirent *de, uid_t uid, gid_t gid)
{
    if (uid == 0) {
        return true;
    } else if (de->uid == uid) {
        return de->mode & S_IRUSR;
    } else if (de->gid == gid) {
        return de->mode & S_IRGRP;
    } else {
        return de->mode & S_IROTH;
    }
}

static bool jfat_can_write(const jfat_dirent *de, uid_t uid, gid_t gid)
{
    if (uid == 0) {
        return true;
    } else if (de->uid == uid) {
        return de->mode & S_IWUSR;
    } else if (de->gid == gid) {
        return de->mode & S_IWGRP;
    } else {
        return de->mode & S_IWOTH;
    }
}

static bool jfat_can_execute(const jfat_dirent *de, uid_t uid, gid_t gid)
{
    if (uid == 0) {
        return true;
    } else if (de->uid == uid) {
        return de->mode & S_IXUSR;
    } else if (de->gid == gid) {
        return de->mode & S_IXGRP;
    } else {
        return de->mode & S_IXOTH;
    }
}

static void jfat_serialize_super_block(jfat_super_block_padded *psuper)
{
    (void)psuper;
    ASSERT(little_endian);
}

static void jfat_deserialize_super_block(jfat_super_block_padded *psuper)
{
    (void)psuper;
    ASSERT(little_endian);
}

static void jfat_serialize_fat(blockaddr_t *fat, size_t count)
{
    (void)fat;
    (void)count;
    ASSERT(little_endian);
}

static void jfat_deserialize_fat(blockaddr_t *fat, size_t count)
{
    (void)fat;
    (void)count;
    ASSERT(little_endian);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// In-Memory Data Structures Definitions
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef DOXYGEN

static int jfat_open_file_compare(void *vk1, void *vk2)
{
    jfat_open_file_key *k1 = (jfat_open_file_key *)vk1;
    jfat_open_file_key *k2 = (jfat_open_file_key *)vk2;

    int comp;
    if (k1->len < k2->len) {
        comp = -(k2->len - k1->len);
    } else if (k1->len > k2->len) {
        comp = k1->len - k2->len;
    } else if (k1->hash < k2->hash) {
        comp = -(k2->hash - k1->hash);
    } else if (k1->hash > k2->hash) {
        comp = k1->hash - k2->hash;
    } else {
        comp = strncmp(k1->path, k2->path, k1->len);
    }

    DEBUG("compare({%zu, %zu, %.*s}, {%zu, %zu, %.*s}) = %d",
        k1->len, (size_t)k1->hash, (int)k1->len, k1->path,
        k2->len, (size_t)k2->hash, (int)k2->len, k2->path,
        comp);
    return comp;
}

static void *jfat_open_file_filler(void *vkey, void *varg)
{
    jfat_open_file_key *key = (jfat_open_file_key *)vkey;
    jfat_context *cxt = (jfat_context *)varg;

    jfat_open_file *f;

    if (key->len == 1 && key->path[0] == '/') {
        // Base case: root directory
        f = (jfat_open_file *)malloc(sizeof(jfat_open_file));
        if (f == NULL) {
            return NULL;
        }
        f->key.len = 1;
        char *fpath = (char *)malloc(1);
        if (fpath == NULL) {
            free(f);
            return NULL;
        }
        fpath[0] = '/';
        f->key.path = fpath;
        f->key.hash = path_hash(f->key.path, f->key.len);

        f->refcount = 0;
        f->marked_for_deletion = false;
        f->de = &cxt->super.root_dir;
        f->de_block = JFAT_EOF; // Bogus value indicating root directory
        f->de_offset = 0;
        return f;
    }

    // General case: recursively open the parent directory and scan it for the target file

    f = (jfat_open_file *)malloc(sizeof(jfat_open_file) + sizeof(jfat_dirent));
    if (f == NULL) {
        goto exit_e_alloc_file;
    }
    f->key.len = key->len;
    f->key.hash = key->hash;
    f->key.path = strndup(key->path, key->len);
    if (f->key.path == NULL) {
        goto exit_e_alloc_path;
    }

    f->refcount = 0;
    f->marked_for_deletion = false;
    f->de = (jfat_dirent *)((char *)f + sizeof(jfat_open_file));

    // Open the parent so we can scan it for the child
    size_t parent_path_len = f->key.len - 1;
    while (parent_path_len > 0 && f->key.path[parent_path_len] != '/') {
        --parent_path_len;
    }
    jfat_open_file *parent = jfat_get_open_file_n(cxt, f->key.path, parent_path_len);
    if (parent == NULL) {
        goto exit_e_open_parent;
    }

    int err;
    char *child_name = NULL;
    jfat_directory_traversal_state state = JFAT_DIRECTORY_TRAVERSAL_INIT;
    while ((err = jfat_traverse_directory(cxt, parent, &state, f->de)) > 0) {
        child_name = (char *)realloc(child_name, f->de->name_size);
        if (child_name == NULL) {
            goto exit_e_alloc_child_name;
        }

        err = jfat_bread(
            cxt, state.block, state.offset + sizeof(jfat_dirent), f->de->name_size, child_name);
        if (err < 0) {
            errno = -err;
            goto exit_e_read_name;
        }

        if (key->len - parent_path_len - 1 == f->de->name_size
            && strncmp(child_name, key->path + parent_path_len + 1, f->de->name_size) == 0) {
            free(child_name);
            jfat_release_open_file(cxt, parent);

            f->de_block = state.block;
            f->de_offset = state.offset;
            return f;
        }
    }

    errno = err >= 0 ? ENOENT : -err;

exit_e_read_name:
    if (child_name) free(child_name);
exit_e_alloc_child_name:
    jfat_release_open_file(cxt, parent);
exit_e_open_parent:
    free((char *)f->key.path);
exit_e_alloc_path:
    free(f);
exit_e_alloc_file:
    return NULL;
}

#endif

static int jfat_touch_open_file(jfat_context *cxt, const jfat_open_file *f)
{
    if (f->marked_for_deletion) {
        return 0;
    }

    if (f->de_block == JFAT_EOF) {
        // Root directory
        jfat_touch_super(cxt);
        return 0;
    } else {
        jfat_dirent de = *f->de;
        jfat_serialize_dirent(&de);
        return jfat_bwrite(cxt, f->de_block, f->de_offset, sizeof(de), &de);
    }
}

static void jfat_init_open_files(jfat_context *cxt)
{
    jfat_lru_init(&cxt->open_files, jfat_open_file_compare, jfat_open_file_filler, cxt);
}

static int jfat_destroy_open_files(jfat_context *cxt)
{
    DEBUG("releasing all open files");

    jfat_lru *fs = &cxt->open_files;

    jfat_lru_iterator it = jfat_lru_begin(fs);
    while (it != jfat_lru_end(fs)) {
        jfat_open_file *f = (jfat_open_file *)jfat_lru_get(it);

        if (f->marked_for_deletion) {
            DEBUG("deleting marked file %.*s", (int)f->key.len, f->key.path);
            // TODO delete f's blocks
        }

        it = jfat_lru_erase(fs, it);

        free((char *)f->key.path);
        free(f);
    }

    jfat_lru_destroy(&cxt->open_files);
    return 0;
}

static jfat_open_file *jfat_get_open_file_n(jfat_context *cxt, const char *path, size_t path_len)
{
    DEBUG("opening file %.*s", (int)path_len, path);

    jfat_lru *fs = &cxt->open_files;

    jfat_open_file_key key;
    key.path = path_len == 0 ? "/" : path;
    key.len = path_len == 0 ? 1 : path_len;
    key.hash = path_hash(key.path, key.len);

    jfat_lru_iterator it = jfat_lru_retrieve(fs, &key);
    if (it == jfat_lru_end(fs)) {
        return NULL;
    }

    jfat_open_file *f = (jfat_open_file *)jfat_lru_get(it);
    ++f->refcount;

    // Try to evict files until the cache is a reasonable size
    it = jfat_lru_begin(fs);
    while (jfat_lru_size(fs) > JFAT_OPEN_FILE_CACHE_THRESHOLD && it != jfat_lru_end(fs)) {
        jfat_open_file *eviction_candidate = (jfat_open_file *)jfat_lru_get(it);
        if (eviction_candidate->refcount == 0) {
            DEBUG("evicting %.*s from open file cache (%zu/%zu full)",
                (int)eviction_candidate->key.len, eviction_candidate->key.path,
                jfat_lru_size(fs), (size_t)JFAT_OPEN_FILE_CACHE_THRESHOLD);
            it = jfat_lru_erase(fs, it);
        } else {
            it = jfat_lru_next(it);
        }
    }

    DEBUG("opened %.*s (refcount=%zu, %zu/%zu open files)",
        (int)f->key.len, f->key.path, f->refcount,
        jfat_lru_size(fs), (size_t)JFAT_OPEN_FILE_CACHE_THRESHOLD);

    return f;
}

static jfat_open_file *jfat_get_open_file(jfat_context *cxt, const char *path)
{
    return jfat_get_open_file_n(cxt, path, strlen(path));
}

static size_t jfat_last_block_size(const jfat_context *cxt, const jfat_open_file *f)
{
    if (f->de->size == 0) {
        return 0;
    } else if (f->de->size % cxt->super.block_size == 0) {
        return cxt->super.block_size;
    } else {
        return f->de->size % cxt->super.block_size;
    }
}

static int jfat_traverse_file(
    jfat_context *cxt, const jfat_open_file *f, jfat_file_traversal_state *state,
    blockaddr_t *block)
{
    if (state->init) {
        *block = f->de->data;
        state->offset = 0;
        state->init = false;
    } else {
        *block = cxt->fat[*block];
        state->offset += state->block_size;
    }

    if (*block == JFAT_EOF) {
        return 0;
    } else {
        if (jfat_get_fat(cxt, *block) == JFAT_EOF) {
            // Partial last block
            state->block_size = jfat_last_block_size(cxt, f);
        } else {
            state->block_size = cxt->super.block_size;
        }
    }

    return 1;
}

static int jfat_traverse_directory(
    jfat_context *cxt, const jfat_open_file *dir, jfat_directory_traversal_state *state,
    jfat_dirent *child)
{
    jfat_dirent *de = dir->de;

    ASSERT(S_ISDIR(de->mode))

    if (de->size == 0) {
        return 0;
    }

    if (state->init) {
        state->block = de->data;
        state->last_block = JFAT_EOF;
        state->next_offset = 0;
        state->offset = 0;
        state->init = false;
    } else {
        state->last_block = state->block;
        state->last_offset = state->offset;
    }

    blockaddr_t next_block = cxt->fat[state->block];
    size_t block_size = cxt->super.block_size;
    if (next_block == JFAT_EOF) {
        block_size = jfat_last_block_size(cxt, dir);
    }

    if (state->next_offset >= block_size) {
        state->next_offset = 0;
        state->block = next_block;
        if (state->block == JFAT_EOF) {
            return 0;
        }
    }

    int err = jfat_bread(cxt, state->block, state->next_offset, sizeof(jfat_dirent), child);
    if (err < 0) {
        return err;
    }
    jfat_deserialize_dirent(child);

    state->offset = state->next_offset;
    state->next_offset += child->ent_size;

    return 1;
}

static int jfat_nftw(
    jfat_context *cxt, jfat_open_file *root, jfat_nftw_callback callback, void *arg)
{
    int err = 0;

    bool needs_slash = root->key.path[root->key.len - 1] != '/';
    size_t root_path_len = root->key.len + needs_slash;
    char *child_path = (char *)malloc(root_path_len);
    if (child_path == NULL) {
        err = -errno;
        goto exit_e_alloc_child_path;
    }
    strncpy(child_path, root->key.path, root->key.len);
    if (needs_slash) child_path[root->key.len] = '/';

    if (S_ISDIR(root->de->mode)) {
        // Traverse children of directory recursively
        jfat_dirent child;
        jfat_directory_traversal_state state = JFAT_DIRECTORY_TRAVERSAL_INIT;
        while ((err = jfat_traverse_directory(cxt, root, &state, &child)) > 0) {
            child_path = (char *)realloc(child_path, root_path_len + child.name_size);
            if (child_path == NULL) {
                err = -errno;
                goto exit_e_alloc_child_path;
            }

            err = jfat_bread(
                cxt, state.block, state.offset + sizeof(jfat_dirent), child.name_size,
                child_path + root_path_len);
            if (err < 0) {
                goto exit_e_read_name;
            }

            jfat_open_file *f = jfat_get_open_file_n(
                cxt, child_path, root_path_len + child.name_size);
            if (f == NULL) {
                err = -errno;
                goto exit_e_open;
            }

            err = jfat_nftw(cxt, f, callback, arg);

            int err2 = jfat_release_open_file(cxt, f);
            if (err >= 0 && err2 < 0) {
                // Errors on release supercede return codes from the recursive call if the recursive
                // call exited because callback returned a positive value. However, if the recursive
                // call exited with a negative value (as in an internal error) we report only the first
                // error.
                err = err2;
            }

            if (err != 0) {
                goto exit_e_recurse;
            }
        }
    }

    // Finally, visit the root itself
    err = callback(cxt, root, arg);

exit_e_recurse:
exit_e_open:
exit_e_read_name:
    free(child_path);
exit_e_alloc_child_path:
    return err;
}

static int jfat_release_open_file(jfat_context *cxt, jfat_open_file *f)
{
    DEBUG("releasing file %.*s, refcount=%u", (int)f->key.len, f->key.path, (unsigned)f->refcount);

    jfat_lru *fs = &cxt->open_files;

    if (--f->refcount == 0) {
        if (f->marked_for_deletion) {
            DEBUG("deleting marked file %.*s", (int)f->key.len, f->key.path);
            int err = jfat_truncate_file(cxt, f, 0);
            if (err < 0) {
                return err;
            }
            err = jfat_fs_sync(cxt);
            if (err < 0) {
                return err;
            }
        }

        if (f->marked_for_deletion || jfat_lru_size(fs) > JFAT_OPEN_FILE_CACHE_THRESHOLD) {
            // Remove the file from the cache
            jfat_lru_iterator it = jfat_lru_find(fs, f);
            if (it == jfat_lru_end(fs)) {
                WARN("releasing file not present in open file cache (%.*s)",
                    (int)f->key.len, f->key.path);
            } else {
                jfat_lru_erase(fs, it);
                free((char *)f->key.path);
                free(f);
            }

        } else {
            DEBUG("will retain reference to %.*s in open file cache (%zu/%zu full)",
                (int)f->key.len, f->key.path, jfat_lru_size(fs),
                (size_t)JFAT_OPEN_FILE_CACHE_THRESHOLD);
        }
    }

    return 0;
}

#ifndef DOXYGEN

static int jfat_open_block_compare(void *vb1, void *vb2)
{
    blockaddr_t *b1 = (blockaddr_t *)vb1;
    blockaddr_t *b2 = (blockaddr_t *)vb2;

    if (*b1 < *b2) {
        return -(*b2 - *b1);
    } else {
        return *b2 - *b1;
    }
}

static int jfat_bevict(jfat_context *cxt)
{
    jfat_lru *blocks = &cxt->open_blocks;

    if (jfat_lru_size(blocks) == 0) {
        return 0;
    }

    // Look for the least recently used clean block (so we can evict without flushing)
    jfat_lru_iterator it;
    for (it = jfat_lru_begin(blocks); it != jfat_lru_end(blocks); it = jfat_lru_next(it)) {
        jfat_open_block *b = (jfat_open_block *)jfat_lru_get(it);
        if (!b->dirty) {
            DEBUG("evicting clean block %u", (unsigned)b->address);
            break;
        }
    }

    if (it == jfat_lru_end(blocks)) {
        // No clean blocks, just take the last dirty one
        it = jfat_lru_begin(blocks);

        jfat_open_block *b = (jfat_open_block *)jfat_lru_get(it);

        // Have to flush it
        DEBUG("flushing to evict block %u", (unsigned)b->address);
        int err = jfat_write_data_block(
            cxt->dev_fd, &cxt->super, b->address, (char *)b + sizeof(jfat_open_block));
        if (err < 0) {
            return err;
        }
    }

    jfat_open_block *b = (jfat_open_block *)jfat_lru_get(it);
    jfat_lru_erase(blocks, it);
    free(b);

    return 0;
}

#endif

static void *jfat_open_block_filler(void *vaddr, void *varg)
{
    blockaddr_t addr = *(blockaddr_t *)vaddr;
    jfat_context *cxt = (jfat_context *)varg;
    jfat_lru *blocks = &cxt->open_blocks;

    jfat_open_block *b = (jfat_open_block *)malloc(sizeof(jfat_open_block) + cxt->super.block_size);
    if (b == NULL) {
        return NULL;
    }

    b->address = addr;
    b->dirty = false;
    int err = jfat_read_data_block(
        cxt->dev_fd, &cxt->super, addr, (char *)b + sizeof(jfat_open_block));
    if (err < 0) {
        free(b);
        errno = -err;
        return NULL;
    }

    // Evict a block if the cache has grown too large
    if (jfat_lru_size(blocks) >= JFAT_MAX_OPEN_BLOCKS) {
        DEBUG("block cache full, evicting");
        err = jfat_bevict(cxt);
        if (err < 0) {
            free(b);
            errno = -err;
            return NULL;
        }
    }

    DEBUG("added bock %u to cache, cache is now %zu/%zu full",
        (unsigned)b->address, jfat_lru_size(blocks), (size_t)JFAT_MAX_OPEN_BLOCKS);

    return b;
}

static void jfat_init_open_blocks(jfat_context *cxt)
{
    jfat_lru_init(&cxt->open_blocks, jfat_open_block_compare, jfat_open_block_filler, cxt);
}

static int jfat_destroy_open_blocks(jfat_context *cxt)
{
    int err = jfat_bflush_all(cxt);
    if (err < 0) {
        return err;
    }

    jfat_lru_destroy(&cxt->open_blocks);

    return 0;
}

static jfat_open_block *jfat_open_block_get(jfat_context *cxt, blockaddr_t block)
{
    jfat_lru *blocks = &cxt->open_blocks;

    jfat_lru_iterator it = jfat_lru_retrieve(blocks, &block);
    if (it == jfat_lru_end(blocks)) {
        return NULL;
    } else {
        return (jfat_open_block *)jfat_lru_get(it);
    }
}

static int jfat_bread(jfat_context *cxt, blockaddr_t block, off_t offset, size_t size, void *buf)
{
    jfat_open_block *b = jfat_open_block_get(cxt, block);
    if (b == NULL) {
        return -errno;
    }

    memcpy(buf, (char *)b + sizeof(jfat_open_block) + offset, size);
    return 0;
}

static int jfat_bwrite(
    jfat_context *cxt, blockaddr_t block, off_t offset, size_t size, const void *buf)
{
    jfat_open_block *b = jfat_open_block_get(cxt, block);
    if (b == NULL) {
        return -errno;
    }

    memcpy((char *)b + sizeof(jfat_open_block) + offset, buf, size);
    b->dirty = true;

    return 0;
}

static int jfat_bflush_all(jfat_context *cxt)
{
    DEBUG("flushing block cache");

    jfat_lru *blocks = &cxt->open_blocks;

    jfat_lru_iterator it;
    for (it = jfat_lru_begin(blocks); it != jfat_lru_end(blocks); it = jfat_lru_next(it)) {
        jfat_open_block *b = (jfat_open_block *)jfat_lru_get(it);
        if (b->dirty) {
            DEBUG("flushing dirty block %u", (unsigned)b->address);
            int err = jfat_write_data_block(
                cxt->dev_fd, &cxt->super, b->address, (char *)b + sizeof(jfat_open_block));
            if (err < 0) {
                return err;
            }
            b->dirty = false;
        }
    }
    return 0;
}

static jfat_context *jfat_get_context()
{
    return (jfat_context *)(fuse_get_context()->private_data);
}

static void jfat_touch_super(jfat_context *cxt)
{
    cxt->super_dirty = true;
}

static int jfat_set_fat(jfat_context *cxt, blockaddr_t key, blockaddr_t value)
{
    cxt->fat[key] = value;
    return jfat_block_set_insert(&cxt->fat_dirty, key / cxt->super.block_size);
}

static blockaddr_t jfat_get_fat(jfat_context *cxt, blockaddr_t key)
{
    return cxt->fat[key];
}

static void jfat_lru_init(
    jfat_lru *c, jfat_lru_compare_t compare, jfat_lru_filler_t filler, void *filler_arg)
{
    c->size = 0;
    c->first = NULL;
    c->last = NULL;
    c->compare = compare;
    c->filler = filler;
    c->filler_arg = filler_arg;

    c->hits = 0;
    c->misses = 0;
}

static void jfat_lru_destroy(jfat_lru *c)
{
    size_t retrieves = c->hits + c->misses;
    INFO("lru@%p final performance summary: %zu accesses, hit rate = %.2f%%",
        c, retrieves, (double)c->hits / retrieves * 100.0);

    while (c->size) jfat_lru_erase(c, c->first);
}

static size_t jfat_lru_size(const jfat_lru *c)
{
    return c->size;
}

static jfat_lru_iterator jfat_lru_begin(const jfat_lru *c)
{
    return c->last;
}

static jfat_lru_iterator jfat_lru_end(const jfat_lru *c)
{
    (void)c;
    return NULL;
}

static jfat_lru_iterator jfat_lru_next(jfat_lru_iterator it)
{
    return it->prev;
}

static void *jfat_lru_get(jfat_lru_iterator it)
{
    return it->val;
}

static jfat_lru_iterator jfat_lru_find(jfat_lru *c, void *key)
{
    jfat_lru_iterator it;
    for (it = c->first; it; it = it->next) {
        if (c->compare(key, it->val) == 0) {
            if (it != c->first) {
                // Bring it to the front of the list
                if (it->next) {
                    it->next->prev = it->prev;
                }
                if (it->prev) {
                    it->prev->next = it->next;
                }
                if (c->last == it) {
                    c->last = it->prev;
                }

                it->prev = NULL;
                it->next = c->first;
                c->first->prev = it;
                c->first = it;
            }

            return it;
        }
    }

    return NULL;
}

static jfat_lru_iterator jfat_lru_retrieve(jfat_lru *c, void *key)
{
    jfat_lru_entry *entry = jfat_lru_find(c, key);
    if (entry == NULL) {
        ++c->misses;

        entry = (jfat_lru_entry *)malloc(sizeof(jfat_lru_entry));
        if (entry == NULL) {
            return NULL;
        }

        entry->val = c->filler(key, c->filler_arg);
        if (entry->val == NULL) {
            free(entry);
            return NULL;
        }

        entry->prev = NULL;
        entry->next = c->first;
        if (c->first) {
            c->first->prev = entry;
        } else {
            // Empty list
            c->last = entry;
        }
        c->first = entry;

        ++c->size;
    } else {
        ++c->hits;
    }

    size_t retrieves = c->hits + c->misses;
    if (retrieves > 0 && retrieves % 1000 == 0) {
        DEBUG("lru@%p performance summary: %zu accesses, hit rate = %.2f%%",
            c, retrieves, (double)c->hits / retrieves * 100.0);
    }

    return entry;
}

static jfat_lru_iterator jfat_lru_erase(jfat_lru *c, jfat_lru_iterator it)
{
    if (it->prev) {
        it->prev->next = it->next;
    }
    if (it->next) {
        it->next->prev = it->prev;
    }
    if (c->first == it) {
        c->first = it->next;
    }
    if (c->last == it) {
        c->last = it->prev;
    }

    --c->size;

    jfat_lru_iterator next = it->next;
    free(it);
    return next;
}

static void jfat_block_set_init(jfat_block_set *set)
{
    set->first = NULL;
    set->last = NULL;
    set->size = 0;
}

static void jfat_block_set_destroy(jfat_block_set *set)
{
    while (set->first) {
        jfat_block_set_erase(set, set->first);
    }
}

static size_t jfat_block_set_size(const jfat_block_set *set)
{
    return set->size;
}

static jfat_block_set_iterator jfat_block_set_find(const jfat_block_set *set, blockaddr_t block)
{
    jfat_block_set_entry *e;
    for (e = set->first; e && e->block < block; e = e->next);
    if (e && e->block == block) {
        return e;
    } else {
        return NULL;
    }
}

static int jfat_block_set_insert(jfat_block_set *set, blockaddr_t block)
{
    jfat_block_set_entry *new_entry = (jfat_block_set_entry *)malloc(sizeof(jfat_block_set_entry));
    if (new_entry == NULL) {
        return -errno;
    }
    new_entry->block = block;
    new_entry->prev = NULL;
    new_entry->next = NULL;

    jfat_block_set_entry *e;
    for (e = set->first; e && e->block < block; e = e->next);

    if (e == NULL) {
        // Insert at end
        if (set->last == NULL) {
            set->first = set->last = new_entry;
        } else {
            new_entry->prev = set->last;
            set->last->next = new_entry;
            set->last = new_entry;
        }
    } else if (e->block == block) {
        free(new_entry);
    } else {
        // Insert before e
        new_entry->next = e;
        if (e->prev) {
            new_entry->prev = e->prev;
            e->prev->next = new_entry;
        }
        e->prev = new_entry;

        if (e == set->first) {
            set->first = new_entry;
        }
    }

    ++set->size;
    return 0;
}

static jfat_block_set_iterator jfat_block_set_erase(jfat_block_set *set, jfat_block_set_iterator it)
{
    ASSERT(set->size > 0);

    if (it->next) {
        it->next->prev = it->prev;
    }
    if (it->prev) {
        it->prev->next = it->next;
    }
    if (set->first == it) {
        set->first = it->next;
    }
    if (set->last == it) {
        set->last = it->prev;
    }

    jfat_block_set_iterator next = it->next;
    free(it);
    --set->size;
    return next;
}

static jfat_block_set_iterator jfat_block_set_begin(const jfat_block_set *set)
{
    return set->first;
}

static jfat_block_set_iterator jfat_block_set_end(const jfat_block_set *set)
{
    (void)set;

    return NULL;
}

static blockaddr_t jfat_block_set_get(jfat_block_set_iterator it)
{
    return it->block;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// I/O Definitions
////////////////////////////////////////////////////////////////////////////////////////////////////

static int jfat_pwrite(int fd, const void *vbuf, size_t count, off_t offset)
{
    const char *buf = (const char *)vbuf;

    size_t bytes_written = 0;
    while (bytes_written < count) {
        ssize_t nbytes = pwrite(
            fd, buf + bytes_written, count - bytes_written, offset + bytes_written);
        if (nbytes == -1) {
            return -errno;
        } else {
            bytes_written += nbytes;
        }
    }

    return 0;
}

static int jfat_write_blocks(
    int fd, const jfat_super_block *super, blockaddr_t start, size_t count, const void *buf)
{
    return jfat_pwrite(fd, buf, count*super->block_size, start*super->block_size);
}

static int jfat_write_block(
    int fd, const jfat_super_block *super, blockaddr_t addr, const void *block)
{
    return jfat_write_blocks(fd, super, addr, 1, block);
}

static int jfat_write_data_block(
    int fd, const jfat_super_block *super, blockaddr_t addr, const void *block)
{
    return jfat_write_block(fd, super, 1 + super->fat_blocks + addr, block);
}

static int jfat_pread(int fd, void *vbuf, size_t count, off_t offset)
{
    char *buf = (char *)vbuf;

    size_t bytes_read = 0;
    while (bytes_read < count) {
        ssize_t nbytes = pread(
            fd, buf + bytes_read, count - bytes_read, offset + bytes_read);
        if (nbytes == -1) {
            return -errno;
        } else if (nbytes == 0) {
            // Unexpected EOF
            return -EIO;
        } else {
            bytes_read += nbytes;
        }
    }

    return 0;
}

static int jfat_read_blocks(
    int fd, const jfat_super_block *super, blockaddr_t start, size_t count, void *buf)
{
    return jfat_pread(fd, buf, count*super->block_size, start*super->block_size);
}

static int jfat_read_block(int fd, const jfat_super_block *super, blockaddr_t addr, void *block)
{
    return jfat_read_blocks(fd, super, addr, 1, block);
}

static int jfat_read_data_block(
    int fd, const jfat_super_block *super, blockaddr_t addr, void *block)
{
    return jfat_read_block(fd, super, 1 + super->fat_blocks + addr, block);
}

static int jfat_flush_super_block(jfat_context *cxt)
{
    if (cxt->super_dirty) {
        DEBUG("flushing dirty super block");

        jfat_super_block_padded psuper;
        memset(&psuper, 0, sizeof(psuper));

        psuper.super = cxt->super;
        jfat_serialize_super_block(&psuper);
        int err = jfat_pwrite(cxt->dev_fd, &psuper, SUPER_BLOCK_SIZE, 0);
        if (err < 0) {
            return err;
        }
    }

    cxt->super_dirty = false;
    return 0;
}

static int jfat_flush_fat(jfat_context *cxt)
{
    int err = 0;

    jfat_block_set *dirty_blocks = &cxt->fat_dirty;

    size_t addrs_per_block = cxt->super.block_size / sizeof(blockaddr_t);

    blockaddr_t dirty_start = JFAT_EOF;
    blockaddr_t dirty_end = JFAT_EOF;

    jfat_block_set_iterator it = jfat_block_set_begin(dirty_blocks);
    while (it != jfat_block_set_end(dirty_blocks)) {
        blockaddr_t b = jfat_block_set_get(it);
        if (dirty_start != JFAT_EOF && b == dirty_end) {
            // We're working on a set of contiguous blocks
            ++dirty_end;
        } else {
            // b is not contiguous, flush this set and start a new one
            if (dirty_start != JFAT_EOF) {
                blockaddr_t *fat_start = cxt->fat + addrs_per_block*dirty_start;
                size_t size = dirty_end - dirty_start;

                DEBUG("flushing FAT blocks %zu through %zu", (size_t)dirty_start, (size_t)dirty_end - 1);

                jfat_serialize_fat(fat_start, size);
                err = jfat_write_blocks(
                    cxt->dev_fd, &cxt->super, dirty_start + 1, dirty_end - dirty_start, fat_start);
                jfat_deserialize_fat(fat_start, size);
                if (err < 0) {
                    break;
                }
            }

            dirty_start = b;
            dirty_end = b + 1;
        }

        it = jfat_block_set_erase(dirty_blocks, it);
    }

    if (err == 0) {
        if (dirty_start != JFAT_EOF) {
            // Flush last set
            blockaddr_t *fat_start = cxt->fat + addrs_per_block*dirty_start;
            size_t size = dirty_end - dirty_start;

            DEBUG("flushing FAT blocks %zu through %zu", (size_t)dirty_start, (size_t)dirty_end - 1);

            jfat_serialize_fat(fat_start, size);
            err = jfat_write_blocks(
                cxt->dev_fd, &cxt->super, dirty_start + 1, dirty_end - dirty_start, fat_start);
            jfat_deserialize_fat(fat_start, size);
        }
    }

    return err;
}

static int jfat_fs_sync(jfat_context *cxt)
{
    int err = 0;

    err = jfat_bflush_all(cxt);
    if (err < 0) {
        return err;
    }

    err = jfat_flush_fat(cxt);
    if (err < 0) {
        return err;
    }

    err = jfat_flush_super_block(cxt);
    if (err < 0) {
        return err;
    }

    return 0;
}

static int jfat_transfer_data(
    jfat_context *cxt, jfat_open_file *f, void *vbuf, size_t size, off_t offset, transfer_type type)
{
    ASSERT(offset >= 0);

    char *buf = (char *)vbuf;

    int err = 0;

    typedef int (*transfer_t)(jfat_context *, blockaddr_t, off_t, size_t, void *);
    transfer_t transfer;

    switch (type) {
    case TRANSFER_TO:
        transfer = (transfer_t)jfat_bwrite;
        break;
    case TRANSFER_FROM:
        transfer = jfat_bread;
        break;
    default:
        ERROR("Invalid transfer type %d", (int)type);
        return -EINVAL;
    }

    size_t bytes_read = 0;
    blockaddr_t block;
    jfat_file_traversal_state state = JFAT_FILE_TRAVERSAL_INIT;
    while ((err = jfat_traverse_file(cxt, f, &state, &block)) > 0) {
        if (state.offset + state.block_size > (size_t)offset) {
            off_t start = offset > state.offset ? offset - state.offset : 0;

            size_t nbytes = MIN(size - bytes_read, state.block_size - start);
            err = transfer(cxt, block, start, nbytes, buf + bytes_read);
            if (err < 0) {
                break;
            }
            bytes_read += nbytes;
            if (bytes_read >= size) {
                break;
            }
        }
    }

    if (err >= 0) {
        err = bytes_read;
    }

    return err;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Block Management Definitions
////////////////////////////////////////////////////////////////////////////////////////////////////

static blockaddr_t jfat_alloc_block(jfat_context *cxt)
{
    blockaddr_t block = cxt->super.first_free_block;
    if (block == JFAT_EOF) {
        errno = ENOSPC;
        return JFAT_EOF;
    }

    cxt->super.first_free_block = jfat_get_fat(cxt, block);
    --cxt->super.free_data_blocks;

    jfat_touch_super(cxt);

    return block;
}

static void jfat_free_block(jfat_context *cxt, blockaddr_t block)
{
    jfat_set_fat(cxt, block, cxt->super.first_free_block);

    cxt->super.first_free_block = block;
    ++cxt->super.free_data_blocks;
    jfat_touch_super(cxt);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Modifiers Definitions
////////////////////////////////////////////////////////////////////////////////////////////////////

static int jfat_free_blocks_after(jfat_context *cxt, jfat_open_file *f, blockaddr_t last_block)
{
    ASSERT(f->de->size > 0);
    ASSERT(last_block != JFAT_EOF);
    blockaddr_t first_free = jfat_get_fat(cxt, last_block);

    if (first_free == JFAT_EOF) {
        return 0;
    }

    int err = jfat_free_blocks_after(cxt, f, first_free);
    if (err < 0) {
        return err;
    }

    jfat_free_block(cxt, first_free);
    jfat_set_fat(cxt, last_block, JFAT_EOF);
    f->de->size -= jfat_last_block_size(cxt, f);
    return jfat_touch_open_file(cxt, f);
}

static int jfat_shrink_file(jfat_context *cxt, jfat_open_file *f, size_t new_size)
{
    ASSERT(f->de->size > new_size);
    ASSERT(f->de->data != JFAT_EOF);

    int err = 0;

    blockaddr_t cur = f->de->data;
    size_t cur_offset = 0;

    // Seek to block containing new EOF
    while (cur_offset + cxt->super.block_size < new_size) {
        cur = jfat_get_fat(cxt, cur);
        ASSERT(cur != JFAT_EOF);

        cur_offset += cxt->super.block_size;
    }

    // Free excess blocks
    err = jfat_free_blocks_after(cxt, f, cur);
    if (err < 0) {
        goto exit_e_free_excess;
    }

    if (cur_offset < new_size) {
        // Partial last block

        size_t partial_block_size = new_size - cur_offset;
        ASSERT(partial_block_size < cxt->super.block_size);

        size_t cur_block_size = jfat_last_block_size(cxt, f);

        f->de->size -= cur_block_size - partial_block_size;
        err = jfat_touch_open_file(cxt, f);
        if (err < 0) {
            goto exit_e_touch;
        }
    }

    if (new_size == 0) {
        ASSERT(jfat_get_fat(cxt, f->de->data) == JFAT_EOF);

        // Free the last block
        jfat_free_block(cxt, f->de->data);
        f->de->data = JFAT_EOF;
        f->de->size = 0;

        err = jfat_touch_open_file(cxt, f);
        if (err < 0) {
            goto exit_e_touch;
        }
    }

    ASSERT(f->de->size == new_size);

exit_e_free_excess:
exit_e_touch:
    return err;
}

static int jfat_grow_file(jfat_context *cxt, jfat_open_file *f, size_t new_size)
{
    ASSERT(f->de->size < new_size);

    int err = 0;

    char *zeros = (char *)malloc(cxt->super.block_size);
    if (zeros == NULL) {
        err = -errno;
        goto exit_e_alloc_zeros;
    }
    memset(zeros, 0, cxt->super.block_size);

    blockaddr_t cur = f->de->data;
    blockaddr_t next = cur == JFAT_EOF ? JFAT_EOF : jfat_get_fat(cxt, cur);

    // Seek to EOF
    while (next != JFAT_EOF) {
        cur = next;
        next = jfat_get_fat(cxt, cur);
    }

    while (f->de->size < new_size) {
        if (f->de->size % cxt->super.block_size != 0) {
            // "Allocate" space in the last block of the current file
            size_t partial_block_offset = f->de->size % cxt->super.block_size;
            size_t partial_block_space =
                MIN(cxt->super.block_size - partial_block_offset, new_size - f->de->size);

            // Zero the new space
            err = jfat_bwrite(cxt, cur, partial_block_offset, partial_block_space, zeros);
            if (err < 0) {
                goto exit_e_zero;
            }

            f->de->size += partial_block_space;
            err = jfat_touch_open_file(cxt, f);
            if (err < 0) {
                goto exit_e_touch;
            }
        } else {
            // Get a block of the free list
            next = jfat_alloc_block(cxt);
            if (next == JFAT_EOF) {
                err = -errno;
                goto exit_e_nospc;
            }

            // Zero out the new block
            err = jfat_bwrite(cxt, next, 0, cxt->super.block_size, zeros);
            if (err < 0) {
                jfat_free_block(cxt, next);
                goto exit_e_zero;
            }

            // Add it to the file
            if (cur == JFAT_EOF) {
                f->de->data = next;
            } else {
                jfat_set_fat(cxt, cur, next);
            }
            jfat_set_fat(cxt, next, JFAT_EOF);

            f->de->size += MIN(cxt->super.block_size, new_size - f->de->size);
            err = jfat_touch_open_file(cxt, f);
            if (err < 0) {
                goto exit_e_touch;
            }

            cur = next;
            next = JFAT_EOF;
        }
    }

    ASSERT(f->de->size == new_size);

exit_e_touch:
exit_e_nospc:
exit_e_zero:
    free(zeros);
exit_e_alloc_zeros:
    return err;
}

static int jfat_truncate_file(jfat_context *cxt, jfat_open_file *f, size_t new_size)
{
    if (new_size < f->de->size) {
        return jfat_shrink_file(cxt, f, new_size);
    } else if (new_size > f->de->size) {
        return jfat_grow_file(cxt, f, new_size);
    } else {
        return 0;
    }
}

static int jfat_remove_child(jfat_context *cxt, jfat_open_file *parent, const jfat_open_file *child)
{
    int err = 0;
    char *candidate_name = NULL;

    const char *child_name = child->key.path + child->key.len - child->de->name_size;

    // Look for the directory entry right before child, so we can expand it to absorb child
    jfat_directory_traversal_state state = JFAT_DIRECTORY_TRAVERSAL_INIT;
    jfat_dirent de;
    while ((err = jfat_traverse_directory(cxt, parent, &state, &de)) > 0) {
        if (de.name_size == child->de->name_size) {
            // Read in the name to compare
            candidate_name = (char *)realloc(candidate_name, de.name_size);
            if (candidate_name == NULL) {
                err = -errno;
                goto exit_e_alloc_candidate_name;
            }

            err = jfat_bread(
                cxt, state.block, state.offset + sizeof(jfat_dirent), de.name_size, candidate_name);
            if (err < 0) {
                goto exit_e_read_candidate_name;
            }

            if (strncmp(child_name, candidate_name, de.name_size) == 0) {
                // de is now a copy of the child, we want to erase it by merging it with another
                // entry
                if (state.offset == 0) {
                    // No previous entry in this block
                    if (de.ent_size == cxt->super.block_size) {
                        // This entry is the only one in the block, so we can just free the block
                        if (state.last_block == JFAT_EOF) {
                            // This is the first entry in the entire directory
                            parent->de->data = JFAT_EOF;
                        } else {
                            jfat_set_fat(cxt, state.last_block, jfat_get_fat(cxt, state.block));
                        }

                        jfat_free_block(cxt, state.block);
                        parent->de->size -= cxt->super.block_size;
                        jfat_touch_open_file(cxt, parent);
                    } else {
                        // Merge with the next entry by moving the next entry to the beginning of
                        // the block
                        jfat_dirent next;
                        err = jfat_bread(cxt, state.block, de.ent_size, sizeof(jfat_dirent), &next);
                        if (err < 0) {
                            goto exit_e_read_next;
                        }

                        jfat_deserialize_dirent(&next);
                        next.ent_size += de.ent_size;

                        // Repurpose candidate_name to hold the next entry's name
                        size_t next_name_size = next.name_size;
                        candidate_name = (char *)realloc(candidate_name, next_name_size);
                        if (candidate_name == NULL) {
                            err = -errno;
                            goto exit_e_alloc_next_name;
                        }
                        err = jfat_bread(
                            cxt, state.block, de.ent_size + sizeof(jfat_dirent), next_name_size,
                            candidate_name);
                        if (err < 0) {
                            goto exit_e_read_next_name;
                        }

                        // Write the new dirent
                        jfat_serialize_dirent(&next);
                        err = jfat_bwrite(cxt, state.block, 0, sizeof(jfat_dirent), &next);
                        if (err < 0) {
                            goto exit_e_write_next;
                        }

                        // Write the name
                        err = jfat_bwrite(
                            cxt, state.block, sizeof(jfat_dirent), next_name_size, candidate_name);
                        if (err < 0) {
                            goto exit_e_write_next_name;
                        }
                    }
                } else {
                    // Merge with the previous entry

                    jfat_dirent prev;
                    err = jfat_bread(
                        cxt, state.block, state.last_offset, sizeof(jfat_dirent), &prev);
                    if (err < 0) {
                        goto exit_e_read_prev;
                    }

                    jfat_deserialize_dirent(&prev);
                    prev.ent_size += de.ent_size;
                    jfat_serialize_dirent(&prev);

                    err = jfat_bwrite(
                        cxt, state.block, state.last_offset, sizeof(jfat_dirent), &prev);
                    if (err < 0) {
                        goto exit_e_write_prev;
                    }
                }

                goto exit_found;
            }
        }
    }

    err = -ENOENT;

exit_found:

exit_e_write_prev:
exit_e_read_prev:
exit_e_write_next_name:
exit_e_write_next:
exit_e_read_next_name:
exit_e_alloc_next_name:
exit_e_read_next:
exit_e_read_candidate_name:
exit_e_alloc_candidate_name:
    if (candidate_name) free(candidate_name);
    return err;
}

static int jfat_add_child(
    jfat_context *cxt, jfat_open_file *parent, const jfat_dirent *child_immutable)
{
    int err = 0;

    jfat_dirent *child = (jfat_dirent *)malloc(child_immutable->ent_size);
    if (child == NULL) {
        err = -errno;
        goto exit_e_alloc_child;
    }

    memcpy(child, child_immutable, child_immutable->ent_size);

    blockaddr_t block_to_write = JFAT_EOF;
    off_t offset_to_write = (off_t)-1;

    if (child->ent_size > cxt->super.block_size) {
        err = -ENOSPC;
        goto exit_e_nospc;
    }

    // Walk the directory, looking for an entry with enough empty space to accomodate the child
    jfat_directory_traversal_state state = JFAT_DIRECTORY_TRAVERSAL_INIT;
    jfat_dirent de;
    while ((err = jfat_traverse_directory(cxt, parent, &state, &de)) > 0) {
        block_to_write = state.block;
        size_t old_size = de.ent_size;
        size_t new_size = sizeof(jfat_dirent) + de.name_size;
        if (old_size - new_size >= child->ent_size) {
            // We're changing the size of the previous entry, so we have to make sure that goes
            // through the open file cache to disk.

            // First get a full path so we can open the file.
            bool needs_slash = parent->key.path[parent->key.len - 1] != '/';
            size_t path_len = parent->key.len + needs_slash + de.name_size;
            char *path = (char *)malloc(path_len);
            if (path == NULL) {
                goto exit_e_alloc_path;
            }
            strncpy(path, parent->key.path, parent->key.len);
            if (needs_slash) path[parent->key.len] = '/';
            err = jfat_bread(cxt, state.block, state.offset + sizeof(jfat_dirent),
                             de.name_size, path + parent->key.len + needs_slash);
            if (err < 0) {
                free(path);
                goto exit_e_read_name;
            }

            jfat_open_file *f = jfat_get_open_file_n(cxt, path, path_len);
            free(path);
            if (f == NULL) {
                goto exit_e_open;
            }

            f->de->ent_size = new_size;
            err = jfat_touch_open_file(cxt, f);
            if (err < 0) {
                goto exit_e_touch;
            }
            jfat_release_open_file(cxt, f);

            offset_to_write = state.offset + new_size;
            child->ent_size = old_size - new_size;
            break;
        }
    }
    if (err < 0) {
        free(child);
        return err;
    }
    if (offset_to_write == (off_t)-1) {
        // There was no room to insert in the file, we need to grow it
        err = jfat_truncate_file(cxt, parent, parent->de->size + cxt->super.block_size);
        if (err < 0) {
            goto exit_e_truncate;
        }
        block_to_write = block_to_write == JFAT_EOF ? parent->de->data : cxt->fat[block_to_write];

        // The new entry becomes the first entry of the last block
        offset_to_write = 0;
        child->ent_size = cxt->super.block_size;
    }

    jfat_serialize_dirent(child);
    err = jfat_bwrite(
        cxt, block_to_write, offset_to_write, sizeof(jfat_dirent) + child->name_size, child);

exit_e_truncate:
exit_e_touch:
exit_e_open:
exit_e_read_name:
exit_e_alloc_path:
exit_e_nospc:
    free(child);
exit_e_alloc_child:
    return err;
}

static int jfat_new_file(jfat_context *cxt, jfat_open_file *parent,
                         const char *name, mode_t mode, uid_t uid, gid_t gid)
{
    size_t name_size = strlen(name);
    jfat_dirent *child = (jfat_dirent *)malloc(sizeof(jfat_dirent) + name_size);
    if (child == NULL) {
        return -errno;
    }
    memset(child, 0, sizeof(jfat_dirent));

    child->size = 0;

    uint64_t ns = now();
    child->accessed = ns;
    child->modified = ns;
    child->changed = ns;

    child->data = JFAT_EOF;

    child->uid = uid;
    child->gid = gid;
    child->mode = mode;

    child->name_size = name_size;
    child->ent_size = sizeof(jfat_dirent) + child->name_size;

    strncpy((char *)child + sizeof(jfat_dirent), name, name_size);

    int err = jfat_add_child(cxt, parent, child);
    free(child);

    if (err == 0) {
        ++cxt->super.num_files;
        jfat_touch_super(cxt);
    }

    return err;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Management Definitions
////////////////////////////////////////////////////////////////////////////////////////////////////

static int jfat_format(int dev_fd)
{
    int err = 0;

    // Create the super block
    jfat_super_block_padded psuper;
    memset(&psuper, 0, sizeof(psuper));

    uint64_t ns = now();

    psuper.super = (jfat_super_block) {
        .fat_blocks         = DEFAULT_FAT_BLOCKS,
        .data_blocks        = DEFAULT_DATA_BLOCKS,
        .num_files          = 1, // Root directory is the only file
        .free_data_blocks   = DEFAULT_DATA_BLOCKS,
        .magic_number       = JFAT_MAGIC_NUMBER,
        .block_size         = DEFAULT_BLOCK_SIZE,
        .first_free_block   = 0,
        .root_dir           = (jfat_dirent) {
            .size = 0,
            .accessed = ns,
            .modified = ns,
            .changed = ns,
            .data = JFAT_EOF,
            .uid = getuid(),
            .gid = getgid(),
            .mode = S_IFDIR | S_IRWXU
        },
        .clean_shutdown     = true
    };
    jfat_serialize_super_block(&psuper);
    err = jfat_pwrite(dev_fd, &psuper, SUPER_BLOCK_SIZE, 0);
    if (err < 0) {
        goto exit_e_write_super;
    }

    jfat_super_block *super = &psuper.super;

    // Initialize the FAT
    size_t fat_size = super->block_size * super->fat_blocks;
    size_t fat_entries = MIN(fat_size / sizeof(blockaddr_t), super->data_blocks);
    blockaddr_t *fat = (blockaddr_t *)malloc(fat_size);
    if (fat == NULL) {
        err = -errno;
        goto exit_e_alloc_fat;
    }
    memset(fat, 0, fat_size);

    // All entries are free, each one points to the next
    size_t i;
    for (i = 0; i < fat_entries - 1; ++i) {
        fat[i] = i + 1;
    }

    // The last free block is JFAT_EOF to mark the end of the free list
    fat[fat_entries - 1] = JFAT_EOF;

    jfat_serialize_fat(fat, super->fat_blocks);
    err = jfat_write_blocks(dev_fd, super, 1, super->fat_blocks, fat);
    if (err < 0) {
        goto exit_e_write_fat;
    }

exit_e_write_fat:
    free(fat);
exit_e_alloc_fat:
exit_e_write_super:
    return err;
}

#ifndef DOXYGEN

typedef struct
{
    jfat_block_set  reachable_blocks;
    jfat_block_set  free_blocks;
    size_t          num_files;
} jfat_recovery_summary;

static int jfat_recover_callback(jfat_context *cxt, jfat_open_file *f, void *arg)
{
    jfat_recovery_summary *sum = (jfat_recovery_summary *)arg;

    ++sum->num_files;

    int err = 0;
    blockaddr_t block;
    size_t num_blocks = 0;
    jfat_file_traversal_state state = JFAT_FILE_TRAVERSAL_INIT;
    while ((err = jfat_traverse_file(cxt, f, &state, &block)) > 0) {
        ++num_blocks;
        if (jfat_block_set_find(&sum->reachable_blocks, block) !=
            jfat_block_set_end(&sum->reachable_blocks)) {
            ERROR("block %zu is owned by multiple files", (size_t)block);
            return -EINVAL;
        } else {
            err = jfat_block_set_insert(&sum->reachable_blocks, block);
            if (err < 0) {
                return err;
            }
        }
    }

    if (num_blocks * cxt->super.block_size < f->de->size) {
        ERROR("file %.*s has too few blocks (%zu blocks, %zu bytes per block, %zu bytes)",
            (int)f->key.len, f->key.path, num_blocks * cxt->super.block_size,
            (size_t)cxt->super.block_size, (size_t)f->de->size);
        return -EINVAL;
    }

    return err;
}

#endif

static int jfat_recover(jfat_context *cxt)
{
    int err = 0;

    jfat_open_file *root = jfat_get_open_file(cxt, "/");
    if (root == NULL) {
        err = -errno;
        goto exit_e_open_root;
    }

    jfat_recovery_summary sum;
    jfat_block_set_init(&sum.reachable_blocks);
    jfat_block_set_init(&sum.free_blocks);
    sum.num_files = 0;

    // Traverse all files, tracking reachable blocks
    err = jfat_nftw(cxt, root, jfat_recover_callback, &sum);
    if (err != 0) {
        ASSERT(err < 0);
        goto exit_e_nftw;
    }

    // Traverse the free list, tracking free blocks
    blockaddr_t block = cxt->super.first_free_block;
    while (block != JFAT_EOF) {
        if (jfat_block_set_find(&sum.free_blocks, block) != jfat_block_set_end(&sum.free_blocks)) {
            ERROR("block %zu appears on the free list twice", (size_t)block);
            err = -EINVAL;
            goto exit_e_consistency;
        } else if (jfat_block_set_find(&sum.reachable_blocks, block) !=
                   jfat_block_set_end(&sum.reachable_blocks)) {
            ERROR("block %zu appears on the free list and in a file", (size_t)block);
            err = -EINVAL;
            goto exit_e_consistency;
        } else {
            err = jfat_block_set_insert(&sum.free_blocks, block);
            if (err < 0) {
                goto exit_e_insert;
            }
        }

        block = jfat_get_fat(cxt, block);
    }

    // Add orphaned blocks to the free list
    for (block = 0; block < cxt->super.data_blocks; ++block) {
        if (jfat_block_set_find(&sum.reachable_blocks, block) ==
                jfat_block_set_end(&sum.reachable_blocks) &&
            jfat_block_set_find(&sum.free_blocks, block) == jfat_block_set_end(&sum.free_blocks)) {
            WARN("found orphaned block %zu, adding to free list", (size_t)block);
            jfat_free_block(cxt, block);
            err = jfat_block_set_insert(&sum.free_blocks, block);
            if (err < 0) {
                goto exit_e_insert;
            }
        }
    }

    size_t reachable_blocks = jfat_block_set_size(&sum.reachable_blocks);
    size_t free_blocks = jfat_block_set_size(&sum.free_blocks);
    if (reachable_blocks + free_blocks != cxt->super.data_blocks) {
        ERROR("found %zu data blocks; super claims %zu",
            reachable_blocks + free_blocks, (size_t)cxt->super.data_blocks);
        err = -EINVAL;
        goto exit_e_consistency;
    }

    if (free_blocks != cxt->super.free_data_blocks) {
        WARN("found %zu free blocks; super claims %zu; correcting",
            free_blocks, (size_t)cxt->super.free_data_blocks);
        cxt->super.free_data_blocks = free_blocks;
        jfat_touch_super(cxt);
    }

    if (sum.num_files != cxt->super.num_files) {
        WARN("found %zu files; super claims %zu; correcting",
            sum.num_files, (size_t)cxt->super.num_files);
        cxt->super.num_files = sum.num_files;
        jfat_touch_super(cxt);
    }

    err = jfat_fs_sync(cxt);
    if (err < 0) {
        goto exit_e_sync;
    }

    DEBUG("recovery successful");

exit_e_sync:
exit_e_insert:
exit_e_consistency:
exit_e_nftw:
    jfat_release_open_file(cxt, root);
exit_e_open_root:

    if (err < 0) {
        jfat_print_fs(cxt, fopen("jfat-recovery.txt", "w"));
        INFO("invalid file system state dumped to jfat-recovery.txt");
    }

    return err;
}

#ifndef DOXYGEN

static int jfat_print_fs_callback(jfat_context *cxt, jfat_open_file *f, void *arg)
{
    FILE *out = (FILE *)arg;

    fprintf(out, "%.*s: ", (int)f->key.len, f->key.path);

    int err = 0;
    blockaddr_t block;
    jfat_file_traversal_state state = JFAT_FILE_TRAVERSAL_INIT;
    while ((err = jfat_traverse_file(cxt, f, &state, &block)) > 0) {
        fprintf(out, "%zu", (size_t)block);
        if (jfat_get_fat(cxt, block) != JFAT_EOF) {
            fprintf(out, " -> ");
        }
    }
    fprintf(out, "\n");

    return err;
}

#endif

static int jfat_print_fs(jfat_context *cxt, FILE *out)
{
    jfat_open_file *root = jfat_get_open_file(cxt, "/");
    if (root == NULL) {
        return -errno;
    }

    int err = jfat_nftw(cxt, root, jfat_print_fs_callback, out);
    if (err != 0) {
        ASSERT(err < 0);
        return err;
    }

    fprintf(out, "Free: ");
    blockaddr_t block = cxt->super.first_free_block;
    while (block != JFAT_EOF) {
        fprintf(out, "%zu", (size_t)block);

        block = jfat_get_fat(cxt, block);
        if (block != JFAT_EOF) {
            fprintf(out, " -> ");
        }
    }
    fprintf(out, "\n");

    return 0;
}

/**
 * \defgroup fuse FUSE Protocol
 *
 * @{
 */

static void *jfat_init(struct fuse_conn_info *conn)
{
    (void)conn;

    int err;

    jfat_context *cxt = (jfat_context *)malloc(sizeof(jfat_context));
    if (cxt == NULL) {
        ERROR("mount failed: cannot allocate in-memory context (%s)", strerror(errno));
        exit(ERR_MOUNT_FAILED);
    }

    struct stat dev_stat;
    if (stat(dev_path, &dev_stat) < 0) {
        WARN("cannot stat device %s (%s); attempting create and format new file system",
            strerror(errno), dev_path);

        cxt->dev_fd = open(dev_path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
        if (cxt->dev_fd < 0) {
            ERROR("mount failed: cannot create file %s (%s)", dev_path, strerror(errno));
            exit(ERR_MOUNT_FAILED);
        }
        if (ftruncate(cxt->dev_fd, DEFAULT_FILE_SYSTEM_SIZE) < 0) {
            ERROR("mount failed: cannot truncate new backing file %s (%s)",
                dev_path, strerror(errno));
            exit(ERR_MOUNT_FAILED);
        }

        err = jfat_format(cxt->dev_fd);
        if (err < 0) {
            ERROR("mount failed: cannot format new file system (%s)", strerror(-err));
            exit(ERR_MOUNT_FAILED);
        }
    } else {
        cxt->dev_fd = open(dev_path, O_RDWR);
        if (cxt->dev_fd < 0) {
            ERROR("mount failed: cannot open %s (%s)", dev_path, strerror(errno));
            exit(ERR_MOUNT_FAILED);
        }
    }

    // Read the super block to get file system parameters
    jfat_super_block_padded psuper;
    err = jfat_pread(cxt->dev_fd, &psuper, SUPER_BLOCK_SIZE, 0);
    if (err < 0) {
        ERROR("mount failed: cannot read super block (%s)", strerror(-err));
        exit(ERR_MOUNT_FAILED);
    }
    jfat_deserialize_super_block(&psuper);
    cxt->super = psuper.super;

    if (cxt->super.magic_number != JFAT_MAGIC_NUMBER) {
        ERROR("%s does not contain a JFAT file system", dev_path);
        exit(ERR_MOUNT_FAILED);
    }

    // Bring the FAT into memory
    cxt->fat = (blockaddr_t *)malloc(cxt->super.block_size*cxt->super.fat_blocks);
    if (cxt->fat == NULL) {
        ERROR("mount failed: cannot allocate FAT in memory (%s)", strerror(errno));
        exit(ERR_MOUNT_FAILED);
    }
    err = jfat_read_blocks(cxt->dev_fd, &cxt->super, 1, cxt->super.fat_blocks, cxt->fat);
    if (err < 0) {
        ERROR("mount failed: cannot read FAT (%s)", strerror(errno));
        exit(ERR_MOUNT_FAILED);
    }
    jfat_deserialize_fat(cxt->fat, cxt->super.fat_blocks);

    jfat_block_set_init(&cxt->fat_dirty);
    jfat_init_open_files(cxt);
    jfat_init_open_blocks(cxt);

    if (!cxt->super.clean_shutdown) {
        WARN("detected unclean shutdown, attempting repair");
        err = jfat_recover(cxt);
        if (err < 0) {
            ERROR("file system repair failed: %s", strerror(-err));
            exit(ERR_MOUNT_FAILED);
        } else {
            INFO("file system successfully repaired");
        }
    }

    cxt->super.clean_shutdown = false;
    cxt->super_dirty = true;
    err = jfat_flush_super_block(cxt);
    if (err < 0) {
        ERROR("mount failed: cannot flush super block (%s)", strerror(-err));
        exit(ERR_MOUNT_FAILED);
    }

    DEBUG("mount succeeded:");
    DEBUG("   fat blocks        = %zu", (size_t)cxt->super.fat_blocks);
    DEBUG("   data blocks       = %zu", (size_t)cxt->super.data_blocks);
    DEBUG("   number of files   = %zu", (size_t)cxt->super.num_files);
    DEBUG("   free blocks       = %zu", (size_t)cxt->super.free_data_blocks);
    DEBUG("   block size        = %zu", (size_t)cxt->super.block_size);

    if (getenv("JFAT_DUMP_STATE") != NULL) {
        jfat_print_fs(cxt, fopen("jfat-mount-state.txt", "w"));
        INFO("state dumped: jfat-mount-state.txt");
    }

    return cxt;
}

static void jfat_destroy(void *private_data)
{
    int err = 0;

    jfat_context *cxt = (jfat_context *)private_data;

    err = jfat_fs_sync(cxt);
    if (err < 0) {
        ERROR("error while syncing file system: %s", strerror(-err));
    } else {
        cxt->super.clean_shutdown = true;
        cxt->super_dirty = true;
        err = jfat_flush_super_block(cxt);
        if (err < 0) {
            ERROR("error while flushing super block: %s", strerror(-err));
        }
    }

    if (getenv("JFAT_DUMP_STATE") != NULL) {
        jfat_print_fs(cxt, fopen("jfat-unmount-state.txt", "w"));
        INFO("state dumped: jfat-unmount-state.txt");
    }

    if (close(cxt->dev_fd) < 0) {
        ERROR("error on closing device: %s", strerror(errno));
    }

    jfat_block_set_destroy(&cxt->fat_dirty);

    err = jfat_destroy_open_blocks(cxt);
    if (err < 0) {
        ERROR("error while flushing block cache: %s", strerror(-err));
    }

    err = jfat_destroy_open_files(cxt);
    if (err < 0) {
        ERROR("error while closing open files: %s", strerror(-err));
    }

    free(cxt->fat);
    free(cxt);
}

static int jfat_fgetattr(const char *path, struct stat *st, struct fuse_file_info *fi)
{
    (void)path;

    jfat_context *cxt = jfat_get_context();

    jfat_open_file *f = (jfat_open_file *)fi->fh;

    // Set the device id to the device containg the backing file
    if (fstat(cxt->dev_fd, st) < 0) {
        WARN("could not stat backing device: %s", strerror(errno));
        st->st_dev = 0;
    }

    jfat_dirent *de = f->de;

    st->st_ino = jfat_dirent_id(&cxt->super, f->de_block, f->de_offset);
    st->st_mode = de->mode;
    st->st_nlink = S_ISDIR(de->mode) ? 3 : 1; // Directories always have 3 links: a parent, ., and ..
    st->st_uid = de->uid;
    st->st_gid = de->gid;
    st->st_rdev = 0;
    st->st_size = de->size;
    st->st_blksize = cxt->super.block_size;
    st->st_blocks = de->size / 512
                  + (de->size % 512 != 0); // Add 1 if there's a partial last block.
    st->st_atim = jfat_access_time(de);
    st->st_mtim = jfat_modify_time(de);
    st->st_ctim = jfat_change_time(de);


    return 0;
}

static int jfat_getattr(const char *path, struct stat *st)
{
    jfat_context *cxt = jfat_get_context();

    jfat_open_file *f = jfat_get_open_file(cxt, path);
    if (f == NULL) {
        return -errno;
    }

    struct fuse_file_info fi;
    fi.fh = (intptr_t)f;

    int ret = jfat_fgetattr(path, st, &fi);

    jfat_release_open_file(cxt, f);

    return ret;
}

static int jfat_access(const char *path, int mask)
{
    int err = 0;

    jfat_context *cxt = jfat_get_context();

    jfat_open_file *f = jfat_get_open_file(cxt, path);
    if (f == NULL) {
        return -errno;
    }

    if (mask & F_OK) {
        err = (mask & ~F_OK) == 0 ? 0 : -EINVAL;
    } else {
        struct fuse_context *fuse_cxt = fuse_get_context();
        uid_t uid = fuse_cxt->uid;
        gid_t gid = fuse_cxt->gid;

        if (  ((mask & R_OK) && !jfat_can_read(f->de, uid, gid))
           || ((mask & W_OK) && !jfat_can_write(f->de, uid, gid))
           || ((mask & X_OK) && !jfat_can_execute(f->de, uid, gid))
           ) {
            err = -EACCES;
        } else {
            err = (mask & ~R_OK & ~W_OK & ~X_OK) == 0 ? 0 : -EINVAL;
        }
    }

    jfat_release_open_file(cxt, f);
    return err;
}

static int jfat_readlink(const char *path, char *buf, size_t size)
{
    int err = 0;

    jfat_context *cxt = jfat_get_context();

    jfat_open_file *f = jfat_get_open_file(cxt, path);
    if (f == NULL) {
        err = -errno;
        goto exit_e_open;
    }

    if (!S_ISLNK(f->de->mode)) {
        err = -EINVAL;
        goto exit_e_inval;
    }

    err = jfat_transfer_data(cxt, f, buf, MIN(size - 1, f->de->size), 0, TRANSFER_FROM);
    if (err < 0) {
        goto exit_e_transfer;
    } else {
        buf[err] = '\0';
        err = 0;
    }

exit_e_transfer:
exit_e_inval:
    jfat_release_open_file(cxt, f);
exit_e_open:
    return err;
}

static int jfat_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi)
{
    (void)path;
    (void)offset;

    int err = 0;

    jfat_context *cxt = jfat_get_context();
    jfat_open_file *f = (jfat_open_file *)fi->fh;
    if (!S_ISDIR(f->de->mode)) {
        err = -ENOTDIR;
        goto exit_e_notdir;
    }

    struct fuse_context *fuse_cxt = fuse_get_context();
    if (!jfat_can_read(f->de, fuse_cxt->uid, fuse_cxt->gid)) {
        err = -EACCES;
        goto exit_e_access;
    }

    // . and ..
    if (filler(buf, ".", NULL, 0)) {
        return 0;
    }
    if (filler(buf, "..", NULL, 0)) {
        return 0;
    }

    jfat_directory_traversal_state state = JFAT_DIRECTORY_TRAVERSAL_INIT;
    jfat_dirent de;
    while ((err = jfat_traverse_directory(cxt, f, &state, &de)) > 0) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = jfat_dirent_id(&cxt->super, state.block, state.offset);
        st.st_mode = de.mode;

        // Names in dirents are denoted by pointer and length, so we need to conver the name to a
        // null-terminated string.
        char *name = (char *)malloc(de.name_size + 1);
        if (name == NULL) {
            err = -errno;
            goto exit_e_alloc_name;
        }
        err = jfat_bread(cxt, state.block, state.offset + sizeof(jfat_dirent), de.name_size, name);
        if (err < 0) {
            free(name);
            goto exit_e_read_name;
        }
        name[de.name_size] = '\0';

        int full = filler(buf, name, &st, 0);
        free(name);
        if (full) {
            err = 0;
            break;
        }
    }

exit_e_read_name:
exit_e_alloc_name:
exit_e_access:
exit_e_notdir:
    return err;
}

static int jfat_mknod(const char *path, mode_t mode, dev_t rdev)
{
    (void)rdev;

    int err = 0;
    jfat_context *cxt = jfat_get_context();

    struct fuse_context *fuse_cxt = fuse_get_context();
    uid_t uid = fuse_cxt->uid;
    gid_t gid = fuse_cxt->gid;

    mode = mode & ~fuse_cxt->umask;

    // Check that mode is supported
    if (!(S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode))) {
        err = -EACCES;
        goto exit_e_mode;
    }

    // Split the path into the path to the parent directory and the name of the child to create
    size_t path_len = strlen(path);
    char *parent_path = (char *)malloc(path_len + 1);
    if (parent_path == NULL) {
        err = -errno;
        goto exit_e_alloc_path;
    }
    char *name = NULL;
    const char *c;
    for (c = path + path_len; c >= path; --c) {
        size_t i = c - path;
        if (*c == '/' && !name) {
            parent_path[i] = '\0';
            name = parent_path + i + 1;
        } else {
            parent_path[i] = *c;
        }
    }

    jfat_open_file *parent = jfat_get_open_file(cxt, parent_path);
    if (parent == NULL) {
        err = -errno;
        goto exit_e_open_parent;
    }

    if (!jfat_can_write(parent->de, uid, gid)) {
        err = -EACCES;
        goto exit_e_access;
    }

    err = jfat_new_file(cxt, parent, name, mode, uid, gid);
    if (err < 0) {
        goto exit_e_add_child;
    }

    // Update parent timestamps
    uint64_t ns = now();
    parent->de->accessed = ns;
    parent->de->modified = ns;
    parent->de->changed = ns;
    err = jfat_touch_open_file(cxt, parent);
    if (err < 0) {
        goto exit_e_touch;
    }

    jfat_fs_sync(cxt);

exit_e_touch:
exit_e_add_child:
exit_e_access:
    jfat_release_open_file(cxt, parent);
exit_e_open_parent:
    free(parent_path);
exit_e_alloc_path:
exit_e_mode:
    return err;
}

static int jfat_mkdir(const char *path, mode_t mode)
{
    return jfat_mknod(path, mode | S_IFDIR, 0);
}

static int jfat_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    jfat_context *cxt = jfat_get_context();

    jfat_open_file *f = jfat_get_open_file(cxt, path);
    if (f == NULL) {
        if (errno == ENOENT) {
            int err = jfat_mknod(path, mode | S_IFREG, 0);
            if (err < 0) {
                return err;
            }

            f = jfat_get_open_file(cxt, path);
            if (f == NULL) {
                return -errno;
            }
        } else {
            return -errno;
        }
    }

    fi->fh = (intptr_t)f;
    return 0;
}

static int jfat_unlink(const char *path)
{
    int err = 0;

    jfat_context *cxt = jfat_get_context();

    jfat_open_file *f = jfat_get_open_file(cxt, path);
    if (f == NULL) {
        err = -errno;
        goto exit_e_open;
    }

    // Open parent to remove link
    size_t path_len = strlen(path);
    size_t parent_path_len = path_len;
    while (parent_path_len > 0 && path[parent_path_len] != '/') {
        --parent_path_len;
    }
    jfat_open_file *parent = jfat_get_open_file_n(cxt, path, parent_path_len);
    if (parent == NULL) {
        err = -errno;
        goto exit_e_open_parent;
    }

    // Check permissions
    struct fuse_context *fuse_cxt = fuse_get_context();
    uid_t uid = fuse_cxt->uid;
    gid_t gid = fuse_cxt->gid;
    if (!jfat_can_write(parent->de, uid, gid)) {
        err = -EACCES;
        goto exit_e_access;
    }

    err = jfat_remove_child(cxt, parent, f);
    if (err < 0) {
        goto exit_e_remove;
    }

    f->marked_for_deletion = true;

    // Update parent timestamps
    uint64_t ns = now();
    parent->de->accessed = ns;
    parent->de->modified = ns;
    parent->de->changed = ns;
    err = jfat_touch_open_file(cxt, parent);
    if (err < 0) {
        goto exit_e_touch;
    }

    err = jfat_fs_sync(cxt);
    if (err < 0) {
        goto exit_e_sync;
    }

exit_e_sync:
exit_e_touch:
exit_e_remove:
exit_e_access:
    jfat_release_open_file(cxt, parent);
exit_e_open_parent:
    jfat_release_open_file(cxt, f);
exit_e_open:
    return err;
}

static int jfat_rmdir(const char *path)
{
    int err = 0;

    jfat_context *cxt = jfat_get_context();

    jfat_open_file *f = jfat_get_open_file(cxt, path);
    if (f == NULL) {
        err = -errno;
        goto exit_e_open;
    }

    if (!S_ISDIR(f->de->mode)) {
        err = -ENOTDIR;
        goto exit_e_notdir;
    }

    if (f->de->size != 0) {
        err = -ENOTEMPTY;
        goto exit_e_notempty;
    }
    ASSERT(f->de->data == JFAT_EOF);

    err = jfat_unlink(path);

exit_e_notempty:
exit_e_notdir:
    jfat_release_open_file(cxt, f);
exit_e_open:
    return err;
}

static int jfat_symlink(const char *to, const char *from)
{
    int err = 0;

    jfat_context *cxt = jfat_get_context();

    err = jfat_mknod(from, S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO, 0);
    if (err < 0) {
        goto exit_e_mknod;
    }

    jfat_open_file *f = jfat_get_open_file(cxt, from);
    if (f == NULL) {
        err = -errno;
        goto exit_e_open;
    }

    size_t size = strlen(to);
    err = jfat_truncate_file(cxt, f, size);
    if (err < 0) {
        goto exit_e_truncate;
    }

    err = jfat_transfer_data(cxt, f, (char *)to, size, 0, TRANSFER_TO);
    if (err < 0) {
        goto exit_e_transfer;
    }

    err = jfat_fs_sync(cxt);

exit_e_transfer:
exit_e_truncate:
    jfat_release_open_file(cxt, f);
exit_e_open:
exit_e_mknod:
    return err;
}

static int jfat_rename(const char *from, const char *to)
{
    (void)from;
    (void)to;
    JFAT_UNIMPLEMENTED;
}

static int jfat_link(const char *from, const char *to)
{
    (void)from;
    (void)to;
    JFAT_UNIMPLEMENTED;
}

static int jfat_chmod(const char *path, mode_t mode)
{
    int err = 0;

    jfat_context *cxt = jfat_get_context();

    jfat_open_file *f = jfat_get_open_file(cxt, path);
    if (f == NULL) {
        err = -errno;
        goto exit_e_open;
    }

    // Check permission
    struct fuse_context *fuse_cxt = fuse_get_context();
    uid_t uid = fuse_cxt->uid;
    if (uid != 0 && uid != f->de->uid) {
        err = -EACCES;
        goto exit_e_access;
    }

    f->de->mode &= ~07777;          // Unset current mode
    f->de->mode |= (mode & 07777);  // Reset with new mode
    f->de->changed = now();

    err = jfat_touch_open_file(cxt, f);
    if (err < 0) {
        goto exit_e_touch;
    }

    err = jfat_fs_sync(cxt);
    if (err < 0) {
        goto exit_e_sync;
    }

exit_e_sync:
exit_e_touch:
exit_e_access:
    jfat_release_open_file(cxt, f);
exit_e_open:
    return err;
}

static int jfat_chown(const char *path, uid_t uid, gid_t gid)
{
    int err = 0;

    jfat_context *cxt = jfat_get_context();

    jfat_open_file *f = jfat_get_open_file(cxt, path);
    if (f == NULL) {
        err = -errno;
        goto exit_e_open;
    }

    // Check permissions
    struct fuse_context *fuse_cxt = fuse_get_context();
    INFO("uid=%u", (unsigned)fuse_cxt->uid);
    if (uid != (uid_t)-1 && fuse_cxt->uid != 0) {
        // Only root can change owner
        err = -EPERM;
        goto exit_e_perm;
    }
    if (gid != (gid_t)-1 && !(fuse_cxt->uid == 0 || fuse_cxt->uid == f->de->uid)) {
        // Only root or the owner of the file can change the group
        err = -EPERM;
        goto exit_e_perm;
    }

    if (uid != (uid_t)-1) f->de->uid = uid;
    if (gid != (gid_t)-1) f->de->gid = gid;
    f->de->changed = now();

    err = jfat_touch_open_file(cxt, f);
    if (err < 0) {
        goto exit_e_touch;
    }

    err = jfat_fs_sync(cxt);
    if (err < 0) {
        goto exit_e_sync;
    }

exit_e_sync:
exit_e_touch:
exit_e_perm:
    jfat_release_open_file(cxt, f);
exit_e_open:
    return err;
}

static int jfat_truncate(const char *path, off_t size)
{
    int err = 0;

    jfat_context *cxt = jfat_get_context();

    jfat_open_file *f = jfat_get_open_file(cxt, path);
    if (f == NULL) {
        err = -errno;
        goto exit_e_open;
    }

    // Check permissions
    struct fuse_context *fuse_cxt = fuse_get_context();
    uid_t uid = fuse_cxt->uid;
    gid_t gid = fuse_cxt->gid;
    if (!jfat_can_write(f->de, uid, gid)) {
        err = -EACCES;
        goto exit_e_access;
    }

    err = jfat_truncate_file(cxt, f, size);
    if (err < 0) {
        goto exit_e_truncate;
    }

    // Update modify/change time
    uint64_t ns = now();
    f->de->modified = ns;
    f->de->changed = ns;
    err = jfat_touch_open_file(cxt, f);
    if (err < 0) {
        goto exit_e_touch;
    }

    err = jfat_fs_sync(cxt);

exit_e_touch:
exit_e_truncate:
exit_e_access:
    jfat_release_open_file(cxt, f);
exit_e_open:
    return err;
}

static int jfat_utimens(const char *path, const struct timespec ts[2])
{
    int err = 0;

    jfat_context *cxt = jfat_get_context();

    jfat_open_file *f = jfat_get_open_file(cxt, path);
    if (f == NULL) {
        err = -errno;
        goto exit_e_open;
    }

    // Check permissions
    struct fuse_context *fuse_cxt = fuse_get_context();
    uid_t uid = fuse_cxt->uid;
    gid_t gid = fuse_cxt->gid;
    if (uid != f->de->uid && !jfat_can_write(f->de, uid, gid)) {
        err = -EACCES;
        goto exit_e_access;
    }

    f->de->accessed = timespec_to_ns(ts[0]);
    f->de->modified = timespec_to_ns(ts[1]);

    err = jfat_touch_open_file(cxt, f);
    if (err < 0) {
        goto exit_e_touch;
    }

    err = jfat_fs_sync(cxt);
    if (err < 0) {
        goto exit_e_sync;
    }

exit_e_sync:
exit_e_touch:
exit_e_access:
    jfat_release_open_file(cxt, f);
exit_e_open:
    return err;
}

static int jfat_open(const char *path, struct fuse_file_info *fi)
{
    jfat_context *cxt = jfat_get_context();

    jfat_open_file *f = jfat_get_open_file(cxt, path);
    if (f == NULL) {
        return -errno;
    }

    fi->fh = (intptr_t)f;
    return 0;
}

static int jfat_opendir(const char *path, struct fuse_file_info *fi)
{
    return jfat_open(path, fi);
}

static int jfat_read(
    const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    (void)path;

    int err = 0;

    if (offset < 0) {
        err = -EINVAL;
        goto exit_e_inval;
    }

    jfat_context *cxt = jfat_get_context();
    jfat_open_file *f = (jfat_open_file *)fi->fh;
    if (!S_ISREG(f->de->mode)) {
        err = -EISDIR;
        goto exit_e_isdir;
    }

    struct fuse_context *fuse_cxt = fuse_get_context();
    if (!jfat_can_read(f->de, fuse_cxt->uid, fuse_cxt->gid)) {
        err = -EACCES;
        goto exit_e_access;
    }

    int nbytes = jfat_transfer_data(cxt, f, buf, size, offset, TRANSFER_FROM);
    if (nbytes < 0) {
        err = nbytes;
        goto exit_e_transfer;
    }

    // Set access time
    f->de->accessed = now();
    err = jfat_touch_open_file(cxt, f);
    if (err < 0) {
        goto exit_e_touch;
    }
    err = jfat_fs_sync(cxt);
    if (err < 0) {
        goto exit_e_sync;
    }

    err = nbytes;

exit_e_sync:
exit_e_touch:
exit_e_transfer:
exit_e_access:
exit_e_isdir:
exit_e_inval:
    return err;
}

static int jfat_write(
    const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    (void)path;

    int err = 0;

    if (offset < 0) {
        err = -EINVAL;
        goto exit_e_inval;
    }

    jfat_context *cxt = jfat_get_context();
    jfat_open_file *f = (jfat_open_file *)fi->fh;
    if (!S_ISREG(f->de->mode)) {
        err = -EISDIR;
        goto exit_e_isdir;
    }

    struct fuse_context *fuse_cxt = fuse_get_context();
    if (!jfat_can_write(f->de, fuse_cxt->uid, fuse_cxt->gid)) {
        err = -EACCES;
        goto exit_e_access;
    }

    if (offset + size > f->de->size) {
        DEBUG("truncating file for write (from %zu to %zu)", f->de->size, (size_t)(offset + size));
        int err = jfat_truncate_file(cxt, f, offset + size);
        if (err < 0) {
            goto exit_e_truncate;
        }
    }

    int nbytes = jfat_transfer_data(cxt, f, (void *)buf, size, offset, TRANSFER_TO);
    if (nbytes < 0) {
        err = nbytes;
        goto exit_e_transfer;
    }

    // Udate modify time
    uint64_t ns = now();
    f->de->modified = ns;
    err = jfat_touch_open_file(cxt, f);
    if (err < 0) {
        goto exit_e_touch;
    }

    err = jfat_fs_sync(cxt);
    if (err < 0) {
        goto exit_e_sync;
    }

    err = nbytes;

exit_e_sync:
exit_e_touch:
exit_e_transfer:
exit_e_truncate:
exit_e_access:
exit_e_isdir:
exit_e_inval:
    return err;
}

static int jfat_statfs(const char *path, struct statvfs *st)
{
    (void)path;

    jfat_context *cxt = jfat_get_context();

    st->f_bsize = cxt->super.block_size;
    st->f_frsize = st->f_bsize; // No fragments
    st->f_blocks = cxt->super.data_blocks;
    st->f_bfree = cxt->super.free_data_blocks;
    st->f_bavail = st->f_bfree; // All free blocks are available to all users

    st->f_files = cxt->super.num_files;

    st->f_fsid = 0;
    st->f_flag = 0;
    st->f_namemax = cxt->super.block_size - sizeof(jfat_dirent);

    return 0;
}

static int jfat_release(const char *path, struct fuse_file_info *fi)
{
    (void)path;

    jfat_release_open_file(jfat_get_context(), (jfat_open_file *)fi->fh);
    return 0;
}

static int jfat_releasedir(const char *path, struct fuse_file_info *fi)
{
    return jfat_release(path, fi);
}

static int jfat_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) isdatasync;
    (void) fi;
    return 0;
}

static struct fuse_operations jfat_oper = {
    .init       = jfat_init,
    .destroy    = jfat_destroy,
    .fgetattr   = jfat_fgetattr,
    .getattr    = jfat_getattr,
    .access     = jfat_access,
    .readlink   = jfat_readlink,
    .readdir    = jfat_readdir,
    .mknod      = jfat_mknod,
    .mkdir      = jfat_mkdir,
    .create     = jfat_create,
    .symlink    = jfat_symlink,
    .unlink     = jfat_unlink,
    .rmdir      = jfat_rmdir,
    .rename     = jfat_rename,
    .link       = jfat_link,
    .chmod      = jfat_chmod,
    .chown      = jfat_chown,
    .truncate   = jfat_truncate,
    .utimens    = jfat_utimens,
    .open       = jfat_open,
    .opendir    = jfat_opendir,
    .read       = jfat_read,
    .write      = jfat_write,
    .statfs     = jfat_statfs,
    .release    = jfat_release,
    .releasedir = jfat_releasedir,
    .fsync      = jfat_fsync
};

/// @}
// end fuse

int main(int argc, char *argv[])
{
    little_endian = htons(1) != 1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [fuse-options] <mnt> <device>\n", argv[0]);
        exit(ERR_USAGE);
    }

    dev_path = argv[argc-1];

    const char *ll = getenv("JFAT_LOG_LEVEL");
    if (ll != NULL) {
        log_level = atoi(ll);
    }

    umask(0);
    return fuse_main(argc - 1, argv, &jfat_oper, NULL);
}
