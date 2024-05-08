#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <archive.h>
#include <archive_entry.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>  // For dirname
#include <errno.h>

#define CHUNK_SIZE 102400 // Chunk size of 100 KB

// Function to create directories recursively
int create_dir_recursively(const char *dir_path, mode_t mode) {
    char tmp[1024];
    strncpy(tmp, dir_path, sizeof(tmp));
    tmp[sizeof(tmp) - 1] = '\0';
    char *p = NULL;

    // Iterate over subpaths and create directories as needed
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                return -1; // Fail if unable to create directory and it doesn't already exist
            }
            *p = '/';
        }
    }
    return mkdir(tmp, mode);
}

int main(int argc, char *argv[]) {
    void *libarchive_handle;
    struct archive *(*archive_read_new)();
    int (*archive_read_support_filter_all)(struct archive *);
    int (*archive_read_support_format_all)(struct archive *);
    int (*archive_read_open_filename)(struct archive *, const char *, size_t);
    struct archive_entry *(*archive_read_next_header)(struct archive *, struct archive_entry **);
    int (*archive_read_free)(struct archive *);
    ssize_t (*archive_read_data)(struct archive *, void *, size_t);
    const char *(*archive_entry_pathname)(struct archive_entry *);
    int64_t (*archive_entry_size)(struct archive_entry *);
    unsigned int (*archive_entry_filetype)(const struct archive_entry *);
    const char *(*archive_entry_symlink)(struct archive_entry *);
    struct archive *(*archive_write_disk_new)();
    int (*archive_write_disk_set_options)(struct archive *, int);
    int (*archive_write_header)(struct archive *, struct archive_entry *);
    int (*archive_write_finish_entry)(struct archive *);
    int (*archive_write_free)(struct archive *);
    const char *(*archive_error_string)(struct archive *);
    mode_t (*archive_entry_mode)(struct archive_entry *);

    // Load the dynamic library
    libarchive_handle = dlopen("libarchive.dylib", RTLD_LAZY);
    if (!libarchive_handle) {
        fprintf(stderr, "Failed to load libarchive.\n");
        exit(1);
    }

    // Load the necessary libarchive functions
    archive_read_new = dlsym(libarchive_handle, "archive_read_new");
    archive_read_support_filter_all = dlsym(libarchive_handle, "archive_read_support_filter_all");
    archive_read_support_format_all = dlsym(libarchive_handle, "archive_read_support_format_all");
    archive_read_open_filename = dlsym(libarchive_handle, "archive_read_open_filename");
    archive_read_next_header = dlsym(libarchive_handle, "archive_read_next_header");
    archive_read_free = dlsym(libarchive_handle, "archive_read_free");
    archive_read_data = dlsym(libarchive_handle, "archive_read_data");
    archive_entry_pathname = dlsym(libarchive_handle, "archive_entry_pathname");
    archive_entry_size = dlsym(libarchive_handle, "archive_entry_size");
    archive_entry_filetype = dlsym(libarchive_handle, "archive_entry_filetype");
    archive_entry_symlink = dlsym(libarchive_handle, "archive_entry_symlink");
    archive_write_disk_new = dlsym(libarchive_handle, "archive_write_disk_new");
    archive_write_disk_set_options = dlsym(libarchive_handle, "archive_write_disk_set_options");
    archive_write_header = dlsym(libarchive_handle, "archive_write_header");
    archive_write_finish_entry = dlsym(libarchive_handle, "archive_write_finish_entry");
    archive_write_free = dlsym(libarchive_handle, "archive_write_free");
    archive_error_string = dlsym(libarchive_handle, "archive_error_string");
    archive_entry_mode = dlsym(libarchive_handle, "archive_entry_mode");

    if (!archive_read_new || !archive_read_support_filter_all || !archive_read_support_format_all ||
        !archive_read_open_filename || !archive_read_next_header || !archive_read_free ||
        !archive_read_data || !archive_entry_pathname || !archive_entry_size ||
        !archive_entry_filetype || !archive_entry_symlink || !archive_write_disk_new ||
        !archive_write_disk_set_options || !archive_write_header ||
        !archive_write_finish_entry || !archive_write_free || !archive_error_string ||
        !archive_entry_mode ) {
        fprintf(stderr, "Failed to load functions.\n");
        exit(1);
    }

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <archive_name> <output_directory>\n", argv[0]);
        exit(1);
    }

    struct archive *a;
    struct archive *a_disk;
    struct archive_entry *entry;
    int r;

    a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    r = archive_read_open_filename(a, argv[1], 10240);  // Block size 10 KB
    if (r != ARCHIVE_OK) {
        fprintf(stderr, "Could not open archive: %s\n", argv[1]);
        exit(1);
    }

    // Ensure output directory exists; create it if not
    struct stat st = {0};
    if (stat(argv[2], &st) == -1) {
        mkdir(argv[2], 0755);
    }

    long runningTotal = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *path = archive_entry_pathname(entry);
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", argv[2], path);
        mode_t mode = archive_entry_mode(entry);
    
        
        switch (archive_entry_filetype(entry)) {
            case AE_IFREG: {
                char *dir = dirname(full_path);
                if( create_dir_recursively(dir, 0755) != 0 ) {
                    if( errno != EEXIST ) {
                        char error[400];
                        snprintf( error, 400, "Failed to create dir: %s", dir );
                        perror( error );
                        continue;
                    }
                }
                
                // Check if the file exists and unlink if not writable
                struct stat file_stat;
                if (stat(full_path, &file_stat) == 0) {  // File exists
                    if (!(file_stat.st_mode & S_IWUSR)) {  // Check if file is not writable
                        if (unlink(full_path) != 0) {  // Attempt to delete the file
                            perror("Failed to delete existing file");
                            continue;
                        }
                    }
                }
                
                int fd = open(full_path, O_WRONLY | O_CREAT | O_TRUNC, mode);
                if (fd == -1) {
                    char error[400];
                    snprintf( error, 400, "Failed to open file for writing: %s",full_path );
                    perror( error );
                    continue;
                }
    
                //printf("Extracting: %s\n", full_path);
    
                size_t total = 0;
                ssize_t size;
                char buffer[CHUNK_SIZE];
                while ((size = archive_read_data(a, buffer, CHUNK_SIZE)) > 0) {
                    if (write(fd, buffer, size) != size) {
                        perror("Failed to write all bytes");
                        close(fd);
                        unlink(full_path);
                        break;
                    }
                    total += size;
                    if (total % CHUNK_SIZE == 0 || size < CHUNK_SIZE) {
                        //printf("%lu\n", size);
                        runningTotal += size;
                        if( runningTotal >= CHUNK_SIZE ) {
                            printf("%lu\n", runningTotal);
                            runningTotal = 0;
                        }
                        //printf("Written %lu KB of %s - Chunk=%lu\n", total / 1024, full_path, size);
                    }
                }
                close(fd);
                break;
            }
            case AE_IFDIR: {
                if (create_dir_recursively(full_path, mode) != 0) {
                    //perror("Failed to create directory");
                }
                break;
            }
            case AE_IFLNK: {
                const char *target = archive_entry_symlink(entry);
                symlink(target, full_path);
                break;
            }
        }
    
        // Set file attributes
        a_disk = archive_write_disk_new();
        archive_write_disk_set_options(a_disk, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS);
        archive_write_header(a_disk, entry);
        archive_write_finish_entry(a_disk);
        archive_write_free(a_disk);
    }
    if( runningTotal > 0 ) {
        printf("%lu\n", runningTotal);
    }

    archive_read_free(a);
    dlclose(libarchive_handle);

    return 0;
}
