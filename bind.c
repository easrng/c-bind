#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/*
 @Author	: ouadev
 @date		: December 2015

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.  No representations are made about the suitability of this
software for any purpose.  It is provided "as is" without express or
implied warranty.

 */

#ifndef H_PMPARSER
#define H_PMPARSER

// Documentation link:
// https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html

// maximum length of the name of an anonymous mapping
#define MAPPING_ANON_NAME_MAX_LEN 80

/**
 * @brief Type of a memory's region mapping.
 *
 */
typedef enum {
  PROCMAPS_MAP_FILE,
  PROCMAPS_MAP_STACK,
  PROCMAPS_MAP_STACK_TID,
  PROCMAPS_MAP_VDSO,
  PROCMAPS_MAP_VVAR,
  PROCMAPS_MAP_VSYSCALL,
  PROCMAPS_MAP_HEAP,
  PROCMAPS_MAP_ANON_PRIV,
  PROCMAPS_MAP_ANON_SHMEM,
  PROCMAPS_MAP_ANON_MMAPS,
  PROCMAPS_MAP_OTHER,
} procmaps_map_type;

/**
 * procmaps_struct
 * @desc hold all the information about an area in the process's  VM
 */
typedef struct procmaps_struct {
  void *addr_start; //< start address of the area
  void *addr_end;   //< end address
  size_t length;    //< size of the range
  short is_r;
  short is_w;
  short is_x;
  short is_p;
  size_t offset; //< offset
  unsigned int dev_major;
  unsigned int dev_minor;
  unsigned long long inode; //< inode of the file that backs the area
  char *pathname; //< the path of the file that backs the area ( dynamically
                  // allocated)
  procmaps_map_type map_type;
  char map_anon_name[MAPPING_ANON_NAME_MAX_LEN +
                     1]; //< name of the anonymous mapping in case map_type
                         // is an anon mapping
  short file_deleted;    //< whether the file backing the mapping was deleted
  // chained list
  struct procmaps_struct *next; //<handler of the chained list
} procmaps_struct;

/**
 * @brief procmaps error type
 *
 */
typedef enum procmaps_error {
  PROCMAPS_SUCCESS = 0,
  PROCMAPS_ERROR_OPEN_MAPS_FILE,
  PROCMAPS_ERROR_READ_MAPS_FILE,
  PROCMAPS_ERROR_MALLOC_FAIL,
} procmaps_error_t;

/**
 * procmaps_iterator
 * @desc holds iterating information
 */
typedef struct procmaps_iterator {
  procmaps_struct *head;
  procmaps_struct *current;
  size_t count;
} procmaps_iterator;

/**
 * @brief Main function to parse process memory
 * @param pid process ID
 * @param maps_it output : the memory region iterator over the chained list, t
 * should only be read when return is 0.
 * @return procmaps_error_t outcome of the function
 */
static procmaps_error_t pmparser_parse(int pid, procmaps_iterator *maps_it);

/**
 * pmparser_next
 * @description move between areas
 * @param p_procmaps_it the iterator to move on step in the chained list
 * @return a procmaps structure filled with information about this VM area
 */
static procmaps_struct *pmparser_next(procmaps_iterator *p_procmaps_it);
/**
 * pmparser_free
 * @description should be called at the end to free the resources
 * @param p_procmaps_it the iterator structure returned by pmparser_parse
 */
static void pmparser_free(procmaps_iterator *p_procmaps_it);

#endif

/*
 @Author	: ouadev
 @date		: December 2015

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.  No representations are made about the suitability of this
software for any purpose.  It is provided "as is" without express or
implied warranty.
*/

// maximum line length in a procmaps file
#define PROCMAPS_LINE_INIT_LENGTH (300)
// maximum length of the path of a maps file : /proc/[pid]/maps
#define PROCMAPS_MAPS_FILE_PATH_MAX_LENGTH 30
// maximum token size while parsing the proc/pid/maps
#define PROCMAPS_LINE_TOKEN_MAX_LEN 100

/**
 * pmparser_parse_line
 * @description internal usage
 */
static void pmparser_parse_line(char *buf, procmaps_struct *mem_reg);

/**
 * @brief Copy into dest_ptr the string from src_ptr to the first occurence of
 * delimiter
 */
static char *pmparser_helper_extract(char *src_ptr, const char *delimiter,
                                     char *dest_ptr);

/**
 * @brief Main function to parse process memory
 *
 * @param pid process ID
 * @param maps_it output : the memory region iterator over the chained list, it
 * should only be read when return is 0
 * @return procmaps_error_t outcome of the function
 */
static procmaps_error_t pmparser_parse(int pid, procmaps_iterator *maps_it) {
  char maps_path[PROCMAPS_MAPS_FILE_PATH_MAX_LENGTH];
  size_t line_len = 0;
  char *line_ptr = NULL;
  procmaps_struct *mem_reg = NULL;
  procmaps_struct *tail_node = NULL;
  procmaps_struct *head_node = NULL;
  size_t node_count = 0;

  if (pid >= 0) {
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  } else {
    sprintf(maps_path, "/proc/self/maps");
  }

  FILE *file = fopen(maps_path, "r");
  if (!file) {
    return PROCMAPS_ERROR_OPEN_MAPS_FILE;
  }

  // scan maps file line by line
  line_len = PROCMAPS_LINE_INIT_LENGTH;
  if ((line_ptr = (char *)malloc(line_len)) == NULL) {
    fclose(file);
    return PROCMAPS_ERROR_MALLOC_FAIL;
  }

  while (1) {
    int read = getline(&line_ptr, &line_len, file);
    if (read == -1) {
      if (!feof(file)) {
        return PROCMAPS_ERROR_READ_MAPS_FILE;
      } else {
        // end of file occured while no characters have been read
        break;
      }
    }

    // allocate a node
    mem_reg = (procmaps_struct *)malloc(sizeof(procmaps_struct));
    // fill the node
    pmparser_parse_line(line_ptr, mem_reg);
    mem_reg->next = NULL;

    // Attach the node
    if (tail_node == NULL) {
      head_node = tail_node = mem_reg;
    } else {
      tail_node->next = mem_reg;
      tail_node = mem_reg;
    }
    node_count++;
  }

  // close file
  fclose(file);
  free(line_ptr);

  // set iterator
  maps_it->head = maps_it->current = head_node;
  maps_it->count = node_count;

  return PROCMAPS_SUCCESS;
}

/**
 * @brief move the iterator to the next memory region
 *
 * @param p_procmaps_it
 * @return procmaps_struct*
 */
static procmaps_struct *pmparser_next(procmaps_iterator *p_procmaps_it) {
  if (p_procmaps_it->current == NULL)
    return NULL;
  procmaps_struct *p_current = p_procmaps_it->current;
  p_procmaps_it->current = p_procmaps_it->current->next;
  return p_current;
}

/**
 * @brief free the parser data
 *
 * @param p_procmaps_it
 */
static void pmparser_free(procmaps_iterator *p_procmaps_it) {
  procmaps_struct *cursor = p_procmaps_it->head;
  procmaps_struct *next = NULL;

  if (p_procmaps_it->head == NULL)
    return;

  while (cursor != NULL) {
    next = cursor->next;
    free(cursor->pathname);
    free(cursor);
    cursor = next;
  }
  memset(p_procmaps_it, 0x00, sizeof(procmaps_iterator));
}

static char *pmparser_helper_extract(char *src_ptr, const char *delimiter,
                                     char *dest_ptr) {
  char *p_separator = NULL;
  size_t copy_len = 0;

  p_separator = strstr(src_ptr, delimiter);
  copy_len = (p_separator - src_ptr);
  memcpy(dest_ptr, src_ptr, copy_len);
  dest_ptr[copy_len] = 0x00;

  return p_separator;
}

static void pmparser_parse_line(char *buf, procmaps_struct *mem_reg) {
  char token[PROCMAPS_LINE_TOKEN_MAX_LEN];
  size_t pathname_len = 0;
  char *p_cursor = buf;

  // addr1
  p_cursor = pmparser_helper_extract(p_cursor, "-", token);
  p_cursor++;

  sscanf(token, "%lx", (long unsigned *)&mem_reg->addr_start);

  // addr2
  p_cursor = pmparser_helper_extract(p_cursor, " ", token);
  p_cursor++;

  sscanf(token, "%lx", (long unsigned *)&mem_reg->addr_end);

  // region size
  mem_reg->length =
      (unsigned long)((char *)mem_reg->addr_end - (char *)mem_reg->addr_start);

  // perm
  p_cursor = pmparser_helper_extract(p_cursor, " ", token);
  p_cursor++;

  mem_reg->is_r = (token[0] == 'r');
  mem_reg->is_w = (token[1] == 'w');
  mem_reg->is_x = (token[2] == 'x');
  mem_reg->is_p = (token[3] == 'p');

  // offset
  p_cursor = pmparser_helper_extract(p_cursor, " ", token);
  p_cursor++;

  sscanf(token, "%lx", &mem_reg->offset);

  // dev
  p_cursor = pmparser_helper_extract(p_cursor, " ", token);
  p_cursor++;

  sscanf(token, "%u:%u", &mem_reg->dev_major, &mem_reg->dev_minor);

  // inode
  p_cursor = pmparser_helper_extract(p_cursor, " ", token);
  p_cursor++;

  sscanf(token, "%llu", &mem_reg->inode);

  // pathname
  // find the start of the pathname
  while (*p_cursor == '\t' || *p_cursor == ' ')
    p_cursor++;
  // calculate its size
  char *ptr_sz = p_cursor;
  while (*ptr_sz != '\n') {
    ptr_sz++;
  }
  pathname_len = (ptr_sz - p_cursor);
  // copy it
  mem_reg->pathname = (char *)malloc(pathname_len * sizeof(char) + 1);
  memcpy(mem_reg->pathname, p_cursor, pathname_len);
  mem_reg->pathname[pathname_len] = 0x00;

  // Pathname decoding
  if (mem_reg->pathname[0] == 0x00) {
    // empty path name
    mem_reg->map_type = PROCMAPS_MAP_ANON_MMAPS;
  } else if (strncmp(mem_reg->pathname, "[stack]", 7) == 0) {
    // mapping backed by main thread stack
    mem_reg->map_type = PROCMAPS_MAP_STACK;
  } else if (strncmp(mem_reg->pathname, "[stack:", 7) == 0) {
    mem_reg->map_type = PROCMAPS_MAP_STACK_TID;
  } else if (strncmp(mem_reg->pathname, "[vdso]", 6) == 0) {
    mem_reg->map_type = PROCMAPS_MAP_VDSO;
  } else if (strncmp(mem_reg->pathname, "[heap]", 6) == 0) {
    mem_reg->map_type = PROCMAPS_MAP_HEAP;
  } else if (strncmp(mem_reg->pathname, "[anon:", 6) == 0) {
    mem_reg->map_type = PROCMAPS_MAP_ANON_PRIV;
    pmparser_helper_extract(mem_reg->pathname + 6, "]", token);
    strncpy(mem_reg->map_anon_name, token, MAPPING_ANON_NAME_MAX_LEN);
  } else if (strncmp(mem_reg->pathname, "[anon_shmem:", 12) == 0) {
    mem_reg->map_type = PROCMAPS_MAP_ANON_SHMEM;
    pmparser_helper_extract(mem_reg->pathname + 12, "]", token);
    strncpy(mem_reg->map_anon_name, token, MAPPING_ANON_NAME_MAX_LEN);
  } else if (strncmp(mem_reg->pathname, "[vvar]", 6) == 0) {
    mem_reg->map_type = PROCMAPS_MAP_VVAR;
  } else if (strncmp(mem_reg->pathname, "[vsyscall]", 10) == 0) {
    mem_reg->map_type = PROCMAPS_MAP_VSYSCALL;
  } else if (strncmp(mem_reg->pathname, "[", 1) == 0) {
    mem_reg->map_type = PROCMAPS_MAP_OTHER;
  } else {
    // file backed mapping then
    mem_reg->map_type = PROCMAPS_MAP_FILE;

    // is the file deleted ?
    // file_deleted
    if (memcmp(mem_reg->pathname + strlen(mem_reg->pathname) - 9, "(deleted)",
               9) == 0) {
      mem_reg->file_deleted = 1;
    } else {
      mem_reg->file_deleted = 0;
    }
  }
}
static void *addr();
static unsigned long int shim(unsigned long int arg0) {
  void *self = addr();
  unsigned long int *ints =
      (unsigned long int *)(((unsigned long int)self) / 8 * 8);
  for (int i = 0;; i++) {
    if (ints[i] == 0x1234567890abcdef && ints[i - 3] == 0x1234567890abcdef) {
      unsigned long int (*real)(unsigned long int, unsigned long int) =
          (void *)ints[i - 2];
      return real(ints[i - 1], arg0);
    }
  }
}
static void *__attribute__((noinline)) addr() {
  return __builtin_extract_return_addr(__builtin_return_address(0));
}
void *bind(void *fn, void *arg0) {
  procmaps_error_t parser_err = PROCMAPS_SUCCESS;
  procmaps_iterator maps_iter = {0};
  parser_err = pmparser_parse(-1, &maps_iter);
  if (parser_err) {
    printf("parser err\n");
    return NULL;
  }
  procmaps_struct *mem_region = NULL;
  void *whoaddr = (void *)&shim;
  int pagesize = getpagesize();
  while ((mem_region = pmparser_next(&maps_iter)) != NULL) {
    if (whoaddr >= mem_region->addr_start && whoaddr <= mem_region->addr_end) {
      long unsigned int file_offset =
          mem_region->offset + (whoaddr - mem_region->addr_start);
      off_t mmap_offset = (file_offset / pagesize) * pagesize;
      int fd = open(mem_region->pathname, O_RDONLY);
      pmparser_free(&maps_iter);
      void *x = mmap(0, pagesize * 2, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd,
                     mmap_offset);
      close(fd);
      if (x == MAP_FAILED) {
        printf("mmap failed\n");
        return NULL;
      }
      if (mprotect(x + pagesize, pagesize, PROT_READ | PROT_WRITE) == -1) {
        printf("mprotect failed\n");
        return NULL;
      }
      unsigned long int *ints = x + pagesize;
      ints[0] = 0x1234567890abcdef;
      ints[1] = (unsigned long int)fn;
      ints[2] = (unsigned long int)arg0;
      ints[3] = 0x1234567890abcdef;
      void (*ptr)() = x + (file_offset - mmap_offset);
      return ptr;
    }
  }
  pmparser_free(&maps_iter);
  return NULL;
}
