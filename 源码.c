#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define VERSION            "Deam1.1"
#define BASE_CPUSET        "/dev/cpuset/DeamOpt"
#define MAX_PKG_LEN        128
#define MAX_THREAD_LEN     32

static const struct {
    const char* name;
    int policy;
} policy_map[] = {
    {"SCHED_OTHER", SCHED_OTHER},
    {"SCHED_FIFO", SCHED_FIFO},
    {"SCHED_RR", SCHED_RR},
    {NULL, 0}
};

typedef struct {
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
} AffinityRule;

typedef struct {
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    int policy;
    int priority;
} PriorityRule;

typedef struct {
    pid_t tid;
    char name[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
    int sched_policy;
    int sched_priority;
} ThreadInfo;

typedef struct {
    pid_t pid;
    char pkg[MAX_PKG_LEN];
    char base_cpuset[128];
    cpu_set_t base_cpus;
    ThreadInfo* threads;
    size_t num_threads;
    AffinityRule** thread_rules;
    size_t num_thread_rules;
} ProcessInfo;

typedef struct {
    cpu_set_t present_cpus;
    char present_str[128];
    char mems_str[32];
    bool cpuset_enabled;
    int base_cpuset_fd;
} CpuTopology;

typedef struct {
    AffinityRule* rules;
    size_t num_rules;
    PriorityRule* priority_rules;
    size_t num_priority_rules;
    time_t mtime;
    CpuTopology topo;
    char** pkgs;
    size_t num_pkgs;
    char config_file[4096];
    char priority_config[4096];
} AppConfig;

typedef struct {
    ProcessInfo* procs;
    size_t num_procs;
    int last_proc_count;
} ProcCache;

static char* strtrim(char* s) {
    char* end;
    while (isspace(*s)) s++;
    if (*s == 0) return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace(*end)) end--;
    *(end + 1) = 0;
    return s;
}

static bool read_file(int dir_fd, const char* filename, char* buf, size_t buf_size) {
    int fd = openat(dir_fd, filename, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return false;
    ssize_t total = 0;
    while (total < (ssize_t)(buf_size - 1)) {
        ssize_t n = read(fd, buf + total, buf_size - 1 - total);
        if (n == -1) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        total += n;
    }
    close(fd);
    if (total <= 0) return false;
    buf[total] = '\0';
    return true;
}

static bool write_file(int dir_fd, const char* filename, const char* content, int flags) {
    int fd = openat(dir_fd, filename, flags | O_CLOEXEC, 0644);
    if (fd == -1) return false;
    const char* ptr = content;
    size_t remaining = strlen(content);
    while (remaining > 0) {
        ssize_t n = write(fd, ptr, remaining);
        if (n == -1) {
            if (errno == EINTR) continue;
            close(fd);
            return false;
        }
        ptr += n;
        remaining -= n;
    }
    close(fd);
    return true;
}

static int build_str(char *dest, size_t dest_size, ...) {
    va_list args;
    const char *segment;
    char *p = dest;
    size_t remaining = dest_size - 1;
    va_start(args, dest_size);
    while ((segment = va_arg(args, const char *)) != NULL) {
        size_t len = strlen(segment);
        if (len > remaining) {
            va_end(args);
            return 0;
        }
        memcpy(p, segment, len);
        p += len;
        remaining -= len;
    }
    *p = '\0';
    va_end(args);
    return 1;
}

static void parse_cpu_ranges(const char* spec, cpu_set_t* set, const cpu_set_t* present) {
    if (!spec) return;
    char* copy = strdup(spec);
    if (!copy) return;
    char* s = copy;

    while (*s) {
        char* end;
        unsigned long a = strtoul(s, &end, 10);
        if (end == s) {
            s++;
            continue;
        }

        unsigned long b = a;
        if (*end == '-') {
            s = end + 1;
            b = strtoul(s, &end, 10);
            if (end == s) b = a;
        }

        if (a > b) { unsigned long t = a; a = b; b = t; }
        for (unsigned long i = a; i <= b && i < CPU_SETSIZE; i++) {
            if (present && !CPU_ISSET(i, present)) continue;
            CPU_SET(i, set);
        }

        s = (*end == ',') ? end + 1 : end;
    }
    free(copy);
}

static char* cpu_set_to_str(const cpu_set_t *set) {
    size_t buf_size = 8 * CPU_SETSIZE;
    char *buf = malloc(buf_size);
    if (!buf) return NULL;
    int start = -1, end = -1;
    char *p = buf;
    size_t remain = buf_size - 1;
    bool first = true;

    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, set)) {
            if (start == -1) {
                start = end = i;
            } else if (i == end + 1) {
                end = i;
            } else {
                int needed;
                if (start == end) {
                    needed = snprintf(p, remain + 1, "%s%d", first ? "" : ",", start);
                } else {
                    needed = snprintf(p, remain + 1, "%s%d-%d", first ? "" : ",", start, end);
                }
                if (needed < 0 || (size_t)needed > remain) {
                    free(buf);
                    return NULL;
                }
                p += needed;
                remain -= needed;
                start = end = i;
                first = false;
            }
        }
    }
    if (start != -1) {
        int needed;
        if (start == end) {
            needed = snprintf(p, remain + 1, "%s%d", first ? "" : ",", start);
        } else {
            needed = snprintf(p, remain + 1, "%s%d-%d", first ? "" : ",", start, end);
        }
        if (needed < 0 || (size_t)needed > remain) {
            free(buf);
            return NULL;
        }
        p += needed;
    }
    *p = '\0';
    return buf;
}

static bool create_cpuset_dir(const char *path, const char *cpus, const char *mems) {
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return false;
    if (chmod(path, 0755) != 0) return false;
    if (chown(path, 0, 0) != 0) return false;

    char cpus_path[256];
    build_str(cpus_path, sizeof(cpus_path), path, "/cpus", NULL);
    if (!write_file(AT_FDCWD, cpus_path, cpus, O_WRONLY | O_CREAT | O_TRUNC)) return false;

    char mems_path[256];
    build_str(mems_path, sizeof(mems_path), path, "/mems", NULL);
    return write_file(AT_FDCWD, mems_path, mems, O_WRONLY | O_CREAT | O_TRUNC);
}

static CpuTopology init_cpu_topo(void) {
    CpuTopology topo = { .cpuset_enabled = false, .base_cpuset_fd = -1 };
    CPU_ZERO(&topo.present_cpus);

    if (read_file(AT_FDCWD, "/sys/devices/system/cpu/present", topo.present_str, sizeof(topo.present_str))) {
        strtrim(topo.present_str);
    }
    parse_cpu_ranges(topo.present_str, &topo.present_cpus, NULL);

    if (access("/dev/cpuset", F_OK) != 0) return topo;

    if (create_cpuset_dir(BASE_CPUSET, topo.present_str, "0")) {
        topo.base_cpuset_fd = open(BASE_CPUSET, O_RDONLY | O_DIRECTORY);
        if (topo.base_cpuset_fd != -1) topo.cpuset_enabled = true;
    }

    char mems_path[256];
    build_str(mems_path, sizeof(mems_path), BASE_CPUSET, "/mems", NULL);
    if (!read_file(AT_FDCWD, mems_path, topo.mems_str, sizeof(topo.mems_str))) {
        strcpy(topo.mems_str, "0");
    } else {
        strtrim(topo.mems_str);
    }

    return topo;
}

static bool load_config(AppConfig* cfg) {
    struct stat st;
    if (stat(cfg->config_file, &st) != 0) {
        const char* initial_content = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n";
        if (write_file(AT_FDCWD, cfg->config_file, initial_content, O_WRONLY | O_CREAT | O_TRUNC)) {
            cfg->mtime = 0;
        }
        return false;
    }

    if (st.st_mtime <= cfg->mtime) return false;
    FILE* fp = fopen(cfg->config_file, "r");
    if (!fp) return false;

    AffinityRule* new_rules = NULL;
    char** new_pkgs = NULL;
    size_t rules_cnt = 0, pkgs_cnt = 0;
    char line[256];

    while (fgets(line, sizeof(line), fp)) {
        char* p = strtrim(line);
        if (*p == '#' || !*p) continue;

        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq++ = 0;

        char* br = strchr(p, '{');
        char* thread = "";
        if (br) {
            *br++ = 0;
            char* eb = strchr(br, '}');
            if (!eb) continue;
            *eb = 0;
            thread = strtrim(br);
        }

        char* pkg = strtrim(p);
        char* cpus = strtrim(eq);
        if (strlen(pkg) >= MAX_PKG_LEN || strlen(thread) >= MAX_THREAD_LEN) continue;

        cpu_set_t set;
        CPU_ZERO(&set);
        parse_cpu_ranges(cpus, &set, &cfg->topo.present_cpus);
        if (CPU_COUNT(&set) == 0) continue;

        char* dir_name = cpu_set_to_str(&set);
        if (!dir_name) continue;

        char path[256];
        build_str(path, sizeof(path), BASE_CPUSET, "/", dir_name, NULL);
        if (!create_cpuset_dir(path, dir_name, cfg->topo.mems_str)) {
            free(dir_name);
            continue;
        }

        AffinityRule rule = {0};
        build_str(rule.pkg, sizeof(rule.pkg), pkg, NULL);
        build_str(rule.thread, sizeof(rule.thread), thread, NULL);
        build_str(rule.cpuset_dir, sizeof(rule.cpuset_dir), dir_name, NULL);
        rule.cpus = set;
        free(dir_name);

        AffinityRule* tmp_rules = realloc(new_rules, (rules_cnt + 1) * sizeof(AffinityRule));
        if (!tmp_rules) goto error;
        new_rules = tmp_rules;
        memcpy(&new_rules[rules_cnt], &rule, sizeof(AffinityRule));
        rules_cnt++;

        bool exists = false;
        if (new_pkgs != NULL) {
            for (size_t i = 0; i < pkgs_cnt; i++) {
                if (strcmp(new_pkgs[i], pkg) == 0) {
                    exists = true;
                    break;
                }
            }
        }
        if (!exists) {
            char** tmp_pkgs = realloc(new_pkgs, (pkgs_cnt + 1) * sizeof(char*));
            if (!tmp_pkgs) goto error;
            new_pkgs = tmp_pkgs;
            new_pkgs[pkgs_cnt] = strdup(pkg);
            if (!new_pkgs[pkgs_cnt]) goto error;
            pkgs_cnt++;
        }
    }

    free(cfg->rules);
    if (cfg->pkgs != NULL) {
        for (size_t i = 0; i < cfg->num_pkgs; i++) free(cfg->pkgs[i]);
        free(cfg->pkgs);
    }

    cfg->rules = new_rules;
    cfg->num_rules = rules_cnt;
    cfg->pkgs = new_pkgs;
    cfg->num_pkgs = pkgs_cnt;
    cfg->mtime = st.st_mtime;

    fclose(fp);
    printf("Config file loaded, Total of %zu rules.\n", rules_cnt);
    return true;

error:
    free(new_rules);
    if (new_pkgs != NULL) {
        for (size_t i = 0; i < pkgs_cnt; i++) free(new_pkgs[i]);
        free(new_pkgs);
    }
    fclose(fp);
    return false;
}

static bool load_priority_config(AppConfig* cfg) {
    struct stat st;
    if (stat(cfg->priority_config, &st) != 0) {
        const char* initial_content = "# 格式：进程名{线程模式}=策略 优先级\n\n";
        write_file(AT_FDCWD, cfg->priority_config, initial_content, O_WRONLY | O_CREAT | O_TRUNC);
        return false;
    }

    FILE* fp = fopen(cfg->priority_config, "r");
    if (!fp) return false;

    PriorityRule* new_rules = NULL;
    size_t rules_cnt = 0;
    char line[256];

    while (fgets(line, sizeof(line), fp)) {
        char* p = strtrim(line);
        if (*p == '#' || !*p) continue;

        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq++ = 0;

        char* br = strchr(p, '{');
        char* thread = "";
        if (br) {
            *br++ = 0;
            char* eb = strchr(br, '}');
            if (!eb) continue;
            *eb = 0;
            thread = strtrim(br);
        }

        char* pkg = strtrim(p);
        char* policy_part = strtrim(eq);
        char* space = strchr(policy_part, ' ');
        if (!space) continue;
        *space++ = 0;
        char* pri_str = strtrim(space);

        int policy = -1;
        for (int i = 0; policy_map[i].name; i++) {
            if (strcmp(policy_map[i].name, policy_part) == 0) {
                policy = policy_map[i].policy;
                break;
            }
        }
        if (policy == -1) continue;

        char* end;
        long prio = strtol(pri_str, &end, 10);
        if (*end != 0) continue;
        if ((policy == SCHED_FIFO || policy == SCHED_RR) && (prio < 1 || prio > 99)) continue;
        if (policy == SCHED_OTHER && prio != 0) continue;

        PriorityRule rule = {0};
        strncpy(rule.pkg, pkg, MAX_PKG_LEN-1);
        strncpy(rule.thread, thread, MAX_THREAD_LEN-1);
        rule.policy = policy;
        rule.priority = (int)prio;

        PriorityRule* tmp = realloc(new_rules, (rules_cnt+1)*sizeof(PriorityRule));
        if (!tmp) goto error;
        new_rules = tmp;
        new_rules[rules_cnt++] = rule;
    }

    free(cfg->priority_rules);
    cfg->priority_rules = new_rules;
    cfg->num_priority_rules = rules_cnt;
    fclose(fp);
    printf("Priority config loaded, Total of %zu rules.\n", rules_cnt);
    return true;

error:
    free(new_rules);
    fclose(fp);
    return false;
}

static ProcessInfo* proc_collect(const AppConfig* cfg, size_t* count) {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return NULL;
    int proc_fd = dirfd(proc_dir);
    size_t proc_cap = 2048;
    ProcessInfo* new_procs = malloc(proc_cap * sizeof(ProcessInfo));
    if (!new_procs) {
        closedir(proc_dir);
        return NULL;
    }
    *count = 0;
    struct dirent* ent;

    while ((ent = readdir(proc_dir))) {
        if (ent->d_type != DT_DIR || !isdigit(ent->d_name[0])) continue;

        char* endptr;
        unsigned long pid_ul = strtoul(ent->d_name, &endptr, 10);
        if (*endptr != '\0') continue;
        pid_t pid = (pid_t)pid_ul;
        int pid_fd = openat(proc_fd, ent->d_name, O_RDONLY | O_DIRECTORY);
        if (pid_fd == -1) continue;

        // 读取进程名
        char cmd[MAX_PKG_LEN] = {0};
        if (!read_file(pid_fd, "cmdline", cmd, sizeof(cmd))) {
            close(pid_fd);
            continue;
        }
        char* name = strrchr(cmd, '/');
        name = name ? name + 1 : cmd;

        bool found = false;
        for (size_t j = 0; j < cfg->num_pkgs; j++) {
            if (strcmp(name, cfg->pkgs[j]) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            close(pid_fd);
            continue;
        }

        ProcessInfo proc = {0};
        proc.pid = pid;
        build_str(proc.pkg, sizeof(proc.pkg), name, NULL);
        CPU_ZERO(&proc.base_cpus);
        proc.base_cpuset[0] = '\0';

        size_t thrules_cap = 8;
        proc.thread_rules = malloc(thrules_cap * sizeof(AffinityRule*));
        if (!proc.thread_rules) {
            close(pid_fd);
            continue;
        }
        proc.num_thread_rules = 0;

        for (size_t i = 0; i < cfg->num_rules; i++) {
            const AffinityRule* rule = &cfg->rules[i];
            if (strcmp(rule->pkg, proc.pkg) != 0) continue;

            if (rule->thread[0]) {  
                if (proc.num_thread_rules >= thrules_cap) {
                    thrules_cap *= 2;
                    AffinityRule** tmp = realloc(proc.thread_rules, thrules_cap * sizeof(AffinityRule*));
                    if (!tmp) break;
                    proc.thread_rules = tmp;
                }
                proc.thread_rules[proc.num_thread_rules++] = (AffinityRule*)rule;
            } else {  
                CPU_OR(&proc.base_cpus, &proc.base_cpus, &rule->cpus);
                build_str(proc.base_cpuset, sizeof(proc.base_cpuset), rule->cpuset_dir, NULL);
            }
        }

        if (CPU_COUNT(&proc.base_cpus) == 0 && proc.num_thread_rules == 0) {
            close(pid_fd);
            free(proc.thread_rules);
            continue;
        }

        int task_fd = openat(pid_fd, "task", O_RDONLY | O_DIRECTORY);
        close(pid_fd);
        if (task_fd == -1) {
            free(proc.thread_rules);
            continue;
        }

        DIR* task_dir = fdopendir(task_fd);
        if (!task_dir) {
            close(task_fd);
            free(proc.thread_rules);
            continue;
        }

        size_t thread_cap = 256;
        ThreadInfo* threads = malloc(thread_cap * sizeof(ThreadInfo));
        if (!threads) {
            closedir(task_dir);
            free(proc.thread_rules);
            continue;
        }
        size_t tcount = 0;
        struct dirent* tent;

        while ((tent = readdir(task_dir))) {
            if (tent->d_type != DT_DIR || !isdigit(tent->d_name[0])) continue;

            char* endptr2;
            unsigned long tid_ul = strtoul(tent->d_name, &endptr2, 10);
            if (*endptr2 != '\0') continue;
            pid_t tid = (pid_t)tid_ul;

            char tname[MAX_THREAD_LEN] = {0};
            int tid_fd = openat(task_fd, tent->d_name, O_RDONLY | O_DIRECTORY);
            if (tid_fd == -1) continue;
            if (!read_file(tid_fd, "comm", tname, sizeof(tname))) {
                close(tid_fd);
                continue;
            }
            close(tid_fd);
            strtrim(tname);
            ThreadInfo ti = { 
                .tid = tid,
                .sched_policy = SCHED_OTHER,
                .sched_priority = 0
            };
            build_str(ti.name, sizeof(ti.name), tname, NULL);
            CPU_ZERO(&ti.cpus); // 初始化为空集合
            bool thread_rule_matched = false;
            char cpuset_dir_buffer[256] = "";

            for (size_t i = 0; i < proc.num_thread_rules; i++) {
                const AffinityRule* rule = proc.thread_rules[i];
                if (fnmatch(rule->thread, ti.name, FNM_NOESCAPE) == 0) {
                    CPU_OR(&ti.cpus, &ti.cpus, &rule->cpus);
                    strncpy(cpuset_dir_buffer, rule->cpuset_dir, sizeof(cpuset_dir_buffer)-1);
                    thread_rule_matched = true;
                }
            }

            if (thread_rule_matched) {
                build_str(ti.cpuset_dir, sizeof(ti.cpuset_dir), cpuset_dir_buffer, NULL);
            } else {
                CPU_OR(&ti.cpus, &ti.cpus, &proc.base_cpus); 
                build_str(ti.cpuset_dir, sizeof(ti.cpuset_dir), proc.base_cpuset, NULL);
            }

            for (size_t i = 0; i < cfg->num_priority_rules; i++) {
                const PriorityRule* rule = &cfg->priority_rules[i];
                if (strcmp(rule->pkg, proc.pkg) != 0) continue;
                
                if (fnmatch(rule->thread, ti.name, FNM_NOESCAPE) == 0) {
                    ti.sched_policy = rule->policy;
                    ti.sched_priority = rule->priority;
                    break;
                }
            }

            if (tcount >= thread_cap) {
                thread_cap *= 2;
                ThreadInfo* tmp = realloc(threads, thread_cap * sizeof(ThreadInfo));
                if (!tmp) continue;
                threads = tmp;
            }
            threads[tcount++] = ti;
        }

        proc.threads = threads;
        proc.num_threads = tcount;
        if (*count >= proc_cap) {
            proc_cap *= 2;
            ProcessInfo* tmp = realloc(new_procs, proc_cap * sizeof(ProcessInfo));
            if (!tmp) {
                free(threads);
                free(proc.thread_rules);
                closedir(task_dir);
                continue;
            }
            new_procs = tmp;
        }
        new_procs[(*count)++] = proc;
        closedir(task_dir);
    }
    closedir(proc_dir);
    return new_procs;
}

static void update_cache(ProcCache* cache, const AppConfig* cfg, int* affinity_counter) {
    bool need_reload = false;
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        need_reload = true;
    } else {
        int current_proc_count = info.procs;
        if (current_proc_count > cache->last_proc_count + 15) {
            need_reload = true;
        } else if (current_proc_count > cache->last_proc_count) {
            *affinity_counter = 0;
        }
        cache->last_proc_count = current_proc_count;
    }
    if (cache->procs != NULL && !need_reload) {
        for (size_t i = 0; i < cache->num_procs; i++) {
            if (kill(cache->procs[i].pid, 0) != 0) {
                need_reload = true;
                break;
            }
        }
    }
    if (need_reload) {
        size_t count;
        ProcessInfo* new_procs = proc_collect(cfg, &count);
        if (!new_procs) return;
        if (cache->procs) {
            for (size_t i = 0; i < cache->num_procs; i++) {
                free(cache->procs[i].threads);
                free(cache->procs[i].thread_rules);
            }
            free(cache->procs);
        }
        cache->procs = new_procs;
        cache->num_procs = count;
        *affinity_counter = 0;
    }
}
static void apply_affinity(ProcCache* cache, const CpuTopology* topo) {
    for (size_t i = 0; i < cache->num_procs; i++) {
        const ProcessInfo* proc = &cache->procs[i];
        for (size_t j = 0; j < proc->num_threads; j++) {
            const ThreadInfo* ti = &proc->threads[j];
            
            if (topo->cpuset_enabled && topo->base_cpuset_fd != -1) {
                char tid_str[32];
                snprintf(tid_str, sizeof(tid_str), "%d\n", ti->tid);
                
                if (CPU_COUNT(&ti->cpus) == 0) {
                    write_file(topo->base_cpuset_fd, "tasks", tid_str, O_WRONLY | O_APPEND);
                } else {
                    if (ti->cpuset_dir[0]) {
                        int fd = openat(topo->base_cpuset_fd, ti->cpuset_dir, O_RDONLY | O_DIRECTORY);
                        if (fd != -1) {
                            write_file(fd, "tasks", tid_str, O_WRONLY | O_APPEND);
                            close(fd);
                        }
                    }
                }
            }

            if (CPU_COUNT(&ti->cpus) == 0) continue;
            
            if (sched_setaffinity(ti->tid, sizeof(ti->cpus), &ti->cpus) == -1) {
                if (errno == ESRCH) { 
                    cache->last_proc_count = 0; 
                }
            }
        }
    }
}
static void apply_scheduling(const ProcCache* cache) {
    for (size_t i = 0; i < cache->num_procs; i++) {
        const ProcessInfo* proc = &cache->procs[i];
        for (size_t j = 0; j < proc->num_threads; j++) {
            const ThreadInfo* ti = &proc->threads[j];
            
            if (ti->sched_policy == SCHED_OTHER && ti->sched_priority == 0) {
                continue;
            }

            bool valid_policy = false;
            for (int k = 0; policy_map[k].name != NULL; k++) {
                if (policy_map[k].policy == ti->sched_policy) {
                    valid_policy = true;
                    break;
                }
            }
            if (!valid_policy) {
                fprintf(stderr, "Invalid policy %d for thread %d (%s)\n",
                        ti->sched_policy, ti->tid, ti->name);
                continue;
            }

            if ((ti->sched_policy == SCHED_FIFO || ti->sched_policy == SCHED_RR) &&
                (ti->sched_priority < 1 || ti->sched_priority > 99)) {
                fprintf(stderr, "Priority %d out of range [1-99] for %s thread %d\n",
                        ti->sched_priority, 
                        (ti->sched_policy == SCHED_FIFO) ? "SCHED_FIFO" : "SCHED_RR",
                        ti->tid);
                continue;
            }

            struct sched_param param = { .sched_priority = ti->sched_priority };

            if (sched_setscheduler(ti->tid, 
                                  ti->sched_policy | SCHED_RESET_ON_FORK, 
                                  &param) == -1) 
            {
                if (errno == ESRCH) {
                    continue;
                }
                
                // 详细错误报告
                const char* policy_name = "UNKNOWN";
                for (int k = 0; policy_map[k].name != NULL; k++) {
                    if (policy_map[k].policy == ti->sched_policy) {
                        policy_name = policy_map[k].name;
                        break;
                    }
                }
                
                fprintf(stderr, "Failed to set %s/%d for TID:%d (%s): %s\n",
                        policy_name, 
                        ti->sched_priority,
                        ti->tid, 
                        ti->name,
                        strerror(errno));
                
                if (errno == EPERM) {
                    fprintf(stderr, "Tip: Requires root privileges for real-time policies\n");
                }
            }
        }
    }
}
static void print_help(const char* prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("CPU Affinity & Thread Priority Controller\n\n");
    printf("Options:\n");
    printf("  -c <file>    Specify affinity config file (default: ./applist.conf)\n");
    printf("  -p <file>    Specify priority config file (default: ./priority.conf)\n");
    printf("  -s <sec>     Set polling interval in seconds (>=1, default: 2)\n");
    printf("  -v           Show program version\n");
    printf("  -h           Show this help message\n\n");
    printf("Config Syntax:\n");
    printf("  [Affinity] Process{ThreadPattern}=CPUList (e.g. com.android.phone{Audio}=0-3)\n");
    printf("  [Priority] Process{ThreadPattern}=POLICY PRIORITY (e.g. system_server{Binder}=SCHED_FIFO 99)\n\n");
    printf("Example:\n");
    printf("  %s -c /data/appopt.conf -p /data/priority.conf -s 3\n", prog_name);
    printf("  %s -v  # Check version\n", prog_name);
}

int main(int argc, char **argv) {
    AppConfig config = { 
        .topo = init_cpu_topo(),
        .priority_config = "./priority.conf"  
    };
    build_str(config.config_file, sizeof(config.config_file), "./applist.conf", NULL);
    int sleep_interval = 2;

    int opt;
    while ((opt = getopt(argc, argv, "c:p:s:hv")) != -1) {
        switch (opt) {
            case 'c':
                build_str(config.config_file, sizeof(config.config_file), optarg, NULL);
                printf("Affinity config: %s\n", config.config_file);
                break;
            case 'p':  
                build_str(config.priority_config, sizeof(config.priority_config), optarg, NULL);
                printf("Scheduler config: %s\n", config.priority_config);
                break;
            case 's': {
                char *endptr;
                long val = strtol(optarg, &endptr, 10);
                if (endptr == optarg || *endptr != '\0' || val < 1) {
                    fprintf(stderr, "Invalid interval value: %s\n", optarg);
                    fprintf(stderr, "Interval must be >=1\n");
                    exit(EXIT_FAILURE);
                }
                sleep_interval = (int)val;
                printf("Sleep interval: %d s\n", sleep_interval);
                break;
            }
            case 'v':
                printf("AppOpt version %s\n", VERSION);
                exit(EXIT_SUCCESS);
            case 'h':
                print_help(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                print_help(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    ProcCache cache = {0};
    int config_counter = 0;
    int affinity_counter = 0;
    int sched_counter = 0;  
    printf("Starting AppOpt service (PID %d)\n", getpid());

    for (;;) {
        // 配置重载逻辑
        if (++config_counter >= 5) {
            if (load_config(&config)) cache.last_proc_count = 0;
            load_priority_config(&config);  
            config_counter = 0;
        }

        update_cache(&cache, &config, &affinity_counter);

        if (++affinity_counter >= 5) {
            apply_affinity(&cache, &config.topo);
            affinity_counter = 0;
        }

        if (++sched_counter >= 5) {
            apply_scheduling(&cache);
            sched_counter = 0;
        }

        sleep(sleep_interval);
    }
}
