/**
 * ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
 * ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
 * ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗  
 * ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
 *  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
 *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
 * 
 *  A C++ VM detection library
 * 
 * ===============================================================

 * This program serves as an internal tool for fuzzing cpuid values 
 * and comparing them between baremetal outputs and VM outputs.
 * 
 * ===============================================================
 * 
 *  - Made by: @kernelwernel (https://github.com/kernelwernel)
 *  - Repository: https://github.com/kernelwernel/VMAware
 */ 


#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#if (defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__))
    #define MSVC 1
    #define LINUX 0
#elif (defined(__GNUC__) || defined(__linux__))
    #define MSVC 0
    #define LINUX 1
#else
    #error "Unknown OS, aborting"
#endif

#if (LINUX)
    #define _GNU_SOURCE
    #include <cpuid.h>
    #include <sched.h>
    #include <pthread.h>
    #include <sys/sysinfo.h>
#endif

// branching macros
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x)   __builtin_expect(!!(x), 1)

// cpu brand shit for ecx idfk
#define intel_ecx 0x6c65746e
#define amd_ecx 0x69746e65

// cpuid leaf values
#define manufacturer 0x00000000
#define proc_info 0x00000001
#define cache_tlb 0x00000002
#define serial 0x00000003
#define topology 0x00000004
#define topology2 0x0000000B
#define management 0x00000006
#define extended 0x00000007 // ecx = 0
#define extended2 0x00000007 // ecx = 1
#define extended3 0x00000007 // ecx = 2
#define xsave 0x0000000D
#define xsave2 0x0000000D // ecx = >2
#define xsave3 0x0000000D // ecx = 0
#define xsave4 0x0000000D // ecx = 1
#define sgx 0x00000012 // ecx = 0
#define sgx2 0x00000012 // ecx = 1
#define sgx3 0x00000012 // ecx = >2
#define proc_trace 0x00000014 // ecx = 0
#define aes 0x00000019
#define avx10 0x00000024 // ecx = 0
#define extended_proc_info 0x80000001
#define hypervisor 0x40000000
#define max_leaf 0x80000000
#define brand1 0x80000002
#define brand2 0x80000003
#define brand3 0x80000004
#define L1_cache 0x80000005
#define L2_cache 0x80000006
#define capabilities 0x80000007
#define virtual 0x80000008
#define svm 0x8000000A
#define enc_mem_cap 0x8000001F
#define ext_info2 0x80000021
#define amd_easter_egg 0x8fffffff
#define centaur_ext 0xC0000000
#define centaur_feature 0xC0000001

// index macros
#define eax 0
#define ebx 1
#define ecx 2
#define edx 3 

// cli flags
#define leaf_mode 1
#define scan_mode 2

// miscellaneous
#define null_leaf 0xFF
#define breakpoint 10000000


typedef struct {
    void (*taskFunction)(void*); // Function pointer to the task
    void* arg;                   // Argument to the task function
} Task;

typedef struct {
    pthread_t* threads; // Array of thread IDs
    Task* taskQueue;    // Array to hold tasks
    int queueSize;      // Size of the task queue
    int nextTaskIndex;  // Index to insert the next task
    int shutdown;       // Flag to indicate pool shutdown
    pthread_mutex_t mutex; // Mutex for synchronization
    pthread_cond_t condition; // Condition variable for task availability
} ThreadPool;

// function executed by each thread in the pool
void* threadFunction(void* arg) {
    ThreadPool* pool = (ThreadPool*)arg;

    while (1) {
        pthread_mutex_lock(&pool->mutex);

        while (pool->nextTaskIndex == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->condition, &pool->mutex);
        }

        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->mutex);
            pthread_exit(NULL);
        }

        Task task = pool->taskQueue[--pool->nextTaskIndex];

        pthread_mutex_unlock(&pool->mutex);

        task.taskFunction(task.arg);
    }

    return NULL;
}

// initialize the thread pool
ThreadPool* initializeThreadPool(int poolSize) {
    ThreadPool* pool = (ThreadPool*)malloc(sizeof(ThreadPool));
    if (!pool) {
        perror("Error creating thread pool");
        exit(EXIT_FAILURE);
    }

    pool->threads = (pthread_t*)malloc(poolSize * sizeof(pthread_t));
    pool->taskQueue = (Task*)malloc(poolSize * sizeof(Task));
    pool->queueSize = poolSize;
    pool->nextTaskIndex = 0;
    pool->shutdown = 0;

    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->condition, NULL);

    for (int i = 0; i < poolSize; i++) {
        if (pthread_create(&pool->threads[i], NULL, threadFunction, (void*)pool) != 0) {
            perror("Error creating thread");
            exit(EXIT_FAILURE);
        }
    }

    return pool;
}

// submit a task to the thread pool
void submitTask(ThreadPool* pool, void (*taskFunction)(void*), void* arg) {
    pthread_mutex_lock(&pool->mutex);

    if (pool->nextTaskIndex == pool->queueSize) {
        fprintf(stderr, "Task queue is full. Task not submitted.\n");
        pthread_mutex_unlock(&pool->mutex);
        return;
    }

    pool->taskQueue[pool->nextTaskIndex].taskFunction = taskFunction;
    pool->taskQueue[pool->nextTaskIndex].arg = arg;
    pool->nextTaskIndex++;

    pthread_cond_signal(&pool->condition);

    pthread_mutex_unlock(&pool->mutex);
}

// shutdown the thread pool
void shutdownThreadPool(ThreadPool* pool) {
    pthread_mutex_lock(&pool->mutex);

    pool->shutdown = 1;

    pthread_cond_broadcast(&pool->condition);

    pthread_mutex_unlock(&pool->mutex);

    for (int i = 0; i < pool->queueSize; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    free(pool->threads);
    free(pool->taskQueue);
    free(pool);
}



// basic cpuid wrapper
static void cpuid
(
    uint32_t *x,
    const uint64_t leaf,
    const uint64_t subleaf
) {
    #if (MSVC)
        __cpuidex((int32_t*)x, (int32_t)(leaf), (int32_t)(subleaf));
    #elif (LINUX)
        __cpuid_count(leaf, subleaf, x[0], x[1], x[2], x[3]);
    #endif
};

// get highest eax leaf 
static uint32_t get_highest_leaf() {
    uint32_t reg[4];
    cpuid(reg, max_leaf, null_leaf);
    return (reg[eax]);
}

// scan for predetermined leafs
void leaf_mode_fuzzer(const uint64_t p_max_leaf) {
    uint32_t reg[4];
    const uint32_t leafs[36] = { 
        manufacturer, proc_info, cache_tlb, 
        serial, topology, topology2, 
        management, extended, extended2, 
        extended3, xsave, xsave2 , 
        xsave3, xsave4, sgx, 
        sgx2, sgx3 , proc_trace, 
        aes, avx10, extended_proc_info, 
        hypervisor, max_leaf, brand1, 
        brand2, brand3, L1_cache, 
        L2_cache, capabilities, virtual, 
        svm, enc_mem_cap, ext_info2, 
        amd_easter_egg, centaur_ext, centaur_feature
    };

    const size_t leaf_arr_size = (sizeof(leafs) / sizeof(leafs[0]));

    for (int i = 0; i < leaf_arr_size; i++) {
        if (leafs[i] >= p_max_leaf) {
            continue;
        }

        cpuid(reg, leafs[i], null_leaf);

        if (likely(
            reg[eax] || \
            reg[ebx] || \
            reg[ecx] || \
            reg[edx]
        )) {
            printf("leaf = %d\n", i);
            printf("eax = %d\n", reg[eax]);
            printf("ebx = %d\n", reg[ebx]);
            printf("ecx = %d\n", reg[ecx]);
            printf("edx = %d\n\n", reg[edx]);
        }
    }
}

/*
atomic_int counter; 

void scan_mode_worker() {
    for (int i = 0; i < divisor; i++) {
        int x = start;

        for (; x < limit; x++) {
            uint32_t reg[4];
            cpuid(reg, x, null_leaf);

            if (unlikely(
                reg[eax] || \
                reg[ebx] || \
                reg[ecx] || \
                reg[edx]
            )) {
                printf("leaf = %d\n", i);
                printf("eax = %d\n", reg[eax]);
                printf("ebx = %d\n", reg[ebx]);
                printf("ecx = %d\n", reg[ecx]);
                printf("edx = %d\n\n", reg[edx]);
                fprintf(file, "%s\n", logMessage);
            }
        }

        const int percent = (((i + 1) * 100) / p_max_leaf);

        printf("[LOG] Reached eax leaf %d (%d%%)\n", atomic_load(&counter), percent);
        limit += breakpoint;
        start += breakpoint;
    }

}

// scan mode fuzzer
void scan_mode_fuzzer(const uint64_t p_max_leaf, const int32_t thread_count) {
    uint32_t limit = breakpoint;
    uint32_t start = 0;

    const int32_t threads = get_nprocs();

    const uint32_t divisor = (uint32_t)(p_max_leaf / breakpoint);
    printf("divisor = %d\n", divisor);

    atomic_init(&counter, 0);
    ThreadPool* pool = initializeThreadPool(8);

    // Submit example tasks to the thread pool
    for (int i = 0; i < 10; i++) {
        int* taskNumber = (int*)malloc(sizeof(int));
        *taskNumber = i;
        submitTask(pool, exampleTask, (void*)taskNumber);
    }

    // Sleep to allow tasks to complete
    sleep(2);

    // Shutdown the thread pool
    shutdownThreadPool(pool);
}


void exampleTask(void* low_bound, void* upper_bound) {
    int taskNumber = *(int*)arg;
    printf("Task %d executed by thread %lu\n", taskNumber, pthread_self());
}
*/


int main(int argc, char *argv[]) {
    uint8_t flags = 0;

    if (argc == 1) {
        flags |= leaf_mode;
    } else if (argc == 2) {
        if (strcmp(argv[2], "--leaf") == 0) {
            flags |= leaf_mode;
        } else if (strcmp(argv[2], "--scan") == 0) {
            flags |= scan_mode;
        } else {
            printf("%s", "Unknown flag provided, aborting\n");
            return 1;
        }
    } else {
        printf("%s", "Too many flags provided, only use either --leaf or --scan\n");
        return 1;
    }

    const uint64_t high_leaf = get_highest_leaf();
    printf("highest leaf = 0x%0lX\n", high_leaf);



    if (flags & leaf_mode) {
        leaf_mode_fuzzer(high_leaf);
    } else if (flags & scan_mode) {
        //scan_mode_fuzzer(high_leaf);
    } else {
        return 1;
    }

    return 0;
}