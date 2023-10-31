#include <ctype.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdatomic.h>

// this is a complete rewrite of hashgen in C
// other than micro controller / embedded systems, I have little coding experience with C
// hashgen (Go) will remain my primary implementation of hashgen and I do not expect hashgen (C) to be maintained
// hashgen (C) uses openssl for all hashing functions

// version history
// it took multiple revisions to get a 100% thread safe implementation of hashgen (C) that was still decently fast
// in order to make hashgen (C) thread safe, a mutex-protected read/write buffer was implemented which slowed performance down to below hashgen (Go) and hashgen (php)
// developing a multi-threaded, thread safe application in C makes me very appreciative of the power and simplicity of Go :)
// v2023.03.18-1945; initial github release
// v2023.03.27-1945; removed mutex locks for better performance
// v2023.04.25-1020; handle memory allocations using malloc, count processed lines using atomic_size for thread safety
// v2023.06.05-1810; default to stdin if -w not specified and stdout if -o not specified

// todo -- probably won't happen any time soon as my focus is on hashgen(Go)
// optimize code (C version is slower than Go)

// program version
#define PROGRAM_VERSION "v2023.06.05-1810"

// read / write buffer
#define BUFFER_SIZE (10 * 1024 * 1024)

typedef struct {
    const char *hash_mode;
    FILE *input_handle;
    FILE *output_handle;
    atomic_size_t *lines_processed;
} ThreadData;

// set number of application threads to CPU threads, defaults to 1 if unable to detect CPU thread count
int get_num_threads() {
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    return (num_threads > 0) ? num_threads : 1; // fallback to 1
}

void print_usage();
void print_version();
void print_cyclone();
void print_algos();
void print_digest_name(const EVP_MD *md, const char *name, const char *unused, void *u);
void *process_lines(void *args);
void main(int argc, char *argv[]);

// clear screen
void clear_screen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

// usage instructions
void print_usage() {
    print_version();
    printf("Example Usage:\n");
    printf("./hashgen.bin -m md5 -w wordlist.txt -o output.txt\n");
    printf("cat wordlist.txt | ./hashgen.bin -m md5 > output.txt\n");
    exit(1);
}

// version info
void print_version() {
    printf("Cyclone's hash generator (c), %s\n", PROGRAM_VERSION);
}

// coded by cyclone
void print_cyclone() {
    printf("Coded by cyclone ;)\n");
}

// print supported algo's
void print_algos() {
    printf("Supported hash algorithms:\n");
    EVP_MD_do_all_sorted(print_digest_name, NULL);
}

void print_digest_name(const EVP_MD *md, const char *name, const char *unused, void *u) {
    printf("%s\n", name);
}

// line processing / hashing logic
void *process_lines(void *args) {
    ThreadData *data = (ThreadData *)args;
    const char *hash_mode = data->hash_mode;
    FILE *input_handle = data->input_handle;
    FILE *output_handle = data->output_handle;
    atomic_size_t *lines_processed = data->lines_processed;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_get_digestbyname(hash_mode);

    char *input_buffer = (char *)malloc(BUFFER_SIZE);
    char *output_buffer = (char *)malloc(BUFFER_SIZE);
    size_t input_pos = 0;
    size_t output_pos = 0;
    char *saveptr;

    while (1) {
        if (!fgets(input_buffer + input_pos, BUFFER_SIZE - input_pos, input_handle)) {
            break;
        }
        input_pos += strlen(input_buffer + input_pos);
        if (input_buffer[input_pos - 1] != '\n' && !feof(input_handle)) {
            continue;
        }

        char *line = strtok_r(input_buffer, "\n", &saveptr);
        while (line) {
            unsigned char hash_value[EVP_MAX_MD_SIZE];
            unsigned int hash_len;
            EVP_DigestInit_ex(mdctx, md, NULL);
            EVP_DigestUpdate(mdctx, line, strlen(line));
            EVP_DigestFinal_ex(mdctx, hash_value, &hash_len);

            for (unsigned int i = 0; i < hash_len; ++i) {
                output_pos += sprintf(output_buffer + output_pos, "%02x", hash_value[i]);
            }
            output_buffer[output_pos++] = '\n';

            if (output_pos >= BUFFER_SIZE - (EVP_MAX_MD_SIZE * 2 + 1)) {
                fwrite(output_buffer, 1, output_pos, output_handle);
                output_pos = 0;
            }

            atomic_fetch_add(lines_processed, 1);

            line = strtok_r(NULL, "\n", &saveptr);
        }

        input_pos = 0;
    }

    if (output_pos > 0) {
        fwrite(output_buffer, 1, output_pos, output_handle);
        fflush(output_handle);
    }

    free(input_buffer);
    free(output_buffer);
    EVP_MD_CTX_free(mdctx);

    return NULL;
}

// main program logic
void main(int argc, char *argv[]) {
    clear_screen();

    if (argc <= 1) {
        print_usage();
    }

    int opt;
    char *wordlist_file = NULL;
    char *hash_mode = NULL;
    char *output_file = NULL;

    while ((opt = getopt(argc, argv, "w:m:o:vcah")) != -1) {
        switch (opt) {
        case 'w':
            if (!wordlist_file) {
                wordlist_file = optarg;
            }
            break;
        case 'm':
            hash_mode = optarg;
            break;
        case 'o':
            if (!output_file) {
                output_file = optarg;
            }
            break;
        case 'v':
            print_version();
            exit(0);
        case 'c':
            print_cyclone();
            exit(0);
        case 'a':
            print_algos();
            exit(0);
        case 'h':
        default:
            print_usage();
        }
    }

    printf("Processing wordlist...\n");

    // if wordlist_file is NULL, -w flag was not provided
    if (!wordlist_file) {
        wordlist_file = "/dev/stdin";  // use stdin as default
    }

    // if output_file is NULL, -o flag was not provided
    if (!output_file) {
        output_file = "/dev/stdout";  // use stdout as default
    }

    if (!EVP_get_digestbyname(hash_mode)) {
        printf("Error: Unsupported hash mode. Supported modes are:\n");
        print_algos();
        exit(1);
    }

    FILE *input_handle = fopen(wordlist_file, "r");
    if (!input_handle) {
        perror("Error opening input file");
        exit(1);
    }

    FILE *output_handle = fopen(output_file, "w");
    if (!output_handle) {
        perror("Error opening output file");
        exit(1);
    }

    int num_threads = get_num_threads();
    pthread_t *threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    ThreadData *thread_data = (ThreadData *)malloc(num_threads * sizeof(ThreadData));

    atomic_size_t *lines_processed = (atomic_size_t *)malloc(sizeof(atomic_size_t));
    atomic_init(lines_processed, 0);

    struct timeval start, end;

    gettimeofday(&start, NULL);

    for (int i = 0; i < num_threads; ++i) {
        thread_data[i].hash_mode = hash_mode;
        thread_data[i].input_handle = input_handle;
        thread_data[i].output_handle = output_handle;
        thread_data[i].lines_processed = lines_processed;
        pthread_create(&threads[i], NULL, process_lines, &thread_data[i]);
    }

    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
    }

    // print out results
    gettimeofday(&end, NULL);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("Finished hashing %zu lines in %.3f sec (%.0f lines/sec)\n", atomic_load(lines_processed), elapsed, atomic_load(lines_processed) / elapsed);
    printf("CPU Threads Used: %d\n", num_threads);

    fclose(input_handle);
    fclose(output_handle);

    free(threads);
    free(thread_data);
    free(lines_processed);

    return;
}

// end code