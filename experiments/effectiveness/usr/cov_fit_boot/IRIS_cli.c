#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <stdint.h>

#include <unistd.h>

#include <xenctrl.h>

#include <inttypes.h>

#include <sched.h>

#include <time.h>

#define BUFFER_DIM_FACTOR 500
#define BIOS_EXIT 15000

#define PRINT_MODE 0
#define MUTATION_MODE 1

#define VMCS_MONITORING_START 0
#define VMCS_MONITORING_STOP 1
#define VMCS_BOOT_MONITORING_SETUP 2
#define VMCS_BOOT_MONITORING_STOP 3
#define VMCS_MUTATION_ENABLE 4
#define VMCS_MUTATION_DISABLE 5
#define VMCS_BOOT_MUTATION_SETUP 6
#define VMCS_MUTATION_START_NEW_ITERATION 7
#define VMCS_DEBUG_MODE_ENABLE 8
#define VMCS_DEBUG_MODE_DISABLE 9
#define VMCS_NON_BLOCKING_MODE_ENABLE 10
#define VMCS_NON_BLOCKING_MODE_DISABLE 11
#define VMCS_BOOT_MONITORING_SET_EXIT_N 12
#define VMCS_BOOT_MONITORING_CHECK 13
#define VMCS_BOOT_MUTATION_DISABLE 14
#define VMCS_MUTATION_START_NEW_ITERATION_BLOCKING 15
#define VMCS_MUTATION_START_NEW_ITERATION_NO_BLOCKING 16
#define VMCS_BOOT_MUTATION_CHECK 17

const char * type[3] = {
  [0] = "WR",
  [1] = "RD",
  [2] = "REG"
};

const char * exit_reason_name[65] = {
  [0] = "EXCEPTION_NMI",
  [1] = "EXTERNAL_INTERRUPT",
  [2] = "TRIPLE_FAULT",
  [3] = "INIT",
  [4] = "SIPI",
  [5] = "IO_SMI",
  [6] = "OTHER_SMI",
  [7] = "PENDING_VIRT_INTR",
  [8] = "PENDING_VIRT_NMI",
  [9] = "TASK_SWITCH",
  [10] = "CPUID",
  [11] = "GETSEC",
  [12] = "HLT",
  [13] = "INVD",
  [14] = "INVLPG",
  [15] = "RDPMC",
  [16] = "RDTSC",
  [17] = "RSM",
  [18] = "VMCALL",
  [19] = "VMCLEAR",
  [20] = "VMLAUNCH",
  [21] = "VMPTRLD",
  [22] = "VMPTRST",
  [23] = "VMREAD",
  [24] = "VMRESUME",
  [25] = "VMWRITE",
  [26] = "VMXOFF",
  [27] = "VMXON",
  [28] = "CR_ACCESS",
  [29] = "DR_ACCESS",
  [30] = "IO_INSTRUCTION",
  [31] = "MSR_READ",
  [32] = "MSR_WRITE",
  [33] = "INVALID_GUEST_STATE",
  [34] = "MSR_LOADING",
  [36] = "MWAIT_INSTRUCTION",
  [37] = "MONITOR_TRAP_FLAG",
  [39] = "MONITOR_INSTRUCTION",
  [40] = "PAUSE_INSTRUCTION",
  [41] = "MCE_DURING_VMENTRY",
  [43] = "TPR_BELOW_THRESHOLD",
  [44] = "APIC_ACCESS",
  [45] = "EOI_INDUCED",
  [46] = "ACCESS_GDTR_OR_IDTR",
  [47] = "ACCESS_LDTR_OR_TR",
  [48] = "EPT_VIOLATION",
  [49] = "EPT_MISCONFIG",
  [50] = "INVEPT",
  [51] = "RDTSCP",
  [52] = "VMX_PREEMPTION_TIMER_EXPIRED",
  [53] = "INVVPID",
  [54] = "WBINVD",
  [55] = "XSETBV",
  [56] = "APIC_WRITE",
  [58] = "INVPCID",
  [59] = "VMFUNC",
  [62] = "PML_FULL",
  [63] = "XSAVES",
  [64] = "XRSTORS"
};

struct bin_data {
  uint64_t field;
  uint64_t value;
  uint64_t type;
};
typedef struct bin_data bin_data_t;

struct seed {
  unsigned long id;
  unsigned long size;
  bin_data_t * seed_items;
};

typedef struct seed seed_t;

struct seeds {
  unsigned long size;
  seed_t * seeds_items;
};

typedef struct seeds seeds_t;

int raw_to_seeds(int size, uint64_t * buffer, seeds_t * seeds, int mode);

int main(int argc, char * argv[]) {
  int res = 0;
  xc_interface * pxch = xc_interface_open(NULL, NULL, 0);

  switch ( * argv[1]) {

  case 'v': {
    unsigned int num_exit = atoi(argv[2]); // num exits
    unsigned int gran_exit = atoi(argv[3]); // exit granularity
    int dom_id = atoi(argv[4]);

    FILE * fp;
    char file_name[50];
    char cmd[90];

    bool first_iter = true;
    struct timespec tim, tim2;
    tim.tv_sec = 0;
    tim.tv_nsec = 1L;

    // Inital setup for the test VM
    xc_vmcs_fuzzing(pxch, 0, VMCS_DEBUG_MODE_DISABLE, 0, NULL);
    xc_vmcs_fuzzing(pxch, 0, VMCS_BOOT_MUTATION_DISABLE, 0, NULL);
    xc_vmcs_fuzzing(pxch, 0, VMCS_NON_BLOCKING_MODE_ENABLE, 0, NULL);

	system ("mkdir cov");

    /************************ START BIOS MONITORING **********************************/
    // 定数値の前計算
    const size_t buffer_size = sizeof(uint64_t) * BUFFER_DIM_FACTOR * 1;
    int count = 0;

    for (int i = 0; i < BIOS_EXIT; i++) {
      count = i + 1;

      // 最初のイテレーションだけリセット
      if (i == 0) {
        printf("Reset coverage\n");
        system("xencov reset");
      }

      // VM設定は一定なので、ループ外に移動可能
      xc_vmcs_fuzzing(pxch, 0, VMCS_BOOT_MONITORING_SET_EXIT_N, 1, NULL);
      xc_vmcs_fuzzing(pxch, 0, VMCS_BOOT_MONITORING_SETUP, BUFFER_DIM_FACTOR * 1, NULL);

      // VMの作成は最初の1回だけ
      if (first_iter) {
        system("xl create ./hvm_configuration.cfg");
        first_iter = false;
      }

      // バッファの効率的な再利用
      uint64_t *buffer_bios = NULL;
      if (i == 0) {
        buffer_bios = malloc(buffer_size);
      } else {
        // 同じサイズなのでreallocは不要、前回のバッファを再利用
        // 前のイテレーションでfreeしないように修正
      }
      memset(buffer_bios, 0, buffer_size);

      // Waits for the end of monitoring
      res = 0;
      while (res != 1) {
        nanosleep( & tim, & tim2);
        res = xc_vmcs_fuzzing(pxch, 0, VMCS_BOOT_MONITORING_CHECK, 0, NULL);
      }

      // Reads monitored buffer
      res = xc_vmcs_fuzzing(pxch, dom_id, VMCS_BOOT_MONITORING_STOP, BUFFER_DIM_FACTOR * 1, buffer_bios);

      // Retrieves coverage every 10 exit
      if (count % 10 == 0) {
        printf("Read coverage i: %d\n", count);
        sprintf(cmd, "xencov read > ./cov/bios_cov%d.dat", count);
        system(cmd);
        printf("Reset coverage\n");
        system("xencov reset");
      }

      // Checks if BIOS is finished
      if (buffer_bios[4] == 0x6f5e && buffer_bios[10] == 0x10) {
        printf("\n\n\n\n\n BIOS end \n\n\n\n\n");
        free(buffer_bios);

        printf("read coverage i: %d\n", count);
        sprintf(cmd, "xencov read > ./cov/bios_cov%d.dat", count);
        system(cmd);
        break;
      } else {
        printf("BIOS exit: #%d\n", i);
      }


    }
    free(buffer_bios);

    // Save a VM snapshot at end of BIOS
    sprintf(cmd, "xl save -c hvm_guest ./guest_snap ./hvm_configuration.cfg");
    system(cmd);

    /***************************************** START BOOT MONITORING ***************************************/
    // seeds ファイルを一度だけオープンし、追記モードで使用
    sprintf(file_name, "./seeds");
    if ((fp = fopen(file_name, "a")) == NULL) return -1;

    // バッファサイズを事前計算
    const size_t boot_buffer_size = sizeof(uint64_t) * BUFFER_DIM_FACTOR * gran_exit;
    uint64_t *buffer = malloc(boot_buffer_size);

    for (int i = 0; i < num_exit; i++) {
      system("xencov reset");

      // 設定
      xc_vmcs_fuzzing(pxch, 0, VMCS_BOOT_MONITORING_SET_EXIT_N, gran_exit, NULL);
      xc_vmcs_fuzzing(pxch, 0, VMCS_BOOT_MONITORING_SETUP, BUFFER_DIM_FACTOR * gran_exit, NULL);

      // 監視完了を待機
      res = 0;
      while (res != 1) {
        nanosleep(&tim, &tim2);
        res = xc_vmcs_fuzzing(pxch, 0, VMCS_BOOT_MONITORING_CHECK, 0, NULL);
      }

      // バッファを再利用（malloc/freeを繰り返さない）
      memset(buffer, 0, boot_buffer_size);
      res = xc_vmcs_fuzzing(pxch, dom_id, VMCS_BOOT_MONITORING_STOP, BUFFER_DIM_FACTOR * gran_exit, buffer);

      // シード書き込み（ファイルは既にオープン済み）
      for (int j = 0; j < res; j++)
        fprintf(fp, "%" PRIx64 "\n", buffer[j]);

      printf("Exit recorded: #%d\n", i);

      // ループごとにfcloseしない

      // カバレッジの取得
      printf("Seed recorded: %d\n", i);
      sprintf(cmd, "xencov read > ./cov/cov_record%d.dat", i);
      system(cmd);
    }

    // ループ終了後に一度だけclose
    fclose(fp);
    free(buffer);

    // Destroy the test VM
    sprintf(cmd, "xl destroy hvm_guest");
    system(cmd);

    break;
  }

  case 'p': {
    printf("[mode] printing mode\n");

    unsigned int num_exit = atoi(argv[3]);
    seeds_t * seeds = malloc(sizeof(seeds_t));

    uint64_t * buffer = malloc(sizeof(uint64_t) * BUFFER_DIM_FACTOR * num_exit);
    uint64_t exit_reason = 0;
    int size_buffer = 0;
    FILE * fp;
    int i, j;

    if ((fp = fopen(argv[2], "r")) == NULL) {
      printf("Errore nell'apertura del file'");
      exit(1);
    }
    while (!feof(fp)) {
      fscanf(fp, "%"
        PRIx64 "\n", & buffer[size_buffer]);
      size_buffer++;
    }
    fclose(fp);

    raw_to_seeds(size_buffer, buffer, seeds, PRINT_MODE);

    for (i = 0; i < seeds -> size; i++) {
      printf("\nSEED #%ld \n", seeds -> seeds_items[i].id);
      for (j = 0; j < seeds -> seeds_items[i].size; j++) {
        if (seeds -> seeds_items[i].seed_items[j].field == 0x00004402) {
          exit_reason = seeds -> seeds_items[i].seed_items[j].value;
        }
        printf("%s: FIELD(%"
          PRIx64 "), VALUE(%"
          PRIx64 ")\n",
          type[seeds -> seeds_items[i].seed_items[j].type],
          seeds -> seeds_items[i].seed_items[j].field,
          seeds -> seeds_items[i].seed_items[j].value);
      }
      printf("EXIT REASON: %s\n", exit_reason_name[exit_reason]);
    }

    free(buffer);
    free(seeds);
    break;
  }

  case 'm': {
    unsigned int num_seeds = atoi(argv[2]); // Num of seeds to inject
    int dom_id = atoi(argv[3]);
    FILE *fp;
    char cmd[100]; // 固定サイズで十分なバッファを確保
    const char *file_name = "./seeds"; // 定数文字列として定義

    // システムコマンド実行前にディレクトリ存在確認
    if (access("./cov", F_OK) != 0) {
      system("mkdir -p ./cov");
    }

    // Reading seeds to be injected
    seeds_t seeds_data = {0}; // スタック上に確保し初期化
    seeds_t *seeds = &seeds_data;

    // サイズを事前計算し1回だけメモリ確保
    const size_t buffer_size = sizeof(uint64_t) * BUFFER_DIM_FACTOR * num_seeds;
    uint64_t *buffer = malloc(buffer_size);
    if (!buffer) {
      fprintf(stderr, "メモリ確保エラー\n");
      return -1;
    }
    memset(buffer, 0, buffer_size);

    if ((fp = fopen(file_name, "r")) == NULL) {
      fprintf(stderr, "Cannot open file: %s\n", file_name);
      free(buffer);
      return -1;
    }

    // 効率的なファイル読み込み
    int size_buffer = 0;
    while (size_buffer < BUFFER_DIM_FACTOR * num_seeds &&
           fscanf(fp, "%" PRIx64 "\n", &buffer[size_buffer]) == 1) {
      size_buffer++;
    }
    fclose(fp);

    // Parse raw seeds from file (MUTATION MODE discards vmwrites)
    if (raw_to_seeds(size_buffer, buffer, seeds, MUTATION_MODE) != 0) {
      fprintf(stderr, "シード解析エラー\n");
      free(buffer);
      return -1;
    }

    if (seeds->size != num_seeds) {
      printf("警告: 予想したシード数と異なります: %lu vs %u\n", seeds->size, num_seeds);
    }

    // Create a test VM in MUTATION MODE from a snapshot
    printf("VM初期化中...\n");
    xc_vmcs_fuzzing(pxch, 0, VMCS_NON_BLOCKING_MODE_ENABLE, 0, NULL);
    xc_vmcs_fuzzing(pxch, 0, VMCS_DEBUG_MODE_DISABLE, 0, NULL);
    xc_vmcs_fuzzing(pxch, dom_id, VMCS_BOOT_MUTATION_SETUP, 0, NULL);
    system("xl restore ./hvm_configuration.cfg ./guest_snap");

    // 注入バッファを1回だけ確保し再利用
    uint64_t *buffer_inject = NULL;
    size_t max_buffer_size = 0;

    // Foreach seed - 事前に最大バッファサイズを計算
    for (int j = 0; j < seeds->size; j++) {
      size_t current_size = seeds->seeds_items[j].size * 3;
      if (current_size > max_buffer_size) {
        max_buffer_size = current_size;
      }
    }

    buffer_inject = malloc(sizeof(uint64_t) * max_buffer_size);
    if (!buffer_inject) {
      fprintf(stderr, "注入バッファのメモリ確保エラー\n");
      free(buffer);
      return -1;
    }

    printf("シード注入開始...\n");
    // Foreach seed
    for (int j = 0; j < seeds->size; j++) {
      int dim_buffer = seeds->seeds_items[j].size * 3;
      uint64_t exit_reason = 0;
      int count = 0;

      // 1回だけ確保したバッファを再利用
      memset(buffer_inject, 0, sizeof(uint64_t) * dim_buffer);

      for (int k = 0; k < seeds->seeds_items[j].size; k++) {
        if (seeds->seeds_items[j].seed_items[k].field == 0x00004402) {
          exit_reason = seeds->seeds_items[j].seed_items[k].value;
        }

        buffer_inject[count] = seeds->seeds_items[j].seed_items[k].field;
        buffer_inject[count + 1] = seeds->seeds_items[j].seed_items[k].value;
        buffer_inject[count + 2] = seeds->seeds_items[j].seed_items[k].type;
        count += 3;
      }

      // Filter EPT MISCONFIG
      if (exit_reason != 49 && exit_reason != 12) {
        printf("SEED注入: #%d, シードID #%lu\n", j, seeds->seeds_items[j].id);

        // Waiting for the pending exit and reset coverage
        while (xc_vmcs_fuzzing(pxch, dom_id, VMCS_BOOT_MUTATION_CHECK, 0, NULL) == 1) {
          // 短いスリープを追加してCPU使用率を抑える
          usleep(1000); // 1ミリ秒待機
        }
        system("xencov reset");

        // Seed injection
        res = xc_vmcs_fuzzing(pxch, dom_id, VMCS_MUTATION_START_NEW_ITERATION_NO_BLOCKING,
                             dim_buffer, buffer_inject);
        printf("変異結果: %d\n", res);

        // Waiting for the end of exit and retrieve coverage
        while (xc_vmcs_fuzzing(pxch, dom_id, VMCS_BOOT_MUTATION_CHECK, 0, NULL) == 1) {
          usleep(1000);
        }
        snprintf(cmd, sizeof(cmd), "xencov read > ./cov/cov_replay%d.dat", j);
        system(cmd);
      } else {
        printf("SEED破棄: #%d, 理由: %s\n", j, exit_reason_name[exit_reason]);
      }
    }

    // リソース解放
    for (int i = 0; i < seeds->size; i++) {
      free(seeds->seeds_items[i].seed_items);
    }
    free(seeds->seeds_items);
    free(buffer);
    free(buffer_inject);

    printf("変異モード無効化中...\n");
    // Disable mutation mode
    xc_vmcs_fuzzing(pxch, dom_id, VMCS_BOOT_MUTATION_DISABLE, 0, NULL);

    // Destroy the test VM
    printf("VM終了中...\n");
    system("xl destroy hvm_guest");

    break;
  }

  default: {
    printf("This mode is not available \n");
    return -1;
  }

  }
  xc_interface_close(pxch);
  return 0;
}

int raw_to_seeds(int size_buffer, uint64_t * buffer, seeds_t * seeds, int mode) {

  int i, j, i_count;
  int size = size_buffer;
  unsigned long * sizes = malloc(sizeof(unsigned long) * size);
  unsigned long * indexes = malloc(sizeof(unsigned long) * size);

  if (size % 3 == 1) return -1;
  i_count = -1;

  for (i = 0; i < size; i = i + 3) {
    if (buffer[i] == 0xFFFFFFFF && buffer[i + 1] == 0xFFFFFFFF && buffer[i + 2] == 0) {
      i_count++; // number of vmexits
      indexes[i_count] = i; // index of first row related to a vmexit
      sizes[i_count] = 0; // number of reads/writes within a vmexit
    } else if (i_count >= 0) {
      sizes[i_count]++;
    }
  }
  i_count++;

  seeds -> size = i_count;
  seed_t * seeds_items = malloc(sizeof(seed_t) * i_count);

  // Foreach vmexit
  for (i = 0; i < i_count; i++) {
    int count = 0;
    int type = 0;
    seeds_items[i].id = i;
    bin_data_t * data = malloc(sizeof(bin_data_t) * sizes[i]);

    // Foreach read/write within a vmexit
    for (j = 0; j < sizes[i] * 3; j = j + 3) {
      if (mode == MUTATION_MODE) type = buffer[indexes[i] + j + 5];
      else if (mode == PRINT_MODE) type = 999;
      if (type != 0) {
        data[count].field = buffer[indexes[i] + j + 3];
        data[count].value = buffer[indexes[i] + j + 4];
        data[count].type = buffer[indexes[i] + j + 5];
        count++;
      }
    }
    seeds_items[i].seed_items = data;
    seeds_items[i].size = count;
  }
  seeds -> seeds_items = seeds_items;

  return 0;
}
