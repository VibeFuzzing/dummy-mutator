#include "afl-fuzz.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct dummy_mutator {
  afl_state_t *afl;
  time_t last_time;
  double delay1;
  int outputs_until_switch;
  double delay2;
} dummy_mutator_t;

void usage(void) {
  fprintf(stderr, "Please set either:\n");
  fprintf(stderr, "  * DUMMY_MUTATOR_DELAY alone (integer number of seconds) "
                  "for a consistent delay, or\n");
  fprintf(stderr, "  * DUMMY_MUTATOR_DELAY1, DUMMY_MUTATOR_DELAY2, and "
                  "DUMMY_MUTATOR_NUM_FAST to switch from a fast to a slow "
                  "cooldown after NUM_FAST iterations.\n");
}

void stall(void) {
  fprintf(stderr, "I'll stall for a few seconds to make sure you've read this, "
                  "then move on with life. Happy fuzzing!\n");
  sleep(10);
}

dummy_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  srand(seed);

  dummy_mutator_t *data = calloc(1, sizeof(dummy_mutator_t));

  data->afl = afl;
  time(&data->last_time);
  const char *delay_s = getenv("DUMMY_MUTATOR_DELAY");
  const char *delay1_s = getenv("DUMMY_MUTATOR_DELAY1");
  const char *delay2_s = getenv("DUMMY_MUTATOR_DELAY2");
  const char *num_fast_s = getenv("DUMMY_MUTATOR_NUM_FAST");

  if (!delay_s && !delay1_s && !delay2_s) {
    fprintf(stderr, "Delay for dummy mutator has not been set. This is bad!\n");
    usage();
    fprintf(stderr, "I will now crash the program. Goodbye!\n");
    abort();
  }

  if (mkdir("telemetry", 0755) != 0) {
    int err = errno;
    if (err != EEXIST) {
      fprintf(stderr,
              "There was an error making the telemetry directory: %s. This is "
              "bad!\n",
              strerror(err));
      fprintf(stderr, "I will now crash the program. Goodbye!\n");
      abort();
    }
  }

  if (delay_s && (delay1_s || delay2_s || num_fast_s)) {
    fprintf(stderr, "Delay for dummy mutator was specified in two different "
                    "ways. To make my job easier, I'm going to use the single "
                    "delay time, which is probably not what you want!\n");
    usage();
    data->delay1 = atoi(delay_s);
    data->outputs_until_switch = 0;
    data->delay2 = data->delay1;
    stall();
  }

  if (delay_s) {
    data->delay1 = atoi(delay_s);
    data->outputs_until_switch = 0;
    data->delay2 = data->delay1;
  } else if ((delay1_s && !delay2_s) || (!delay1_s && delay2_s) ||
             !num_fast_s) {
    fprintf(stderr, "Delay for dummy mutator was underspecified. To make my "
                    "job easier, I'm going to use one single delay time, which "
                    "is probably not what you want!\n");
    usage();
    int delay;
    if (delay1_s) {
      delay = atoi(delay1_s);
    } else {
      delay = atoi(delay2_s);
    }
    data->delay1 = delay;
    data->outputs_until_switch = 0;
    data->delay2 = delay;
    stall();
  } else {
    data->delay1 = atoi(delay1_s);
    data->outputs_until_switch = atoi(num_fast_s);
    data->delay2 = atoi(delay2_s);
  }

  return data;
}

size_t afl_custom_fuzz(dummy_mutator_t *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
  time_t cur_time = time(NULL);
  double time_passed = difftime(cur_time, data->last_time);

  if (((time_passed >= data->delay1) && data->outputs_until_switch > 0) ||
      ((time_passed >= data->delay2) && data->outputs_until_switch == 0)) {
    if (data->outputs_until_switch > 0)
      data->outputs_until_switch -= 1;

    data->last_time = cur_time;

    // -- DUMPING BUFFERS --

    // First, we need to pick a file path.
    // The general path format is `telemetry/YYYY-MM-DD-hh:mm:ss/xxxxxxxx.json`,
    // where Y/M/D are year/month/day, h/m/s are hour/minute/second, and x is
    // the ID in the queue.

    struct tm *t = localtime(&cur_time);
    char file_path[44];
    // stick with the directory path for now
    snprintf(file_path, sizeof(file_path),
             "telemetry/%04d-%02d-%02d-%02d:%02d:%02d", t->tm_year,
             t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

    if (mkdir(file_path, 0755) != 0) {
      int err = errno;
      if (err != EEXIST) {
        fprintf(
            stderr,
            "There was an error making a telemetry sub-directory: %s. This is "
            "bad!\n",
            strerror(err));
        fprintf(stderr, "I will now crash the program. Goodbye!\n");
        abort();
      }
    }

    for (int i = 0; i < data->afl->queued_items; ++i) {
      struct queue_entry *entry = data->afl->queue_buf[i];
      // 29 is the length of "telemetry/YYYY-MM-DD-hh:mm:ss"
      snprintf(&file_path[29], sizeof(file_path) - 29, "/%08d.json", entry->id);
      FILE *file = fopen(file_path, "wb");

      fprintf(file, "{\n");

      fprintf(file, "    \"id\": %d,\n", entry->id);
      fprintf(file, "    \"fname\": \"%s\",\n", entry->fname);

      fprintf(file, "    \"trimmed\": %s,\n",
              entry->trim_done ? "true" : "false");
      fprintf(file, "    \"passed_det\": %s,\n",
              entry->passed_det ? "true" : "false");
      fprintf(file, "    \"has_new_cov\": %s,\n",
              entry->has_new_cov ? "true" : "false");
      fprintf(file, "    \"var_behavior\": %s,\n",
              entry->var_behavior ? "true" : "false");
      fprintf(file, "    \"favored\": %s,\n",
              entry->favored ? "true" : "false");
      fprintf(file, "    \"fs_redundant\": %s,\n",
              entry->fs_redundant ? "true" : "false");
      fprintf(file, "    \"is_ascii\": %s,\n",
              entry->is_ascii ? "true" : "false");
      fprintf(file, "    \"disabled\": %s,\n",
              entry->disabled ? "true" : "false");
      
      fprintf(file, "    \"bitmap_size\": %d,\n", entry->bitmap_size);
      fprintf(file, "    \"fuzz_level\": %d,\n", entry->fuzz_level);

      fprintf(file, "    \"exec_us\": %lld,\n", entry->exec_us);
      fprintf(file, "    \"depth\": %lld,\n", entry->depth);
      fprintf(file, "    \"custom\": %lld,\n", entry->custom);
      fprintf(file, "    \"stats_mutated\": %lld,\n", entry->stats_mutated);

      fprintf(file, "    \"perf_score\": %f,\n", entry->perf_score);
      fprintf(file, "    \"weight\": %f,\n", entry->weight);

      if (entry->mother)
        fprintf(file, "    \"mother_id\": %d\n", entry->mother->id);
      else
        fprintf(file, "    \"mother_id\": -1\n");

      fprintf(file, "}\n");

      fclose(file);
    }
  }

  *out_buf = buf;

  return buf_size;
}

void afl_custom_deinit(dummy_mutator_t *data) { free(data); }
