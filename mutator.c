#include "afl-fuzz.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct dummy_mutator {
  afl_state_t *afl;
  FILE *telementry_file;
} dummy_mutator_t;

dummy_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  srand(seed);

  dummy_mutator_t *data = calloc(1, sizeof(dummy_mutator_t));

  data->afl = afl;
  data->telementry_file = fopen("telementry.txt", "w");

  return data;
}

size_t afl_custom_fuzz(dummy_mutator_t *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
  fprintf(data->telementry_file, "\n-- afl_custom_fuzz called --\n\n");

  fprintf(data->telementry_file, "queue data:\n");
  for (int i = 0; i < data->afl->queued_items; ++i) {
    struct queue_entry *entry = data->afl->queue_buf[i];
    fprintf(data->telementry_file, "  * entry %d:\n", i);
    fprintf(data->telementry_file, "      * file path: %s\n", entry->fname);
    fprintf(data->telementry_file, "      * favored: %s\n", entry->favored ? "true" : "false");
  }

  *out_buf = buf;

  return buf_size;
}

void afl_custom_deinit(dummy_mutator_t *data) {
  fclose(data->telementry_file);
  free(data);
}
