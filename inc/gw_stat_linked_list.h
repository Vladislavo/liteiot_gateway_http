#ifndef GW_STAT_LINKED_LIST_H
#define GW_STAT_LINKED_LIST_H

#include <stdint.h>

void gw_stat_linked_list_init(void);

uint8_t gw_stat_linked_list_add(const char *app_key, const uint8_t dev_id);

void gw_stat_linked_list_flush(char *store, uint8_t file);

void gw_stat_linked_list_destroy(void);

#endif // GW_STAT_LINKED_LIST_H
