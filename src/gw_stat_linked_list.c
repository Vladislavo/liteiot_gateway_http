#include "gw_stat_linked_list.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define APP_KEY_SIZE 	8

typedef struct _gw_stat_linked_list gw_stat_linked_list_t;

typedef struct _gw_stat_linked_list {
	char app_key[APP_KEY_SIZE+1];
	uint8_t dev_id;
	uint64_t num_msgs;
	struct _gw_stat_linked_list *next;
} _gw_stat_linked_list;

static gw_stat_linked_list_t *root;
static uint64_t size;

void gw_stat_linked_list_init(void) {
	root = NULL;
	size = 0;
}

uint8_t gw_stat_linked_list_add(const char *app_key, const uint8_t dev_id) {
	gw_stat_linked_list_t *ptr = root;
	uint8_t found = 0, ret = 1;

	while (ptr && !found) {
		if (!memcmp(ptr->app_key, app_key, APP_KEY_SIZE) && ptr->dev_id == dev_id) {
			found = 1;
		} else {
			ptr = ptr->next;
		}
	}
	
	if (ptr) {
		ptr->num_msgs++;
	} else {
		ptr = (gw_stat_linked_list_t *)malloc(sizeof(gw_stat_linked_list_t));
		if (ptr) {
			memcpy(ptr->app_key, app_key, APP_KEY_SIZE);
			ptr->app_key[APP_KEY_SIZE] = '\0';
			ptr->dev_id = dev_id;
			ptr->num_msgs = 1;
			ptr->next = root;
			root = ptr;

			size++;
		} else {
			ret = 0;
		}
	}

	return ret;
}

void gw_stat_linked_list_flush(char *store, uint8_t file) {
	gw_stat_linked_list_t *ptr = root, *tmp;
	char buf[64];
	FILE *fp;
	
	if (ptr && size) {
		if (file) { // file output
			fp = fopen(store, "w");
			
			while (ptr) {
				snprintf(buf, 64, "%s#%d#%lld|", ptr->app_key, ptr->dev_id, ptr->num_msgs);
				fwrite(buf, strlen(buf), 1, fp);
				
				tmp = ptr;
				ptr = ptr->next;
				free(tmp);
			}

			fclose(fp);
		} else { // str output
			store[0] = '\0';

			while (ptr) {
				snprintf(buf, 64, "%s#%d#%lld|", ptr->app_key, ptr->dev_id, ptr->num_msgs);
				strcat(store, buf);
				
				tmp = ptr;
				ptr = ptr->next;
				free(tmp);
			}
		}
		size = 0;
		root = NULL;
	}
}

void gw_stat_linked_list_destroy(void) {
	gw_stat_linked_list_t *ptr = root, *tmp;
	
	while (ptr && size) {
		tmp = ptr;
		ptr = ptr->next;
		free(tmp);
		
		size--;
	}
	root = NULL;
}
