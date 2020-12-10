#ifndef __TASK_QUEUE_H__
#define __TASK_QUEUE_H__

/* Task queue that create threads for completing tasks
 * having an upper threads limit 
 */


struct task_queue;
typedef struct task_queue task_queue_t;

typedef void (*task_func_t)(void *arg);


task_queue_t * task_queue_create(const int max_threads);

void task_queue_destroy(task_queue_t *tq);

int task_queue_enqueue(task_queue_t *tq, task_func_t task, void *arg);

void task_queue_suspend(task_queue_t *tq);

void task_queue_unsuspend(task_queue_t *tq);

int task_queue_get_size(task_queue_t *tq);

int task_queue_is_empty(task_queue_t *tq);

#endif // __TASK_QUEUE_H__
