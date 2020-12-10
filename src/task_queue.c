#include <stdlib.h>
#include <pthread.h>

#include "task_queue.h"

struct queue_job {
	task_func_t 		func;
	void 			*arg;
	struct queue_job 	*next;
};
typedef struct queue_job queue_job_t;

struct task_queue {
	queue_job_t 	*next;
	queue_job_t 	*last;
	pthread_mutex_t mutex;
	int 		active_tasks;
	int 		size;
	int 		suspended;
};

static int max_active_tasks;

static queue_job_t * queue_job_create(task_func_t func, void *arg);
static void queue_job_destroy(queue_job_t *qj);
static queue_job_t * queue_job_get_next(task_queue_t *tq);
static void * queue_job_exec(void *arg_tq);



task_queue_t * task_queue_create(const int max_threads) {
	task_queue_t *tq = (task_queue_t *)malloc(sizeof(task_queue_t));

	if (!tq) {
		return NULL;
	}

	tq->next 		= NULL;
	tq->last 		= NULL;
	tq->active_tasks 	= 0;
	tq->size	 	= 0;
	tq->suspended 		= 0;
	pthread_mutex_init(&(tq->mutex), NULL);
	
	max_active_tasks = max_threads > 0 ? max_threads : 1;

	return tq;
}

void task_queue_destroy(task_queue_t *tq) {
	queue_job_t *qj1, *qj2;

	if (!tq) {
		return; 
	}
	
	pthread_mutex_lock(&(tq->mutex));	
	tq->suspended = 1;

	qj1 = tq->next;
	while (qj1) {
		qj2 = qj1->next;
		queue_job_destroy(qj1);
		qj1 = qj2;
	}

	pthread_mutex_destroy(&(tq->mutex));

	free(tq);	
}

int task_queue_enqueue(task_queue_t *tq, task_func_t task, void *arg) {
	queue_job_t *qj;
	pthread_t thread;
	int i, can_run, need_run, run, ret;

	if (!tq || !task) {
		return -1;
	}
	
	qj = queue_job_create(task, arg);

	if (!qj) {
		return -1;
	}

	pthread_mutex_lock(&(tq->mutex));
	if (!tq->next) {
		tq->next = qj;
		tq->last = qj;
	} else {
		tq->last->next 	= qj; // assign next
		tq->last 	= qj; // move pointer
	}

	tq->size++;

	if ((tq->active_tasks < max_active_tasks) & !tq->suspended) {
		can_run = max_active_tasks - tq->active_tasks;
		need_run = tq->size - tq->active_tasks;
		run = need_run < can_run ? need_run : can_run;		

		for (i = 0; i < run; i++) {
			if (pthread_create(&thread, NULL, queue_job_exec, tq) < 0) {
				// perror("new thread creation error");
			} else {
				pthread_detach(thread);
				tq->active_tasks++;
			}
		}
	}

	ret = tq->active_tasks;	
	pthread_mutex_unlock(&(tq->mutex));

	return ret;
}

void task_queue_suspend(task_queue_t *tq) {
	if (!tq) {
		return;
	}

	pthread_mutex_lock(&(tq->mutex));
	tq->suspended = 1;
	pthread_mutex_unlock(&(tq->mutex));
}

void task_queue_unsuspend(task_queue_t *tq) {
	pthread_t thread;
	int i, can_run, need_run, run;

	if (!tq) {
		return;
	}

	pthread_mutex_lock(&(tq->mutex));
	tq->suspended = 0;

	if (tq->size && tq->active_tasks < max_active_tasks) {
		can_run = max_active_tasks - tq->active_tasks;
		need_run = tq->size - tq->active_tasks;
		run = need_run < can_run ? need_run : can_run;		
		
		for (i = 0; i < run; i++) {
			if (pthread_create(&thread, NULL, &queue_job_exec, tq) < 0) {
				// perror("new thread creation error");
			} else {
				pthread_detach(thread);
				tq->active_tasks++;
			}
		}
	}
	pthread_mutex_unlock(&(tq->mutex));
}

int task_queue_get_size(task_queue_t *tq) {
	int res;
	pthread_mutex_lock(&(tq->mutex));
	res = tq->size;
	pthread_mutex_unlock(&(tq->mutex));
	return res;
}

int task_queue_is_empty(task_queue_t *tq) {
	return task_queue_get_size(tq) == 0;
}

static queue_job_t * queue_job_create(task_func_t func, void *arg) {
	queue_job_t *qj;

	if (!func) {
		return NULL;
	}
	
	qj = (queue_job_t *)malloc(sizeof(queue_job_t));
	qj->func 	= func;
	qj->arg 	= arg;
	qj->next	= NULL;

	return qj;
}

static void queue_job_destroy(queue_job_t *qj) {
	if (!qj) {
		return;
	}
	free(qj);
}

static queue_job_t * queue_job_get_next(task_queue_t *tq) {
	queue_job_t *qj;

	if (!tq) {
		return NULL;
	}
	
	pthread_mutex_lock(&(tq->mutex));
	if (tq->next) {
		qj = tq->next;
		tq->next = qj->next;
	} else {
		qj = NULL;
	}
	pthread_mutex_unlock(&(tq->mutex));

	return qj;
}


static void * queue_job_exec(void *arg_tq) {
	task_queue_t *tq = (task_queue_t *)arg_tq;
	queue_job_t *qj;
	pthread_t thread;
	int i, can_run, need_run, run;

	if (!tq) {
		return NULL;
	}
	
	qj = queue_job_get_next(tq);
	
	if (qj && qj->func) {
		qj->func(qj->arg);
	}
	
	queue_job_destroy(qj);

	pthread_mutex_lock(&(tq->mutex));
	tq->active_tasks--;
	tq->size--;
	if (tq->size && tq->active_tasks < max_active_tasks && !tq->suspended) {
		can_run = max_active_tasks - tq->active_tasks;
		need_run = tq->size - tq->active_tasks;
		run = need_run < can_run ? need_run : can_run;		
		
		for (i = 0; i < run; i++) {
			if (pthread_create(&thread, NULL, &queue_job_exec, tq) < 0) {
				// perror("new thread creation error");
			} else {
				pthread_detach(thread);
				tq->active_tasks++;
			}
		}
	}
	pthread_mutex_unlock(&(tq->mutex));
	return NULL;
}
