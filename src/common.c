
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

struct p_thread {
	timer_t timer_id;
	unsigned int n_overrun;
};
struct p_thread tt_thread[SR_CTR_NUM+1];

void sig_block(void) {
	sigset_t sigmask, oldmask;
#ifdef _DEBUG
	int i;
#endif

	sigemptyset(&sigmask);

	sigaddset(&sigmask, SIGRTMIN);

#ifdef _DEBUG 
	for (i= 1; i <= SR_CTR_NUM; i++)  
		sigaddset(&sigmask, SIGRTMIN+i);
#endif

	pthread_sigmask(SIG_BLOCK, &sigmask, &oldmask);
}

void clock_handler (int sig, siginfo_t *info, void * context) {
	//  int value, cpu_id;
	int index;

	index = sig - SIGRTMIN;

	//  cpu_id = sched_getcpu();

	tt_thread[index].n_overrun += timer_getoverrun (tt_thread[index].timer_id);

	//  printf("timer %d hit, cpu = %d \n", index, cpu_id);
}


void start_clock(unsigned int sig_offset,
				 unsigned long long start_offset, 
				 unsigned long long interval) 
{   // in micro sec

	timer_t timer;

	sigset_t sigmask;
	struct sigevent sigev;
	struct itimerspec itval, oitval;

	struct sigaction newact;


	tt_thread[sig_offset].n_overrun = 0;

	newact.sa_flags = SA_SIGINFO;
	newact.sa_sigaction = clock_handler;

	sigaction (SIGRTMIN+sig_offset, &newact, NULL);

	sig_block();    // block all timer signals

	sigev.sigev_notify = SIGEV_SIGNAL;
	sigev.sigev_signo = SIGRTMIN+sig_offset;
	sigev.sigev_value.sival_ptr = &(tt_thread[sig_offset].timer_id);

	timer_create(CLOCK_REALTIME, &sigev, &(tt_thread[sig_offset].timer_id));
	if (start_offset >= 1000000) {
		itval.it_value.tv_sec = start_offset / 1000000;
		itval.it_value.tv_nsec = (start_offset%1000000)*1000;
	} else if (start_offset == 0) {
		itval.it_value.tv_sec = 0;
		itval.it_value.tv_nsec = 1;
	} else {
		itval.it_value.tv_sec = 0;
		itval.it_value.tv_nsec = start_offset*1000;
	}
	if (interval >= 1000000) {
		itval.it_interval.tv_sec = interval / 1000000;
		itval.it_interval.tv_nsec = (interval%1000000)*1000;
	} else {
		itval.it_interval.tv_sec = 0;
		itval.it_interval.tv_nsec = interval*1000;
	}

	timer_settime(tt_thread[sig_offset].timer_id, 0, &itval, &oitval);
}

int set_cpu (unsigned int cpu_id)
{
	cpu_set_t my_cpu_set;
	int result;

	CPU_ZERO(&my_cpu_set);
    CPU_SET(cpu_id, &my_cpu_set);
    result = pthread_setaffinity_np(pthread_self(), 
									sizeof(cpu_set_t), &my_cpu_set);
    return result;
}

int pthread_create_by_cpu(	pthread_t *thread, 
							unsigned int cpu, 
							void *(*start_routine)(void *), 
							void *arg)
{
    pthread_attr_t  new_attr;
    cpu_set_t       cpuset;
    struct sched_param s_param;
    int             retval = 0;

    pthread_attr_init(&new_attr);

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    /* bind process to core N */
    pthread_attr_setaffinity_np(&new_attr, sizeof(cpuset), &cpuset);

    if(pthread_create(thread, &new_attr, start_routine, arg) != 0) {
        retval = 1;
        fprintf(stderr, "ERROR: %s\n", __FUNCTION__);
    }

    pthread_attr_destroy(&new_attr);

    return retval;
}


