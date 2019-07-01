/* copyright jun851102 */
#define __DEBUG
#define __SIMULATE

//#define PING_PONG

#define _GNU_SOURCE

////////////////////////////////////////////////////////////////////////////////
//
// 샘플 코드 작성시 고려하지 않은 사항
//
// 1. 워커별 임계치를 합산하고 초기화 하는 과정에서 오차가 발생함
// 2. 워커별 통계를 합산하고 초기화 하는 과정에서 오차가 발생함
//  - 실제 코드에서는 2개의 버퍼를 운영하면서 스위칭하는 구조
//
// 3. thread 간의 변수 값이 레지스터화 또는 캐쉬에 등록되어 공유되지 않는 현상
//  - volatile 지시자를 이용하여 제어
//
////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>

#include <sched.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <signal.h>
#include <time.h>

#ifdef PING_PONG
#include <x86intrin.h> //AVX/SSE Extensions
#endif

#define RANDOM_SEED         (268435455) // 랜덤값 재현을 위해 사용할 소수값

#define SR_RULE_SIZE        (1000)
#define SR_RULE_THRESHOLD   (10000)
#define SR_WORKER_NUM       (12)
//#define SR_WORKER_NUM       (20)

#define SR_CTR_NUM         (2)


#include "common.c"            // added by teamKim



volatile int stat_run = 0;    // if 1, statistics_thread is running, the controller must wait

enum rule_action{
  SR_PERMIT = 0,
  SR_DETECT = 1,
  SR_BLOCK = 2,
};

enum rule_control{
  SR_NOT_CONTROL = 0,
  SR_CONTROL = 1,
};



typedef struct sr_rule_config_s {
  int32_t action;      // 0: permit, 1: detect, 2: block
  int32_t is_control; // 제어 플래그 ( 0: not control, 1: control )
  int32_t g_threshold;
} sr_rule_config_t;

typedef struct sr_rule_statistics_s {
  uint64_t input_cnt; // 입력된 패킷 카운트
  uint64_t permit_cnt; // 허용된 패킷 카운트 ( 해당값이 임계치보다 크면 제어 )
  uint64_t block_cnt; // 차단된 패킷 카운트 ( 제어시 입력된 패킷 카운트)
} sr_rule_statistics_t;

typedef struct sr_worker_s {
#ifdef PING_PONG
  sr_rule_statistics_t rule_stat[2][SR_RULE_SIZE+1];
#else
  // jgson
  sr_rule_statistics_t rule_stat[SR_RULE_SIZE+1];
#endif
} sr_worker_t;

typedef struct sr_manager_s {
  sr_rule_config_t rule_cfg[SR_RULE_SIZE];
#ifdef PING_PONG
  sr_rule_statistics_t rule_stat[2][SR_RULE_SIZE];
  volatile uint8_t cur_rule_stat_idx;    // ping pong index
#else
  sr_rule_statistics_t rule_stat[SR_RULE_SIZE];
#endif

  sr_worker_t *p_wrk[SR_WORKER_NUM];
} sr_manager_t;


static sr_manager_t g_mgr;


////////////////////////////////////////////////////////////////////////////////
//
// 자료 구조 생성을 위한 함수들
//
//
// - init_sr_manager : Static Ratelimit 엔진을 관리하는 매니저 자료구조 초기화
// - create_sr_worker : Static Ratelimit 엔진에서 워커별로 사용할 자료구조를
//                     생성하고 매니저에 등록
// - wait_sr_worker : 워커들의 초기화 완료를 기다림
//
////////////////////////////////////////////////////////////////////////////////

void init_sr_manager(void)
{
  int32_t i, j;
  sr_rule_config_t *p_rule_cfg;
  sr_rule_statistics_t *p_rule_stat;

  for (i = 0; i < SR_RULE_SIZE; i++)
  {
    p_rule_cfg = &(g_mgr.rule_cfg[i]);

    p_rule_cfg->action = SR_BLOCK;
    p_rule_cfg->is_control = SR_NOT_CONTROL;
    p_rule_cfg->g_threshold = SR_RULE_THRESHOLD;
  }

#ifdef PING_PONG
  for (i = 0; i < 2; i++)
  {
#endif
    for (j= 0; j <SR_RULE_SIZE; j++)
    {
#ifdef PING_PONG
      p_rule_stat = &(g_mgr.rule_stat[i][j]);
#else
      p_rule_stat = &(g_mgr.rule_stat[j]);
#endif

      p_rule_stat->input_cnt = 0;
      p_rule_stat->permit_cnt = 0;
      p_rule_stat->block_cnt = 0;
    }
#ifdef PING_PONG
  }
  g_mgr.cur_rule_stat_idx = 0;
#endif

  for (i = 0; i < SR_WORKER_NUM; i++)
  {
    g_mgr.p_wrk[i] = NULL;
  }
}

sr_worker_t *create_sr_worker(int64_t wrk_id)
{
  int32_t i,j;
  sr_worker_t *p_wrk = malloc(sizeof(sr_worker_t));
  sr_rule_statistics_t *p_rule_stat;

#ifdef PING_PONG
  for (i = 0; i < 2; i++)
  {
#endif
    for (j = 0; j < SR_RULE_SIZE; j++)
    {
#ifdef PING_PONG
      p_rule_stat = &(p_wrk->rule_stat[i][j]);
#else
      p_rule_stat = &(p_wrk->rule_stat[j]);

#endif
      p_rule_stat->input_cnt = 0;
      p_rule_stat->permit_cnt = 0;
      p_rule_stat->block_cnt = 0;
    }

#ifdef PING_PONG
  }
#endif

  return g_mgr.p_wrk[wrk_id] = p_wrk;
}

void wait_sr_worker(void)
{
  int32_t i;

  for (i = 0; i < SR_WORKER_NUM; i++)
  {
    while (NULL == g_mgr.p_wrk[i])
    {
      usleep(10);
    }
  }
}

////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
//
// NIC 에서 패킷을 읽어서 분석하는 부분에 대한 코멘트
//
// - 실제 장비에서는 NIC 로 부터 패킷을 읽고, 파싱한후 비교 검사 로직을
//  수행 하지만, 해당 코드는 컨셉을 나타내는 슈도형식의 코드로 작성하였으므로,
//  4BYTE 의 랜덤 IP 를 읽는 과정으로 단순화 시킴
//
// - init_input_value : 워커별 입력값의 초기값 설정 (srand 의 역할)
// - read_input_value : 워커별로 랜덤한 4BYTE 의 값을 생성 (100% 랜덤 보장 X)
//
////////////////////////////////////////////////////////////////////////////////

static __thread uint32_t g_val;

void init_input_value(uint32_t val)
{
  g_val = val;
}

uint32_t read_input_value()
{
  return g_val += RANDOM_SEED;
}

////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
//
// 분석된 패킷이 설정된 정책에 매칭되는지 검사하는 부분에 대한 코멘트
//
// - 실제 장비에서는 Hash Table, Ip Search Tree 등의 자료구조를 활용해서
//  매칭되는 정책을 검사하지만, 해당 코드에서는 단순화를 위하여 나머지 연산자를
//  이용하여 인덱스를 매칭되는 정책 ID 라 가정함
//
// - search_matching_sr_rule_id : 4BYTE 의 IP 값을 정책 아이디로 변환
//
//
////////////////////////////////////////////////////////////////////////////////

int32_t search_matching_sr_rule_id(uint32_t val) {
  return val % SR_RULE_SIZE;
}

////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
//
// 패킷을 읽어서 분석한후, 정책에 매칭되는지 검사하는 워커 스레드
//
////////////////////////////////////////////////////////////////////////////////


void *sr_worker(void *arg)
{
  int64_t wrk_id =(int64_t)arg;

  int32_t i;
  int32_t rule_id;
  uint32_t val;

  sr_worker_t *p_wrk;
  sr_rule_config_t *p_rule_cfg;
  sr_rule_statistics_t *p_local_rule_stat;
#ifdef PING_PONG
  sr_rule_statistics_t *p_local_sum;
#endif

  p_wrk = create_sr_worker(wrk_id);
  init_input_value(wrk_id);

#ifdef __DEBUG
  printf("Worker    id = %2d cpu = %2d, pid = %4d tid = %4d\n",
      wrk_id, sched_getcpu(), getpid(), syscall(SYS_gettid));
  fflush(stdout);
#endif

  sig_block();

  for (;;)
  {
    val = read_input_value();

    rule_id = search_matching_sr_rule_id(val);

    if (0 <= rule_id)
    {
#ifdef PING_PONG
      uint8_t _index = g_mgr.cur_rule_stat_idx;

      p_rule_cfg = &(g_mgr.rule_cfg[rule_id]);
      p_local_rule_stat = &(p_wrk->rule_stat[_index][rule_id]);
      p_local_sum = &(p_wrk->rule_stat[_index][SR_RULE_SIZE]);

      p_local_rule_stat->input_cnt++;
      p_local_sum->input_cnt++;

      if (p_rule_cfg->is_control == SR_NOT_CONTROL)
      {
        p_local_rule_stat->permit_cnt++;
        p_local_sum->permit_cnt++;
      }
      else
      {
        p_local_rule_stat->block_cnt++;
        p_local_sum->block_cnt++;
      }
#else
      p_rule_cfg = &(g_mgr.rule_cfg[rule_id]);

      p_local_rule_stat = &(p_wrk->rule_stat[rule_id]);
      p_local_rule_stat->input_cnt++;

      // jgson
      p_wrk->rule_stat[SR_RULE_SIZE].input_cnt++;


      if (p_rule_cfg->is_control == SR_NOT_CONTROL)
      {
        p_local_rule_stat->permit_cnt++;
      }
      else
      {
        p_local_rule_stat->block_cnt++;
      }
#endif  // PING_PONG
    }
#ifdef __SIMULATE
#define _mm_pause()  __asm__ __volatile__ ("pause")
    {
      int t = 10;
      while((t--) > 0)
        _mm_pause();
    }
#endif
  }


  return NULL;
}

////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
//
// 워커 스레드의 메시지를 분석하고, 정책의 제어여부를 설정하는 스레드
//
////////////////////////////////////////////////////////////////////////////////

void *sr_control(void *arg )
{
  register int i, j;
#ifdef PING_PONG
  uint32_t _index;
#endif

  register sr_worker_t *p_wrk;
  sr_rule_config_t *p_rule_cfg;
  volatile sr_rule_statistics_t *p_global_rule_stat;
  volatile sr_rule_statistics_t *p_local_rule_stat;

  int start, range;
  int length = SR_RULE_SIZE / SR_CTR_NUM;

  int64_t ctr_id = (int64_t)arg;

  start = ctr_id * length;
  range = start + length;

#ifdef __DEBUG
  printf("Controler id = %2d cpu = %2d, pid = %4d tid = %4d \n",
      ctr_id, sched_getcpu(), getpid(), syscall(SYS_gettid));
  fflush(stdout);
#endif

  wait_sr_worker();  // wait for init. of workers

  while (1)
  {
    usleep(10);

#ifdef PING_PONG
    for (j = start; j < range; j++)
    {
      _index = g_mgr.cur_rule_stat_idx;

      p_global_rule_stat = &(g_mgr.rule_stat[_index][j]);
      p_rule_cfg = &(g_mgr.rule_cfg[j]);

      for (i = SR_WORKER_NUM; i--;)
      {
        p_wrk = g_mgr.p_wrk[i];
        p_local_rule_stat = &(p_wrk->rule_stat[_index][j]);

        p_global_rule_stat->permit_cnt += p_local_rule_stat->permit_cnt;
        p_local_rule_stat->permit_cnt = 0;
      }

      // threshold overflow
      if (p_rule_cfg->g_threshold <= p_global_rule_stat->permit_cnt)
      {
        p_rule_cfg->is_control = SR_CONTROL;
      }
    }  // end rules
#else
    while (stat_run == 1);     // waiting for the statistics thread's finish when overlapped
    // this is to reduce the gap between tot_input and tot_permit + tot_block
    // but the size of the gap is not important this statement can be removed.

    for (i = 0; i < SR_WORKER_NUM; i++)
    {
      p_wrk = g_mgr.p_wrk[i];

      for (j = start, p_local_rule_stat = &(p_wrk->rule_stat[start]); j < range; j++, p_local_rule_stat++)
      {    // when multiple controller are used, rules(reposible) are divided evenly into contrller threads

        if (p_local_rule_stat->input_cnt)
        {

          p_rule_cfg = &(g_mgr.rule_cfg[j]);

          p_global_rule_stat = &(g_mgr.rule_stat[j]);

          p_global_rule_stat->input_cnt += p_local_rule_stat->input_cnt;
          p_global_rule_stat->permit_cnt += p_local_rule_stat->permit_cnt;
          p_global_rule_stat->block_cnt += p_local_rule_stat->block_cnt;

          // threshold overflow
          if (p_rule_cfg->g_threshold <= p_global_rule_stat->permit_cnt)
          {
            p_rule_cfg->is_control = SR_CONTROL;
          }

          p_local_rule_stat->input_cnt = 0;
          p_local_rule_stat->permit_cnt = 0;
          p_local_rule_stat->block_cnt = 0;
        }
      }  // end rules
    }      // end workers
#endif // PING_PONG --------------------------------------------------------------------------------
  }  // end: infinite loop body

  return NULL;
}

////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
//
// 워커 스레드에서의 개별 통계를 합산하는 스레드
//
////////////////////////////////////////////////////////////////////////////////


void *sr_statistics(void)
{
  int32_t i, j;
#ifdef PING_PONG
  uint8_t _index;
  uint64_t  check_permit_cnt = 0;
#endif

  uint64_t tot_input_cnt, tot_permit_cnt, tot_block_cnt;
  sr_worker_t *p_wrk;
  sr_rule_config_t *p_rule_cfg;
  sr_rule_statistics_t *p_global_rule_stat;
  sr_rule_statistics_t *p_local_rule_stat;

  //jgson
  uint64_t  check_tot_input_cnt = 0;


  wait_sr_worker();

  // set a POSIX timer to run every 1 sec
  start_clock((unsigned int)0, (unsigned long long)1000000, (unsigned long long)1000000);

  while (1)
  {
    sigpause(SIGRTMIN);    // to be invokeed by the POSIX timer (RTMIN is used): when invoked, SIGRTMIN will be blocked again

    stat_run = 1;  // to prevent overlap with the controler_thread

    tot_input_cnt = tot_permit_cnt = tot_block_cnt = 0;

#ifdef PING_PONG //------------------------------------------------------------------------------------------
    _index = g_mgr.cur_rule_stat_idx;
    g_mgr.cur_rule_stat_idx = (g_mgr.cur_rule_stat_idx + 1)%2;

    check_permit_cnt = 0;
    for (i = 0, p_rule_cfg = &(g_mgr.rule_cfg[0]); i < SR_RULE_SIZE; i++, p_rule_cfg++)
    {
      check_permit_cnt += g_mgr.rule_stat[_index][i].permit_cnt;
      p_rule_cfg->is_control = SR_NOT_CONTROL;
    }

    for (i = SR_WORKER_NUM; i--;)
    {
      p_wrk = g_mgr.p_wrk[i];
      p_local_rule_stat = &(p_wrk->rule_stat[_index][SR_RULE_SIZE]);

      tot_input_cnt += p_local_rule_stat->input_cnt;
      tot_permit_cnt += p_local_rule_stat->permit_cnt;
      tot_block_cnt += p_local_rule_stat->block_cnt;

      p_local_rule_stat->input_cnt = 0;
      p_local_rule_stat->permit_cnt = 0;
      p_local_rule_stat->block_cnt = 0;

      for (j = SR_RULE_SIZE, p_local_rule_stat = &(p_wrk->rule_stat[_index][0]); j--; p_local_rule_stat++)
      {
        p_local_rule_stat->input_cnt = 0;
        p_local_rule_stat->permit_cnt = 0;
        p_local_rule_stat->block_cnt = 0;
      }
    }

    for (i = SR_RULE_SIZE, p_global_rule_stat = &(g_mgr.rule_stat[_index][SR_RULE_SIZE-1]); i--;  p_global_rule_stat--)
    {
#ifdef __DEBUG
      {
        float rate = (float)p_global_rule_stat->permit_cnt / (float)g_mgr.rule_cfg[i].g_threshold * 100 - 100;
        printf("rule %4d permit %ld,overflow rate = %lf\n",
            i, p_global_rule_stat->permit_cnt, rate);
      }
#endif
      p_global_rule_stat->permit_cnt = 0;
    }


#else  // PING_PONG ---------------------------------------------------------------------------------------
    for (i = 0, p_global_rule_stat = &(g_mgr.rule_stat[0]); i< SR_RULE_SIZE;p_global_rule_stat++, i++)
    {

#ifdef __DEBUG
      {
        float rate = (float)p_global_rule_stat->permit_cnt / (float)g_mgr.rule_cfg[i].g_threshold * 100 - 100;
        printf("rule %4d permit %ld,overflow rate = %lf\n",
            i, p_global_rule_stat->permit_cnt, rate);
      }
#endif  // __DEBUG

      tot_input_cnt += p_global_rule_stat->input_cnt;
      tot_permit_cnt += p_global_rule_stat->permit_cnt;
      tot_block_cnt += p_global_rule_stat->block_cnt;

      p_global_rule_stat->input_cnt = 0;
      p_global_rule_stat->permit_cnt = 0;
      p_global_rule_stat->block_cnt = 0;
    }

#ifdef __DEBUG
    check_tot_input_cnt = 0;
    for (i = SR_WORKER_NUM; i--;)
    {
      p_wrk = g_mgr.p_wrk[i];
      check_tot_input_cnt += p_wrk->rule_stat[SR_RULE_SIZE].input_cnt;
      p_wrk->rule_stat[SR_RULE_SIZE].input_cnt = 0;;
    }
    printf("[DEBUG] Verify input count = %ld\n", check_tot_input_cnt);
#endif
#endif  // PING_PONG ---------------------------------------------------------------------------------------

    stat_run = 0;    // release the controler_thread


#ifdef __DEBUG
    printf("INPUT [%ld], PERMIT [%ld], BLOCK [%ld] per=%f dif=%ld \n",
        tot_input_cnt, tot_permit_cnt, tot_block_cnt,
        (float)(tot_permit_cnt+tot_block_cnt)/tot_input_cnt*100,
        tot_input_cnt - (tot_permit_cnt+tot_block_cnt));
    fflush(stdout);

#ifdef PING_PONG
    if (tot_permit_cnt != check_permit_cnt )
    {
      fprintf(stderr, "[DEBUG] PERMIT COUNT IS NOT MATCH! %ld\n", tot_permit_cnt - check_permit_cnt);
    }
#endif  // PING_PONG


#if 0
    for (i = 0; i <SR_CTR_NUM; i++)
      printf("timer %d overrun = %d\n", i+1, tt_thread[i+1].n_overrun);
#endif

    if (tot_input_cnt != tot_permit_cnt + tot_block_cnt)
    {
      fprintf(stderr, "[DEBUG] TOTAL COUNT MISMATCH! difference = %ld \n",
          tot_input_cnt - (tot_permit_cnt + tot_block_cnt));
    }
#endif

#ifdef PING_PONG
#else
    for (i = 0, p_rule_cfg = &(g_mgr.rule_cfg[0]); i < SR_RULE_SIZE; i++, p_rule_cfg++)
    {
      p_rule_cfg->is_control = SR_NOT_CONTROL;
    }
#endif
  }

  return NULL;
}

////////////////////////////////////////////////////////////////////////////////
//
// Static Ratelimit 테스트 프로그램
//
////////////////////////////////////////////////////////////////////////////////


int32_t main(void)
{
  int64_t i;
  pthread_t wrk_thr[SR_WORKER_NUM];
  pthread_t control_thr;

  //   set_cpu(0);  // set the CPU for main thread

  init_sr_manager();

  // create multiple worker threads
  for (i = 0; i < SR_WORKER_NUM; i++)
  {
    pthread_create_by_cpu(&wrk_thr[i], i+SR_CTR_NUM+1, sr_worker, (void*)i);  // 2nd arg: CPU #
  }

  // create multiple controller threads
  for (i = 0; i <SR_CTR_NUM; i++)
  {
    pthread_create_by_cpu(&control_thr, i+1, sr_control, (void*)i);  // 2nd arg: CPU #
  }

  sr_statistics();   // in the context of the main thread

  return 0;
}


////////////////////////////////////////////////////////////////////////////////



