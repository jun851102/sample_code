/* copyright jun851102 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>


#define RANDOM_SEED         (268435455)	  // 랜덤값 재현을 위해 사용할 소수값

#define SR_RULE_SIZE        (1000)		  // 시뮬레이션할 정책 갯수
#define SR_RULE_THRESHOLD   (10000)		  // 시뮬레이션할 정책 임계치
#define SR_WORKER_NUM       (12)		  // 시뮬레이션할 워커 스레드 갯수


typedef struct sr_rule_config_s {
  int32_t action;		// 정책 설정 ( 0: permit, 1: detect, 2: block )
  int32_t is_control;	// 제어 플래그 ( 0: not control, 1: control )
  uint32_t g_threshold;	// 정책 임계치
} sr_rule_config_t;

typedef struct sr_rule_statistics_s {
  uint64_t input_cnt;	// 입력된 패킷 카운트
  uint64_t permit_cnt;	// 허용된 패킷 카운트 ( 해당값이 임계치보다 크면 제어 )
  uint64_t block_cnt;	// 차단된 패킷 카운트 ( 제어시 입력된 패킷 카운트)
} sr_rule_statistics_t;

typedef struct sr_worker_s {
  sr_rule_statistics_t arr_rule_stat[2][SR_RULE_SIZE];	// 워커별 로컬 정책 통계
  volatile uint32_t cur_arr_rule_stat_idx;				// Double Buffering Index
} sr_worker_t;

typedef struct sr_manager_s {
  sr_rule_config_t arr_rule_cfg[SR_RULE_SIZE];			// 전역 정책 설정

  sr_rule_statistics_t arr_rule_stat[2][SR_RULE_SIZE];	// 전역 정책 통계
  uint32_t cur_arr_rule_stat_idx;						// Double Buffering Index

  sr_worker_t *p_arr_wrk[SR_WORKER_NUM];				// 워커별 자료구조 관리 풀
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

void init_sr_manager() {
  int32_t i, j;
  sr_rule_config_t *p_rule_cfg;
  sr_rule_statistics_t *p_rule_stat;

  for (i = 0; i < SR_RULE_SIZE; i++) {
    p_rule_cfg = &(g_mgr.arr_rule_cfg[i]);

    p_rule_cfg->action = 2; 
    p_rule_cfg->is_control = 0; 
    p_rule_cfg->g_threshold = SR_RULE_THRESHOLD;
  }

  for (i = 0; i < 2; i++) {
	for (j = 0; j < SR_RULE_SIZE; j++) {
	  p_rule_stat = &(g_mgr.arr_rule_stat[i][j]);

	  p_rule_stat->input_cnt = 0;
	  p_rule_stat->permit_cnt = 0;
	  p_rule_stat->block_cnt = 0;
	}
  }
  g_mgr.cur_arr_rule_stat_idx = 0;

  for (i = 0; i < SR_WORKER_NUM; i++) {
    g_mgr.p_arr_wrk[i] = NULL;
  }
}

sr_worker_t *create_sr_worker(int64_t wrk_id) {
  int32_t i, j;
  sr_worker_t *p_wrk = malloc(sizeof(sr_worker_t));
  sr_rule_statistics_t *p_rule_stat;

  for (i = 0; i < 2; i++) {
	for (j = 0; j < SR_RULE_SIZE; j++) {
	  p_rule_stat = &(p_wrk->arr_rule_stat[i][j]);

	  p_rule_stat->input_cnt = 0;
	  p_rule_stat->permit_cnt = 0;
	  p_rule_stat->block_cnt = 0;
	}
  }

  //p_wrk->cur_arr_rule_stat_idx = 0;

  return g_mgr.p_arr_wrk[wrk_id] = p_wrk;
}


void wait_sr_worker() {
  int32_t i;

  for (i = 0; i < SR_WORKER_NUM; i++) {
    while (NULL == g_mgr.p_arr_wrk[i]) {
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

void init_input_value(uint32_t val) {
  g_val = val;
}

uint32_t read_input_value() {
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

void *process_sr_worker(void *arg) {
  int64_t wrk_id =(*(uint64_t*)arg);

  int32_t i;
  int32_t rule_id;
  uint32_t val;
  
  sr_worker_t *p_wrk;
  sr_rule_config_t *p_rule_cfg;
  sr_rule_statistics_t *p_local_rule_stat;

  p_wrk = create_sr_worker(wrk_id);
  init_input_value(wrk_id);

  for (;;) {
    val = read_input_value();

    rule_id = search_matching_sr_rule_id(val);
    // 매칭시 rule id(0~999), miss시 -1 리턴

    if(0 <= rule_id) {
      p_rule_cfg = &(g_mgr.arr_rule_cfg[rule_id]);

      p_local_rule_stat = &(p_wrk->arr_rule_stat[p_wrk->cur_arr_rule_stat_idx][rule_id]);
      p_local_rule_stat->input_cnt++;

	  //p_rule_cfg->is_control : 차단 여부 결정 1:차단 0:허용)
      if (!p_rule_cfg->is_control) {
        p_local_rule_stat->permit_cnt++;
      } else {
        p_local_rule_stat->block_cnt++;
      }
    }

	// 스레드간 메모리 동기화를 위하여 mfence 명령을 추가
	// __sync_synchronize();
  }

  return NULL;
}

////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
//
// 워커 스레드의 메시지를 분석하고, 정책의 제어여부를 설정하는 스레드
//
////////////////////////////////////////////////////////////////////////////////

void *process_sr_control() {
  int32_t i, j;
  uint32_t next_arr_rule_stat_idx;
  sr_worker_t *p_wrk;
  sr_rule_config_t *p_rule_cfg;
  sr_rule_statistics_t *p_local_rule_stat;
  sr_rule_statistics_t *p_global_rule_stat;

  wait_sr_worker();

  while (1) {
	// 현재 버킷을 초기화하고, 차단여부(is_control) 셋팅
	// worker에서 통계를 저장하는 버킷으로 전달

	for (i = 0; i < SR_WORKER_NUM; i++) {
	  p_wrk = g_mgr.p_arr_wrk[i];

	  // p_wrk->arr_rule_stat의 double buffering 
	  next_arr_rule_stat_idx = (p_wrk->cur_arr_rule_stat_idx + 1) % 2;

	  for (j = 0; j < SR_RULE_SIZE; j++) {
		p_local_rule_stat = &(p_wrk->arr_rule_stat[next_arr_rule_stat_idx][j]);

		if (p_local_rule_stat->input_cnt) {
		  p_rule_cfg = &(g_mgr.arr_rule_cfg[j]);
		  p_global_rule_stat = &(g_mgr.arr_rule_stat[g_mgr.cur_arr_rule_stat_idx][j]);

		  p_global_rule_stat->input_cnt += p_local_rule_stat->input_cnt;
		  p_global_rule_stat->permit_cnt += p_local_rule_stat->permit_cnt;
		  p_global_rule_stat->block_cnt += p_local_rule_stat->block_cnt;

		  if (p_rule_cfg->g_threshold <= p_global_rule_stat->permit_cnt) {
			p_rule_cfg->is_control = 1;
		  }

		  p_local_rule_stat->input_cnt = 0;
		  p_local_rule_stat->permit_cnt = 0;
		  p_local_rule_stat->block_cnt = 0;
		}
	  }

	  // p_wrk->arr_rule_stat의 double buffering 
	  p_wrk->cur_arr_rule_stat_idx = next_arr_rule_stat_idx;
	}

	usleep(50);
  }

  return NULL;
}

////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
//
// 워커 스레드에서의 개별 통계를 합산하는 스레드
//
////////////////////////////////////////////////////////////////////////////////

void *process_sr_statistics() {
  int32_t i, j;
  uint32_t next_arr_rule_stat_idx;

  time_t o_sec, n_sec;
  uint64_t tot_input_cnt;
  uint64_t tot_permit_cnt;
  uint64_t tot_block_cnt;
  sr_worker_t *p_wrk;
  sr_rule_config_t *p_rule_cfg;
  sr_rule_statistics_t *p_local_rule_stat;
  sr_rule_statistics_t *p_global_rule_stat;

  o_sec = n_sec = 0;

  // worker 초기화 할 동안 대기
  wait_sr_worker();

  while (1) {
    n_sec = time(NULL);
    if (!(o_sec < n_sec)) {
      // 매 초마다 구동할 것이므로 5msec 마다 loop
      usleep(5000);
      continue;
    }

    o_sec = n_sec;


    // tot_input_cnt, tot_permit_cnt, tot_block_cnt은 매초마다 통계 저장하여 log로 수록하지만
    // 본 샘플에서는 출력만 하는 것으로 간략화 함.
    tot_input_cnt = tot_permit_cnt = tot_block_cnt = 0;

    //g_mgr.arr_rule_stat의 double buffering 
	next_arr_rule_stat_idx = (g_mgr.cur_arr_rule_stat_idx + 1) % 2;

    for (i = 0; i < SR_RULE_SIZE; i++) {
      p_global_rule_stat = &(g_mgr.arr_rule_stat[next_arr_rule_stat_idx][i]);	

      tot_input_cnt += p_global_rule_stat->input_cnt;
      tot_permit_cnt += p_global_rule_stat->permit_cnt;
      tot_block_cnt += p_global_rule_stat->block_cnt;

      p_global_rule_stat->input_cnt = 0;
      p_global_rule_stat->permit_cnt = 0;
      p_global_rule_stat->block_cnt = 0;
    }

    // g_mgr.arr_rule_stat의 double buffering 
	g_mgr.cur_arr_rule_stat_idx = next_arr_rule_stat_idx;

    printf("[%lu] INPUT COUNT [%lu], PERMIT COUNT [%lu], "
		   "BLOCK COUNT [%lu], AVERAGE COUNT [%lu] \n",
        n_sec, tot_input_cnt, tot_permit_cnt,
		tot_block_cnt, tot_block_cnt / SR_WORKER_NUM);
	// 합산한 통계 카운트의 정합성을 체크하기 위한 디버깅 코드
	if (tot_input_cnt != tot_permit_cnt + tot_block_cnt) {
	  fprintf(stderr, "[DEBUG] TOTAL COUNT IS NOT MATCH! \n");	
	}

    // 1초가 지나갔으므로 차단설정을 초기화 함
    for (i = 0; i < SR_RULE_SIZE; i++) {
      p_rule_cfg = &(g_mgr.arr_rule_cfg[i]);

      p_rule_cfg->is_control = 0;
    }
  }

  return NULL;
}

////////////////////////////////////////////////////////////////////////////////
//
// Static Ratelimit 테스트 프로그램
//
////////////////////////////////////////////////////////////////////////////////


int32_t main(void) {
  int32_t i;
  int64_t arg[SR_WORKER_NUM]={0,};
  pthread_t thr;

  init_sr_manager();

  for (i = 0; i < SR_WORKER_NUM; i++) {
    arg[i]=i;
    pthread_create(&thr, NULL, process_sr_worker, (void *)(&arg[i]));
  }

  pthread_create(&thr, NULL, process_sr_control, NULL);
  process_sr_statistics();

  return 0;
}

////////////////////////////////////////////////////////////////////////////////

