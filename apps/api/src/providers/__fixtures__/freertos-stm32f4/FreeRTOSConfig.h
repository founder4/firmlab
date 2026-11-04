/* FreeRTOS configuration for the FirmLab task-walk fixture (Cortex-M4 run as ARM_CM3, no FPU, no peripherals). */
#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#define configUSE_PREEMPTION 1
#define configUSE_TIME_SLICING 1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION 0
#define configCPU_CLOCK_HZ 72000000UL
#define configTICK_RATE_HZ 1000
#define configMAX_PRIORITIES 5
#define configMINIMAL_STACK_SIZE 128
#define configMAX_TASK_NAME_LEN 16
#define configTOTAL_HEAP_SIZE (24 * 1024)
#ifndef configTICK_TYPE_WIDTH_IN_BITS
#define configTICK_TYPE_WIDTH_IN_BITS TICK_TYPE_WIDTH_32_BITS
#endif
#define configIDLE_SHOULD_YIELD 1
#define configUSE_MUTEXES 0
#define configUSE_RECURSIVE_MUTEXES 0
#define configUSE_COUNTING_SEMAPHORES 0
#define configQUEUE_REGISTRY_SIZE 0
#define configUSE_IDLE_HOOK 0
#define configUSE_TICK_HOOK 0
#define configUSE_MALLOC_FAILED_HOOK 0
#define configCHECK_FOR_STACK_OVERFLOW 0
#define configUSE_TRACE_FACILITY 1
#define configUSE_STATS_FORMATTING_FUNCTIONS 0
#define configUSE_TIMERS 0
#define configUSE_CO_ROUTINES 0
#define configSUPPORT_DYNAMIC_ALLOCATION 1
#define configSUPPORT_STATIC_ALLOCATION 1
#define configKERNEL_PROVIDED_STATIC_MEMORY 0
#define configNUMBER_OF_CORES 1

/* Fixture-only: queue.c expands this where Queue_t is complete, exporting both direct List_t addresses for E2E. */
extern void fixture_trace_queue_create(void *queue, void *send_list, void *receive_list);
#define traceQUEUE_CREATE(queue)                                                                     \
  do {                                                                                               \
    fixture_trace_queue_create(                                                                      \
        (void *)(queue), (void *)&((queue)->xTasksWaitingToSend), (void *)&((queue)->xTasksWaitingToReceive)); \
  } while (0)

/* Fixture-only: event_groups.c expands this where EventGroup_t is complete, exporting its direct List_t address. */
extern void fixture_trace_event_group_create(void *event_group, void *waiting_list);
#define traceEVENT_GROUP_CREATE(event_group)                                                    \
  do {                                                                                          \
    fixture_trace_event_group_create(                                                           \
        (void *)(event_group), (void *)&((event_group)->xTasksWaitingForBits));                 \
  } while (0)

#define INCLUDE_vTaskDelay 1
#define INCLUDE_vTaskSuspend 1
#define INCLUDE_vTaskDelete 0
#define INCLUDE_vTaskPrioritySet 0
#define INCLUDE_uxTaskPriorityGet 0
#define INCLUDE_xTaskGetCurrentTaskHandle 1

#define configPRIO_BITS 4
#define configKERNEL_INTERRUPT_PRIORITY (15 << (8 - configPRIO_BITS))
#define configMAX_SYSCALL_INTERRUPT_PRIORITY (5 << (8 - configPRIO_BITS))

#define configASSERT(x) \
  if ((x) == 0) {       \
    for (;;) {          \
    }                   \
  }

#define vPortSVCHandler SVC_Handler
#define xPortPendSVHandler PendSV_Handler
#define xPortSysTickHandler SysTick_Handler

#endif
