/*
 * FirmLab FreeRTOS task-walk fixture. The task set is chosen so every state list FirmLab walks has a known,
 * expected occupant once the scheduler has run for a few ticks:
 *
 *   SpinA, SpinB  priority 1  busy loops      -> pxReadyTasksLists[1] (one of them is pxCurrentTCB)
 *   Sleeper       priority 2  long vTaskDelay -> a delayed list (xDelayedTaskList1 or 2)
 *   Parked        priority 3  vTaskSuspend    -> xSuspendedTaskList
 *   QueueRx       priority 4  queue receive   -> xSuspendedTaskList + queue xTasksWaitingToReceive
 *   QueueTx       priority 2  queue send      -> xSuspendedTaskList + queue xTasksWaitingToSend
 *   EventWait     priority 3  event bits 0+2  -> xSuspendedTaskList + EventGroup xTasksWaitingForBits
 *   IDLE          priority 0  kernel's own    -> pxReadyTasksLists[0]
 *
 * No peripheral is touched, so the firmware runs on any Cortex-M platform with SRAM at 0x20000000.
 */
#include "FreeRTOS.h"
#include "event_groups.h"
#include "queue.h"
#include "task.h"

volatile unsigned long fixture_spin_a;
volatile unsigned long fixture_spin_b;
StaticQueue_t fixture_rx_queue_storage;
uint8_t fixture_rx_queue_data[1];
QueueHandle_t fixture_rx_queue;
TaskHandle_t fixture_rx_task;
void * volatile fixture_waiting_receive_list;
StaticQueue_t fixture_tx_queue_storage;
uint8_t fixture_tx_queue_data[1];
QueueHandle_t fixture_tx_queue;
TaskHandle_t fixture_tx_task;
void * volatile fixture_waiting_send_list;
volatile unsigned long fixture_queue_create_count;
StaticEventGroup_t fixture_event_group_storage;
EventGroupHandle_t fixture_event_group;
TaskHandle_t fixture_event_task;
void * volatile fixture_waiting_event_bits_list;

void fixture_trace_queue_create(void *queue, void *send_list, void *receive_list) {
  (void)queue;
  if (fixture_queue_create_count == 0) fixture_waiting_receive_list = receive_list;
  if (fixture_queue_create_count == 1) fixture_waiting_send_list = send_list;
  fixture_queue_create_count++;
}

void fixture_trace_event_group_create(void *event_group, void *waiting_list) {
  (void)event_group;
  fixture_waiting_event_bits_list = waiting_list;
}

static StaticTask_t fixture_idle_tcb;
static StackType_t fixture_idle_stack[configMINIMAL_STACK_SIZE];

void vApplicationGetIdleTaskMemory(StaticTask_t **tcb, StackType_t **stack, uint32_t *stack_size) {
  *tcb = &fixture_idle_tcb;
  *stack = fixture_idle_stack;
  *stack_size = configMINIMAL_STACK_SIZE;
}

static void spin_a(void *arg) {
  (void)arg;
  for (;;) fixture_spin_a++;
}

static void spin_b(void *arg) {
  (void)arg;
  for (;;) fixture_spin_b++;
}

static void sleeper(void *arg) {
  (void)arg;
  for (;;) vTaskDelay(pdMS_TO_TICKS(3600000));
}

static void parked(void *arg) {
  (void)arg;
  for (;;) vTaskSuspend(NULL);
}

static void queue_rx(void *arg) {
  uint8_t value;
  (void)arg;
  for (;;) (void)xQueueReceive(fixture_rx_queue, &value, portMAX_DELAY);
}

static void queue_tx(void *arg) {
  const uint8_t value = 0xa5;
  (void)arg;
  for (;;) (void)xQueueSend(fixture_tx_queue, &value, portMAX_DELAY);
}

static void event_wait(void *arg) {
  (void)arg;
  for (;;) (void)xEventGroupWaitBits(fixture_event_group, 0x5, pdTRUE, pdTRUE, portMAX_DELAY);
}

int main(void) {
  const uint8_t occupied = 0x5a;
  fixture_rx_queue = xQueueCreateStatic(
      1, sizeof(fixture_rx_queue_data[0]), fixture_rx_queue_data, &fixture_rx_queue_storage);
  configASSERT(fixture_rx_queue != NULL);
  fixture_tx_queue = xQueueCreateStatic(
      1, sizeof(fixture_tx_queue_data[0]), fixture_tx_queue_data, &fixture_tx_queue_storage);
  configASSERT(fixture_tx_queue != NULL);
  configASSERT(xQueueSend(fixture_tx_queue, &occupied, 0) == pdPASS);
  fixture_event_group = xEventGroupCreateStatic(&fixture_event_group_storage);
  configASSERT(fixture_event_group != NULL);
  xTaskCreate(spin_a, "SpinA", configMINIMAL_STACK_SIZE, NULL, 1, NULL);
  xTaskCreate(spin_b, "SpinB", configMINIMAL_STACK_SIZE, NULL, 1, NULL);
  xTaskCreate(sleeper, "Sleeper", configMINIMAL_STACK_SIZE, NULL, 2, NULL);
  xTaskCreate(parked, "Parked", configMINIMAL_STACK_SIZE, NULL, 3, NULL);
  xTaskCreate(queue_rx, "QueueRx", configMINIMAL_STACK_SIZE, NULL, 4, &fixture_rx_task);
  xTaskCreate(queue_tx, "QueueTx", configMINIMAL_STACK_SIZE, NULL, 2, &fixture_tx_task);
  xTaskCreate(event_wait, "EventWait", configMINIMAL_STACK_SIZE, NULL, 3, &fixture_event_task);
  vTaskStartScheduler();
  for (;;) {
  }
}
