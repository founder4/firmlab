/*
 * FirmLab FreeRTOS task-walk fixture. The task set is chosen so every state list FirmLab walks has a known,
 * expected occupant once the scheduler has run for a few ticks:
 *
 *   SpinA, SpinB  priority 1  busy loops      -> pxReadyTasksLists[1] (one of them is pxCurrentTCB)
 *   Sleeper       priority 2  long vTaskDelay -> a delayed list (xDelayedTaskList1 or 2)
 *   Parked        priority 3  vTaskSuspend    -> xSuspendedTaskList
 *   IDLE          priority 0  kernel's own    -> pxReadyTasksLists[0]
 *
 * No peripheral is touched, so the firmware runs on any Cortex-M platform with SRAM at 0x20000000.
 */
#include "FreeRTOS.h"
#include "task.h"

volatile unsigned long fixture_spin_a;
volatile unsigned long fixture_spin_b;

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

int main(void) {
  xTaskCreate(spin_a, "SpinA", configMINIMAL_STACK_SIZE, NULL, 1, NULL);
  xTaskCreate(spin_b, "SpinB", configMINIMAL_STACK_SIZE, NULL, 1, NULL);
  xTaskCreate(sleeper, "Sleeper", configMINIMAL_STACK_SIZE, NULL, 2, NULL);
  xTaskCreate(parked, "Parked", configMINIMAL_STACK_SIZE, NULL, 3, NULL);
  vTaskStartScheduler();
  for (;;) {
  }
}
