/* Minimal Cortex-M startup for the fixture: vector table, .data copy, .bss zero, then main(). */
#include <stdint.h>

extern uint32_t _estack, _sidata, _sdata, _edata, _sbss, _ebss;
extern int main(void);
void SVC_Handler(void);
void PendSV_Handler(void);
void SysTick_Handler(void);

void Reset_Handler(void) {
  uint32_t *src = &_sidata;
  for (uint32_t *dst = &_sdata; dst < &_edata;) *dst++ = *src++;
  for (uint32_t *dst = &_sbss; dst < &_ebss;) *dst++ = 0;
  main();
  for (;;) {
  }
}

static void Default_Handler(void) {
  for (;;) {
  }
}

__attribute__((section(".isr_vector"), used)) void (*const vectors[16])(void) = {
    (void (*)(void))(&_estack), Reset_Handler, Default_Handler, Default_Handler, Default_Handler, Default_Handler,
    Default_Handler,            0,             0,               0,               0,               SVC_Handler,
    Default_Handler,            0,             PendSV_Handler,  SysTick_Handler,
};

/* The kernel calls these; the fixture links no libc, so it carries the two it needs. */
void *memset(void *dst, int c, unsigned int n) {
  unsigned char *d = dst;
  while (n--) *d++ = (unsigned char)c;
  return dst;
}

void *memcpy(void *dst, const void *src, unsigned int n) {
  unsigned char *d = dst;
  const unsigned char *s = src;
  while (n--) *d++ = *s++;
  return dst;
}
