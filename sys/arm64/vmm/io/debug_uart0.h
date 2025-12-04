#ifndef _CASEMATE_DEBUG_UART_H
#define _CASEMATE_DEBUG_UART_H

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/proc.h>

/* Instead of using the kernel's printf() to trace
 * we send casemate debug/trace to a dedicated UART-like device directly
 */

/* The magic address for the QEMU virt machine UART0
 * This lays squarely in the identity mapped region for hyp */
#define QEMU_VIRT_UART0_BASE 0x09000000ULL

static inline void
__casemate_debug_device_writeb(unsigned char c)
{
	volatile unsigned char *base = (volatile unsigned char *)QEMU_VIRT_UART0_BASE;
	*base = c;
}

static inline void
casemate_putc(const char c)
{
	__casemate_debug_device_writeb(c);
}

static inline void
casemate_puts(const char *s)
{
	char c;
	while ((c = *s++)) {
		__casemate_debug_device_writeb(c);
	}
}

static inline void
casemate_putx(uint64_t x)
{
	unsigned int b __diagused;
	unsigned char c __diagused;
	for (uint64_t i = 0; i < 16; i++) {
		b = (x >> 4*(15 - i)) & 0xf;
		if (b < 10)
			c = '0' + b;
		else
			c = 'a' + (b - 10);
		__casemate_debug_device_writeb(c);
	}
}
#endif
