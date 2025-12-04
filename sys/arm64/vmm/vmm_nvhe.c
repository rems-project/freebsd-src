/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Andrew Turner
 * Copyright (c) 2024 Arm Ltd
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define VMM_nVHE

#define	VMM_STATIC	static
#define	VMM_HYP_FUNC(func)	vmm_nvhe_ ## func

#define	guest_or_nonvhe(guest)	(true)
#define	EL1_REG(reg)		MRS_REG_ALT_NAME(reg ## _EL1)
#define	EL0_REG(reg)		MRS_REG_ALT_NAME(reg ## _EL0)

#include "vmm_hyp.c"

#if defined(__CASEMATE_FREEBSD__)
#include "io/debug_uart0.h"
#include <dev/psci/psci.h>

static void
psci_system_off(void)
{
	__asm __volatile(
		"mov w0,%w[x0]\n"
		"smc #0x0\n"
		:
		: [x0] "r" (PSCI_FNID_SYSTEM_OFF)
		:
	);
	__unreachable();
}

static int
casemate_ghost_driver_putc(char c)
{
	casemate_putc(c);
	return 0;
}


static void
casemate_ghost_driver_trace(const char *msg)
{
	/* CR before and after ensures this appears on its own 'line' */
	casemate_puts("\r");
	casemate_puts("\033[46;37;1m");
	casemate_puts(msg);
	casemate_puts("\033[0m");
	/* pad to 79 */
	for (int i=strlen(msg); i < 140; i++) {
		casemate_putc(' ');
	}
	casemate_puts("\r");
}

static void
casemate_ghost_driver_abort(const char *msg)
{
	casemate_puts("\033[41;37;1m[");
	casemate_puts(msg);
	casemate_puts("]\033[0m");
	casemate_puts("\n");
	psci_system_off();
	__unreachable();
}

uint64_t
casemate_cpu_id(void)
{
	return 0;
}

static bool __casemate_init = false;

static int
casemate_ensure_setup(uint64_t smva, size_t sm_size)
{
	int r;

	if (__casemate_init)
		return (-1);

	casemate_puts("vmm: CASEMATE: initialising at EL2\n");

	// initialise the EL2 driver
	struct ghost_driver cm_driver = {
		.putc = &casemate_ghost_driver_putc,
		.abort = &casemate_ghost_driver_abort,
		.read_physmem = NULL,
		.read_sysreg = NULL,
		.trace = &casemate_ghost_driver_trace,
	};
	initialise_ghost_driver(&cm_driver);
	r = attach_casemate_model((void*)smva);

	if (r)
		return -1;

	__casemate_init = true;

	casemate_model_step_msr(SYSREG_MAIR_EL2, READ_SPECIALREG(MAIR_EL2));
	casemate_model_step_msr(SYSREG_TCR_EL2, READ_SPECIALREG(TCR_EL2));
	casemate_model_step_msr(SYSREG_VTCR_EL2, READ_SPECIALREG(VTCR_EL2));
	casemate_model_step_msr(SYSREG_TTBR_EL2, READ_SPECIALREG(TTBR0_EL2));
	casemate_model_step_msr(SYSREG_VTTBR, READ_SPECIALREG(VTTBR_EL2));

	casemate_puts("vmm: CASEMATE: initialised EL2\n");

	return (0);
}
#endif


uint64_t vmm_hyp_enter(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t);

/*
 * Handlers for EL2 addres space. Only needed by non-VHE code as in VHE the
 * kernel is in EL2 so pmap will manage the address space.
 */
static int
vmm_dc_civac(uint64_t start, uint64_t len)
{
	size_t line_size, end;
	uint64_t ctr;

	ctr = READ_SPECIALREG(ctr_el0);
	line_size = sizeof(int) << CTR_DLINE_SIZE(ctr);
	end = start + len;
	dsb(ishst);
	/* Clean and Invalidate the D-cache */
	for (; start < end; start += line_size)
		__asm __volatile("dc	civac, %0" :: "r" (start) : "memory");
	dsb(ish);
	return (0);
}

static int
vmm_el2_tlbi(uint64_t type, uint64_t start, uint64_t len)
{
	uint64_t end, r;

	dsb(ishst);
	switch (type) {
	default:
	case HYP_EL2_TLBI_ALL:
		__asm __volatile("tlbi	alle2" ::: "memory");
		break;
	case HYP_EL2_TLBI_VA:
		end = TLBI_VA(start + len);
		start = TLBI_VA(start);
		for (r = start; r < end; r += TLBI_VA_L3_INCR) {
			__asm __volatile("tlbi	vae2is, %0" :: "r"(r));
		}
		break;
	}
	dsb(ish);

	return (0);
}

uint64_t
vmm_hyp_enter(uint64_t handle, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7)
{
	switch (handle) {
	case HYP_ENTER_GUEST:
		return (VMM_HYP_FUNC(enter_guest)((struct hyp *)x1,
		    (struct hypctx *)x2));
	case HYP_READ_REGISTER:
		return (VMM_HYP_FUNC(read_reg)(x1));
	case HYP_CLEAN_S2_TLBI:
		VMM_HYP_FUNC(clean_s2_tlbi());
		return (0);
	case HYP_DC_CIVAC:
		return (vmm_dc_civac(x1, x2));
	case HYP_EL2_TLBI:
		return (vmm_el2_tlbi(x1, x2, x3));
	case HYP_S2_TLBI_RANGE:
		VMM_HYP_FUNC(s2_tlbi_range)(x1, x2, x3, x4);
		return (0);
	case HYP_S2_TLBI_ALL:
		VMM_HYP_FUNC(s2_tlbi_all)(x1);
		return (0);
#if defined(__CASEMATE_FREEBSD__)
	case HYP_CASEMATE_INIT:
		return casemate_ensure_setup(x1, x2);
#endif
	case HYP_CLEANUP:	/* Handled in vmm_hyp_exception.S */
	default:
		break;
	}

	return (0);
}
