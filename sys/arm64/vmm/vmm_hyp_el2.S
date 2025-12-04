/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Andrew Turner
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/elf_common.h>

#include <machine/asm.h>
#include <machine/param.h>

	.section .rodata
	.align PAGE_SHIFT

	/* CASEMATE: HACK: separate ELF + binary blobs to load */

	/* the nVHE ELF blob */
	.globl vmm_hyp_elf_blob
vmm_hyp_elf_blob:
	.incbin "vmm_hyp_blob.elf"
	.globl vmm_hyp_elf_blob_end
vmm_hyp_elf_blob_end:

	/* empty page between ELF blob and load segment to catch overflows */
	.align PAGE_SHIFT
	.space PAGE_SIZE

	/* reserve space to load nVHE blob at
	 * and align it on a 2M boundary */
	.align 25
	.globl vmm_hyp_code
vmm_hyp_code:
	.space PAGE_SIZE_64K
	.globl vmm_hyp_code_end
vmm_hyp_code_end:

	/* empty page after the load segment to catch overflows */
	.align PAGE_SHIFT
	.space PAGE_SIZE

GNU_PROPERTY_AARCH64_FEATURE_1_NOTE(GNU_PROPERTY_AARCH64_FEATURE_1_VAL)
