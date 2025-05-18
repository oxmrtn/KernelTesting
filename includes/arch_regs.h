#ifndef ARCH_REGS_H
# define ARCH_REGS_H

#include <linux/ptrace.h>

#if defined(__x86_64__)

    #define REG_ARG0(regs) ((regs)->di)
    #define REG_ARG1(regs) ((regs)->si)
    #define REG_ARG2(regs) ((regs)->dx)
    #define REG_RET(regs)  ((regs)->ax)

    #define SET_RET(regs, val) ((regs)->ax = (val))

#elif defined(__aarch64__)

    #define REG_ARG0(regs) ((regs)->regs[0])
    #define REG_ARG1(regs) ((regs)->regs[1])
    #define REG_ARG2(regs) ((regs)->regs[2])
    #define REG_RET(regs)  ((regs)->regs[0])

    #define SET_RET(regs, val) ((regs)->regs[0] = (val))

#endif

#endif