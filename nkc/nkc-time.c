/*
 * Conformance: clocks.
 *
 * The clock routines a driver reads time with. Times differ from run to
 * run, so what is logged is whether each clock behaves: it advances, it
 * does not run backwards, a stall lasts at least as long as asked.
 */

#define NKC_DEVICE L"\\Device\\NkcTime"
#include "nkc.h"

static VOID NkcStallMs(ULONG Ms)
{
    while (Ms-- != 0) {
        KeStallExecutionProcessor(1000);
    }
}

static VOID NkcRun(NKC_LOG *Log)
{
    LARGE_INTEGER Frequency, Before, After, Tick0, Tick1, System0, System1;
    ULONGLONG Interrupt0, Interrupt1, Micros;
    ULONG Increment, Tries;

    /* 1: the clock tick is between 0.5 and 16 milliseconds, in 100 ns
     * units. (Windows uses 15.625 ms on most machines, not all.) */
    Increment = KeQueryTimeIncrement();
    NkcPut(Log, Increment >= 5000 && Increment <= 160000 ? 1 : 0);

    /* 1: the performance counter has a frequency of at least 1 MHz. */
    Before = KeQueryPerformanceCounter(&Frequency);
    NkcPut(Log, Frequency.QuadPart >= 1000000 ? 1 : 0);

    /* 1, 1: a 20 ms stall takes at least 20 ms by the performance
     * counter, and well under a second. */
    NkcStallMs(20);
    After = KeQueryPerformanceCounter(NULL);
    Micros = (ULONGLONG)(After.QuadPart - Before.QuadPart) * 1000000 / (ULONGLONG)Frequency.QuadPart;
    NkcPut(Log, Micros >= 20000 ? 1 : 0);
    NkcPut(Log, Micros < 1000000 ? 1 : 0);

    /* 1: the tick count advances within a tenth of a second. */
    KeQueryTickCount(&Tick0);
    Tick1 = Tick0;
    for (Tries = 0; Tries < 100 && Tick1.QuadPart == Tick0.QuadPart; Tries++) {
        NkcStallMs(1);
        KeQueryTickCount(&Tick1);
    }
    NkcPut(Log, Tick1.QuadPart > Tick0.QuadPart ? 1 : 0);

    /* 1, 1: interrupt time advances across 50 ms, by at least 30 ms. */
    Interrupt0 = KeQueryInterruptTime();
    KeQuerySystemTime(&System0);
    NkcStallMs(50);
    Interrupt1 = KeQueryInterruptTime();
    KeQuerySystemTime(&System1);
    NkcPut(Log, Interrupt1 > Interrupt0 ? 1 : 0);
    NkcPut(Log, Interrupt1 - Interrupt0 >= 300000 ? 1 : 0);

    /* 1, 1: so does system time, and it is later than the year 2020
     * (in 100 ns units since 1601). */
    NkcPut(Log, System1.QuadPart - System0.QuadPart >= 300000 ? 1 : 0);
    NkcPut(Log, System1.QuadPart > 132223104000000000LL ? 1 : 0);

    /* 0: all of it at PASSIVE_LEVEL. */
    NkcPut(Log, KeGetCurrentIrql());
}
