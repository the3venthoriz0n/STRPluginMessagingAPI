#pragma once

// Shared safety layer for every native INT3/TF hook in STRPluginMessagingBridge.
//
// - One process-wide recursive lock serialises every VirtualProtect/code-byte
//   write and every breakpoint arm/disarm, so concurrent patches on the same
//   page cannot restore RX between another thread's VirtualProtect and write.
// - Targets are validated (committed executable page inside the expected
//   allocation/module image, function entry where unwind data exists, first
//   byte not already INT3) before a breakpoint is armed. Failures are logged
//   as refusals and nothing is patched.
// - One shared single-step dispatcher owns EXCEPTION_SINGLE_STEP. A hook that
//   needs to execute its original instruction records a per-thread pending
//   step keyed by hook id; only that thread's pending steps are serviced, a
//   hardware-breakpoint step (Dr6.B0-B3 without Dr6.BS) or a step on a thread
//   with nothing pending is passed on with EXCEPTION_CONTINUE_SEARCH, and the
//   trap flag is cleared once no pending step on that thread wants it.
// - Every bridge handler runs inside a guard. An SEH or C++ exception inside a
//   handler restores the touched context registers, disarms that hook, and is
//   logged once as "bridge hook <name> disarmed after <reason>".
//
// Everything here is header-only with inline variables so the three bridge
// translation units share a single lock, registry and dispatcher.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <atomic>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace STRPMHookGuard
{
    enum class HookId : std::uint32_t
    {
        kSendCapture = 0,
        kReceiveOnConsume,
        kChatUiExecuteAsync,
        kProxyLifecycle,
        kProxyTrace,
        kProxyIdentityObserver,
        kChatUiCandidates,
        kCount
    };

    inline constexpr std::size_t kHookCount = static_cast<std::size_t>(HookId::kCount);
    inline constexpr std::uint32_t kTrapFlag = 0x100u;
    inline constexpr std::uint8_t kInt3 = 0xCC;

    inline constexpr const char* kHookNames[kHookCount] = {
        "send-capture",
        "receive-onconsume",
        "chatui-executeasync",
        "proxy-lifecycle",
        "proxy-trace",
        "proxy-identity-observer",
        "chatui-candidates",
    };

    // Return true to keep single-stepping this thread for the same hook.
    using StepFn = bool (*)(CONTEXT* context, std::uintptr_t hookAddress, void* cookie);
    using DisarmFn = void (*)();
    using HandlerFn = LONG (*)(EXCEPTION_POINTERS* exceptionInfo);

    namespace detail
    {
        struct HookHealth
        {
            std::atomic<std::uint32_t> faults{ 0 };
            std::atomic<std::uint32_t> refusals{ 0 };
            std::atomic<std::uint32_t> foreignSteps{ 0 };
            std::atomic<std::uint32_t> hits{ 0 };
            std::atomic_bool disarmed{ false };
            std::atomic<DisarmFn> disarm{ nullptr };
        };

        struct PatchLock
        {
            SRWLOCK lock = SRWLOCK_INIT;
            std::atomic<DWORD> owner{ 0 };
            std::uint32_t depth{ 0 };
        };

        struct PendingStep
        {
            StepFn fn{ nullptr };
            std::uintptr_t hookAddress{ 0 };
            void* cookie{ nullptr };
        };

        struct ArmedAddress
        {
            std::atomic<std::uintptr_t> address{ 0 };
            std::atomic<std::uint32_t> hook{ 0 };
        };

        inline constexpr std::size_t kArmedAddressSlots = 64;

        inline HookHealth g_health[kHookCount];
        inline PatchLock g_patchLock;
        inline ArmedAddress g_armedAddresses[kArmedAddressSlots];
        inline std::atomic<std::size_t> g_armedAddressNext{ 0 };
        inline std::atomic<PVOID> g_dispatcher{ nullptr };
        inline std::atomic_bool g_announced{ false };
        inline thread_local PendingStep t_pending[kHookCount]{};

        inline std::size_t Index(HookId id) noexcept
        {
            const auto index = static_cast<std::size_t>(id);
            return index < kHookCount ? index : 0;
        }
    }

    inline const char* HookName(HookId id) noexcept
    {
        return kHookNames[detail::Index(id)];
    }

    inline void Log(const char* format, ...) noexcept
    {
        FILE* file = nullptr;
        fopen_s(&file, "Data\\SKSE\\Plugins\\STRPluginMessagingBridge.log", "a");
        if (!file)
            return;

        va_list args;
        va_start(args, format);
        std::vfprintf(file, format, args);
        va_end(args);
        std::fputc('\n', file);
        std::fclose(file);
    }

    // ------------------------------------------------------------------
    // Patch lock (recursive, no constructor, safe to take inside a VEH).
    // ------------------------------------------------------------------

    inline void LockPatches() noexcept
    {
        auto& state = detail::g_patchLock;
        const DWORD self = GetCurrentThreadId();
        if (state.owner.load(std::memory_order_acquire) == self)
        {
            ++state.depth;
            return;
        }
        AcquireSRWLockExclusive(&state.lock);
        state.owner.store(self, std::memory_order_release);
        state.depth = 1;
    }

    inline void UnlockPatches() noexcept
    {
        auto& state = detail::g_patchLock;
        if (state.owner.load(std::memory_order_acquire) != GetCurrentThreadId() || state.depth == 0)
            return;
        if (--state.depth == 0)
        {
            state.owner.store(0, std::memory_order_release);
            ReleaseSRWLockExclusive(&state.lock);
        }
    }

    // Only for non-VEH arm paths. VEH paths use the self-contained helpers
    // below, which never hold the lock across code that could raise SEH.
    struct PatchScope
    {
        PatchScope() noexcept { LockPatches(); }
        ~PatchScope() { UnlockPatches(); }
        PatchScope(const PatchScope&) = delete;
        PatchScope& operator=(const PatchScope&) = delete;
    };

    namespace detail
    {
        inline bool WriteCodeByteUnlocked(std::uintptr_t address, std::uint8_t value) noexcept
        {
            bool ok = false;
            __try
            {
                DWORD oldProtect = 0;
                if (VirtualProtect(reinterpret_cast<void*>(address), 1, PAGE_EXECUTE_READWRITE, &oldProtect))
                {
                    *reinterpret_cast<volatile std::uint8_t*>(address) = value;
                    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), 1);
                    DWORD ignored = 0;
                    VirtualProtect(reinterpret_cast<void*>(address), 1, oldProtect, &ignored);
                    ok = true;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                ok = false;
            }
            return ok;
        }

        inline bool ReadCodeByte(std::uintptr_t address, std::uint8_t& value) noexcept
        {
            SIZE_T read = 0;
            return address >= 0x10000 &&
                   ReadProcessMemory(
                       GetCurrentProcess(),
                       reinterpret_cast<const void*>(address),
                       &value,
                       sizeof(value),
                       &read) != FALSE &&
                   read == sizeof(value);
        }

        inline bool IsExecutableProtection(DWORD protect) noexcept
        {
            if ((protect & PAGE_GUARD) != 0 || protect == PAGE_NOACCESS)
                return false;
            const DWORD value = protect & 0xFF;
            return value == PAGE_EXECUTE || value == PAGE_EXECUTE_READ ||
                   value == PAGE_EXECUTE_READWRITE || value == PAGE_EXECUTE_WRITECOPY;
        }

        inline void RecordArmedAddress(HookId id, std::uintptr_t address) noexcept
        {
            for (auto& slot : g_armedAddresses)
            {
                if (slot.address.load(std::memory_order_acquire) == address)
                {
                    slot.hook.store(static_cast<std::uint32_t>(id), std::memory_order_release);
                    return;
                }
            }
            const auto index = g_armedAddressNext.fetch_add(1, std::memory_order_relaxed) % kArmedAddressSlots;
            g_armedAddresses[index].hook.store(static_cast<std::uint32_t>(id), std::memory_order_release);
            g_armedAddresses[index].address.store(address, std::memory_order_release);
        }

        inline bool WasArmedBy(HookId id, std::uintptr_t address) noexcept
        {
            if (address == 0)
                return false;
            for (const auto& slot : g_armedAddresses)
            {
                if (slot.address.load(std::memory_order_acquire) == address &&
                    slot.hook.load(std::memory_order_acquire) == static_cast<std::uint32_t>(id))
                {
                    return true;
                }
            }
            return false;
        }
    }

    // Single locked code-byte write. Safe inside a VEH.
    inline bool PatchByte(std::uintptr_t address, std::uint8_t value) noexcept
    {
        if (address < 0x10000)
            return false;
        LockPatches();
        const bool ok = detail::WriteCodeByteUnlocked(address, value);
        UnlockPatches();
        return ok;
    }

    // Puts the original byte back if our INT3 is still there. Returns true when
    // the original byte is in place afterwards. Refuses to overwrite a byte that
    // is neither our INT3 nor the original. Safe inside a VEH.
    inline bool RestoreBreakpointByte(std::uintptr_t address, std::uint8_t originalByte) noexcept
    {
        if (address < 0x10000)
            return false;
        LockPatches();
        bool ok = false;
        std::uint8_t current = 0;
        if (detail::ReadCodeByte(address, current))
        {
            if (current == originalByte)
                ok = true;
            else if (current == kInt3)
                ok = detail::WriteCodeByteUnlocked(address, originalByte);
        }
        UnlockPatches();
        return ok;
    }

    // Writes INT3 back over the original byte. Returns true when our INT3 is in
    // place afterwards. Refuses if the byte was changed by someone else. Safe
    // inside a VEH.
    inline bool RearmBreakpointByte(std::uintptr_t address, std::uint8_t originalByte) noexcept
    {
        if (address < 0x10000)
            return false;
        LockPatches();
        bool ok = false;
        std::uint8_t current = 0;
        if (detail::ReadCodeByte(address, current))
        {
            if (current == kInt3)
                ok = true;
            else if (current == originalByte)
                ok = detail::WriteCodeByteUnlocked(address, kInt3);
        }
        UnlockPatches();
        return ok;
    }

    // ------------------------------------------------------------------
    // Health / disarm.
    // ------------------------------------------------------------------

    inline void RegisterDisarm(HookId id, DisarmFn fn) noexcept
    {
        detail::g_health[detail::Index(id)].disarm.store(fn, std::memory_order_release);
    }

    inline bool IsDisarmed(HookId id) noexcept
    {
        return detail::g_health[detail::Index(id)].disarmed.load(std::memory_order_acquire);
    }

    inline void CountHit(HookId id) noexcept
    {
        detail::g_health[detail::Index(id)].hits.fetch_add(1, std::memory_order_relaxed);
    }

    namespace detail
    {
        inline bool CallDisarmGuarded(DisarmFn fn) noexcept
        {
            bool ok = true;
            __try
            {
                fn();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                ok = false;
            }
            return ok;
        }
    }

    // Counts a fault, disarms the hook once (restoring its original bytes via
    // the module's disarm function) and logs which hook was disarmed and why.
    inline void ReportFault(HookId id, const char* reason) noexcept
    {
        auto& health = detail::g_health[detail::Index(id)];
        const auto faults = health.faults.fetch_add(1, std::memory_order_relaxed) + 1;
        if (health.disarmed.exchange(true, std::memory_order_acq_rel))
            return;

        bool disarmOk = true;
        if (const auto fn = health.disarm.load(std::memory_order_acquire))
            disarmOk = detail::CallDisarmGuarded(fn);

        Log("bridge hook %s disarmed after %s (faults=%u refusals=%u foreignSteps=%u hits=%u%s)",
            HookName(id),
            reason ? reason : "unknown fault",
            static_cast<unsigned>(faults),
            static_cast<unsigned>(health.refusals.load(std::memory_order_relaxed)),
            static_cast<unsigned>(health.foreignSteps.load(std::memory_order_relaxed)),
            static_cast<unsigned>(health.hits.load(std::memory_order_relaxed)),
            disarmOk ? "" : "; disarm routine itself faulted");
    }

    inline void LogRefusal(HookId id, std::uintptr_t address, const char* reason) noexcept
    {
        constexpr std::uint32_t kRefusalLogLimit = 3;
        const auto previous =
            detail::g_health[detail::Index(id)].refusals.fetch_add(1, std::memory_order_relaxed);
        if (previous < kRefusalLogLimit)
        {
            Log("bridge hook %s refused to arm at 0x%llX: %s%s",
                HookName(id),
                static_cast<unsigned long long>(address),
                reason ? reason : "validation failed",
                previous + 1 == kRefusalLogLimit ? " (further refusals for this hook are not logged)" : "");
        }
    }

    // ------------------------------------------------------------------
    // Target validation.
    // ------------------------------------------------------------------

    // Returns nullptr when the address is acceptable for an INT3, otherwise a
    // short reason. expectedAllocationBase may be nullptr to skip that check.
    inline const char* ValidateCodeTarget(
        std::uintptr_t address,
        const void* expectedAllocationBase) noexcept
    {
        if (address < 0x10000 || address > 0x00007FFFFFFFFFFFull)
            return "address outside user-mode range";

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) != sizeof(mbi))
            return "VirtualQuery failed";
        if (mbi.State != MEM_COMMIT)
            return "page not committed";
        if (!detail::IsExecutableProtection(mbi.Protect))
            return "page not executable";
        if (expectedAllocationBase != nullptr && mbi.AllocationBase != expectedAllocationBase)
            return "address outside the expected module allocation";

        // When the allocation carries a readable PE header, require the address
        // to lie inside SizeOfImage and inside a section. STR 1.8.4 unpacks and
        // remaps its runtime, so the live page protection (checked above) is the
        // authority for "executable"; header section flags are not trusted.
        const auto base = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);
        IMAGE_DOS_HEADER dos{};
        SIZE_T read = 0;
        if (base != 0 &&
            ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(base), &dos, sizeof(dos), &read) &&
            read == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
            dos.e_lfanew > 0 && dos.e_lfanew < 0x1000)
        {
            IMAGE_NT_HEADERS64 nt{};
            if (ReadProcessMemory(
                    GetCurrentProcess(),
                    reinterpret_cast<const void*>(base + static_cast<std::uintptr_t>(dos.e_lfanew)),
                    &nt,
                    sizeof(nt),
                    &read) &&
                read == sizeof(nt) && nt.Signature == IMAGE_NT_SIGNATURE &&
                nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                const auto rva = address - base;
                if (rva >= nt.OptionalHeader.SizeOfImage)
                    return "address beyond the module image";

                const auto sectionTable =
                    base + static_cast<std::uintptr_t>(dos.e_lfanew) +
                    offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                    nt.FileHeader.SizeOfOptionalHeader;
                const auto sectionCount = nt.FileHeader.NumberOfSections;
                bool inSection = sectionCount == 0;
                for (WORD i = 0; i < sectionCount && i < 96; ++i)
                {
                    IMAGE_SECTION_HEADER section{};
                    if (!ReadProcessMemory(
                            GetCurrentProcess(),
                            reinterpret_cast<const void*>(sectionTable + i * sizeof(IMAGE_SECTION_HEADER)),
                            &section,
                            sizeof(section),
                            &read) ||
                        read != sizeof(section))
                    {
                        inSection = true; // unreadable table: do not guess
                        break;
                    }
                    const auto size = section.Misc.VirtualSize != 0 ? section.Misc.VirtualSize : section.SizeOfRawData;
                    if (rva >= section.VirtualAddress && rva < static_cast<std::uintptr_t>(section.VirtualAddress) + size)
                    {
                        inSection = true;
                        break;
                    }
                }
                if (!inSection)
                    return "address not inside any section of the module image";
            }
        }

        // Where unwind data exists, the address must be a function entry. A
        // missing entry (leaf function or thunk) is allowed.
        DWORD64 imageBase = 0;
        if (const auto* function = RtlLookupFunctionEntry(static_cast<DWORD64>(address), &imageBase, nullptr);
            function && imageBase != 0 &&
            static_cast<std::uintptr_t>(imageBase + function->BeginAddress) != address)
        {
            return "address is inside a function, not at its entry";
        }

        return nullptr;
    }

    // Validates a breakpoint target and reads its original byte. Call with the
    // patch lock held (PatchScope) and only from non-VEH code. On success the
    // address is recorded as owned by this hook. Logs a refusal on failure.
    inline bool PrepareBreakpoint(
        HookId id,
        std::uintptr_t address,
        const void* expectedAllocationBase,
        std::uint8_t& originalByte) noexcept
    {
        if (IsDisarmed(id))
        {
            LogRefusal(id, address, "hook was disarmed earlier in this session");
            return false;
        }

        if (const auto reason = ValidateCodeTarget(address, expectedAllocationBase))
        {
            LogRefusal(id, address, reason);
            return false;
        }

        std::uint8_t current = 0;
        if (!detail::ReadCodeByte(address, current))
        {
            LogRefusal(id, address, "first code byte unreadable");
            return false;
        }
        if (current == kInt3)
        {
            LogRefusal(id, address, "first code byte is already INT3 (another hook or debugger owns it)");
            return false;
        }

        originalByte = current;
        detail::RecordArmedAddress(id, address);
        return true;
    }

    // ------------------------------------------------------------------
    // Shared single-step dispatcher.
    // ------------------------------------------------------------------

    namespace detail
    {
        inline bool IsHardwareBreakpointStep(const CONTEXT* context) noexcept
        {
            // Only trust Dr6 when the kernel supplied debug registers.
            if ((context->ContextFlags & CONTEXT_DEBUG_REGISTERS) != CONTEXT_DEBUG_REGISTERS)
                return false;
            const auto dr6 = context->Dr6;
            const bool hardwareHit = (dr6 & 0xFull) != 0;
            const bool singleStep = (dr6 & 0x4000ull) != 0;
            return hardwareHit && !singleStep;
        }

        inline bool InvokeStepGuarded(const PendingStep& step, CONTEXT* context, bool& faulted) noexcept
        {
            bool keep = false;
            faulted = false;
            __try
            {
                keep = step.fn(context, step.hookAddress, step.cookie);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                keep = false;
                faulted = true;
            }
            return keep;
        }

        inline LONG CALLBACK DispatchSingleStep(EXCEPTION_POINTERS* exceptionInfo)
        {
            if (!exceptionInfo || !exceptionInfo->ExceptionRecord || !exceptionInfo->ContextRecord)
                return EXCEPTION_CONTINUE_SEARCH;
            if (exceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
                return EXCEPTION_CONTINUE_SEARCH;

            bool anyPending = false;
            for (const auto& step : t_pending)
            {
                if (step.fn)
                {
                    anyPending = true;
                    break;
                }
            }
            if (!anyPending)
                return EXCEPTION_CONTINUE_SEARCH;

            auto* context = exceptionInfo->ContextRecord;
            if (IsHardwareBreakpointStep(context))
            {
                // Someone else's hardware breakpoint fired while our step is
                // still pending. Leave our pending steps and TF untouched.
                for (std::size_t i = 0; i < kHookCount; ++i)
                {
                    if (t_pending[i].fn)
                        g_health[i].foreignSteps.fetch_add(1, std::memory_order_relaxed);
                }
                return EXCEPTION_CONTINUE_SEARCH;
            }

            // Service every hook with a step pending on this thread, in hook-id
            // order (entry re-arm before trace), from a snapshot so a callback
            // that starts a new step is not serviced twice for one trap.
            PendingStep snapshot[kHookCount]{};
            for (std::size_t i = 0; i < kHookCount; ++i)
            {
                snapshot[i] = t_pending[i];
                t_pending[i] = PendingStep{};
            }

            for (std::size_t i = 0; i < kHookCount; ++i)
            {
                const auto& step = snapshot[i];
                if (!step.fn)
                    continue;

                bool faulted = false;
                const bool keep = InvokeStepGuarded(step, context, faulted);
                if (faulted)
                {
                    t_pending[i] = PendingStep{};
                    ReportFault(static_cast<HookId>(i), "exception inside its single-step handler");
                    continue;
                }
                if (keep && !t_pending[i].fn && !g_health[i].disarmed.load(std::memory_order_acquire))
                    t_pending[i] = step;
            }

            bool keepTrap = false;
            for (const auto& step : t_pending)
            {
                if (step.fn)
                {
                    keepTrap = true;
                    break;
                }
            }

            if (keepTrap)
                context->EFlags |= kTrapFlag;
            else
                context->EFlags &= ~kTrapFlag;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    // Registers the shared dispatcher once. Call from arm paths only (never
    // from inside an exception handler).
    inline bool EnsureDispatcher() noexcept
    {
        if (detail::g_dispatcher.load(std::memory_order_acquire))
            return true;

        PatchScope scope;
        if (detail::g_dispatcher.load(std::memory_order_acquire))
            return true;

        const auto handler = AddVectoredExceptionHandler(1, &detail::DispatchSingleStep);
        if (!handler)
            return false;
        detail::g_dispatcher.store(handler, std::memory_order_release);
        if (!detail::g_announced.exchange(true))
            Log("bridge hook guard active: shared single-step dispatcher, patch lock and target validation enabled");
        return true;
    }

    // Records a pending single-step for this hook on the current thread and
    // sets TF. Returns false (and leaves TF alone) if the dispatcher is not
    // registered, so the caller can fall back without an orphaned trap.
    inline bool BeginStep(
        HookId id,
        CONTEXT* context,
        std::uintptr_t hookAddress,
        StepFn fn,
        void* cookie = nullptr) noexcept
    {
        if (!context || !fn || !detail::g_dispatcher.load(std::memory_order_acquire))
            return false;
        detail::t_pending[detail::Index(id)] = detail::PendingStep{ fn, hookAddress, cookie };
        context->EFlags |= kTrapFlag;
        return true;
    }

    inline bool HasPendingStep(HookId id) noexcept
    {
        return detail::t_pending[detail::Index(id)].fn != nullptr;
    }

    // Drops this thread's pending step for the hook and clears TF if nothing
    // else on this thread still needs it.
    inline void CancelStep(HookId id, CONTEXT* context) noexcept
    {
        detail::t_pending[detail::Index(id)] = detail::PendingStep{};
        if (!context)
            return;
        for (const auto& step : detail::t_pending)
        {
            if (step.fn)
                return;
        }
        context->EFlags &= ~kTrapFlag;
    }

    // ------------------------------------------------------------------
    // Handler guard.
    // ------------------------------------------------------------------

    namespace detail
    {
        // If the INT3 that trapped at an address this hook armed has since been
        // removed (disarm, concurrent restore), re-execute the original code.
        inline bool RecoverRemovedBreakpoint(HookId id, EXCEPTION_POINTERS* exceptionInfo) noexcept
        {
            if (exceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
                return false;
            const auto address = reinterpret_cast<std::uintptr_t>(
                exceptionInfo->ExceptionRecord->ExceptionAddress);
            if (!WasArmedBy(id, address))
                return false;
            std::uint8_t current = 0;
            if (!ReadCodeByte(address, current) || current == kInt3)
                return false;
            exceptionInfo->ContextRecord->Rip = static_cast<DWORD64>(address);
            return true;
        }

        inline LONG InvokeHandlerGuarded(HandlerFn inner, EXCEPTION_POINTERS* exceptionInfo, bool& faulted) noexcept
        {
            LONG result = EXCEPTION_CONTINUE_SEARCH;
            faulted = false;
            __try
            {
                result = inner(exceptionInfo);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                result = EXCEPTION_CONTINUE_SEARCH;
                faulted = true;
            }
            return result;
        }
    }

    // Runs a module's exception handler so that nothing escapes it. On a fault
    // the context registers the handler may have touched are restored, the
    // hook's pending step is dropped, the hook is disarmed and logged once.
    inline LONG GuardedHandler(HookId id, HandlerFn inner, EXCEPTION_POINTERS* exceptionInfo) noexcept
    {
        if (!exceptionInfo || !exceptionInfo->ExceptionRecord || !exceptionInfo->ContextRecord || !inner)
            return EXCEPTION_CONTINUE_SEARCH;

        if (IsDisarmed(id))
        {
            return detail::RecoverRemovedBreakpoint(id, exceptionInfo)
                ? EXCEPTION_CONTINUE_EXECUTION
                : EXCEPTION_CONTINUE_SEARCH;
        }

        auto* context = exceptionInfo->ContextRecord;
        const auto savedRip = context->Rip;
        const auto savedRsp = context->Rsp;
        const auto savedFlags = context->EFlags;
        const bool hadPending = HasPendingStep(id);

        bool faulted = false;
        const auto result = detail::InvokeHandlerGuarded(inner, exceptionInfo, faulted);
        if (faulted)
        {
            context->Rip = savedRip;
            context->Rsp = savedRsp;
            context->EFlags = savedFlags;
            if (!hadPending)
                detail::t_pending[detail::Index(id)] = detail::PendingStep{};
            ReportFault(id, "exception inside its exception handler");
            return detail::RecoverRemovedBreakpoint(id, exceptionInfo)
                ? EXCEPTION_CONTINUE_EXECUTION
                : EXCEPTION_CONTINUE_SEARCH;
        }

        if (result == EXCEPTION_CONTINUE_SEARCH && detail::RecoverRemovedBreakpoint(id, exceptionInfo))
            return EXCEPTION_CONTINUE_EXECUTION;
        return result;
    }
}
