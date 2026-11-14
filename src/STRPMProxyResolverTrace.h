#pragma once

// Loaded after STRPMProxyResolverBridge.h in the bridge SKSE translation unit.
//
// The lifecycle resolver deliberately uses Trap Flag only inside the small STR
// OverlayService methods that publish player-3D state. A raw TF trace would
// enter every CALL target and immediately leave the owning function. This
// controller implements debugger-style "step over": it places a one-shot INT3
// at the instruction following a CALL, clears TF while the callee executes,
// then resumes TF tracing when the callee returns.
//
// Single steps themselves are owned by the shared STRPMHookGuard dispatcher;
// this module only supplies the trace step callback and handles its own
// step-over INT3.

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <thread>

namespace STRPMProxyResolverTrace
{
    namespace detail
    {
        constexpr std::size_t kMaxInstructionBytes = 15;

        std::jthread g_worker;
        std::atomic_bool g_started{ false };
        PVOID g_handler{ nullptr };

        // The step-over INT3 lives in shared code, so its ownership is global:
        // at most one step-over exists process-wide, owned by one thread. A
        // different thread that reaches it gets the original byte back and runs
        // on untraced instead of dying on an unowned INT3.
        std::atomic<std::uintptr_t> g_stepOverAddress{ 0 };
        std::atomic<std::uint8_t> g_stepOverOriginalByte{ 0 };
        std::atomic<DWORD> g_stepOverOwner{ 0 };
        constexpr auto kTraceHook = STRPMHookGuard::HookId::kProxyTrace;

        bool IsLegacyPrefix(std::uint8_t value) noexcept
        {
            switch (value)
            {
            case 0x2E:
            case 0x36:
            case 0x3E:
            case 0x26:
            case 0x64:
            case 0x65:
            case 0x66:
            case 0xF0:
            case 0xF2:
            case 0xF3:
                return true;
            default:
                return false;
            }
        }

        std::optional<std::size_t> DecodeCallLength(std::uintptr_t address) noexcept
        {
            std::uint8_t bytes[kMaxInstructionBytes]{};
            if (!STRPMProxyResolverBridge::detail::ReadProcessBytes(
                    address,
                    bytes,
                    sizeof(bytes)))
            {
                return std::nullopt;
            }

            std::size_t index = 0;
            while (index < kMaxInstructionBytes)
            {
                const auto value = bytes[index];
                if (IsLegacyPrefix(value) || (value >= 0x40 && value <= 0x4F))
                {
                    ++index;
                    continue;
                }
                // 0x67 changes ModRM addressing semantics. It is not emitted by
                // the x64 STR lifecycle code we target; reject rather than guess.
                if (value == 0x67)
                    return std::nullopt;
                break;
            }

            if (index >= kMaxInstructionBytes)
                return std::nullopt;

            if (bytes[index] == 0xE8)
            {
                if (index + 5 <= kMaxInstructionBytes)
                    return index + 5;
                return std::nullopt;
            }

            if (bytes[index] != 0xFF || index + 2 > kMaxInstructionBytes)
                return std::nullopt;

            const auto modrm = bytes[index + 1];
            if (((modrm >> 3) & 0x7u) != 2u)
                return std::nullopt;

            const auto mod = static_cast<std::uint8_t>((modrm >> 6) & 0x3u);
            const auto rm = static_cast<std::uint8_t>(modrm & 0x7u);
            std::size_t length = index + 2;

            if (mod != 3 && rm == 4)
            {
                if (length >= kMaxInstructionBytes)
                    return std::nullopt;
                const auto sib = bytes[length++];
                const auto base = static_cast<std::uint8_t>(sib & 0x7u);
                if (mod == 0 && base == 5)
                    length += 4;
            }
            else if (mod == 0 && rm == 5)
            {
                length += 4;
            }

            if (mod == 1)
                length += 1;
            else if (mod == 2)
                length += 4;

            if (length > kMaxInstructionBytes)
                return std::nullopt;
            return length;
        }

        // Called from the single-step dispatcher (inside a VEH): uses only the
        // self-contained locked helpers. The return address is inside the traced
        // function's bounds, which were validated when the entry hook armed.
        bool ArmStepOver(std::uintptr_t address) noexcept
        {
            if (address < 0x10000 || STRPMHookGuard::IsDisarmed(kTraceHook))
                return false;

            std::uintptr_t expected = 0;
            if (!g_stepOverAddress.compare_exchange_strong(expected, address))
                return false;

            std::uint8_t original = 0;
            if (!STRPMProxyResolverBridge::detail::ReadProcessValue(address, original) ||
                original == 0xCC)
            {
                g_stepOverAddress.store(0);
                return false;
            }

            g_stepOverOriginalByte.store(original);
            g_stepOverOwner.store(GetCurrentThreadId());
            STRPMHookGuard::detail::RecordArmedAddress(kTraceHook, address);
            if (!STRPMProxyResolverBridge::detail::PatchByte(address, 0xCC))
            {
                g_stepOverOwner.store(0);
                g_stepOverAddress.store(0);
                return false;
            }
            return true;
        }

        void DisarmStepOver()
        {
            const auto address = g_stepOverAddress.load();
            if (address == 0)
                return;
            STRPMHookGuard::RestoreBreakpointByte(address, g_stepOverOriginalByte.load());
            g_stepOverOwner.store(0);
            g_stepOverAddress.store(0);
        }

        bool CaptureLifecycleCall(CONTEXT* context) noexcept
        {
            if (!context || !STRPMProxyResolverBridge::detail::g_traceActive)
                return false;

            if (STRPMProxyResolverBridge::detail::g_traceKind ==
                    STRPMProxyResolverBridge::detail::HookKind::kPlayerLoaded &&
                STRPMProxyResolverBridge::detail::IsPlausibleProxyFormID(context->Rcx))
            {
                STRPMProxyResolverBridge::detail::g_traceFormID =
                    static_cast<STRPM::ProxyFormID>(context->Rcx & 0xFFFFFFFFu);
            }

            const auto index = static_cast<std::uint32_t>(context->Rdx & 0xFFFFFFFFu);
            const auto playerId = static_cast<std::uint32_t>(context->R8 & 0xFFFFFFFFu);
            const bool plausiblePlayerId =
                playerId > 0 &&
                playerId <= STRPMProxyResolverBridge::detail::kMaxPlausiblePlayerId;

            if (index != 0 || !plausiblePlayerId)
                return false;

            if (STRPMProxyResolverBridge::detail::g_traceKind ==
                    STRPMProxyResolverBridge::detail::HookKind::kPlayerLoaded &&
                STRPMProxyResolverBridge::detail::g_traceFormID !=
                    STRPM::kInvalidProxyFormID)
            {
                STRPMProxyResolverBridge::detail::ObservePlayerProxy(
                    playerId,
                    STRPMProxyResolverBridge::detail::g_traceFormID);
                return true;
            }

            if (STRPMProxyResolverBridge::detail::g_traceKind ==
                STRPMProxyResolverBridge::detail::HookKind::kPlayerUnloaded)
            {
                STRPMProxyResolverBridge::detail::RemovePlayerProxy(playerId);
                return true;
            }

            return false;
        }

        // Trace step with call step-over. Runs from the shared single-step
        // dispatcher; returns true to keep TF set for the next instruction.
        bool TraceStep(CONTEXT* context, std::uintptr_t, void*)
        {
            namespace bridge = STRPMProxyResolverBridge::detail;
            if (!bridge::g_traceActive || STRPMHookGuard::IsDisarmed(bridge::kLifecycleHook))
            {
                bridge::StopTrace(nullptr);
                return false;
            }

            const auto rip = static_cast<std::uintptr_t>(context->Rip);
            const auto bounds = bridge::g_traceBounds;
            if (rip < bounds.begin || rip >= bounds.end ||
                ++bridge::g_traceSteps > bridge::kMaxTraceSteps)
            {
                bridge::Log("ProxyResolver lifecycle trace ended without a complete mapping");
                bridge::StopTrace(nullptr);
                return false;
            }

            const auto callLength = DecodeCallLength(rip);
            if (!callLength)
                return !bridge::StopTraceBeforeFlagsInstruction(rip);

            if (CaptureLifecycleCall(context))
            {
                bridge::StopTrace(nullptr);
                return false;
            }

            const auto returnAddress = rip + *callLength;
            if (returnAddress < bounds.end && ArmStepOver(returnAddress))
            {
                // TF off while the callee runs; the step-over INT3 resumes it.
                return false;
            }

            // If a one-shot breakpoint cannot be armed, keep TF enabled. The
            // trace will safely abandon if execution leaves the owning method;
            // this degrades to a missed mapping, never modified call semantics.
            return true;
        }

        LONG ExceptionHandlerInner(EXCEPTION_POINTERS* exceptionInfo)
        {
            auto* context = exceptionInfo->ContextRecord;
            const auto code = exceptionInfo->ExceptionRecord->ExceptionCode;
            const auto address = reinterpret_cast<std::uintptr_t>(
                exceptionInfo->ExceptionRecord->ExceptionAddress);

            if (code != EXCEPTION_BREAKPOINT || address == 0 || address != g_stepOverAddress.load())
                return EXCEPTION_CONTINUE_SEARCH;

            STRPMHookGuard::CountHit(kTraceHook);
            if (!STRPMHookGuard::RestoreBreakpointByte(address, g_stepOverOriginalByte.load()))
            {
                STRPMHookGuard::ReportFault(kTraceHook, "restore of step-over byte failed");
                return EXCEPTION_CONTINUE_SEARCH;
            }

            const bool ownedByThisThread = g_stepOverOwner.load() == GetCurrentThreadId();
            g_stepOverOwner.store(0);
            g_stepOverAddress.store(0);
            context->Rip = static_cast<DWORD64>(address);

            // Resume tracing only on the thread that armed the step-over.
            if (ownedByThisThread &&
                STRPMProxyResolverBridge::detail::g_traceActive &&
                !STRPMHookGuard::BeginStep(kTraceHook, context, address, &TraceStep))
            {
                STRPMProxyResolverBridge::detail::StopTrace(nullptr);
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        LONG CALLBACK ExceptionHandler(EXCEPTION_POINTERS* exceptionInfo)
        {
            return STRPMHookGuard::GuardedHandler(kTraceHook, &ExceptionHandlerInner, exceptionInfo);
        }

        bool SleepInterruptible(
            std::stop_token token,
            std::chrono::milliseconds duration)
        {
            constexpr auto slice = std::chrono::milliseconds(100);
            auto slept = std::chrono::milliseconds(0);
            while (slept < duration && !token.stop_requested())
            {
                const auto remaining = duration - slept;
                const auto current = remaining < slice ? remaining : slice;
                std::this_thread::sleep_for(current);
                slept += current;
            }
            return !token.stop_requested();
        }

        void Worker(std::stop_token token)
        {
            // Wait until the main resolver has installed its VEH, then insert
            // this controller as the new first handler so it owns trace stepping.
            while (!token.stop_requested() &&
                   STRPMProxyResolverBridge::detail::g_vectoredHandler == nullptr)
            {
                if (!SleepInterruptible(token, std::chrono::milliseconds(100)))
                    return;
            }

            if (token.stop_requested())
                return;

            STRPMHookGuard::RegisterDisarm(kTraceHook, &DisarmStepOver);
            g_handler = AddVectoredExceptionHandler(1, &ExceptionHandler);
            if (g_handler)
            {
                // Step-over INT3s can now be handled; route trace steps here.
                STRPMProxyResolverBridge::detail::g_traceStep.store(&TraceStep);
                STRPMProxyResolverBridge::detail::Log(
                    "ProxyResolver call step-over controller armed");
            }
            else
            {
                STRPMProxyResolverBridge::detail::Log(
                    "ProxyResolver failed to arm call step-over controller");
            }
        }
    }

    inline void Start() noexcept
    {
        bool expected = false;
        if (!detail::g_started.compare_exchange_strong(expected, true))
            return;
        try
        {
            detail::g_worker = std::jthread(&detail::Worker);
        }
        catch (...)
        {
            detail::g_started.store(false);
            STRPMProxyResolverBridge::detail::Log(
                "ProxyResolver failed to start call step-over controller worker");
        }
    }
}
