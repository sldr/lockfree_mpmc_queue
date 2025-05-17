#pragma once

#ifdef _WIN32

#include <__msvc_int128.hpp>
#include <intrin.h>
#include <atomic>

#if defined(_M_X64) || defined(_M_ARM64)

// std::atomic<> template specialization for std::_Signed128

template<>
struct std::atomic<std::_Signed128>
{
public:
    using value_type = std::_Signed128;

private:
    volatile value_type _value;

public:
    static constexpr bool is_always_lock_free = true; // This will be using intrinsic functions for cmpxchg16b on _M_X64 or _M_ARM64

    constexpr atomic() noexcept = default;
    inline atomic(const std::_Signed128& value) noexcept : _value(value) {};
    atomic(const atomic&)         = delete;
    ~atomic()                     = default;

    void operator=(const atomic&) = delete;
    // inline void operator=(std::_Signed128&& _Value) noexcept : value(std::move(_Value)) {} TODO: maybe get this to work but not used currently

    [[nodiscard]] inline bool is_lock_free() const noexcept { return is_always_lock_free; }

    inline operator std::_Signed128() const noexcept { return load(); }

    inline void store(std::_Signed128 value, const memory_order order = memory_order_seq_cst) noexcept
    {
        // TODO: Only support memory_order_seq_cst at compile time
        exchange(value);
    };

    inline [[nodiscard]] std::_Signed128 load(const memory_order order = memory_order_seq_cst) const noexcept
    {
        // TODO: Only support memory_order_seq_cst at compile time
        std::_Signed128 expected;
        _InterlockedCompareExchange128((volatile long long*)(&this->_value._Word[0]), expected._Word[1],
                                       expected._Word[0], (long long*)&expected._Word[0]);
        return expected;
    }

    inline std::_Signed128 exchange(std::_Signed128 value, const memory_order order = memory_order_seq_cst) noexcept
    {
        // TODO: Only support memory_order_seq_cst at compile time
        std::_Signed128 expected;
        while (true)
        {
            // if (_InterlockedCompareExchange128((volatile long long*)(&this->_value._Word[0]), value._Word[1], value._Word[0], (long long*)&expected._Word[0]))
            if (compare_exchange_strong(expected, value))
            {
                return expected;
            }
        }
    }

    inline bool compare_exchange_strong(std::_Signed128& expected, std::_Signed128 desired,
                                        const memory_order _Order = memory_order_seq_cst) noexcept
    {
        // TODO: Only support memory_order_seq_cst at compile time
        if (_InterlockedCompareExchange128((volatile long long*)(&this->_value._Word[0]), desired._Word[1],
                                           desired._Word[0], (long long*)&expected._Word[0]))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

};

// std::atomic<> template specialization for std::_Unsigned128

template<>
struct std::atomic<std::_Unsigned128>
{
public:
    using value_type = std::_Unsigned128;

private:
    volatile value_type _value;

public:
    static constexpr bool is_always_lock_free = true;  // This will be using intrinsic functions for cmpxchg16b on _M_X64 or _M_ARM64

    constexpr atomic() noexcept = default;
    inline atomic(const std::_Unsigned128& value) noexcept : _value(value) {};
    atomic(const atomic&) = delete;
    ~atomic()             = default;

    void operator=(const atomic&) = delete;
    // inline void operator=(std::_Unsigned128&& _Value) noexcept : value(std::move(_Value)) {} TODO: maybe get this to work but not used currently

    [[nodiscard]] inline bool is_lock_free() const noexcept { return is_always_lock_free; }

    inline operator std::_Unsigned128() const noexcept { return load(); }

    inline void store(std::_Unsigned128 value, const memory_order order = memory_order_seq_cst) noexcept
    {
        // TODO: Only support memory_order_seq_cst at compile time
        exchange(value);
    };

    inline [[nodiscard]] std::_Unsigned128 load(const memory_order order = memory_order_seq_cst) const noexcept
    {
        // TODO: Only support memory_order_seq_cst at compile time
        std::_Unsigned128 expected;
        _InterlockedCompareExchange128((volatile long long*)(&this->_value._Word[0]), expected._Word[1],
                                       expected._Word[0], (long long*)&expected._Word[0]);
        return expected;
    }

    inline std::_Unsigned128 exchange(std::_Unsigned128 value, const memory_order order = memory_order_seq_cst) noexcept
    {
        // TODO: Only support memory_order_seq_cst at compile time
        std::_Unsigned128 expected;
        while (true)
        {
            // if (_InterlockedCompareExchange128((volatile long long*)(&this->_value._Word[0]), value._Word[1], value._Word[0], (long long*)&expected._Word[0]))
            if (compare_exchange_strong(expected, value))
            {
                return expected;
            }
        }
    }

    inline bool compare_exchange_strong(std::_Unsigned128& expected, std::_Unsigned128 desired,
                                        const memory_order _Order = memory_order_seq_cst) noexcept
    {
        // TODO: Only support memory_order_seq_cst at compile time
        if (_InterlockedCompareExchange128((volatile long long*)(&this->_value._Word[0]), desired._Word[1],
                                           desired._Word[0], (long long*)&expected._Word[0]))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
};

#endif  // #if defined(_M_X64) || defined(_M_ARM64)
#endif  // #ifdef _WIN32