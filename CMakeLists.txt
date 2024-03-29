# Qnicorn
# By Lazymio(@wtcode) 2021

cmake_minimum_required(VERSION 3.1)

# Workaround to fix wrong compiler on macos.
if ((APPLE) AND (NOT CMAKE_C_COMPILER))
    set(CMAKE_C_COMPILER "/usr/bin/cc")
endif()
project(qnicorn C)

set(QNICORN_VERSION_MAJOR 1)
set(QNICORN_VERSION_MINOR 0)
set(QNICORN_VERSION_PATCH 0)

option(QNICORN_BUILD_SHARED "Build shared instead of static library" ON)

if (NOT QNICORN_ARCH)
    # build all architectures
    set(QNICORN_ARCH "x86 arm aarch64 riscv mips sparc m68k ppc")
endif()

string(TOUPPER ${QNICORN_ARCH} QNICORN_ARCH)
string(REPLACE " " ";" QNICORN_ARCH_LIST ${QNICORN_ARCH})

foreach(ARCH_LOOP ${QNICORN_ARCH_LIST})
    set(QNICORN_HAS_${ARCH_LOOP} TRUE)
endforeach(ARCH_LOOP)

if(MSVC)
    include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/msvc
    )
else()
    include_directories(
        ${CMAKE_BINARY_DIR}
    )
endif()

include_directories(
    glib_compat
    qemu
    qemu/include
    include
    qemu/tcg
)

if(MSVC)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(MSVC_FLAG  -D__x86_64__)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(MSVC_FLAG  -D__i386__)
    else()
        message(FATAL_ERROR "Neither WIN64 or WIN32!")
    endif()
    add_compile_options(
        -Dinline=__inline
        -D__func__=__FUNCTION__
        -D_CRT_SECURE_NO_WARNINGS
        -DWIN32_LEAN_AND_MEAN
        ${MSVC_FLAG}
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/i386
    )
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4018 /wd4098 /wd4244 /wd4267")
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        string(REPLACE "/ZI" "/Zi" CMAKE_C_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
    endif()
    # default use the multithread, static version of the run-time library.
    option(QNICORN_STATIC_MSVCRT "Embed static runtime library" ON)
    if (QNICORN_STATIC_MSVCRT)
        string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
        string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})
    endif()
else()
    if (MINGW)
        execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpmachine
            OUTPUT_VARIABLE UC_COMPILER_VERSION)

        string(FIND "${UC_COMPILER_VERSION}" "i686" UC_RET)
        if (${UC_RET} GREATER_EQUAL "0")
            set(QNICORN_TARGET_ARCH "i386")
            set(QNICORN_CFLAGS -m32)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32")
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32")
        else()
            set(QNICORN_TARGET_ARCH "i386")
            set(QNICORN_CFLAGS -m64 -mcx16)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m64")
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m64")
        endif()
    elseif(ANDROID_ABI)
        string(FIND "${ANDROID_ABI}" "arm64" UC_RET)
        file(WRITE ${CMAKE_BINARY_DIR}/adb.sh "#!/bin/bash\n\n# Auto-generated by CMakeLists.txt\n\nadb shell mkdir -p /data/local/tmp/build\n")

        if (${UC_RET} GREATER_EQUAL "0")
            set(QNICORN_TARGET_ARCH "aarch64")
        else()
            string(FIND "${ANDROID_ABI}" "armeabi" UC_RET)

            if (${UC_RET} GREATER_EQUAL "0")
                set(QNICORN_TARGET_ARCH "arm")
            else()
                set(QNICORN_TARGET_ARCH "i386")
            endif()
        endif()
    else()
        execute_process(COMMAND ${CMAKE_C_COMPILER} -dM -E -
            INPUT_FILE /dev/null
            OUTPUT_VARIABLE UC_COMPILER_MACRO)

        while(TRUE)
            string(FIND "${UC_COMPILER_MACRO}" "__x86_64__" UC_RET)
            if (${UC_RET} GREATER_EQUAL "0")
                set(QNICORN_TARGET_ARCH "i386")
                string(FIND "${UC_COMPILER_MACRO}" "__ILP32__" UC_RET)
                if (${UC_RET} GREATER_EQUAL "0")
                    set(QNICORN_CFLAGS -mx32)
                    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -mx32")
                    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -mx32")
                else()
                    set(QNICORN_CFLAGS -m64 -mcx16)
                    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m64")
                    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m64")
                endif()
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__i386__" UC_RET)
            if (${UC_RET} GREATER_EQUAL "0")
                set(QNICORN_TARGET_ARCH "i386")
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__arm__" UC_RET)
            if (${UC_RET} GREATER_EQUAL "0")
                set(QNICORN_TARGET_ARCH "arm")
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__aarch64__" UC_RET)
            if (${UC_RET} GREATER_EQUAL "0")
                set(QNICORN_TARGET_ARCH "aarch64")
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__mips__" UC_RET)
            if (${UC_RET} GREATER_EQUAL "0")
                set(QNICORN_TARGET_ARCH "mips")
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__sparc__" UC_RET)
            if (${UC_RET} GREATER_EQUAL "0")
                set(QNICORN_TARGET_ARCH "sparc")
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__ia64__" UC_RET)
            if (${UC_RET} GREATER_EQUAL "0")
                set(QNICORN_TARGET_ARCH "ia64")
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "_ARCH_PPC" UC_RET)
            if (${UC_RET} GREATER_EQUAL "0")
                set(QNICORN_TARGET_ARCH "ppc")
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__riscv" UC_RET)
            if (${UC_RET} GREATER_EQUAL "0")
                set(QNICORN_TARGET_ARCH "riscv")
                break()
            endif()
            string(FIND "${UC_COMPILER_MACRO}" "__s390__" UC_RET)
            if (${UC_RET} GREATER_EQUAL "0")
                set(QNICORN_TARGET_ARCH "s390")
                break()
            endif()
            message(FATAL_ERROR "Unknown host compiler: ${CMAKE_C_COMPILER}.")
        endwhile(TRUE)
    endif()

    set(EXTRA_CFLAGS "--extra-cflags=")
    if (QNICORN_HAS_X86)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DQNICORN_HAS_X86 ")
    endif()
    if (QNICORN_HAS_ARM)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DQNICORN_HAS_ARM -DQNICORN_HAS_ARMEB ")
    endif()
    if (QNICORN_HAS_AARCH64)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DQNICORN_HAS_ARM64 -DQNICORN_HAS_ARM64EB ")
    endif()
    if (QNICORN_HAS_M68K)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DQNICORN_HAS_M68K ")
    endif()
    if (QNICORN_HAS_MIPS)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DQNICORN_HAS_MIPS -DQNICORN_HAS_MIPSEL -DQNICORN_HAS_MIPS64 -DQNICORN_HAS_MIPS64EL ")
    endif()
    if (QNICORN_HAS_SPARC)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DQNICORN_HAS_SPARC ")
    endif()
    if (QNICORN_HAS_PPC)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DQNICORN_HAS_PPC ")
    endif()
    if (QNICORN_HAS_RISCV)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-DQNICORN_HAS_RISCV ")
    endif()

    set (EXTRA_CFLAGS "${EXTRA_CFLAGS}-fPIC")
    if(ANDROID_ABI)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS} --target=${CMAKE_C_COMPILER_TARGET}")
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS} --sysroot=${CMAKE_SYSROOT}")
    endif()
    if (QNICORN_FUZZ)
        set (EXTRA_CFLAGS "${EXTRA_CFLAGS} ${CMAKE_C_FLAGS}")
    endif()

    set(TARGET_LIST "--target-list=")
    if (QNICORN_HAS_X86)
        set (TARGET_LIST "${TARGET_LIST}x86_64-softmmu, ")
    endif()
    if (QNICORN_HAS_ARM)
        set (TARGET_LIST "${TARGET_LIST}arm-softmmu, armeb-softmmu, ")
    endif()
    if (QNICORN_HAS_AARCH64)
        set (TARGET_LIST "${TARGET_LIST}aarch64-softmmu, aarch64eb-softmmu, ")
    endif()
    if (QNICORN_HAS_M68K)
        set (TARGET_LIST "${TARGET_LIST}m68k-softmmu, ")
    endif()
    if (QNICORN_HAS_MIPS)
        set (TARGET_LIST "${TARGET_LIST}mips-softmmu, mipsel-softmmu, mips64-softmmu, mips64el-softmmu, ")
    endif()
    if (QNICORN_HAS_SPARC)
        set (TARGET_LIST "${TARGET_LIST}sparc-softmmu, sparc64-softmmu, ")
    endif()
    if (QNICORN_HAS_PPC)
        set (TARGET_LIST "${TARGET_LIST}ppc-softmmu, ppc64-softmmu, ")
    endif()
    if (QNICORN_HAS_RISCV)
        set (TARGET_LIST "${TARGET_LIST}riscv32-softmmu, riscv64-softmmu, ")
    endif()
    set (TARGET_LIST "${TARGET_LIST} ")

    # GEN config-host.mak & target directories
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/configure
        --cc=${CMAKE_C_COMPILER}
        ${EXTRA_CFLAGS}
        ${TARGET_LIST}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
        INPUT_FILE ${CMAKE_BINARY_DIR}/config-host.mak
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/config-host.h
    )
    if (QNICORN_HAS_X86)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/x86_64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/x86_64-softmmu/config-target.h
        )
    endif()
    if (QNICORN_HAS_ARM)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/arm-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/arm-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/armeb-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/armeb-softmmu/config-target.h
        )
    endif()
    if (QNICORN_HAS_AARCH64)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/aarch64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/aarch64-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/aarch64eb-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/aarch64eb-softmmu/config-target.h
        )
    endif()
    if (QNICORN_HAS_M68K)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/m68k-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/m68k-softmmu/config-target.h
        )
    endif()
    if (QNICORN_HAS_MIPS)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/mips-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/mips-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/mipsel-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/mipsel-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/mips64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/mips64-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/mips64el-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/mips64el-softmmu/config-target.h
        )
    endif()
    if (QNICORN_HAS_SPARC)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/sparc-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/sparc-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/sparc64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/sparc64-softmmu/config-target.h
        )
    endif()
    if (QNICORN_HAS_PPC)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/ppc-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/ppc-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/ppc64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/ppc64-softmmu/config-target.h
        )
    endif()
    if (QNICORN_HAS_RISCV)
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/riscv32-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/riscv32-softmmu/config-target.h
        )
        execute_process(COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/qemu/scripts/create_config
            INPUT_FILE ${CMAKE_BINARY_DIR}/riscv64-softmmu/config-target.mak
            OUTPUT_FILE ${CMAKE_BINARY_DIR}/riscv64-softmmu/config-target.h
        )
    endif()
    add_compile_options(
        ${QNICORN_CFLAGS}
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/tcg/${QNICORN_TARGET_ARCH}
        -D_GNU_SOURCE
        -D_FILE_OFFSET_BITS=64
        -D_LARGEFILE_SOURCE
        -Wall
        -fPIC
    )
    if (APPLE)
        # This warning is disabled by default for gcc and doesn't cause any bug.
        add_compile_options(
            -Wno-missing-braces
        )
    endif()
endif()

set(QNICORN_ARCH_COMMON
    qemu/exec.c
    qemu/exec-vary.c

    qemu/softmmu/cpus.c
    qemu/softmmu/ioport.c
    qemu/softmmu/memory.c
    qemu/softmmu/memory_mapping.c

    qemu/fpu/softfloat.c

    qemu/tcg/optimize.c
    qemu/tcg/tcg.c
    qemu/tcg/tcg-op.c
    qemu/tcg/tcg-op-gvec.c
    qemu/tcg/tcg-op-vec.c

    qemu/accel/tcg/cpu-exec.c
    qemu/accel/tcg/cpu-exec-common.c
    qemu/accel/tcg/cputlb.c
    qemu/accel/tcg/tcg-all.c
    qemu/accel/tcg/tcg-runtime.c
    qemu/accel/tcg/tcg-runtime-gvec.c
    qemu/accel/tcg/translate-all.c
    qemu/accel/tcg/translator.c
)

if (QNICORN_HAS_X86)
add_library(x86_64-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/hw/i386/x86.c

    qemu/target/i386/arch_memory_mapping.c
    qemu/target/i386/bpt_helper.c
    qemu/target/i386/cc_helper.c
    qemu/target/i386/cpu.c
    qemu/target/i386/excp_helper.c
    qemu/target/i386/fpu_helper.c
    qemu/target/i386/helper.c
    qemu/target/i386/int_helper.c
    qemu/target/i386/machine.c
    qemu/target/i386/mem_helper.c
    qemu/target/i386/misc_helper.c
    qemu/target/i386/mpx_helper.c
    qemu/target/i386/seg_helper.c
    qemu/target/i386/smm_helper.c
    qemu/target/i386/svm_helper.c
    qemu/target/i386/translate.c
    qemu/target/i386/xsave_helper.c
    qemu/target/i386/unicorn.c
)

if(MSVC)
    target_compile_options(x86_64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIx86_64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/x86_64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/i386
    )
else()
    target_compile_options(x86_64-softmmu PRIVATE
        -DNEED_CPU_H
        -include x86_64.h
        -I${CMAKE_BINARY_DIR}/x86_64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/i386
    )

    # Log and pow
    target_link_libraries(x86_64-softmmu m)
endif()
endif()

if (QNICORN_HAS_ARM)
add_library(arm-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/arm/cpu.c
    qemu/target/arm/crypto_helper.c
    qemu/target/arm/debug_helper.c
    qemu/target/arm/helper.c
    qemu/target/arm/iwmmxt_helper.c
    qemu/target/arm/m_helper.c
    qemu/target/arm/neon_helper.c
    qemu/target/arm/op_helper.c
    qemu/target/arm/psci.c
    qemu/target/arm/tlb_helper.c
    qemu/target/arm/translate.c
    qemu/target/arm/vec_helper.c
    qemu/target/arm/vfp_helper.c
    qemu/target/arm/unicorn_arm.c
)

if(MSVC)
    target_compile_options(arm-softmmu PRIVATE
        -DNEED_CPU_H
        /FIarm.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/arm-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/arm
    )
else()
    target_compile_options(arm-softmmu PRIVATE
        -DNEED_CPU_H
        -include arm.h
        -I${CMAKE_BINARY_DIR}/arm-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/arm
    )
endif()

add_library(armeb-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/arm/cpu.c
    qemu/target/arm/crypto_helper.c
    qemu/target/arm/debug_helper.c
    qemu/target/arm/helper.c
    qemu/target/arm/iwmmxt_helper.c
    qemu/target/arm/m_helper.c
    qemu/target/arm/neon_helper.c
    qemu/target/arm/op_helper.c
    qemu/target/arm/psci.c
    qemu/target/arm/tlb_helper.c
    qemu/target/arm/translate.c
    qemu/target/arm/vec_helper.c
    qemu/target/arm/vfp_helper.c
    qemu/target/arm/unicorn_arm.c
)

if(MSVC)
    target_compile_options(armeb-softmmu PRIVATE
        -DNEED_CPU_H
        /FIarmeb.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/armeb-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/arm
    )
else()
    target_compile_options(armeb-softmmu PRIVATE
        -DNEED_CPU_H
        -include armeb.h
        -I${CMAKE_BINARY_DIR}/armeb-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/arm
    )
endif()
endif()

if (QNICORN_HAS_AARCH64)
add_library(aarch64-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/arm/cpu64.c
    qemu/target/arm/cpu.c
    qemu/target/arm/crypto_helper.c
    qemu/target/arm/debug_helper.c
    qemu/target/arm/helper-a64.c
    qemu/target/arm/helper.c
    qemu/target/arm/iwmmxt_helper.c
    qemu/target/arm/m_helper.c
    qemu/target/arm/neon_helper.c
    qemu/target/arm/op_helper.c
    qemu/target/arm/pauth_helper.c
    qemu/target/arm/psci.c
    qemu/target/arm/sve_helper.c
    qemu/target/arm/tlb_helper.c
    qemu/target/arm/translate-a64.c
    qemu/target/arm/translate.c
    qemu/target/arm/translate-sve.c
    qemu/target/arm/vec_helper.c
    qemu/target/arm/vfp_helper.c
    qemu/target/arm/unicorn_aarch64.c
)

if(MSVC)
    target_compile_options(aarch64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIaarch64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/aarch64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/arm
    )
else()
    target_compile_options(aarch64-softmmu PRIVATE
        -DNEED_CPU_H
        -include aarch64.h
        -I${CMAKE_BINARY_DIR}/aarch64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/arm
    )
endif()

add_library(aarch64eb-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/arm/cpu64.c
    qemu/target/arm/cpu.c
    qemu/target/arm/crypto_helper.c
    qemu/target/arm/debug_helper.c
    qemu/target/arm/helper-a64.c
    qemu/target/arm/helper.c
    qemu/target/arm/iwmmxt_helper.c
    qemu/target/arm/m_helper.c
    qemu/target/arm/neon_helper.c
    qemu/target/arm/op_helper.c
    qemu/target/arm/pauth_helper.c
    qemu/target/arm/psci.c
    qemu/target/arm/sve_helper.c
    qemu/target/arm/tlb_helper.c
    qemu/target/arm/translate-a64.c
    qemu/target/arm/translate.c
    qemu/target/arm/translate-sve.c
    qemu/target/arm/vec_helper.c
    qemu/target/arm/vfp_helper.c
    qemu/target/arm/unicorn_aarch64.c
)

if(MSVC)
    target_compile_options(aarch64eb-softmmu PRIVATE
        -DNEED_CPU_H
        /FIaarch64eb.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/aarch64eb-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/arm
    )
else()
    target_compile_options(aarch64eb-softmmu PRIVATE
        -DNEED_CPU_H
        -include aarch64eb.h
        -I${CMAKE_BINARY_DIR}/aarch64eb-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/arm
    )
endif()
endif()

if (QNICORN_HAS_M68K)
add_library(m68k-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/m68k/cpu.c
    qemu/target/m68k/fpu_helper.c
    qemu/target/m68k/helper.c
    qemu/target/m68k/op_helper.c
    qemu/target/m68k/softfloat.c
    qemu/target/m68k/translate.c
    qemu/target/m68k/unicorn.c
)

if(MSVC)
    target_compile_options(m68k-softmmu PRIVATE
        -DNEED_CPU_H
        /FIm68k.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/m68k-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/m68k
    )
else()
    target_compile_options(m68k-softmmu PRIVATE
        -DNEED_CPU_H
        -include m68k.h
        -I${CMAKE_BINARY_DIR}/m68k-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/m68k
    )
endif()
endif()

if (QNICORN_HAS_MIPS)
add_library(mips-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/mips/cp0_helper.c
    qemu/target/mips/cp0_timer.c
    qemu/target/mips/cpu.c
    qemu/target/mips/dsp_helper.c
    qemu/target/mips/fpu_helper.c
    qemu/target/mips/helper.c
    qemu/target/mips/lmi_helper.c
    qemu/target/mips/msa_helper.c
    qemu/target/mips/op_helper.c
    qemu/target/mips/translate.c
    qemu/target/mips/unicorn.c
)

if(MSVC)
    target_compile_options(mips-softmmu PRIVATE
        -DNEED_CPU_H
        /FImips.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/mips-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
else()
    target_compile_options(mips-softmmu PRIVATE
        -DNEED_CPU_H
        -include mips.h
        -I${CMAKE_BINARY_DIR}/mips-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
endif()

add_library(mipsel-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/mips/cp0_helper.c
    qemu/target/mips/cp0_timer.c
    qemu/target/mips/cpu.c
    qemu/target/mips/dsp_helper.c
    qemu/target/mips/fpu_helper.c
    qemu/target/mips/helper.c
    qemu/target/mips/lmi_helper.c
    qemu/target/mips/msa_helper.c
    qemu/target/mips/op_helper.c
    qemu/target/mips/translate.c
    qemu/target/mips/unicorn.c
)

if(MSVC)
    target_compile_options(mipsel-softmmu PRIVATE
        -DNEED_CPU_H
        /FImipsel.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/mipsel-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
else()
    target_compile_options(mipsel-softmmu PRIVATE
        -DNEED_CPU_H
        -include mipsel.h
        -I${CMAKE_BINARY_DIR}/mipsel-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
endif()

add_library(mips64-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/mips/cp0_helper.c
    qemu/target/mips/cp0_timer.c
    qemu/target/mips/cpu.c
    qemu/target/mips/dsp_helper.c
    qemu/target/mips/fpu_helper.c
    qemu/target/mips/helper.c
    qemu/target/mips/lmi_helper.c
    qemu/target/mips/msa_helper.c
    qemu/target/mips/op_helper.c
    qemu/target/mips/translate.c
    qemu/target/mips/unicorn.c
)

if(MSVC)
    target_compile_options(mips64-softmmu PRIVATE
        -DNEED_CPU_H
        /FImips64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/mips64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
else()
    target_compile_options(mips64-softmmu PRIVATE
        -DNEED_CPU_H
        -include mips64.h
        -I${CMAKE_BINARY_DIR}/mips64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
endif()

add_library(mips64el-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/mips/cp0_helper.c
    qemu/target/mips/cp0_timer.c
    qemu/target/mips/cpu.c
    qemu/target/mips/dsp_helper.c
    qemu/target/mips/fpu_helper.c
    qemu/target/mips/helper.c
    qemu/target/mips/lmi_helper.c
    qemu/target/mips/msa_helper.c
    qemu/target/mips/op_helper.c
    qemu/target/mips/translate.c
    qemu/target/mips/unicorn.c
)

if(MSVC)
    target_compile_options(mips64el-softmmu PRIVATE
        -DNEED_CPU_H
        /FImips64el.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/mips64el-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
else()
    target_compile_options(mips64el-softmmu PRIVATE
        -DNEED_CPU_H
        -include mips64el.h
        -I${CMAKE_BINARY_DIR}/mips64el-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/mips
    )
endif()
endif()

if (QNICORN_HAS_SPARC)
add_library(sparc-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/sparc/cc_helper.c
    qemu/target/sparc/cpu.c
    qemu/target/sparc/fop_helper.c
    qemu/target/sparc/helper.c
    qemu/target/sparc/int32_helper.c
    qemu/target/sparc/ldst_helper.c
    qemu/target/sparc/mmu_helper.c
    qemu/target/sparc/translate.c
    qemu/target/sparc/win_helper.c
    qemu/target/sparc/unicorn.c
)

if(MSVC)
    target_compile_options(sparc-softmmu PRIVATE
        -DNEED_CPU_H
        /FIsparc.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/sparc-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/sparc
    )
else()
    target_compile_options(sparc-softmmu PRIVATE
        -DNEED_CPU_H
        -include sparc.h
        -I${CMAKE_BINARY_DIR}/sparc-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/sparc
    )
endif()

add_library(sparc64-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/sparc/cc_helper.c
    qemu/target/sparc/cpu.c
    qemu/target/sparc/fop_helper.c
    qemu/target/sparc/helper.c
    qemu/target/sparc/int64_helper.c
    qemu/target/sparc/ldst_helper.c
    qemu/target/sparc/mmu_helper.c
    qemu/target/sparc/translate.c
    qemu/target/sparc/vis_helper.c
    qemu/target/sparc/win_helper.c
    qemu/target/sparc/unicorn64.c
)

if(MSVC)
    target_compile_options(sparc64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIsparc64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/sparc64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/sparc
    )
else()
    target_compile_options(sparc64-softmmu PRIVATE
        -DNEED_CPU_H
        -include sparc64.h
        -I${CMAKE_BINARY_DIR}/sparc64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/sparc
    )
endif()
endif()

if (QNICORN_HAS_PPC)
add_library(ppc-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/hw/ppc/ppc.c
    qemu/hw/ppc/ppc_booke.c

    qemu/libdecnumber/decContext.c
    qemu/libdecnumber/decNumber.c
    qemu/libdecnumber/dpd/decimal128.c
    qemu/libdecnumber/dpd/decimal32.c
    qemu/libdecnumber/dpd/decimal64.c

    qemu/target/ppc/cpu.c
    qemu/target/ppc/cpu-models.c
    qemu/target/ppc/dfp_helper.c
    qemu/target/ppc/excp_helper.c
    qemu/target/ppc/fpu_helper.c
    qemu/target/ppc/int_helper.c
    qemu/target/ppc/machine.c
    qemu/target/ppc/mem_helper.c
    qemu/target/ppc/misc_helper.c
    qemu/target/ppc/mmu-hash32.c
    qemu/target/ppc/mmu_helper.c
    qemu/target/ppc/timebase_helper.c
    qemu/target/ppc/translate.c
    qemu/target/ppc/unicorn.c
)

if(MSVC)
    target_compile_options(ppc-softmmu PRIVATE
        -DNEED_CPU_H
        /FIppc.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/ppc-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/ppc
    )
else()
    target_compile_options(ppc-softmmu PRIVATE
        -DNEED_CPU_H
        -include ppc.h
        -I${CMAKE_BINARY_DIR}/ppc-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/ppc
    )
endif()

add_library(ppc64-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/hw/ppc/ppc.c
    qemu/hw/ppc/ppc_booke.c

    qemu/libdecnumber/decContext.c
    qemu/libdecnumber/decNumber.c
    qemu/libdecnumber/dpd/decimal128.c
    qemu/libdecnumber/dpd/decimal32.c
    qemu/libdecnumber/dpd/decimal64.c

    qemu/target/ppc/compat.c
    qemu/target/ppc/cpu.c
    qemu/target/ppc/cpu-models.c
    qemu/target/ppc/dfp_helper.c
    qemu/target/ppc/excp_helper.c
    qemu/target/ppc/fpu_helper.c
    qemu/target/ppc/int_helper.c
    qemu/target/ppc/machine.c
    qemu/target/ppc/mem_helper.c
    qemu/target/ppc/misc_helper.c
    qemu/target/ppc/mmu-book3s-v3.c
    qemu/target/ppc/mmu-hash32.c
    qemu/target/ppc/mmu-hash64.c
    qemu/target/ppc/mmu_helper.c
    qemu/target/ppc/mmu-radix64.c
    qemu/target/ppc/timebase_helper.c
    qemu/target/ppc/translate.c
    qemu/target/ppc/unicorn.c
)

if(MSVC)
    target_compile_options(ppc64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIppc64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/ppc64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/ppc
    )
else()
    target_compile_options(ppc64-softmmu PRIVATE
        -DNEED_CPU_H
        -include ppc64.h
        -I${CMAKE_BINARY_DIR}/ppc64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/ppc
    )
endif()
endif()

if (QNICORN_HAS_RISCV)
add_library(riscv32-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/riscv/cpu.c
    qemu/target/riscv/cpu_helper.c
    qemu/target/riscv/csr.c
    qemu/target/riscv/fpu_helper.c
    qemu/target/riscv/op_helper.c
    qemu/target/riscv/pmp.c
    qemu/target/riscv/translate.c
    qemu/target/riscv/unicorn.c
)

if(MSVC)
    target_compile_options(riscv32-softmmu PRIVATE
        -DNEED_CPU_H
        /FIriscv32.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/riscv32-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/riscv
    )
else()
    target_compile_options(riscv32-softmmu PRIVATE
        -DNEED_CPU_H
        -include riscv32.h
        -I${CMAKE_BINARY_DIR}/riscv32-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/riscv
    )
endif()

add_library(riscv64-softmmu
    ${QNICORN_ARCH_COMMON}

    qemu/target/riscv/cpu.c
    qemu/target/riscv/cpu_helper.c
    qemu/target/riscv/csr.c
    qemu/target/riscv/fpu_helper.c
    qemu/target/riscv/op_helper.c
    qemu/target/riscv/pmp.c
    qemu/target/riscv/translate.c
    qemu/target/riscv/unicorn.c
)

if(MSVC)
    target_compile_options(riscv64-softmmu PRIVATE
        -DNEED_CPU_H
        /FIriscv64.h
        /I${CMAKE_CURRENT_SOURCE_DIR}/msvc/riscv64-softmmu
        /I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/riscv
    )
else()
    target_compile_options(riscv64-softmmu PRIVATE
        -DNEED_CPU_H
        -include riscv64.h
        -I${CMAKE_BINARY_DIR}/riscv64-softmmu
        -I${CMAKE_CURRENT_SOURCE_DIR}/qemu/target/riscv
    )
endif()
endif()


set(QNICORN_SRCS
    uc.c

    qemu/softmmu/vl.c

    qemu/hw/core/cpu.c
)

set(QNICORN_COMMON_SRCS

    list.c

    glib_compat/glib_compat.c
    glib_compat/gtestutils.c
    glib_compat/garray.c
    glib_compat/gtree.c
    glib_compat/grand.c
    glib_compat/glist.c
    glib_compat/gmem.c
    glib_compat/gpattern.c
    glib_compat/gslice.c

    qemu/util/bitmap.c
    qemu/util/bitops.c
    qemu/util/crc32c.c
    qemu/util/cutils.c
    qemu/util/getauxval.c
    qemu/util/guest-random.c
    qemu/util/host-utils.c
    qemu/util/osdep.c
    qemu/util/qdist.c
    qemu/util/qemu-timer.c
    qemu/util/qemu-timer-common.c
    qemu/util/range.c
    qemu/util/qht.c
    qemu/util/pagesize.c
    qemu/util/cacheinfo.c

    qemu/crypto/aes.c
)

# A workaround to avoid circle dependency between unicorn and *-softmmu
if (MSVC)
    set(QNICORN_COMMON_SRCS
        ${QNICORN_COMMON_SRCS}
        qemu/util/oslib-win32.c
        qemu/util/qemu-thread-win32.c
    )
    if (CMAKE_SIZEOF_VOID_P EQUAL 8)
        if (MSVC_VERSION LESS 1600 AND MSVC_IDE)
            add_custom_command(OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/build/setjmp-wrapper-win32.dir/setjmp-wrapper-win32.obj"
                COMMAND ml64 /c /nologo /Fo"${CMAKE_CURRENT_SOURCE_DIR}/build/setjmp-wrapper-win32.dir/setjmp-wrapper-win32.obj" /W3 /errorReport:prompt /Ta"${CMAKE_CURRENT_SOURCE_DIR}/qemu/util/setjmp-wrapper-win32.asm"
                DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/qemu/util/setjmp-wrapper-win32.asm"
            )
            set(QNICORN_SRCS ${QNICORN_SRCS} "${CMAKE_CURRENT_SOURCE_DIR}/build/setjmp-wrapper-win32.dir/setjmp-wrapper-win32.obj")
        else()
            enable_language(ASM_MASM)
        endif()
        set(QNICORN_COMMON_SRCS ${QNICORN_COMMON_SRCS} qemu/util/setjmp-wrapper-win32.asm)
    endif()
else()
    set(QNICORN_COMMON_SRCS
        ${QNICORN_COMMON_SRCS}
        qemu/util/oslib-posix.c
        qemu/util/qemu-thread-posix.c
    )
endif()

add_library(qnicorn-common
    ${QNICORN_COMMON_SRCS}
)

if (NOT MSVC AND NOT ANDROID_ABI)
    target_link_libraries(qnicorn-common pthread)
endif()

if (QNICORN_BUILD_SHARED)

    add_library(qnicorn SHARED
        ${QNICORN_SRCS}
    )
    if (ANDROID_ABI)
        file(APPEND ${CMAKE_BINARY_DIR}/adb.sh "adb push ./libqnicorn.so /data/local/tmp/build/\n")
    endif()
else()
    add_library(qnicorn STATIC
        ${QNICORN_SRCS}
    )
endif()

enable_testing()
set(QNICORN_LINK_LIBRARIES ${QNICORN_LINK_LIBRARIES} qnicorn-common)
if (QNICORN_HAS_X86)
    set(QNICORN_COMPILE_OPTIONS ${QNICORN_COMPILE_OPTIONS} -DQNICORN_HAS_X86)
    set(QNICORN_LINK_LIBRARIES ${QNICORN_LINK_LIBRARIES} x86_64-softmmu)
    set(QNICORN_SAMPLE_FILE ${QNICORN_SAMPLE_FILE} sample_x86 sample_x86_32_gdt_and_seg_regs sample_batch_reg mem_apis shellcode)
    target_link_libraries(x86_64-softmmu qnicorn-common)
    set(QNICORN_TEST_FILE ${QNICORN_TEST_FILE} test_x86)
endif()
if (QNICORN_HAS_ARM)
    set(QNICORN_COMPILE_OPTIONS ${QNICORN_COMPILE_OPTIONS} -DQNICORN_HAS_ARM)
    set(QNICORN_LINK_LIBRARIES ${QNICORN_LINK_LIBRARIES} arm-softmmu armeb-softmmu)
    set(QNICORN_SAMPLE_FILE ${QNICORN_SAMPLE_FILE} sample_arm)
    target_link_libraries(arm-softmmu qnicorn-common)
    target_link_libraries(armeb-softmmu qnicorn-common)
    set(QNICORN_TEST_FILE ${QNICORN_TEST_FILE} test_arm)
endif()
if (QNICORN_HAS_AARCH64)
    set(QNICORN_COMPILE_OPTIONS ${QNICORN_COMPILE_OPTIONS} -DQNICORN_HAS_ARM64)
    set(QNICORN_LINK_LIBRARIES ${QNICORN_LINK_LIBRARIES} aarch64-softmmu aarch64eb-softmmu)
    set(QNICORN_SAMPLE_FILE ${QNICORN_SAMPLE_FILE} sample_arm64)
    target_link_libraries(aarch64-softmmu qnicorn-common)
    target_link_libraries(aarch64eb-softmmu qnicorn-common)
    set(QNICORN_TEST_FILE ${QNICORN_TEST_FILE} test_arm64)
endif()
if (QNICORN_HAS_M68K)
    set(QNICORN_COMPILE_OPTIONS ${QNICORN_COMPILE_OPTIONS} -DQNICORN_HAS_M68K)
    set(QNICORN_LINK_LIBRARIES ${QNICORN_LINK_LIBRARIES} m68k-softmmu)
    set(QNICORN_SAMPLE_FILE ${QNICORN_SAMPLE_FILE} sample_m68k)
    target_link_libraries(m68k-softmmu qnicorn-common)
    set(QNICORN_TEST_FILE ${QNICORN_TEST_FILE} test_m68k)
endif()
if (QNICORN_HAS_MIPS)
    set(QNICORN_COMPILE_OPTIONS ${QNICORN_COMPILE_OPTIONS} -DQNICORN_HAS_MIPS -DQNICORN_HAS_MIPSEL -DQNICORN_HAS_MIPS64 -DQNICORN_HAS_MIPS64EL)
    set(QNICORN_LINK_LIBRARIES ${QNICORN_LINK_LIBRARIES} mips-softmmu mipsel-softmmu mips64-softmmu mips64el-softmmu)
    set(QNICORN_SAMPLE_FILE ${QNICORN_SAMPLE_FILE} sample_mips)
    target_link_libraries(mips-softmmu qnicorn-common)
    target_link_libraries(mipsel-softmmu qnicorn-common)
    target_link_libraries(mips64-softmmu qnicorn-common)
    target_link_libraries(mips64el-softmmu qnicorn-common)
    set(QNICORN_TEST_FILE ${QNICORN_TEST_FILE} test_mips)
endif()
if (QNICORN_HAS_SPARC)
    set(QNICORN_COMPILE_OPTIONS ${QNICORN_COMPILE_OPTIONS} -DQNICORN_HAS_SPARC)
    set(QNICORN_LINK_LIBRARIES ${QNICORN_LINK_LIBRARIES} sparc-softmmu sparc64-softmmu)
    set(QNICORN_SAMPLE_FILE ${QNICORN_SAMPLE_FILE} sample_sparc)
    target_link_libraries(sparc-softmmu qnicorn-common)
    target_link_libraries(sparc64-softmmu qnicorn-common)
    set(QNICORN_TEST_FILE ${QNICORN_TEST_FILE} test_sparc)
endif()
if (QNICORN_HAS_PPC)
    set(QNICORN_COMPILE_OPTIONS ${QNICORN_COMPILE_OPTIONS} -DQNICORN_HAS_PPC)
    set(QNICORN_LINK_LIBRARIES ${QNICORN_LINK_LIBRARIES} ppc-softmmu ppc64-softmmu)
    set(QNICORN_SAMPLE_FILE ${QNICORN_SAMPLE_FILE} sample_ppc)
    target_link_libraries(ppc-softmmu qnicorn-common)
    target_link_libraries(ppc64-softmmu qnicorn-common)
    set(QNICORN_TEST_FILE ${QNICORN_TEST_FILE} test_ppc)
endif()
if (QNICORN_HAS_RISCV)
    set(QNICORN_COMPILE_OPTIONS ${QNICORN_COMPILE_OPTIONS} -DQNICORN_HAS_RISCV)
    set(QNICORN_LINK_LIBRARIES ${QNICORN_LINK_LIBRARIES} riscv32-softmmu riscv64-softmmu)
    set(QNICORN_SAMPLE_FILE ${QNICORN_SAMPLE_FILE} sample_riscv)
    target_link_libraries(riscv32-softmmu qnicorn-common)
    target_link_libraries(riscv64-softmmu qnicorn-common)
    set(QNICORN_TEST_FILE ${QNICORN_TEST_FILE} test_riscv)
endif()

# Extra tests
set(QNICORN_TEST_FILE ${QNICORN_TEST_FILE} test_mem)
set(QNICORN_TEST_FILE ${QNICORN_TEST_FILE} test_ctl)
set(QNICORN_SAMPLE_FILE ${QNICORN_SAMPLE_FILE} sample_ctl)

target_compile_options(qnicorn PRIVATE
    ${QNICORN_COMPILE_OPTIONS}
)

if (MINGW)
    set(QNICORN_LINK_LIBRARIES ${QNICORN_LINK_LIBRARIES} pthread)
endif()

if(QNICORN_TARGET_ARCH STREQUAL "riscv")
    set(QNICORN_LINK_LIBRARIES ${QNICORN_LINK_LIBRARIES} atomic)
endif()

if(MSVC)
    if (QNICORN_BUILD_SHARED)
        target_compile_options(qnicorn PRIVATE
            -DQNICORN_SHARED
        )
    endif()

    target_link_libraries(qnicorn
        ${QNICORN_LINK_LIBRARIES}
    )
else()
    target_link_libraries(qnicorn
        ${QNICORN_LINK_LIBRARIES}
        m
    )
    set_target_properties(qnicorn PROPERTIES
        VERSION ${QNICORN_VERSION_MAJOR}
        SOVERSION ${QNICORN_VERSION_MAJOR}
    )
endif()

if(MSVC)
    set(SAMPLES_LIB
        qnicorn
    )
elseif(NOT ANDROID_ABI)
    set(SAMPLES_LIB
        qnicorn
        pthread
    )
else()
    set(SAMPLES_LIB
        qnicorn
    )
endif()


if(QNICORN_FUZZ)
    set(QNICORN_FUZZ_SUFFIX "arm_arm;arm_armbe;arm_thumb;arm64_arm;arm64_armbe;m68k_be;mips_32be;mips_32le;sparc_32be;x86_16;x86_32;x86_64")
    set(SAMPLES_LIB ${SAMPLES_LIB} rt)
    foreach(SUFFIX ${QNICORN_FUZZ_SUFFIX})
        add_executable(fuzz_emu_${SUFFIX}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/fuzz_emu_${SUFFIX}.c
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/onedir.c
        )
        target_link_libraries(fuzz_emu_${SUFFIX}
            ${SAMPLES_LIB}
        )
    endforeach()
else()
    foreach(SAMPLE_FILE ${QNICORN_SAMPLE_FILE})
        add_executable(${SAMPLE_FILE}
            ${CMAKE_CURRENT_SOURCE_DIR}/samples/${SAMPLE_FILE}.c
        )
        target_link_libraries(${SAMPLE_FILE}
            ${SAMPLES_LIB}
        )
        endforeach(SAMPLE_FILE)

        foreach(TEST_FILE ${QNICORN_TEST_FILE})
        add_executable(${TEST_FILE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/${TEST_FILE}.c
        )
        target_link_libraries(${TEST_FILE}
            ${SAMPLES_LIB}
        )
        add_test(${TEST_FILE} ${TEST_FILE})
        if (ANDROID_ABI)
            file(APPEND ${CMAKE_BINARY_DIR}/adb.sh "adb push ${TEST_FILE} /data/local/tmp/build/\n")
            file(APPEND ${CMAKE_BINARY_DIR}/adb.sh "adb shell \"chmod +x /data/local/tmp/build/${TEST_FILE}\"\n")
            file(APPEND ${CMAKE_BINARY_DIR}/adb.sh "adb shell \'LD_LIBRARY_PATH=/data/local/tmp/build:$LD_LIBRARY_PATH /data/local/tmp/build/${TEST_FILE}\' || exit -1\n")
        endif()
    endforeach(TEST_FILE)
endif()

if(NOT MSVC)
    include("GNUInstallDirs")
    file(GLOB QNICORN_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include/qnicorn/*.h)
    set(QNICORN_HEADERS ${QNICORN_HEADERS} ${CMAKE_CURRENT_SOURCE_DIR}/include/unicorn/unicorn.h)
    install(TARGETS qnicorn
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
    install(FILES ${QNICORN_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qnicorn)
    file(WRITE ${CMAKE_BINARY_DIR}/qnicorn.pc "Name: qnicorn\n\
Description: Qnicorn emulator engine\n\
Version: ${QNICORN_VERSION_MAJOR}.${QNICORN_VERSION_MINOR}.${QNICORN_VERSION_PATCH}\n\
libdir=${CMAKE_INSTALL_FULL_LIBDIR}\n\
includedir=${CMAKE_INSTALL_FULL_INCLUDEDIR}\n\
Libs: -L\$\{libdir\} -lqnicorn\n\
Cflags: -I\$\{includedir\}\n"
    )
    install(FILES ${CMAKE_BINARY_DIR}/qnicorn.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()
