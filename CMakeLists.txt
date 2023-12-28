cmake_minimum_required(VERSION 3.15.3)

# Optional: print out extra messages to see what is going on. Comment it to have less verbose messages
#set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_BUILD_TYPE Release)

# Path to toolchain file. This one has to be before 'project()' below
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_SOURCE_DIR}/arm-none-eabi-gcc.cmake)

# Setup project, output and linker file
project(mc60cmake)
set(EXECUTABLE ${PROJECT_NAME}.elf)

set(MCU "MC60" CACHE STRING "Default target is MC60")


enable_language(C ASM)
#set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)


# Optional: issue a message to be sure it uses the correct toolchain file.
message(STATUS "CMAKE_TOOLCHAIN_FILE is: ${CMAKE_TOOLCHAIN_FILE}")

# List of source files
set(SRC_FILES
        config/sys_config.c
        config/custom_sys_cfg.c

        # inlude ril librarry
        ril/src/ril_system.c
        ril/src/ril_sms.c
        ril/src/ril_sim.c
        ril/src/ril_ntp.c
        ril/src/ril_network.c
        ril/src/ril_location.c
        ril/src/ril_init.c
        ril/src/ril_http.c
        ril/src/ril_gps.c
        ril/src/Ril_dtmf.c
        ril/src/ril_custom.c
        ril/src/ril_bluetooth.c
        ril/src/ril_ble.c
        ril/src/ril_audio.c
        ril/src/ril_alarm.c
        ril/src/ril_telephony.c
        ril/src/ril_urc.c
        ril/src/ril_util.c
        ril/src/ril_atResponse.c
        ril/src/ril_ftp.c 
        ril/src/ril_mqtt.c

        src/main.c        
        )

if(MCU STREQUAL "MC60")
        set(LINKER_SECTIONS ${CMAKE_SOURCE_DIR}/libs/gcc/MC60/linkscript.ld)
elseif(MCU STREQUAL "MC60E")
        list(APPEND SRC_FILES 
                ril/src/ril_ble_clinet.c                        
        )
        set(LINKER_SECTIONS ${CMAKE_SOURCE_DIR}/libs/gcc/MC60E/linkscript.ld)
endif()

# Build the executable based on the source files
add_executable(${EXECUTABLE} ${SRC_FILES})

# List of includ directories
target_include_directories(${EXECUTABLE} PRIVATE
        config/inc/
        ril/inc
        include
        )

# List of compiler defines, prefix with -D compiler option
target_compile_definitions(${EXECUTABLE} PRIVATE
        -D__OCPU_COMPILER_GCC__ 
        -DMT6252        
        )



# Compiler options
target_compile_options(${EXECUTABLE} PRIVATE
        -march=armv5te
        -mthumb-interwork
        -mlittle-endian
        -mfloat-abi=soft
        -mlong-calls

        -fmessage-length=0 
        -fsigned-char 
        -ffunction-sections
        
        -Wall
        -Os

        # -----------------------------------------
        -mfpu=vfp 
        -Wstrict-prototypes 
        -std=c99 
        )

# Linker options
target_link_options(${EXECUTABLE} PRIVATE
        -T${LINKER_SECTIONS}
        -L${CMAKE_SOURCE_DIR}/libs/gcc

        -march=armv5te
        -mthumb-interwork
        -mlittle-endian
        -mfloat-abi=soft
        -mlong-calls

        -fmessage-length=0 
        -fsigned-char 
        -ffunction-sections
        
        -Wall

        -nostartfiles
        -Xlinker --gc-sections
        -Wl,-Map=${PROJECT_NAME}.map,--cref
        -Wl,--gc-sections


        #-Xlinker -print-memory-usage -Xlinker
        )

TARGET_LINK_LIBRARIES(${EXECUTABLE}
        m
        c
        gcc
        app_start
)

# Optional: Print executable size as part of the post build process
add_custom_command(TARGET ${EXECUTABLE}
        POST_BUILD
        COMMAND ${CMAKE_SIZE_UTIL} ${EXECUTABLE})

# Optional: Create hex, bin and S-Record files after the build
add_custom_command(TARGET ${EXECUTABLE}
        POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary ${EXECUTABLE} ${PROJECT_NAME}.bin
        COMMAND ${CMAKE_SOURCE_DIR}/tools/makeGFH.py ${PROJECT_NAME}.bin ${MCU}
        COMMAND echo ${PROJECT_NAME}HDR.bin > ${PROJECT_NAME}.cfg
        )
