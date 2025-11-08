cmake_minimum_required(VERSION 3.18)
project(secrets_tray LANGUAGES CXX)

set(QT_DEFAULT_MAJOR_VERSION 6)
set(KF_MIN_VERSION 6.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    message(FATAL_ERROR 
        "CMAKE_BUILD_TYPE must be explicitly set.\n"
        "Use: cmake -DCMAKE_BUILD_TYPE=Release  (for production)\n"
        "  or: cmake -DCMAKE_BUILD_TYPE=Debug    (for development)")
endif()

if(NOT CMAKE_BUILD_TYPE MATCHES "^(Debug|Release|RelWithDebInfo|MinSizeRel)$")
    message(FATAL_ERROR 
        "Invalid CMAKE_BUILD_TYPE='${CMAKE_BUILD_TYPE}'.\n"
        "Allowed values: Debug, Release, RelWithDebInfo, MinSizeRel")
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

find_package(ECM REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDECompilerSettings NO_POLICY_SCOPE)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets DBus)
find_package(KF6 ${KF_MIN_VERSION} REQUIRED COMPONENTS I18n WidgetsAddons StatusNotifierItem)

add_executable(secrets-tray
    src/main.cpp
    src/ui/SecurePasswordDialog.cpp
)

target_link_libraries(secrets-tray
    Qt6::Core
    Qt6::Widgets
    KF6::I18n
    KF6::WidgetsAddons
    KF6::StatusNotifierItem
    Qt6::DBus
)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

target_compile_options(secrets-tray PRIVATE "-fstack-protector-strong")


if(CMAKE_BUILD_TYPE MATCHES "^(Release|RelWithDebInfo)$")
    message(STATUS "Applying production hardening (maximum security)")
    message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
    
    include(CheckCXXCompilerFlag)
    include(CheckLinkerFlag OPTIONAL)

    set(_hardening_cxx_flags
        "-Wall"                        
        "-Wextra"                      
        "-fstack-clash-protection"     
        "-fcf-protection=full"         
        "-Wformat"                    
        "-Wformat=2"                  
        "-Wformat-security"            
        "-Werror=format-security"      
        "-Wconversion"                
        "-Wimplicit-fallthrough"      
        "-fno-strict-overflow"         
        "-fwrapv"                      
        "-fno-delete-null-pointer-checks"
        "-fstrict-flex-arrays=3"      
        "-ftrivial-auto-var-init=zero" 
    )

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        list(APPEND _hardening_cxx_flags
            "-Wtrampolines"                
            "-Wlogical-op"                 
            "-Wduplicated-cond"            
            "-Wduplicated-branches"        
        )
        message(STATUS "  Detected GCC: adding GCC-specific hardening flags")
    endif()

    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        list(APPEND _hardening_cxx_flags
            "-Wthread-safety"              
            "-Wunused-exception-parameter" 
        )
        message(STATUS "  Detected Clang: adding Clang-specific hardening flags")
    endif()

    foreach(flag IN LISTS _hardening_cxx_flags)
        string(REPLACE "," "_" _var_name "HAVE_CXX_${flag}")
        string(REPLACE "=" "_" _var_name "${_var_name}")
        check_cxx_compiler_flag("${flag}" ${_var_name})
        if(${_var_name})
            target_compile_options(secrets-tray PRIVATE "${flag}")
            message(STATUS "  Enabled: ${flag}")
        else()
            message(STATUS "  Skipped: ${flag} (not supported)")
        endif()
    endforeach()

    set(_hardening_ld_flags
        "-Wl,-z,relro"                
        "-Wl,-z,now"                   
        "-Wl,-z,noexecstack"           
        "-Wl,--as-needed"              
        "-Wl,--no-copy-dt-needed-entries"
        "-Wl,-z,nodlopen"             
        "-pie"                         
    )

    foreach(ldflag IN LISTS _hardening_ld_flags)
        if(COMMAND check_linker_flag)
            string(REPLACE "," "_" _ld_var_name "HAVE_LD_${ldflag}")
            string(REPLACE "-" "_" _ld_var_name "${_ld_var_name}")
            check_linker_flag(CXX "${ldflag}" ${_ld_var_name})
            if(${_ld_var_name})
                target_link_options(secrets-tray PRIVATE "${ldflag}")
                message(STATUS "  Enabled: ${ldflag}")
            else()
                message(STATUS "  Skipped: ${ldflag} (not supported)")
            endif()
        else()
            target_link_options(secrets-tray PRIVATE "${ldflag}")
        endif()
    endforeach()

    include(CheckCXXSourceCompiles)
    set(_saved_req_flags "${CMAKE_REQUIRED_FLAGS}")
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3")
    check_cxx_source_compiles("
        #include <string.h>
        #if !defined(_FORTIFY_SOURCE) || _FORTIFY_SOURCE < 3
        #error FORTIFY_SOURCE=3 not supported
        #endif
        int main() { 
            char buf[10]; 
            strcpy(buf, \"test\"); 
            return 0; 
        }
    " HAVE_FORTIFY3)
    set(CMAKE_REQUIRED_FLAGS "${_saved_req_flags}")
    if(HAVE_FORTIFY3)
        target_compile_options(secrets-tray PRIVATE "-U_FORTIFY_SOURCE")
        target_compile_definitions(secrets-tray PRIVATE _FORTIFY_SOURCE=3 _GLIBCXX_ASSERTIONS)
        message(STATUS "  Enabled: _FORTIFY_SOURCE=3, _GLIBCXX_ASSERTIONS")
    else()
        target_compile_definitions(secrets-tray PRIVATE _FORTIFY_SOURCE=2 _GLIBCXX_ASSERTIONS)
        message(STATUS "  Fallback: _FORTIFY_SOURCE=2, _GLIBCXX_ASSERTIONS")
    endif()

    check_cxx_compiler_flag("-fPIE" HAVE_CXX_fPIE)
    if(HAVE_CXX_fPIE)
        target_compile_options(secrets-tray PRIVATE "-fPIE")
        message(STATUS "  Enabled: -fPIE")
    endif()

    include(CheckIPOSupported)
    check_ipo_supported(RESULT _ipo_supported OUTPUT _ipo_output)
    if(_ipo_supported)
        set_property(TARGET secrets-tray PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
        message(STATUS "  Enabled: LTO/IPO")
    else()
        message(STATUS "  Skipped: LTO/IPO (not supported: ${_ipo_output})")
    endif()

endif() 

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Debug mode: enabling sanitizers")
    
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(secrets-tray PRIVATE 
            "-fno-omit-frame-pointer"
            "-fsanitize=address,undefined"
        )
        target_link_options(secrets-tray PRIVATE 
            "-fsanitize=address,undefined"
        )
        message(STATUS "  Enabled: ASan + UBSan")
        message(WARNING 
            "  Sanitizers are incompatible with systemd MemoryDenyWriteExecute=yes.\n"
            "  Run debug builds outside of sandboxed systemd services.")
    else()
        message(STATUS "  Skipped: sanitizers (compiler not supported)")
    endif()
    
    target_compile_options(secrets-tray PRIVATE "-g3")
    message(STATUS "  Enabled: debug symbols (-g3)")
endif()

install(TARGETS secrets-tray DESTINATION ${KDE_INSTALL_BINDIR})

message(STATUS "===== Build Configuration Summary =====")
message(STATUS "Build Type:         ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler:           ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Install Prefix:     ${CMAKE_INSTALL_PREFIX}")
message(STATUS "======================================")