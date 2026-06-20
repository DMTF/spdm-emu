cmake_minimum_required(VERSION 3.5)

include_directories(${LIBSPDM_DIR}/include
                    ${SPDM_EMU_DIR}/include
)

set(src_pci_tdisp_device_lib_sample
    pci_tdisp_device_context.c
    pci_tdisp_device_version.c
    pci_tdisp_device_capabilities.c
    pci_tdisp_device_lock_interface.c
    pci_tdisp_device_interface_report.c
    pci_tdisp_device_interface_state.c
    pci_tdisp_device_start_interface.c
    pci_tdisp_device_stop_interface.c
)

add_library(pci_tdisp_device_lib_sample STATIC ${src_pci_tdisp_device_lib_sample})

# The DEVICE_INTERFACE_REPORT can optionally be loaded from a JSON file. This
# requires the Jansson development library to be present in the build
# environment. If it is not available this feature is simply compiled out and
# DEVICE_INTERFACE_REPORT is populated with hardcoded default values instead.
find_library(JANSSON_LIBRARY NAMES jansson)
find_path(JANSSON_INCLUDE_DIR NAMES jansson.h)
if(JANSSON_LIBRARY AND JANSSON_INCLUDE_DIR)
    message(STATUS "libjansson found: enabling support for loading DEVICE_INTERFACE_REPORT from JSON file.")
    target_sources(pci_tdisp_device_lib_sample PRIVATE
                   pci_tdisp_device_interface_report_json.c)
    target_compile_definitions(pci_tdisp_device_lib_sample PRIVATE TDISP_DEVICE_INTERFACE_REPORT_JSON_SUPPORT)
    target_include_directories(pci_tdisp_device_lib_sample PRIVATE
                               ${JANSSON_INCLUDE_DIR}
                               ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(pci_tdisp_device_lib_sample PUBLIC ${JANSSON_LIBRARY})
else()
    message(STATUS "libjansson not found: disabling support for loading DEVICE_INTERFACE_REPORT from JSON file.")
endif()
