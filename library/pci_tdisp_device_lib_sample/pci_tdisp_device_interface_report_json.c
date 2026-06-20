/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>

#include "hal/base.h"
#include "hal/library/memlib.h"
#include "hal/library/debuglib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "library/pci_tdisp_device_lib.h"

#include "pci_tdisp_device_interface_report_json.h"

#define MAX_MMIO_RANGE_COUNT 4

/*
 * Default location of the JSON file describing a DEVICE_INTERFACE_REPORT. It
 * can be overridden at runtime through the TDISP_DEVICE_INTERFACE_REPORT
 * environment variable.
 */
#define TDISP_DEVICE_INTERFACE_REPORT_JSON_FILE "tdisp_device_interface_report.json"

/**
 *  Resolve the path of the DEVICE_INTERFACE_REPORT JSON file.
 **/
static const char *get_device_interface_report_json_path (void)
{
    const char *path;

    path = getenv("TDISP_DEVICE_INTERFACE_REPORT");
    if (path == NULL) {
        path = TDISP_DEVICE_INTERFACE_REPORT_JSON_FILE;
    }
    return path;
}

/**
 *  Fetch an unsigned integer field from a JSON object given a field name.
 *
 *  @param object  the JSON object to read from.
 *  @param field   the member name to read.
 *  @param value   on success, receives the unsigned integer value.
 *
 *  @retval true   the member exists and could be converted to an unsigned
 *                 integer.
 *  @retval false  the member is missing or could not be converted to an
 *                 unsigned integer.
 **/
static bool json_get_uint (const json_t *object, const char *field, uint64_t *value)
{
    json_t *node;

    node = json_object_get(object, field);
    if (json_is_integer(node)) {
        *value = json_integer_value(node);
        return true;
    }

    if (json_is_string(node)) {
        const char *str = json_string_value(node);
        char *end;

        if (*str == '+' || *str == '-') {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                          "JSON field '%s' string '%s' must not be signed!\n", field, str));
            return false;
        }

        errno = 0;
        *value = strtoull(str, &end, 0);
        if (end == str || *end != '\0' || errno != 0) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "JSON field '%s' string '%s' is not a valid unsigned integer!\n", field, str));
            return false;
        }
        return true;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                  "JSON field '%s' is missing or not an unsigned integer!\n", field));
    return false;
}

bool pci_tdisp_device_interface_report_load_from_json (uint8_t *buffer,
                                                       size_t buffer_size,
                                                       uint16_t *report_size)
{
    const char *json_file;
    json_t *root;
    json_t *ranges;
    json_t *info;
    json_error_t error;
    uint64_t value;

    pci_tdisp_device_interface_report_struct_t header;
    size_t mmio_range_count;
    uint32_t info_len;
    const char *info_str;
    uint8_t *buffer_ptr;
    size_t total_size;

    bool ret;

    json_file = get_device_interface_report_json_path();

    root = json_load_file(json_file, 0, &error);
    if (root == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                      "tdisp: cannot load DEVICE_INTERFACE_REPORT from JSON file: %s (line %d)\n",
                      error.text, error.line));
        return false;
    }

    ret = false;

    if (!json_is_object(root)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "tdisp: report JSON root is not an object\n"));
        goto out;
    }

    /*
     * The MMIO range count is inferred from the number of mmio regions
     * described in the JSON file.
     */
    ranges = json_object_get(root, "mmio_ranges");
    if (!json_is_array(ranges)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "tdisp: 'mmio_ranges' is missing or not an array\n"));
        goto out;
    }
    mmio_range_count = json_array_size(ranges);
    if (mmio_range_count > MAX_MMIO_RANGE_COUNT) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "tdisp: a number of 'mmio_ranges' > %d is not supported\n", MAX_MMIO_RANGE_COUNT));
        goto out;
    }

    info = json_object_get(root, "device_specific_info");
    if (!json_is_string(info)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "tdisp: 'device_specific_info' is missing or not a string\n"));
        goto out;
    }
    info_str = json_string_value(info);
    info_len = strlen(info_str);

    /* fixed header + mmio_range[mmio_range_count] + device_specific_info_len + info bytes */
    total_size = sizeof(header) +
                 mmio_range_count * sizeof(pci_tdisp_mmio_range_t) +
                 sizeof(uint32_t) + info_len;
    if (total_size > buffer_size) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "tdisp: JSON DEVICE_INTERFACE_REPORT (%zu bytes) exceeds buffer (%zu bytes)\n",
                      total_size, buffer_size));
        goto out;
    }

    libspdm_zero_mem(buffer, buffer_size);

    /* Build the fixed header in a local copy, then serialize it. */
    libspdm_zero_mem(&header, sizeof(header));
    if (!json_get_uint(root, "interface_info", &value)) {
        goto out;
    }
    header.interface_info = (uint16_t)value;
    if (!json_get_uint(root, "msi_x_message_control", &value)) {
        goto out;
    }
    header.msi_x_message_control = (uint16_t)value;
    if (!json_get_uint(root, "lnr_control", &value)) {
        goto out;
    }
    header.lnr_control = (uint16_t)value;
    if (!json_get_uint(root, "tph_control", &value)) {
        goto out;
    }
    header.tph_control = (uint32_t)value;
    header.mmio_range_count = (uint32_t)mmio_range_count;

    buffer_ptr = buffer;
    libspdm_copy_mem(buffer_ptr, buffer_size, &header, sizeof(header));
    buffer_ptr += sizeof(header);

    for (size_t index = 0; index < mmio_range_count; index++) {
        json_t *element = json_array_get(ranges, index);
        pci_tdisp_mmio_range_t range;

        if (!json_is_object(element)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "tdisp: mmio_ranges[%zu] is not an object\n", index));
            goto out;
        }
        libspdm_zero_mem(&range, sizeof(range));
        if (!json_get_uint(element, "first_page", &value)) {
            goto out;
        }
        range.first_page = (uint64_t)value;
        if (!json_get_uint(element, "number_of_pages", &value)) {
            goto out;
        }
        range.number_of_pages = (uint32_t)value;
        if (!json_get_uint(element, "range_attributes", &value)) {
            goto out;
        }
        range.range_attributes = (uint16_t)value;
        if (!json_get_uint(element, "range_id", &value)) {
            goto out;
        }
        range.range_id = (uint16_t)value;

        libspdm_copy_mem(buffer_ptr, (size_t)(buffer + buffer_size - buffer_ptr),
                         &range, sizeof(range));
        buffer_ptr += sizeof(range);
    }

    libspdm_copy_mem(buffer_ptr, (size_t)(buffer + buffer_size - buffer_ptr),
                     &info_len, sizeof(info_len));
    buffer_ptr += sizeof(info_len);
    libspdm_copy_mem(buffer_ptr, (size_t)(buffer + buffer_size - buffer_ptr),
                     info_str, info_len);

    *report_size = (uint16_t)total_size;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "tdisp: loaded DEVICE_INTERFACE_REPORT from '%s' (%zu mmio ranges, %zu bytes)\n",
                  json_file, mmio_range_count, total_size));
    ret = true;

out:
    json_decref(root);
    return ret;
}
