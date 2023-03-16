/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_responder.h"

void __stack_chk_guard (void)
{
}

void __stack_chk_fail (void)
{
}

#if !defined(_MSC_EXTENSIONS)

#if !defined(__ARMCOMPILER_VERSION) // to exclude armclang

void *
memcpy (void *dst_buf, const void *src_buf, size_t len)
{
    libspdm_copy_mem(dst_buf, len, src_buf, len);
    return dst_buf;
}

/* Sets buffers to a specified character */
void *memset(void *dest, int ch, size_t count)
{

    /* NOTE: Here we use one base implementation for memset, instead of the direct
     *       optimized libspdm_set_mem() wrapper. Because the intrinsiclib has to be built
     *       without whole program optimization option, and there will be some
     *       potential register usage errors when calling other optimized codes.*/



    /* Declare the local variables that actually move the data elements as
     * volatile to prevent the optimizer from replacing this function with
     * the intrinsic memset()*/

    volatile uint8_t *pointer;

    pointer = (uint8_t *)dest;
    while (count-- != 0) {
        *(pointer++) = (uint8_t)ch;
    }

    return dest;
}

void *memmove(void *dest, const void *src, size_t count)
{
    libspdm_copy_mem(dest, count, src, count);
    return dest;
}

/* Compare bytes in two buffers. */
int memcmp(const void *buf1, const void *buf2, size_t count)
{
    return (int)(libspdm_consttime_is_mem_equal(buf1, buf2, count) ? 0 : 1);
}

int ascii_strcmp(const char *first_string, const char *second_string)
{
    while ((*first_string != '\0') && (*first_string == *second_string)) {
        first_string++;
        second_string++;
    }

    return *first_string - *second_string;
}

int ascii_strncmp(const char *first_string, const char *second_string, size_t length)
{
    if (length == 0) {
        return 0;
    }
    while ((*first_string != '\0') && (*first_string != '\0')  &&
           (*first_string == *second_string) && (length > 1)) {
        first_string++;
        second_string++;
        length--;
    }

    return *first_string - *second_string;
}

int strcmp(const char *s1, const char *s2)
{
    return (int)ascii_strcmp(s1, s2);
}

size_t ascii_strlen(const char *string)
{
    size_t length;

    if (string == NULL) {
        return 0;
    }
    for (length = 0; *string != '\0'; string++, length++) {
    }
    return length;
}

unsigned int strlen(char *s)
{
    return (unsigned int)ascii_strlen(s);
}

char *ascii_strstr(char *string, const char *search_string)
{
    char *first_match;
    const char *search_string_tmp;

    if (*search_string == '\0') {
        return string;
    }

    while (*string != '\0') {
        search_string_tmp = search_string;
        first_match = string;

        while ((*string == *search_string_tmp) && (*string != '\0')) {
            string++;
            search_string_tmp++;
        }

        if (*search_string_tmp == '\0') {
            return first_match;
        }

        if (*string == '\0') {
            return NULL;
        }

        string = first_match + 1;
    }

    return NULL;
}

char *strstr(char *str1, const char *str2)
{
    return ascii_strstr(str1, str2);
}

const void * memscan ( const void * ptr, int value, size_t num )
{
  const char  *p;

  p = (const char *)ptr;
  do {
    if (*p == value) {
      return (const void *)p;
    }
    ++p;
  } while (--num != 0);

  return NULL;
}

const void * memchr ( const void * ptr, int value, size_t num )
{
    return memscan (ptr, value, num);
}

const char * strchr ( const char * str, int ch )
{
    return memscan (str, (int)ascii_strlen(str) + 1, ch);
}

int strncmp ( const char * str1, const char * str2, size_t num )
{
    return (int)ascii_strncmp(str1, str2, num);
}

#endif //#if !defined(__ARMCOMPILER_VERSION)
#endif //#if !defined(_MSC_EXTENSIONS)