/*
 * SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
 * SPDX-License-Identifier: Apache-2.0
 *
 * openaic_json_test.c — standalone unit test for libopenaic (no OpenSSL).
 *   cc -o openaic_json_test openaic_json_test.c ../lib/openaic.c ../lib/cjson/cJSON.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openaic.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); failures++; } \
    else { printf("ok:   %s\n", msg); } \
} while (0)

static void test_canonical(void)
{
    const unsigned char in[] = "{\"max\": 3}";
    char *out = openaic_params_canonical(in, sizeof(in) - 1);
    CHECK(out != NULL && strcmp(out, "{\"max\":3}") == 0, "canonical minified");
    free(out);

    out = openaic_params_canonical((const unsigned char *)"not json", 8);
    CHECK(out == NULL, "non-json params rejected");
}

static void test_pretty(void)
{
    const unsigned char in[] = "{\"max\":2}";
    char *out = openaic_params_pretty(in, sizeof(in) - 1);
    CHECK(out != NULL && strstr(out, "\"max\"") != NULL, "pretty contains key");
    free(out);
}

static void test_max_concurrent(void)
{
    CHECK(openaic_validate_max_concurrent((const unsigned char *)"{\"max\":1}", 9) == 1,
          "max=1 valid");
    CHECK(openaic_validate_max_concurrent((const unsigned char *)"{\"max\":1024}", 12) == 1,
          "max=1024 valid");
    CHECK(openaic_validate_max_concurrent((const unsigned char *)"{\"max\":0}", 8) == 0,
          "max=0 invalid");
    CHECK(openaic_validate_max_concurrent((const unsigned char *)"{\"max\":1025}", 11) == 0,
          "max=1025 invalid");
    CHECK(openaic_validate_max_concurrent((const unsigned char *)"{\"max\":2.5}", 9) == 0,
          "non-integral invalid");
    CHECK(openaic_validate_max_concurrent((const unsigned char *)"{\"nope\":2}", 9) == 0,
          "missing max key invalid");
    CHECK(openaic_validate_max_concurrent((const unsigned char *)"garbage", 7) == 0,
          "invalid json invalid");
}

static void test_dispatch(void)
{
    CHECK(openaic_validate_capability_params("max-concurrent",
          (const unsigned char *)"{\"max\":4}", 9) == 1, "dispatch max-concurrent");
    CHECK(openaic_validate_capability_params("max-concurrent",
          (const unsigned char *)"{\"max\":0}", 8) == 0, "dispatch bad max");
    CHECK(openaic_validate_capability_params("unknown-cap",
          (const unsigned char *)"{\"a\":1}", 7) == 0, "unknown cap with params fail-closed");
    CHECK(openaic_validate_capability_params("any-cap", NULL, 0) == 1,
          "empty params acceptable");
}

static void test_constraint_scheme(void)
{
    CHECK(openaic_validate_constraint_scheme("constraint") == 1, "scheme constraint");
    CHECK(openaic_validate_constraint_scheme("constraint-v1") == 1, "scheme constraint-v1");
    CHECK(openaic_validate_constraint_scheme("tt") == 0, "scheme tt rejected");
    CHECK(openaic_validate_constraint_scheme(NULL) == 0, "NULL scheme rejected");
}

static void test_params_from_json(void)
{
    cJSON *obj = cJSON_CreateObject();
    size_t len = 0;
    unsigned char *bytes;
    cJSON_AddNumberToObject(obj, "max", 5);
    bytes = openaic_params_from_json(obj, &len);
    CHECK(bytes != NULL && len == (size_t)strlen((char *)bytes) && strcmp((char *)bytes, "{\"max\":5}") == 0,
          "params from json round-trips");
    free(bytes);
    cJSON_Delete(obj);
}

int main(void)
{
    test_canonical();
    test_pretty();
    test_max_concurrent();
    test_dispatch();
    test_constraint_scheme();
    test_params_from_json();
    printf("%s: %d failure(s)\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
