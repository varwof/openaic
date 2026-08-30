/*
 * SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
 * SPDX-License-Identifier: Apache-2.0
 *
 * openaic.c — auxiliary JSON layer for AIC capability parameters.
 */

#include <stdlib.h>
#include <string.h>

#include "openaic.h"

cJSON *openaic_params_parse(const unsigned char *params, size_t n)
{
    cJSON *root;
    char *buf;

    if (params == NULL || n == 0)
        return NULL;
    buf = (char *)cJSON_malloc(n + 1);
    if (buf == NULL)
        return NULL;
    memcpy(buf, params, n);
    buf[n] = '\0';
    root = cJSON_ParseWithLength(buf, n);
    cJSON_free(buf);
    return root;
}

char *openaic_params_canonical(const unsigned char *params, size_t n)
{
    cJSON *root = openaic_params_parse(params, n);
    char *out;

    if (root == NULL)
        return NULL;
    out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

char *openaic_params_pretty(const unsigned char *params, size_t n)
{
    cJSON *root = openaic_params_parse(params, n);
    char *out;

    if (root == NULL)
        return NULL;
    out = cJSON_Print(root);
    cJSON_Delete(root);
    return out;
}

unsigned char *openaic_params_from_json(const cJSON *obj, size_t *outlen)
{
    char *s;
    unsigned char *bytes;
    size_t len;

    if (obj == NULL || outlen == NULL)
        return NULL;
    s = cJSON_PrintUnformatted(obj);
    if (s == NULL)
        return NULL;
    len = strlen(s);
    bytes = (unsigned char *)cJSON_malloc(len + 1);
    if (bytes == NULL) {
        cJSON_free(s);
        return NULL;
    }
    memcpy(bytes, s, len);
    bytes[len] = '\0';
    *outlen = len;
    cJSON_free(s);
    return bytes;
}

int openaic_validate_max_concurrent(const unsigned char *params, size_t n)
{
    cJSON *root = openaic_params_parse(params, n);
    cJSON *max;
    double v;

    if (root == NULL)
        return 0;
    max = cJSON_GetObjectItemCaseSensitive(root, "max");
    if (max == NULL || !cJSON_IsNumber(max)) {
        cJSON_Delete(root);
        return 0;
    }
    v = max->valuedouble;
    cJSON_Delete(root);
    if (v < OPENAIC_MAX_CONCURRENT_MIN || v > OPENAIC_MAX_CONCURRENT_MAX)
        return 0;
    if (v != (double)(int)v)
        return 0;  /* must be integral */
    return 1;
}

int openaic_validate_capability_params(const char *capabilityId,
                                       const unsigned char *params, size_t n)
{
    if (params == NULL || n == 0)
        return 1;  /* empty params always acceptable */

    if (capabilityId != NULL
        && strcmp(capabilityId, OPENAIC_CAP_MAX_CONCURRENT) == 0)
        return openaic_validate_max_concurrent(params, n);

    /* Fail-closed: parameters without a known validator are rejected. */
    return 0;
}

int openaic_validate_constraint_scheme(const char *schemeId)
{
    return schemeId != NULL
        && (strcmp(schemeId, OPENAIC_CONSTRAINT_SCHEME) == 0
            || strcmp(schemeId, OPENAIC_CONSTRAINT_SCHEME_V1) == 0);
}
