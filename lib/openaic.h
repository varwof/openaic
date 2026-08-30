/*
 * SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
 * SPDX-License-Identifier: Apache-2.0
 *
 * openaic.h — auxiliary layer (OUTSIDE libcrypto). Builds on cJSON for the
 * JSON handling of AIC Capability.parameters and constraint validation that
 * the libcrypto patch intentionally leaves opaque.
 *
 * This file has NO OpenSSL dependency, so it can be unit-tested standalone
 * (test/openaic_json_test.c).
 */

#ifndef LIB_OPENAIC_H
# define LIB_OPENAIC_H

# include <stddef.h>
# include <cJSON.h>

# ifdef __cplusplus
extern "C" {
# endif

/* schemeId values for authorization constraints (spec v1.7.1). */
# define OPENAIC_CONSTRAINT_SCHEME      "constraint"
# define OPENAIC_CONSTRAINT_SCHEME_V1   "constraint-v1"

/* max-concurrent constraint: capabilityId and JSON parameter shape {"max":N}. */
# define OPENAIC_CAP_MAX_CONCURRENT     "max-concurrent"
# define OPENAIC_MAX_CONCURRENT_MIN     1
# define OPENAIC_MAX_CONCURRENT_MAX     1024

/*
 * Parse `params` as JSON. On success return a new cJSON object (caller frees
 * with cJSON_Delete). On failure return NULL. Bytes are NOT required to be
 * NUL-terminated (n is the exact length).
 */
cJSON *openaic_params_parse(const unsigned char *params, size_t n);

/*
 * Canonicalize: parse+re-serialize (minified) into a NUL-terminated string.
 * Returns NULL if params is not valid JSON. Caller frees with cJSON_free().
 */
char *openaic_params_canonical(const unsigned char *params, size_t n);

/* Pretty-print params as JSON (2-space indent). NULL if not JSON. */
char *openaic_params_pretty(const unsigned char *params, size_t n);

/*
 * Build parameters bytes from a JSON object (minified, exact length in
 * *outlen). Caller frees with OPENSSL-equivalent free (cJSON_free).
 */
unsigned char *openaic_params_from_json(const cJSON *obj, size_t *outlen);

/*
 * Validate the max-concurrent constraint parameters: JSON object {"max": N}
 * with N in [1,1024]. Returns 1 valid, 0 invalid.
 */
int openaic_validate_max_concurrent(const unsigned char *params, size_t n);

/*
 * Dispatch parameter validation by capabilityId. Currently only
 * max-concurrent is specified; unknown capabilityIds with non-empty params
 * are rejected (fail-closed). Returns 1 valid, 0 invalid.
 */
int openaic_validate_capability_params(const char *capabilityId,
                                       const unsigned char *params, size_t n);

/*
 * Validate a whole capability's constraint scheme (authorization constraint
 * entries must use schemeId constraint/constraint-v1). Returns 1 ok, 0 bad.
 */
int openaic_validate_constraint_scheme(const char *schemeId);

# ifdef __cplusplus
}
# endif

#endif
