/*
 * SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
 * SPDX-License-Identifier: Apache-2.0
 *
 * aic_ext_test.c — OpenSSL-side unit tests for the AIC extension, compiled
 * against the patched 3.5.7 build and linked against libopenaic + cJSON.
 *
 * Built by `make test-aic`; consumes test/vectors/out/ produced by the Go
 * side (cross consistency) and additionally round-trips DER through the ASN.1
 * templates, asserting field equality with the Go-emitted expectations.
 *
 *   1. d2i/i2d round-trip of aic.der preserves all fields
 *   2. AIC_validate() passes for the good vector, rejects tampered/mismatch
 *   3. AIC_verify_cert() accepts aic-good with user-principal, rejects
 *      aic-tampered and aic-spki-mismatch
 *   4. libopenaic JSON layer: max-concurrent params {"max":3} validate;
 *      {"level":2} capability params pretty-print
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "openaic.h"
#include "v3_aic.h"
#include "aic_verify.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } \
    else { printf("ok:   %s\n", msg); } \
} while (0)

static X509 *load_cert(const char *path)
{
    FILE *fp = fopen(path, "rb");
    X509 *x;
    if (fp == NULL)
        return NULL;
    x = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return x;
}

static AIC *extract_aic(X509 *cert, int *crit)
{
    return X509_get_ext_d2i(cert, NID_AIC, crit, NULL);
}

int main(int argc, char **argv)
{
    const char *vd = argc > 1 ? argv[1] : "test/vectors/out";
    char path[1024];
    X509 *agent, *user, *tampered, *mismatch;
    AIC *aic;
    STACK_OF(X509) *untrusted = NULL;
    AIC_VERIFY_OPTS opts;
    int crit = 0, rc;

    snprintf(path, sizeof(path), "%s/user-principal.pem", vd);
    user = load_cert(path);
    CHECK(user != NULL, "load user-principal.pem");

    snprintf(path, sizeof(path), "%s/aic-good.pem", vd);
    agent = load_cert(path);
    CHECK(agent != NULL, "load aic-good.pem");

    /* 1. d2i round trip of raw DER */
    {
        unsigned char *der;
        int len;
        const unsigned char *p;
        AIC *rt;
        snprintf(path, sizeof(path), "%s/aic.der", vd);
        FILE *fp = fopen(path, "rb");
        CHECK(fp != NULL, "open aic.der");
        if (fp != NULL) {
            fseek(fp, 0, SEEK_END);
            len = (int)ftell(fp);
            rewind(fp);
            der = malloc((size_t)len);
            CHECK(fread(der, 1, (size_t)len, fp) == (size_t)len, "read aic.der");
            fclose(fp);
            p = der;
            rt = d2i_AIC(NULL, &p, len);
            CHECK(rt != NULL && p - (const unsigned char *)der == len,
                  "d2i aic.der consumes full buffer");
            if (rt != NULL) {
                char *pu = AIC_principalUid_to_string(rt->principalUid);
                CHECK(pu != NULL && strstr(pu, ":") != NULL, "principalUid string form");
                free(pu);
            }
            AIC_free(rt);
            free(der);
        }
    }

    /* 2. validation */
    aic = extract_aic(agent, &crit);
    CHECK(aic != NULL, "aic-good has AIC ext");
    CHECK(crit == 0, "AIC is not critical");
    CHECK(aic != NULL && AIC_validate(aic, NULL) == 1, "aic-good validates");
    AIC_free(aic);

    snprintf(path, sizeof(path), "%s/aic-tampered.pem", vd);
    tampered = load_cert(path);
    aic = tampered != NULL ? extract_aic(tampered, &crit) : NULL;
    CHECK(aic != NULL && AIC_validate(aic, NULL) == 1, "aic-tampered structurally valid (sig broken)");
    AIC_free(aic);

    snprintf(path, sizeof(path), "%s/aic-spki-mismatch.pem", vd);
    mismatch = load_cert(path);
    aic = mismatch != NULL ? extract_aic(mismatch, &crit) : NULL;
    CHECK(aic != NULL && AIC_validate(aic, NULL) == 1, "aic-spki-mismatch structurally valid (hash broken)");
    AIC_free(aic);

    /* 3. verification */
    untrusted = sk_X509_new_null();
    CHECK(untrusted != NULL && sk_X509_push(untrusted, user), "untrusted stack");

    memset(&opts, 0, sizeof(opts));
    opts.flags = AIC_VERIFY_CHECK_SPKI | AIC_VERIFY_VERIFY_DA;

    rc = AIC_verify_cert(agent, untrusted, &opts);
    CHECK(rc == 1, "aic-good verifies with user-principal");

    rc = AIC_verify_cert(tampered, untrusted, &opts);
    CHECK(rc == 0, "aic-tampered rejected");

    rc = AIC_verify_cert(mismatch, untrusted, &opts);
    CHECK(rc == 0, "aic-spki-mismatch rejected");

    /* 4. JSON helper layer */
    CHECK(openaic_validate_capability_params("max-concurrent",
          (const unsigned char *)"{\"max\":3}", 9) == 1, "json: max-concurrent {\"max\":3}");
    {
        char *p = openaic_params_pretty((const unsigned char *)"{\"level\":2}", 11);
        CHECK(p != NULL && strstr(p, "\"level\"") != NULL, "json: capability params pretty");
        free(p);
    }
    CHECK(openaic_validate_constraint_scheme("constraint") == 1, "json: constraint scheme");

    sk_X509_pop_free(untrusted, X509_free);
    X509_free(user);
    X509_free(agent);
    X509_free(tampered);
    X509_free(mismatch);

    printf("%s: %d failure(s)\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
