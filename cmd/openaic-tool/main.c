/*
 * SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
 * SPDX-License-Identifier: Apache-2.0
 *
 * openaic-tool — CLI around AIC: parse/print/verify.
 *
 * Links against the patched OpenSSL 3.5 LTS build, libopenaic and cJSON.
 *
 *   openaic-tool print  <cert.pem>
 *   openaic-tool verify <agent.pem> --user <principal.pem> [--require] [--replay]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "openaic.h"
#include "v3_aic.h"
#include "aic_verify.h"

static X509 *load_cert(const char *path)
{
    FILE *fp = fopen(path, "rb");
    X509 *x;
    if (fp == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        return NULL;
    }
    x = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (x == NULL)
        fprintf(stderr, "cannot parse cert %s\n", path);
    return x;
}

static void print_principal_uid(const AIC_PRINCIPALUID *pu)
{
    char *s = AIC_principalUid_to_string(pu);
    printf("  principalUid: %s\n", s != NULL ? s : "(invalid)");
    free(s);
}

static void print_capabilities(const char *label, STACK_OF(AIC_CAPABILITY) *st)
{
    int i, n = st == NULL ? 0 : sk_AIC_CAPABILITY_num(st);
    for (i = 0; i < n; i++) {
        AIC_CAPABILITY *c = sk_AIC_CAPABILITY_value(st, i);
        printf("  %s: ", label);
        if (c->schemeId != NULL)
            printf("%.*s:", ASN1_STRING_length(c->schemeId),
                   ASN1_STRING_get0_data(c->schemeId));
        if (c->capabilityId != NULL)
            printf("%.*s", ASN1_STRING_length(c->capabilityId),
                   ASN1_STRING_get0_data(c->capabilityId));
        if (c->parameters != NULL) {
            char *json = openaic_params_pretty(c->parameters->data,
                                               c->parameters->length);
            if (json != NULL) {
                printf(" params=%s", json);
                free(json);
            } else {
                printf(" params=<non-json %d bytes>", c->parameters->length);
            }
        }
        printf("\n");
    }
}

static int cmd_print(int argc, char **argv)
{
    X509 *cert;
    AIC *aic;
    const AIC_DELEGATIONAUTH *da;
    int crit = 0;

    if (argc < 1) {
        fprintf(stderr, "usage: openaic-tool print <cert.pem>\n");
        return 2;
    }
    cert = load_cert(argv[0]);
    if (cert == NULL)
        return 1;

    aic = X509_get_ext_d2i(cert, NID_AIC, &crit, NULL);
    if (aic == NULL) {
        printf("certificate has no AIC extension\n");
        X509_free(cert);
        return 0;
    }
    if (AIC_validate(aic, NULL) != 1)
        printf("AIC: WARNING: fails spec validation\n");

    printf("AIC extension (critical=%d):\n", crit);
    printf("  version: %ld\n",
           aic->version != NULL ? ASN1_INTEGER_get(aic->version) : -1);
    if (aic->agentId != NULL)
        printf("  agentId: %.*s\n", ASN1_STRING_length(aic->agentId),
               ASN1_STRING_get0_data(aic->agentId));
    print_principal_uid(aic->principalUid);
    print_capabilities("capability", aic->capabilities);
    print_capabilities("authorizationConstraint", aic->authorizationConstraints);

    da = aic->delegationAuthorization;
    if (da != NULL) {
        printf("  delegationAuthorization:\n");
        if (da->reason != NULL && da->reason->reasonCode != NULL)
            printf("    reasonCode: %.*s\n",
                   ASN1_STRING_length(da->reason->reasonCode),
                   ASN1_STRING_get0_data(da->reason->reasonCode));
        if (da->requestedLifetime != NULL)
            printf("    requestedLifetime: %ld\n",
                   ASN1_INTEGER_get(da->requestedLifetime));
        if (da->timestamp != NULL)
            printf("    timestamp: %.*s\n",
                   ASN1_STRING_length(da->timestamp),
                   ASN1_STRING_get0_data(da->timestamp));
        if (da->nonce != NULL)
            printf("    nonce (%d bytes)\n", ASN1_STRING_length(da->nonce));
        if (da->signatureValue != NULL)
            printf("    signatureValue (%d bytes)\n",
                   ASN1_STRING_length(da->signatureValue));
    }
    AIC_free(aic);
    X509_free(cert);
    return 0;
}

static void print_verify_usage(void)
{
    fprintf(stderr,
        "usage: openaic-tool verify <agent.pem> [options]\n"
        "options:\n"
        "  --user <principal.pem>   principal cert whose SPKI signed the DA\n"
        "                           (repeatable; at least one needed for --verify-da)\n"
        "  --check-spki             require principalUid.keyHash == SPKI(principal) [default]\n"
        "  --no-check-spki          skip the keyHash cross-check\n"
        "  --verify-da              verify the DelegationAuthorization signature [default]\n"
        "  --no-verify-da           skip DA signature verification\n"
        "  --require                fail if the cert lacks an AIC extension\n"
        "  --no-require             tolerate missing AIC (return success, print 'absent')\n"
        "  --replay                 anti-replay: reject reused nonces (stateful)\n");
}

static int cmd_verify(int argc, char **argv)
{
    X509 *agent = NULL, *user = NULL;
    STACK_OF(X509) *untrusted = NULL;
    AIC_VERIFY_OPTS opts;
    int rc, i, error = 0;

    if (argc < 1) {
        print_verify_usage();
        return 2;
    }
    agent = load_cert(argv[0]);
    if (agent == NULL)
        return 1;

    memset(&opts, 0, sizeof(opts));
    opts.flags = AIC_VERIFY_CHECK_SPKI | AIC_VERIFY_VERIFY_DA;
    for (i = 1; i < argc && !error; i++) {
        if (strcmp(argv[i], "--user") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "error: --user needs a cert path\n");
                error = 1;
                break;
            }
            user = load_cert(argv[++i]);
            if (user == NULL) {
                error = 1;
                break;
            }
            if (untrusted == NULL) {
                untrusted = sk_X509_new_null();
                if (untrusted == NULL)
                    error = 1;
            }
            if (!error && sk_X509_push(untrusted, user) <= 0)
                error = 1;
        } else if (strcmp(argv[i], "--check-spki") == 0) {
            opts.flags |= AIC_VERIFY_CHECK_SPKI;
        } else if (strcmp(argv[i], "--no-check-spki") == 0) {
            opts.flags &= ~AIC_VERIFY_CHECK_SPKI;
        } else if (strcmp(argv[i], "--verify-da") == 0) {
            opts.flags |= AIC_VERIFY_VERIFY_DA;
        } else if (strcmp(argv[i], "--no-verify-da") == 0) {
            opts.flags &= ~AIC_VERIFY_VERIFY_DA;
        } else if (strcmp(argv[i], "--require") == 0) {
            opts.flags |= AIC_VERIFY_REQUIRE;
        } else if (strcmp(argv[i], "--no-require") == 0) {
            opts.flags &= ~AIC_VERIFY_REQUIRE;
        } else if (strcmp(argv[i], "--replay") == 0) {
            opts.flags |= AIC_VERIFY_REPLAY;
            if (opts.replay == NULL)
                opts.replay = AIC_replay_new();
        } else {
            fprintf(stderr, "error: unknown option: %s\n", argv[i]);
            error = 1;
        }
    }
    if (error) {
        AIC_replay_free(opts.replay);
        sk_X509_pop_free(untrusted, X509_free);
        X509_free(agent);
        print_verify_usage();
        return 2;
    }

    rc = AIC_verify_cert(agent, untrusted, &opts);
    if (rc == 1)
        printf("AIC verified OK\n");
    else if (rc == 0)
        printf("AIC verification FAILED\n");
    else
        printf("certificate has no AIC extension (not required)\n");

    AIC_replay_free(opts.replay);
    sk_X509_pop_free(untrusted, X509_free);
    X509_free(agent);
    return rc == 1 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: openaic-tool <print|verify> ...\n");
        return 2;
    }
    if (strcmp(argv[1], "print") == 0)
        return cmd_print(argc - 2, argv + 2);
    if (strcmp(argv[1], "verify") == 0)
        return cmd_verify(argc - 2, argv + 2);
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}
