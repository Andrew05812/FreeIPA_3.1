/* decode_pac.c - Extract PAC from service ticket and show Extra SIDs
 * Compile: gcc -o decode_pac decode_pac.c -lkrb5
 * Usage:   kinit testuser && kvno host/ipa.example.com && ./decode_pac
 */
#include <krb5.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define KRB5_AUTHDATA_WIN2K_PAC 128
#define KRB5_AUTHDATA_IF_RELEVANT 1

static void write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
        printf("  Written %zu bytes to %s\n", len, path);
    } else {
        fprintf(stderr, "  Failed to write %s\n", path);
    }
}

static void dump_pac_extra_sids(const uint8_t *data, size_t len) {
    if (len < 8) return;
    uint32_t version = *(uint32_t *)data;
    uint32_t count   = *(uint32_t *)(data + 4);
    printf("  PAC version=%u, buffers=%u\n", version, count);

    for (uint32_t i = 0; i < count; i++) {
        size_t off = 8 + i * 16;
        if (off + 16 > len) break;
        uint32_t btype   = *(uint32_t *)(data + off);
        uint32_t bsize   = *(uint32_t *)(data + off + 4);
        uint32_t boff    = *(uint32_t *)(data + off + 8);
        printf("  Buffer[%u]: type=%u, size=%u, offset=%u", i, btype, bsize, boff);

        if (btype == 1) {
            printf(" (LOGON_INFO - contains Extra SIDs)\n");
            write_file("/tmp/pac_logon_info.bin", data + boff, bsize);
            printf("  Run: ndrdump krb5pac PAC_LOGON_INFO in /tmp/pac_logon_info.bin\n");
        } else {
            printf("\n");
        }
    }

    write_file("/tmp/pac_full.bin", data, len);
    printf("  Full PAC: ndrdump krb5pac PAC_DATA in /tmp/pac_full.bin\n");
}

int main(int argc, char *argv[]) {
    krb5_context ctx = NULL;
    krb5_ccache ccache = NULL;
    krb5_creds mcreds, *creds = NULL;
    krb5_keytab kt = NULL;
    krb5_keytab_entry kt_entry;
    krb5_ticket *ticket = NULL;
    krb5_error_code ret;
    int found_pac = 0;
    const char *svc = "host/ipa.example.com@EXAMPLE.COM";

    memset(&kt_entry, 0, sizeof(kt_entry));
    memset(&mcreds, 0, sizeof(mcreds));

    ret = krb5_init_context(&ctx);
    if (ret) { fprintf(stderr, "krb5_init_context failed\n"); return 1; }

    ret = krb5_cc_default(ctx, &ccache);
    if (ret) { fprintf(stderr, "No ccache. Run: kinit testuser\n"); goto done; }

    ret = krb5_parse_name(ctx, svc, &mcreds.server);
    if (ret) goto done;

    ret = krb5_cc_retrieve_cred(ctx, ccache, 0, &mcreds, &creds);
    if (ret) {
        fprintf(stderr, "No service ticket for %s. Run: kvno %s\n", svc, svc);
        goto done;
    }

    ret = krb5_kt_default(ctx, &kt);
    if (ret) { fprintf(stderr, "No keytab\n"); goto done; }

    ret = krb5_kt_get_entry(ctx, kt, mcreds.server, 0, 0, &kt_entry);
    if (ret) {
        fprintf(stderr, "No keytab entry for %s\n", svc);
        goto done;
    }

    ret = decode_krb5_ticket(&creds->ticket, &ticket);
    if (ret) { fprintf(stderr, "decode_krb5_ticket failed: %d\n", ret); goto done; }

    ret = krb5_decrypt_tkt_part(ctx, &kt_entry.key, ticket);
    if (ret) { fprintf(stderr, "decrypt_tkt_part failed: %d\n", ret); goto done; }

    if (!ticket->enc_part2 || !ticket->enc_part2->authorization_data) {
        fprintf(stderr, "No authorization data in ticket\n");
        goto done;
    }

    printf("Authorization data in service ticket for %s:\n", svc);
    krb5_authdata **ad;
    for (ad = ticket->enc_part2->authorization_data; *ad; ad++) {
        printf("  ad_type=%d, length=%lu\n", (*ad)->ad_type, (unsigned long)(*ad)->length);

        if ((*ad)->ad_type == KRB5_AUTHDATA_IF_RELEVANT) {
            krb5_authdata **inner = NULL;
            krb5_data d;
            d.data = (char *)(*ad)->contents;
            d.length = (*ad)->length;
            ret = decode_krb5_authdata(&d, &inner);
            if (ret) {
                printf("  (failed to decode IF_RELEVANT: %d)\n", ret);
                continue;
            }
            for (int j = 0; inner[j]; j++) {
                printf("    inner ad_type=%d, length=%lu\n", inner[j]->ad_type, (unsigned long)inner[j]->length);
                if (inner[j]->ad_type == KRB5_AUTHDATA_WIN2K_PAC) {
                    printf("    *** PAC FOUND ***\n");
                    dump_pac_extra_sids(inner[j]->contents, inner[j]->length);
                    found_pac = 1;
                }
            }
            krb5_free_authdata(ctx, inner);
        }

        if ((*ad)->ad_type == KRB5_AUTHDATA_WIN2K_PAC) {
            printf("  *** PAC FOUND (direct) ***\n");
            dump_pac_extra_sids((*ad)->contents, (*ad)->length);
            found_pac = 1;
        }
    }

    if (!found_pac) {
        printf("No PAC found in ticket\n");
    }

done:
    if (ticket) krb5_free_ticket(ctx, ticket);
    if (creds) krb5_free_creds(ctx, creds);
    krb5_kt_free_entry(ctx, &kt_entry);
    if (kt) krb5_kt_close(ctx, kt);
    if (ccache) krb5_cc_close(ctx, ccache);
    if (mcreds.server) krb5_free_principal(ctx, mcreds.server);
    if (ctx) krb5_free_context(ctx);
    return found_pac ? 0 : 1;
}
