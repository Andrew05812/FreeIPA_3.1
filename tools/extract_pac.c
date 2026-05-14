/* extract_pac.c — Extract PAC from Kerberos credential cache
 * Compile: gcc -o extract_pac extract_pac.c -lkrb5
 * Usage:   kinit testuser && kvno host/$(hostname -f) && ./extract_pac
 * Then:    ndrdump krb5pac PAC_DATA in /tmp/pac_extracted.bin
 */
#include <krb5.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void save_pac(const krb5_octet *data, unsigned int len) {
    FILE *f = fopen("/tmp/pac_extracted.bin", "wb");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
        printf("  Written %u bytes to /tmp/pac_extracted.bin\n", len);
        printf("  Run: ndrdump krb5pac PAC_DATA in /tmp/pac_extracted.bin\n");
    }
}

static int parse_der_length(const unsigned char *d, unsigned int *pos, unsigned int len) {
    if (*pos >= len) return -1;
    if (!(d[*pos] & 0x80)) return d[(*pos)++];
    int n = d[(*pos)++] & 0x7f;
    unsigned int val = 0;
    for (int i = 0; i < n && *pos < len; i++)
        val = (val << 8) | d[(*pos)++];
    return (int)val;
}

static int find_pac_in_if_relevant(const krb5_octet *data, unsigned int len) {
    unsigned int pos = 0;
    if (pos >= len || data[pos++] != 0x30) return 0;
    parse_der_length(data, &pos, len);

    while (pos + 6 < len) {
        if (data[pos] != 0x30) break;
        pos++;
        int seq_len = parse_der_length(data, &pos, len);
        if (seq_len < 0) break;
        unsigned int seq_end = pos + (unsigned int)seq_len;

        if (pos >= len || data[pos++] != 0xA0) break;
        parse_der_length(data, &pos, len);
        if (pos >= len || data[pos++] != 0x02) break;
        int int_len = data[pos++];
        int ad_type = 0;
        for (int j = 0; j < int_len && pos < len; j++)
            ad_type = (ad_type << 8) | data[pos++];

        if (pos >= len || data[pos++] != 0xA1) break;
        parse_der_length(data, &pos, len);
        if (pos >= len || data[pos++] != 0x04) break;
        int data_len = parse_der_length(data, &pos, len);
        if (data_len < 0) break;

        if (ad_type == 128) {
            printf("  *** PAC FOUND (inside IF_RELEVANT)! ***\n");
            save_pac(data + pos, (unsigned int)data_len);
            return 1;
        }
        pos = seq_end;
    }
    return 0;
}

int main() {
    krb5_context ctx = NULL;
    krb5_ccache ccache = NULL;
    krb5_cc_cursor cursor;
    krb5_creds creds;
    krb5_error_code ret;
    int found = 0;

    ret = krb5_init_context(&ctx);
    if (ret) { fprintf(stderr, "krb5_init_context failed\n"); return 1; }

    ret = krb5_cc_default(ctx, &ccache);
    if (ret) { fprintf(stderr, "No ccache. Run: kinit testuser\n"); goto done; }

    ret = krb5_cc_start_seq_get(ctx, ccache, &cursor);
    if (ret) { fprintf(stderr, "cc_start_seq_get failed\n"); goto done; }

    printf("Scanning credential cache for PAC...\n\n");

    while ((ret = krb5_cc_next_cred(ctx, ccache, &cursor, &creds)) == 0) {
        char *name = NULL;
        krb5_unparse_name(ctx, creds.server, &name);
        printf("Ticket: %s\n", name);

        if (creds.authdata) {
            int i;
            for (i = 0; creds.authdata[i]; i++) {
                printf("  authdata[%d]: type=%d, length=%u\n", i,
                       creds.authdata[i]->ad_type, creds.authdata[i]->length);

                if (creds.authdata[i]->ad_type == 128) {
                    printf("  *** PAC FOUND! ***\n");
                    save_pac(creds.authdata[i]->contents, creds.authdata[i]->length);
                    found = 1;
                } else if (creds.authdata[i]->ad_type == 1) {
                    printf("  (IF_RELEVANT - checking inside)\n");
                    if (find_pac_in_if_relevant(creds.authdata[i]->contents,
                                                creds.authdata[i]->length))
                        found = 1;
                }
            }
            printf("  Total authdata entries: %d\n", i);
        } else {
            printf("  No authdata in this ticket\n");
        }

        krb5_free_unparsed_name(ctx, name);
        krb5_free_cred_contents(ctx, &creds);
    }

    krb5_cc_end_seq_get(ctx, ccache, &cursor);

    if (!found) {
        printf("\nNo PAC in authdata. PAC is in the ticket's encrypted part.\n");
        printf("The KDC log proves the PAC is there:\n");
        printf("  grep trust-level /var/log/krb5kdc.log | tail -1\n");
    }

done:
    if (ccache) krb5_cc_close(ctx, ccache);
    krb5_free_context(ctx);
    return found ? 0 : 1;
}
