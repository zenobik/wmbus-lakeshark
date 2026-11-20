/* Host tests for wmbus/wm_aes.c and wmbus/wm_proto.c.
 *   cc -std=c11 -Iwmbus tests/test_wmbus.c wmbus/wm_aes.c wmbus/wm_proto.c -o test_wmbus
 * Published vectors: FIPS-197 C.1, RFC 4493, NIST SP 800-38A F.2.2 / F.5.1,
 * CRC-16/EN-13757 check value. The telegram tests build a frame the way a
 * meter does (records, AES, CRC blocks, 3-of-6 / Manchester) and decode it. */
#include "wm_aes.h"
#include "wm_proto.h"
#include <stdio.h>
#include <string.h>

static int fails, checks;

#define CHECK(cond, ...)                                     \
    do {                                                     \
        checks++;                                            \
        if (!(cond)) {                                       \
            fails++;                                         \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);      \
            printf(__VA_ARGS__);                             \
            printf("\n");                                    \
        }                                                    \
    } while (0)

static void hex(const char *s, uint8_t *out, int n)
{
    const int got = wm_hex_parse(s, out, n);
    if (got != n) printf("bad hex in test: %s\n", s);
}

static void test_aes(void)
{
    uint8_t key[16], pt[16], ct[16], out[16];
    wm_aes_t a;
    hex("000102030405060708090a0b0c0d0e0f", key, 16);
    hex("00112233445566778899aabbccddeeff", pt, 16);
    hex("69c4e0d86a7b0430d8cdb78070b4c55a", ct, 16);
    wm_aes_init(&a, key);
    wm_aes_encrypt(&a, pt, out);
    CHECK(!memcmp(out, ct, 16), "FIPS-197 encrypt");
    wm_aes_decrypt(&a, ct, out);
    CHECK(!memcmp(out, pt, 16), "FIPS-197 decrypt");

    uint8_t k2[16], iv[16], buf[16], exp[16];
    hex("2b7e151628aed2a6abf7158809cf4f3c", k2, 16);
    hex("000102030405060708090a0b0c0d0e0f", iv, 16);
    hex("7649abac8119b246cee98e9b12e9197d", buf, 16);
    hex("6bc1bee22e409f96e93d7e117393172a", exp, 16);
    wm_aes_cbc_decrypt(k2, iv, buf, 16);
    CHECK(!memcmp(buf, exp, 16), "SP800-38A CBC decrypt");

    hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", iv, 16);
    hex("6bc1bee22e409f96e93d7e117393172a", buf, 16);
    hex("874d6191b620e3261bef6864990db6ce", exp, 16);
    wm_aes_ctr(k2, iv, buf, 16);
    CHECK(!memcmp(buf, exp, 16), "SP800-38A CTR");

    uint8_t mac[16], msg[40];
    wm_aes_cmac(k2, msg, 0, mac);
    hex("bb1d6929e95937287fa37d129b756746", exp, 16);
    CHECK(!memcmp(mac, exp, 16), "RFC4493 CMAC empty");
    hex("6bc1bee22e409f96e93d7e117393172a", msg, 16);
    wm_aes_cmac(k2, msg, 16, mac);
    hex("070a16b46b4d4144f79bdd9dd04a287c", exp, 16);
    CHECK(!memcmp(mac, exp, 16), "RFC4493 CMAC 16");
    hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", msg, 40);
    wm_aes_cmac(k2, msg, 40, mac);
    hex("dfa66747de9ae63030ca32611497c827", exp, 16);
    CHECK(!memcmp(mac, exp, 16), "RFC4493 CMAC 40");
}

static void test_crc(void)
{
    CHECK(wm_crc((const uint8_t *)"123456789", 9) == 0xC2B7, "CRC-16/EN-13757 check 0x%04X",
          wm_crc((const uint8_t *)"123456789", 9));
}

/* ---- a meter, in the test ---------------------------------------------------- */

static void cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], uint8_t *buf, size_t len)
{
    wm_aes_t a;
    wm_aes_init(&a, key);
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        for (int i = 0; i < 16; i++) buf[off + i] ^= prev[i];
        wm_aes_encrypt(&a, buf + off, buf + off);
        memcpy(prev, buf + off, 16);
    }
}

/* Plain frame (L first, no CRC) -> format A bytes on air. */
static size_t add_crc_a(const uint8_t *f, size_t n, uint8_t *out)
{
    size_t o = 0, i = 0;
    while (i < n) {
        const size_t blk = i == 0 ? 10 : (n - i > 16 ? 16 : n - i);
        memcpy(out + o, f + i, blk);
        const uint16_t c = wm_crc(f + i, blk);
        o += blk;
        out[o++] = (uint8_t)(c >> 8);
        out[o++] = (uint8_t)c;
        i += blk;
    }
    return o;
}

static size_t add_crc_b(uint8_t *f, size_t n, uint8_t *out)   /* n data bytes, <=126 */
{
    f[0] = (uint8_t)(n + 1);            /* L counts the CRC */
    memcpy(out, f, n);
    const uint16_t c = wm_crc(f, n);
    out[n] = (uint8_t)(c >> 8);
    out[n + 1] = (uint8_t)c;
    return n + 2;
}

static const uint8_t CODE36[16] = { 22, 13, 14, 11, 28, 25, 26, 19, 44, 37, 38, 35, 52, 49, 50, 41 };

static void put_bits(uint8_t *raw, size_t *bit, unsigned v, int n)
{
    for (int i = n - 1; i >= 0; i--, (*bit)++)
        if ((v >> i) & 1) raw[*bit >> 3] |= (uint8_t)(0x80 >> (*bit & 7));
}

static size_t enc36(const uint8_t *b, size_t n, uint8_t *raw, size_t cap)
{
    memset(raw, 0, cap);
    size_t bit = 0;
    for (size_t i = 0; i < n; i++) {
        put_bits(raw, &bit, CODE36[b[i] >> 4], 6);
        put_bits(raw, &bit, CODE36[b[i] & 15], 6);
    }
    return cap;                         /* the radio hands over a fixed 255 */
}

static size_t manchester(const uint8_t *b, size_t n, uint8_t *raw, size_t cap)
{
    memset(raw, 0x55, cap);
    size_t bit = 0;
    memset(raw, 0, n * 2);
    for (size_t i = 0; i < n; i++)
        for (int k = 7; k >= 0; k--) put_bits(raw, &bit, ((b[i] >> k) & 1) ? 2 : 1, 2);
    return cap;
}

static const uint8_t KEY[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
static const uint8_t *keyfn(uint32_t id, uint32_t link_id, void *ctx)
{
    (void)ctx;
    return id == 0x12345678 || link_id == 0x12345678 ? KEY : NULL;
}

/* Records: volume 12345.678 m3 (BCD8), date/time 2026-11-20 10:43,
   error flags 0, storage 1 date 2026-10-31, storage 1 volume int32 6.868 m3 */
static const char RECORDS[] = "0C1378563412" "046D2B0A543B" "02FD170000" "426C5F3A" "4413D41A0000";

static size_t build_plain(uint8_t *f, int ci, uint8_t acc, uint16_t cfg, const uint8_t *app, size_t applen)
{
    size_t n = 0;
    f[n++] = 0;                         /* L, set below */
    f[n++] = 0x44;                      /* SND_NR */
    f[n++] = 0x01; f[n++] = 0x06;       /* manufacturer "APA": (1<<10)|(16<<5)|1 = 0x0601 */
    f[n++] = 0x78; f[n++] = 0x56; f[n++] = 0x34; f[n++] = 0x12;   /* id 12345678 */
    f[n++] = 0x05;                      /* version */
    f[n++] = 0x07;                      /* water */
    f[n++] = (uint8_t)ci;
    if (ci == 0x7A) {
        f[n++] = acc;
        f[n++] = 0x00;
        f[n++] = (uint8_t)cfg;
        f[n++] = (uint8_t)(cfg >> 8);
    }
    memcpy(f + n, app, applen);
    n += applen;
    f[0] = (uint8_t)(n - 1);
    return n;
}

static void check_records(const wm_msg_t *m, const char *what)
{
    wm_rec_t r[16];
    bool bad = true;
    const int n = wm_records(m->buf + m->app_off, m->app_len, r, 16, &bad);
    CHECK(n == 5 && !bad, "%s: %d records, bad %d", what, n, bad);
    if (n < 5) return;
    CHECK(!strcmp(r[0].name, "Volume") && !strcmp(r[0].value, "12345.678 m3") && r[0].primary,
          "%s: rec0 %s = %s", what, r[0].name, r[0].value);
    CHECK(!strcmp(r[1].value, "2026-11-20 10:43"), "%s: rec1 %s", what, r[1].value);
    CHECK(!strcmp(r[2].name, "Error flags") && !strcmp(r[2].value, "0x0000"), "%s: rec2 %s %s", what,
          r[2].name, r[2].value);
    CHECK(r[3].storage == 1 && !strcmp(r[3].value, "2026-10-31"), "%s: rec3 s%u %s", what,
          (unsigned)r[3].storage, r[3].value);
    CHECK(r[4].storage == 1 && !strcmp(r[4].value, "6.868 m3") && !r[4].primary, "%s: rec4 %s", what,
          r[4].value);
}

static void test_plain_t1(void)
{
    uint8_t app[64], f[128], air[200], raw[255];
    const int al = wm_hex_parse(RECORDS, app, sizeof(app));
    const size_t n = build_plain(f, 0x78, 0, 0, app, (size_t)al);
    const size_t an = add_crc_a(f, n, air);
    enc36(air, an, raw, sizeof(raw));
    wm_frame_t fr;
    const int e = wm_phy_decode_tc(raw, sizeof(raw), &fr);
    CHECK(e == WM_OK && fr.phy == WM_PHY_T1 && fr.len == n && !memcmp(fr.data, f, n), "T1 plain decode %d", e);
    wm_msg_t m;
    CHECK(wm_parse(&fr, keyfn, NULL, &m) == WM_OK && m.dec == WM_DEC_PLAIN && m.ci == 0x78, "T1 parse");
    char mfr[4];
    wm_mfr_str(m.mfr, mfr);
    CHECK(!strcmp(mfr, "APA") && m.id == 0x12345678 && m.type == 7, "link layer %s %08X", mfr, (unsigned)m.id);
    check_records(&m, "T1 plain");

    /* one flipped chip: repaired with the block CRC */
    raw[20] ^= 0x10;
    CHECK(wm_phy_decode_tc(raw, sizeof(raw), &fr) == WM_OK && fr.fixed == 1 && !memcmp(fr.data, f, n),
          "T1 chip error repaired");
    /* valid symbols with a wrong header CRC: never a frame */
    air[3] ^= 0x01;
    enc36(air, an, raw, sizeof(raw));
    CHECK(wm_phy_decode_tc(raw, sizeof(raw), &fr) == WM_E_CRC, "T1 bad header rejected");
}

static void test_mode5_c1(void)
{
    uint8_t app[64], f[128], air[200], raw[255];
    int al = wm_hex_parse("2F2F" "0C1378563412" "046D2B0A543B" "02FD170000" "426C5F3A" "4413D41A0000", app, sizeof(app));
    while (al % 16) app[al++] = 0x2F;   /* fill to whole blocks */
    const uint8_t acc = 0x5A;
    const uint16_t cfg = (uint16_t)(5 << 8 | (al / 16) << 4);
    const size_t n = build_plain(f, 0x7A, acc, cfg, app, (size_t)al);
    uint8_t iv[16];
    memcpy(iv, f + 2, 8);
    memset(iv + 8, acc, 8);
    cbc_encrypt(KEY, iv, f + 15, (size_t)al);

    /* C1 frame A */
    raw[0] = 0x54;
    raw[1] = 0xCD;
    const size_t an = add_crc_a(f, n, air);
    memset(raw + 2, 0xAA, sizeof(raw) - 2);
    memcpy(raw + 2, air, an);
    wm_frame_t fr;
    int e = wm_phy_decode_tc(raw, sizeof(raw), &fr);
    CHECK(e == WM_OK && fr.phy == WM_PHY_C1A, "C1A decode %d", e);
    wm_msg_t m;
    wm_parse(&fr, keyfn, NULL, &m);
    CHECK(m.dec == WM_DEC_OK && m.sec == 5 && m.enc_blocks == al / 16, "mode 5 decrypt: %s %s", wm_dec_name(m.dec), m.note);
    check_records(&m, "mode 5");

    /* no key / wrong key */
    wm_parse(&fr, NULL, NULL, &m);
    CHECK(m.dec == WM_DEC_NOKEY, "mode 5 without key: %s", wm_dec_name(m.dec));
    fr.data[5] ^= 1;                    /* other id -> keyfn has none */
    wm_parse(&fr, keyfn, NULL, &m);
    CHECK(m.dec == WM_DEC_NOKEY, "mode 5 other meter: %s", wm_dec_name(m.dec));

    /* C1 frame B, same telegram */
    uint8_t fb[128];
    memcpy(fb, f, n);
    raw[1] = 0x3D;
    const size_t bn = add_crc_b(fb, n, air);
    memset(raw + 2, 0xAA, sizeof(raw) - 2);
    memcpy(raw + 2, air, bn);
    e = wm_phy_decode_tc(raw, sizeof(raw), &fr);
    CHECK(e == WM_OK && fr.phy == WM_PHY_C1B && fr.len == n, "C1B decode %d len %u", e, fr.len);
    wm_parse(&fr, keyfn, NULL, &m);
    CHECK(m.dec == WM_DEC_OK, "C1B mode 5: %s", wm_dec_name(m.dec));
    check_records(&m, "C1B");
}

/* A Relay radio converter (type 0x37, link id 00001111) carrying water meter
   00111101 in a long transport header, plain, 48.998 m3. */
static const char RELAY_T1[] = "2644AC4811110000503772011111" "00AC485007C7000000"
                               "2F2F0C13988904002F2F2F2F2F2F2F2F";

static const uint8_t *link_only_key(uint32_t id, uint32_t link_id, void *ctx)
{
    (void)ctx;
    (void)id;
    return link_id == 0x00001111 ? KEY : NULL;
}

static void test_radio_converter(void)
{
    wm_frame_t fr = { .phy = WM_PHY_T1, .format = 'A' };
    fr.len = (uint16_t)wm_hex_parse(RELAY_T1, fr.data, sizeof(fr.data));
    CHECK(fr.len == 0x27 && fr.data[0] == 0x26, "relay frame %u bytes", fr.len);
    wm_msg_t m;
    CHECK(wm_parse(&fr, keyfn, NULL, &m) == WM_OK && m.dec == WM_DEC_PLAIN && m.long_tpl, "relay parse %s",
          wm_dec_name(m.dec));
    char mfr[4];
    wm_mfr_str(m.mfr, mfr);
    CHECK(!strcmp(mfr, "REL") && m.id == 0x00001111 && m.type == 0x37 && m.tpl_id == 0x00111101 && m.tpl_type == 7,
          "relay ids %s %08X type %02X inner %08X type %02X", mfr, (unsigned)m.id, m.type, (unsigned)m.tpl_id,
          m.tpl_type);
    CHECK(wm_type_name(0x37) && !strcmp(wm_type_name(0x37), "radio conv."), "type 0x37 name");
    wm_rec_t r[8];
    bool bad = true;
    const int n = wm_records(m.buf + m.app_off, m.app_len, r, 8, &bad);
    CHECK(n == 1 && !bad && !strcmp(r[0].value, "48.998 m3") && r[0].primary, "relay volume %d %s", n,
          n ? r[0].value : "");

    /* the same telegram in mode 5: the key typed for the id in the list (the
       converter's) must decrypt the inner meter's data */
    const size_t data = 0x17;
    fr.data[0x15] = 0x10;               /* cfg: 1 encrypted block */
    fr.data[0x16] = 0x05;               /*      security mode 5 */
    uint8_t iv[16];
    memcpy(iv, fr.data + 0x0F, 2);      /* inner M (CI 72 at 0x0A) */
    memcpy(iv + 2, fr.data + 0x0B, 4);  /* inner id */
    iv[6] = fr.data[0x11];              /* inner version */
    iv[7] = fr.data[0x12];              /* inner type */
    memset(iv + 8, fr.data[0x13], 8);   /* ACC */
    cbc_encrypt(KEY, iv, fr.data + data, 16);
    wm_parse(&fr, link_only_key, NULL, &m);
    CHECK(m.dec == WM_DEC_OK, "relay mode 5 with the link id's key: %s %s", wm_dec_name(m.dec), m.note);
    wm_parse(&fr, NULL, NULL, &m);
    CHECK(m.dec == WM_DEC_NOKEY, "relay mode 5 without key: %s", wm_dec_name(m.dec));
}

/* ---- public keys and Techem formats ------------------------------------
   Telegrams from the wmbusmeters driver tests (drivers/src, .xmq files), with the
   readings wmbusmeters expects for them. */

static bool frame_from_hex(const char *hex, wm_frame_t *fr)
{
    memset(fr, 0, sizeof(*fr));
    fr->phy = WM_PHY_T1;
    fr->format = 'A';
    const int n = wm_hex_parse(hex, fr->data, sizeof(fr->data));
    if (n < 10) return false;
    fr->len = (uint16_t)n;
    return fr->data[0] == n - 1;
}

static bool has_value(const wm_msg_t *m, const char *value, bool primary)
{
    wm_rec_t r[40];
    bool bad;
    const int n = wm_msg_records(m, r, 40, &bad);
    for (int i = 0; i < n; i++)
        if (!strcmp(r[i].value, value) && (!primary || r[i].primary)) return true;
    return false;
}

static const uint8_t *any_key(uint32_t id, uint32_t link_id, void *ctx)
{
    (void)id;
    (void)link_id;
    (void)ctx;
    return KEY;
}

static void test_public_keys(void)
{
    static const struct {
        const char *what, *hex, *pub, *value;
    } V[] = {
        /* hydrus.xmq HydrusAES: HYD converter, DME meter in a long header, mode 5 */
        { "Diehl Hydrus",
          "6644242328001081640E7266567464A51170071F0050052C411A08674048DD6BA82A0DF79FFD401309179A893A1B"
          "E3CE8EDC50C2A45CD7AFEC3B4CE765820BE8056C124A17416C3722985FFFF7FCEB7094901AB3A16294B511B9A740"
          "C9F9911352B42A72FB3B0C",
          "Diehl default", "137.291 m3" },
        /* hydrus.xmq Industrial: DME, short header */
        { "Diehl industrial", "2e44a5117625167275077ae7402005e908429273aec91c92bc22c9c256fadf126382aba2cc97eacd2606cf6fa7f248",
          "Diehl default", "144729.29 m3" },
        /* unismart.xmq GasMeter: AMX gas, zero key */
        { "UniSmart",
          "6044B8059430040001037A1D005085E2B670BCF1A5C87E0C1A51DA18924EF984613DA2A9CD39D8F4C7208326C76D"
          "42DBEADF80D574192B71BD7C4F56A7F1513151768A9DB804883B28CB085CA2D0F7438C361CB9E2734712ED9BFBB2"
          "A14EF55208",
          "zero key", "917.00 m3" },
    };
    for (size_t i = 0; i < sizeof(V) / sizeof(V[0]); i++) {
        wm_frame_t fr;
        CHECK(frame_from_hex(V[i].hex, &fr), "%s: frame", V[i].what);
        wm_msg_t m;
        wm_parse(&fr, NULL, NULL, &m);
        CHECK(m.dec == WM_DEC_NOKEY && m.pubkey == -1, "%s: no public keys unless asked: %s", V[i].what,
              wm_dec_name(m.dec));
        wm_parse_ex(&fr, NULL, NULL, WM_TRY_PUBLIC, &m);
        const wm_pubkey_t *pk = wm_pubkey_get(m.pubkey);
        CHECK(m.dec == WM_DEC_OK && pk && !strcmp(pk->name, V[i].pub), "%s: %s with %s", V[i].what,
              wm_dec_name(m.dec), pk ? pk->name : "-");
        CHECK(has_value(&m, V[i].value, false), "%s: reads %s", V[i].what, V[i].value);
        /* a wrong key of the user's: still opened by the public key */
        wm_parse_ex(&fr, any_key, NULL, WM_TRY_PUBLIC, &m);
        CHECK(m.dec == WM_DEC_OK && m.pubkey >= 0, "%s: user key wrong, public key fits", V[i].what);
        wm_parse(&fr, any_key, NULL, &m);
        CHECK(m.dec == WM_DEC_BADKEY && fr.len > 20 && !memcmp(m.buf, fr.data, fr.len),
              "%s: bad key leaves the telegram as received", V[i].what);
    }

    /* the Diehl key is tried for Diehl meters only, the zero key for all */
    const wm_pubkey_t *d = wm_pubkey_get(0), *z = wm_pubkey_get(1);
    CHECK(wm_pubkey_count() == 2 && d && z && d->mfr[0] == WM_MFR('D', 'M', 'E') && !z->mfr[0], "key table");

    /* our own mode 5 telegram (APA, key 0011..FF): no public key fits it */
    uint8_t app[64], f[128];
    int al = wm_hex_parse("2F2F" "0C1378563412" "046D2B0A543B" "02FD170000" "426C5F3A" "4413D41A0000", app,
                          sizeof(app));
    while (al % 16) app[al++] = 0x2F;
    const uint16_t cfg = (uint16_t)(5 << 8 | (al / 16) << 4);
    const size_t n = build_plain(f, 0x7A, 0x33, cfg, app, (size_t)al);
    uint8_t iv[16];
    memcpy(iv, f + 2, 8);
    memset(iv + 8, 0x33, 8);
    cbc_encrypt(KEY, iv, f + 15, (size_t)al);
    wm_frame_t fr = { .phy = WM_PHY_T1, .format = 'A', .len = (uint16_t)n };
    memcpy(fr.data, f, n);
    wm_msg_t m;
    wm_parse_ex(&fr, NULL, NULL, WM_TRY_PUBLIC, &m);
    CHECK(m.dec == WM_DEC_NOKEY && m.pubkey == -1, "public keys do not open another key's telegram: %s",
          wm_dec_name(m.dec));
    wm_parse_ex(&fr, keyfn, NULL, WM_TRY_PUBLIC, &m);
    CHECK(m.dec == WM_DEC_OK && m.pubkey == -1, "the user's key comes first");
}

static void test_techem(void)
{
    static const struct {
        const char *what, *hex, *total, *curr, *prev;
    } V[] = {
        /* vario451.xmq HeatMeter: Vario 4 type 4.5.1, MJ */
        { "Vario 4", "374468506549235827C3A2129F25383300A8622600008200800A2AF862115175552877A36F26C9AB1CB24400000004000000000004908002",
          "22.938 GJ", "9.826 GJ", "13.112 GJ" },   /* = 6371.7 / 2729.4 / 3642.2 kWh */
        /* compact5.xmq Heating: Compact V, kWh, CI A1 */
        { "Compact V", "36446850626262624543A1009F2777010060780000000A000000000000000000000000000000000000000000000000A0400000B4010000",
          "495 kWh", "120 kWh", "375 kWh" },
        /* compact5.xmq vario: TCH 39/43, CI A2 */
        { "Vario 39/43", "37446850792055673943A2109F2F13C500608F1D00008066E8A69B26988D335F6411450C564C5145145CA0F1DA35B9DD37A1936BBF3D31D8",
          "58018 kWh", "7567 kWh", "50451 kWh" },
    };
    for (size_t i = 0; i < sizeof(V) / sizeof(V[0]); i++) {
        wm_frame_t fr;
        CHECK(frame_from_hex(V[i].hex, &fr), "%s: frame", V[i].what);
        wm_msg_t m;
        wm_parse(&fr, NULL, NULL, &m);
        CHECK(m.dec == WM_DEC_PLAIN && m.mfct != WM_MFCT_NONE, "%s: %s %s", V[i].what, wm_dec_name(m.dec), m.note);
        wm_rec_t r[8];
        bool bad;
        const int k = wm_msg_records(&m, r, 8, &bad);
        CHECK(k == 3 && r[0].primary && !strcmp(r[0].value, V[i].total) && !strcmp(r[1].value, V[i].curr) &&
                  !strcmp(r[2].value, V[i].prev),
              "%s: %s / %s / %s", V[i].what, k > 0 ? r[0].value : "", k > 1 ? r[1].value : "", k > 2 ? r[2].value : "");
    }
    /* fhkvdataiii.xmq: heat cost allocators, units, dates and temperatures */
    static const struct {
        const char *what, *hex, *v[6];
    } H[] = {
        { "FHKV 69 (11)", "34446850226677116980A0119F27020480048300C408F709143C003D341A2B0B2A0707000000000000062D114457563D71A1850000",
          { "131 HCA", "2020-02-08", "1026 HCA", "2019-12-31", "22.44 C", "25.51 C" } },
        { "FHKV 69 (01)", "32446850059605416980A0019F334805400CFE029808B1080000000000060F4F3467AEA9A88D7B8D503E000000000000000000",
          { "766 HCA", "2026-06-04", "1352 HCA", "2025-12-31", "22.00 C", "22.25 C" } },
        { "FHKV 94 (0F)", "33446850828712129480A20F9F3344042016960091E807DC0701030003030000000000000000010001020F05161635162A1B4018",
          { "150 HCA", "2026-11-02", "1092 HCA", "2025-12-31", "20.24 C", "20.12 C" } },
    };
    for (size_t i = 0; i < sizeof(H) / sizeof(H[0]); i++) {
        wm_frame_t fr;
        CHECK(frame_from_hex(H[i].hex, &fr), "%s: frame", H[i].what);
        wm_msg_t m;
        wm_parse(&fr, NULL, NULL, &m);
        CHECK(m.dec == WM_DEC_PLAIN && m.mfct == WM_MFCT_TCH_FHKV3, "%s: %s %s", H[i].what, wm_dec_name(m.dec), m.note);
        wm_rec_t r[8];
        bool bad;
        const int k = wm_msg_records(&m, r, 8, &bad);
        CHECK(k == 6 && r[0].primary && !bad, "%s: %d records", H[i].what, k);
        for (int j = 0; j < 6 && j < k; j++)
            CHECK(!strcmp(r[j].value, H[i].v[j]), "%s: %s is %s, want %s", H[i].what, r[j].name, r[j].value, H[i].v[j]);
    }
    /* water meters, radio 3 / radio 4: total, this period, date, last period, period end */
    static const struct {
        const char *what, *hex, *v[5];
    } W[] = {
        /* mkradio3.xmq Duschen, tests 1 and 3 */
        { "radio 3", "2F446850313233347462A2069F255900B029310000000306060906030609070606050509050505050407040605070500",
          { "13.8 m3", "4.9 m3", "2019-04-27", "8.9 m3", "2018-12-31" } },
        { "radio 3 b", "2F446850313233347462A2067F245900F007310000000306060906030609070606050509050505050407040605070500",
          { "13.8 m3", "4.9 m3", "2019-03-31", "8.9 m3", "2018-03-31" } },
        /* mkradio4.xmq Duschagain */
        { "radio 4", "2F446850200141029562A206702901006017030004000300000000000000000000000000000000000000000000000000",
          { "0.4 m3", "0.3 m3", "2020-11-22", "0.1 m3", "2020-11-16" } },
        /* radio 4, TCH 95/72, cold water */
        { "radio 4 cold", "2F446850785634129572A2069F33C40340176C0400000928284432362C212E3D333947472E3934362732393D3D3D3E39",
          { "209.6 m3", "113.2 m3", "2026-11-20", "96.4 m3", "2025-12-31" } },
    };
    for (size_t i = 0; i < sizeof(W) / sizeof(W[0]); i++) {
        wm_frame_t fr;
        CHECK(frame_from_hex(W[i].hex, &fr), "%s: frame", W[i].what);
        wm_msg_t m;
        wm_parse(&fr, NULL, NULL, &m);
        CHECK(m.dec == WM_DEC_PLAIN && m.mfct == WM_MFCT_TCH_RADIO, "%s: %s %s", W[i].what, wm_dec_name(m.dec), m.note);
        wm_rec_t r[8];
        bool bad;
        const int k = wm_msg_records(&m, r, 8, &bad);
        CHECK(k == 5 && r[0].primary && !r[1].primary, "%s: %d records", W[i].what, k);
        for (int j = 0; j < 5 && j < k; j++)
            CHECK(!strcmp(r[j].value, W[i].v[j]), "%s: %s is %s, want %s", W[i].what, r[j].name, r[j].value, W[i].v[j]);
    }
    /* Techem OMS telegrams are encrypted with the meter's own key */
    static const char *const ENC[] = {
        /* heat meter TCH 17/04 (Vario 4.5.1 MID), C1, CI 7A mode 5 */
        "334468507856341217047A2700202597996DF3639D2781443E5F7E42E3418A8B97A7E79A8D2C65D4ACEEE77C2EA0320FF727B8B8",
        /* radio 4 module TCH 95/37 of the water meter above, C1, long header, mode 5 */
        "364468507856341295377221436587A85CFE0743002025E7E01413961D6092E18C4441FAD104CE5165027076BB1D274ED5E23540255835",
    };
    for (size_t i = 0; i < 2; i++) {
        wm_frame_t fr;
        frame_from_hex(ENC[i], &fr);
        wm_msg_t m;
        wm_parse_ex(&fr, NULL, NULL, WM_TRY_PUBLIC, &m);
        CHECK(m.dec == WM_DEC_NOKEY && m.sec == 5 && m.mfct == WM_MFCT_NONE, "Techem OMS telegram %u: %s", (unsigned)i,
              wm_dec_name(m.dec));
    }

    CHECK(!strcmp(wm_type_name_mfr(WM_MFR('T', 'C', 'H'), 0x80), "HCA") && !wm_type_name(0x80) &&
              !strcmp(wm_type_name_mfr(WM_MFR('T', 'C', 'H'), 0xC3), "heat") &&
              !strcmp(wm_type_name_mfr(WM_MFR('K', 'A', 'M'), 0x04), "heat"),
          "type names by manufacturer");

    /* another manufacturer's CI A2 stays unsupported */
    wm_frame_t fr;
    frame_from_hex("374468506549235827C3A2129F25383300A8622600008200800A2AF862115175552877A36F26C9AB1CB24400000004000000000004908002", &fr);
    fr.data[2] ^= 1;
    wm_msg_t m;
    wm_parse(&fr, NULL, NULL, &m);
    CHECK(m.dec == WM_DEC_UNSUP && m.mfct == WM_MFCT_NONE, "CI A2 of another maker: %s", wm_dec_name(m.dec));
}

static void test_mode7_afl(void)
{
    /* link | AFL (FCL: MCRP, MCR) | TPL 7A short, mode 7 | encrypted records */
    uint8_t f[160], app[64], raw[255], air[220];
    int al = wm_hex_parse("2F2F" "0C1378563412" "046D2B0A543B" "02FD170000" "426C5F3A" "4413D41A0000", app, sizeof(app));
    while (al % 16) app[al++] = 0x2F;
    size_t n = 0;
    f[n++] = 0; f[n++] = 0x44; f[n++] = 0x01; f[n++] = 0x06;
    f[n++] = 0x78; f[n++] = 0x56; f[n++] = 0x34; f[n++] = 0x12; f[n++] = 0x05; f[n++] = 0x07;
    const uint32_t mcr = 0x00000102;
    f[n++] = 0x90; f[n++] = 6;          /* AFL.L: FCL 2 + MCR 4 */
    f[n++] = 0x00; f[n++] = 0x08;       /* FCL: MCRP (bit 11) */
    for (int i = 0; i < 4; i++) f[n++] = (uint8_t)(mcr >> (8 * i));
    const uint16_t cfg = (uint16_t)(7 << 8 | (al / 16) << 4);
    f[n++] = 0x7A; f[n++] = 0x21; f[n++] = 0x00; f[n++] = (uint8_t)cfg; f[n++] = (uint8_t)(cfg >> 8);
    f[n++] = 0x10;                      /* configuration field extension */
    const size_t enc_at = n;
    memcpy(f + n, app, (size_t)al);
    n += (size_t)al;
    f[0] = (uint8_t)(n - 1);
    uint8_t in[16] = { 0x00, 0x02, 0x01, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 7, 7, 7, 7, 7, 7, 7 };
    uint8_t kenc[16], iv[16] = { 0 };
    wm_aes_cmac(KEY, in, 16, kenc);
    cbc_encrypt(kenc, iv, f + enc_at, (size_t)al);
    const size_t an = add_crc_a(f, n, air);
    enc36(air, an, raw, sizeof(raw));
    wm_frame_t fr;
    const int e = wm_phy_decode_tc(raw, sizeof(raw), &fr);
    CHECK(e == WM_OK, "mode 7 T1 decode %d", e);
    wm_msg_t m;
    wm_parse(&fr, keyfn, NULL, &m);
    CHECK(m.has_afl && m.has_mcr && m.mcr == mcr, "AFL counter %08X", (unsigned)m.mcr);
    CHECK(m.dec == WM_DEC_OK && m.sec == 7, "mode 7 decrypt: %s %s", wm_dec_name(m.dec), m.note);
    check_records(&m, "mode 7");
}

/* A Sagemcom XT211 shaped telegram (868.3 MHz, T mode): 209 bytes, AFL
   with MCL, MCR and an 8-byte MAC, mode 7, 11 blocks. Values made up, layout as
   the real meter sends it. 237 bytes with CRCs are 356 on air; the radio hands
   over 255, so only the first 8 CRC blocks arrive. */
static size_t xt211_frame(uint8_t *f)
{
    uint8_t app[176];
    int al = wm_hex_parse("2F2F" "066D323AB05E3A00" "0C7878563412" "0E03674523010000" "8E1003674523010000"
                          "8E2003000000000000" "8E3003000000000000" "0E833C000000000000" "8E10833C000000000000"
                          "8E20833C000000000000" "8E30833C000000000000" "0B2B120500" "0BAB3C000000"
                          "8B8040ABC8FC10000100" "8B40ABC8FC10000000" "8B8040ABC8FC10000100" "0D3A20",
                          app, sizeof(app));
    memset(app + al, 0, 32);
    al += 32;
    while (al < 176) app[al++] = 0x2F;
    size_t n = 0;
    f[n++] = 0; f[n++] = 0x44; f[n++] = 0x27; f[n++] = 0x4C;   /* SAG */
    f[n++] = 0x78; f[n++] = 0x56; f[n++] = 0x34; f[n++] = 0x12; f[n++] = 0x50; f[n++] = 0x02;
    const uint32_t mcr = 0x00000AA7;
    f[n++] = 0x90; f[n++] = 0x0F;       /* AFL.L: FCL 2 + MCL 1 + MCR 4 + MAC 8 */
    f[n++] = 0x00; f[n++] = 0x2C;       /* FCL: MCLP, MCRP, MACP */
    f[n++] = 0x25;                      /* MCL: AES-CMAC, 8 bytes */
    for (int i = 0; i < 4; i++) f[n++] = (uint8_t)(mcr >> (8 * i));
    for (int i = 0; i < 8; i++) f[n++] = (uint8_t)(0xA0 + i);   /* MAC, not checked */
    f[n++] = 0x7A; f[n++] = 0x78; f[n++] = 0x00; f[n++] = 0xB0; f[n++] = 0x07;   /* mode 7, 11 blocks */
    f[n++] = 0x10;
    const size_t enc_at = n;
    memcpy(f + n, app, 176);
    n += 176;
    f[0] = (uint8_t)(n - 1);
    uint8_t in[16] = { 0x00, 0xA7, 0x0A, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 7, 7, 7, 7, 7, 7, 7 };
    uint8_t kenc[16], iv[16] = { 0 };
    wm_aes_cmac(KEY, in, 16, kenc);
    cbc_encrypt(kenc, iv, f + enc_at, 176);
    return n;
}

static void test_cut_frame(void)
{
    uint8_t f[256], air[300], raw[420];
    const size_t n = xt211_frame(f);
    CHECK(n == 209, "XT211 frame %u bytes", (unsigned)n);

    /* whole, as a receiver without the limit sees it */
    wm_frame_t fr = { .phy = WM_PHY_T1, .format = 'A', .len = (uint16_t)n };
    memcpy(fr.data, f, n);
    wm_msg_t m;
    wm_parse(&fr, keyfn, NULL, &m);
    CHECK(m.dec == WM_DEC_OK && m.sec == 7 && m.mcr == 0xAA7 && !m.cut, "XT211 whole: %s %s", wm_dec_name(m.dec), m.note);
    wm_rec_t r[40];
    bool bad;
    int k = wm_msg_records(&m, r, 40, &bad);
    CHECK(k == 16 && !bad, "XT211 whole: %d records, bad %d", k, bad);
    if (k == 16) {
        CHECK(!strcmp(r[2].value, "1234.567 kWh") && r[2].primary && !strcmp(r[3].value, "1234.567 kWh") && r[3].tariff == 1,
              "XT211 energy %s / t%u %s", r[2].value, r[3].tariff, r[3].value);
        CHECK(!strcmp(r[6].name, "Energy export") && !r[6].primary, "XT211 export name %s", r[6].name);
        CHECK(!strcmp(r[10].name, "Power") && !strcmp(r[10].value, "512 W"), "XT211 power %s %s", r[10].name, r[10].value);
        CHECK(!strcmp(r[11].name, "Power export"), "XT211 power export %s", r[11].name);
        CHECK(!strcmp(r[15].value, "(empty)"), "XT211 empty field %s", r[15].value);
    }

    /* through the radio: 255 bytes of 3-of-6 */
    const size_t an = add_crc_a(f, n, air);
    CHECK(an == 237, "XT211 on air %u", (unsigned)an);
    enc36(air, an, raw, sizeof(raw));
    memset(&fr, 0, sizeof(fr));
    int e = wm_phy_decode_tc(raw, 255, &fr);
    CHECK(e == WM_OK && fr.cut && fr.len == 138 && fr.data[0] == 0xD0, "XT211 cut decode %d cut %u len %u", e, fr.cut, fr.len);
    CHECK(wm_phy_used_tc(&fr, 255) == 255, "a cut frame takes the whole packet");
    wm_parse(&fr, keyfn, NULL, &m);
    CHECK(m.dec == WM_DEC_OK && m.cut && m.app_len == 96, "XT211 cut: %s %s, %u bytes", wm_dec_name(m.dec), m.note, m.app_len);
    k = wm_msg_records(&m, r, 40, &bad);
    CHECK(k == 11 && bad, "XT211 cut: %d records, bad %d", k, bad);
    if (k >= 11)
        CHECK(!strcmp(r[2].value, "1234.567 kWh") && r[2].primary && !strcmp(r[10].value, "512 W"),
              "XT211 cut readings %s %s", r[2].value, r[10].value);
    /* no key: still a meter, not noise */
    wm_parse_ex(&fr, NULL, NULL, WM_TRY_PUBLIC, &m);
    CHECK(m.dec == WM_DEC_NOKEY, "XT211 cut, no key: %s", wm_dec_name(m.dec));
    /* a flipped chip in what arrived: repaired */
    raw[100] ^= 0x10;
    e = wm_phy_decode_tc(raw, 255, &fr);
    CHECK(e == WM_OK && fr.cut && fr.len == 138 && fr.fixed == 1, "XT211 cut, chip repaired: %d, %u bytes", e, fr.len);
    /* a wrong byte with valid symbols fails block 2's CRC: header and block 1 are kept */
    enc36(air, an, raw, sizeof(raw));
    air[40] ^= 0x01;
    enc36(air, an, raw, sizeof(raw));
    e = wm_phy_decode_tc(raw, 255, &fr);
    CHECK(e == WM_OK && fr.cut && fr.len == 26, "XT211 cut with a bad block: %d, %u bytes", e, fr.len);
}

/* Shifts the bits of src into dst starting at bit `bit`. */
static void put_bytes_at(uint8_t *dst, size_t bit, const uint8_t *src, size_t n)
{
    for (size_t i = 0; i < n; i++) put_bits(dst, &bit, src[i], 8);
}

static void test_two_in_one(void)
{
    /* A C1 telegram (Techem Vario 4.5.1 MID, OMS) and a T1 telegram (its own
       17/C3 frame, CI A2) in one packet. */
    uint8_t c1[128], t1[128], air[160], t1raw[200], raw[255];
    const int cn = wm_hex_parse("334468507856341217047A2700202597996DF3639D2781443E5F7E42E3418A8B97A7E79A8D2C65D4ACEEE77C2EA0320FF727B8B8",
                                c1, sizeof(c1));
    const int tn = wm_hex_parse("374468507856341217C3A2129F3390AA00500C480000032F901C7268F1C30A4850B1C4187AD8610521FED414C658B2626CEFAF23562A0E55",
                                t1, sizeof(t1));
    CHECK(cn == 52 && tn == 56, "two-in-one vectors");
    memset(raw, 0, sizeof(raw));
    raw[0] = 0x54; raw[1] = 0xCD;
    const size_t ca = add_crc_a(c1, (size_t)cn, raw + 2);           /* 60 bytes */
    size_t bit = (2 + ca + 9) * 8 + 3;                              /* a gap, off the byte grid */
    static const uint8_t PRE[] = { 0x55, 0x55, 0x55, 0x54, 0x3D };
    put_bytes_at(raw, bit, PRE, sizeof(PRE));
    bit += 8 * sizeof(PRE);
    const size_t ta = add_crc_a(t1, (size_t)tn, air);              /* 64 bytes, 96 on air */
    enc36(air, ta, t1raw, sizeof(t1raw));
    put_bytes_at(raw, bit, t1raw, 96);

    wm_frame_t fr;
    CHECK(wm_phy_decode_tc(raw, sizeof(raw), &fr) == WM_OK && fr.phy == WM_PHY_C1A, "first frame C1");
    size_t from = wm_phy_used_tc(&fr, sizeof(raw));
    CHECK(from == 62, "C1 frame takes %u bytes", (unsigned)from);
    uint8_t tail[255];
    size_t at = 0;
    const size_t got = wm_find_sync_tc(raw, sizeof(raw), from, tail, sizeof(tail), &at);
    CHECK(got >= 96 && at > from, "second sync found: %u bytes at %u", (unsigned)got, (unsigned)at);
    CHECK(wm_phy_decode_tc(tail, got, &fr) == WM_OK && fr.phy == WM_PHY_T1, "second frame T1");
    wm_msg_t m;
    wm_parse(&fr, NULL, NULL, &m);
    CHECK(m.dec == WM_DEC_PLAIN && m.mfct == WM_MFCT_TCH_VARIO451, "17/C3 is Vario 4.5.1: %s %s", wm_dec_name(m.dec), m.note);
    wm_rec_t r[8];
    bool bad;
    const int k = wm_msg_records(&m, r, 8, &bad);
    CHECK(k == 3 && !strcmp(r[0].value, "62.108 GJ") && !strcmp(r[1].value, "18.444 GJ") &&
              !strcmp(r[2].value, "43.664 GJ"),
          "17/C3 values %s / %s / %s", k > 0 ? r[0].value : "", k > 1 ? r[1].value : "", k > 2 ? r[2].value : "");
    from = at + wm_phy_used_tc(&fr, got);
    CHECK(!wm_find_sync_tc(raw, sizeof(raw), from, tail, sizeof(tail), &at), "nothing after the second frame");
}

/* T1 chips flipped on the way: repaired with the block CRCs, or the frame is
   kept up to the block past repair. */
static void flip(uint8_t *raw, size_t chip) { raw[chip >> 3] ^= (uint8_t)(0x80 >> (chip & 7)); }

static void test_repair(void)
{
    uint8_t t1[128], air[160], raw[255];
    const int tn = wm_hex_parse("374468507856341217C3A2129F3390AA00500C480000032F901C7268F1C30A4850B1C4187AD8610521FED414C658B2626CEFAF23562A0E55",
                                t1, sizeof(t1));
    const size_t ta = add_crc_a(t1, (size_t)tn, air);
    enc36(air, ta, raw, sizeof(raw));
    /* header block: CRC symbol; block 1: two symbols; last block: one */
    flip(raw, 10 * 12 + 3);
    flip(raw, 14 * 12 + 1);
    flip(raw, 20 * 12 + 8);
    flip(raw, 60 * 12 + 5);
    wm_frame_t fr;
    int e = wm_phy_decode_tc(raw, sizeof(raw), &fr);
    CHECK(e == WM_OK && !fr.cut && fr.fixed == 4 && fr.len == (uint16_t)tn && !memcmp(fr.data + 1, t1 + 1, (size_t)tn - 1),
          "repair: %d cut %u fixed %u len %u", e, fr.cut, fr.fixed, fr.len);
    wm_msg_t m;
    wm_parse(&fr, NULL, NULL, &m);
    CHECK(m.mfct == WM_MFCT_TCH_VARIO451, "repaired 17/C3 reads");

    /* block 2 with five bad symbols: past repair, blocks 0 and 1 kept */
    enc36(air, ta, raw, sizeof(raw));
    for (int s = 0; s < 5; s++) flip(raw, (size_t)(30 * 2 + 2 * s) * 6 + 2);
    e = wm_phy_decode_tc(raw, sizeof(raw), &fr);
    CHECK(e == WM_OK && fr.cut && fr.len == 26 && fr.data[0] == 0x37, "past repair: %d cut %u len %u", e, fr.cut, fr.len);
    wm_parse(&fr, NULL, NULL, &m);
    CHECK(m.mfct == WM_MFCT_TCH_VARIO451 && m.cut, "first block still gives the Techem values");

    /* a bad header block is still an error */
    enc36(air, ta, raw, sizeof(raw));
    for (int s = 0; s < 4; s++) flip(raw, (size_t)(4 + 2 * s) * 6 + 1);
    e = wm_phy_decode_tc(raw, sizeof(raw), &fr);
    CHECK(e == WM_E_CODING || e == WM_E_CRC, "bad header: %d", e);
}

static void test_ell_ctr_s1(void)
{
    /* link | ELL 8D (CC ACC SN PayloadCRC) | 78 + records, AES-CTR from PayloadCRC on */
    uint8_t f[128], app[64], raw[255], air[200];
    const int al = wm_hex_parse(RECORDS, app, sizeof(app));
    size_t n = 0;
    f[n++] = 0; f[n++] = 0x44; f[n++] = 0x01; f[n++] = 0x06;
    f[n++] = 0x78; f[n++] = 0x56; f[n++] = 0x34; f[n++] = 0x12; f[n++] = 0x05; f[n++] = 0x07;
    const uint32_t sn = (1u << 29) | 0x00012345;
    f[n++] = 0x8D; f[n++] = 0x20; f[n++] = 0x33;
    for (int i = 0; i < 4; i++) f[n++] = (uint8_t)(sn >> (8 * i));
    const size_t crc_at = n;
    n += 2;
    f[n++] = 0x78;
    memcpy(f + n, app, (size_t)al);
    n += (size_t)al;
    f[0] = (uint8_t)(n - 1);
    const uint16_t pc = wm_crc(f + crc_at + 2, n - crc_at - 2);
    f[crc_at] = (uint8_t)pc;
    f[crc_at + 1] = (uint8_t)(pc >> 8);
    uint8_t iv[16] = { 0 };
    memcpy(iv, f + 2, 8);
    iv[8] = 0x20;
    memcpy(iv + 9, f + crc_at - 4, 4);
    wm_aes_ctr(KEY, iv, f + crc_at, n - crc_at);
    const size_t an = add_crc_a(f, n, air);
    manchester(air, an, raw, sizeof(raw));
    wm_frame_t fr;
    const int e = wm_phy_decode_s(raw, sizeof(raw), &fr);
    CHECK(e == WM_OK && fr.phy == WM_PHY_S1, "S1 decode %d", e);
    wm_msg_t m;
    wm_parse(&fr, keyfn, NULL, &m);
    CHECK(m.dec == WM_DEC_OK && m.ell_ci == 0x8D && m.ci == 0x78, "ELL CTR: %s %s", wm_dec_name(m.dec), m.note);
    check_records(&m, "ELL S1");
    /* the other Manchester convention */
    for (size_t i = 0; i < sizeof(raw); i++) raw[i] = (uint8_t)~raw[i];
    CHECK(wm_phy_decode_s(raw, sizeof(raw), &fr) == WM_OK, "S1 inverted Manchester");
}

static void test_long_frame(void)
{
    /* 150 bytes of records: format A with ten CRC blocks, still inside 255 raw bytes? No:
       T1 carries 170 bytes, so L=120 fits. */
    uint8_t app[200], f[220], air[300], raw[255];
    size_t al = 0;
    for (int i = 0; i < 18; i++) {      /* 18 x 6-byte records */
        app[al++] = 0x04; app[al++] = 0x13;
        app[al++] = (uint8_t)i; app[al++] = 0; app[al++] = 0; app[al++] = 0;
    }
    const size_t n = build_plain(f, 0x78, 0, 0, app, al);
    const size_t an = add_crc_a(f, n, air);
    enc36(air, an, raw, sizeof(raw));
    wm_frame_t fr;
    const int e = wm_phy_decode_tc(raw, sizeof(raw), &fr);
    CHECK(e == WM_OK && fr.len == n, "long T1 (%u bytes on air) %d", (unsigned)an, e);
    wm_msg_t m;
    wm_parse(&fr, keyfn, NULL, &m);
    wm_rec_t r[32];
    bool bad;
    CHECK(wm_records(m.buf + m.app_off, m.app_len, r, 32, &bad) == 18 && !bad, "18 records");
    CHECK(!strcmp(r[17].value, "0.017 m3"), "rec17 %s", r[17].value);
}

static void test_misc(void)
{
    uint8_t b[16];
    CHECK(wm_hex_parse("00 11:22-33", b, 16) == 4 && b[3] == 0x33, "hex separators");
    CHECK(wm_hex_parse("0", b, 16) == -1, "odd hex");
    CHECK(wm_hex_parse("zz", b, 16) == -1, "bad hex");
    wm_rec_t r[4];
    bool bad;
    uint8_t neg[] = { 0x0A, 0x5B, 0x34, 0xF2 };        /* BCD4 -234 * 10^0 C (flow temp 10^0) */
    CHECK(wm_records(neg, sizeof(neg), r, 4, &bad) == 1 && !strcmp(r[0].value, "-234 C"), "neg bcd %s", r[0].value);
    uint8_t txt[] = { 0x0D, 0xFD, 0x0C, 0x03, 'C', 'B', 'A' };   /* model "ABC" */
    CHECK(wm_records(txt, sizeof(txt), r, 4, &bad) == 1 && !strcmp(r[0].value, "ABC"), "ascii %s", r[0].value);
    uint8_t energy[] = { 0x04, 0x06, 0x10, 0x27, 0x00, 0x00 };   /* 10000 kWh */
    CHECK(wm_records(energy, sizeof(energy), r, 4, &bad) == 1 && !strcmp(r[0].value, "10000 kWh"), "energy %s", r[0].value);
    uint8_t trunc[] = { 0x04, 0x13, 0x01 };
    CHECK(wm_records(trunc, sizeof(trunc), r, 4, &bad) == 0 && bad, "truncated record");
}

/* "dump": the radio bytes of a plain T1 telegram and a mode 5 T1 telegram,
   as hex for the simulator's packethex= script step. */
static void dump(void)
{
    uint8_t app[64], f[128], air[200], raw[255];
    char hexs[600];
    int al = wm_hex_parse(RECORDS, app, sizeof(app));
    size_t n = build_plain(f, 0x78, 0, 0, app, (size_t)al);
    f[4] = 0x11;                        /* id 12345611: no key */
    size_t an = add_crc_a(f, n, air);
    enc36(air, an, raw, sizeof(raw));
    wm_hex_str(raw, sizeof(raw), hexs, sizeof(hexs));
    printf("plain %s\n", hexs);
    al = wm_hex_parse("2F2F" "0C1378563412" "046D2B0A543B" "02FD170000" "426C5F3A" "4413D41A0000", app, sizeof(app));
    while (al % 16) app[al++] = 0x2F;
    const uint16_t cfg = (uint16_t)(5 << 8 | (al / 16) << 4);
    n = build_plain(f, 0x7A, 0x5A, cfg, app, (size_t)al);
    uint8_t iv[16];
    memcpy(iv, f + 2, 8);
    memset(iv + 8, 0x5A, 8);
    cbc_encrypt(KEY, iv, f + 15, (size_t)al);
    an = add_crc_a(f, n, air);
    enc36(air, an, raw, sizeof(raw));
    wm_hex_str(raw, sizeof(raw), hexs, sizeof(hexs));
    printf("mode5 %s\n", hexs);
    /* public-key and Techem telegrams from test_public_keys / test_techem, on air */
    static const char *const MORE[][2] = {
        { "diehl", "6644242328001081640E7266567464A51170071F0050052C411A08674048DD6BA82A0DF79FFD401309179A893A1B"
                   "E3CE8EDC50C2A45CD7AFEC3B4CE765820BE8056C124A17416C3722985FFFF7FCEB7094901AB3A16294B511B9A740"
                   "C9F9911352B42A72FB3B0C" },
        { "techem", "374468506549235827C3A2129F25383300A8622600008200800A2AF862115175552877A36F26C9AB1CB2440000"
                    "0004000000000004908002" },
    };
    for (size_t i = 0; i < 2; i++) {
        uint8_t fb[256];
        const int fl = wm_hex_parse(MORE[i][1], fb, sizeof(fb));
        an = add_crc_a(fb, (size_t)fl, air);
        enc36(air, an, raw, sizeof(raw));
        wm_hex_str(raw, sizeof(raw), hexs, sizeof(hexs));
        printf("%s %s\n", MORE[i][0], hexs);
    }
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "dump")) {
        dump();
        return 0;
    }
    test_aes();
    test_crc();
    test_plain_t1();
    test_mode5_c1();
    test_mode7_afl();
    test_cut_frame();
    test_two_in_one();
    test_repair();
    test_ell_ctr_s1();
    test_long_frame();
    test_radio_converter();
    test_public_keys();
    test_techem();
    test_misc();
    printf("%d checks, %d failed\n", checks, fails);
    return fails != 0;
}
