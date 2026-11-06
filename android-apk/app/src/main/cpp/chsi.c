// libchsi.so — L5/L6/L7：密钥派生 / 签名期望值 / 反调试反Frida，全部收进 native。
// jadx 只能看到 external 声明；密钥与哈希经 XOR 0xA7 混淆分段存放。
#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ================= SHA-256 ================= */
typedef struct { unsigned int st[8]; unsigned long long len; unsigned char buf[64]; size_t bl; } sha256_ctx;

static const unsigned int K256[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static unsigned int ror32(unsigned int x, int n){ return (x >> n) | (x << (32 - n)); }

static void sha256_block(sha256_ctx *cx, const unsigned char *p){
    unsigned int w[64], v[8], t1, t2; int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned int)p[i*4] << 24) | ((unsigned int)p[i*4+1] << 16) | ((unsigned int)p[i*4+2] << 8) | p[i*4+3];
    for (i = 16; i < 64; i++){
        unsigned int s0 = ror32(w[i-15],7) ^ ror32(w[i-15],18) ^ (w[i-15] >> 3);
        unsigned int s1 = ror32(w[i-2],17) ^ ror32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    memcpy(v, cx->st, sizeof v);
    for (i = 0; i < 64; i++){
        unsigned int S1 = ror32(v[4],6) ^ ror32(v[4],11) ^ ror32(v[4],25);
        unsigned int ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        t1 = v[7] + S1 + ch + K256[i] + w[i];
        unsigned int S0 = ror32(v[0],2) ^ ror32(v[0],13) ^ ror32(v[0],22);
        unsigned int mj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        t2 = S0 + mj;
        v[7]=v[6]; v[6]=v[5]; v[5]=v[4]; v[4]=v[3]+t1;
        v[3]=v[2]; v[2]=v[1]; v[1]=v[0]; v[0]=t1+t2;
    }
    for (i = 0; i < 8; i++) cx->st[i] += v[i];
}

static void sha256_init(sha256_ctx *cx){
    cx->st[0]=0x6a09e667; cx->st[1]=0xbb67ae85; cx->st[2]=0x3c6ef372; cx->st[3]=0xa54ff53a;
    cx->st[4]=0x510e527f; cx->st[5]=0x9b05688c; cx->st[6]=0x1f83d9ab; cx->st[7]=0x5be0cd19;
    cx->len = 0; cx->bl = 0;
}

static void sha256_update(sha256_ctx *cx, const void *data, size_t n){
    const unsigned char *p = (const unsigned char *)data;
    cx->len += n;
    while (cx->bl + n >= 64){
        memcpy(cx->buf + cx->bl, p, 64 - cx->bl);
        sha256_block(cx, cx->buf);
        p += 64 - cx->bl; n -= 64 - cx->bl; cx->bl = 0;
    }
    if (n){ memcpy(cx->buf + cx->bl, p, n); cx->bl += n; }
}

static void sha256_final(sha256_ctx *cx, unsigned char out[32]){
    unsigned long long bits = cx->len * 8;
    unsigned char pad = 0x80, z = 0, lenb[8]; int i;
    sha256_update(cx, &pad, 1);
    while (cx->bl != 56) sha256_update(cx, &z, 1);
    for (i = 0; i < 8; i++) lenb[i] = (unsigned char)((bits >> (56 - 8*i)) & 0xff);
    sha256_update(cx, lenb, 8);
    for (i = 0; i < 8; i++){
        out[i*4]   = (unsigned char)(cx->st[i] >> 24);
        out[i*4+1] = (unsigned char)(cx->st[i] >> 16);
        out[i*4+2] = (unsigned char)(cx->st[i] >> 8);
        out[i*4+3] = (unsigned char)(cx->st[i]);
    }
}

static void sha256_hex(const void *d, size_t n, char *hex){
    unsigned char o[32]; sha256_ctx cx; int i;
    sha256_init(&cx); sha256_update(&cx, d, n); sha256_final(&cx, o);
    static const char *H = "0123456789abcdef";
    for (i = 0; i < 32; i++){ hex[i*2] = H[o[i]>>4]; hex[i*2+1] = H[o[i]&15]; }
    hex[64] = 0;
}

/* ================= HMAC-SHA256 ================= */
static void hmac_sha256(const unsigned char *key, size_t klen,
                        const unsigned char *msg, size_t mlen, unsigned char out[32]){
    unsigned char k0[64], kh[32]; unsigned char ip[64], op[64]; int i; sha256_ctx cx;
    memset(k0, 0, 64);
    if (klen > 64){ sha256_init(&cx); sha256_update(&cx, key, klen); sha256_final(&cx, kh); memcpy(k0, kh, 32); }
    else memcpy(k0, key, klen);
    for (i = 0; i < 64; i++){ ip[i] = k0[i] ^ 0x36; op[i] = k0[i] ^ 0x5c; }
    sha256_init(&cx); sha256_update(&cx, ip, 64); sha256_update(&cx, msg, mlen); sha256_final(&cx, kh);
    sha256_init(&cx); sha256_update(&cx, op, 64); sha256_update(&cx, kh, 32); sha256_final(&cx, out);
}

/* ================= 混淆密钥/哈希（XOR 0xA7 还原） ================= */
// APK 专用隧道密钥（与 PC/iOS 的 TUNNEL_KEY 分离）
static const unsigned char K1[] = {193,146,149,198,150,145,149,193,195,149,159,194,159,196,146,150,158,148,151,159,147,196,151,149,159,193,150,158,159,149,197,196};
static const unsigned char S1[] = {196,147,148,198,147,193,150,198,144,149,193,147,194,194,194,193,149,145,149,197,151,148,147,150,196,195,198,194,198,146,150,145,146,149,146,146,145,151,194,148,193,144,144,148,147,197,195,145,196,198,151,193,197,159,194,196,147,194,159,151,147,145,198,158};

static char *unmask(const unsigned char *src, int n){
    static char bufs[2][128]; static int flip = 0;
    char *b = bufs[flip++ & 1]; int i;
    for (i = 0; i < n; i++) b[i] = (char)(src[i] ^ 0xA7);
    b[n] = 0;
    return b;
}

/* ================= JNI 接口 ================= */
// HMAC-SHA256(key, "token|device") hex[:32] —— 服务端 X-K / ?sig 校验
JNIEXPORT jstring JNICALL
Java_com_chsi_app_Native_tunnelSig(JNIEnv *e, jclass c, jstring token, jstring device){
    (void)c;
    const char *t = (*e)->GetStringUTFChars(e, token, NULL);
    const char *d = (*e)->GetStringUTFChars(e, device, NULL);
    char msg[256]; unsigned char mac[32]; char out[33];
    const char *kk = unmask(K1, (int)sizeof K1);   // ★ 先还原密钥（修复：误用混淆态字节当密钥）
    snprintf(msg, sizeof msg, "%s|%s", t, d);
    hmac_sha256((const unsigned char *)kk, strlen(kk), (const unsigned char *)msg, strlen(msg), mac);
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 16; i++){ out[i*2] = H[mac[i]>>4]; out[i*2+1] = H[mac[i]&15]; }
    out[32] = 0;
    (*e)->ReleaseStringUTFChars(e, token, t);
    (*e)->ReleaseStringUTFChars(e, device, d);
    return (*e)->NewStringUTF(e, out);
}

// SHA256(key|token) 32B —— 隧道流 XOR 密钥
JNIEXPORT jbyteArray JNICALL
Java_com_chsi_app_Native_streamKey(JNIEnv *e, jclass c, jstring token){
    (void)c;
    const char *t = (*e)->GetStringUTFChars(e, token, NULL);
    char msg[128];
    snprintf(msg, sizeof msg, "%s|%s", unmask(K1, (int)sizeof K1), t);
    unsigned char o[32]; sha256_ctx cx;
    sha256_init(&cx); sha256_update(&cx, msg, strlen(msg)); sha256_final(&cx, o);
    (*e)->ReleaseStringUTFChars(e, token, t);
    jbyteArray r = (*e)->NewByteArray(e, 32);
    (*e)->SetByteArrayRegion(e, r, 0, 32, (const jbyte *)o);
    return r;
}

// 签名期望值（重打包检测）
JNIEXPORT jstring JNICALL
Java_com_chsi_app_Native_expectedSig(JNIEnv *e, jclass c){
    (void)c; (void)e;
    return (*e)->NewStringUTF(e, unmask(S1, (int)sizeof S1));
}

/* ================= L7：反调试 / 反 Frida ================= */
static int port_open(int port){
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; int r;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    r = connect(s, (struct sockaddr *)&a, sizeof a);
    close(s);
    return r == 0;
}

static int has_string(const char *path, const char *needle){
    FILE *f = fopen(path, "r"); char line[512];
    if (!f) return 0;
    while (fgets(line, sizeof line, f)){
        if (strstr(line, needle)){ fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

JNIEXPORT jboolean JNICALL
Java_com_chsi_app_Native_isCompromised(JNIEnv *e, jclass c){
    (void)e; (void)c;
    FILE *f; char line[256];
    // 1. 调试器附加
    f = fopen("/proc/self/status", "r");
    if (f){
        while (fgets(line, sizeof line, f)){
            if (strncmp(line, "TracerPid:", 10) == 0){
                int pid = atoi(line + 10);
                fclose(f);
                if (pid != 0) return JNI_TRUE;
                break;
            }
        }
        if (f) fclose(f);
    }
    // 2. Frida 默认端口
    if (port_open(27042) || port_open(27043)) return JNI_TRUE;
    // 3. 注入框架特征
    {
        const char *bad[] = {"frida", "gum-js-loop", "gadget", "Xposed", "LSPosed", "edxp", "substrate"};
        for (int i = 0; i < 7; i++) if (has_string("/proc/self/maps", bad[i])) return JNI_TRUE;
    }
    // 4. 进程处于被调试停止态
    if (has_string("/proc/self/status", "State:\tT")) return JNI_TRUE;
    return JNI_FALSE;
}
