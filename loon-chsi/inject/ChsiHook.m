// ============================================================
// ChsiHook.m —— QQ/微信 内置 WebView 注入 dylib
//   v4：QQ/微信自己的「设置」页插一行入口 + App 内编辑器
//   v3：字段值可在 iOS「设置」里改（Settings.bundle 面板，保留作回退）
//
// 规则来源：chsi-report-rewrite.js（FIELD_RULES 13 项 + 离校日期→预计毕业日期改名）
//
// ⚠️ v4 变更（2026-09-19）：设置入口搬进 QQ/微信原生「设置」页 ——
//   hook UIViewController.viewDidAppear: 探测设置页（微信=社区已知类名
//   NewSettingViewController 等；QQ=运行时 objc_copyClassList 扫描含
//   setting 的控制器类 + 标题「设置」判别），找到页内 UITableView 后
//   swizzle 数据源/代理在最后追加一行「学信网报告改写」，点开是内置
//   编辑器 ChsiEditorVC（纯公开 UIKit UITableViewController），实时写
//   本 App 沙箱内的配置 plist（EffectiveRules 最高优先层；
//   ⚠️ v4.1.9 起 QQ 与微信各存各的，不共享）。
//   探测/插行失败一律静默降级（不影响 WKWebView 注入主功能）；
//   探测记录写 /var/mobile/Library/ChsiHook/probe.log 供定位 QQ 类名。
//   安全约束（吸取 v1 教训）：
//     * 所有被 swizzle 的方法参数只含 ObjC 对象 / 基本类型；
//     * 可选 delegate 方法仅在宿主已实现时才 hook；
//     * 行为改动用关联对象 tag 守卫，未插行的表格全部直通原始实现。
//
// ⚠️ v4.1 变更（2026-09-19 晚）：实测 v4 在 QQ 设置页未插出行、
//   微信注入即闪退 —— 入口改为「App 内悬浮球」：
//   * 启动 2 秒后主线程创建 44×44 独立 UIWindow（绑定 foreground
//     UIWindowScene；windowLevel 高于 Alert；【不调 makeKeyAndVisible】
//     不抢宿主 key 状态），可拖动、左右吸边、位置记忆
//     （NSUserDefaults chsi_float_x/y），点按打开编辑器。
//   * 编辑器加「显示悬浮球」开关（NSUserDefaults chsi_float，默认开）。
//   * 插行模块整体停用（ChsiInstallSettingsRowModule 直接 return，
//     代码保留便于日后重启）；
//     若 v4.1 微信不再闪退 → 闪退来自插行 hook；
//     若仍闪退 → 基本可定性微信反注入（抓 .ips 确认后放弃微信路线）。
//
// ⚠️ v4.1.1 修复（2026-09-19 晚，用户实测反馈）：
//   症状：QQ 里球能看见，但球点不动、**QQ 整个 App 也都点不动**。
//   根因（两个错误叠加，都在触摸链路）：
//     (1) 原实现球是「全屏透明承载层」的子视图，而承载层
//         userInteractionEnabled=NO —— iOS 的阻断规则是**父视图禁用
//         会连带禁用全部子视图**，所以球的手势一个都不生效；
//     (2) 就算把承载层改成 YES，铺满全屏的透明窗口仍然会把整个 App
//         的触摸全部接走（透明 ≠ 触摸穿透，命中测试只看 frame 与
//         userInteractionEnabled），宿主自己的按钮全点不动。
//   修法：窗口尺寸 = 球尺寸、球自己就是 rootVC.view（无承载层）。
//         窗口只在球的 44×44 内参与 hit-test，球外区域系统直接
//         交给下层窗口，天然穿透；拖动时同步移动窗口 frame。
//
// ⚠️ v4.1.2 调整（2026-09-19 晚，用户要求）：
//   * 球上不再显示「改」字（纯色蓝圆球）；
//   * 编辑器改为**独立小窗口**呈现（v4.1.5）：
//     自建 UIWindow（windowLevel = Alert+200）承载 UINavigationController，
//     窗口铺满以承接「点遮罩关闭」，nav.view 缩成居中卡片（≤340×520、
//     圆角 12）——尺寸完全自定，不经过 formSheet 的系统约束。
//     ⚠️ 必须显式不聚焦输入框：早期用 presentViewController + formSheet
//     时，点球后弹出的是系统**键盘输入候选浮层**（白色小方块带蓝色字影），
//     编辑器本体没显示出来。现在 viewDidLoad/viewDidAppear 都
//     endEditing:YES，只有用户主动点输入框才弹键盘。
//
// ⚠️ v3 机制（保留）：字段值也可在 iOS 系统「设置」里改（Settings.bundle）——
//   设置入口 = iOS 系统「设置」App → QQ（或微信）页内的面板，
//   由随包携带的 Settings.bundle 提供（用户用 Filza 把 Settings.bundle
//   拷进 QQ.app / WeChat.app 根目录即可，非代码资源免重签）。
//   面板把值写进宿主 App 的偏好域（Library/Preferences/<bundleid>.plist），
//   dylib 每次生成注入 JS 前实时读取 —— 改完设置刷新页面即生效。
//
//   值的读取优先级（高 → 低）：
//     1) 本 App 沙箱内的配置 plist：
//        <App 沙箱>/Library/Preferences/com.chsihook.rules.plist
//        （编辑器写入；⚠️ v4.1.9 起 QQ 与微信各存各的，互不共享）
//     2) 设置面板：CFPreferences 键 chsi_f01..chsi_f13（本 App 域）
//        键从未设置 → 用默认；显式空字符串 → 清空该字段值
//     3) 内置默认（FieldSpecsOrdered 的第三列）
//   总开关 chsi_enabled（面板开关）；关 = 不改任何内容（改名也停）。
//
// ⚠️ JS 热更机制
//   每次注入的 JS 带 VER（= 规则内容 hash）。同一页面重复注入时：
//   VER 相同 → 直接空跑；VER 不同（用户改了设置）→ 重新定义
//   window.__chsiRewrite 覆盖旧版（旧 MutationObserver 回调动态查找
//   window.__chsiRewrite，自动用上新版）；observer/定次重试仅首次安装。
//   所以「改设置 → 刷新页面」后 loadRequest 兜底 evaluateJavaScript
//   会把页面切换到新规则，无需任何 App 内操作。
//
// ⚠️ v2 机制（保持）：全公开 API ——
//   主路径 swizzle 公开 init initWithFrame:configuration:，在原始 init
//   【之前】把 WKUserScript（AtDocumentEnd、含子框架）装进
//   configuration.userContentController（WKWebView init 会 copy
//   configuration，必须 init 前装）。
//   兜底 swizzle 公开 loadRequest: / loadHTMLString:baseURL: /
//   loadFileURL: / loadData:...，之后 evaluateJavaScript 定次补改。
//   v1 教训：swizzle 私有方法 _didFinishNavigation: 的参数是 WebKit
//   C++ 对象 API::Navigation*，ARC 对 id 参数执行 objc_storeStrong →
//   retain C++ 对象 → SIGSEGV。本文件所有 swizzle 目标均为公开 API。
//
// ⚠️ 微信兼容
//   hook 的是 WKWebView 公开 API，与宿主无关；ChsiHook.plist 的
//   Bundle 过滤已加 com.tencent.xin。QQ 与微信的配置完全独立
//   （⚠️ v4.1.9：各自写在各自沙箱，不存在任何共享通道）；
//   想让两端一致就各填一次。
//
// 免责：仅用于本机截图/演示。不改动学信网服务器数据。
// ============================================================

// v4.6.15 防破解：这两个头**必须 textual include 且在所有模块化 import 之前**
// （放 Foundation 之后会撞 clang module：「definition of 'kinfo_proc' must be
//   imported from module 'Darwin.sys.sysctl'」，CI 实测连挂）
#include <sys/sysctl.h>
#include <mach-o/dyld.h>

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <CoreFoundation/CoreFoundation.h>
#import <WebKit/WebKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
// v4.6.44 全下发：QQ 端二进制不再编入 JS 模板密文（改写脚本只在服务器上，
//   /check 响应加密下发）。WX 无服务器，仍走内置密文。
#if defined(CHSI_BUILD_WX)
#import "ChsiJSPayload.h"   // WX 专属：注入 JS 模板密文（_pack_js.py 生成）
#endif

// ==================== 可配置区 ====================

// 兜底路径（evaluateJavaScript）总执行次数与间隔（毫秒）。
// 主路径（WKUserScript）就位后这些执行大多是"已安装"空跑，开销可忽略。
static const int kRepatchCount = 5;
static const int kRepatchIntervalMS = 400;

// 检测到页面就改写（默认 NO）。置 YES 只处理 chsi.com.cn（仅兜底路径生效）。
static const BOOL kOnlyChsiHost = NO;

// 调试日志
static const BOOL kVerboseLog = YES;

// ==================== v4.1 构建宏区（双包拆分）====================
// 同一份源码编两个独立 dylib（互相不影响，微信崩了 QQ 照常用）：
//   ChsiHookQQ.dylib → CFLAGS -DCHSI_BUILD_QQ → bundle 过滤只放行 com.tencent.mqq
//   ChsiHookWX.dylib → CFLAGS -DCHSI_BUILD_WX → bundle 过滤只放行 com.tencent.xin
// 两个宏都没定义 = UNI 单包（本地调试用，不过滤 bundle）。
#if defined(CHSI_BUILD_QQ) && defined(CHSI_BUILD_WX)
#error "CHSI_BUILD_QQ 与 CHSI_BUILD_WX 不能同时定义"
#elif defined(CHSI_BUILD_QQ)
#define CHSI_BUILD_TAG "QQ"
static NSString * const kChsiWantedBundle = @"com.tencent.mqq";
#elif defined(CHSI_BUILD_WX)
#define CHSI_BUILD_TAG "WX"
static NSString * const kChsiWantedBundle = @"com.tencent.xin";
#else
#define CHSI_BUILD_TAG "UNI"
static NSString * const kChsiWantedBundle = nil;   // 不过滤
#endif

// 编译期重启 v4 插行模块（默认停用）：给 CFLAGS 加 -DCHSI_KEEP_SETTINGS_ROW
// #define CHSI_KEEP_SETTINGS_ROW   ← 不在此处定义，走 CFLAGS

// ==================== 字段规格（单一数据源）====================

// 三元组：设置面板键 / 标签文字（= 改写目标）/ 内置默认值
// 空字符串默认值 = 清空该字段值
// ⚠️ Settings.bundle/Root.plist 的键与默认值必须与此处一致
static NSArray *FieldSpecsOrdered(void) {
    static NSArray *arr = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        arr = @[
            @[@"chsi_f01", @"学校名称",   @"清华大学"],
            @[@"chsi_f02", @"层次",       @"本科"],
            @[@"chsi_f03", @"专业",       @"智能科学与技术"],
            @[@"chsi_f04", @"学制",       @"4 年"],
            @[@"chsi_f05", @"学历类别",   @"普通高等教育"],
            @[@"chsi_f06", @"学习形式",   @"普通全日制"],
            @[@"chsi_f07", @"分院",       @""],
            @[@"chsi_f08", @"系所",       @"多智能体"],
            @[@"chsi_f09", @"入学日期",   @"2025年08月31日"],
            @[@"chsi_f10", @"学籍状态",   @"在籍（注册学籍）"],
            @[@"chsi_f11", @"预计毕业日期", @"2029年07月01日"],
            @[@"chsi_f12", @"离校日期",   @"2029年07月01日"],
            @[@"chsi_f13", @"在线验证码", @"DEMO1234ABCD5678"],
            // v4.6.44：姓名/照片 —— **默认不修改页面**（留空 = 无规则，与
            //   其它字段「内置默认值兜底 / 空串=清空」语义不同，见
            //   EffectiveRules 的 noopDefault 分支）。照片存 data URI。
            @[@"chsi_f14", @"姓名",       @""],
            // v4.6.44：性别 —— 同姓名语义（留空 = 不改写；填 男/女 才改）
            @[@"chsi_f17", @"性别",       @""],
            // v4.6.44：网页自动登录凭据（opt-in 留空=不启用）。走 RULES 通道
            //   传给 JS 的 autoLogin()，纯内存不落盘、不进探针日志、不上服务器。
            @[@"chsi_f18", @"学信网账号",  @""],
            @[@"chsi_f19", @"学信网密码",  @""],
            // v4.6.44：更新日期 —— 同姓名语义（留空 = 不改写页面）
            @[@"chsi_f16", @"更新日期",   @""],
            @[@"chsi_f15", @"照片",       @""],
        ];
    });
    return arr;
}

// 标签改名规则（固定内置；对应仓库 JS 的"离校日期 → 预计毕业日期"）
static NSArray *RenameRulesOrdered(void) {
    static NSArray *arr = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        arr = @[ @[@"离校日期", @"预计毕业日期"] ];
    });
    return arr;
}

// ==================== 配置读取 ====================

// 进阶路线：本机覆盖配置，键 = 字段名，值 = 字符串/数字
// 例：{ "enabled" : true, "学校名称" : "清华大学" }
// 没有这个文件就完全跳过此层，不影响设置面板路线。
// ⚠️ v4.1.6：配置路径改造。
//   旧路径 /var/mobile/Library/Preferences/com.chsihook.rules.plist 是
//   **全局** Preferences 目录，QQ/微信这类沙箱 App **没有写权限** ——
//   编辑器里 writeToFile 静默失败，用户改的值全部丢失（实测：填
//   「哈佛大学」点完成，页面仍显示「清华大学」= 内置默认值）。
//   新方案：写**App 自己沙箱**内的 Library/Preferences/（必定可写）。
//   读取顺序：① 沙箱内文件（编辑器写的）；② 无 → 回退面板 / 内置默认。
// ⚠️ v4.1.9：**QQ 与微信配置彻底不共享**。原先沙箱内文件读不到时会
//   回退读全局旧路径，而全局文件是两端进程都能读到的 —— 等于留了
//   一条「改一端、另一端跟着变」的暗道，本次整条删除。
//   现在每个 App 只认自己沙箱里的那份：QQ 填「哈佛大学」不会影响
//   微信，反之亦然。要让两端一致就各自填一次。
static NSString *ChsiConfigPath(void) {
    NSString *home = NSHomeDirectory();   // App 沙箱根
    NSString *dir = [home stringByAppendingPathComponent:@"Library/Preferences"];
    // 目录不存在则创建
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:dir]) {
        [fm createDirectoryAtPath:dir
      withIntermediateDirectories:YES
                       attributes:nil
                            error:NULL];
    }
    return [dir stringByAppendingPathComponent:@"com.chsihook.rules.plist"];
}

// v4.3.5：QQ 端**不再本地存储任何插件配置** —— 改写值、总开关、手动 QQ 号
// 全部只存活在**当前进程的内存**里；每次打开 QQ 都回到内置默认值，必须重新输。
// （微信端行为一律不变，仍按 v4.1.9 起的方式存本 App 沙箱。）
#if defined(CHSI_BUILD_QQ)
static NSMutableDictionary *gCfgMem = nil;     // 覆盖层（v4.6.44 起落盘持久 + 内存缓存）
static void ChsiNoStorePurge(void);            // 定义在下面「QQ 号」那一节
// v4.6.44：前置声明（磁盘恢复日志在定义前用到 CHLog，-Werror 会炸）
static void CHLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
// v4.6.44：字段配置落盘路径（用户要求：除授权码外全部持久化，切后台/杀 QQ 不丢）。
//   授权码仍纯内存（gLicenseState 链路没动）；此 plist 只含字段值 + enabled 开关。
static NSString *ChsiQQCfgDiskPath(void) {
    return @"/var/mobile/Library/ChsiHook/qq-cfg.plist";
}
#endif

// 读本 App 覆盖配置
//   QQ 包：内存缓存优先；冷启动从磁盘加载（v4.6.44 持久化）；
//   WX 包：照旧读沙箱内 plist。
static NSDictionary *ChsiConfigRead(void) {
#if defined(CHSI_BUILD_QQ)
    ChsiNoStorePurge();
    if (!gCfgMem) {
        // v4.6.44：冷启动从磁盘恢复字段配置（除授权码外全持久化）
        gCfgMem = [NSMutableDictionary dictionaryWithContentsOfFile:ChsiQQCfgDiskPath()];
        if (gCfgMem) CHLog(@"配置已从磁盘恢复 %lu 项", (unsigned long)gCfgMem.count);
    }
    return gCfgMem ? (NSDictionary *)gCfgMem : @{};
#else
    return [NSDictionary dictionaryWithContentsOfFile:ChsiConfigPath()];
#endif
}

// 读设置面板写进宿主 App 偏好域的值（键存在返回 NSString，可能为 @""；不存在返回 nil）
static NSString *ReadPanelValue(NSString *key) {
    CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
    CFTypeRef v = CFPreferencesCopyAppValue((__bridge CFStringRef)key,
                                            kCFPreferencesCurrentApplication);
    if (!v) return nil;
    id obj = (__bridge_transfer id)v;   // ARC 接管
    if ([obj isKindOfClass:[NSString class]]) return obj;
    if ([obj isKindOfClass:[NSNumber class]]) return [(NSNumber *)obj stringValue];
    return nil;
}

// 总开关：本机覆盖配置的 enabled > 面板 chsi_enabled（键不存在 = 开）
static BOOL ChsiEnabled(void) {
    NSDictionary *shared = ChsiConfigRead();
    if (shared && shared[@"enabled"] != nil) return [shared[@"enabled"] boolValue];

    CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);
    CFTypeRef v = CFPreferencesCopyAppValue(CFSTR("chsi_enabled"),
                                            kCFPreferencesCurrentApplication);
    if (!v) return YES;
    BOOL on = YES;
    if ([(__bridge id)v respondsToSelector:@selector(boolValue)]) {
        on = [(__bridge id)v boolValue];
    }
    CFRelease(v);
    return on;
}

// 当前生效规则（label → value），按上面写的优先级合并
// ⚠️ v4.6.0：**空字符串一律视为「无覆盖」**，继续往下一层回落。
//   🔴 修用户实测 bug：把「学校名称」改成别的值、再**删空**它，再次改写时
//     字段变空白（没有回到内置默认「清华大学」）。
//     老逻辑 `shared[label] != nil` 会把空串当有效覆盖 → 命中空串 → 页面渲染空。
//     现在统一语义：**删空 = 恢复默认**。
static NSArray *EffectiveRules(void) {
    NSDictionary *shared = ChsiConfigRead();
    NSMutableArray *out = [NSMutableArray array];
    for (NSArray *spec in FieldSpecsOrdered()) {
        NSString *label = spec[1];
        NSString *dft   = spec[2];
        // v4.6.44：姓名/更新日期 = 留空不生成规则（不改写页面）；照片走
        //   EffectivePhoto 的独立链路，永远不进文本规则。
        BOOL isPhoto = [label isEqualToString:@"照片"];
        BOOL isOptIn = [label isEqualToString:@"姓名"] ||
                       [label isEqualToString:@"更新日期"] ||
                       [label isEqualToString:@"性别"] ||
                       [label isEqualToString:@"学信网账号"] ||
                       [label isEqualToString:@"学信网密码"];
        if (isPhoto) continue;
        NSString *val = nil;
        if (shared && shared[label] != nil) {
            NSString *s = [NSString stringWithFormat:@"%@", shared[label]];
            if (s.length > 0) val = s;   // 空串 = 无覆盖
        }
        if (val == nil) {
            NSString *pv = ReadPanelValue(spec[0]);
            if (pv != nil && pv.length > 0) val = pv;
        }
        if (val == nil) {
            if (isOptIn) continue;       // v4.6.44：姓名/更新日期无覆盖 = 不改写
            val = dft;
        }
        // 🔴 v4.6.8：用户要求 —— 字段值输入「null」= **改写为空白**。
        //   与「留空」区分：空串 = 无覆盖（回落默认值）；「null」= 显式
        //   要求该字段写空白（页面渲染成空）。PairsToJS 对空串的输出
        //   就是把 DOM 文本设为 ""，正好是「空白」。
        if ([val isEqualToString:@"null"]) val = @"";
        [out addObject:@[label, val ?: @""]];
    }
    return out;
}

// v4.6.44：本机设置的照片（data URI）——只来自编辑器覆盖值，无内置默认。
//   未设置返回 nil → 注入 JS 的 PHOTO 为空串 → 页面图片不动。
//   QQ 端跟随 gCfgMem（纯内存，重开 QQ 需重选）；WX 端存沙箱 plist。
static NSString *EffectivePhoto(void) {
    NSDictionary *shared = ChsiConfigRead();
    if (shared && shared[@"照片"] != nil) {
        NSString *s = [NSString stringWithFormat:@"%@", shared[@"照片"]];
        if (s.length > 0) return s;
    }
    return nil;
}

// ==================== 日志 ====================

static void CHLog(NSString *fmt, ...) {
    if (!kVerboseLog) return;
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[CHSI-DYLIB] %@", msg);
}

// ==================== v4.3.4：联网授权（码 + 后台双重校验，仅 QQ 包）====================
//
// 每次打开 QQ（含从后台切回）都要重新走一遍：
//   ① 弹框输授权码 —— 码只存内存、绝不落盘，App 一进后台立刻清空
//   ② 拿「码 + QQ 号 + bundle」去后台问一次（v4.3.4：一个 QQ 号一个授权码）
//   ③ 后台同时校验 codes.txt（授权码）和 devices.txt（设备白名单）
//   ④ 两条都过 → 本次会话允许改写；任一不过 → 不改写
// ❗ 严格模式：不留任何离线宽限。连不上后台 / 码错 / 设备不在白名单 = 不改写。
// ❗ 取消授权 = 后台 devices.txt 删掉那行，或 codes.txt 删掉那个码，即刻生效。
// ⚠️ v4.3.4 起不再用 IDFV，改用当前登录 QQ 号（多路径探测，兜底 UNKNOWN-QQ）；
//    删掉腾讯系全部 App 后重装会变 → 新的 ID 要重新加白名单。
// ⚠️ 微信包（CHSI_BUILD_WX）不启用，行为与 v4.1.9 完全一致。
// 🔴 这是访问控制（防止 dylib 被别人拿去用），不是防逆向。
//
// 为什么不用 NSURLSession 发请求：明文 http:// 会被 ATS 拦，而 ATS 开关在
// 宿主 App 的 Info.plist 里，我们改不了。这里直接用 BSD socket 发一个最短
// 的 HTTP/1.1 POST，绕开 ATS，连通性只取决于网络本身，行为确定。

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// 后台验证地址。v4.6.17 起搬回**家庭软路由（网心云 OES）**，走公网 IPv6 直连：
//     http://[2408:8214:3a12:9d20:d851:ebff:fe55:bd27]:8787/check
//   · 接口 ID 是 EUI-64（由 MAC 生成，稳定）；会轮换的是前缀 —— 运营商
//     换前缀后本地址失效，需要改这里重编译。
//   · 光猫 IPv6 防火墙必须关闭（gwfw.py off）才收得到入站 TCP 8787；
//     管理页 http://[同址]:8787/admin 可远程开关防火墙。
// 之前是腾讯云轻量 81.70.90.7:8787（保留可随时切回）。
// ⚠️ 换地址要重新编译（地址是编译期常量，写死在二进制里）。
#if defined(CHSI_BUILD_QQ)
static NSString * const kChsiLicenseURL =
    @"http://[2408:8214:3a12:9d20:d851:ebff:fe55:bd27]:8787/check";
#endif

// ==================== v4.6.15 防破解 · 加密工具（两包公用）====================
// 威胁模型：
//   ① 二进制破解 —— patch gSessionVerified / gLicenseState 直接放行；
//   ② 网络侧破解 —— mitmproxy 等伪造后台响应 {"ok":true} 重放放行。
// 对策：
//   A. 注入 JS 模板**密文**进二进制（ChsiJSPayload.h），解密密钥 QQ 端
//      **由服务器在授权响应里下发**（jskey），patch 内存标记拿不到密钥 →
//      解密失败 → 注入空脚本 → 改写功能整体失效（功能绑定加密）；
//   B. 授权响应带 HMAC-SHA256 签名（SECRET 只在服务器 + dylib 里，不过网），
//      覆盖 qq|exp|nonce|jskey —— 伪造响应没有 SECRET 签不出来；
//      nonce 由手机端每次随机生成并在响应里回验（防预存重放）；
//      exp 短时效（60 分钟），过期清密钥并静默复验（防抓包重放过期凭据）。
// ============================================================================

// ---- 授权协议 SECRET（分段组装，不以完整字面量进二进制）----
#if defined(CHSI_BUILD_QQ)   // 仅 QQ 授权链路使用（WX 无服务器，包内无 HMAC 调用点）
static NSString *ChsiSecret(void) {
    static NSString *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        static const char p1[] = {'C','h','s','i','H','o','o','k','#','v','5','#'};
        static const char p2[] = {'4','a','7','d','9','1','f','2'};
        static const char p3[] = {'#','l','i','c','e','n','s','e'};
        NSMutableString *m = [NSMutableString string];
        for (unsigned i = 0; i < sizeof(p1); i++) [m appendFormat:@"%c", p1[i]];
        for (unsigned i = 0; i < sizeof(p2); i++) [m appendFormat:@"%c", p2[i]];
        for (unsigned i = 0; i < sizeof(p3); i++) [m appendFormat:@"%c", p3[i]];
        s = m;   // = "ChsiHook#v5#4a7d91f2#license"（与服务器 CHSI_SECRET 一致）
    });
    return s;
}

static NSString *ChsiHex(NSData *d) {
    const unsigned char *b = (const unsigned char *)d.bytes;
    NSMutableString *h = [NSMutableString stringWithCapacity:d.length * 2];
    for (NSUInteger i = 0; i < d.length; i++) [h appendFormat:@"%02x", b[i]];
    return h;
}

// HMAC-SHA256(key, msg) → hex 小写
static NSString *ChsiHmacHex(NSString *key, NSString *msg) {
    NSData *kd = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *md = [msg dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, kd.bytes, kd.length, md.bytes, md.length, mac);
    return ChsiHex([NSData dataWithBytes:mac length:CC_SHA256_DIGEST_LENGTH]);
}
#endif   // CHSI_BUILD_QQ（ChsiSecret / ChsiHmacHex）

// ---- 会话密钥状态（QQ 专属；WX 无授权体系，密钥本地混淆内置）----
#if defined(CHSI_BUILD_QQ)
static NSString *gJSKeyHex = nil;   // 服务器下发的 jskey（64 hex = 32B）
static double gSessExp = 0;         // 会话到期时刻（Unix 秒，服务器下发）
static NSString *gLastNonce = nil;  // 本次验证请求的挑战串（响应里回验）
// v4.6.44 全下发：改写脚本密文（服务器 /check 下发，jskey 加密）+ 脚本版本
//   内存驻留，绝不落盘；重启/复验时随响应刷新。服务器不下发 = 零改写（远程断供）。
static NSData *gRemoteJSEnc = nil;  // hex 解码后的脚本密文
static NSInteger gJSVer = -1;       // 脚本版本号（会话内只升不降，防降级回放）
// 前置声明（定义在文件后段 probe 日志节；js-deliver 探针在授权解析里要先打）
static void ChsiFloatDiag(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
#endif

#if defined(CHSI_BUILD_WX)
// WX 无服务器：K_BLOB 以异或掩码拆成 8 个 uint32 内置（_pack_js.py 生成）
static const uint32_t kChsiKeyObf[8] = { 0x5959f7c8, 0x009f55cf, 0x11b07a85, 0x05b5c7f9, 0x672e1926, 0x3fcb0238, 0x1ce4ee01, 0x499ab723 };
static const uint32_t kChsiKeyMask = 0x5a3c69a7u;
static NSString *ChsiWXJSKeyHex(void) {
    static BOOL sLogged = NO;
    if (!sLogged) { sLogged = YES; CHLog(@"wxkey ready"); }
    NSMutableString *h = [NSMutableString stringWithCapacity:64];
    for (int i = 0; i < 8; i++) [h appendFormat:@"%08x", kChsiKeyObf[i] ^ kChsiKeyMask];
    return h;
}
#endif

// v4.6.44：解密器参数化 —— 输入任意密文 blob + 32B 密钥，输出明文。
//   QQ：blob = 服务器下发的 gRemoteJSEnc，key = 会话 jskey（全下发，二进制零脚本）。
//   WX：blob = 内置 gChsiJSBlob，key = 本地混淆密钥（无服务器，维持 v4.6.15 方案）。
//   magic 校验失败（密钥不对/密文被改）→ nil → 注入空脚本。
static NSData *ChsiJSBlobDecrypt(NSData *enc, NSString *keyHex) {
    if (keyHex.length != 64 || enc.length < 16) return nil;
    unsigned char key[32];
    const char *hx = keyHex.UTF8String;
    for (int i = 0; i < 32; i++) {
        unsigned v = 0;
        sscanf(hx + i * 2, "%2x", &v);
        key[i] = (unsigned char)v;
    }
    NSUInteger len = enc.length;
    NSMutableData *out = [NSMutableData dataWithLength:len];
    unsigned char *o = (unsigned char *)out.mutableBytes;
    const unsigned char *src = (const unsigned char *)enc.bytes;
    uint32_t blocks = (uint32_t)((len + 31) / 32);
    for (uint32_t bIdx = 0; bIdx < blocks; bIdx++) {
        unsigned char in[36];
        memcpy(in, key, 32);
        in[32] = (unsigned char)(bIdx & 0xff);
        in[33] = (unsigned char)((bIdx >> 8) & 0xff);
        in[34] = (unsigned char)((bIdx >> 16) & 0xff);
        in[35] = (unsigned char)((bIdx >> 24) & 0xff);
        unsigned char ks[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(in, 36, ks);
        NSUInteger n = len - (NSUInteger)bIdx * 32;
        if (n > 32) n = 32;
        for (NSUInteger i = 0; i < n; i++)
            o[(NSUInteger)bIdx * 32 + i] = src[(NSUInteger)bIdx * 32 + i] ^ ks[i];
    }
    // magic 校验：密钥不对 → 明文是乱码 → 拒绝
    if (memcmp(out.bytes, "(function(){", 12) != 0) {
        CHLog(@"jscore decrypt FAIL len=%lu", (unsigned long)out.length);
        return nil;
    }
    return out;
}

// v4.6.44：按包取「当前应注入的脚本密文 + 密钥」再解密（带缓存）。
static NSData *ChsiJSPayloadDecrypt(void) {
#if defined(CHSI_BUILD_QQ)
    // QQ 全下发：密文来自服务器响应（内存驻留）；无 jskey / 无下发 → nil。
    NSString *keyHex = gJSKeyHex;
    NSData *enc = gRemoteJSEnc;
    if (keyHex.length != 64 || enc.length < 16) return nil;
    static NSData *sCache = nil;
    static NSString *sCacheKey = nil;
    static NSData *sCacheEnc = nil;
    if (sCache && [sCacheKey isEqualToString:keyHex] && [sCacheEnc isEqualToData:enc]) return sCache;
    NSData *out = ChsiJSBlobDecrypt(enc, keyHex);
    if (!out) return nil;
    CHLog(@"remote-js unlock bytes=%lu", (unsigned long)out.length);
    sCache = out;
    sCacheKey = [keyHex copy];
    sCacheEnc = [enc copy];
    return out;
#else
    NSString *keyHex = ChsiWXJSKeyHex();
    if (keyHex.length != 64) return nil;
    static NSData *sCache = nil;
    static NSString *sCacheKey = nil;
    if (sCache && [sCacheKey isEqualToString:keyHex]) return sCache;
    NSData *enc = [NSData dataWithBytes:gChsiJSBlob length:CHSI_JS_BLOB_LEN];
    NSData *out = ChsiJSBlobDecrypt(enc, keyHex);
    if (!out) return nil;
    CHLog(@"jscore unlock bytes=%lu", (unsigned long)out.length);
    sCache = out;
    sCacheKey = [keyHex copy];
    return out;
#endif
}

typedef NS_ENUM(NSInteger, ChsiLicenseState) {
    ChsiLicensePending = 0,   // 还没问到结果（默认 = 不改写）
    ChsiLicenseGranted,       // 后台确认：码 + 设备都过
    ChsiLicenseDenied,        // 拒绝 / 连不上 / 出错 / 没输码
};

static volatile NSInteger gLicenseState = ChsiLicensePending;

// 前台/后台通知观察者必须强引用持有，否则 ARC 一放就收不到通知了
static id gChsiActiveObserver = nil;
static id gChsiBgObserver = nil;

// 本次会话输入的授权码：只存内存，进后台立刻清空（严格模式）
static NSString *gEnteredCode = nil;
#if defined(CHSI_BUILD_QQ)
static BOOL gPrompting = NO;
static NSInteger gPromptRetry = 0;
// v4.3.7：弹框存活看门狗计数（弹框被宿主换掉后重弹，最多 6 次）
static NSInteger gPromptWatchdog = 0;
// v4.3.6：gPrompting 置位的时间戳。用来做看门狗 —— 置位后 15 秒还没复位
// 就说明上一次 present 根本没成功（宿主 VC 被换掉 / 窗口已销毁），
// 强制复位，否则之后所有弹框请求都会被 `if (gPrompting) return` 吞掉。
static NSTimeInterval gPromptSince = 0;
// v4.5.1：🔴 记住**我们自己 present 出去的那个 alert 实例**。
//   为什么必须记实例：v4.5.0 的看门狗靠「沿 keyWindow→rootVC 的
//   presentedViewController 链找 UIAlertController」来判断弹框在不在屏上。
//   而**授权框输入时键盘会弹出，键盘窗口成为 keyWindow** ——
//   ChsiTopVC() 这时拿到的是**键盘窗口**那条链，链里当然没有我们的 alert
//   → 看门狗误判「弹框已不在屏上」→ 重弹 → **把用户刚输的内容清空**。
//   这就是真机反馈的「输入时间不够」（其实不是时间不够，是输入被反复打断）。
//   ⇒ 修法：不猜，直接记实例 + 查它的 view.window。
static __weak UIAlertController *gActiveAlert = nil;
// v4.5.1：用户是否正在这个弹框里打字。正在打字时看门狗一律不动它。
static BOOL gAlertEditing = NO;
// v4.5.2：🔴🔴 原 `gVerifyFromPrompt` 已**删除**，改用请求序号（见下）。
//   它的问题：用户点「验证」置 YES → 请求飞行中 QQ 恰好发 DidBecomeActive
//   → ChsiLicenseRefresh() 又置回 NO → 后台响应回来时成功分支被判成
//   「自动重验」→ **静默，成功弹窗永不出现**（真机反馈「没有授权成功提示」）。
//   序号方案：发起请求时记下序号，响应回来比对，不受任何自动流程干扰。
// v4.5.2：用户主动验证的请求序号。0 = 当前没有「用户主动」请求在飞。
static NSInteger gUserVerifySeq = 0;
// v4.5.2：全局请求自增序号，每次 ChsiLicenseVerify 都会 +1。
static NSInteger gVerifySeqCounter = 0;
// v4.5.5：本会话「用户主动验证成功过」的标记。
//   真机反馈：v4.5.4 验证**成功**了，之后还会**再弹一次输入授权码**。
//   根因：`ChsiLicenseRefresh()` 只判 `gEnteredCode.length == 0` 就弹框要码，
//   而 `gEnteredCode` 会被 `ChsiLicenseInvalidate()`（进后台）/「重新输入」清成 nil。
//   点「验证」时输入框 alert 被 dismiss（键盘收起）会让 iOS 补发一次
//   `DidBecomeActive` → 触发 Refresh → 此时若 gEnteredCode 恰好为空 → 重弹。
//   ⇒ 用这个标记表达真正的产品语义：**本会话已成功授权过，就绝不再要码。**
//     只有「用户主动改 QQ 号 / 主动点重新输入」才把它清掉。
static BOOL gSessionVerified = NO;
// v4.5.6：🔴🔴 **弹框"单飞"令牌** —— 彻底根治「一打开弹 2 次 / 认证完又弹一次 /
//   取消要点两次才退出」这一组现象。
//   真机反馈（v4.5.5）：① 一打开连续弹 2 个授权框；② 认证成功后还会再弹；
//   ③ **点第一次「取消」QQ 不闪退，点第二次才闪退**。
//   ③ 是铁证：`ChsiCancelQuit()` 每次点击都必然 SIGKILL，要死两次
//   ⇒ **同时有两个 alert 实例在屏上**，第一次只消费掉其中一个。
//   根因：`ChsiLicensePrompt()` 的并发守卫有缺口 ——
//     · 非主线程分支先 `dispatch_async` 再 return，**没置 `gPrompting`**；
//     · 「拿不到宿主 → 重试」分支也是**先 return、后置位**，中间这段窗口期
//       `gPrompting == NO`，第二个入口照样能穿过守卫 → 并排弹两个框；
//     · 两个框都 present 成功后 `gActiveAlert` 被后者覆盖，前一个成"幽灵"
//       （既不在 gActiveAlert 里、也 dismiss 不到），于是它的「取消」按钮
//       点下去会被"吞"（其实是被上层框挡住），要点两次。
//   ⇒ 修法：进入 `ChsiLicensePrompt()` **第一件事就是抢这个令牌**（原子地
//     test-and-set），拿不到就立刻 return；令牌只在
//     「弹框已 dismiss / 用户已点掉 / 弹框流程放弃」时才归还。
//     这样无论有多少个入口（+load 延时 / DidBecomeActive / 编辑器 / 失败重输）
//     并发调用，同一时刻**只可能有一个弹框流程**存在。
static BOOL gPromptInFlight = NO;
#endif

// 互相引用，先声明（WX 包 Prompt 无定义，声明也一起条件编译）
#if defined(CHSI_BUILD_QQ)
static void ChsiLicenseVerify(NSString *code);
// v4.5.2：带「是否用户主动」的验证入口 —— 授权框「验证」按钮里会先于定义调用它，
//   所以必须在这里前置声明，否则 -Werror 下报 implicit declaration。
static void ChsiLicenseVerifyFrom(NSString *code, BOOL fromUser);
static void ChsiLicensePrompt(void);
static void ChsiProbeLog(NSString *line);   // 定义在 probe 日志那节（QQ/WX 都有）
#endif
// ChsiTopVC 定义在文件后面（v4 编辑器呈现那节），这里先声明一下。
// 直接用现成那份，不另写一份：CI 开 -Werror，[UIApplication windows] /
// keyWindow 都是 deprecated，现成那份已经用 objc_msgSend 绕开了。
static UIViewController *ChsiTopVC(void);

// ============================================================
// v4.5.3：🔴🔴🔴 **找「可用的呈现宿主」不再依赖 keyWindow。**
// ------------------------------------------------------------
// 真机反馈（第七轮）：「还是没有弹窗」。
//   真因：旧写法走 `[UIApplication keyWindow].rootViewController`，而
//   **keyWindow 是「当前接收键盘的那个窗口」**——
//     · 授权框一输入，键盘窗口成为 keyWindow → 拿到键盘那条链 → 没有 QQ 的 VC；
//     · 我们自己的 toast 窗口（Alert+500）、编辑器窗口（Alert+200）
//       也都会在某些时刻抢走 keyWindow；
//     · QQ 在 iOS17 场景化生命周期下 keyWindow 还可能是 nil。
//   ⇒ `ChsiShowAlert()` 拿到的宿主时对时错，重试几次后**静默放弃**
//     → 用户「还是没有弹窗」。
//   ⇒ 正确做法：**穷举所有 connectedScenes 的所有 window**，
//     逐个取 `rootViewController` 并沿 presentedViewController 链走到顶，
//     再按「可用性」筛，挑一个真正能 present 的。
//
// ⚠️ 这两个函数**不带 QQ 条件编译** —— 纯 UIKit 窗口枚举，无任何授权字符串；
//    QQ/WX 两个包都要用（编辑器宿主也改走它），放在共同的声明区。
// ============================================================
static NSArray<UIViewController *> *ChsiHostCandidates(void) {
    NSMutableArray<UIViewController *> *out = [NSMutableArray array];
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        // 主路径：遍历所有 scene 的所有 window（含我们自己的编辑器/toast 窗口）
        for (UIScene *sc in app.connectedScenes) {
            if (![sc isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)sc;
            for (UIWindow *w in ws.windows) {
                if (!w.isHidden && w.alpha > 0.01 && w.rootViewController) {
                    [out addObject:w.rootViewController];
                }
            }
        }
        // 兜底：keyWindow（可能为 nil，也可能是键盘窗口 —— 放着，后面会筛掉）
        SEL kw = NSSelectorFromString(@"keyWindow");
        if ([app respondsToSelector:kw]) {
            id win = ((id (*)(id, SEL))objc_msgSend)(app, kw);
            if ([win isKindOfClass:[UIWindow class]] && ((UIWindow *)win).rootViewController) {
                [out addObject:((UIWindow *)win).rootViewController];
            }
        }
    } @catch (NSException *e) {
        CHLog(@"枚举候选宿主异常: %@", e);
    }
    // 去重 + 每个都沿 presentedViewController 链走到顶
    NSMutableArray<UIViewController *> *tops = [NSMutableArray array];
    for (UIViewController *r in out) {
        UIViewController *cur = r;
        @try {
            NSInteger guard = 0;
            while (cur.presentedViewController && guard++ < 12) {
                cur = cur.presentedViewController;
            }
        } @catch (NSException *e) {}
        if (cur && ![tops containsObject:cur]) [tops addObject:cur];
    }
    return tops;
}

// v4.5.3：🔴 从**候选列表**里挑一个真正能 present 的宿主。
//   返回 nil = 暂时都不行（调用方重试）。
static UIViewController *ChsiPickPresentHost(NSString **whyOut) {
    NSArray<UIViewController *> *cands = ChsiHostCandidates();
    NSString *why = nil;
    for (UIViewController *vc in cands) {
        // ① 最上层已经是 alert —— 不能叠第二个
        if ([vc isKindOfClass:[UIAlertController class]]) { why = @"已是alert"; continue; }
        // ② 正在转场 —— UIKit 会拒绝 present
        if (vc.isBeingDismissed) { why = @"转场中(dismiss)"; continue; }
        if (vc.isBeingPresented) { why = @"转场中(present)"; continue; }
        // ③ 已经挂着别的 VC（且不是正在消失的）—— 会拒绝
        UIViewController *pv = vc.presentedViewController;
        if (pv && !pv.isBeingDismissed) { why = @"已有presentedVC"; continue; }
        // ④ view 还没进 window 层级 —— present 上去也看不见
        UIView *v = vc.viewIfLoaded;
        if (!v || !v.window) { why = @"view不在window层级"; continue; }
        if (whyOut) *whyOut = nil;
        return vc;   // 找到可用宿主
    }
    if (whyOut) *whyOut = (why ?: @"无候选窗口");
    return nil;
}

// v4.3.7：🔴 授权弹框**彻底不依赖宿主的 VC 层级**，改挂**自己的独立 UIWindow**。
//    为什么必须这么做（真机连报五轮才定位）：
//      · 登录态下 QQ 启动有转场，刚 present 上去的那个宿主 VC 马上被换掉，
//        挂在它上面的 alert 跟着一起消失 → 「没弹窗」；
//      · 未登录时停在登录页（VC 稳定）→ 反倒看得到弹窗（用户原话：
//        「但我在未登录 qq 的状态下就有弹窗了」）；
//      · 编辑器（Alert+200）也会把弹到主 window 上的 alert 整个盖死；
//      · 后台日志有 v4.3.6 的 __CANCEL__ 遥测 → 弹框**弹出来过、handler 跑了**，
//        但宿主被换后 alert 已经不在屏上，所以既看不到后续弹窗也退不掉。
//    现在：自己开一个 Alert+400 的透明窗口当宿主并临时设为 key —— 弹框必然
//    在最上层、必然活着；弹完立刻拆窗口、把 key 还给 QQ。
//
// 🔴🔴🔴 v4.5.0 最终结论：**「自建全屏窗口」这条路整体废弃**。
//   四版实机全败（v4.3.7 YES / v4.3.8 NO / v4.3.9 hitTest nil / v4.4.0 只查不建），
//   证据链见下：
//     · v4.4.0 真机：弹框标题确实显示 `· v4.4.0`（包没错），
//       但「**整个 QQ 还是点不动，只能动输入法**」，且**后台一条遥测都没有**。
//     · ⇒ 弹框出来了、巡检也没拆（判定「窗口在、弹框也在」= 正常），
//       但这一个 Alert+400 全屏窗口，**无论怎么配置都在吃掉 QQ 的所有触摸**。
//     · **UIKit 的触摸分发在窗口层级上是「最上层可见窗口优先」，
//       且不会因为 hitTest 返回 nil 就继续往下层窗口找。**
//       ⇒ 不存在「留在屏上但不挡事」的全屏高等级窗口。
//   最终方案：**不建任何窗口**，alert 直接 present 到
//     **QQ 自己 keyWindow 的最上层 VC**（ChsiTopVC 实时遍历，每次现取）。
//     alert 天然活在 QQ 自己的窗口里 → **零额外遮挡**，不可能点死 QQ。
//   ⇒ 于是 ChsiAlertHostView / ChsiAlertHostVC 两个类整个删掉，不再需要。
// ============================================================
//   ⚠️ 保持一行空注释占位，避免下方 #if 与上方的相对位置变化。
//
#if defined(CHSI_BUILD_QQ)
// v4.5.0：ChsiFindKeyWindow / gAlertWindow / gPrevKeyWindow 全部删除 ——
//   不再自建窗口，也就没有 key 需要记与还。

// ============================================================
// v4.4.0：🔴🔴 把「查宿主」和「建窗口」彻底分开 —— 这是三版反复
//         出现「整屏点不动」的**最终根因**。
// ------------------------------------------------------------
// 罪证链：
//   · ChsiAlertHost() 以前是个**有副作用**的函数 —— 一被调用就建窗口 +
//     makeKeyAndVisible。而 ChsiLicensePrompt() 每次 DidBecomeActive 都调它。
//   · 拆窗口的路径有 10 处，任何一处拆掉后，下一次 prompt 又建一个新窗口。
//   · 更致命：ChsiLicensePrompt() 里那个「已经有弹框了 → return」的早退分支，
//     **return 时窗口已经建好了**。只要那次判断没命中，就留下一个
//     「全屏 + 没有弹框 + Alert+400」的窗口把 QQ 整个盖住
//     = 真机现象「整个 QQ 点不动，只能动输入法」。
//   ⇒ 修法：**先判断该不该弹；确认要弹了，才建窗口**。
//     并新增 ChsiAlertHostIfExists()（只查不建），所有「只想知道有没有弹框」
//     的地方一律用它。
// ============================================================
// ============================================================
// v4.5.0：🔴🔴🔴 **彻底放弃「自建全屏窗口」** —— 四版反复失败的终极结论。
// ------------------------------------------------------------
// 真机证据（v4.4.0）：弹框标题确实显示 `· v4.4.0`（包没错），
//   但「**整个 QQ 还是点不动，只能动输入法**」，且**后台一条遥测都没有**。
//   ⇒ 弹框出来了、巡检也没拆它（因为「窗口在、弹框也在」= 判断为正常），
//     但**这一个 Alert+400 的全屏窗口，无论怎么配置，都在吃掉 QQ 的所有触摸**。
//
// 四版试错全记录（把这条路彻底走死）：
//   · v4.3.7 自建全屏窗口，默认 userInteractionEnabled=YES → 吃光 QQ 触摸
//   · v4.3.8 改成 NO → 连坐禁用弹框按钮（「按钮灰的点不动」）
//   · v4.3.9 改 YES + 根视图 hitTest 空白返 nil → 依然吃光（hitTest 穿不透窗口）
//   · v4.4.0 只查不建 + 加了巡检 → 弹框在时窗口仍在，照样吃光触摸
//   ⇒ **结论：不存在「留在屏上但不挡事」的全屏高等级窗口。**
//     iOS 的触摸分发在**窗口层级**上是「最上层可见窗口优先」，
//     且不会因为 hitTest 返回 nil 就继续往下层窗口找。
//
// 最终方案：**不建任何窗口**，把 alert 直接 present 到
//   **QQ 自己 keyWindow 的最上层 VC**（ChsiTopVC 会沿 presentedViewController
//   链走到最上面，每次调用重新取，宿主被换掉也能拿到新的）。
//   ⇒ alert 天然活在 QQ 自己的窗口里，**零额外遮挡**，不可能点死 QQ。
//   ⚠️ v4.3.6 用同样思路失败过，但那次是「取 keyWindow.rootViewController」
//      且**只取一次就存起来**；现在是**每次现取**（ChsiTopVC 内部实时遍历），
//      配合已有的弹框存活看门狗，宿主被换掉会重弹。
// ------------------------------------------------------------
// ------------------------------------------------------------
// v4.5.1：`ChsiAlertHostIfExists()` 已删除（它只服务于「沿 VC 链猜弹框」的老判断，
//   现在一律走 ChsiOurAlertIsOnScreen()）。留着会被 -Werror,-Wunused-function 拦下。

// v4.5.1：🔴 「我们那个授权弹框现在到底还在不在屏上？」
//   不再靠 `ChsiTopVC()` 沿 keyWindow 链猜 —— 那个方法在**键盘弹起时**
//   会拿到键盘窗口那条链，查不到我们的 alert，于是误判「弹框没了」→ 重弹
//   → 把用户输了一半的内容清空（真机反馈：「输入的时间不够」）。
//   现在直接看**我们自己记住的那个 alert 实例**在不在 window 层级上：
//     alert.view.window != nil  ⇒ 确实还在屏上（正在打字也算在）
//   这是唯一可靠的判据，且完全不受键盘 / 转场 / keyWindow 漂移影响。
static BOOL ChsiOurAlertIsOnScreen(void) {
    UIAlertController *ac = gActiveAlert;
    if (!ac) return NO;                          // 从没弹过，或已被清掉
    if (ac.isBeingDismissed) return NO;          // 正在消失
    UIView *v = ac.viewIfLoaded;
    if (!v) return NO;                           // view 还没加载 = 肯定不在屏上
    return (v.window != nil);                    // 挂在某个 window 上 = 在屏上
}

// v4.5.3：`ChsiAlertHost()` 改为走候选列表 —— 不再只信 keyWindow 一条链。
//   返回 nil 表示「暂时没有可用宿主」，调用方应重试。
//   ⚠️ `ChsiHostCandidates()` / `ChsiPickPresentHost()` 已移到文件上方
//      共同声明区（不带条件编译，WX 包的编辑器宿主也用它）。
static UIViewController *ChsiAlertHost(void) {
    return ChsiPickPresentHost(NULL);
}

// v4.5.0：不再自建窗口，所以拆窗口变成空操作。
//   保留函数名只为兼容 10 处调用点（否则要改一大片，风险更大）。
static void ChsiAlertHostSetTouch(BOOL on) {
    (void)on;   // 已无窗口可切，空实现
}


// 拆掉授权弹框。
// v4.5.3：🔴🔴 **改成按实例精确 dismiss，不再沿 keyWindow 链猜。**
//   真机第七轮反馈「还是没有弹窗」，根因就在这个函数：
//     · 它原来用 `ChsiTopVC()`（依赖 keyWindow）找「最上层的 alert」，
//       但 keyWindow 在输入框消失后可能指向**键盘窗口 / 我们的 toast 窗口**，
//       那条链里根本没有我们的 alert → dismiss 打偏（日志都不打）→
//       alert 没被真正拆掉 / 或者拆了别的东西；
//     · 更糟的是：响应回来时会调一次 `ChsiDismissAnyAlert()`，
//       紧接着 0.45s 后又要 present 成功弹窗 —— 如果这次 teardown
//       没有把状态清干净，新弹窗就会被判定成「宿主忙」而重试到放弃。
//   ⇒ 现在只认我们自己记住的 `gActiveAlert`：
//       它在哪个 VC 上，就从哪个 VC dismiss。一步到位，零猜测。
static void ChsiAlertHostTeardown(void) {
    UIAlertController *ac = gActiveAlert;
    if (ac) {
        @try {
            // 优先走 presentingViewController（最精确，不依赖任何全局状态）
            UIViewController *presenter = ac.presentingViewController;
            if (!presenter) {
                // 极少数情况 present 还没完成 → 退回候选列表里找
                presenter = ChsiPickPresentHost(NULL);
            }
            if (presenter && presenter.presentedViewController == ac) {
                [presenter dismissViewControllerAnimated:NO completion:^{
                    CHLog(@"已 dismiss 授权弹框（按实例，宿主 = %@）",
                          NSStringFromClass([presenter class]));
                }];
            } else {
                // 兜底：直接让它自己 dismiss（presentingViewController 丢了也能收）
                [ac dismissViewControllerAnimated:NO completion:nil];
                CHLog(@"已 dismiss 授权弹框（按实例，走自身兜底）");
            }
        } @catch (NSException *e) {
            CHLog(@"dismiss 弹框异常: %@", e);
        }
    } else {
        CHLog(@"teardown：没有记录在案的弹框实例，跳过");
    }
    // v4.5.1：无论走哪条路径，清掉实例引用与打字标记 ——
    //   否则残留的弱引用会让巡检误报「弹框不见了」。
    gActiveAlert = nil;
    gAlertEditing = NO;
}

// v4.5.1：`ChsiPresentTarget()` / `ChsiAlertHostIfExists()` 已删除。
//   它们原本只服务于「沿 VC 链猜有没有弹框」那套判断，现在一律改用
//   `ChsiOurAlertIsOnScreen()`（看实例），两个函数再无调用点 ——
//   留着会被 -Werror,-Wunused-function 拦下（v4.5.1 第一次 CI 就死在这）。
//
// v4.4.0：保命巡检。
// v4.5.0：不再有自建窗口了，所以「拆窗口」不再需要 —— 改为**确认弹框还在**。
// v4.5.1：改用 ChsiOurAlertIsOnScreen()（看我们记住的实例），不再沿
//   keyWindow 链猜 —— 键盘弹起时 keyWindow 会变成键盘窗口，那种猜法必然误判。
static void ChsiAlertGuardCheck(NSString *why) {
    if (ChsiOurAlertIsOnScreen()) return;      // 弹框还在，正常
    if (!gActiveAlert) return;                 // 本来就没弹过（或已被消费），不报
    CHLog(@"[巡检/%@] 我们的授权弹框已不在屏上（可能已被 QQ 换掉宿主 VC）", why);
}

// v4.5.2：ChsiShowAlert 的重试内核（前置声明，供自身递归调用）。
//   `tryCount` = 本函数第几次尝试（0 起）。只在「宿主忙」时退让重试；
//   其他失败原因（拿不到 VC）也重试 —— scene 未就绪时多等一拍往往就好了。
static BOOL ChsiShowAlertRetry(UIAlertController *ac, NSString *who, NSInteger tryCount);

// v4.5.0：统一弹一个 alert —— **present 到 QQ 自己的最上层 VC**（不自建窗口）。
// 这是全项目**唯一**的弹框入口。
//   ⚠️ 为什么不再自建窗口：见文件上方 v4.5.0 那段结论 ——
//      不存在「留在屏上却不挡事」的全屏高等级窗口，四版实机全败。
//
// v4.5.2：🔴🔴 **加重试**。真机反馈「没有授权成功提示 / 授权失败提示」
//   （v4.5.1 已修好输入被打断，但结果弹窗看不见）。真因：
//     授权框的「验证」按钮里先 `ChsiAlertHostTeardown()` 把输入框 dismiss
//     （dismissViewControllerAnimated:NO —— **同步发起、异步完成**），
//     紧接着 0.45s 后成功/失败弹窗又 present 到**同一个宿主 VC** 上。
//     dismiss 还没走完时 UIKit 会**直接拒绝这次 present**
//     （控制台只留一行 "Attempt to present ... whose view is not in the
//      window hierarchy" / "already presenting"，且 present 静默失败）。
//     而 ChsiShowAlert 原来一句 `if ([vc isKindOfClass:UIAlertController]) return NO`
//     就把这次弹窗**永久丢掉**了 —— 于是「没提示」。
//   ⇒ 修法：present 不成就**退让重试**（最多 8 次，每次 0.35s），
//     直到宿主空闲。失败弹窗/成功弹窗都走这条路径，不可能再被吞。
static BOOL ChsiShowAlert(UIAlertController *ac, NSString *who) {
    return ChsiShowAlertRetry(ac, who, 0);
}

static BOOL ChsiShowAlertRetry(UIAlertController *ac, NSString *who, NSInteger tryCount) {
    // v4.5.3：宿主改走**候选列表**（遍历所有 scene 的所有 window），
    //   不再只信 keyWindow 一条链 —— 键盘窗口 / 我们的 toast 窗口 /
    //   nil keyWindow 都会让旧写法拿错人或拿不到人。
    NSString *why = nil;
    UIViewController *vc = ChsiPickPresentHost(&why);
    if (!vc) {
        // 拿不到宿主：重试次数放宽到 20 次（≈7 秒），覆盖「输入框刚 dismiss、
        // 键盘还在收」这段窗口期 —— 真机「还是没有弹窗」就死在这里。
        if (tryCount >= 20) {
            CHLog(@"%@：重试 20 次仍拿不到可用宿主（最后原因=%@），放弃弹窗", who, why ?: @"?");
            return NO;
        }
        CHLog(@"%@：拿不到可用宿主（原因=%@，retry=%ld），0.35s 后重试", who, why ?: @"?", (long)tryCount);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            ChsiShowAlertRetry(ac, who, tryCount + 1);
        });
        return YES;
    }
    // v4.5.6：🔴 屏上已经有我们自己的 alert（且不是这一个）→ 拒绝再弹。
    //   真机「一打开弹 2 次 / 取消要点两次」= 两个 alert 实例并存，
    //   `gActiveAlert` 被后者覆盖，前者成"幽灵"（dismiss 不到、按钮被挡）。
    //   这里做最后一道闸：同一时刻只允许一个我们的 alert 在屏上。
    if (gActiveAlert && gActiveAlert != ac && ChsiOurAlertIsOnScreen()) {
        CHLog(@"%@：屏上已有我们的 alert（%@），拒绝再弹第二个", who,
              NSStringFromClass([gActiveAlert class]));
        return NO;
    }
    // v4.5.1：记住这个实例 —— 看门狗 / 巡检 / 清理全靠它精确定位，
    //   不再依赖「沿 keyWindow 链猜」。
    gActiveAlert = ac;
    gAlertEditing = NO;
    @try {
        [vc presentViewController:ac animated:YES completion:^{
            CHLog(@"%@ 弹框已呈现（宿主 = %@）", who, NSStringFromClass([vc class]));
            ChsiFloatDiag(@"prompt presented host=%@", NSStringFromClass([vc class]));
        }];
    } @catch (NSException *e) {
        CHLog(@"%@ 弹框呈现异常: %@", who, e);
        gActiveAlert = nil;
        return NO;
    }
    // v4.5.0：只确认一次「弹框还在不在」。不再有窗口需要拆，巡检仅作诊断。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ChsiAlertGuardCheck(who); });
    return YES;
}
#endif

// v4.3.4：拿当前登录的 QQ 号 —— 授权改成「一个 QQ 号一个授权码」
// 优先级：手动填的值（NSUserDefaults，编辑器里可改）> 自动探测 > UNKNOWN-QQ
// 自动探测：Documents / Files 下的纯数字目录 → plist 里含 uin 的值
// ⚠️ 实测（v4.3.4）：沙盒里可能有多个纯数字目录（历史账号残留），
//    直接取第一个会拿到错的号（实测拿到 2655520187），所以必须能手动覆盖。
// （仅 QQ 包编译；WX 包整段不编译，保证授权字符串不进 WX 二进制）
#if defined(CHSI_BUILD_QQ)
static NSString *ChsiQQPrefsKey(void) { return @"ChsiHookQQNumber"; }

// v4.3.5：启动时清一次「本地不存储」相关的历史留存：
//   ① 删掉 v4.3.4 及以前写在沙箱里的配置 plist；
//   ② 删掉 v4.3.1~v4.3.4 存进 NSUserDefaults 的手动 QQ 号。
// 只跑一次，之后 dylib 全程不再往这两处写任何东西。
static void ChsiNoStorePurge(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        @try {
            NSFileManager *fm = [NSFileManager defaultManager];
            NSString *p = ChsiConfigPath();
            if ([fm fileExistsAtPath:p]) {
                [fm removeItemAtPath:p error:NULL];
                CHLog(@"本地不存储模式：已删除旧配置文件 %@", p);
            }
            if ([[NSUserDefaults standardUserDefaults] objectForKey:ChsiQQPrefsKey()]) {
                [[NSUserDefaults standardUserDefaults] removeObjectForKey:ChsiQQPrefsKey()];
                [[NSUserDefaults standardUserDefaults] synchronize];
                CHLog(@"本地不存储模式：已清除本地保存的 QQ 号");
            }
        } @catch (NSException *e) { }
    });
}

// v4.3.5：手动指定的 QQ 号**不再落盘**（原先存 NSUserDefaults）。
// 跟授权码一个待遇 —— 只在当前进程内存里，每次打开 QQ 都要重新填。
static NSString *gQQOverride = nil;

// 读手动指定的 QQ 号（没有则空串）
static NSString *ChsiQQOverride(void) {
    ChsiNoStorePurge();
    return gQQOverride ?: @"";
}

static void ChsiQQOverrideSet(NSString *v) {
    NSString *t = v ? [v stringByTrimmingCharactersInSet:
                        [NSCharacterSet whitespaceAndNewlineCharacterSet]] : @"";
    gQQOverride = t;   // 空串 = 清空手动值（授权会按 UNKNOWN-QQ 被后台拒）
    CHLog(@"QQ 号手动指定（仅本次进程有效，不落盘）: %@", t.length ? t : @"(清空)");
}

// 自动探测当前登录 QQ 号（可能不准，仅作默认值）
static NSString *ChsiQQGuess(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *dirs = @[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"],
                      [NSHomeDirectory() stringByAppendingPathComponent:@"Files"]];
    for (NSString *dir in dirs) {
        NSArray *ents = [fm contentsOfDirectoryAtPath:dir error:NULL];
        for (NSString *e in ents) {
            NSString *t = [e stringByTrimmingCharactersInSet:
                           [NSCharacterSet whitespaceCharacterSet]];
            if (t.length >= 5 && t.length <= 12) {
                BOOL digit = YES;
                for (NSUInteger i = 0; i < t.length; i++) {
                    unichar ch = [t characterAtIndex:i];
                    if (ch < '0' || ch > '9') { digit = NO; break; }
                }
                if (digit) return t;
            }
        }
    }
    // 兜底：plist 里找 key 含 uin 的字符串/数字
    NSString *pp = [NSHomeDirectory() stringByAppendingPathComponent:
                    @"Library/Preferences/com.tencent.mqq.plist"];
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:pp];
    for (NSString *k in prefs) {
        NSString *lk = [k lowercaseString];
        if ([lk rangeOfString:@"uin"].location != NSNotFound) {
            id v = prefs[k];
            if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] >= 5) return v;
            if ([v isKindOfClass:[NSNumber class]]) {
                NSString *s = [(NSNumber *)v stringValue];
                if (s.length >= 5) return s;
            }
        }
    }
    return @"";
}

// 最终取用的 QQ 号 —— v4.3.5：**只认手动输入**。
// 自动探测（沙盒纯数字目录 / mqq 偏好里的 uin）实测会取到历史残留目录，
// 拿到 2655520187 这种不是本人的号，所以从本版起它**不再当授权主体**，
// 只在日志里打一次，供排障参考。
// 没手动填 → UNKNOWN-QQ，后台按 bad_request 拒（提示用户去填第二栏）。
// 手动值存在进程内存里（见 ChsiQQOverride），每次打开 QQ 都要重新输。
static NSString *ChsiQQID(void) {
    NSString *m = ChsiQQOverride();
    if (m.length) return m;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *g = ChsiQQGuess();
        CHLog(@"QQ 号未手动填写，本次授权将用 UNKNOWN-QQ；"
              @"自动探测值仅作参考（不用于授权）: %@", g.length ? g : @"(探测不到)");
    });
    return @"UNKNOWN-QQ";
}

// v4.6.12 前向声明（定义在 v4.6.11 QQ 监测段）：当前登录号（plist LastLoginUin）
static NSString *ChsiQQCurrentLogin(void);
#endif

// 当前是否允许改写（微信包恒允许）
static BOOL ChsiLicenseAllows(void) {
#if defined(CHSI_BUILD_QQ)
    return gLicenseState == (NSInteger)ChsiLicenseGranted;
#else
    return YES;
#endif
}

// 主线程上更新状态 + 刷新编辑器底部
static void ChsiLicenseSetState(NSInteger st) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ ChsiLicenseSetState(st); });
        return;
    }
    gLicenseState = st;
    [[NSNotificationCenter defaultCenter] postNotificationName:@"ChsiLicenseChanged" object:nil];
}

// 把 kChsiLicenseURL 拆成 host / port / path（仅 QQ 包）
// v4.6.17：支持 [IPv6] 字面量 —— hostOut 返回**裸地址**（喂 getaddrinfo），
//   hostBracketOut 返回带方括号形式（喂 HTTP Host 头，RFC 7230）。
#if defined(CHSI_BUILD_QQ)
static void ChsiLicenseSplit(NSString **hostOut, int *portOut, NSString **pathOut) {
    NSString *s = kChsiLicenseURL;
    NSRange sc = [s rangeOfString:@"://"];
    if (sc.location != NSNotFound) s = [s substringFromIndex:NSMaxRange(sc)];
    NSString *auth = s, *p = @"/";
    NSRange sl = [s rangeOfString:@"/"];
    if (sl.location != NSNotFound) {
        auth = [s substringToIndex:sl.location];
        p = [s substringFromIndex:sl.location];
    }
    NSString *h = auth; int port = 80;
    if ([auth hasPrefix:@"["]) {
        // [v6]:port —— 先取方括号内的裸地址，再取 ]: 后面的端口
        NSRange rb = [auth rangeOfString:@"]"];
        if (rb.location != NSNotFound) {
            h = [auth substringWithRange:NSMakeRange(1, rb.location - 1)];
            if (rb.location + 1 < auth.length && [auth characterAtIndex:rb.location + 1] == ':') {
                port = [[auth substringFromIndex:rb.location + 2] intValue];
            }
        }
    } else {
        NSRange co = [auth rangeOfString:@":"];
        if (co.location != NSNotFound) {
            h = [auth substringToIndex:co.location];
            port = [[auth substringFromIndex:NSMaxRange(co)] intValue];
        }
    }
    if (h.length) *hostOut = h;
    if (port > 0) *portOut = port;
    if (p.length) *pathOut = p;
}

// 最短 HTTP POST（BSD socket，走全局队列，不卡主线程）
// v4.6.4：`pathOverride` 允许调用方指定请求路径（默认走 kChsiLicenseURL 的路径，
//   即 /check）。用于把真机诊断日志 POST 到 /probe（自动回传，免手工导文件）。
static void ChsiLicensePostPath(NSString *json, NSString *pathOverride,
                                void (^done)(NSString *resp, BOOL fail)) {
    NSString *host = nil; int port = 80; NSString *p = nil;
    ChsiLicenseSplit(&host, &port, &p);
    NSString *h = [host copy];
    NSString *path = [(pathOverride.length ? pathOverride : p) copy];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *resp = nil;
        BOOL fail = YES;
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        char ps[16];
        snprintf(ps, sizeof(ps), "%d", port);
        int fd = -1;
        if (getaddrinfo([h UTF8String], ps, &hints, &res) == 0 && res) {
            for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
                int s2 = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
                if (s2 < 0) continue;
                struct timeval tv;
                // v4.6.18：超时 6s → 1s（用户要求：后台 1 秒不响应 = 授权失败）。
                //   Darwin 上 connect() 也吃 SO_SNDTIMEO，所以连接+收发全部 1s 封顶；
                //   超时 → fd<0 / send 截断 → fail=YES → Denied（严格失败关闭）。
                tv.tv_sec = 1; tv.tv_usec = 0;
                setsockopt(s2, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(s2, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                if (connect(s2, ai->ai_addr, ai->ai_addrlen) == 0) { fd = s2; break; }
                close(s2);
            }
            freeaddrinfo(res);
        }
        if (fd >= 0) {
            // v4.6.17：Host 头 —— IPv6 字面量必须带方括号（RFC 7230）
            NSString *hostHdr = ([h rangeOfString:@":"].location != NSNotFound)
                ? [NSString stringWithFormat:@"[%@]", h] : h;
            NSString *req = [NSString stringWithFormat:
                @"POST %@ HTTP/1.1\r\nHost: %@:%d\r\nContent-Type: application/json\r\n"
                @"Content-Length: %lu\r\nConnection: close\r\n\r\n%@",
                path, hostHdr, port,
                (unsigned long)[json lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                json];
            const char *b = [req UTF8String];
            size_t total = strlen(b), off = 0;
            while (off < total) {
                ssize_t w = send(fd, b + off, total - off, 0);
                if (w <= 0) break;
                off += (size_t)w;
            }
            if (off == total) {
                NSMutableData *buf = [NSMutableData data];
                char tmp[4096];
                for (int i = 0; i < 128; i++) {
                    ssize_t r = recv(fd, tmp, sizeof(tmp), 0);
                    if (r > 0) {
                        [buf appendBytes:tmp length:(NSUInteger)r];
                        if ([buf length] > 65536) break;
                    } else break;
                }
                resp = [[NSString alloc] initWithData:buf encoding:NSUTF8StringEncoding];
                fail = NO;
            }
            close(fd);
        }
        done(resp, fail);
    });
}

// 兼容包装：走默认 /check 路径
static void ChsiLicensePost(NSString *json, void (^done)(NSString *resp, BOOL fail)) {
    ChsiLicensePostPath(json, nil, done);
}
#endif   // CHSI_BUILD_QQ（ChsiLicenseSplit / ChsiLicensePost）

// 弹授权码输入框（仅 QQ 包；WX 包空实现，授权字符串不进 WX 二进制）
#if defined(CHSI_BUILD_QQ)
// v4.3.7：统一「点取消 → 退出 QQ」，两个取消按钮（授权输入框 / 失败弹框）共用。
//   ① 先拆弹框宿主窗口；
//   ② 给后台留一条遥测（后台日志能看到这段代码到底跑没跑到、跑的是哪版）；
//   ③ SIGKILL **放到后台队列**上延迟 0.35 秒 —— v4.3.6 用 dispatch_after 挂在主
//      队列上，一旦主线程被卡住就永远不执行（真机现象：遥测到了、QQ 不死）。
//      后台队列不依赖主线程 runloop，外加 _exit(1) 兜底，不可能不生效。
static void ChsiCancelQuit(NSString *tag) {
    gPrompting = NO;
    gPromptInFlight = NO;   // v4.5.6：还令牌（虽然马上要 SIGKILL，但保持状态自洽）
    // v4.3.8：先把触摸还给 QQ（万一 kill 延迟的这 0.35 秒里用户还会点一点），
    //         再拆窗口 —— 顺序反过来会有一个「窗口拆到一半、触摸还锁着」的窗口期。
    ChsiAlertHostSetTouch(NO);
    ChsiAlertHostTeardown();
    NSString *t = tag.length ? tag : @"__CANCEL__";
    @try {
        NSDictionary *tb = @{ @"qq": ChsiQQID(),
                              @"bundle": @"com.tencent.mqq",
                              @"code": t,
                              @"ver": @"v4.6.44" };
        NSData *tj = [NSJSONSerialization dataWithJSONObject:tb options:0 error:NULL];
        NSString *ts = [[NSString alloc] initWithData:tj encoding:NSUTF8StringEncoding];
        if (ts) ChsiLicensePost(ts, ^(NSString *r, BOOL f) { });
    } @catch (NSException *e) { }
    CHLog(@"%@ 点取消，0.35 秒后 SIGKILL 退出 QQ", t);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        usleep((useconds_t)(0.35 * 1000000.0));
        kill(getpid(), SIGKILL);
        usleep(200000);          // 兜底：万一 kill 没生效（不可能，但留一手）
        _exit(1);
    });
}

static void ChsiLicensePrompt(void) {
    // v4.5.6：🔴🔴 **单飞令牌** —— 所有入口（+load 延时 / DidBecomeActive /
    //   编辑器 / 失败重输 / 看门狗）并发调用时，只有第一个能进。
    //   必须在任何 return / dispatch 之前抢，否则窗口期照样漏。
    //   ⚠️ 只在主线程读写（下面有主线程归一），所以不存在真正的原子性问题；
    //      非主线程的调用会先被 dispatch 到主线程再抢。
    if (![NSThread isMainThread]) {
        // v4.5.6：不再「先 dispatch 再 return」—— 那个分支没置任何标记，
        //   连续两次非主线程调用会排队弹两个框。改成直接回主线程重入
        //   （重入后会走下面的令牌逻辑），且**不置 gPromptRetry**。
        dispatch_async(dispatch_get_main_queue(), ^{ ChsiLicensePrompt(); });
        return;
    }
    // ---- 以下全部在主线程执行 ----
    // ① 令牌：拿不到 = 已经有一个弹框流程在跑，直接退出。
    if (gPromptInFlight) {
        CHLog(@"授权弹框：已有流程在飞（gPromptInFlight=YES），本次调用忽略");
        return;
    }
    // ② 我们自己记住的那个 alert 还在屏上 → 也不该再弹（双保险）。
    if (ChsiOurAlertIsOnScreen()) {
        CHLog(@"已有授权弹框在屏上（按实例判定），跳过");
        return;
    }
    // ③ 本会话已成功授权过 → 不该再弹输入框。
    if (gSessionVerified) {
        CHLog(@"本会话已授权成功（gSessionVerified=YES），拒绝再弹输入框");
        return;
    }
    // ④ 旧的 gPrompting 看门狗（90 秒兜底）—— 现在与令牌互补：
    //    令牌防并发，看门狗防「令牌被异常路径吞掉后永远拿不回来」。
    if (gPrompting) {
        NSTimeInterval n = [[NSDate date] timeIntervalSince1970];
        if (n - gPromptSince < 90.0) {
            CHLog(@"授权弹框：gPrompting 仍为 YES（%.0f 秒），本次调用忽略", n - gPromptSince);
            return;
        }
        CHLog(@"授权弹框看门狗：gPrompting 卡住 %.0f 秒，强制复位", n - gPromptSince);
        gPrompting = NO;
    }
    // ⑤ 到这里才真正开始弹 —— 抢下令牌。
    gPromptInFlight = YES;
    CHLog(@"即将弹授权输入框（gEnteredCodeLen=%lu gSessionVerified=%@）",
          (unsigned long)gEnteredCode.length, gSessionVerified ? @"YES" : @"NO");
    // 拿宿主（= ChsiPickPresentHost，无副作用）
    UIViewController *vc = ChsiAlertHost();
    if (!vc) {   // 启动早期 scene 还没就绪，稍后再来
        // v4.6.44：宿主拿不到走探针（新版 QQ 登录页层级变化排查用）
        ChsiFloatDiag(@"prompt host-nil retry=%ld", (long)gPromptRetry);
        if (gPromptRetry++ < 8) {
            // ⚠️ 重试期间必须把令牌还掉，否则这一路自己就把自己锁死了
            //    （8 次重试要 8 秒，期间别的入口全被挡，最后谁都弹不出来）。
            gPromptInFlight = NO;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ ChsiLicensePrompt(); });
        } else {
            gPromptInFlight = NO;   // 放弃，还令牌
            CHLog(@"授权弹框：重试 8 次仍拿不到宿主，本次放弃");
        }
        return;
    }
    gPrompting = YES;
    gPromptSince = [[NSDate date] timeIntervalSince1970];
    gPromptRetry = 0;
    // v4.5.1：如果上一次的框是被系统/看门狗拆掉的（不是用户点掉的），
    //   把已输入的内容带回来，免得用户白打一遍。
    NSString *keepCode = gEnteredCode;   // 可能为 nil
    UIAlertController *ac = [UIAlertController
        alertControllerWithTitle:@"ChsiHook 授权 · v4.6.44"
                         message:@"输入授权码；第二栏 = 当前登录的 QQ 号（自动检测，不可修改）。"
              preferredStyle:UIAlertControllerStyleAlert];
    [ac addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"授权码";
        tf.text = keepCode;               // v4.5.1：带回上次输入（若有）
        tf.secureTextEntry = NO;          // v4.5.1：改明文显示 ——
        //   授权码是 CHSI-XXXX-XXXX-XXXX 固定格式，secure 输入看不到容易打错，
        //   而「看不到 + 输错 + 重弹」正是「感觉永远输不完」的帮凶。
        tf.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
        tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];
    // v4.6.12：第二栏 = 自动检测的当前登录号（plist LastLoginUin，真机实测准确）
    //   **不可修改**；检测到就直接当绑定号用（进内存，不落盘）。
    //   检测不到（极少见）才退回「可手填」的老行为，footer 提示会说明。
    NSString *autoQQ = ChsiQQCurrentLogin();
    if (autoQQ.length >= 5) ChsiQQOverrideSet(autoQQ);
    [ac addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"QQ 号（自动检测）";
        tf.text = autoQQ.length >= 5 ? autoQQ : ChsiQQOverride();
        tf.enabled = !(autoQQ.length >= 5);   // 检测到 → 锁定不可改
        tf.keyboardType = UIKeyboardTypeNumberPad;
        tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    [ac addAction:[UIAlertAction actionWithTitle:@"验证"
                                           style:UIAlertActionStyleDefault
                                         handler:^(UIAlertAction *a) {
        gPrompting = NO;
        gPromptInFlight = NO;   // v4.5.6：弹框流程到此结束，归还令牌
        NSArray *tfs = [ac textFields];        NSString *c = [(UITextField *)tfs[0] text] ?: @"";
        // 第二栏 = QQ 号；填了就以此为准（本次进程内有效，不落盘）
        if (tfs.count > 1) {
            NSString *q = [(UITextField *)tfs[1] text];
            if ([q stringByTrimmingCharactersInSet:
                 [NSCharacterSet whitespaceAndNewlineCharacterSet]].length) {
                ChsiQQOverrideSet(q);
            }
        }
        gEnteredCode = c.length ? [c copy] : nil;
        // v4.3.8：先把触摸还给 QQ，再拆宿主窗口（顺序反了会有短暂触摸锁死窗口期）
        ChsiAlertHostSetTouch(NO);
        ChsiAlertHostTeardown();
        // v4.5.2：明确告诉 verify「这是用户主动发起的」——
        //   成功/失败弹窗必须出现，不能被自动刷新静默掉。
        ChsiLicenseVerifyFrom(gEnteredCode, YES);
    }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"取消"
                                           style:UIAlertActionStyleCancel
                                         handler:^(UIAlertAction *a) {
        // v4.3.6：统一走 ChsiCancelQuit（遥测 → 0.35s → SIGKILL）
        ChsiCancelQuit(@"__CANCEL__");
    }]];
    // v4.5.1：输入框开始/结束编辑时记录状态 —— 用户正在打字时，
    //   看门狗和任何自动流程一律不得动这个弹框（否则输入被清空）。
    //   ⚠️ addObserverForName:...usingBlock: 返回的 token 必须持有并在下次
    //      prompt 时移除，否则每次弹框都会累积一份观察者（泄漏 + 重复触发）。
    static id gEditBeginObs = nil;
    static id gEditEndObs = nil;
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    if (gEditBeginObs) { [nc removeObserver:gEditBeginObs]; gEditBeginObs = nil; }
    if (gEditEndObs)   { [nc removeObserver:gEditEndObs];   gEditEndObs = nil; }
    gEditBeginObs = [nc addObserverForName:UITextFieldTextDidBeginEditingNotification
                                    object:nil queue:[NSOperationQueue mainQueue]
                                usingBlock:^(NSNotification *n) {
        UITextField *tf = n.object;
        // 只认我们这个弹框里的输入框（同一个 window）
        if (tf && ac.view.window && tf.window == ac.view.window) gAlertEditing = YES;
    }];
    gEditEndObs = [nc addObserverForName:UITextFieldTextDidEndEditingNotification
                                  object:nil queue:[NSOperationQueue mainQueue]
                              usingBlock:^(NSNotification *n) {
        UITextField *tf = n.object;
        if (tf && ac.view.window && tf.window == ac.view.window) gAlertEditing = NO;
    }];
    // v4.3.6：present 也要兜住异常 —— 以前 present 失败时 gPrompting 永远
    // 复位不了，后面所有弹框都被吞掉。失败了就立刻复位，让下一次还能弹。
    // v4.3.8：统一走 ChsiShowAlert（现在 = present 到 QQ 自己的 VC）。
    // v4.5.6：present 失败 → 连令牌一起还掉，让下一次还能弹。
    if (!ChsiShowAlert(ac, @"授权输入框")) {
        gPrompting = NO;
        gPromptInFlight = NO;
    }
    // v4.5.0：弹框存活看门狗 —— 回来看一眼，弹框不在屏上就重弹。
    // v4.5.1：🔴🔴 修「输入时间不够」的核心改动：
    //   ① 判定方式改成 ChsiOurAlertIsOnScreen()（看实例，不看 keyWindow 链）——
    //      以前键盘弹起时 keyWindow 变键盘窗口，误判「弹框没了」→ 重弹 → 清空输入；
    //   ② 轮询间隔 5s → 2s，**只在「用户没在打字」时才允许重弹**；
    //   ③ 打字中只静默观察、绝不重弹；重弹次数上限 6 次（避免无限循环）。
    //   这样正常输入（哪怕打两分钟）绝不会被打断。
    //   ⚠️ 实现上**不能用自引用 block**（ARC 下 -Werror 会报
    //      "capturing 'tick' strongly in this block is likely to lead to
    //       a retain cycle"）。改用「每拍调度一个独立 block」的循环写法。
    // v4.5.5：🔴 改成**单拍自链式**（每拍只排下一次，最多 6 拍）。
    //   旧写法 `for (k=0; k<seq; k++)` + `seq = ++gPromptWatchdog` 是**累积**的：
    //   每弹一次框就多排 seq 个 tick —— 弹第 3 次时会有 1+2+3=6 个 tick 在飞，
    //   响应回来时若恰好有 tick 命中「不在屏上」，就会**在成功之后又弹一次**。
    //   现在每拍只排下一个（固定在 2 秒后），gPromptWatchdog 仍限总数 ≤6。
    if (gPromptWatchdog < 6) {
        gPromptWatchdog++;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (!gPrompting) return;                 // 用户已经点掉/验证完了
            if (gAlertEditing) return;               // 用户正在打字 → 一律不动
            if (gSessionVerified) return;            // v4.5.5：已成功 → 绝不重弹
            if (ChsiOurAlertIsOnScreen()) return;    // 弹框还在屏上 → 正常
            CHLog(@"弹框看门狗[%ld]：弹框确实已不在屏上，重弹", (long)gPromptWatchdog);
            gPrompting = NO;
            gPromptInFlight = NO;   // v4.5.6：先还令牌，否则下面的重弹会被自己挡住
            ChsiLicensePrompt();
        });
    }
}
#endif   // CHSI_BUILD_QQ（ChsiLicensePrompt）

// v4.3.4：轻量 toast（1.6 秒自动消失，不打断操作）
// 用途：授权成功/失败给一个明确反馈，避免「明明通过了却以为没过」
// ⚠️ v4.3.4 的教训：走 UIApplication.keyWindow 在 iOS 17 + QQ（场景化生命周期）
//    下拿到 nil，toast 根本画不出来。v4.3.4 改用**独立 UIWindow**，
//    挂在自己的 window 上，不依赖宿主任何窗口状态 —— 必然可见。
#if defined(CHSI_BUILD_QQ)
static UIWindow *gToastWindow = nil;
static void ChsiToast(NSString *msg, BOOL ok) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gToastWindow) {
            UIWindowScene *scn = nil;
            for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
                if ([sc isKindOfClass:[UIWindowScene class]]) { scn = (UIWindowScene *)sc; break; }
            }
            if (scn) gToastWindow = [[UIWindow alloc] initWithWindowScene:scn];
            else     gToastWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            // v4.3.7：Alert+500 —— 必须高于弹框宿主窗口（Alert+400），
            //        否则弹框一出现 toast 就被压在下面看不见。
            //        编辑器是 Alert+200，也早已被 300 版压过。
            //        toast 窗口 userInteractionEnabled=NO，提到最高也不挡触摸。
            gToastWindow.windowLevel = UIWindowLevelAlert + 500.0;
            gToastWindow.userInteractionEnabled = NO;              // 不挡触摸
        }
        UIWindow *w = gToastWindow;
        CGFloat Wd = CGRectGetWidth(w.bounds), Ht = CGRectGetHeight(w.bounds);
        if (Wd < 10) { Wd = [UIScreen mainScreen].bounds.size.width; Ht = [UIScreen mainScreen].bounds.size.height; }
        UIView *box = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 260, 46)];
        box.center = CGPointMake(Wd / 2.0, Ht * 0.34);
        box.backgroundColor = ok ? [UIColor colorWithRed:0.11 green:0.43 blue:0.34 alpha:0.94]
                                 : [UIColor colorWithRed:0.64 green:0.18 blue:0.18 alpha:0.94];
        box.layer.cornerRadius = 10;
        box.layer.masksToBounds = YES;
        box.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin
                             | UIViewAutoresizingFlexibleTopMargin | UIViewAutoresizingFlexibleBottomMargin;
        UILabel *lb = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 260, 46)];
        lb.text = msg;
        lb.font = [UIFont systemFontOfSize:14];
        lb.textColor = [UIColor whiteColor];
        lb.textAlignment = NSTextAlignmentCenter;
        lb.numberOfLines = 2;
        [box addSubview:lb];
        [w addSubview:box];
        w.hidden = NO;
        box.alpha = 0;
        [UIView animateWithDuration:0.18 animations:^{ box.alpha = 1; }];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.6 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [UIView animateWithDuration:0.25 animations:^{ box.alpha = 0; }
                             completion:^(BOOL fin) { [box removeFromSuperview]; }];
        });
    });
}
#endif

// v4.3.4：关掉当前挂在最上层的授权弹框（成功/失败都要收干净）
// v4.3.7：弹框现在挂在我们自己的宿主窗口上，所以「清弹框」= 直接把宿主窗口
//         拆掉（连窗口带弹框一起没了），并把 key 还给 QQ。
#if defined(CHSI_BUILD_QQ)
static void ChsiDismissAnyAlert(void) {
    ChsiAlertHostTeardown();
}
#endif

// v4.5.4：🔴🔴 从裸 HTTP 响应里取出**真正的 body 字符串**。
//   我们手写的 BSD socket 请求没做 HTTP 分帧，以前直接拿 "header\r\n\r\n" 之后
//   的内容去 NSJSONSerialization —— 一旦服务端（或中间代理）用
//   **Transfer-Encoding: chunked**，body 在 wire 上长这样：
//       1e\r\n{"ok":true,"reason":"granted"}\r\n0\r\n\r\n
//   前面挂着十六进制 chunk 长度、后面跟着结束块 → JSON 解析必失败
//   → ok 保持 NO → **后台明明 granted，手机却弹「授权未通过」**。
//   （v4.5.1/4.5.2/4.5.3 三轮都在修弹窗路径，真凶一直在这个解析上，
//     因为前几版压根弹不出窗，把它盖住了。）
//   ⇒ 这里按 HTTP/1.1 规矩把 body 解出来：chunked 就逐块拼接、非 chunked 直取。
#if defined(CHSI_BUILD_QQ)
static NSString *ChsiHTTPBodyExtract(NSString *resp) {
    if (resp.length == 0) return nil;
    // 1) 切掉响应头（兼容 \r\n\r\n 与 \n\n 两种）
    NSRange sep = [resp rangeOfString:@"\r\n\r\n"];
    NSUInteger bodyStart;
    if (sep.location != NSNotFound) {
        bodyStart = NSMaxRange(sep);
    } else {
        NSRange sep2 = [resp rangeOfString:@"\n\n"];
        if (sep2.location == NSNotFound) return resp;   // 没有头，当纯 body
        bodyStart = NSMaxRange(sep2);
    }
    NSString *head = [resp substringToIndex:bodyStart];
    NSString *body = [resp substringFromIndex:bodyStart];
    // 2) 是否 chunked（只看响应头，避免 body 里恰好有这个词）
    BOOL chunked = ([head rangeOfString:@"Transfer-Encoding: chunked"
                                 options:NSCaseInsensitiveSearch].location != NSNotFound);
    if (!chunked) return body;
    // 3) 逐块解码：每块 "<hexLen>\r\n<data>\r\n"，长度 0 结束
    NSMutableString *out = [NSMutableString string];
    NSUInteger i = 0;
    NSInteger guard = 0;
    while (i < body.length && guard++ < 4096) {
        NSRange crlf = [body rangeOfString:@"\r\n"
                                    options:0
                                      range:NSMakeRange(i, body.length - i)];
        if (crlf.location == NSNotFound) break;
        NSString *lenLine = [body substringWithRange:NSMakeRange(i, crlf.location - i)];
        // 长度行可能带 chunk 扩展（"1e;foo=bar"），取分号前
        NSRange semi = [lenLine rangeOfString:@";"];
        if (semi.location != NSNotFound) lenLine = [lenLine substringToIndex:semi.location];
        unsigned int chunkLen = 0;
        NSScanner *sc = [NSScanner scannerWithString:lenLine];
        if (![sc scanHexInt:&chunkLen]) break;
        NSUInteger dataStart = NSMaxRange(crlf);
        if (chunkLen == 0) break;                        // 末块
        if (dataStart + chunkLen > body.length) {        // 数据不完整，能拿多少拿多少
            [out appendString:[body substringFromIndex:dataStart]];
            break;
        }
        [out appendString:[body substringWithRange:NSMakeRange(dataStart, chunkLen)]];
        i = dataStart + chunkLen;
        if (i + 1 < body.length && [body characterAtIndex:i] == '\r'
            && [body characterAtIndex:i + 1] == '\n') i += 2;   // 跳过块尾 CRLF
    }
    return out.length ? out : body;   // 解不出就退回原始 body（至少不更糟）
}
#endif   // CHSI_BUILD_QQ（ChsiHTTPBodyExtract）

// 真正发一次验证请求（码为空直接判否）—— 仅 QQ 包
// v4.5.2：加 `fromUser` —— 是否用户点「验证」主动发起。
//   用**请求序号**携带到响应回调里，避免「用户主动验证在路上时被切前台的
//   自动刷新清掉标记 → 成功弹窗被静默」这个竞态。
//   ⚠️ 前置声明已挪到文件上方声明区（授权框按钮里先于此处调用）。
// v4.5.4：响应解析改走 ChsiHTTPBodyExtract()（修 chunked 吞结果）。
#if defined(CHSI_BUILD_QQ)
static void ChsiLicenseVerify(NSString *code) {
    // 旧单参入口 = 非用户主动（自动重验），保持静默语义
    ChsiLicenseVerifyFrom(code, NO);
}

static void ChsiLicenseVerifyFrom(NSString *code, BOOL fromUser) {
    if (code.length == 0) { ChsiLicenseSetState((NSInteger)ChsiLicenseDenied); return; }
    // v4.5.2：本次请求的序号；只有 fromUser 的那次才记进 gUserVerifySeq
    NSInteger mySeq = ++gVerifySeqCounter;
    if (fromUser) gUserVerifySeq = mySeq;
    // v4.6.15：挑战串 —— 响应里的 sig 必须覆盖它（防预存响应重放）
    NSString *nonce = [NSString stringWithFormat:@"%08x%08x", arc4random(), arc4random()];
    gLastNonce = nonce;
    NSDictionary *body = @{ @"qq": ChsiQQID(),
                            @"bundle": @"com.tencent.mqq",
                            @"code": code,
                            @"nonce": nonce };
    NSData *jd = [NSJSONSerialization dataWithJSONObject:body options:0 error:NULL];
    NSString *json = [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding];
    if (!json) json = @"{}";
    ChsiLicenseSetState((NSInteger)ChsiLicensePending);
    ChsiLicensePost(json, ^(NSString *resp, BOOL fail) {
        BOOL ok = NO;
        NSString *reason = @"";
        if (!fail && resp.length) {
            // v4.5.4：🔴 走 ChsiHTTPBodyExtract —— 兼容 Transfer-Encoding: chunked。
            //   以前直接取 "\r\n\r\n" 之后的内容，chunked 时拿到的是
            //   "1e\r\n{...}\r\n0\r\n\r\n"，JSON 解析必失败 → 后台 granted 却弹失败。
            NSString *b = ChsiHTTPBodyExtract(resp);
            id j = [NSJSONSerialization JSONObjectWithData:[b dataUsingEncoding:NSUTF8StringEncoding]
                                                   options:0 error:NULL];
            if ([j isKindOfClass:[NSDictionary class]]) {
                ok = [j[@"ok"] boolValue];
                reason = [j[@"reason"] isKindOfClass:[NSString class]] ? j[@"reason"] : @"";
                // ---- v4.6.15：响应签名校验（防网络侧伪造 / 抓包重放）----
                //   sig = HMAC-SHA256(SECRET, qq|exp|nonce|jskey)；
                //   SECRET 不过网；nonce 必须等于手机本次请求的挑战串；
                //   exp 过期即拒。jskey = JS 模板解密密钥（功能绑定加密）。
                if (ok) {
                    NSString *sig = [j[@"sig"] isKindOfClass:[NSString class]] ? j[@"sig"] : @"";
                    NSString *jskey = [j[@"jskey"] isKindOfClass:[NSString class]] ? j[@"jskey"] : @"";
                    NSString *rnonce = [j[@"nonce"] isKindOfClass:[NSString class]] ? j[@"nonce"] : @"";
                    double exp = [j[@"exp"] doubleValue];
                    double now = [[NSDate date] timeIntervalSince1970];
                    NSString *base = [NSString stringWithFormat:@"%@|%.0f|%@|%@",
                                      ChsiQQID(), exp, rnonce, jskey];
                    NSString *expect = ChsiHmacHex(ChsiSecret(), base);
                    BOOL nonceOk = [rnonce isEqualToString:(gLastNonce ?: @"")];
                    if (jskey.length != 64 || !nonceOk || exp <= now
                        || ![expect isEqualToString:sig]) {
                        ok = NO;
                        reason = @"sig_invalid";
                        CHLog(@"sig-miss nonceOk=%d exp余量=%.0fs jskeyLen=%lu",
                              nonceOk ? 1 : 0, exp - now,
                              (unsigned long)jskey.length);
                    } else {
                        gJSKeyHex = [jskey copy];
                        gSessExp = exp;
                        CHLog(@"session-key ok exp余量=%.0fs", exp - now);
                        // ---- v4.6.44 全下发：改写脚本随响应加密下发 ----
                        //   jsenc = 脚本密文 hex（jskey 加密，算法同内置 blob）；
                        //   jsver = 脚本版本（会话内只升不降，防降级回放）；
                        //   jsig  = HMAC-SHA256(jskey, "js|jsver|exp|jsenc")。
                        //   jskey 本身被 sig=HMAC(SECRET, qq|exp|nonce|jskey) 封印
                        //   → 伪造响应拿不到合法 jskey → jsig 必然验不过。
                        //   任一环失败 → 清空 gRemoteJSEnc（fail closed，零改写）。
                        NSString *jsenc = [j[@"jsenc"] isKindOfClass:[NSString class]] ? j[@"jsenc"] : @"";
                        NSString *jsig  = [j[@"jsig"] isKindOfClass:[NSString class]] ? j[@"jsig"] : @"";
                        NSInteger jsver = [j[@"jsver"] isKindOfClass:[NSNumber class]] ? [j[@"jsver"] integerValue] : -1;
                        if (jsenc.length >= 32 && (jsenc.length % 2) == 0 && jsver >= 0 && jsver >= gJSVer) {
                            NSString *jsBase = [NSString stringWithFormat:@"js|%ld|%.0f|%@",
                                                (long)jsver, exp, jsenc];
                            NSString *jsExpect = ChsiHmacHex(jskey, jsBase);
                            if ([jsExpect isEqualToString:jsig]) {
                                // 安全 hex 解码：先全串校验字符集，再两两配对
                                static NSCharacterSet *hexCS = nil;
                                if (!hexCS) hexCS = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
                                BOOL hexOk = (jsenc.length % 2) == 0 &&
                                             [jsenc rangeOfCharacterFromSet:[hexCS invertedSet]].location == NSNotFound;
                                NSMutableData *d = [NSMutableData dataWithCapacity:jsenc.length / 2];
                                if (hexOk) {
                                    const char *p = jsenc.UTF8String;
                                    for (NSUInteger i = 0; i + 1 < jsenc.length; i += 2) {
                                        unsigned v = 0;
                                        sscanf(p + i, "%2x", &v);
                                        unsigned char b = (unsigned char)v;
                                        [d appendBytes:&b length:1];
                                    }
                                }
                                if (hexOk && d.length >= 16) {
                                    gRemoteJSEnc = [d copy];
                                    gJSVer = jsver;
                                    ChsiFloatDiag(@"js-deliver ver=%ld bytes=%lu",
                                                  (long)jsver, (unsigned long)d.length);
                                    CHLog(@"js-deliver ok ver=%ld bytes=%lu",
                                          (long)jsver, (unsigned long)d.length);
                                } else {
                                    gRemoteJSEnc = nil;
                                    CHLog(@"js-deliver hex-bad ver=%ld", (long)jsver);
                                }
                            } else {
                                gRemoteJSEnc = nil;
                                CHLog(@"js-deliver sig-miss ver=%ld", (long)jsver);
                            }
                        } else {
                            // 服务器未下发（断供开关 / 版本回退）→ 零改写
                            gRemoteJSEnc = nil;
                            CHLog(@"js-miss ver=%ld have=%lu", (long)jsver, (unsigned long)jsenc.length);
                        }
                    }
                }
            } else {
                // 解析失败也要留证据：把前 120 字符打进日志，方便下次一眼看出分帧问题
                NSString *snippet = b.length > 120 ? [b substringToIndex:120] : (b ?: @"");
                CHLog(@"授权响应 JSON 解析失败（可能是 HTTP 分帧/chunked 未处理），"
                      @"原文前 120 字符: %@", [snippet stringByReplacingOccurrencesOfString:@"\r" withString:@"\\r"]);
            }
        }
        BOOL okk = ok;
        NSString *rs = [reason copy];
        // v4.5.2：🔴 用**请求序号**判断「这次是不是用户主动验证」，
        //   而不是读全局 gVerifyFromPrompt —— 后者会被切前台的
        //   ChsiLicenseRefresh() 清成 NO，导致成功弹窗被误判为「自动重验」
        //   → 静默 → 用户看到「没有授权成功提示」。
        //   现在：响应回来时，只要 gUserVerifySeq 还等于本次请求序号，
        //   就说明「用户点验证那次」的结果，必须给弹窗。
        BOOL userInitiated = (mySeq == gUserVerifySeq) && (gUserVerifySeq != 0);
        if (userInitiated) gUserVerifySeq = 0;   // 消费掉，一次请求只弹一次
        dispatch_async(dispatch_get_main_queue(), ^{
            gLicenseState = okk ? (NSInteger)ChsiLicenseGranted : (NSInteger)ChsiLicenseDenied;
            CHLog(@"授权验证 %@（QQ %@，码长 %lu，联网 %@，主动 %@，reason=%@）",
                  okk ? @"通过" : @"未通过", ChsiQQID(),
                  (unsigned long)code.length, fail ? @"失败" : @"正常",
                  userInitiated ? @"是" : @"否",
                  rs.length ? rs : (fail ? @"无响应" : @"-"));
            [[NSNotificationCenter defaultCenter] postNotificationName:@"ChsiLicenseChanged" object:nil];
            // v4.3.4：先无条件清掉所有残留授权弹框，再决定要不要弹新的
            ChsiDismissAnyAlert();
            if (okk) {
                // v4.5.5：🔴 本会话已成功授权 → 记下来，之后 Refresh 一律不再弹输入框。
                //   （必须在 userInitiated 判定之外 —— 自动重验成功也算成功。）
                gSessionVerified = YES;
                // v4.5.2：用户主动验证成功 → toast + 确认弹窗（都带版本指纹）；
                //          自动重验成功保持静默（只刷 footer），免得每次切 App 都弹
                if (userInitiated) {
                    ChsiToast([NSString stringWithFormat:@"ChsiHook v4.6.44 ✔ 授权通过（QQ %@）", ChsiQQID()], YES);
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.45 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{
                        UIAlertController *ac = [UIAlertController
                            alertControllerWithTitle:@"✔ 授权通过"
                                             message:@"ChsiHook v4.6.44 后台验证已通过，可以改写学信网字段了。"
                                      preferredStyle:UIAlertControllerStyleAlert];
                        [ac addAction:[UIAlertAction actionWithTitle:@"好"
                                                               style:UIAlertActionStyleDefault
                                                             handler:^(UIAlertAction *a) {
                            // v4.3.8：先把触摸还给 QQ，再拆窗口
                            ChsiAlertHostSetTouch(NO);
                            ChsiAlertHostTeardown();
                        }]];
                        ChsiShowAlert(ac, @"成功弹窗");
                    });
                }
            } else {
                // v4.3.4：把后台给的 reason 翻成人话，直接告诉用户错在哪
                NSString *msg;
                if (fail) {
                    msg = @"连不上后台（检查网络 / IPv6 是否可达；路由器授权服务或防火墙被关了）。";
                } else if ([rs isEqualToString:@"qq_not_match"]) {
                    // v4.6.13：第二栏已改为自动检测只读，「改成后台登记的号」
                    //   这句删掉（用户改不了）；改提示重启重检测。
                    msg = [NSString stringWithFormat:
                           @"这个码没绑当前登录的 QQ 号（本机检测到 %@）。\n"
                           @"如果号不对：退出当前 QQ 账号、登录后台登记的号，"
                           @"再重开 QQ 重试。", ChsiQQID()];
                } else if ([rs isEqualToString:@"code_invalid"]) {
                    msg = @"授权码不存在（19 位，形如 CHSI-XXXX-XXXX-XXXX，注意别漏字符）。";
                } else if ([rs isEqualToString:@"bad_request"]) {
                    // v4.3.5：QQ 号不再自动探测 → 没填就是 UNKNOWN-QQ，直接提示去填
                    msg = @"没填 QQ 号。请回授权弹框第二栏填上你的 QQ 号再点「验证」。";
                } else {
                    msg = @"授权码无效 / 不属于当前 QQ 号 / 连不上后台。";
                }
                // v4.3.4：延迟 0.45s（dismiss 动画 ~0.3s + 余量），
                //          且不再排除 UIAlertController —— 从任何顶层 VC 都能弹，
                //          根治「失败弹框被 dismiss 时序吞掉」这一类 bug
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.45 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{
                    ChsiToast(@"ChsiHook v4.6.44 ✘ 授权未通过", NO);
                    UIAlertController *ac = [UIAlertController
                        alertControllerWithTitle:@"授权未通过"
                                         message:msg
                              preferredStyle:UIAlertControllerStyleAlert];
                    [ac addAction:[UIAlertAction actionWithTitle:@"重新输入"
                                                           style:UIAlertActionStyleDefault
                                                         handler:^(UIAlertAction *a) {
                        gEnteredCode = nil;
                        ChsiAlertHostSetTouch(NO);
                        ChsiAlertHostTeardown();
                        ChsiLicensePrompt();
                    }]];
                    [ac addAction:[UIAlertAction actionWithTitle:@"取消"
                                                           style:UIAlertActionStyleCancel
                                                         handler:^(UIAlertAction *a) {
                        // v4.3.7：统一走 ChsiCancelQuit（遥测 → 后台队列 0.35s → SIGKILL）
                        ChsiCancelQuit(@"__CANCELFAIL__");
                    }]];
                    ChsiShowAlert(ac, @"失败弹框");
                });
            }
        });
    });
}
#endif   // CHSI_BUILD_QQ（ChsiLicenseVerify 整个函数）

// 每次「打开」调用：没码就弹框要码，有码就重新问后台
static void ChsiLicenseRefresh(void) {
#if !defined(CHSI_BUILD_QQ)
    gLicenseState = ChsiLicenseGranted;
#else
    // v4.3.4：节流 —— QQ 启动/切前台会连发多次 DidBecomeActive，
    // 以前一次打开能打 13 次后台（用户实测）。同号同码且已在验证中就不重复发。
    static NSTimeInterval lastReq = 0;
    static NSString *lastKey = nil;
    NSString *key = [NSString stringWithFormat:@"%@|%@", ChsiQQID(), gEnteredCode ?: @""];
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (gLicenseState == (NSInteger)ChsiLicensePending
        && [lastKey isEqualToString:key] && (now - lastReq) < 10.0) {
        return;   // 10 秒内同一次验证已在飞行中，别再发
    }
    lastReq = now;
    lastKey = key;

    gPromptRetry = 0;
    gPromptWatchdog = 0;   // v4.3.7：每次重新打开 QQ，弹框看门狗计数归零
    // v4.5.5：🔴🔴 本会话已成功授权过 → 绝不再弹输入框。
    //   真机反馈「验证成功了，还会跳一次输入授权码」的根因就在下面那个
    //   `gEnteredCode.length == 0` 分支：点「验证」时输入框 alert 被 dismiss
    //   （键盘收起）会让 iOS 补发 DidBecomeActive → 又走一遍 Refresh；
    //   只要那一刻 gEnteredCode 恰好为空（例如中途进过一次后台被
    //   ChsiLicenseInvalidate 清掉），就会**重新弹一个空的输入框**。
    //   语义上「已经成功」根本不需要再输码 ⇒ 直接短路，顺带把状态修回 Granted。
    if (gSessionVerified) {
        if (gLicenseState != (NSInteger)ChsiLicenseGranted) {
            ChsiLicenseSetState((NSInteger)ChsiLicenseGranted);
        }
        return;
    }
    if (gEnteredCode.length == 0) {
        ChsiLicenseSetState((NSInteger)ChsiLicenseDenied);
        // v4.6.44：🔴 启动/切前台**不再立即弹框** —— 等检测到登录号
        //   （ChsiQQWatchTick 里自动弹，自动带出号码）。刚重装的 QQ 没有
        //   账号，此时弹框 = 用户填完码也会因「登录号 ≠ 弹框里填的号」被
        //   mismatch 杀掉，形成「删 QQ 重装还是闪退」的死循环。
        //   登录后的自动弹在 ChsiQQWatchTick（10s tick）里。
    } else {
        // v4.5.2：不再清任何「用户主动」标记 —— 这里只是自动重验，
        //   不该影响用户那次请求的弹窗判定（序号机制已隔离）。
        ChsiLicenseVerify(gEnteredCode);
    }
#endif
}

// App 进后台：码作废，下次回来必须重新输入（严格模式）
static void ChsiLicenseInvalidate(void) {
#if !defined(CHSI_BUILD_QQ)
    return;
#endif
    // v4.5.5：🔴 **不再清 `gEnteredCode`**。
    //   以前这里清码，导致「切后台看一眼授权码 → 切回来」就丢码 → 重弹输入框。
    //   而且点「验证」时 alert dismiss（键盘收起）会补发 DidBecomeActive，
    //   若中间夹过一次 DidEnterBackground，回来就必然重弹 = 真机看到的
    //   「成功了还跳一次输入授权码」。
    //   ⇒ 进后台只把状态降级（不改写），但**保留已输入的码**；
    //     是否要重新输码由 `gSessionVerified` / 用户主动动作决定。
    ChsiLicenseSetState((NSInteger)ChsiLicenseDenied);
#if defined(CHSI_BUILD_QQ)
    // v4.6.15：进后台同时清 JS 模板密钥（严格无离线宽限 —— 回前台由
    // Refresh 自动复验，成功即换新 exp + 密钥，改写恢复）
    gJSKeyHex = nil;
    gSessExp = 0;
#endif
}

// ==================== JS 辅助 ====================

static NSString *JSEscape(NSString *s) {
    if (!s) return @"";
    NSString *r = [s stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
    r = [r stringByReplacingOccurrencesOfString:@"'" withString:@"\\'"];
    r = [r stringByReplacingOccurrencesOfString:@"\n" withString:@"\\n"];
    r = [r stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    return r;
}

// NSArray<NSArray*> → JS 字面量 [['a','b'],...]
static NSString *PairsToJS(NSArray *pairs) {
    NSMutableArray *parts = [NSMutableArray array];
    for (NSArray *p in pairs) {
        [parts addObject:[NSString stringWithFormat:@"['%@','%@']",
                          JSEscape(p[0]), JSEscape(p[1])]];
    }
    return [NSString stringWithFormat:@"[%@]", [parts componentsJoinedByString:@","]];
}

// djb2 → 8 位 hex，作 JS 热更版本号（规则变了 VER 必变）
static NSString *CHHash8(NSString *s) {
    uint64_t h = 5381;
    for (NSUInteger i = 0; i < s.length; i++) {
        h = h * 33 + (uint64_t)[s characterAtIndex:i];
    }
    return [NSString stringWithFormat:@"%08llx", (unsigned long long)(h & 0xFFFFFFFFull)];
}

// ==================== 注入的 JS（v3：参数化 + 热更）====================

// ⚠️ 参数名必须保持 rulesJS / renameJS / verJS ——
//   本地校验脚本 _check_js.cjs / _test_inject.cjs 按这三个 token 抽取拼接。
// ==================== 注入的 JS（v4.6.15：模板密文 + 运行时解密）====================

// ⚠️ 模板明文位置（v4.6.44 全下发）：
//   QQ —— 二进制里**零脚本**，模板明文只在服务器 /root/chsi/js-remote.js，
//     /check 响应以 jskey 加密（jsenc）+ HMAC 签名（jsig）下发，验签解密进内存。
//   WX —— 无服务器，模板密文仍内置（ChsiJSPayload.h，_pack_js.py 生成）。
//   模板占位符 %@ ×4：verJS / rulesJS / renameJS / photoJS。
static NSString *InjectionJSCore(NSString *rulesJS, NSString *renameJS,
                                 NSString *verJS, NSString *photoJS) {
    NSData *pt = ChsiJSPayloadDecrypt();
    if (!pt) {
        // QQ 全下发：无会话密钥 / 服务器未下发 / 验签失败 → 空脚本（零改写）。
        //   patch gSessionVerified 绕不过 —— 脚本本身只在真实服务器响应里。
        // WX：密钥错（被篡改）→ 空脚本。
        CHLog(@"jscore 无密钥 → 注入空脚本");
        return @"(function(){return '';})();";
    }
    NSString *tpl = [[NSString alloc] initWithData:pt encoding:NSUTF8StringEncoding];
    if (!tpl) {
        CHLog(@"jscore 模板解码失败 → 注入空脚本");
        return @"(function(){return '';})();";
    }
    return [[NSString alloc] initWithFormat:tpl, verJS, rulesJS, renameJS, photoJS];
}

// 组装：实时读配置 → 生成当前版本的注入 JS
static NSString *InjectionJS(void) {
    // v4.3.4：总开关 + 后台授权 两者都通过才改写（未授权时规则与改名都置空）
    BOOL allowed = ChsiEnabled() && ChsiLicenseAllows();
    NSString *rulesJS  = PairsToJS(allowed ? EffectiveRules() : @[]);
    NSString *renameJS = PairsToJS(allowed ? RenameRulesOrdered() : @[]);
    // v4.6.44：照片 —— 已授权且本机设置过才下发 data URI，否则空串（不改图）。
    NSString *photoJS  = @"";
    if (allowed) {
        NSString *p = EffectivePhoto();
        if (p.length > 0) photoJS = p;
    }
    // v4.6.44：VER 必须计入照片状态 —— 否则选完照片后 VER 不变，
    //   页面里旧闭包走 __chsiRewriterVer === VER 早退，永远用旧（空）PHOTO。
    //   照片 data URI 以 "data:image/jpeg;base64," 开头，取长度+尾字符
    //   足以区分 空/换图（同长同尾概率可忽略）。
    unichar pTail = photoJS.length > 0 ? [photoJS characterAtIndex:photoJS.length - 1] : 0;
    NSString *verInput = [[rulesJS stringByAppendingString:renameJS]
                          stringByAppendingFormat:@"|P%lu|%C",
                          (unsigned long)photoJS.length, pTail];
    NSString *verJS    = CHHash8(verInput);
    return InjectionJSCore(rulesJS, renameJS, verJS, photoJS);
}

// ==================== v4.6.15 防破解 · 反调试 / 反注入（两包公用）====================

// 前置声明（定义在文件后段的 probe 日志那节；两包公用 —— hard-kill 两条包都打）
static void ChsiFloatDiag(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);

extern int ptrace(int, pid_t, caddr_t, int);
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

// 硬杀：随机延迟 0.4~2.4s 后 SIGKILL（随机化是为了让破解者难定位检查点）
static void ChsiHardKill(NSString *why) {
    CHLog(@"hard-kill %@", why);
    ChsiFloatDiag(@"hard-kill %@", why);
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        usleep((useconds_t)(400 + arc4random_uniform(2000)) * 1000);
        kill(getpid(), SIGKILL);
        usleep(200000);
        _exit(1);
    });
}

// 周期自检：
//   ① P_TRACED（调试器附着）→ 杀；
//   ② 本 dylib 重复注入（TrollFools 新旧并存 → 逻辑翻倍/门控失效）→ 杀；
//   ③ frida / substrate / ElleKit 等注入框架 → 只诊断不杀（防误伤
//      装了其他巨魔插件的机子 —— 误杀比漏杀代价大，v4.6.11 铁律）。
static void ChsiHardCheck(void) {
    @try {
        // ① 调试器
        struct kinfo_proc info;
        size_t sz = sizeof(info);
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
        if (sysctl(mib, 4, &info, &sz, NULL, 0) == 0 &&
            (info.kp_proc.p_flag & P_TRACED)) {
            ChsiHardKill(@"hard-check P_TRACED");
            return;
        }
        // ② 重复注入 + ③ 注入框架（只诊断）
        int32_t n = _dyld_image_count();
        int selfCnt = 0;
        NSMutableArray *sus = nil;
        for (int32_t i = 0; i < n; i++) {
            const char *p = _dyld_get_image_name(i);
            if (!p) continue;
            NSString *path = [NSString stringWithUTF8String:p];
            NSString *base = path.lastPathComponent ?: @"";
            if ([base containsString:@"ChsiHook"]) selfCnt++;
            if ([base.lowercaseString containsString:@"frida"]
                || [base.lowercaseString containsString:@"cycript"]
                || [base.lowercaseString containsString:@"substrate"]
                || [base.lowercaseString containsString:@"tweakinject"]
                || [base.lowercaseString containsString:@"ellekit"]) {
                if (!sus) sus = [NSMutableArray array];
                [sus addObject:base];
            }
        }
        if (selfCnt > 1) {
            ChsiHardKill([NSString stringWithFormat:@"hard-dup count=%d", selfCnt]);
            return;
        }
        if (sus.count) {
            CHLog(@"hard-diag 注入框架在场（不杀）: %@", sus);
        }
    } @catch (NSException *e) { }
}

static void ChsiHardStart(void) {
    static dispatch_once_t once;
    static dispatch_source_t sTimer;
    dispatch_once(&once, ^{
        ptrace(PT_DENY_ATTACH, 0, 0, 0);   // 一次性：拒绝调试器附着
        sTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                        dispatch_get_global_queue(
                                            DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
        dispatch_source_set_timer(sTimer,
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8 * NSEC_PER_SEC)),
            (uint64_t)(20 * NSEC_PER_SEC), (uint64_t)(2 * NSEC_PER_SEC));
        dispatch_source_set_event_handler(sTimer, ^{ ChsiHardCheck(); });
        dispatch_resume(sTimer);
        ChsiHardCheck();   // 启动立即一拍
        CHLog(@"hard-check 已启动（20s 一拍）");
    });
}

// ==================== 注入器 ====================

static const void *kChsiScriptInstalledKey = &kChsiScriptInstalledKey;

@interface ChsiInjector : NSObject
+ (void)installUserScriptIntoConfiguration:(WKWebViewConfiguration *)configuration;
@end

@implementation ChsiInjector

+ (instancetype)shared {
    static ChsiInjector *inst = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ inst = [[ChsiInjector alloc] init]; });
    return inst;
}

// 主路径：在 WKWebView 原始 init 执行【之前】把用户脚本装进 config。
// 关键时序：WKWebView init 内部会 copy configuration —— init 之后才装，
// 只会改到原 config 对象，脚本永远到不了 webview。
// 守卫挂在 userContentController 上（同一 config 可能创建多个 webview）。
+ (void)installUserScriptIntoConfiguration:(WKWebViewConfiguration *)configuration {
    if (!configuration) return;
    WKUserContentController *ucc = configuration.userContentController;
    if (!ucc) return;
    if (objc_getAssociatedObject(ucc, kChsiScriptInstalledKey)) return;

    WKUserScript *script =
        [[WKUserScript alloc] initWithSource:InjectionJS()
                               injectionTime:WKUserScriptInjectionTimeAtDocumentEnd
                              forMainFrameOnly:NO];
    [ucc addUserScript:script];
    objc_setAssociatedObject(ucc, kChsiScriptInstalledKey, @YES,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    CHLog(@"WKUserScript 已装入（v4：设置页/面板均可改值，改完设置刷新页面生效）");
}

// 2026-09-19：检测到页面就改写 —— 默认不再按域名/路径过滤。
- (BOOL)isTargetURL:(NSURL *)url {
    if (!kOnlyChsiHost) return YES;
    if (!url) return NO;
    NSString *s = url.absoluteString ?: @"";
    return [s rangeOfString:@"chsi.com.cn"].location != NSNotFound;
}

// 兜底路径：evaluateJavaScript 定次补改（JS 带最新 VER，可热更旧页面）
- (void)scheduleInjectForWebView:(WKWebView *)webView {
    __weak WKWebView *weakWV = webView;
    NSString *js = InjectionJS();

    [self runInject:js on:weakWV index:1];

    for (int i = 1; i < kRepatchCount; i++) {
        int64_t delayMS = (int64_t)kRepatchIntervalMS * i;
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, delayMS * NSEC_PER_MSEC),
            dispatch_get_main_queue(),
            ^{
                [self runInject:js on:weakWV index:i + 1];
            });
    }
}

- (void)runInject:(NSString *)js on:(WKWebView *)webView index:(int)idx {
    if (!webView) return;
    [webView evaluateJavaScript:js
              completionHandler:^(id result, NSError *error) {
        if (error) {
            CHLog(@"第 %d 次注入失败: %@", idx, error.localizedDescription);
        } else {
            NSString *applied = [result isKindOfClass:[NSString class]] ? result : @"";
            CHLog(@"第 %d 次注入完成，已改: %@", idx,
                  applied.length > 0 ? applied : @"(无匹配)");
            // v4.6.44：applied 带**照片诊断**或**自动流程动作**（自动点/自动登录）
            //   都走一次探针回传 —— 自动流程排障用。
            if ([applied rangeOfString:@"照片"].location != NSNotFound ||
                [applied rangeOfString:@"自动"].location != NSNotFound) {
                ChsiFloatDiag(@"js#%d %@", idx, applied);
            }
        }
    }];
}

@end

// ==================== v4：本机覆盖配置写入（编辑器用）====================

// 把编辑器当前值写进本 App 沙箱内的配置 plist（键 = 字段名 + enabled）。
// 该 plist 是 EffectiveRules / ChsiEnabled 的最高优先层。
// ⚠️ v4.1.9：只写本 App 沙箱 —— QQ 与微信各存各的，互不影响。
// overrides 只含要覆盖的键（缺键 = 删本机覆盖，回到面板/内置默认）；
// enabled == nil 表示连 enabled 键一起删（「恢复默认」用）。
static BOOL ChsiConfigWrite(NSDictionary *overrides, NSNumber *enabled) {
    @try {
#if defined(CHSI_BUILD_QQ)
        // v4.3.5：只更新内存层，**不写任何文件**（本地不留存插件配置）。
        if (!gCfgMem) gCfgMem = [NSMutableDictionary dictionary];
        NSMutableDictionary *d = gCfgMem;
#else
        NSMutableDictionary *d =
            [NSMutableDictionary dictionaryWithContentsOfFile:ChsiConfigPath()];
        if (!d) d = [NSMutableDictionary dictionary];
#endif
#if defined(CHSI_BUILD_QQ)
        NSUInteger n = 0;        // 只给内存模式的日志计数；WX 分支别声明，否则 -Werror 报未使用
#endif
        for (NSArray *spec in FieldSpecsOrdered()) {
            NSString *label = spec[1];
            NSString *v = overrides[label];
            // v4.6.0：**空串 = 无覆盖**（删键，回落默认）。
            //   老注释写的是「空字符串 = 显式清空（隐藏该字段值）」，但用户
            //   实测语义相反：把值删空就是「想恢复默认」。现在统一成删键。
            if (v == nil || v.length == 0) {
                [d removeObjectForKey:label];
            } else {
                d[label] = v;
#if defined(CHSI_BUILD_QQ)
                n++;            // 只给内存模式的日志计数（WX 分支用不到，别留未读变量）
#endif
            }
        }
        if (enabled == nil) [d removeObjectForKey:@"enabled"];
        else d[@"enabled"] = enabled;
#if defined(CHSI_BUILD_QQ)
        CHLog(@"本机配置已更新：覆盖 %lu 项，开关 %@，学校名称=%@",
              (unsigned long)n,
              enabled ? ([enabled boolValue] ? @"开" : @"关") : @"(未设置→默认)",
              d[@"学校名称"] ?: @"(无)");
        // v4.6.44：落盘持久化（除授权码外全存；杀 QQ / 切后台不丢）。
        //   🔴 例外：学信网账号/密码只存内存（用户指定）——落盘副本剔除这两键。
        NSString *diskPath = ChsiQQCfgDiskPath();
        NSMutableDictionary *disk = [NSMutableDictionary dictionaryWithDictionary:d];
        [disk removeObjectForKey:@"学信网账号"];
        [disk removeObjectForKey:@"学信网密码"];
        [[NSFileManager defaultManager] createDirectoryAtPath:
            [diskPath stringByDeletingLastPathComponent] withIntermediateDirectories:YES
                                                            attributes:nil error:NULL];
        BOOL okDisk = [disk writeToFile:diskPath atomically:YES];
        CHLog(@"配置落盘 %@（%lu 项，账密只存内存）", okDisk ? @"成功" : @"失败", (unsigned long)disk.count);
        return YES;
#else
        NSString *path = ChsiConfigPath();
        BOOL ok = [d writeToFile:path atomically:YES];
        // 写后回读校验（比对「学校名称」是否真落盘），失败要能在日志里看到
        NSDictionary *back = [NSDictionary dictionaryWithContentsOfFile:path];
        CHLog(@"本机配置写入 %@ → %@（回读条数 %lu，学校名称=%@）",
              ok ? @"成功" : @"失败", path,
              (unsigned long)back.count,
              back[@"学校名称"] ?: @"(无)");
        return ok;
#endif
    } @catch (NSException *e) {
        CHLog(@"本机配置写入失败: %@", e);
        return NO;
    }
}

// v4.6.0：原 `ChsiPanelEnabled()` 已删除 —— 「开启改写」总开关从编辑器下线后
//   它再无调用点，留着会被 `-Werror,-unused-function` 拦下（CI 必挂）。
//   面板值读取逻辑已在上面 `ChsiEnabled()` 里内联，无需另立函数。

// ==================== v4：probe 日志（定位 QQ 设置页类名用）====================

// 每个进程生命周期内同类名只记一次；文件超 48KB 截尾到 32KB。
// 用户开一次 QQ 设置页，把 /var/mobile/Library/ChsiHook/probe.log 发回来即可定位。
static void ChsiProbeLog(NSString *line) {
    static NSMutableSet *seen = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ seen = [NSMutableSet set]; });
    if (line.length == 0) return;
    if ([seen containsObject:line]) return;
    [seen addObject:line];
    @try {
        NSString *dir = @"/var/mobile/Library/ChsiHook";
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:nil];
        NSString *path = [dir stringByAppendingPathComponent:@"probe.log"];
        NSString *old = [NSString stringWithContentsOfFile:path
                                                  encoding:NSUTF8StringEncoding
                                                     error:nil] ?: @"";
        if (old.length > 48000) old = [old substringFromIndex:old.length - 32000];
        NSString *out = [NSString stringWithFormat:@"%@%@\t%@\n",
                         old, [[NSDate date] description], line];
        [out writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch (NSException *e) { /* 权限问题就放弃，只留 NSLog */ }
    CHLog(@"probe: %@", line);
}

// ==================== v4：设置页候选类 ====================

// QQ：全量扫类名（含 setting + controller 的类），缓存并写 probe 日志
static NSArray *ChsiScanSettingClassNames(void) {
    static NSArray *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSMutableArray *m = [NSMutableArray array];
        unsigned int n = 0;
        Class *list = objc_copyClassList(&n);
        if (list) {
            for (unsigned int i = 0; i < n; i++) {
                NSString *name = NSStringFromClass(list[i]);
                if (name.length == 0 || name.length > 48) continue;
                NSString *low = [name lowercaseString];
                if (![low containsString:@"setting"]) continue;
                if (![low containsString:@"controller"]) continue;
                if ([low containsString:@"cell"] || [low containsString:@"item"]) continue;
                if ([low containsString:@"section"] || [low containsString:@"header"]) continue;
                [m addObject:name];
            }
            free(list);
        }
        [m sortUsingSelector:@selector(localizedCompare:)];
        cached = [m copy];
        for (NSString *s in cached) {
            ChsiProbeLog([NSString stringWithFormat:@"[scan-candidate] %@", s]);
        }
    });
    return cached;
}

// 当前 App 的设置页候选类名（微信 = 社区已知类名；QQ = 运行时扫描）
static NSArray *ChsiSettingCandidates(void) {
    static NSArray *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
        if ([bid isEqualToString:@"com.tencent.xin"]) {
            cached = @[@"NewSettingViewController",
                       @"MMNewSettingViewController",
                       @"SettingViewController"];
        } else if ([bid isEqualToString:@"com.tencent.mqq"]) {
            cached = ChsiScanSettingClassNames();
        } else {
            cached = @[];
        }
    });
    return cached;
}

// ==================== v4.1：App 内悬浮球（全公开 UIKit）====================
// 设计约束：
//   * 44×44 独立 UIWindow，绑定 foreground UIWindowScene（无 scene 降级
//     initWithFrame:），windowLevel = UIWindowLevelAlert + 100；
//   * 【绝不调 makeKeyAndVisible】——不抢宿主 App 的 key 状态；
//   * ⚠️ 窗口尺寸 = 球尺寸，且【球自己就是 rootVC.view】（无子视图叠层）：
//     窗口只在球的 44×44 区域参与 hit-test，球外系统直接交给宿主窗口 →
//     天然穿透。（v4.1 曾用「全屏透明承载层 + 球做子视图」，实测症状是
//     球可见但点不动、且 QQ 整个 App 都点不动 —— 见下方实现处注释。）
//   * 可拖动（窗口随手指位移 + 20pt 边距钳制）、松手左右吸边、
//     位置记忆 NSUserDefaults chsi_float_x/y；
//   * 点按 → ChsiPresentEditorFrom(nil)（定义在插行段，此处前向声明）。

void ChsiPresentEditorFrom(id fromObject);   // 前向声明（悬浮球点按引用）

// ==================== v4.6.3：悬浮球诊断埋点 ====================
// 🔴 背景：v4.6.2 删掉 hitTest 闸门后，真机反馈**双指长按 + 三指双击
//   都不能唤出编辑器**。静态审代码这条链本该是通的 —— 说明断点在
//   运行时（球没在屏上 / 窗口收不到触摸 / scene 漂移 / 用户按的位置不对），
//   光看代码猜不出来。⇒ 在球链路上全程埋点，写进 probe.log（用户可取回）。
//   取回路径：/var/mobile/Library/ChsiHook/probe.log（与设置页扫描同一个文件）
//   注意：probe.log 有「同行去重」，所以**每条日志都带动态数值**
//   （时间戳由 ChsiProbeLog 自己加；这里额外带上关键状态），确保不重复。
//   ⚠️ v4.6.4：**同时自动回传到后台 /probe** —— 用户不用再手工导文件。
//     真机做一次手势，服务器 probe-inbox/ 里就有日志。仅 QQ 包（授权段所在包）。
static void ChsiFloatDiag(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSString *line = [NSString stringWithFormat:@"[float] %@", msg];
    ChsiProbeLog(line);
#if defined(CHSI_BUILD_QQ)
    // v4.6.4：每行诊断都自动 POST 回后台（fire-and-forget，失败静默）。
    NSString *qq = ChsiQQID() ?: @"unknown";
    NSDictionary *o = @{ @"qq": qq, @"line": line };
    NSData *d = [NSJSONSerialization dataWithJSONObject:o options:0 error:nil];
    if (d) {
        NSString *json = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        ChsiLicensePostPath(json, @"/probe", ^(NSString *r, BOOL f) {
            if (f) CHLog(@"probe 回传失败: %@", line);
        });
    }
#endif
}


// ==================== v4.6.11：登录 QQ 号监测 + 不匹配/切号/加号闪退 ====================
// 用户需求：① 检测当前登录的 QQ 号；② 当前登录号 ≠ 弹框第二栏手填的绑定号
//   （= 后台下发验证码对应的号）→ 自动闪退 QQ；③ 切换 QQ 账号 → 闪退；
//   ④ 添加 QQ 账号（登录了别的号）→ 闪退。
// 检测手段（只信「活跃」信号，警惕 v4.3.4 铁证的沙盒历史残留）：
//   ① hook -[NSUserDefaults objectForKey:] —— key 含 uin/qqnum/username/account
//      且值为 5~12 位纯数字 → 当场判定（QQ 账号态切换必然读写 defaults）；
//   ② 周期 10s tick：Documents/Files 下纯数字目录按 mtime 取**最新**
//      （当前活跃账号目录被高频写，mtime 必然最新 —— 老版 ChsiQQGuess 的
//      缺陷是「取第一个」而不是「取最新」）。
// 闪退门控（三道，防误杀）：
//   a. 绑定号非空（用户在弹框里填过）；
//   b. gSessionVerified == YES（后台已验证 该码+该号 绑定关系）；
//   c. 信号来源可杀（defaults 读事件 / dir-newest）；plist 键值**只进诊断**
//      （mqq.plist 里可能躺着残留的旧号 key，杀了会误伤）。
// 诊断：每次检测值变化打 `qq-watch detect=…`，闪退前打 `qq-mismatch KILL`
//   —— 全走 /probe 自动回传，误杀可复盘。
#if defined(CHSI_BUILD_QQ)
static NSString *gDetectedQQ = nil;          // 最近一次检测到的活跃号
static dispatch_queue_t gWatchQ = nil;       // 串行队列，保护 gDetectedQQ

static id (*gOrigNSUserDefaultsObjectForKey)(id, SEL, NSString *);

static BOOL ChsiQQLooksNum(NSString *s) {
    if (s.length < 5 || s.length > 12) return NO;
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];
        if (c < '0' || c > '9') return NO;
    }
    return YES;
}

static BOOL ChsiQQWatchKeyMatch(NSString *k) {
    if (k.length == 0 || k.length > 64) return NO;
    NSString *lk = [k lowercaseString];
    return [lk containsString:@"uin"] || [lk containsString:@"qqnum"]
        || [lk containsString:@"username"] || [lk containsString:@"account"];
}

static void ChsiQQWatchKill(NSString *qq, NSString *bound, NSString *src) {
    ChsiFloatDiag(@"qq-mismatch KILL detected=%@ bound=%@ src=%@", qq, bound, src);
    CHLog(@"当前登录 QQ(%@) ≠ 绑定号(%@)（%@）→ 0.35s 后闪退", qq, bound, src);
    // 与 ChsiCancelQuit 同款杀法：后台队列 0.35s → SIGKILL → _exit(1) 兜底
    // （绝不能挂主队列 —— 主线程卡住就永远杀不死，v4.3.6 教训）。
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        usleep((useconds_t)(0.35 * 1000000.0));
        kill(getpid(), SIGKILL);
        usleep(200000);
        _exit(1);
    });
}

// 每个候选号都过这里：去重 → 诊断 → 门控判定
// 🔴 v4.6.12：killable 改为显式传参 —— dir-newest 已被真机证伪
//   （11:47:18 误杀：残留目录 249986308 的 mtime 比真登录号 1326814220 新，
//   验证通过 10 秒就被杀 → QQ 重开再弹框 = 用户看到的「弹 2 次/又弹一个」）。
//   可杀信号只剩两种：defaults 读事件 / plist 的 LastLoginUin 类键
//   （GuildPostLaunchLastLoginUinKey = QQ 自己维护的「本次启动最后登录号」，
//   真机实测准确）。dir 与其他 plist 键只进诊断。
static void ChsiQQWatchCheck(NSString *qq, NSString *src, BOOL killable) {
    if (!ChsiQQLooksNum(qq)) return;
    NSString *bound = ChsiQQOverride();
    __block BOOL changed = NO;
    dispatch_sync(gWatchQ, ^{
        if (![qq isEqualToString:(gDetectedQQ ?: @"")]) {
            gDetectedQQ = [qq copy];
            changed = YES;
        }
    });
    if (changed) {
        ChsiFloatDiag(@"qq-watch detect=%@ bound=%@ src=%@ verified=%d",
                      qq, bound.length ? bound : @"(未填)", src,
                      gSessionVerified ? 1 : 0);
        // v4.6.44：**检测到号的瞬间就弹授权**（此前只在 15s 后的 tick 里弹，
        //   用户重启 QQ 后几秒内就切走/杀掉，弹窗永远赶不上）。未验证 +
        //   号码合法 → 主队列弹框（号码自动带出）。tick 里的同款逻辑保留作兜底。
        if (!gSessionVerified && qq.length >= 5) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (gSessionVerified || gPrompting || gPromptInFlight) return;
                if (ChsiOurAlertIsOnScreen()) return;
                ChsiFloatDiag(@"detect-prompt qq=%@", qq);
                ChsiLicensePrompt();
            });
        }
    }
    if (bound.length < 5 || !gSessionVerified) return;   // 门控 a/b
    if (killable && ![qq isEqualToString:bound]) {       // 门控 c + 不匹配
        ChsiQQWatchKill(qq, bound, src);
    }
}

// NSUserDefaults hook：读到的号类值当场判定（切号/加号时 QQ 必刷这些键）
static id ChsiQQDefaultsObjectForKeyHook(id self, SEL _cmd, NSString *key) {
    id v = gOrigNSUserDefaultsObjectForKey(self, _cmd, key);
    @try {
        if (key && ChsiQQWatchKeyMatch(key)) {
            NSString *s = nil;
            if ([v isKindOfClass:[NSString class]] && ChsiQQLooksNum(v)) s = v;
            else if ([v isKindOfClass:[NSNumber class]]) {
                NSString *t = [(NSNumber *)v stringValue];
                if (ChsiQQLooksNum(t)) s = t;
            }
            if (s) {
                ChsiQQWatchCheck(s, [NSString stringWithFormat:@"defaults:%@", key], YES);
            } else if (gSessionVerified && gDetectedQQ.length >= 5
                       && [key isEqualToString:@"GuildPostLaunchLastLoginUinKey"]) {
                // v4.6.44：**退出登录也闪退** —— 本会话已验证且见过登录号，
                //   而 QQ 自己的「本次启动最后登录号」键被清空/置空 = 用户
                //   退出了登录。门控收紧到该键 + 已验证 + 本会话见过号，
                //   防止启动早期（键还没值）误杀。
                ChsiFloatDiag(@"qq-logout KILL had=%@ key=%@", gDetectedQQ, key);
                CHLog(@"检测到退出登录（%@ 已清空）→ 0.35s 后闪退", key);
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    usleep((useconds_t)(0.35 * 1000000.0));
                    kill(getpid(), SIGKILL);
                    usleep(200000);
                    _exit(1);
                });
            }
        }
    } @catch (NSException *e) { }
    return v;
}

// v4.6.12：当前登录号（读 QQ 自己维护的「本次启动最后登录号」键）。
// 🔴 v4.6.13：**改读内存 NSUserDefaults，弃用磁盘 plist** —— 真机铁证
//   （12:03:30）：同一把键，内存 defaults = 1326814220（当前值，正确），
//   磁盘 plist = 249986308（上一次会话切号测试留下的滞后值）→ 弹框把滞后号
//   锁进只读栏 → DENY qq_not_match → 重开再弹 = 用户看到的「弹 2 次」。
//   磁盘 plist 落后于内存，永远不可信；内存值由 defaults hook 实时印证。
static NSString *ChsiQQCurrentLogin(void) {
    @try {
        // ① 内存 defaults 的 GuildPostLaunchLastLoginUinKey（live，优先）
        id v = [[NSUserDefaults standardUserDefaults]
                objectForKey:@"GuildPostLaunchLastLoginUinKey"];
        NSString *s = nil;
        if ([v isKindOfClass:[NSString class]] && ChsiQQLooksNum(v)) s = v;
        else if ([v isKindOfClass:[NSNumber class]]) {
            NSString *t = [(NSNumber *)v stringValue];
            if (ChsiQQLooksNum(t)) s = t;
        }
        if (s) return s;
        // ② watch 已抓到的最新 defaults 值（启动早期键还没被读到时的兜底）
        __block NSString *det = nil;
        dispatch_sync(gWatchQ, ^{ det = gDetectedQQ; });
        if (det.length >= 5) return det;
    } @catch (NSException *e) { }
    return @"";
}

// 纯数字目录快照：按 mtime 新→旧，最新 = 当前活跃账号
static NSArray *ChsiQQDirSnapshot(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *out = [NSMutableArray array];
    NSArray *dirs = @[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"],
                      [NSHomeDirectory() stringByAppendingPathComponent:@"Files"]];
    for (NSString *dir in dirs) {
        NSArray *ents = [fm contentsOfDirectoryAtPath:dir error:NULL];
        for (NSString *e in ents) {
            if (!ChsiQQLooksNum(e)) continue;
            NSString *full = [dir stringByAppendingPathComponent:e];
            NSDictionary *attr = [fm attributesOfItemAtPath:full error:NULL];
            NSDate *mt = attr[NSFileModificationDate];
            [out addObject:@{ @"num": [e copy], @"mt": mt ?: [NSDate distantPast] }];
        }
    }
    [out sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [(NSDate *)b[@"mt"] compare:a[@"mt"]];
    }];
    return out;
}

static void ChsiQQWatchTick(void) {
    @try {
        // ⓪ v4.6.44：**登录后才弹授权** —— 检测到登录号且未验证时自动弹
        //    （号码自动带出，用户只填码）。未登录/空号状态绝不弹框。
        __block NSString *det0 = nil;
        dispatch_sync(gWatchQ, ^{ det0 = gDetectedQQ; });
        if (!gSessionVerified && det0.length >= 5 && !gPrompting && !gPromptInFlight) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (gSessionVerified || gPrompting || gPromptInFlight) return;
                if (ChsiOurAlertIsOnScreen()) return;
                CHLog(@"watch tick：已检测到登录号 %@ 且未验证 → 自动弹授权框", det0);
                ChsiLicensePrompt();
            });
        }
        // ① 目录快照：**v4.6.12 起只诊断不杀**（mtime 新 ≠ 当前登录号，
        //    真机 11:47:18 铁证：残留目录 249986308 mtime 比真号还新 → 误杀循环）
        NSArray *cands = ChsiQQDirSnapshot();
        if (cands.count) {
            ChsiQQWatchCheck(cands[0][@"num"], @"dir-newest-diag", NO);
            NSMutableArray *nms = [NSMutableArray array];
            for (NSUInteger i = 0; i < cands.count && i < 3; i++) [nms addObject:cands[i][@"num"]];
            static int sBaseOnce = 0;
            if (sBaseOnce++ < 2) {
                ChsiFloatDiag(@"qq-watch dirs(top3)=%@ bound=%@", nms,
                              ChsiQQOverride().length ? ChsiQQOverride() : @"(未填)");
            }
        }
        // ② plist 键：**v4.6.13 起全部只诊断不杀** —— 磁盘 plist 滞后于内存
        //    （12:03:30 铁证：磁盘 GuildPostLaunchLastLoginUinKey 还是上次会话
        //    的 249986308，内存已是 1326814220）。可杀信号只剩 defaults hook。
        NSString *pp = [NSHomeDirectory() stringByAppendingPathComponent:
                        @"Library/Preferences/com.tencent.mqq.plist"];
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:pp];
        for (NSString *k in prefs) {
            if (!ChsiQQWatchKeyMatch(k)) continue;
            id v = prefs[k];
            NSString *s = nil;
            if ([v isKindOfClass:[NSString class]] && ChsiQQLooksNum(v)) s = v;
            else if ([v isKindOfClass:[NSNumber class]]) {
                NSString *t = [(NSNumber *)v stringValue];
                if (ChsiQQLooksNum(t)) s = t;
            }
            if (!s) continue;
            ChsiQQWatchCheck(s, [NSString stringWithFormat:@"plist:%@", k], NO);
        }
        // ③ 内存 defaults（v4.6.14：**唯一可靠的周期可杀信号**）——
        //    磁盘 plist 滞后（铁律 P），而 GuildPostLaunchLastLoginUinKey
        //    QQ 只在启动时读一次 ⇒ 只靠 hook 抓不到切号（v4.6.13 装机反馈
        //    「切号/加号闪退失效」）⇒ tick 直接读内存 defaults（实时准确）。
        id mv = [[NSUserDefaults standardUserDefaults]
                 objectForKey:@"GuildPostLaunchLastLoginUinKey"];
        NSString *ms = nil;
        if ([mv isKindOfClass:[NSString class]] && ChsiQQLooksNum(mv)) ms = mv;
        else if ([mv isKindOfClass:[NSNumber class]]) {
            NSString *t = [(NSNumber *)mv stringValue];
            if (ChsiQQLooksNum(t)) ms = t;
        }
        if (ms) ChsiQQWatchCheck(ms, @"memdefaults:GuildPostLaunchLastLoginUinKey", YES);
        // ---- ④ v4.6.15：会话过期心跳（防抓包重放）----
        //   到期前 5 分钟内静默复验换新 exp；过期即刻清 jskey（JS 模板解不出
        //   → 改写失效）并置 Denied。网络失败 → 保持锁定，直到复验成功。
        static double sLastReverify = 0;
        double now = [[NSDate date] timeIntervalSince1970];
        if (gSessionVerified && gSessExp > 0 && now > gSessExp - 300
            && now - sLastReverify > 120) {
            sLastReverify = now;
            ChsiFloatDiag(@"session-exp reverify exp=%.0f now=%.0f", gSessExp, now);
            if (now > gSessExp) {
                gSessionVerified = NO;
                gJSKeyHex = nil;
                gSessExp = 0;
                gLicenseState = (NSInteger)ChsiLicenseDenied;
                [[NSNotificationCenter defaultCenter]
                 postNotificationName:@"ChsiLicenseChanged" object:nil];
            }
            if (gEnteredCode.length) ChsiLicenseVerify(gEnteredCode);
        }
    } @catch (NSException *e) { }
}

// v4.6.14：setObject:forKey: 写事件 hook —— 切号/加号时 QQ 会**写**登录号键，
//   读事件（objectForKey:）可能不发生，写 hook 保证当场抓到。
static void (*gOrigNSUserDefaultsSetObjectForKey)(id, SEL, id, NSString *);

static void ChsiQQDefaultsSetObjectForKeyHook(id self, SEL _cmd, id value, NSString *key) {
    gOrigNSUserDefaultsSetObjectForKey(self, _cmd, value, key);
    @try {
        if (key && ChsiQQWatchKeyMatch(key)) {
            NSString *s = nil;
            if ([value isKindOfClass:[NSString class]] && ChsiQQLooksNum(value)) s = value;
            else if ([value isKindOfClass:[NSNumber class]]) {
                NSString *t = [(NSNumber *)value stringValue];
                if (ChsiQQLooksNum(t)) s = t;
            }
            if (s) ChsiQQWatchCheck(s,
                [NSString stringWithFormat:@"defaults-set:%@", key], YES);
        }
    } @catch (NSException *e) { }
}

static void ChsiQQWatchStart(void) {
    static dispatch_once_t once;
    static dispatch_source_t sTimer;
    dispatch_once(&once, ^{
        gWatchQ = dispatch_queue_create("chsi.qqwatch", DISPATCH_QUEUE_SERIAL);
        // hook NSUserDefaults objectForKey:
        Method m = class_getInstanceMethod([NSUserDefaults class],
                                           @selector(objectForKey:));
        if (m) {
            gOrigNSUserDefaultsObjectForKey =
                (id (*)(id, SEL, NSString *))method_getImplementation(m);
            method_setImplementation(m, (IMP)ChsiQQDefaultsObjectForKeyHook);
            CHLog(@"QQ 号监测：NSUserDefaults hook 已挂");
        }
        // v4.6.14：setObject:forKey: 写事件 hook（切号/加号时 QQ 写登录号键）
        Method m2 = class_getInstanceMethod([NSUserDefaults class],
                                            @selector(setObject:forKey:));
        if (m2) {
            gOrigNSUserDefaultsSetObjectForKey =
                (void (*)(id, SEL, id, NSString *))method_getImplementation(m2);
            method_setImplementation(m2, (IMP)ChsiQQDefaultsSetObjectForKeyHook);
            CHLog(@"QQ 号监测：NSUserDefaults 写 hook 已挂");
        }
        // 首拍 15s 后（等 QQ 登录态稳定），之后每 10s 一拍
        sTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                        dispatch_get_global_queue(
                                            DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
        dispatch_source_set_timer(sTimer,
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15 * NSEC_PER_SEC)),
            (uint64_t)(10 * NSEC_PER_SEC), (uint64_t)(2 * NSEC_PER_SEC));
        dispatch_source_set_event_handler(sTimer, ^{ ChsiQQWatchTick(); });
        dispatch_resume(sTimer);
        ChsiFloatDiag(@"qq-watch started ver=v4.6.44 —— 监测登录号，"
                      @"不匹配即闪退");
    });
}
#endif   // CHSI_BUILD_QQ


// 🔴🔴🔴 v4.6.9：**悬浮球 UI 整体移除** —— 编辑器入口只留双指长按。
// ------------------------------------------------------------
// 用户要求：把悬浮球去除，打开编辑器只剩双指长按这一个入口。
//   ✅ 保留：双指长按（宿主窗口全屏手势，授权门控，v4.6.6~v4.6.7 修通）；
//   ❌ 删除：球窗口（44×44）、球视图（ChsiFloatBallView）、单击/拖动、
//      三指双击（它只负责切球显隐，球没了就没有意义）、显隐持久化
//      （chsi_float_hidden）、位置记忆（chsi_float_x/y）、
//      ChsiFloatSetHidden / ChsiFloatApplyGestureMode 等整套显隐逻辑。
//   ChsiFloatViewController 瘦身为「手势 target」：不再有球视图/窗口，
//   只承载 chsiFloatTwoFingerLongPress:（授权门控 + 唤出编辑器）。
//   以下是本项目沉淀的铁律，**全部继续有效**（历史记录见各版本注释）：
//   🔴 铁律 F：「留在屏上但不挡事」的全屏高等级窗口不存在。
//   🔴 铁律 G：不要用 `hitTest` 做「按手指数分流」。
//   🔴 铁律 N：QQ 的 activationState 恒为 0，是假信号。
@interface ChsiFloatViewController : UIViewController
@end

static ChsiFloatViewController *gFloatVC = nil;   // 手势 target（static 强引用）

// v4.6.6~v4.6.7：宿主窗口全屏兜底手势 —— 双指长按挂到 QQ 自己的窗口上
//   （宿主窗口本来就收得到全屏触摸，不需要自建全屏窗口 —— 铁律 F）。
//   ChsiHostGesturesAttach() 穷举**所有**符合条件的 QQ 窗口逐个挂载
//   （每个窗口一组新手势，associated object 防重挂）—— QQ 是多窗口/
//   多 scene 结构，只挂「第一个」会挂错窗口。

// v4.6.6：宿主窗口上的「全屏多指手势」—— 修「隐藏态双指长按/三指双击
//   只在球那 44×44 里有效」的回归（v4.6.0 时代隐藏态是全屏感应层，
//   双指长按全屏任意位置都能唤出编辑器；v4.6.1 把窗口缩回 44×44 时，
//   手势命中区也跟着缩小了，但没人意识到这个副作用 —— 真机第 18/19 轮
//   「双指长按没反应」的真根因）。
//   ✅ 做法：把两个多指手势**复制一份挂到 QQ 自己的窗口上** ——
//   宿主窗口本来就收得到全屏触摸，不需要自建全屏窗口（铁律 F：
//   「留在屏上但不挡事」的全屏高等级窗口不存在）。触摸在球区时命中
//   球窗口（球组手势响应）、在球区外时命中宿主窗口（宿主组响应），
//   两者命中区互斥，不会双触发。
//   v4.6.7：改由 ChsiHostGesturesAttach() 穷举**所有**符合条件的 QQ
//   窗口逐个挂载（每个窗口一组新手势，associated object 防重挂）——
//   QQ 是多窗口/多 scene 结构，只挂「第一个」会挂错窗口。

// v4.6.8：「显示悬浮球」开关已随编辑器开关行一起删除 ——
//   入口只留双指长按（全屏，见 v4.6.6/v4.6.7 宿主手势）。
//   原 ChsiFloatEnabled() / ChsiFloatApplyVisibility() / swFloatChanged:
//   已删除（调用点全没了，留着会 -Werror,-unused-function）。
// v4.6.9：ChsiFloatHidden() / ChsiFloatStoreHidden()（chsi_float_hidden）
//   与 kChsiFloat* 常量也随悬浮球 UI 一起删除。

// 🔴🔴🔴 v4.6.2：**删掉 hitTest 多指闸门** —— 它把「双指长按」彻底打死了。
// ------------------------------------------------------------
// v4.6.1 的闸门逻辑（`chsiPassthroughMode` 为真时 `allTouches.count < 2`
// 就返回 nil）从原理上就是错的：
//
//   🔴 **`hitTest:withEvent:` 只在「触摸开始时」被调用一次**，
//     而那一刻 iOS **还不知道用户最终会放几根手指** ——
//     第一根手指落下的瞬间 `event.allTouches.count` 就是 **1**，
//     闸门据此返回 nil ⇒ **球直接被排除出这次触摸事件**；
//     之后第二根手指再落下，窗口系统**不会重新做 hitTest**，
//     球也就永远收不到这个手势。
//   ⇒ 结果：**双指长按（以及三指双击）在隐藏态下完全失效**。
//     （真机反馈：「现在双指长按打不开窗口」——即本闸门所致。）
//
//   ⚠️ 而且它是**多余的**：「点完成之后 QQ 点不动」的真正修法只是
//     「**窗口保持球大小（44×44）**」—— 窗口既然只有球那么大，
//     屏幕其余部分天然穿透，根本不需要再加一道闸门。
//     v4.6.1 多加这道闸门属于**过度设计**，代价是把唯一的唤出入口打死。
//
//   ✅ v4.6.2 起：球的 `hitTest` 一律走 **默认实现**（`[super hitTest:…]`），
//     不再做任何手指数判断。隐藏态下 44×44 区域内：
//       · 单指 → 被球接走（但 `chsiApplyGestureModeForHidden:` 已把
//         单击/拖动手势 `enabled = NO`，所以**什么都不会发生**，
//         既不会误触编辑器、也谈不上「挡住 QQ」——因为那本来就是
//         球自己的 44×44 地盘，且球已不可见、不会有视觉上的「点不动」）；
//       · 双指 / 三指 → 正常被手势识别器捕获 → 唤出编辑器 ✅。
//
//   🔴 铁律（新增）：**不要用 `hitTest` 做「按手指数分流」** ——
//     它拿不到「最终手指数」，只能看到「这一刻已有几根手指」。
//     要按手指数分流，只能在**手势识别器层面**做（`numberOfTouchesRequired`），
//     那正是本文件 `chsiApplyGestureModeForHidden:` 干的事。
//
//   注意：`ChsiFloatBallView` 这个子类**保留**（它是"球"这个 UIView 的载体，
//     将来若要按需扩展更稳），但 `chsiPassthroughMode` 属性与 `hitTest:`
//     覆写都**已删除**。
// 🔴 v4.6.9：`ChsiFloatBallView` 已随悬浮球 UI 一起删除（球没了）。

// 把球切到「隐藏」或「显示」形态。**两种形态的窗口尺寸都是球大小**。
//
// ⚠️ v4.6.1：隐藏态 = 球**变透明**（看不见）+ 球区 `hitTest` 只认多指。
//   · 为什么不做全屏感应层：全屏窗口 = 整屏 hit-test = 必然吃掉宿主触摸，
//     表现就是「关掉编辑器后 QQ 整个点不动」（v4.6.0 真机第十二轮反馈）。
//     历史教训见文件上方 v4.5.0 结论 + 本函数下方的 v4.6.1 长注释。
//   · 隐藏态要点：
//     1. 窗口背景 clearColor、球背景也 clearColor 且阴影/圆角清零；
//     2. 不能用 view.alpha = 0（alpha < 0.01 不参与 hit-test，
//        那样手势也收不到了）—— 必须「可见但全透明」；
//     3. 单指手势（单击/拖动）关掉、且球区 hitTest 对单指返回 nil
//        （穿透给 QQ），只放行多指（三指双击 / 双指长按）。
// v4.6.6：把宿主组多指手势挂到 QQ 自己的窗口上（全屏兜底）。
//   挑窗口口径与 ChsiPickAttachScene 的第①步一致（可见 + level 正常 +
//   有 rootVC 的第一个窗口）。手势对象由 viewDidLoad 创建（target=球 VC，
//   球窗口 hidden 时 VC 仍存活，selector 照常回调）。
//   ⚠️ 调用时机：viewDidLoad（球手势建好）、ChsiFloatSetHidden 末尾、
//   mounted 复核 block —— 三处都调，天然实现「宿主窗口没就绪就重试」。
// v4.6.7：associated-object 标记，防止对同一窗口重复挂载
static const void *kChsiHostGestureMark = &kChsiHostGestureMark;

// v4.6.7：把宿主组多指手势**穷举挂到所有符合条件的 QQ 窗口上**。
//   🔴 v4.6.6 教训：只挂「第一个匹配」的窗口不够 —— QQ 是多窗口/多
//   scene 结构（activationState 全 0 就是证据），用户正在看的 UI 可能
//   在另一个 window 上（真机第 20 轮：手势挂上了 level=0 的窗口、
//   enabled=1，但双指长按依然零回调）。⇒ 全部都挂，多指手势误触风险
//   本就极低。每个窗口新建一组手势（UIGestureRecognizer 同时只能属于
//   一个 view），target = 球 VC（gFloatWindow 持有，哪怕窗口 hidden）。
static void ChsiHostGesturesAttach(void) {
    if (!gFloatVC) return;                     // 手势 target 没了就不挂
    UIViewController *vc = gFloatVC;
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        int n = 0;
        for (UIScene *sc in app.connectedScenes) {
            if (![sc isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)sc;
            for (UIWindow *w in ws.windows) {
                if (w.windowLevel >= UIWindowLevelAlert + 50) continue;
                if (w.isHidden || w.alpha < 0.01) continue;
                if (!w.rootViewController) continue;
                if (objc_getAssociatedObject(w, kChsiHostGestureMark)) {
                    n++;                           // 已挂过，计数不重挂
                    continue;
                }
                // 🔴 v4.6.9：只挂双指长按（三指双击随悬浮球 UI 一起删除，
                //   它只负责切球显隐，球没了就没有意义）。
                UILongPressGestureRecognizer *hp =
                    [[UILongPressGestureRecognizer alloc] initWithTarget:vc
                        action:@selector(chsiFloatTwoFingerLongPress:)];
                hp.numberOfTouchesRequired = 2;
                hp.minimumPressDuration = 0.6;     // 按住 0.6 秒触发
                hp.allowableMovement = 12.0;       // 手指可轻微滑动
                [w addGestureRecognizer:hp];
                objc_setAssociatedObject(w, kChsiHostGestureMark, @YES,
                                         OBJC_ASSOCIATION_RETAIN);
                n++;
                // ⚠️ 双指长按的参数值刻意写进日志文案 —— 属性名是
                //   ObjC selector，不会作为字符串字面量进二进制，校验
                //   脚本只能靠这行日志确认参数确实设上了。
                CHLog(@"双指长按手势已挂：指头数=2 按住=0.6s 容移=12pt（唤出编辑器）");
                ChsiFloatDiag(@"hostGestures attached win=%@ level=%.0f "
                              @"frame=(%.0f,%.0f,%.0f,%.0f) idx=%d",
                              NSStringFromClass([w class]),
                              (double)w.windowLevel,
                              w.frame.origin.x, w.frame.origin.y,
                              w.frame.size.width, w.frame.size.height, n);
            }
        }
        if (n == 0) {
            ChsiFloatDiag(@"hostGestures NO-WINDOW —— 没有任何可挂的宿主窗口，"
                          @"稍后重试");
        }
    } @catch (NSException *e) {
        CHLog(@"宿主手势挂载异常: %@", e);
    }
}


// 🔴 v4.6.8：原 ChsiFloatApplyVisibility() 已随「显示悬浮球」开关一起
//   删除 —— 球的显隐现在只由三指双击（chsi_float_hidden）控制，
//   创建时按持久化的隐藏状态定形态。

@implementation ChsiFloatViewController
// v4.6.9：悬浮球 UI 已移除 —— 本类瘦身为「手势 target」：
//   只承载 chsiFloatTwoFingerLongPress:（授权门控 + 唤出编辑器），
//   挂在宿主 QQ 窗口上（见 ChsiHostGesturesAttach）。

// ============================================================
// 🔴🔴🔴 v4.6.1：修「双指长按打开编辑器 → 点完成 → QQ 整个点不动」。
// ------------------------------------------------------------
// 现象（真机第十二轮）：双指长按唤出编辑器、点「完成」关掉后，
//   返回 QQ 时**整个界面点不动**（同 v4.4.0 的「触摸黑洞」）。
//
// 🔴 根因：v4.6.0 的「全屏透明感应层」从根上就是错的。
//   · v4.6.0 为了修「开关一关就唤不出编辑器」，把「开关关闭」的形态
//     从「窗口 hidden」改成了「**窗口铺满全屏 + 全透明**」；
//   · 但窗口一旦铺满，就**整个屏幕都参与 hit-test** ——
//     即使所有手势都关掉，rootVC.view（球本身）仍会命中并返回自己；
//   · 于是「完成」关掉编辑器后，回到的是这层全屏窗口 → QQ 收不到触摸。
//   · 这不是新坑：v4.4.0 已经用四版试错把这条路走死过 ——
//     **iOS 的触摸分发在窗口层级上是「最上层可见窗口优先」，
//       不会因为 hitTest 返回 nil 就继续往下层窗口找。**
//     ⇒ **不存在「留在屏上但不挡事」的全屏高等级窗口**（见文件上方 v4.5.0 结论）。
//
// ✅ 修法：**窗口永远保持「球大小」（44×44），绝不铺满全屏**。
//   开关关闭时不再放大窗口，而是：
//     ① 球**全透明**（clearColor）→ 屏幕上看不见（满足「关闭显示」的语义）；
//     ② 窗口仍是 44×44 → **只在这 44×44 区域参与 hit-test**，
//        屏幕其余部分天然穿透给 QQ（这正是球形态本来的优点）；
//   ③ 这 44×44 区域内再加一道 `hitTest` 闸门：
//      **只有「多指」触摸才命中自己**（双指长按 / 三指双击要感应），
//      **单指触摸一律返回 nil 穿透给 QQ** ——
//      这样即使开关关了、球不可见，用户单指点到那个小区域也不会被吃掉。
//   ⇒ 双指长按 / 三指双击依然可达（它们是这个入口存在的唯一理由），
//     而 QQ 在任何时刻都不会被整屏遮挡。
//
// ⚠️ 落地位置（v4.6.1 第二轮 CI 踩坑，**闸门本身已随 v4.6.2 删除**）：
//   `hitTest:withEvent:` **是 UIView 的方法，UIViewController 上没有** ——
//   最初把闸门写在本 VC 里，报
//   `no visible @interface for 'UIViewController'
//    declares the selector 'hitTest:withEvent:'`。
//   ⇒ 编译期这条仍然成立：**hitTest 只能写在 UIView 子类上**
//     （本文件 `ChsiFloatBallView` 即为此而留，v4.6.2 起不再覆写它）。
//
// 🔴🔴 v4.6.2：**那道「球区 hitTest 闸门」已删除** —— 它在原理上就是错的，
//   把双指长按彻底打死了：
//   `hitTest` 只在**触摸开始**时调用一次，那一刻 `allTouches.count` 恒为 **1**
//   （第一根手指刚落下），闸门据此返回 nil ⇒ 球被排除出这次触摸事件；
//   之后第二根手指再落（三指双击的第二三指同理），**系统都不会重做 hitTest**
//   ⇒ 隐藏态下双指长按 / 三指双击**全部失效**
//   （真机反馈：「现在双指长按打不开窗口」= 本闸门所致）。
//   ⇒ 「点完成后 QQ 点不动」的真正修法只是「**窗口保持球大小**」——
//     窗口只有 44×44 时屏幕其余部分天然穿透，**根本不需要再加闸门**。
//   详见本文件上方 `@interface ChsiFloatBallView` 处的 v4.6.2 长注释。
// ============================================================

// v4.6.1 起：双指长按 → 无条件唤出编辑器。
//   🔴 窗口**永远在屏上、永远是球大小**（不再有「全屏」「hidden」两种形态），
//     所以这里不需要任何「先把窗口显出来」的补救动作 —— 手势本来就能收到。
//     ⚠️ 前提是**没有任何 hitTest 闸门**把它挡掉（v4.6.2 已删掉那道闸门）。
//   注意：**不改** chsi_float 开关本身（用户的选择要保留 —— 开关关着就
//     一直关着，下次启动球还是不显示）。
//   v4.6.3：**记录每一次回调**（含非 began 状态）—— 用来区分两种情况：
//     · 完全没有任何回调  ⇒ 触摸根本没到球（球不在屏上 / 坐标不对 / 被挡）；
//     · 有回调但 state 不是 began ⇒ 手势识别被别的识别器搅了。
- (void)chsiFloatTwoFingerLongPress:(UILongPressGestureRecognizer *)g {
    ChsiFloatDiag(@"twoFingerLongPress state=%ld touches=%lu",
                  (long)g.state,
                  (unsigned long)g.numberOfTouches);
    if (g.state != UIGestureRecognizerStateBegan) return;   // 只认按下那一刻
    // 🔴 v4.6.8：授权门控 —— **未授权（Pending/Denied）时双指长按不可用**。
    //   QQ 包查 gLicenseState（后台 granted 才放行）；微信包
    //   ChsiLicenseAllows() 恒 YES（无授权体系）。三指双击（切显隐）
    //   不受门控 —— 它只是球的显隐开关，不给任何改写能力。
    if (!ChsiLicenseAllows()) {
        ChsiFloatDiag(@"twoPress BLOCKED —— 未授权，双指长按不可用");
        CHLog(@"双指长按被拦截：未授权（先输授权码通过后才可用）");
        return;
    }
    CHLog(@"双指长按 → 唤出编辑器");
    @try {
        ChsiPresentEditorFrom(nil);
    } @catch (NSException *e) {
        CHLog(@"双指长按打开编辑器异常: %@", e);
    }
}

@end

// v4.6.9：悬浮球 UI 已移除 —— 这里只创建「手势 target」（空 VC），
//   然后把双指长按挂到 QQ 宿主窗口上（全屏，授权门控在回调里）。
// 🔴 v4.6.10：**常驻周期补挂**。
//   真机铁证（v4.6.9 装机反馈「验证通过之后双指长按打不开」+ /probe 日志）：
//   v4.6.9 只在启动后 2s/3s 各挂一轮，而 QQ 启动期那几个窗口是临时窗口，
//   稍后 QQ 会**重建真正的交互窗口** —— 旧版 v4.6.8 靠 setHidden / mounted
//   复核 / 授权流程等多处调用点反复补挂，v4.6.9 删球时把这些调用点全删了
//   ⇒ 新交互窗口永远挂不上手势 ⇒ 双指长按零回调（连 BLOCKED 都没有）。
//   修法 = 定时器每 5 秒补挂一次（attach 幂等，已挂窗口 associated 标记
//   直接跳过，单次开销 = 遍历几个窗口，可忽略）。
static void ChsiFloatCreate(void) {
    if (gFloatVC) return;
    @try {
        gFloatVC = [[ChsiFloatViewController alloc] init];
        if (!gFloatVC) return;
#if defined(CHSI_BUILD_QQ)
        // v4.6.11：登录 QQ 号监测（不匹配/切号/加号 → 闪退）
        ChsiQQWatchStart();
#endif
        CHLog(@"ChsiHook 已就绪（悬浮球已移除，双指长按唤出编辑器）");
        ChsiFloatDiag(@"ready bundle=%@ —— 悬浮球已移除，入口=双指长按",
                      [[NSBundle mainBundle] bundleIdentifier] ?: @"");
        ChsiHostGesturesAttach();
        // v4.6.10：常驻周期补挂（5 秒一次，幂等）。
        static dispatch_source_t sKeepAttach;
        static dispatch_once_t sKeepOnce;
        dispatch_once(&sKeepOnce, ^{
            sKeepAttach = dispatch_source_create(
                DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
            dispatch_source_set_timer(
                sKeepAttach,
                dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                (uint64_t)(5 * NSEC_PER_SEC), (uint64_t)(1 * NSEC_PER_SEC));
            dispatch_source_set_event_handler(sKeepAttach, ^{
                ChsiHostGesturesAttach();
            });
            dispatch_resume(sKeepAttach);
        });
        ChsiFloatDiag(@"keepalive attach every=5s —— QQ 会重建窗口，"
                      @"必须周期补挂");
    } @catch (NSException *e) {
        CHLog(@"手势 target 创建异常: %@", e);
    }
}

// v4.1 主入口：+load 里调用；按宏限定 bundle（QQ 包只进 QQ、WX 包只进微信）。
static void ChsiInstallFloatBall(void) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    if (kChsiWantedBundle && ![bid isEqualToString:kChsiWantedBundle]) {
        CHLog(@"悬浮球模块跳过（bundle=%@ 非 %@）", bid, kChsiWantedBundle);
        return;
    }
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // 启动 2 秒后主线程创建（等宿主 scene/UI 稳定）
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
            dispatch_get_main_queue(), ^{ ChsiFloatCreate(); });
    });
}

// ==================== v4：内置编辑器（纯公开 UIKit）====================

// v4.1.5：编辑器在独立窗口里，关闭函数定义在该类之后 —— 此处文件级
// 前向声明（方法体内的 extern 声明不算文件级作用域，会导致
// implicit-function-declaration 编译错误）。
void ChsiCloseEditorWindow(void);

// v4.1.4：字段行自定义 cell（上下两行布局）
// 小面板下并排布局会把输入区压得过窄（长标签尤甚），改为：上行标签、
// 下行输入框铺满宽度。⚠️ 必须定义在 ChsiEditorVC 之前 —— 上次误插到
// ChsiEditorVC 的 @implementation 内部，导致 missing '@end' 编译失败。
@interface ChsiFieldCell : UITableViewCell
@property (nonatomic, strong) UILabel *chsiLabel;
@property (nonatomic, strong) UITextField *chsiField;
@end

@implementation ChsiFieldCell

- (instancetype)initWithStyle:(UITableViewCellStyle)style
              reuseIdentifier:(NSString *)reuseIdentifier {
    self = [super initWithStyle:style reuseIdentifier:reuseIdentifier];
    if (self) {
        _chsiLabel = [[UILabel alloc] initWithFrame:CGRectZero];
        _chsiLabel.font = [UIFont systemFontOfSize:13];
        _chsiLabel.textColor = [UIColor secondaryLabelColor];
        _chsiField = [[UITextField alloc] initWithFrame:CGRectZero];
        _chsiField.font = [UIFont systemFontOfSize:15];
        _chsiField.borderStyle = UITextBorderStyleRoundedRect;
        _chsiField.adjustsFontSizeToFitWidth = YES;
        _chsiField.minimumFontSize = 11;
        [self.contentView addSubview:_chsiLabel];
        [self.contentView addSubview:_chsiField];
    }
    return self;
}

- (void)layoutSubviews {
    [super layoutSubviews];
    CGFloat padX = 16, padY = 8;
    CGFloat w = self.contentView.bounds.size.width - padX * 2;
    if (w < 60) w = 60;
    _chsiLabel.frame = CGRectMake(padX, padY, w, 16);
    _chsiField.frame = CGRectMake(padX, padY + 18, w, 34);
}

@end

@interface ChsiEditorVC : UITableViewController
    <UITextFieldDelegate, UIImagePickerControllerDelegate, UINavigationControllerDelegate>
@end

// v4.6.44：选图专用窗口 —— 🔴 PHPicker（v4.6.19~21，present / 独立窗口
//   直挂 rootVC 两种方式）在 QQ 环境下选完图都把主线程挂死，彻底弃用。
//   换 UIImagePickerController 旧版相册选择器：内部走老路径（非 PHPicker
//   的 photolibraryd 新栈），QQ 自带相册权限声明。同样走独立窗口直挂
//   rootVC（零 presentation 动画，与 toast 窗口同一套可靠机制）。
static UIWindow *gPhotoPickWindow = nil;

@implementation ChsiEditorVC {
    // 13 个元素：NSString = 覆盖值（v4.6.0 起永不存空串）；
    //            NSNull  = 未覆盖（回落内置默认）
    NSMutableArray *_vals;
}

- (instancetype)init {
    return [super initWithStyle:UITableViewStyleGrouped];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"学信网报告改写";
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"完成"
                                        style:UIBarButtonItemStyleDone
                                       target:self
                                       action:@selector(chsiDone)];
    NSDictionary *shared = ChsiConfigRead() ?: @{};
    _vals = [NSMutableArray array];
    for (NSArray *spec in FieldSpecsOrdered()) {
        id v = shared[spec[1]];
        // v4.6.0：空串/缺失一律视为「无覆盖」→ 输入框留空、显示默认值占位。
        NSString *sv = (v == nil) ? nil : [NSString stringWithFormat:@"%@", v];
        if (sv.length == 0) [_vals addObject:[NSNull null]];
        else [_vals addObject:sv];
    }
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    self.tableView.tableFooterView = [self chsiFooterView];
    // v4.1.5：⚠️ 绝不自动聚焦任何输入框 —— 之前点球后弹出的正是
    //   系统「键盘输入候选浮层」（白色小方块带蓝色字影）。这里显式
    //   取消 first responder，只有用户主动点输入框才弹键盘。
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    self.tableView.allowsSelectionDuringEditing = NO;
    // v4.1.4：小面板高度有限，键盘弹起会盖住正在编辑的字段行 ——
    // 监听键盘通知，用 contentInset 把可滚动区域顶上去。
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserver:self selector:@selector(chsiKeyShow:)
               name:UIKeyboardWillShowNotification object:nil];
    [nc addObserver:self selector:@selector(chsiKeyHide:)
               name:UIKeyboardWillHideNotification object:nil];
    // v4.3.4：后台授权结果回来后刷新底部状态
    [nc addObserver:self selector:@selector(chsiLicenseChanged:)
               name:@"ChsiLicenseChanged" object:nil];
}

// 授权状态变化 → 重画底部说明（状态文字和 QQ 号都在里面）
- (void)chsiLicenseChanged:(NSNotification *)note {
    self.tableView.tableFooterView = [self chsiFooterView];
}

// v4.1.5：打开面板时确保没有输入框抢焦点（ViewDidAppear 兜一道，
//   防止 UIKit 在呈现过程中自动把首个可编辑控件设为 first responder）。
- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self.view endEditing:YES];
}

// v4.1.5：点遮罩（卡片外空白区域）关闭编辑器。
// 手势挂在 window 上，所以先判断触点是否落在本 VC 的 view 内。
- (void)chsiMaskTap:(UITapGestureRecognizer *)g {
    UIView *card = self.navigationController.view ?: self.view;
    CGPoint p = [g locationInView:card.superview];
    if (!CGRectContainsPoint(card.frame, p)) {
        [self.view endEditing:YES];
        ChsiCloseEditorWindow();
    }
}

- (void)chsiKeyShow:(NSNotification *)n {
    CGRect kb = [n.userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    UIEdgeInsets in = self.tableView.contentInset;
    in.bottom = kb.size.height + 8;
    self.tableView.contentInset = in;
    self.tableView.scrollIndicatorInsets = in;
}

- (void)chsiKeyHide:(NSNotification *)n {
    UIEdgeInsets in = self.tableView.contentInset;
    in.bottom = 0;
    self.tableView.contentInset = in;
    self.tableView.scrollIndicatorInsets = in;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)chsiDone {
    // v4.1.5：编辑器在自己的独立窗口里，点「完成」= 隐藏并释放那个窗口
    // （前向声明见 ChsiEditorVC 之前的文件级声明）。
    // 先收起键盘，避免窗口隐藏后键盘浮层残留。
    [self.view endEditing:YES];
    ChsiCloseEditorWindow();
}

- (UIView *)chsiFooterView {
    UILabel *l = [[UILabel alloc] initWithFrame:CGRectZero];
    l.numberOfLines = 0;
    l.font = [UIFont systemFontOfSize:11];
    l.textColor = [UIColor secondaryLabelColor];
    NSString *base = @"值按「本机配置 → 本 App 设置面板 → 内置默认」优先级生效；"
                     @"**清空文本 = 恢复该字段的默认值**；「恢复默认」删除全部本机覆盖。"
                     @"改完回到学信网页面刷新即生效。";
#if defined(CHSI_BUILD_QQ)
    // v4.3.4：显示授权状态 + 版本指纹（footer 里带版本号，
    //          用户截一张编辑器的图就能确认手机上跑的是哪版 dylib）。
    //          应用户要求删掉「QQ 号：xxx（手动指定）」那一行（截图泄露号码）。
    NSString *st = (gLicenseState == (NSInteger)ChsiLicenseGranted) ? @"✔ 已授权，可改写"
                 : (gLicenseState == (NSInteger)ChsiLicensePending)  ? @"… 正在向后台验证"
                                                                     : @"✘ 未授权（未输码 / 码无效 / 连不上后台）";
    base = [base stringByAppendingFormat:
            @"\n\n【授权（QQ 端）· v4.6.44】%@", st];
    if (gLicenseState == (NSInteger)ChsiLicenseDenied) {
        base = [base stringByAppendingString:
                @"\n提示：码输错或 QQ 号不对时，点「修改 QQ 号」改号，再点「重新输入授权码」。"];
    }
#endif
    l.text = base;
    // v4.1.2：编辑器改成小面板呈现，不能再按屏宽算宽度 ——
    // 用当前 tableView 宽度（未布局时退化为屏宽），保证窄窗不溢出。
    CGFloat w = self.tableView.bounds.size.width;
    if (w < 100) w = [UIScreen mainScreen].bounds.size.width;
    w -= 40;
    CGSize sz = [l sizeThatFits:CGSizeMake(w, CGFLOAT_MAX)];
    l.frame = CGRectMake(20, 12, w, sz.height);
    CGFloat totalH = sz.height + 24;
    UIView *wrap = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w + 40, totalH)];
    [wrap addSubview:l];
#if defined(CHSI_BUILD_QQ)
    // v4.3.4：QQ 端底部加「重新输入授权码」+「修改 QQ 号」两个按钮
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(20, 12 + sz.height + 4, w, 30);
    [btn setTitle:@"重新输入授权码" forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont systemFontOfSize:12];
    btn.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    [btn addTarget:self action:@selector(chsiReauth) forControlEvents:UIControlEventTouchUpInside];
    [wrap addSubview:btn];

    UIButton *btn2 = [UIButton buttonWithType:UIButtonTypeSystem];
    btn2.frame = CGRectMake(20, 12 + sz.height + 34, w, 30);
    [btn2 setTitle:@"修改 QQ 号" forState:UIControlStateNormal];
    btn2.titleLabel.font = [UIFont systemFontOfSize:12];
    btn2.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    [btn2 addTarget:self action:@selector(chsiEditQQ) forControlEvents:UIControlEventTouchUpInside];
    [wrap addSubview:btn2];
    wrap.frame = CGRectMake(0, 0, w + 40, totalH + 64);
#endif
    return wrap;
}

// v4.3.5：手动填 QQ 号（不再自动探测；值只在本次进程有效，不落盘）
- (void)chsiEditQQ {
#if defined(CHSI_BUILD_QQ)
    UIAlertController *ac = [UIAlertController
        alertControllerWithTitle:@"修改 QQ 号"
                         message:@"这里填的号只在本次 QQ 会话有效，不存本地；重开 QQ 要重新填。"
              preferredStyle:UIAlertControllerStyleAlert];
    [ac addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"QQ 号（必填）";
        tf.text = ChsiQQOverride();
        tf.keyboardType = UIKeyboardTypeNumberPad;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    [ac addAction:[UIAlertAction actionWithTitle:@"保存"
                                           style:UIAlertActionStyleDefault
                                         handler:^(UIAlertAction *a) {
        NSString *v = [[ac textFields].firstObject text] ?: @"";
        ChsiQQOverrideSet(v);
        ChsiLicenseSetState((NSInteger)ChsiLicenseDenied);   // 号变了要重新授权
        gEnteredCode = nil;
        gSessionVerified = NO;   // v4.5.5：号变了 → 允许重新弹输入框
        gJSKeyHex = nil;         // v4.6.15：号变了 → 旧会话密钥一并作废
        gSessExp = 0;
        ChsiAlertHostSetTouch(NO);      // v4.3.8：先还触摸，再拆窗口
        ChsiAlertHostTeardown();
        [[NSNotificationCenter defaultCenter] postNotificationName:@"ChsiLicenseChanged" object:nil];
    }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"取消"
                                           style:UIAlertActionStyleCancel
                                         handler:^(UIAlertAction *a) {
        ChsiAlertHostSetTouch(NO);      // v4.3.8：先还触摸，再拆窗口
        ChsiAlertHostTeardown();
    }]];
    // v4.3.8：走统一入口（含「弹不上就拆窗口」兜底）
    ChsiShowAlert(ac, @"改 QQ 号弹框");
#endif
}

// v4.3.4：手动再弹一次授权码输入框（QQ 端）
- (void)chsiReauth {
#if defined(CHSI_BUILD_QQ)
    CHLog(@"点「重新输入授权码」→ 弹授权框（gPrompting=%@）", gPrompting ? @"YES" : @"NO");
    gEnteredCode = nil;
    gSessionVerified = NO;   // v4.5.5：用户主动要求重新输码 → 清掉「已成功」标记
    ChsiLicensePrompt();
#endif
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    // 🔴 v4.6.8：删掉「显示悬浮球」开关行（用户要求：入口只留双指长按）
    //   —— 原 section 0 消失，3 节变 2 节：0=字段值、1=恢复默认。
    return 2;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (section == 0) return (NSInteger)FieldSpecsOrdered().count;   // 字段值
    return 1;   // 恢复默认（v4.3.4 删掉下面那行说明）
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    // v4.6.0：用户要求删掉「总开关」与「字段值」两个节标题
    //   —— 返回空串即不显示分组头。
    return @"";
}

// v4.1.4：字段行是「标签 + 输入框」两行，行高给足 62pt。
- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 0) return 62.0;
    return 44.0;
}

- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (indexPath.section == 0) {
        NSArray *specs = FieldSpecsOrdered();
        // v4.6.44：最后一行 = 照片 —— 不是文本输入，点行选相册图。
        if (indexPath.row == (NSInteger)specs.count - 1) {
            ChsiFieldCell *c =
                [[ChsiFieldCell alloc] initWithStyle:UITableViewCellStyleDefault
                                     reuseIdentifier:nil];
            c.selectionStyle = UITableViewCellSelectionStyleDefault;
            c.chsiLabel.text = @"照片（4寸，点本行选择）";
            id v = _vals[_vals.count - 1];
            NSString *uri = [v isKindOfClass:[NSNull class]] ? nil : (NSString *)v;
            if (uri.length > 24) {
                // base64 长度 ≈ 4/3 字节数，去掉 "data:image/jpeg;base64," 前缀（23 字符）
                NSUInteger kb = (NSUInteger)((uri.length - 23) * 3 / 4 / 1024);
                c.chsiField.text = [NSString stringWithFormat:
                    @"已设置（约 %lu KB，点行可换/清除）", (unsigned long)kb];
            } else {
                c.chsiField.text = @"";
                c.chsiField.placeholder = @"未设置（不选 = 不改写页面图片）";
            }
            c.chsiField.enabled = NO;
            return c;
        }
        NSArray *spec = specs[(NSUInteger)indexPath.row];
        // ⚠️ v4.1.4：小面板下「左标签 + 右输入框」并排布局会把输入区
        //   压到只剩 ~100pt（长标签如「预计毕业日期」更甚），实测
        //   用户反馈「内容显示/输入有问题」。改用自定义 cell 走
        //   **上下两行**布局（见 ChsiFieldCell），窄面板也能从容输入。
        ChsiFieldCell *c =
            [[ChsiFieldCell alloc] initWithStyle:UITableViewCellStyleDefault
                                 reuseIdentifier:nil];
        c.selectionStyle = UITableViewCellSelectionStyleNone;
        c.chsiLabel.text = spec[1];

        UITextField *tf = c.chsiField;
        tf.tag = indexPath.row;
        tf.delegate = self;
        tf.returnKeyType = UIReturnKeyDone;
        tf.clearButtonMode = UITextFieldViewModeWhileEditing;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
        // v4.6.44：密码字段密文显示（学信网密码）
        tf.secureTextEntry = [spec[1] isEqualToString:@"学信网密码"];
        tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
        id v = _vals[(NSUInteger)indexPath.row];
        if (![v isKindOfClass:[NSNull class]]) tf.text = (NSString *)v;
        NSString *dft = spec[2];
        tf.placeholder =
            [NSString stringWithFormat:@"默认:%@", dft.length ? dft : @"(空)"];
        [tf removeTarget:self action:@selector(valChanged:)
        forControlEvents:UIControlEventEditingChanged];
        [tf addTarget:self action:@selector(valChanged:)
                     forControlEvents:UIControlEventEditingChanged];
        return c;
    }
    UITableViewCell *c =
        [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                               reuseIdentifier:nil];
    c.textLabel.text = @"恢复默认（删除本机覆盖）";
    c.textLabel.textColor = [UIColor systemRedColor];
    c.textLabel.textAlignment = NSTextAlignmentCenter;
    return c;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    // v4.6.44：照片行 —— 点行弹出「选图 / 清除」
    if (indexPath.section == 0 &&
        indexPath.row == (NSInteger)FieldSpecsOrdered().count - 1) {
        [self chsiPhotoTap];
        return;
    }
    // 🔴 v4.6.8：原 section 2（恢复默认）随「显示悬浮球」行删除变为 section 1
    if (indexPath.section != 1 || indexPath.row != 0) return;
    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:@"恢复默认"
                                            message:@"删除本 App 的覆盖值，回到本 App 设置面板 / 内置默认值。"
                                     preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"恢复"
                                              style:UIAlertActionStyleDestructive
                                            handler:^(UIAlertAction *a) {
        for (NSUInteger i = 0; i < (NSUInteger)FieldSpecsOrdered().count; i++) {
            _vals[i] = [NSNull null];
        }
        [self persist];
        [self.tableView reloadData];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

// v4.6.8：原 swFloatChanged: 已随「显示悬浮球」开关行一起删除。

// v4.6.0：空字符串 = 无覆盖（回落内置默认）。
// 🔴 用户实测 bug：把「学校名称」改成别的值、再把它**删空**，再次改写时
//   该字段变成空白，没有回到内置默认「清华大学」。
//   根因：老逻辑把空串当"有效覆盖值"存下来 → EffectiveRules 命中空串 →
//   页面渲染成空。这里统一语义：**删空 = 恢复默认**。
- (void)valChanged:(UITextField *)tf {
    if (tf.tag < 0 || tf.tag >= (NSInteger)FieldSpecsOrdered().count) return;
    NSString *t = tf.text ?: @"";
    // 空串存 NSNull（= 该项无覆盖），非空存原文
    _vals[(NSUInteger)tf.tag] = (t.length == 0) ? (id)[NSNull null] : (id)t;
    [self persist];
    NSArray *spec = FieldSpecsOrdered()[(NSUInteger)tf.tag];
    NSString *dft = spec[2];
    tf.placeholder = (t.length == 0)
        ? [NSString stringWithFormat:@"默认:%@（留空=恢复默认）", dft.length ? dft : @"(空)"]
        : [NSString stringWithFormat:@"默认:%@", dft.length ? dft : @"(空)"];
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return YES;
}

#pragma mark —— v4.6.44 照片（UIImagePickerController 旧版相册选择器）
// 🔴 v4.6.19~21 血泪史：PHPicker 在 QQ 环境下（present / 独立窗口直挂
//   rootVC 两种方式都试过）选完图把主线程挂死，整个 QQ 永久点不动。
//   v4.6.44 改用旧版 UIImagePickerController：内部路径与 PHPicker 完全
//   不同，QQ 自带相册权限声明；仍然走独立窗口直挂 rootVC（零 present）。

- (void)chsiPhotoTap {
    id v = _vals[_vals.count - 1];
    NSString *uri = [v isKindOfClass:[NSNull class]] ? nil : (NSString *)v;
    if (uri.length <= 24) {
        [self chsiPhotoPick];
        return;
    }
    UIAlertController *ac = [UIAlertController
        alertControllerWithTitle:@"照片"
                         message:@"已设置照片。可重新选择，或清除（清除 = 不改写页面图片）。"
              preferredStyle:UIAlertControllerStyleActionSheet];
    [ac addAction:[UIAlertAction actionWithTitle:@"重新选择照片"
                                           style:UIAlertActionStyleDefault
                                         handler:^(UIAlertAction *a) {
        [self chsiPhotoPick];
    }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"清除照片"
                                           style:UIAlertActionStyleDestructive
                                         handler:^(UIAlertAction *a) {
        _vals[_vals.count - 1] = [NSNull null];
        [self persist];
        [self.tableView reloadData];
    }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"取消"
                                           style:UIAlertActionStyleCancel
                                         handler:nil]];
    [self presentViewController:ac animated:YES completion:nil];
}

// v4.6.44：旧版相册选择器（UIImagePickerController），独立窗口直挂 rootVC。
- (void)chsiPhotoPick {
    UIImagePickerController *pk = [[UIImagePickerController alloc] init];
    pk.sourceType = UIImagePickerControllerSourceTypePhotoLibrary;
    pk.delegate = self;
    pk.allowsEditing = NO;
    pk.modalPresentationStyle = UIModalPresentationFullScreen;
    UIWindowScene *scn = self.view.window.windowScene;
    if (!scn) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) { scn = (UIWindowScene *)s; break; }
        }
    }
    UIWindow *w = scn ? [[UIWindow alloc] initWithWindowScene:scn]
                      : [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    w.frame = [UIScreen mainScreen].bounds;
    w.windowLevel = UIWindowLevelAlert + 300;   // 高于编辑器（Alert+200）
    w.rootViewController = pk;
    w.hidden = NO;
    [w makeKeyAndVisible];
    gPhotoPickWindow = w;
    ChsiFloatDiag(@"photo-pick22 window opened");
}

// 拆选图窗口（delegate 回调第一件事，成功/取消都走这里）
- (void)chsiPhotoTeardownWindow {
    UIWindow *w = gPhotoPickWindow;
    gPhotoPickWindow = nil;
    if (w) {
        [w endEditing:YES];
        w.hidden = YES;
        w.rootViewController = nil;
        w.windowScene = nil;
    }
}

// v4.6.44：UIImagePickerController 回调 —— 直接给 UIImage，无 UTI 匹配问题
- (void)imagePickerController:(UIImagePickerController *)picker
didFinishPickingMediaWithInfo:(NSDictionary<UIImagePickerControllerInfoKey, id> *)info {
    [self chsiPhotoTeardownWindow];
    ChsiFloatDiag(@"photo-pick22 done keys=%@", [info allKeys]);
    UIImage *img = info[UIImagePickerControllerOriginalImage];
    if (!img) {
        [self chsiPhotoFail:@"相册没有返回图片数据"];
        return;
    }
    [self chsiStorePhoto:img];
}

- (void)imagePickerControllerDidCancel:(UIImagePickerController *)picker {
    [self chsiPhotoTeardownWindow];
    ChsiFloatDiag(@"photo-pick22 cancel");
}

// v4.6.44：照片读取/处理失败给明确提示（之前静默失败，用户不知道）
- (void)chsiPhotoFail:(NSString *)why {
    UIAlertController *al = [UIAlertController
        alertControllerWithTitle:@"照片设置失败"
                         message:why ?: @"未知原因"
                  preferredStyle:UIAlertControllerStyleAlert];
    [al addAction:[UIAlertAction actionWithTitle:@"好"
                                           style:UIAlertActionStyleCancel
                                         handler:nil]];
    [self presentViewController:al animated:YES completion:nil];
}

- (void)chsiStorePhoto:(UIImage *)img {
    // 4寸照片：v4.6.44 压缩 160px/JPEG0.5 —— 页面头像显示宽仅 58px，
    //   480x640 原图压成 120x160（~10KB data URI），2 倍视网膜屏清晰度足够。
    CGFloat maxDim = 160;
    CGSize sz = img.size;
    CGFloat m = MAX(sz.width, sz.height);
    CGFloat k = (m > maxDim) ? (maxDim / m) : 1.0;
    CGSize ns = CGSizeMake(MAX(1, round(sz.width * k)),
                           MAX(1, round(sz.height * k)));
    UIGraphicsImageRenderer *r =
        [[UIGraphicsImageRenderer alloc] initWithSize:ns];
    UIImage *out = [r imageWithActions:^(UIGraphicsImageRendererContext *c) {
        [img drawInRect:CGRectMake(0, 0, ns.width, ns.height)];
    }];
    NSData *jpg = UIImageJPEGRepresentation(out, 0.5);
    if (jpg.length == 0) {
        // ⚠️ 不能用 ChsiToast（QQ 包专属，WX 编译会炸）—— 编辑器此时必然
        //   在屏上，直接 present alert 两包通用。
        UIAlertController *al = [UIAlertController
            alertControllerWithTitle:@"照片处理失败"
                             message:@"请换一张图片再试。"
                      preferredStyle:UIAlertControllerStyleAlert];
        [al addAction:[UIAlertAction actionWithTitle:@"好"
                                               style:UIAlertActionStyleCancel
                                             handler:nil]];
        [self presentViewController:al animated:YES completion:nil];
        return;
    }
    NSString *b64 = [jpg base64EncodedStringWithOptions:0];
    NSString *uri = [NSString stringWithFormat:@"data:image/jpeg;base64,%@", b64];
    _vals[_vals.count - 1] = uri;
    [self persist];
    [self.tableView reloadData];
    CHLog(@"照片已设置：原图 %lu KB → 压缩 %lu KB",
          (unsigned long)(img.size.width), (unsigned long)(jpg.length / 1024));
}

- (void)persist {
    NSMutableDictionary *ov = [NSMutableDictionary dictionary];
    NSArray *specs = FieldSpecsOrdered();
    for (NSUInteger i = 0; i < (NSUInteger)specs.count; i++) {
        id v = _vals[i];
        if ([v isKindOfClass:[NSNull class]]) continue;
        NSString *s = [NSString stringWithFormat:@"%@", v];
        if (s.length == 0) continue;   // v4.6.0：空串不写（= 无覆盖，回落默认）
        ov[specs[i][1]] = s;
    }
    // v4.6.0：「开启改写」总开关已从编辑器删除 —— 不再写 enabled 键。
    //   enabled 缺失时 ChsiEnabled() 回落到面板 chsi_enabled（默认 YES），
    //   实际改写开关权交给「联网授权」那一层（未授权即不改写）。
    BOOL ok = ChsiConfigWrite(ov, nil);
    CHLog(@"编辑器保存本机配置: %@", ok ? @"OK" : @"失败");
    // v4.6.44：摘除 v4.6.25 的保存后自动重注入（回到 18 式「改完刷新页面生效」）
}

@end

// ==================== v4：插行 hook 基础设施 ====================

void ChsiPresentEditorFrom(id fromObject);   // 前向声明（ChsiHookDidSelect 引用）

static const void *kChsiRowTagKey = &kChsiRowTagKey;
static NSMutableSet *gHookedKeys = nil;    // "类名#selector" 防二次 hook
static NSString *gRowInjectedClass = nil;  // 本进程只给一个类插行

// 被动 hook 的原始实现（同一进程只 hook 一个设置页的数据源/代理类）
static long (*gOrigNumberOfRows)(id, SEL, UITableView *, long);
static UITableViewCell *(*gOrigCellForRow)(id, SEL, UITableView *, NSIndexPath *);
static void (*gOrigDidSelect)(id, SEL, UITableView *, NSIndexPath *);
static CGFloat (*gOrigHeightForRow)(id, SEL, UITableView *, NSIndexPath *);
static void (*gOrigWillDisplay)(id, SEL, UITableView *, UITableViewCell *, NSIndexPath *);
static CGFloat (*gOrigEstHeight)(id, SEL, UITableView *, NSIndexPath *);
static long (*gOrigIndentLevel)(id, SEL, UITableView *, NSIndexPath *);
static void (*gOrigVCAppear)(id, SEL, BOOL);

// 找到「类自己实现 sel」的那一层类（class_copyMethodList 只含本类方法）
static Class ChsiOwnerOfClassMethod(Class cls, SEL sel) {
    for (Class c = cls; c != nil; c = class_getSuperclass(c)) {
        unsigned int count = 0;
        Method *list = class_copyMethodList(c, &count);
        BOOL own = NO;
        for (unsigned int i = 0; i < count; i++) {
            if (method_getName(list[i]) == sel) { own = YES; break; }
        }
        if (list) free(list);
        if (own) return c;
    }
    return nil;
}

// 在 cls 上 hook sel：
//   宿主已实现 → 优先 class_addMethod（cls 没实现时 = 只加本类 override，
//   影响面最小）；cls 自己实现了则改「最派生实现类」的方法。
//   宿主未实现 → 仅当 addTypes 非空时新增实现（didSelect 用；此时 orig=NULL）。
// 返回原始 IMP；拿不到原始实现返回 NULL。
static IMP ChsiHookOptional(Class cls, SEL sel, IMP newImp,
                            const char *addTypes, IMP *outOrig) {
    Method m = class_getInstanceMethod(cls, sel);
    IMP orig = NULL;
    if (m) {
        orig = method_getImplementation(m);
        const char *types = method_getTypeEncoding(m);
        if (!class_addMethod(cls, sel, newImp, types)) {
            Class owner = ChsiOwnerOfClassMethod(cls, sel);
            if (!owner || owner == [NSObject class]) return NULL;
            Method om = class_getInstanceMethod(owner, sel);
            if (!om) return NULL;
            method_setImplementation(om, newImp);
        }
    } else {
        if (!addTypes || !class_addMethod(cls, sel, newImp, addTypes)) return NULL;
    }
    if (outOrig) *outOrig = orig;
    return orig;
}

// 同一 (类, selector) 只 hook 一次；重复视为成功（orig 早已写入全局静态）。
static BOOL ChsiHookOnce(Class cls, SEL sel, IMP newImp,
                         const char *addTypes, IMP *outOrig) {
    if (!cls || !gHookedKeys) return NO;
    NSString *key = [NSString stringWithFormat:@"%@#%@",
                     NSStringFromClass(cls), NSStringFromSelector(sel)];
    @synchronized (gHookedKeys) {
        if ([gHookedKeys containsObject:key]) return YES;
        if (!ChsiHookOptional(cls, sel, newImp, addTypes, outOrig)) return NO;
        [gHookedKeys addObject:key];
        return YES;
    }
}

// ==================== v4：插行核心（tag 守卫，未插行表格全部直通）====================

static BOOL ChsiIsTagged(UITableView *tv) {
    return tv != nil && objc_getAssociatedObject(tv, kChsiRowTagKey) != nil;
}

// 原始 section 数（numberOfSectionsInTableView: 从不 hook，直接调用即原始值）
static long ChsiOrigSectionCount(UITableView *tv) {
    id ds = tv.dataSource;
    if (!ds || ![ds respondsToSelector:@selector(numberOfSectionsInTableView:)]) return 1;
    return (long)[ds numberOfSectionsInTableView:tv];
}

// 是否为「我们插入的那一行」（只对已插行的表格成立）
static BOOL ChsiIsOurRow(UITableView *tv, NSIndexPath *ip) {
    if (!ChsiIsTagged(tv)) return NO;
    id ds = tv.dataSource;
    if (!ds || !gOrigNumberOfRows) return NO;
    long secs = ChsiOrigSectionCount(tv);
    if (secs <= 0 || ip.section != secs - 1) return NO;
    long rows = gOrigNumberOfRows(ds, @selector(numberOfRowsInSection:), tv, ip.section);
    return ip.row == rows;
}

static long ChsiHookNumberOfRows(id self, SEL _cmd, UITableView *tv, long section) {
    @try {
        if (ChsiIsTagged(tv) && gOrigNumberOfRows) {
            long rows = gOrigNumberOfRows(self, _cmd, tv, section);
            long secs = ChsiOrigSectionCount(tv);
            if (secs > 0 && section == secs - 1) return rows + 1;
            return rows;
        }
    } @catch (NSException *e) { CHLog(@"numberOfRows hook 异常: %@", e); }
    if (gOrigNumberOfRows) return gOrigNumberOfRows(self, _cmd, tv, section);
    return 0;
}

static UITableViewCell *ChsiHookCellForRow(id self, SEL _cmd, UITableView *tv, NSIndexPath *ip) {
    @try {
        if (ChsiIsOurRow(tv, ip)) {
            UITableViewCell *c =
                [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                       reuseIdentifier:nil];
            c.textLabel.text = @"学信网报告改写";
            c.detailTextLabel.text = ChsiEnabled() ? @"已开启" : @"已关闭";
            c.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
            return c;
        }
    } @catch (NSException *e) { CHLog(@"cellForRow hook 异常: %@", e); }
    if (gOrigCellForRow) return gOrigCellForRow(self, _cmd, tv, ip);
    return [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
}

static void ChsiHookDidSelect(id self, SEL _cmd, UITableView *tv, NSIndexPath *ip) {
    @try {
        if (ChsiIsOurRow(tv, ip)) {
            ChsiPresentEditorFrom(self);   // 定义在后，前向声明见上
            return;
        }
    } @catch (NSException *e) { CHLog(@"didSelect hook 异常: %@", e); }
    if (gOrigDidSelect) gOrigDidSelect(self, _cmd, tv, ip);
}

static CGFloat ChsiHookHeightForRow(id self, SEL _cmd, UITableView *tv, NSIndexPath *ip) {
    @try {
        if (ChsiIsOurRow(tv, ip)) return 44.0;
    } @catch (NSException *e) {}
    if (gOrigHeightForRow) return gOrigHeightForRow(self, _cmd, tv, ip);
    return 44.0;
}

static void ChsiHookWillDisplay(id self, SEL _cmd, UITableView *tv,
                                UITableViewCell *cell, NSIndexPath *ip) {
    @try {
        // 不让宿主按 indexPath 查模型重配我们插入的行
        if (ChsiIsOurRow(tv, ip)) return;
    } @catch (NSException *e) {}
    if (gOrigWillDisplay) gOrigWillDisplay(self, _cmd, tv, cell, ip);
}

static CGFloat ChsiHookEstHeight(id self, SEL _cmd, UITableView *tv, NSIndexPath *ip) {
    @try {
        if (ChsiIsOurRow(tv, ip)) return 44.0;
    } @catch (NSException *e) {}
    if (gOrigEstHeight) return gOrigEstHeight(self, _cmd, tv, ip);
    return 44.0;
}

static long ChsiHookIndentLevel(id self, SEL _cmd, UITableView *tv, NSIndexPath *ip) {
    @try {
        if (ChsiIsOurRow(tv, ip)) return 0;
    } @catch (NSException *e) {}
    if (gOrigIndentLevel) return gOrigIndentLevel(self, _cmd, tv, ip);
    return 0;
}

// ==================== v4：编辑器呈现 ====================

// v4.5.3：🔴 也改走候选列表 —— 原先只信 keyWindow 一条链，键盘弹起时
//   keyWindow 会变成键盘窗口，拿到的「最上层 VC」根本不是 QQ 的 VC。
//   编辑器宿主（ChsiPresentEditorFrom）用它，两者口径保持一致。
//   ⚠️ 保留函数名/签名（多处引用），内部换成 ChsiPickPresentHost()。
static UIViewController *ChsiTopVC(void) {
    @try {
        NSString *why = nil;
        UIViewController *vc = ChsiPickPresentHost(&why);
        if (vc) return vc;
        CHLog(@"ChsiTopVC：暂无可用宿主（原因=%@）", why ?: @"?");
    } @catch (NSException *e) { CHLog(@"取 topVC 失败: %@", e); }
    return nil;
}

// fromObject = tableView 的 delegate（通常是设置页 VC 本身）
//
// v4.1.5：彻底换掉 presentViewController 路线。
//   实测问题：点球后弹出的不是编辑器，而是系统的**键盘输入候选浮层**
//   （白色小方块带蓝色字影）—— 因为 formSheet 呈现 + 面板内首个
//   UITextField 被系统自动聚焦，在异常层级下只显示出键盘候选框。
//   新做法：编辑器放进**自己的独立 UIWindow**（windowLevel 比球再高一档），
//   尺寸完全由我们指定（不经过 formSheet 的系统约束），并且
//   **打开时显式不聚焦任何输入框**（需要用户主动点输入框才弹键盘）。
static UIWindow *gEditorWindow = nil;   // 编辑器独立窗口（v4.1.5）

// 「完成」按钮 → 关闭编辑窗口（声明在此、定义在 ChsiEditorVC 之后导入使用）
void ChsiCloseEditorWindow(void);

void ChsiPresentEditorFrom(id fromObject) {
    // v4.6.3 诊断：谁在什么时候唤起编辑器（区分单击球 / 双指长按 / 设置页）。
    ChsiFloatDiag(@"presentEditor from=%@ editorWindowExists=%d",
                  fromObject ? NSStringFromClass([fromObject class]) : @"nil",
                  (int)(gEditorWindow != nil));
    // 已开着就不重复开
    if (gEditorWindow) {
        gEditorWindow.hidden = NO;
        return;
    }
    UIViewController *host = nil;
    if ([fromObject isKindOfClass:[UIViewController class]]) host = fromObject;
    if (!host) host = ChsiTopVC();
    if (!host) {
        CHLog(@"找不到宿主 VC，放弃打开编辑器");
        ChsiFloatDiag(@"presentEditor ABORT 找不到宿主 VC");
        return;
    }
    @try {
        // 找一个 foreground scene 承载编辑窗口
        UIWindowScene *scene = nil;
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]
                && s.activationState == UISceneActivationStateForegroundActive) {
                scene = (UIWindowScene *)s; break;
            }
        }
        if (!scene) scene = (UIWindowScene *)[UIApplication sharedApplication]
                                      .connectedScenes.anyObject;
        UIWindow *w = scene ? [[UIWindow alloc] initWithWindowScene:scene]
                            : [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        if (!w) return;

        ChsiEditorVC *ed = [[ChsiEditorVC alloc] init];
        UINavigationController *nav =
            [[UINavigationController alloc] initWithRootViewController:ed];

        // 窗口铺满（承载半透明遮罩 + 居中的卡片），卡片尺寸自定。
        // ⚠️ 与悬浮球的「窗口=控件大小」策略不同：编辑器窗口需要
        //    接收「点击遮罩关闭」，所以必须铺满；但它是独立的
        //    Alert+200 窗口，且只在编辑器打开期间存在，关闭即摘除，
        //    不会长期占用触摸。
        CGRect screen = [UIScreen mainScreen].bounds;
        w.frame = screen;
        w.windowLevel = UIWindowLevelAlert + 200;
        w.backgroundColor = [UIColor colorWithWhite:0 alpha:0.35];
        w.rootViewController = nav;
        // 让 nav 的 view 缩小成居中卡片（而不是铺满窗口）
        CGFloat mw = MIN(340, screen.size.width - 24);
        CGFloat mh = MIN(520, screen.size.height - 140);
        nav.view.frame = CGRectMake((screen.size.width - mw) / 2.0,
                                    (screen.size.height - mh) / 2.0, mw, mh);
        nav.view.layer.cornerRadius = 12;
        nav.view.clipsToBounds = YES;
        nav.view.backgroundColor = [UIColor systemBackgroundColor];
        w.hidden = NO;
        gEditorWindow = w;
        // 点卡片外（遮罩）关闭编辑器 —— 手机上没有 Esc，这是必需的退出方式。
        UITapGestureRecognizer *tap =
            [[UITapGestureRecognizer alloc] initWithTarget:ed
                                                    action:@selector(chsiMaskTap:)];
        tap.cancelsTouchesInView = NO;
        [w addGestureRecognizer:tap];
        CHLog(@"已打开改写编辑器（独立窗口，卡片 %.0fx%.0f）", mw, mh);
    } @catch (NSException *e) {
        CHLog(@"打开编辑器异常: %@", e);
    }
}

// v4.1.5：关掉编辑窗口（「完成」按钮调用）。
void ChsiCloseEditorWindow(void) {
    @try {
        UIWindow *w = gEditorWindow;
        gEditorWindow = nil;
        if (w) {
            // 先让窗口里的所有编辑控件失焦（否则键盘浮层可能残留）
            [w endEditing:YES];
            w.hidden = YES;
            w.rootViewController = nil;
            // 从 scene 上摘掉，避免窗口累积
            w.windowScene = nil;
        }
        CHLog(@"编辑器已关闭");
    } @catch (NSException *e) {
        CHLog(@"关闭编辑器异常: %@", e);
    }
}

// ==================== v4：设置页探测与安装 ====================

static UITableView *ChsiFindTableView(UIView *v) {
    if (!v) return nil;
    if ([v isKindOfClass:[UITableView class]]) return (UITableView *)v;
    for (UIView *s in v.subviews) {
        UITableView *r = ChsiFindTableView(s);
        if (r) return r;
    }
    return nil;
}

static void ChsiAttemptInsert(UIViewController *vc) {
    if (!vc || !vc.isViewLoaded) return;
    UITableView *tv = ChsiFindTableView(vc.view);
    if (!tv) {
        ChsiProbeLog([NSString stringWithFormat:@"[insert-miss] %@ 页内无 UITableView",
                      NSStringFromClass([vc class])]);
        return;
    }
    if (objc_getAssociatedObject(tv, kChsiRowTagKey)) return;

    id ds = tv.dataSource;
    if (!ds) { ChsiProbeLog(@"[insert-miss] dataSource 为空"); return; }
    id dl = tv.delegate;
    Class dsCls = [ds class];
    Class dlCls = dl ? [dl class] : dsCls;

    BOOL okRows = ChsiHookOnce(dsCls, @selector(numberOfRowsInSection:),
                               (IMP)ChsiHookNumberOfRows, "l@:@l",
                               (IMP *)&gOrigNumberOfRows);
    BOOL okCell = ChsiHookOnce(dsCls, @selector(tableView:cellForRowAtIndexPath:),
                               (IMP)ChsiHookCellForRow, "@@:@@",
                               (IMP *)&gOrigCellForRow);
    BOOL okSel = ChsiHookOnce(dlCls, @selector(tableView:didSelectRowAtIndexPath:),
                              (IMP)ChsiHookDidSelect, "v@:@@",
                              (IMP *)&gOrigDidSelect);
    if (!okRows || !okCell || !okSel) {
        CHLog(@"插行 hook 失败 rows=%d cell=%d select=%d (%@)",
              okRows, okCell, okSel, NSStringFromClass(dsCls));
        return;
    }
    // 可选 delegate 方法：宿主已实现才 hook（不传 addTypes = 不允许新增），
    // 防「转发实现/未实现」时破坏原始行为。
    if ([dl respondsToSelector:@selector(tableView:heightForRowAtIndexPath:)]) {
        ChsiHookOnce(dlCls, @selector(tableView:heightForRowAtIndexPath:),
                     (IMP)ChsiHookHeightForRow, NULL,
                     (IMP *)&gOrigHeightForRow);
    }
    if ([dl respondsToSelector:@selector(tableView:willDisplayCell:forRowAtIndexPath:)]) {
        ChsiHookOnce(dlCls, @selector(tableView:willDisplayCell:forRowAtIndexPath:),
                     (IMP)ChsiHookWillDisplay, NULL,
                     (IMP *)&gOrigWillDisplay);
    }
    if ([dl respondsToSelector:@selector(tableView:estimatedHeightForRowAtIndexPath:)]) {
        ChsiHookOnce(dlCls, @selector(tableView:estimatedHeightForRowAtIndexPath:),
                     (IMP)ChsiHookEstHeight, NULL,
                     (IMP *)&gOrigEstHeight);
    }
    if ([dl respondsToSelector:@selector(tableView:indentationLevelForRowAtIndexPath:)]) {
        ChsiHookOnce(dlCls, @selector(tableView:indentationLevelForRowAtIndexPath:),
                     (IMP)ChsiHookIndentLevel, NULL,
                     (IMP *)&gOrigIndentLevel);
    }

    objc_setAssociatedObject(tv, kChsiRowTagKey, @YES,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    ChsiProbeLog([NSString stringWithFormat:
                  @"[insert-ok] vc=%@ tv=%@ ds=%@ dl=%@",
                  NSStringFromClass([vc class]), NSStringFromClass([tv class]),
                  NSStringFromClass(dsCls), NSStringFromClass(dlCls)]);
    [tv reloadData];   // 立即多出一行
}

static void ChsiMaybeInsertRow(UIViewController *vc) {
    NSArray *cands = ChsiSettingCandidates();
    if (cands.count == 0) return;
    NSString *name = NSStringFromClass([vc class]);
    ChsiProbeLog([NSString stringWithFormat:@"[vc-appear] %@", name]);

    // 本进程只给一个类插行
    if (gRowInjectedClass && ![name isEqualToString:gRowInjectedClass]) return;

    BOOL isCand = [cands containsObject:name];
    NSString *title = vc.title ?: @"";
    if (title.length == 0) title = vc.navigationItem.title ?: @"";
    BOOL isWeChat = [[[NSBundle mainBundle] bundleIdentifier]
                     isEqualToString:@"com.tencent.xin"];
    BOOL hit = NO;
    if (isCand) {
        if (isWeChat) {
            hit = YES;   // 社区已知类名直接命中
        } else {
            hit = ([title containsString:@"设置"] || cands.count == 1);
        }
    } else if ([name.lowercaseString containsString:@"setting"] &&
               [title containsString:@"设置"]) {
        hit = YES;   // 类名/标题双条件兜底（已知类名失效时）
    }
    if (!hit) return;

    if (!gRowInjectedClass) {
        gRowInjectedClass = name;
        CHLog(@"命中设置页候选: %@ (title=%@)", name, title);
    }
    // 等表格 build 完再尝试，两次幂等（tag 去重）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ChsiAttemptInsert(vc); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ChsiAttemptInsert(vc); });
}

static void ChsiHookVCAppearImpl(id self, SEL _cmd, BOOL animated) {
    if (gOrigVCAppear) gOrigVCAppear(self, _cmd, animated);
    @try {
        if ([self isKindOfClass:[UIViewController class]]) {
            ChsiMaybeInsertRow((UIViewController *)self);
        }
    } @catch (NSException *e) {
        CHLog(@"设置页探测异常: %@", e);
    }
}

static void ChsiInstallSettingsRowModule(void) {
#if !defined(CHSI_KEEP_SETTINGS_ROW)
    // v4.1：插行模块整体停用（QQ 实测未插出行；它也是微信闪退的头号
    // 嫌疑）。入口改用悬浮球。代码保留，CFLAGS 加 -DCHSI_KEEP_SETTINGS_ROW
    // 可整体重启该路线。+load 仍保留本函数调用（内部直接 return，
    // 零开销，同时避免未使用警告）。
    CHLog(@"v4.1 插行模块已停用（入口改为悬浮球，包=%@）", @(CHSI_BUILD_TAG));
    (void)ChsiHookVCAppearImpl;   // 保留引用：抑制 -Wunused-function（整条插行链随之算已使用）
    return;
#else
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
        BOOL isWeChat = [bid isEqualToString:@"com.tencent.xin"];
        BOOL isQQ = [bid isEqualToString:@"com.tencent.mqq"];
        if (!isWeChat && !isQQ) {
            CHLog(@"v4 设置页插行模块跳过（bundle=%@ 非 QQ/微信）", bid);
            return;
        }
        gHookedKeys = [NSMutableSet set];
        Method m = class_getInstanceMethod([UIViewController class],
                                           @selector(viewDidAppear:));
        if (!m) return;
        gOrigVCAppear = (void (*)(id, SEL, BOOL))method_getImplementation(m);
        method_setImplementation(m, (IMP)ChsiHookVCAppearImpl);
        ChsiProbeLog([NSString stringWithFormat:@"[boot] v4 模块已装 bundle=%@", bid]);
        CHLog(@"v4 设置页插行模块已装（bundle=%@）", bid);
    });
#endif
}

// ==================== Hook（全公开 API，参数全为 ObjC 对象，ARC 安全）====================

static void SwizzleInstanceMethod(Class cls, SEL original, SEL replacement) {
    Method orig = class_getInstanceMethod(cls, original);
    Method repl = class_getInstanceMethod(cls, replacement);
    if (!orig || !repl) {
        CHLog(@"swizzle 跳过（方法不存在）: %@", NSStringFromSelector(original));
        return;
    }
    method_exchangeImplementations(orig, repl);
}

@implementation WKWebView (ChsiHook)

+ (void)load {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        CHLog(@"dylib 已加载（v4.1 包=%@：悬浮球入口 + App 内编辑器 + WKUserScript 主路径 + load* 兜底，检测到页面即改写）",
              @(CHSI_BUILD_TAG));

        // v4.6.15：反调试 / 反注入自检（拒绝调试器 + 周期查 P_TRACED / 重复注入）
        ChsiHardStart();

        // ⚠️ 不能在 +load 里直接弹窗：dylib 在 main() 之前就加载，
        //    这时候 [UIApplication sharedApplication] 还没就绪。延后到主线程 3 秒。
        //    这 3 秒里 gLicenseState 还是 Pending（= 不改写），安全。
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            ChsiLicenseRefresh();
        });
        gChsiActiveObserver = [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidBecomeActiveNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *note) {
                        ChsiLicenseRefresh();       // 从后台切回来也算「打开」
                    }];
        gChsiBgObserver = [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidEnterBackgroundNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *note) {
                        ChsiLicenseInvalidate();    // 进后台即作废，回来要重新输码
                    }];

        // ---- 主路径：公开初始化方法，init 前预装用户脚本 ----
        SwizzleInstanceMethod(
            [WKWebView class],
            @selector(initWithFrame:configuration:),
            @selector(chsi_initWithFrame:configuration:));

        // ---- 兜底路径：公开 load* 方法，之后 evaluateJavaScript 补改 ----
        SwizzleInstanceMethod(
            [WKWebView class],
            @selector(loadRequest:),
            @selector(chsi_loadRequest:));

        SwizzleInstanceMethod(
            [WKWebView class],
            @selector(loadHTMLString:baseURL:),
            @selector(chsi_loadHTMLString:baseURL:));

        SwizzleInstanceMethod(
            [WKWebView class],
            @selector(loadFileURL:allowingReadAccessToURL:),
            @selector(chsi_loadFileURL:allowingReadAccessToURL:));

        SwizzleInstanceMethod(
            [WKWebView class],
            @selector(loadData:MIMEType:characterEncodingName:baseURL:),
            @selector(chsi_loadData:MIMEType:characterEncodingName:baseURL:));

        // ---- v4.1：App 内悬浮球入口（QQ 包只进 QQ、WX 包只进微信）----
        ChsiInstallFloatBall();
        // ---- v4 设置页插行（v4.1 编译期停用，保留调用与代码便于日后重启）----
        ChsiInstallSettingsRowModule();
    });
}

// initWithFrame: 与 initWithCoder: 内部都会走这个公开方法，
// 所以只 swizzle 这一个 init 就能覆盖代码创建的 webview。
- (instancetype)chsi_initWithFrame:(CGRect)frame configuration:(WKWebViewConfiguration *)configuration {
    [ChsiInjector installUserScriptIntoConfiguration:configuration];
    return [self chsi_initWithFrame:frame configuration:configuration];
}

- (WKNavigation *)chsi_loadRequest:(NSURLRequest *)request {
    WKNavigation *nav = [self chsi_loadRequest:request];
    if ([[ChsiInjector shared] isTargetURL:request.URL]) {
        [[ChsiInjector shared] scheduleInjectForWebView:self];
    }
    return nav;
}

- (WKNavigation *)chsi_loadHTMLString:(NSString *)html baseURL:(NSURL *)baseURL {
    WKNavigation *nav = [self chsi_loadHTMLString:html baseURL:baseURL];
    if ([[ChsiInjector shared] isTargetURL:baseURL]) {
        [[ChsiInjector shared] scheduleInjectForWebView:self];
    }
    return nav;
}

- (WKNavigation *)chsi_loadFileURL:(NSURL *)url allowingReadAccessToURL:(NSURL *)readAccessURL {
    WKNavigation *nav = [self chsi_loadFileURL:url allowingReadAccessToURL:readAccessURL];
    if ([[ChsiInjector shared] isTargetURL:url]) {
        [[ChsiInjector shared] scheduleInjectForWebView:self];
    }
    return nav;
}

- (WKNavigation *)chsi_loadData:(NSData *)data MIMEType:(NSString *)MIMEType
          characterEncodingName:(NSString *)characterEncodingName baseURL:(NSURL *)baseURL {
    WKNavigation *nav = [self chsi_loadData:data MIMEType:MIMEType
                      characterEncodingName:characterEncodingName baseURL:baseURL];
    if ([[ChsiInjector shared] isTargetURL:baseURL]) {
        [[ChsiInjector shared] scheduleInjectForWebView:self];
    }
    return nav;
}

@end
