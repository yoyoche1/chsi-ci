#!/usr/bin/env python3
"""校验 dylib 是否为可加载的 Mach-O（支持 FAT 与 thin，不需要 macOS）"""
import struct
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "ChsiHook.dylib"
data = open(path, "rb").read()
print("文件: %s  大小: %d 字节" % (path, len(data)))

FT = {1: "object", 2: "executable", 6: "dylib", 8: "bundle", 10: "dSYM"}
CPU = {0x0100000C: "arm64", 0x0200000C: "arm64e", 0x0000000C: "armv7"}


def cpu_label(cputype, cpusub):
    """arm64e 有两种写法：cputype=0x0200000C，或 cputype=arm64 + cpusub=0x80000002
    （新式 ldid/Xcode 用后者）。只看 cputype 会把 arm64e 误标成 arm64。"""
    if cputype == 0x0100000C and (cpusub & 0x80000000) and (cpusub & 0x00FFFFFF) == 2:
        return "arm64e"
    return CPU.get(cputype, hex(cputype))


def check_slice(buf, label):
    """检查一段 Mach-O 头，返回 (filetype, cputype)"""
    magic = buf[:4]
    if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        pass
    elif magic in (b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"):
        pass
    else:
        print("  %s: Magic 异常 %s" % (label, magic.hex()))
        return None
    cputype, cpusub, filetype, ncmds = struct.unpack("<IIII", buf[4:20])
    print(
        "  %s: %-6s filetype=%d(%s)  ncmds=%d"
        % (label, cpu_label(cputype, cpusub), filetype, FT.get(filetype, "?"), ncmds)
    )
    return filetype, cputype


magic = data[:4]
if magic == b"\xca\xfe\xba\xbe":
    n = struct.unpack(">I", data[4:8])[0]
    print("Magic: FAT 胖二进制，含 %d 个架构\n" % n)
    results = []
    off = 8
    for i in range(n):
        cputype, cpusub, offset, size, align = struct.unpack(">IIIII", data[off : off + 20])
        off += 20
        print("  [%d] %s  切片偏移=%d 大小=%d" % (i, cpu_label(cputype, cpusub), offset, size))
        r = check_slice(data[offset : offset + size], "  ->")
        if r:
            results.append(r)
    ok = bool(results) and all(ft == 6 for ft, _ in results)
    print("\n判定: %s" % ("含可加载 dylib 切片 OK" if ok else "有切片不是 dylib"))
else:
    r = check_slice(data, "thin")
    ok = r is not None and r[0] == 6

txt = data.decode("utf-8", "replace")
needles = [
    # ---- 结构 / hook 机制（v2：公开 init + WKUserScript 主路径，load* 兜底）----
    ("模块名", "ChsiHook"),
    # ---- v4.6.19：姓名/照片改写（编辑器标签串，两包公用代码，必须在 needles）----
    ("照片行指纹", "照片（4寸，点本行选择）"),
    ("照片已设置指纹", "已设置（约"),
    ("更新日期字段指纹", "更新日期"),
    ("init主路径", "initWithFrame:configuration:"),
    ("swizzle回调", "chsi_initWithFrame:configuration:"),
    ("用户脚本类", "WKUserScript"),
    ("hook兜底1", "loadRequest:"),
    ("hook兜底2", "loadHTMLString:baseURL:"),
    ("hook兜底3", "loadFileURL:allowingReadAccessToURL:"),
    ("hook兜底4", "loadData:MIMEType:characterEncodingName:baseURL:"),
    # ---- v4.6.15：JS 模板已加密进二进制，明文 JS 字符串的 12 条旧断言下线
    #   （__chsiRewrite / MutationObserver / createTreeWalker 等改为反向检查，
    #     在二进制里出现 = 密文没编进去 / 明文回潮）。
    # ---- v4.6.15 新断言：防破解模块 ----
    # v4.6.42：QQ 解密成功日志改名 "remote-js unlock"（见 license_needles）；
    #   WX 仍是 "jscore unlock"（移入 wx_needles）
    ("JS解密失败诊断", "jscore decrypt FAIL"),
    ("JS兜底空脚本", "(function(){return '';})();" ),
    ("防调试自检启动", "hard-check 已启动（20s 一拍）"),
    ("硬杀诊断", "hard-kill %@"),
    ("重复注入检测", "hard-dup count=%d"),
    ("日志前缀", "[CHSI-DYLIB]"),
    # ---- v3：设置面板可改值 ----
    ("设置键样例", "chsi_f01"),
    ("设置键末位", "chsi_f13"),
    ("总开关键", "chsi_enabled"),
    # ---- v4.1.9：配置只存本 App 沙箱（QQ/微信不共享）----
    #   路径由 NSHomeDirectory() + 这两段拼成，二进制里只看得到片段。
    ("配置文件名", "com.chsihook.rules.plist"),
    ("沙箱Prefs", "Library/Preferences"),
    #   v4.6.15：随 JS 模板加密下线（__chsiRewriterVer 在明文 JS 里，二进制不该有）
    ("v4日志", "设置页/面板均可改值"),
    # ---- v4：QQ/微信设置页插行 + App 内编辑器 ----
    ("编辑器类", "ChsiEditorVC"),
    ("入口行标题", "学信网报告改写"),
    ("微信候选类", "NewSettingViewController"),
    ("QQ候选扫描", "objc_copyClassList"),
    ("QQbundle", "com.tencent.mqq"),
    ("probe日志", "probe.log"),
    ("probe目录", "/var/mobile/Library/ChsiHook"),
    ("插行成功标记", "insert-ok"),
    ("VC探测标记", "vc-appear"),
    # v4.6.8：「显示悬浮球」开关行也删了（入口只留双指长按）——
    #   「显示悬浮球」移入下方 absent 反向检查。
    ("恢复默认", "恢复默认"),
    ("hook保护标记", "插行 hook 失败"),
    # ---- v4.1：悬浮球（QQ/WX 双包共用代码，两个包都应命中）----
    ("悬浮球类", "ChsiFloatViewController"),
    # v4.6.9：悬浮球位置记忆（chsi_float_x/y）随拖动手势一起删除

    ("悬浮球跳过日志", "悬浮球模块跳过"),
    ("停用插行日志", "插行模块已停用"),
    # ---- 报告页三种结构 / 选择器：v4.6.15 起随 JS 模板加密下线 ----
    # ---- 规则值（对应 chsi-report-rewrite.js 的 FIELD_RULES）----
    ("学校值", "清华大学"),
    ("层次值", "本科"),
    ("专业值", "智能科学与技术"),
    ("学制", "4 年"),
    ("学历类别", "普通高等教育"),
    ("学习形式", "普通全日制"),
    ("分院标签", "分院"),
    ("系所", "多智能体"),
    ("入学日期", "2025年08月31日"),
    ("学籍状态", "在籍（注册学籍）"),
    ("毕业值", "2029年07月01日"),
    ("离校标签", "离校日期"),
    ("改名目标", "预计毕业日期"),
    ("验证码", "DEMO1234ABCD5678"),
    # ---- v4.5.3：宿主候选枚举（**两包公用**，纯 UIKit，不带授权字符串）----
    #   为什么放 needles 而不是 license_needles：见下方 license_needles 里的说明。
    ("候选宿主枚举函数", "ChsiHostCandidates"),
    ("宿主可用性筛选函数", "ChsiPickPresentHost"),
    ("候选枚举遍历API", "connectedScenes"),
    ("候选枚举异常日志", "枚举候选宿主异常"),
    # ---- v4.6.0：三项编辑器 / 手势 / 默认值改动（**两包公用**）----
    #   为什么放 needles 而不是 license_needles：
    #     双指长按挂在悬浮球 VC 上、EffectiveRules 的空串回落，
    #     都属于「不带授权字符串的纯 UIKit / 纯逻辑」代码，WX 包也编译。
    #     放 license_needles 会被 WX 包的「授权串应在 WX 缺席」反向检查误报。
    #   ① 双指长按唤出编辑器（与三指双击并列可达）
    ("双指长按手势类", "UILongPressGestureRecognizer"),
    ("双指长按方法", "chsiFloatTwoFingerLongPress"),
    # ⚠️ 这两个参数（numberOfTouchesRequired / minimumPressDuration）是 ObjC
    #   selector，**不会作为字符串字面量进二进制**（v4.6.0 踩过：最初直接断言
    #   属性名 → 两条永久 MISS）。改为断言源码里那行带参数的日志文案。
    ("双指参数日志", "双指长按手势已挂"),
    ("双指手势两指数", "指头数=2"),
    ("双指按下时长", "按住=0.6s"),
    # v4.6.8：原「开关关闭仍可唤出日志」随 ChsiFloatApplyVisibility 删除
    # v4.6.9：原「隐藏态双指保留」（三指双击 / 双指长按）随悬浮球 UI 删除
    # ---- v4.6.1：修「双指长按开编辑器 → 点完成 → QQ 点不动」----
    #   核心是「窗口永远是球大小」。
    #   ⚠️ `hitTest` / `withEvent:` 是 selector，不进二进制。
    # v4.6.9：「球View子类 ChsiFloatBallView」「球区感应日志」随悬浮球 UI 删除
    #   ③ 空串 = 无覆盖（删空字段值 → 回落内置默认）
    ("清空即恢复默认文案", "清空文本 = 恢复该字段的默认值"),
    ("恢复默认占位提示", "留空=恢复默认"),
    # ---- v4.6.3：悬浮球诊断埋点（球/手势全链路写 probe.log）----
    #   为什么加：v4.6.2 删闸门后真机仍报「双指长按 + 三指双击都不通」，
    #   静态审代码那条链是通的 ⇒ 断点在运行时，必须靠真机日志定位。
    #   这几条断言是「诊断代码真的编进去了」的凭据。
    ("诊断前缀", "[float]"),
    # v4.6.9：created/setHidden/gestures attached/threeFingerDoubleTap
    #   随悬浮球 UI 删除；只留双指回调与唤出编辑器两条。
    ("诊断双指回调", "twoFingerLongPress state=%ld touches=%lu"),
    ("诊断唤出编辑器", "presentEditor from=%@"),
    # ---- v4.6.9：悬浮球移除后的就绪诊断 ----
    ("就绪诊断", "ready bundle=%@"),
    # ---- v4.6.10：常驻周期补挂（修「验证通过后双指长按零回调」）----
    #   真机 /probe 铁证：v4.6.9 只在启动 2s/3s 挂两轮，QQ 重建交互窗口后
    #   再无人补挂 ⇒ 新窗口没手势 ⇒ 双指长按零回调。改成 5 秒一次常驻补挂。
    ("周期补挂诊断", "keepalive attach every=5s"),
    # ---- v4.6.5：挂载复核自愈（修「窗口挂在 Unattached scene → 手势全灭」）----
    #   created 时 sceneState=0（v4.6.4 真机 /probe 日志钉死的根因）。
    #   创建 1s 后复核 scene 就绪 + view 入窗；失败拆掉重建（4s/8s，最多 3 次）。
    #   ⚠️ 创建/复核代码在 #if CHSI_BUILD_QQ **之外**（两包公用）→ 必须放 needles。
    #      （差点重蹈 v4.6.4 铁律 I：_precheck 的 license越界 检查这回抓到了。）
    # ---- v4.6.6/4.6.7：宿主窗口全屏兜底多指手势（修「隐藏态多指只在球区有效」）----
    #   v4.6.5 mounted 复核证明 QQ 的 activationState 恒为 0（假信号），
    #   真根因 = v4.6.1 把窗口缩回 44×44 时多指手势命中区跟着缩小。
    #   修法 = 多指手势挂 QQ 自己的窗口；v4.6.7 起穷举**所有**符合条件的
    #   QQ 窗口逐个挂（QQ 多窗口/多 scene，只挂第一个会挂错窗口）。
    ("宿主手势挂载诊断", "hostGestures attached win="),
    # ---- v4.6.8：双指长按授权门控（未授权不可用；两包公用，#if 外）----
    ("长按授权门控日志", "twoPress BLOCKED"),
    # ---- v4.6.8：字段输入 null = 改写为空白（EffectiveRules）----
    #   ⚠️ 「null」子串太短太常见，改断言带上下文的整段格式串不可行
    #      （是代码不是字面量）⇒ 断言挂不了这个语义，靠 CI 双包 + 真机验证。
    ("宿主手势未就绪诊断", "hostGestures NO-WINDOW"),
    # v4.6.9：原「挂载复核放弃 GIVEUP」随 mounted 复核一起删除
    ("诊断无宿主放弃", "ABORT 找不到宿主 VC"),
]

# ---- v4.3.0：授权相关字符串只在 QQ 包里（WX 包被 #if CHSI_BUILD_QQ 挡掉）----
license_needles = [
    ("授权弹框标题", "ChsiHook 授权"),
    ("QQ号兜底值", "UNKNOWN-QQ"),
    # ---- v4.6.42 全下发：脚本只在服务器，二进制零脚本 ----
    ("远端脚本解锁日志", "remote-js unlock"),
    ("脚本下发探针", "js-deliver ok ver="),
    ("脚本断供日志", "js-miss ver="),
    ("授权通过文案", "已授权，可改写"),
    ("重新输码按钮", "重新输入授权码"),
    ("授权失败标题", "授权未通过"),
    ("授权失败文案", "不属于当前 QQ 号"),
    # ---- v4.3.1：QQ 号可手动改 ----
    ("改QQ号按钮", "修改 QQ 号"),
    # v4.3.5：旧文案「自动探测可能取到历史残留目录」随自动探测一起下线
    ("改QQ号弹框", "这里填的号只在本次 QQ 会话有效"),
    ("手动标记", "手动指定"),
    # v4.3.6：输入提示改成明确要求第二栏填 QQ 号（旧提示已下线）
    # v4.3.6 旧提示「第二栏填你的 QQ 号」随 v4.6.12 自动带出一起下线
    ("授权输入提示v4612", "第二栏 = 当前登录的 QQ 号"),
    # ---- v4.3.2：明确反馈 ----
    ("通过toast", "✔ 授权通过"),
    ("失败toast", "✘ 授权未通过"),
    ("号不匹配说明", "这个码没绑当前登录的 QQ 号"),   # v4.6.13 文案加「登录的」
    ("码无效说明", "授权码不存在"),
    ("连不上说明", "连不上后台"),
    ("日志带reason", "reason=%@"),
    # ---- v4.3.8：版本指纹 + 成功弹窗（v4.6.1：版本号已升）----
    ("版本指纹toast", "ChsiHook v4.6.42"),
    ("footer版本指纹", "（QQ 端）· v4.6.42"),
    ("成功弹窗文案", "后台验证已通过"),
    ("取消遥测标记", "__CANCEL__"),
    # 注意：遥测的 @"ver" 键只有 3 个字符，属通用串，WX 包里必然命中，
    # 不能放进断言（v4.3.4 首次 CI 就死在这条反向检查上）。改用长唯一串。
    ("失败弹框取消遥测", "__CANCELFAIL__"),
    # 弹框标题直接带版本号：真机上一眼看出装的是哪一版，不用翻日志
    ("弹框标题版本指纹", "授权 · v4.6.42"),
    # ---- v4.3.6：弹框宿主改编辑器窗口 + 取消退出延后 ----
    ("present成功日志", "弹框已呈现"),
    ("看门狗日志", "授权弹框看门狗"),
    ("取消退出延迟日志", "0.35 秒后 SIGKILL 退出 QQ"),
    # ---- v4.6.11：登录 QQ 号监测 + 不匹配/切号/加号闪退（QQ 专属，#if 内）----
    ("监测启动诊断", "qq-watch started ver=v4.6.42"),
    # ---- v4.6.17：授权后台迁软路由（公网 IPv6 字面量，QQ 专属）----
    ("服务器地址指纹", "2408:8214:3a12"),
    ("监测变更诊断", "qq-watch detect=%@ bound=%@ src=%@ verified=%d"),
    ("不匹配闪退诊断", "qq-mismatch KILL detected=%@ bound=%@ src=%@"),
    # ---- v4.6.14：切号/加号闪退修复（内存 defaults 周期读 + 写 hook）----
    ("内存周期信号", "memdefaults:GuildPostLaunchLastLoginUinKey"),
    ("写事件hook诊断", "defaults-set:%@"),
    # ---- v4.6.15：防破解（响应签名 + 会话密钥 + 心跳）----
    ("响应签名失败诊断", "sig-miss nonceOk=%d"),
    ("签名拒绝reason", "sig_invalid"),
    ("会话密钥成功日志", "session-key ok exp余量=%.0fs"),
    ("jskey字段", "jskey"),
    ("nonce字段", "nonce"),
    ("会话过期心跳", "session-exp reverify exp=%.0f"),
    # ---- v4.6.12：第二栏自动带出当前登录号（LastLoginUin 键）+ 不可修改 ----
    #   v4.6.13 起 ChsiQQCurrentLogin 精确读内存 defaults 的
    #   GuildPostLaunchLastLoginUinKey（键名本身现在是源码字面量，可断言）
    ("GuildPostLastLoginUin键", "GuildPostLaunchLastLoginUinKey"),
    ("自动检测提示", "（自动检测，不可修改）"),
    ("点重输按钮日志", "重新输入授权码」→ 弹授权框"),
    # ---- v4.3.7：弹框存活看门狗（v4.5.0 仍在）----
    ("弹框存活看门狗", "弹框看门狗["),
    # ---- v4.4.0：只查不建 ----
    ("弹框巡检函数", "ChsiAlertGuardCheck"),
    # ---- v4.5.0：alert 改 present 到 QQ 自己的最上层 VC（不再自建窗口）----
    #   注：旧断言「属 QQ 自己的窗口」随日志文案精简一并下线
    #   （v4.5.3 起呈现日志统一为「弹框已呈现（宿主 = <类名>）」）。
    ("present日志带宿主类名", "弹框已呈现（宿主 = %@）"),
    ("dismiss弹框日志", "已 dismiss 授权弹框"),
    ("巡检弹框不在屏日志", "我们的授权弹框已不在屏上"),   # v4.5.1 改文案
    # ---- v4.5.1：修「输入时间不够」—— 看门狗不再误判、打字中不动弹框 ----
    ("按实例判弹框在屏", "ChsiOurAlertIsOnScreen"),
    ("实例判定跳过日志", "按实例判定"),
    ("看门狗重弹日志v451", "弹框确实已不在屏上，重弹"),
    # ---- v4.5.2：修「没有授权成功/失败提示」—— 弹窗重试 + 请求序号 ----
    ("弹窗重试内核", "ChsiShowAlertRetry"),
    ("请求序号函数", "ChsiLicenseVerifyFrom"),
    ("主动请求标记", "gUserVerifySeq"),
    ("主动请求日志", "主动 %@"),
    # ---- v4.5.3：修「还是没有弹窗」—— dismiss 改按实例精确操作（QQ 端专属）----
    #   ⚠️ `ChsiHostCandidates` / `ChsiPickPresentHost` / `connectedScenes` /
    #      `枚举候选宿主异常` 这几条**不放这里**：它们是纯 UIKit 窗口枚举，
    #      不带任何授权字符串，QQ/WX 两包都会编进去（WX 包编辑器宿主也用），
    #      放进 license_needles 会被 WX 包的「授权串应在 WX 缺席」反向检查
    #      误报残留（v4.5.3 首次 CI 就死在这）→ 已挪到上方 needles 列表。
    ("拿不到宿主日志", "拿不到可用宿主（原因=%@"),
    ("放弃弹窗日志", "重试 20 次仍拿不到可用宿主"),
    ("按实例dismiss日志", "已 dismiss 授权弹框（按实例"),
    ("dismiss兜底日志", "走自身兜底"),
    ("无弹框跳过日志", "没有记录在案的弹框实例"),
    # ---- v4.5.4：修「输入正确却提示未通过」—— 🔴 真凶是 HTTP chunked 分帧 ----
    #   服务端 Node 没设 Content-Length → 自动 Transfer-Encoding: chunked，
    #   body 在 wire 上是 "1e\r\n{...}\r\n0\r\n\r\n"；旧代码只切 "\r\n\r\n"
    #   就把带 chunk 长度前缀的内容丢给 NSJSONSerialization → 解析必失败
    #   → 后台 granted 但手机弹「未通过」（v4.5.1/2/3 三轮都被这个坑住）。
    ("HTTP响应体解码函数", "ChsiHTTPBodyExtract"),
    ("chunked分帧判定", "Transfer-Encoding: chunked"),
    ("JSON解析失败日志", "授权响应 JSON 解析失败"),
    ("解析失败排查提示", "可能是 HTTP 分帧/chunked 未处理"),
    # ---- v4.5.5：修「验证成功了还会再弹一次输入授权码」----
    #   根因：ChsiLicenseRefresh() 只判 gEnteredCode 是否为空 → 点「验证」时
    #   输入框 alert dismiss（键盘收起）会让 iOS 补发 DidBecomeActive，
    #   若期间夹过一次进后台（旧 ChsiLicenseInvalidate 会清码）→ 重弹空输入框。
    #   ⇒ 新增 gSessionVerified 标记 + 进后台不再清码 + 看门狗改单拍自链式。
    ("会话已成功标记", "gSessionVerified"),
    ("已成功拒弹日志", "拒绝再弹输入框"),
    ("弹框来源日志", "即将弹授权输入框"),
    # ---- v4.5.6：修「一打开弹 2 次 / 认证完又弹 / 取消要点两次才退出」----
    #   根因：ChsiLicensePrompt() 的并发守卫有缺口（非主线程分支、拿不到宿主
    #   重试分支都是「先 return 后置位」），多入口并发 → 两个 alert 并存 →
    #   gActiveAlert 被覆盖、前一个成"幽灵"，于是取消要点两次。
    #   修法：进入 Prompt 第一件事就抢「单飞令牌」，同一时刻只允许一个弹框流程。
    ("弹框单飞令牌", "gPromptInFlight"),
    ("单飞忽略日志", "已有流程在飞"),
    ("拒弹第二个日志", "拒绝再弹第二个"),
    ("放弃还令牌日志", "重试 8 次仍拿不到宿主"),
    # ---- v4.3.5：本地不存储（配置/改写/QQ 号全走内存，不落盘）----
    ("配置落盘日志", "配置落盘"),   # v4.6.42：字段配置持久化（除授权码）
    ("清理旧配置日志", "本地不存储模式"),
    ("QQ号手动日志", "仅本次进程有效，不落盘"),
    ("QQ号不自动填", "QQ 号（必填"),
    ("QQ号仅手动日志", "自动探测值仅作参考"),
    # ---- v4.6.4：诊断日志**自动回传后台 /probe**（免用户手工导文件）----
    #   为什么加：用户连报三轮「两个手势都不通」，手工取 probe.log 太慢，
    #   改为每行诊断直接 POST 到 http://81.70.90.7:8787/probe，服务器落盘。
    #   🔴 为什么放 license_needles 而不是 needles：这两串在源码里都位于
    #   `#if defined(CHSI_BUILD_QQ)`（ChsiFloatDiag 的自动回传 + ChsiLicensePostPath），
    #   **WX 包根本编不出这两串** → 放 needles 会让 WX 报 86/88 MISS（第二轮 CI 就挂这）。
    #   ⚠️ 又踩一坑：断言不能带引号。@"/probe" 进 Mach-O 后是**裸串 /probe**，
    #   写成 "\"/probe\"" 必然 MISS（第一轮 CI 145/146 就挂在这条）。
    ("诊断自动回传端点", "/probe"),
    ("诊断回传失败日志", "probe 回传失败"),
]

# ---- v4.3.5：微信端**不跟** QQ 一起改成纯内存，仍走 v4.1.9 起的落盘路径 ----
# 所以「回读条数」这条日志现在只有 WX 包有；QQ 包被 #if CHSI_BUILD_QQ 分支替换掉了。
wx_needles = [
    ("写入回读日志", "回读条数"),
    # v4.6.42：WX 保留内置密文路径，解密成功日志仍叫 jscore unlock
    ("WX解密成功日志", "jscore unlock bytes=%lu"),
    # v4.6.15：WX 无服务器，JS 模板密钥本地混淆内置（ChsiWXJSKeyHex）
    #   ⚠️ 不能用 "wx-jskey" —— 含 "jskey" 子串会撞 WX 反向检查（实测 CI 三连挂）
    ("WX内置JS密钥诊断", "wxkey ready"),
]

is_qq = "QQ" in path
if is_qq:
    needles += license_needles      # 必须在内容检查打印之前追加
else:
    needles += wx_needles
print("\n===== 内容检查（UTF-8 / UTF-16LE 两种编码都查）=====")
hit = 0
for name, nd in needles:
    # Obj-C 的 @"..." 字面量在二进制里是 UTF-16LE；纯 ASCII 常量可能是 UTF-8
    in16 = nd.encode("utf-16-le") in data
    in8 = nd.encode("utf-8") in data
    f = in16 or in8
    if f:
        hit += 1
    how = ("UTF16" if in16 else "") + ("+UTF8" if in8 else "") or "-"
    print("  %-12s %-4s %-11s %s" % (name, "OK" if f else "MISS", how, nd))
print("\n命中 %d/%d" % (hit, len(needles)))

# ---- 反向断言：以下字符串必须不存在 ----
#   v1 私有方法 swizzle（会崩）；
#   v4.1.9 起全局共享路径（QQ/微信串配置的暗道，已彻底删除）
absent = [
    # ---- v4.6.9 删掉的东西（悬浮球 UI 整体移除，存在 = 编的是旧源码）----
    ("旧球视图类", "ChsiFloatBallView"),
    ("旧球创建日志", "悬浮球已创建"),
    ("旧球显隐持久化", "chsi_float_hidden"),
    ("旧三指回调诊断", "threeFingerDoubleTap"),
    ("旧created诊断", "created bundle=%@"),
    ("旧gestures诊断", "gestures attached view=%@"),
    ("旧setHidden诊断", "setHidden=%d frame="),
    ("旧mounted诊断", "mounted try=%d sceneState="),
    # ---- v4.6.8 删掉的东西（存在 = 编的是旧源码）----
    #   「显示悬浮球」开关行 + swFloatChanged + ChsiFloatEnabled +
    #   ChsiFloatApplyVisibility 全删（入口只留双指长按，授权门控）。
    #   ⚠️ 「chsi_float」不能加反向 —— chsi_float_hidden / chsi_float_x
    #      还在，子串污染必误报。
    ("旧悬浮球开关行", "显示悬浮球"),
    ("旧开关setter", "悬浮球开关: "),
    ("旧放行日志", "其余区域完全放行 QQ"),
    ("v1私有hook", "_didFinishNavigation:"),
    ("v1私有回调", "chsi_didFinishNavigation"),
    ("旧全局配置路径", "/var/mobile/Library/Preferences/com.chsihook.rules.plist"),
    ("旧的二号路径常量", "ChsiSharedPathLegacy"),
    ("旧读函数", "ChsiSharedRead"),
    ("旧写函数", "ChsiSharedWrite"),
    # ---- v4.3.0 删掉的东西（存在 = 编的是旧源码）----
    ("旧IDFV函数", "identifierForVendor"),
    ("旧设备兜底", "UNKNOWN-DEVICE"),
    ("旧设备标签", "设备 ID："),
    ("旧后台地址提示", "先确认服务还活着"),
    ("旧白名单说明", "把上面这个 ID 加进后台白名单"),
    ("旧输码提示", "每次打开 QQ 都要重新输入"),
    ("旧沙箱说明行", "QQ 与微信各存各的"),
    # ---- v4.3.1 删掉的旧提示 ----
    ("v4.3.0单栏提示", "输入授权码（当前 QQ 号：%@）"),
    # ---- v4.3.4 删掉的 footer 行（用户要求：截图别泄露 QQ 号）----
    ("v4.3.4删的footer行", "QQ 号："),
    # ---- v4.3.8：版本号已升到当前版，源码里不该再有上一版的字面量 ----
    ("上一版版本指纹", "v4.6.41"),   # v4.6.42 源码里不该再有 v4.6.38 运行时字面量
    # ---- v4.6.15：JS 模板已加密 —— 明文 JS 特征串在二进制里出现 = 密文没编进去 ----
    ("旧JS明文1", "__chsiRewriterInstalled"),
    ("旧JS明文2", "MutationObserver"),
    ("旧JS明文3", "createTreeWalker"),
    ("旧JS明文4", "__chsiRewrite()"),
    # ---- v4.6.1：隐藏态「全屏感应层」措辞已下线（窗口改回球大小）----
    #   ⚠️ 只断言**带版本化的长串**。裸 "全屏" 会命中 v4.5.0/v4.6.0 历史注释
    #      与编辑器窗口注释（注释不进二进制，但这里是查源码 + 产物双查）。
    # ---- v4.6.2：hitTest 多指闸门已删（它把双指长按打死），源码里不该再有 ----
    ("v4.6.2删的穿透标记", "chsiPassthroughMode"),
    ("v4.6.1删的全屏感应措辞", "全屏感应"),
    ("v4.6.1删的全屏透明层", "全屏透明感应层"),
    # ---- v4.6.0：编辑器「开启改写」总开关已删除，源码/二进制里不该再有这个文案 ----
    #   注：这是**编辑器 cell 文案**（4 个字，够长够唯一），不是通用短串。
    #   源码注释里的「开启改写」不进二进制，所以断言打在编译产物上是安全的。
    ("v4.6.0删的开启改写行", "开启改写"),
    # ⚠️ 只断言「版本化的长串」，不能拿裸 "v4.5.3" 做反向 ——
    #    文件里大量「v4.5.3：xxx」历史注释会命中（注释不进二进制，但这里是查源码）。
    # ---- v4.5.4：旧的无脑切 "\r\n\r\n" 解析路径已换成 ChsiHTTPBodyExtract ----
    #   （不反向断言 \r\n\r\n 本身 —— 新函数内部还在用它切头，属正常）
    # ---- v4.5.3：弹窗重试日志文案已改，旧的「宿主忙（retry=」不该再出现 ----
    ("v4.5.2旧重试日志", "宿主忙（retry="),
    ("v4.3.5旧输入提示", "QQ 号不对就直接改下面那栏"),
    # 注：v4.3.2 起失败弹框按后台 reason 分类给具体文案，
    #     但仍保留笼统那句作 fallback（reason 为空/未知时用），故不做反向断言。
]
if not is_qq:
    absent += [("v4.3授权串应在WX缺席", nd) for _, nd in license_needles]
print("\n===== 反向检查（必须不存在，存在=残留旧代码）=====")
absent_ok = True
for name, nd in absent:
    in16 = nd.encode("utf-16-le") in data
    in8 = nd.encode("utf-8") in data
    gone = not (in16 or in8)
    if not gone:
        absent_ok = False
    print("  %-14s %-4s %-11s %s" % (name, "OK(已移除)" if gone else "!! 残留", "", nd))
print("\n反向检查 %s" % ("全部通过" if absent_ok else "存在残留"))

sys.exit(0 if (ok and hit == len(needles) and absent_ok) else 1)
