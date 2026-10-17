# v4.1：同一份 ChsiHook.m 编两个互相独立的 dylib ——
#   ChsiHookQQ.dylib → -DCHSI_BUILD_QQ（bundle 过滤只放行 com.tencent.mqq）
#   ChsiHookWX.dylib → -DCHSI_BUILD_WX（bundle 过滤只放行 com.tencent.xin）
# 一个 App 崩了不影响另一个（TrollFools 分别注入/移除）。
# 2026-09-19 起只编 arm64：App Store 应用一律以 arm64 运行，
# arm64e 切片无用；且新 lipo 产出的 FAT entry（cputype=0x0100000C +
# cpusub=0x80000002）在部分设备上有加载风险（实测 QQ 注入闪退）。
export ARCHS = arm64
export TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = ChsiHookQQ ChsiHookWX

ChsiHookQQ_FILES = ChsiHook.m
ChsiHookQQ_FRAMEWORKS = UIKit WebKit Foundation
ChsiHookQQ_CFLAGS = -fobjc-arc -DCHSI_BUILD_QQ
ChsiHookQQ_INSTALL_PATH = /Library/MobileSubstrate/DynamicLibraries

ChsiHookWX_FILES = ChsiHook.m
ChsiHookWX_FRAMEWORKS = UIKit WebKit Foundation
ChsiHookWX_CFLAGS = -fobjc-arc -DCHSI_BUILD_WX
ChsiHookWX_INSTALL_PATH = /Library/MobileSubstrate/DynamicLibraries

include $(THEOS)/makefiles/library.mk
