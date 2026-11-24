# Android 交叉編譯：host（Linux x64）的 mksnapshot 仍啟用 trap handler，
# 但 v8.gyp 因 OS=="android" 沒把 posix handler 編進 host → 連結失敗。補上 host 專用條件。
import sys
p=sys.argv[1]+'/tools/v8_gypfiles/v8.gyp'
s=open(p).read()
if 'LMA_ANDROID_HOST' in s: sys.exit(0)
P='''['_toolset=="host" and OS=="android" and host_arch=="x64"', {  # LMA_ANDROID_HOST
                  'sources': [
                    '<(V8_ROOT)/src/trap-handler/handler-inside-posix.cc',
                    '<(V8_ROOT)/src/trap-handler/handler-outside-posix.cc',%s
                  ],
                }],
                '''
a='[\'OS in "linux mac ios freebsd openharmony"\', {'
base=s.index("'target_name': 'v8_base_without_compiler'")
i=s.index(a,base); s=s[:i]+P%''+s[i:]
b='[\'((_toolset=="host" and host_arch=="arm64"'
i=s.index(b,base); s=s[:i]+P%"\n                    '<(V8_ROOT)/src/trap-handler/handler-outside-simulator.cc',"+s[i:]
open(p,'w').write(s); print('patched',p)
