adb push libhello.so /dev/
adb push libhook_open.so /dev/
adb push inject /dev/
adb shell chmod 777 /dev/inject
adb shell ./dev/inject
@pause