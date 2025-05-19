SKIPUNZIP=0
check_magisk_version() {
	ui_print "- Magisk version: $MAGISK_VER_CODE"
	ui_print "- Module version: $(grep_prop version "${TMPDIR}/module.prop")"
	ui_print "- Module versionCode: $(grep_prop versionCode "${TMPDIR}/module.prop")"
	ui_print "********************************************"
	ui_print "- $(grep_prop description "${TMPDIR}/module.prop")"
	if [ "$MAGISK_VER_CODE" -lt 20400 ]; then
		ui_print "********************************************"
		ui_print "! 请安装 Magisk v20.4+ (20400+)"
		abort    "********************************************"
	fi
}
check_required_files() {
	REQUIRED_FILE_LIST="/sys/devices/system/cpu/present /proc/loadavg"
	for REQUIRED_FILE in $REQUIRED_FILE_LIST; do
		if [ ! -e $REQUIRED_FILE ]; then
			ui_print "********************************************"
			ui_print "! $REQUIRED_FILE 文件不存在"
			ui_print "! 请联系模块作者"
			abort    "********************************************"
		fi
	done
}
extract_bin() {
	ui_print "********************************************"
	if [ "$ARCH" == "arm" ]; then
		cp $MODPATH/bin/armeabi-v7a/DeamOpt $MODPATH
	elif [ "$ARCH" == "arm64" ]; then
		cp $MODPATH/bin/arm64-v8a/DeamOpt $MODPATH
	elif [ "$ARCH" == "x86" ]; then
		cp $MODPATH/bin/x86/DeamOpt $MODPATH
	elif [ "$ARCH" == "x64" ]; then
		cp $MODPATH/bin/x86_64/DeamOpt $MODPATH
	else
		abort "! Unsupported platform: $ARCH"
	fi
	ui_print "- Device platform: $ARCH"
	rm -rf $MODPATH/bin
}
remove_sys_perf_config() {
	for SYSPERFCONFIG in $(ls /system/vendor/bin/msm_irqbalance); do
		[[ ! -d $MODPATH${SYSPERFCONFIG%/*} ]] && mkdir -p $MODPATH${SYSPERFCONFIG%/*}
		ui_print "- Config file:$SYSPERFCONFIG"
		touch $MODPATH$SYSPERFCONFIG
	done
	if [ -n "$(pm path com.xiaomi.joyose)" ] && [ -n "$(getprop ro.miui.ui.version.code)" ]; then
		pm disable --user 0 com.xiaomi.joyose/.smartop.SmartOpService
		echo 'pm enable com.xiaomi.joyose/.smartop.SmartOpService' >> $MODPATH/uninstall.sh
	fi
}

check_magisk_version
check_required_files
extract_bin
remove_sys_perf_config
if [ -f /data/adb/modules/DeamAppOpt/applist.conf ]; then
	mv $MODPATH/applist.conf $MODPATH/applist.conf.bak
	cp -r /data/adb/modules/DeamAppOpt/applist.conf ${MODPATH}
fi
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm_recursive "$MODPATH/*.sh" 0 2000 0755 0755 u:object_r:magisk_file:s0
set_perm_recursive "$MODPATH/DeamOpt" 0 2000 0755 0755
