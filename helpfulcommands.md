wmic path win32_startupcommand where "name='OneDriveStandaloneUpdater.exe'" call delete
wmic product where "name like 'Microsoft OneDrive%'" call uninstall
loki -p C:\ --intense --pesieveshellc --vulnchecks
wmic RECOVEROS set DebugInfoType = 1
