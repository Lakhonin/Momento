Ошибка синхронизации времени в Windows
Get-ScheduledTask SynchronizeTime
w32tm /query /peers
nslookup time.windows.com
tcping time.windows.com 123
123/udp
w32tm /config /update
w32tm /resync
w32tm /query /status

сброс 
net stop w32time
w32tm /unregister
w32tm /register
net start w32time
****************
Какая программа слушает определенный порт в Windows?
netstat -aon | findstr ":80" | findstr "LISTENING"
tasklist /FI "PID eq 16124"

Get-Process -Id (Get-NetTCPConnection -LocalPort 80).OwningProcess
Get-Process -Id (Get-NetUDPEndpoint -LocalPort 80).OwningProcess
****************
Как полностью удалить драйвер в Windows
dism /online /get-drivers /format:table
pnputil /delete-driver <Published Name> /uninstall /force
****************
Как расширить диск (раздел) в Windows
Get-Partition -DiskNumber 0
Get-PartitionSupportedSize -DriveLetter C
Resize-Partition -DriveLetter C -Size 42169532416
Изменить имя компьютера в Windows
•	Длина не более 15 символов
•	Не должно содержать специальных символов (< > ; : » * + = \ | ? ,)
•	Можно использовать тире и нижнее подчеркивание
•	Не должно состоять только из цифр
•	Имя компьютера регистр независимо
•	Если компьютер будет добавлен в домен Active Directory, имя компьютера должно быть уникальным в пределах домена.
Rename-Computer -NewName "WKS-MSKO12S3" –Restart -Force
логи печати принтеров из журнала событий Windows
$all2dayprint=Get-WinEvent -FilterHashTable @{LogName="Microsoft-Windows-PrintService/Operational"; ID=307; StartTime=(Get-Date).AddDays(-1)} | Select-object -Property TimeCreated, @{label='UserName';expression={$_.properties[2].value}}, @{label='Document';expression={$_.properties[1].value}}, @{label='PrinterName';expression={$_.properties[4].value}}, @{label='PrintSizeKb';expression={$_.properties[6].value/1024}}, @{label='Pages';expression={$_.properties[7].value}}
$all2dayprint|ft
****************
Просмотр и анализ событий (логов) Windows с помощью PowerShell
Get-WinEvent -FilterHashtable @{logname='System';id=1074}|ft TimeCreated,Id,Message
В параметре FilterHashtable можно использовать фильтры по следующим атрибутам событий:
•	LogName
•	ProviderName
•	Path
•	Keywords (для поиска успешных событий нужно использовать значение 9007199254740992 или для неуспешных попыток 4503599627370496)
•	ID
•	Level (1=FATAL, 2=ERROR, 3=Warning, 4=Information, 5=DEBUG, 6=TRACE, 0=Info)
•	StartTime
•	EndTime
•	UserID (SID пользователя)
•	Data
****************
Как вручную установить размер MTU
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\<AdapterID>
****************
Меняем значение Time To Live (TTL)
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
New — DWORD (32-bit), задайте имя этому параметру имя «DefaultTTL» и установите его значение в диапазоне от «0» до «255»
****************
Resource Monitor для определения блокировок файлов
 ![alt text](image-1.png)
 ****************
Сброс настроек протокола TCP/IP
ipconfig /flushdns
nbtstat -R
nbtstat -RR
netsh int reset all
netsh int ip reset
netsh winsock reset
netsh interface tcp set global autotuninglevel=disabled
****************
Изоляция драйвера принтера
Как следует из названия, технология Printer Driver Isolation (PDI) реализует изоляцию драйверов принтеров в отдельные процессы, отделенные от процесса диспетчера печати (spoolsv.exe)
************
Восстановление хранилища компонентов
Файлы хранилища компонентов Windows на диске располагаются в каталоге \Windows\WinSxS
Файлы в каталогах:
•	%SYSTEMROOT%\Servicing\Packages
•	%SYSTEMROOT%\WinSxS\Manifests
Содержимое веток реестра:
•	%SYSTEMROOT%\WinSxS\Manifests
•	HKEY_LOCAL_MACHINE\Schema
•	HKEY_LOCAL_MACHINE\Components
•	HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing
Code	Error	Description
0×80070002	ERROR_FILE_NOT_FOUND	The system cannot find the file specified.
0x8007000D	ERROR_INVALID_DATA	The data is invalid.
0x800F081F	CBS_E_SOURCE_MISSING	The source for the package or file not found.
0×80073712	ERROR_SXS_COMPONENT_STORE_CORRUPT	The component store is in an inconsistent state.
0x800736CC	ERROR_SXS_FILE_HASH_MISMATCH	A component’s file does not match the verification information present in the component manifest.
0x800705B9	ERROR_XML_PARSE_ERROR	Unable to parse the requested XML data.
0×80070246	ERROR_ILLEGAL_CHARACTER	An invalid character was encountered.
0x8007370D	ERROR_SXS_IDENTITY_PARSE_ERROR	An identity string is malformed.
0x8007370B	ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME	The name of an attribute in an identity is not within the valid range.
0x8007370A	ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE	The value of an attribute in an identity is not within the valid range.
0×80070057	ERROR_INVALID_PARAMETER	The parameter is incorrect.
0x800B0100	TRUST_E_NOSIGNATURE	No signature was present in the subject.
0×80092003	CRYPT_E_FILE_ERROR	An error occurred while Windows Update reads or writes to a file.
0x800B0101	CERT_E_EXPIRED	A required certificate is not within its validity period when verifying against the current system clock or the time stamp in the signed file.
0x8007371B	ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE	One or more required members of the transaction are not present.
0×80070490	ERROR_NOT_FOUND	Windows could not search for new updates.
Dism /Online /Cleanup-Image /CheckHealth
1.	Команда Dism /Cleanup-Image сохраняет логи в каталогах C:\Windows\Logs\CBS\CBS.log и C:\Windows\Logs\DISM\dism.log
2.	Dism.exe /Online /Cleanup-Image /Restorehealth
3.	Get-WindowsImage -ImagePath E:\sources\install.wim
4.	Repair-WindowsImage -Online -RestoreHealth -Source G:\sources\install.wim:1
 проверка целостности системных файлов с помощью команды
sfc /scannow
net stop wuauserv

net stop bits

net stop cryptsvc

ren %systemroot%\SoftwareDistribution oldSD

ren %systemroot%\System32\catroot2 oldCat2

net start cryptsvc

net start bits

net start wuauserv
*************
Настройка часового пояса в Windows
reg query HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation
Get-TimeZone -ListAvailable | Where-Object {$_.Id -like "*Russ*"}
Set-TimeZone -Name "Astrakhan Standard Time"
************
Резервное копирование (экспорт) и восстановление драйверов в Windows
Export-WindowsDriver –Online -Destination c:\drivers
pnputil.exe /add-driver C:\drivers\*.inf /subdirs /install
***********
WMI: Исправление ошибок, восстановление репозитория в Windows
%windir%\System32\Wbem\Repository 
•	Ошибки обработки WMI запросов в системных журналах и логах приложений ( 0x80041002 - WBEM_E_NOT_FOUND , WMI: Not Found , 0x80041010 WBEM_E_INVALID_CLASS );
•	Ошибки обработки GPO, связанные на WMI ( некорректная работа wmi фильтров групповых политик, и пр.);
•	WMI запросы выполняются очень медленно;
•	Ошибки при установке или работе агентов SCCM/SCOM;
•	Ошибки в работе скриптов (vbs или PowerShell), использующих пространство имен WMI (скрипты с Get-WmiObject и т.д.).
проверить целостность репозитория WMI с помощью команды:
winmgmt /verifyrepository
Winmgmt /salvagerepository
Мяг
sc config winmgmt start= disabled
net stop winmgmt
cd %windir%\system32\wbem
for /f %s in ('dir /b *.dll') do regsvr32 /s %s
wmiprvse /regserver
sc config winmgmt start= auto
net start winmgmt
for /f %s in ('dir /b *.mof') do mofcomp %s
for /f %s in ('dir /b *.mfl') do mofcomp %s
cd %windir%\SysWOW64\wbem
жестк
Winmgmt /resetrepository

sc config winmgmt start= disabled
net stop winmgmt
cd %windir%\system32\wbem
winmgmt /resetrepository
winmgmt /resyncperf
if exist Repos_bakup rd Repos_bakup /s /q
rename Repository Repos_bakup
regsvr32 /s %systemroot%\system32\scecli.dll
regsvr32 /s %systemroot%\system32\userenv.dll
for /f %s in ('dir /b *.dll') do regsvr32 /s %s
for /f %s in ('dir /b *.mof') do mofcomp %s
for /f %s in ('dir /b *.mfl') do mofcomp %s
sc config winmgmt start= auto
net start winmgmt
wmiprvse /regserver
************
Сброс настроек службы обновлений Windows Update
net stop bits
net stop wuauserv
net stop appidsvc
net stop cryptsvc
taskkill /im wuauclt.exe /f
Del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat"
Ren %systemroot%\SoftwareDistribution SoftwareDistribution.bak
Ren %systemroot%\system32\catroot2 catroot2.bak
del /f /s /q %windir%\windowsupdate.log
sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY) (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA) (A;;CCLCSWLOCRRC;;;AU) (A;;CCLCSWRPWPDTLOCRRC;;;PU)
sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY) (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA) (A;;CCLCSWLOCRRC;;;AU) (A;;CCLCSWRPWPDTLOCRRC;;;PU)
sc.exe sdset cryptsvc D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLCRSDRCWDWO;;;SO)(A;;CCLCSWRPWPDTLOCRRC;;;SY)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;WD)
sc.exe sdset trustedinstaller D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLCRSDRCWDWO;;;SO)(A;;CCLCSWRPWPDTLOCRRC;;;SY)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;WD)
cd /d %windir%\system32
regsvr32.exe /s atl.dll
regsvr32.exe /s urlmon.dll
regsvr32.exe /s mshtml.dll
regsvr32.exe /s shdocvw.dll
regsvr32.exe /s browseui.dll
regsvr32.exe /s jscript.dll
regsvr32.exe /s vbscript.dll
regsvr32.exe /s scrrun.dll
regsvr32.exe /s msxml.dll
regsvr32.exe /s msxml3.dll
regsvr32.exe /s msxml6.dll
regsvr32.exe /s actxprxy.dll
regsvr32.exe /s softpub.dll
regsvr32.exe /s wintrust.dll
regsvr32.exe /s dssenh.dll
regsvr32.exe /s rsaenh.dll
regsvr32.exe /s gpkcsp.dll
regsvr32.exe /s sccbase.dll
regsvr32.exe /s slbcsp.dll
regsvr32.exe /s cryptdlg.dll
regsvr32.exe /s oleaut32.dll
regsvr32.exe /s ole32.dll
regsvr32.exe /s shell32.dll
regsvr32.exe /s initpki.dll
regsvr32.exe /s wuapi.dll
regsvr32.exe /s wuaueng.dll
regsvr32.exe /s wuaueng1.dll
regsvr32.exe /s wucltui.dll
regsvr32.exe /s wups.dll
regsvr32.exe /s wups2.dll
regsvr32.exe /s wuweb.dll
regsvr32.exe /s qmgr.dll
regsvr32.exe /s qmgrprxy.dll
regsvr32.exe /s wucltux.dll
regsvr32.exe /s muweb.dll
regsvr32.exe /s wuwebv.dll
netsh winsock reset
netsh winhttp reset proxy
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v AccountDomainSid /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v PingID /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v SusClientId /f
REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v TargetGroup /f
REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer /f
REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUStatusServer /f
sc.exe config wuauserv start= auto
sc.exe config bits start= delayed-auto
sc.exe config cryptsvc start= auto
sc.exe config TrustedInstaller start= demand
sc.exe config DcomLaunch start= auto
net start bits
net start wuauserv
net start appidsvc
net start cryptsvc
wuauclt /resetauthorization /detectnow
*********
Управление приоритетами процессов в Windows
Где это может понадобиться? Например, в связке 1С-SQL можно дать больше процессорного времени 1С и SQL, как наиболее критичным к ресурсам процессам
Они группируются так:
•	31 — 16 уровни реального времени;
•	15 — 1 динамические уровни;
•	0 — системный уровень, зарезервированный для потока обнуления страниц (zero-page thread).
При создании процесса, ему назначается один из шести классов приоритетов:
1.	Real time class (значение 24),
2.	High class (значение 13),
3.	Above normal class (значение 10),
4.	Normal class (значение 8),
5.	Below normal class (значение 6),
6.	или Idle class (значение 4).
Приоритет каждого потока (базовый приоритет потока) складывается из приоритета его процесса и относительного приоритета самого потока. Есть семь относительных приоритетов потоков:
1.	Normal: такой же как и у процесса;
2.	Above normal: +1 к приоритету процесса;
3.	Below normal: -1;
4.	Highest: +2;
5.	Lowest: -2;
6.	Time critical: устанавливает базовый приоритет потока для Real time класса в 31, для остальных классов в 15.
7.	Idle: устанавливает базовый приоритет потока для Real time класса в 16, для остальных классов в 1.
wmic process where processid='XXXX' CALL setpriority ProcessIDLevel
wmic process where processid='8476' CALL setpriority "above normal"
**************
Измерение производительности и IOPS жестких дисков
Physical Disk (можете выбрать счётчики для конкретного диска или для всех доступных локальных дисков):
•	 Disk sec/Transfer – время, необходимое для выполнения одной операции записи/чтения на устройство хранения/диск — disk latency. Если задержка более 25 мс (0.25) или выше, значит дисковый массив не успевает выполнять операции. Для высоконагруженных систем значение не должно превышать 10 мс (0.1);
•	Disk Transfers/sec – количество операций чтения/записи в секунду (IOPS). Это основной показатель интенсивности обращений к дискам (примерные значения в IOPS для разных типов дисков представлены в конце статьи);
•	Disk Bytes/Sec – средняя скорость обмена с диском (чтения/записи) за 1 секунду. Максимальные значения зависит от типа диска (150-250 Мб/секунду — для обычного диска и 500-10000 для SSD);
•	Split IO/sec – показатель фрагментации диска, когда операционной системе приходится разделять одну операцию ввода/вывода на несколько операций. Может также говорить о том, приложение запрашивает слишком большие блоки данных, которые немогут быть переданы за одну операцию;
•	Avg. Disk Queue Length– длина очереди к диску (количество транзакций ожидающий обработку). Для одиночного диска длина очереди не должна превышать 2. Для RAID массива из 4 дисков длина очереди до 8 будет считаться допустимым значением
https://aka.ms/diskspd
diskspd.exe –c50G -d300 -r -w40 -t8 -o32 -b64K -Sh -L E:\diskpsdtmp.dat > DiskSpeedResults.txt
•	 -c50G – размер файла 50 Гб (лучше использовать большой размер файла, чтобы он не поместился в кэш контроллера СХД);
•	 -d30 0 – продолжительность тестирования в секундах;
•	 -r – произвольное чтение/запись (если нужно тестировать последовательный доступ, используйте –s);
•	 -t8 – количество потоков;
•	 -w40 – соотношение операций записи к операциям чтения 40% / 60%;
•	 -o32 — длина очереди;
•	 -b64K — размер блока;
•	 -Sh — не использовать кэширование;
•	 -L — измерять задержки (latency) ;
•	 E:\diskpsdtmp.dat – путь к тестовому файл.
•	В следующей таблице указаны примерные значения IOPS для различных типов дисков:
Тип	IOPS
SSD(SLC)	6000
SSD(MLC)	1000
15K RPM	175-200
10K RPM	125-150
7.2K RPM	50-75
RAID5 из 6 дисков с 10000 RPM	900
User Account Control
•	Уровень 4 — Always notify — Всегда уведомлять (максимальный уровень защиты UAC);
•	Уровень 3 — Notify only when programs try to make changes to my computer (default) – Уведомить только когда программа пытается внести изменения в мой компьютер (стандартный уровень защиты);
•	Уровень 2 — Notify only when programs try to make changes to my computer (do not dim my desktop) – то же что и предыдущий уровень, но без переключения на Secure Desktop с блокировкой рабочего стола;
•	Уровень 1 — Never notify – Никогда не уведомлять (UAC отключен).
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
Имя политики		Ключ реестра, настраиваемый политикой
User Account Control: Admin Approval Mode for the Built-in Administrator account	Контроль учетных записей: использование режима одобрения администратором для встроенной учетной записи администратора	FilterAdministratorToken
User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop	Контроль учетных записей: разрешать UIAccess-приложениям запрашивать повышение прав, не используя безопасный рабочий стол	EnableUIADesktopToggle
User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode	Контроль учетных записей: поведение запроса на повышение прав для администраторов в режиме одобрения администратором	ConsentPromptBehaviorAdmin
User Account Control: Behavior of the elevation prompt for standard users	Контроль учетных записей: поведение запроса на повышение прав для обычных пользователей	ConsentPromptBehaviorUser
User Account Control: Detect application installations and prompt for elevation	Контроль учетных записей: обнаружение установки приложений и запрос на повышение прав	EnableInstallerDetection
User Account Control: Only elevate executables that are signed and validated	Контроль учетных записей: повышение прав только для подписанных и проверенных исполняемых файлов	ValidateAdminCodeSignatures
User Account Control: Only elevate UIAccess applications that are installed in secure locations	Контроль учетных записей: повышать права только для UIAccess-приложений, установленных в безопасном местоположении	EnableSecureUIAPaths
User Account Control: Run all administrators in Admin Approval Mode	Контроль учетных записей: включение режима одобрения администратором	EnableLUA
User Account Control: Switch to the secure desktop when prompting for elevation	Контроль учетных записей: переключение к безопасному рабочему столу при выполнении запроса на повышение прав	PromptOnSecureDesktop
User Account Control: Virtualize file and registry write failures to per-user locations	Контроль учетных записей: при сбоях записи в файл или реестр виртуализация в размещение пользователя	EnableVirtualization
Восстановление несохраненного документа в Word
 
C:\Users\%username%\AppData\Local\Microsoft\Office\UnsavedFiles
C:\Users\%username%\AppData\Roaming\Microsoft\Word
*********
Принудительная очистка очереди печати в Windows
при отправке документа на печать на принтер, служба печати Windows (Print Spooler) формирует задание печати и создает два файла: один с расширением .SHD (содержит настройки задания печати), второй — .SPL (хранит собственно данные, которые нужно распечатать). Таким образом, задания печати будут доступны службе печати, даже после закрытия программы, инициировавшей печать. Данные файлы хранятся в каталоге спулера (по умолчанию, «%systemroot%\System32\spool\PRINTERS”)
net stop spooler
del %systemroot%\system32\spool\printers\*.shd /F /S /Q
del %systemroot%\system32\spool\printers\*.spl /F /S /Q
net start spooler
*********
Очистка (сброс) поврежденного кэша иконок в Windows
iconcache_ (iconcache_16.db, iconcache_32.db, iconcache_48.db и т.д. в соответствии с размерами иконки в пикселях) и хранятся в каталоге %userprofile%\AppData\Local\Microsoft\Windows\Explorer
taskkill /f /im explorer.exe
cd /d %userprofile%\AppData\Local\Microsoft\Windows\Explorer
attrib –h iconcache_*.db
del /f IconCache*
del /f thumbcache*
cd /d  %userprofile%\AppData\Local\
attrib –h IconCache.db
del /f IconCache.db
start C:\Windows\explorer.exe
*************
Как в Windows 10 отключить ограничение на длину пути в 260
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name LongPathsEnabled -Value 1
Настройка макета меню Пуск и панели задач в Windows 10
Export-StartLayout –path c:\ps\StartLayoutW10.xml
Import-StartLayout –LayoutPath c:\ps\StartLayoutW10.xml  –MountPath c:\
Ошибка 0x00000057 при установке сетевого принтера
ам понадобится компьютер, на котором данный принтер установлен корректно и успешно печатает. На этом компьютере запустите редактор реестра и перейдите в следующую ветку реестра
•	на x64 системе: HKEY_LOCAL_MACHINE System\CurrentControlSet\Control\Print\Environments\Windows NT x64\Drivers\Version-3\
•	на x86 системе HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Environments\Windows NT x86\Drivers\Version-3\
•	Найдите ветку с именем драйвера принтера, который вы хотите установить и экспортируйте ее в Reg файл.
•	Затем в данной ветке найдите значение ключа InfPath. В моем примере это C:\Windows\System32\DriverStore\FileRepository\prnhp002.inf_amd64_neutral_04d05d1f6a90ea24\prnhp002.inf
Перейдите в каталог C:\Windows\System32\DriverStore\FileRepository и найдите имя папки, на которую указывает ключ
Теперь на проблемном компьютере попытайтесь найти эту папку. Скорее всего она будет присутствовать, но будет пустой. Это свидетельствует о том, что процесс установки драйвера аварийно прервался
*******
Отключение протоколов NetBIOS и LLMNR в Windows
LLMNR (UDP/5355, Link-Local Multicast Name Resolution — механизм широковещательного разрешения имен) – протокол присутствует во всех версиях Windows, начиная с Vista и позволяет IPv6 и IPv4 клиентам разрешать имена соседних компьютеров без использования DNS сервера за счет широковещательных запросов в локальном сегменте сети L2. Этот протокол также автоматически используется при недоступности DNS (в рабочих группах Windows этот протокол используется для сетевого обнаружения/Network Discovery). Соответственно, при работающих DNS-серверах в домене, этот протокол абсолютно не нужен
ротокол NetBIOS over TCP/IP или NBT-NS (UDP/137,138;TCP/139) – является широковещательным протоколом-предшественником LLMNR и используется в локальной сети для публикации и поиска ресурсов. Поддержка NetBIOS over TCP/IP по умолчанию включена для всех интерфейсов во всех версиях Windows
New-Item  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name DNSClient  -Force
New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value 0 -PropertyType DWORD  -Force

$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
Не удается подключить сетевой принтер в Windows
Ошибка 0x00000002 может возникнуть при попытке подключить сетевой принтер через принт-сервер и TCP/IP порт
Remove-PrinterDriver -Name "HP Universal Printing PCL 6"
Массовая проблема с подключением сетевых принтеров Windows с ошибкой 0x0000011b началась после установки обновлений безопасности Windows с 15 сентября 2021 года.
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 0 /f
*********
Windows LAPS
Windows при загрузке изменит пароль локального администратора и запишет его в защищенный атрибут msLAPS-Password в объект компьютера в AD
•	msLAPS-PasswordExpirationTime
•	msLAPS-Password
•	msLAPS-EncryptedPassword
•	msLAPS-EncryptedPasswordHistory
•	msLAPS-EncryptedDSRMPassword
•	msLAPS-EncryptedDSRMPasswordHistory
Get-Command -Module LAPS
Ошибка Windows: обновление неприменимо к вашему компьютеру
•	Если компьютер давно не перезагружался или не перезагружался после установки последних обновлений, попробуйте принудительно перезагрузить Windows;
•	Данное обновление не соответствует вашей версии ОС, редакции, билду, разрядности (архитектуре процессора: x86, x64; ARM) или языку
Перед установкой некоторых обновлений нужно сначала установить последнее доступное обновление служебного стека (SSU — Servicing Stack Update)
проверьте ошибки установки обновлений в файле %systemroot%\Logs\CBS\CBS.log
expand _f:* “C:\Temp\windows10.0-KB4103723-x64.msu” C:\Temp\KB4103723
DISM.exe /Online /Add-Package /PackagePath:c:\Temp\Windows10.0-KB4103723-x64.cab
*************
Как создать, удалить и изменить локального пользователя или группу
New-LocalUser -Name "TestUser1" -FullName "Test User" -Description "User for tests"
Add-LocalGroupMember -Group 'RemoteSupport' -Member ('SIvanov','root', 'Administrators') –Verbose
Сбивается время компьютера (сервера) после выключения / перезагрузки
reg add "HKLMACHINE\System\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation /v RealTimeIsUniversal /t REG_QWORD /d 1
Как правильно удалять обновления в Windows
wusa.exe /quiet /uninstall /kb:2693643 /promptrestart
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
Как удалить файл с длиной пути более 260 символов
mklink /d c:\install\link “C:\Install\MS SQL 2012 Express Edition 64 bit\verylongpath”
Протокол SMB: определить, включить или отключить определенную версию SMB в Windows
•	CIFS — Windows NT 4.0;
•	SMB 1.0 — Windows 2000;
•	SMB 2.0 — Windows Server 2008 и Windows Vista SP1 (поддерживается в Samba 3.6);
•	SMB 2.1 — Windows Server 2008 R2 и Windows 7 (поддерживается в Samba 4.0);
•	SMB 3.0 — Windows Server 2012 и Windows 8 (поддерживается в Samba 4.2);
•	SMB 3.02 — Windows Server 2012 R2 и Windows 8. 1 (не поддерживается в Samba);
•	SMB 3.1.1 – Windows Server 2016 и Windows 10 (не поддерживается в Samba).
Get-SmbServerConfiguration | select EnableSMB1Protocol,EnableSMB2Protocol
Get-WinEvent -LogName Microsoft-Windows-SMBServer/Audit
Отключить клиент и сервер SMBv1:
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
Отключить только SMBv1 сервер:
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Включить клиент и сервер SMBv1:
Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol
Включить только SMBv1 сервер:
Set-SmbServerConfiguration -EnableSMB1Protocol $true
Driver Verifier — выявляем проблемные драйвера Windows
verifier /standard /driver myPCDriver.sys
Verifier /reset
Загрузите файл windows\system32\config\system
5) Удалите ключи реестра
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\VerifyDrivers
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\VerifyDriverLevel
***
Ошибка DistributedCOM 10016 в Windows: Параметры разрешений для приложения не дают разрешения локальной активации
ource: DistributedCOM
Event ID: 10016
Level: Ошибка
User: SYSTEM
Описание: Параметры разрешений для конкретного приложения не дают разрешения Локальный Запуск для приложения COM-сервера с CLSID {1CCB96F4-B8AD-4B43-9688-B273F58E0910} и APPID {AD65A69D-3831-40D7-9629-9B0B50A93843}пользователю NT AUTHORITY\система с SID (S-1-5-18) и адресом LocalHost (с использованием LRPC). Это разрешение безопасности можно изменить с помощью служебной программы управления службами компонентов.
HKEY_CLASSES_ROOT\CLSID\{000209FF-0000-0000-C000-000000000046};
HKEY_CLASSES_ROOT\AppID\{AD65A69D-3831-40D7-9629-9B0B50A93843};
Dcomcnfg
Local Activation -> Allow и Local Launch (Локальная активация) -> Allow;
****
Просмотр журнала обновлений WindowsUpdate.log в Windows
Get-WindowsUpdateLog -logpath C:\PS\Logs\WindowsUpdate.log
•	AGENT- события агента Windows Update;
•	AU – автоматическое обновление;
•	AUCLNT- взаимодействие с пользователем;
•	HANDLER- управление установщиком обновлений;
•	MISC- общая информация;
•	PT- синхронизация обновлений с локальным хранилищем;
•	REPORT- сбор отчетов;
•	SERVICE- запуск/выключение службы wuauserv;
•	SETUP- установка новых версий клиента Windows Update;
•	DownloadManager – загрузка обновлений в локальных кэш;
•	Handler, Setup – заголовки установщиков (CBS и т.п.);
•	И т.д.

Applications and Services Logs -> Microsoft -> Windows –> WindowsUpdateClient -> Operational
******
Исправляем ошибку: Службе профилей пользователей не удалось войти в систему
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList.
Использование Robocopy для синхронизации и резервного копирования файлов
robocopy C:\source\ F:\dest\ /MOVE /E /COPYALL /Z /B /J /R:3 /W:1 /REG /TEE /LOG+:%appdata%\robocopy.log
Способы ограничения скорости копирования по сети в Windows
Для управления классами и приоритетами трафика в сетях TCP/IP используется технология QoS (quality of service).
Get-NetQosPolicy

New-NetQosPolicy -Name "SMBRestrictFileCopySpeed" -SMB -ThrottleRateActionBitsPerSecond 10MB
Get-SmbBandwidthLimit
Настройка политики запуска скриптов (Execution Policy) PowerShell
Get-ExecutionPolicy
•	Restricted – запрещен запуск скриптов PowerShell, можно выполнять только интерактивные команды в консоли;
•	AllSigned – разрешено выполнять только подписанные PS скрипты с цифровой подписью от доверенного издателя (можно подписать скрипт самоподписанным сертификатом и добавить его в доверенные). При запуске недоверенных скриптов появляется предупреждение:
•	RemoteSigned – можно запускать локальные PowerShell скрипты без ограничения. Можно запускать удаленные PS файлы с цифровой подписью (нельзя запустить PS1 файлы, скачанные из Интернета, запущенные из сетевой папки по UNC пути и т.д.);
•	Unrestricted – разрешен запуск всех PowerShell скриптов; Bypass – разрешён запуск любых PS файлов (предупреждения не выводятся) – эта политика обычно используется для автоматического запуска PS скриптов без вывода каких-либо уведомлений (например при запуске через GPO, SCCM, планировщик и т.д.) и не рекомендуется для постоянного использования;
•	Default – сброс настроек выполнения скриптов на стандартную;
•	Undefined – не задано. Применяется политика Restricted для десктопных ОС и RemoteSigned для серверных.
•	MachinePolicy – действует для всех пользователей компьютера, настраивается через GPO;
•	UserPolicy – действует на пользователей компьютера, также настраивается через GPO;
•	Process — настройки ExecutionPolicy действует только для текущего сеанса PowerShell.exe (сбрасываются при закрытии процесса);
•	CurrentUser – политика ExecutionPolicy применяется только к текущему пользователю (параметр из ветки реестра HKEY_CURRENT_USER);
•	LocalMachine – политика для всех пользователей компьютера (параметр из ветки реестра HKEY_LOCAL_MACHINE);
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Restricted –Force
*******
Удаление скрытых сетевых адаптеров в Windows
Get-PnpDevice -class net | ? Status -eq Unknown | Select FriendlyName,InstanceId
$InstanceId = “PCI\VEN_8086&DEV_10D3&SUBSYS_07D015AD&REV_00\000C29FFFF66A80700”
$RemoveKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\$InstanceId"
Get-Item $RemoveKey | Select-Object -ExpandProperty Property | %{ Remove-ItemProperty -Path $RemoveKey -Name $_ -Verbose}
Удаленное управление PowerShell Remoting через WinRM HTTPS
По умолчанию трафик в сессии PowerShell Remoting шифруется независимо от того, используется ли для передачи протокол HTTP (порт TCP/5985) или HTTPS (порт TCP/5986). Весть трафик в любом случае шифруется с помощью ключа AES-256
****
Как узнать, кто перезагрузил (выключил) сервер Windows
Get-EventLog -LogName System |
where {$_.EventId -eq 1074} |select-object -first 10 |
ForEach-Object {
$rv = New-Object PSObject | Select-Object Date, User, Action, process, Reason, ReasonCode
if ($_.ReplacementStrings[4]) {
$rv.Date = $_.TimeGenerated
$rv.User = $_.ReplacementStrings[6]
$rv.Process = $_.ReplacementStrings[0]
$rv.Action = $_.ReplacementStrings[4]
$rv.Reason = $_.ReplacementStrings[2]
$rv
}
} | Select-Object Date, Action, Reason, User, Process |ft
Как узнать размер папок на диске 
"{0:N2} GB" -f ((gci c:\iso | measure Length -s).sum / 1Gb)
***
Сетевой принтер переходит в режим “Автономная работа”
get-printerport |where {$_.SNMPCommunity -ne ‘Public’ –and $_.snmpenabled -eq $True }|select name,protocol,description,printerhostaddress, snmpenabled, SNMPCommunity
1.	Проверьте, что в настройках порта печати указан правильный IP адрес принтера;
2.	Проверьте, что для порта печати используется тип “Standard TCP/IP Port”, а не “WSD Port”;  
3.	Убедитесь, что ваши файерволы не блокирует SNMP трафик (порты 161/UDP и 162/UDP);
4.	Полностью удалите и пересоздайте принтер и порт печати. Переустановите драйвера принтера;
5.	Перезапустите службу spooler;
6.	Вы можете полностью отключить SNMP опрос для всех принтеров, создав в ветке реестра HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print новый ключ типа DWORD с именем SNMPLegacy и значением 1.
***
Файл заблокирован процессом Windows, как снять блокировку?
Handle – это еще одна утилита командной строки из комплекта инструментов Sysinternals (доступна для скачивания на сайте Microsoft (https://docs.microsoft.com/en-us/sysinternals/downloads/handle. Она позволяет найти процесс, который заблокировал ваш файл и снять блокировку, освободив дескриптор.
1.	Скачайте и распакуйте архив с утилитой Handle;
2.	Запустите командную строку с правами администратора и выполните команду: handle64.exe > listproc.txt • Данная команда сохранит список открытых дескрипторов в файл. Можно вывести дескрипторы для каталога, в котором находится файл, который вы хотите изменить: Handle64.exe -a C:\Some\Path или конкретного процесса: handle64.exe -p winword.exe
Ошибка “Сервер RPC недоступен” в Windows 
В типовом сеансе клиент RPC подключается к службе RPC Endpoint Mapper (сопоставления конечных точек) на RPC сервере по TCP порту 135 
Get-Service RpcSs,RpcEptMapper,DcomLaunch| Select DisplayName,Status,StartType
•	Удаленный вызов процедур (RPC) — ветка реестра HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RpcSs 
•	Сопоставитель конечных точек RPC — HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RpcEptMapper
•	Модуль запуска процессов DCOM-сервера — HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DcomLaunch
•	Удаленный компьютер выключен;
•	Не запущены службы RPC на сервере;
•	Вы пытаетесь подключиться к RPC серверу по неправильному имени (или как вариант, DNS имени сервера соответствует неверный IP адрес);
•	Используются некорректные настройки сетевого подключение на клиенте или сервере;
•	RPC трафик между клиентом и сервером блокируется файерволом;
***
Cached Credentials: вход в Windows под сохраненными учетными данными при недоступности домена
Вход на компьютер под кэшированными данными для пользователя доступен, если он ранее хотя бы один раз авторизовался на этом компьютере, и пароль в домене не был сменен с момента входа
Сохраненные пароли хранятся в ветке реестра HKEY_LOCAL_MACHINE\Security\Cache
***
Ошибка предварительного просмотра вложений в Outlook
1.	Перейдите в раздел Файл -> Параметры -> Центр управления безопасностью -> Параметры центра управления безопасностью -> Обработка вложении (File -> Options -> Trust Center -> Trust Center Settings -> Attachment Handling“);
2.	Убедитесь, что не включена опция “Отключить просмотр вложений” (Turn off Attachment Preview);
3.	Нажмите на кнопку “Средства просмотра документов и вложений” (Attachment and Document Previewers);
4.	x86 версия Outlook из Office 2021/2019/2016 — HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PreviewHandlers
5.	x64 Outlook — HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\PreviewHandlers

Название параметра	Значение
{00020827-0000-0000-C000-000000000046}	Microsoft Excel previewer
{21E17C2F-AD3A-4b89-841F-09CFE02D16B7}	Microsoft Visio previewer
{65235197-874B-4A07-BDC5-E65EA825B718}	Microsoft PowerPoint previewer
{84F66100-FF7C-4fb4-B0C0-02CD7FB668FE}	Microsoft Word previewer
{DC6EFB56-9CFA-464D-8880-44885D7DC193}	Adobe PDF Preview Handler for Vista
Получаем историю запуска программ в Windows
Откройте Event Viewer ( eventvwr.msc ) и разверните раздел Windows Logs -> Security. Теперь при запуске любой программы (процесса) в этом журнале событий появляется событие Process Creation с EventID 4688.
$processhistory = @()
$today = get-date -DisplayHint date -UFormat %Y-%m-%d
$events=Get-WinEvent -FilterHashtable @{
LogName = 'Security'
starttime="$today"
ID = 4688
}
foreach ($event in $events){
$proc = New-Object PSObject -Property @{
ProcessName=$event.Properties[5].Value
Time=$event.TimeCreated
CommandLine=$event.Properties[8].Value
User=$event.Properties[1].Value
ParentProcess=$event.Properties[13].Value
}
$processhistory += $proc
}
$processhistory| Out-GridView
Удаление программ в Windows
(Get-WmiObject Win32_Product -Filter "Name = 'XXX'").Uninstall()
Мониторинг состояния жестких дисков (SMART) 
В BIOS/UEFI для дисков должна быть включена поддержка SMART.
Get-WmiObject -namespace root\wmi –class MSStorageDriver_FailurePredictStatus
Установка PowerShell модулей в офлайн режиме 
Как вы видите, PowerShell модули могут хранится по одному из следующих путей:
•	C:\Users\root\Documents\WindowsPowerShell\Modules ( $Home\Documents\PowerShell\Modules ) – модули в этом каталоге в доступны только данному пользователю (CurrentUser)
•	C:\Program Files\WindowsPowerShell\Modules ($Env:ProgramFiles\WindowsPowerShell\Modules) — путь используется при установке модуля для всех пользователей компьютера (-Scope AllUsers)
•	C:\Windows\system32\WindowsPowerShell\v1.0\Modules (каталог для встроенных модулей по-умолчанию)
Не удается расширить диск
1.	Справа от раздела, которые вы хотите расширить находится другой раздел;
2.	Раздел отформатирован в файловой системе, которая не поддерживается расширение (FAT32, exFAT). Можно расширить только тома с NTFS/ReFS;
3.	Нельзя создать разделы более 2 Тб на дисках с таблицей разделов MBR. На дисках размером более 2 Тб нужно использовать таблицу разделов GPT (можно сконвертировать MBR в GPT без потери данных). Тип таблицы разделов можно посмотреть на вкладке Volumes диска в диспетчере устройств. В этом примере на моей ВМ Windows 10 установлена в режиме EFI (GPT разметка на диске).
Команды DISM и SFC
sfc /scannow , DISM /Online /Cleanup-Image /RestoreHealth
оманда sfc /scannow позволяет проверить целостность системных файлов Windows. Если какие-то системные файлы отсутствуют или повреждены, утилита SFC попробует восстановить их оригинальные копии из хранилища системных компонентов Windows (каталог C:\Windows\WinSxS).
findstr /c:"[SR]" %windir%\Logs\CBS\CBS.log >"%userprofile%\Desktop\sfc.txt"
DISM /Online /Cleanup-Image /ScanHealth
•	No component store corruption detected – DISM не обнаружил повреждения в хранилище компонентов;
•	The component store is repairable – DISM обнаружил ошибки в хранилище компонентов и может исправить их;
•	The component store is not repairable – DISM не может исправить хранилище компонентов Windows (попробуйте использовать более новую версию DISM
C:\Windows\Logs\DISM\dism.log .
Dism /image:C:\ /Cleanup-Image /RestoreHealth /Source:WIM:D:\sources\install.wim:6
Не удалось запустить или подключиться к службе виртуальных дисков
то нужно проверить состояние системной службы Virtual Disk (vds) / Виртуальный диск. Открыв консоль управления службами
Как включить или отключить сжатую память в Windows
ункция сжатия оперативной памяти в Windows 10 и 11 используется для оптимизации использования RAM за счет хранения части страниц в оперативной памяти в сжатом виде (компрессия). Благодаря использованию сжатия памяти процессов вы можете размещать больше процессов в физической оперативной памяти без складывания их в своп файла на диске. Нужные данные извлекаются из более быстрой оперативной памяти быстрее, даже с учетом того, что на их сжатие/декомпрессию тратятся дополнительные ресурсы процессора. При использовании сжатия памяти уменьшается использование RAM, снижается нагрузка на жесткий диск за счет меньшего количества операций ввода/вывода к файлу подкачки и сохраняется ресурс SSD.
Процесс «Система и сжатая память» сильно грузит компьютер
•	Отключите файл подкачки системы (опция Без файла подкачки), перезагрузите компьютер, включите файл подкачки (опция Автоматически выбирать размер файла подкачки) и еще раз перезагрузитесь.
•	Если проблема высокой загрузки процессом «Сжатая память» возникает только при выходе из режима сна или гибернации (а после перезагрузки пропадает), попробуйте скачать и установить с сайта производителя последние версии драйверов для ваших дисковых контроллеров (ACPI/AHCI/RAI SCSI), дисков и видеокарты. После чего желательно отключить автоматическое обновление драйверов.
Не работает кнопка подпись в Outlook
Windows Registry Editor Version 5.00
[HKEY_CLASSES_ROOT\Outlook.Application]
@="Microsoft Outlook 16.0 Object Library"
[HKEY_CLASSES_ROOT\Outlook.Application\CLSID]
@="{0006F03A-0000-0000-C000-000000000046}"
[HKEY_CLASSES_ROOT\Outlook.Application\CurVer]
@="Outlook.Application.16"
[HKEY_CLASSES_ROOT\Outlook.Application.16]
@="Microsoft Outlook 16.0 Object Library"
[HKEY_CLASSES_ROOT\Outlook.Application.16\CLSID]
@="{0006F03A-0000-0000-C000-000000000046}"
[HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{0006F03A-0000-0000-C000-000000000046}]
[HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{0006F03A-0000-0000-C000-000000000046}\InprocServer32]
"Assembly"="Microsoft.Office.Interop.Outlook, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71E9BCE111E9429C"
"Class"="Microsoft.Office.Interop.Outlook.ApplicationClass"
"RuntimeVersion"="v2.0.50727"
[HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{0006F03A-0000-0000-C000-000000000046}\InprocServer32\16.0.0.0]
"Assembly"="Microsoft.Office.Interop.Outlook, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71E9BCE111E9429C"
"Class"="Microsoft.Office.Interop.Outlook.ApplicationClass"
"RuntimeVersion"="v2.0.50727"
[HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{0006F03A-0000-0000-C000-000000000046}\LocalServer32]
@="C:\\Program Files\\Microsoft Office\\Office16\\OUTLOOK.EXE"
[HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{0006F03A-0000-0000-C000-000000000046}\ProgID]
@="Outlook.Application.16"
[HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{0006F03A-0000-0000-C000-000000000046}\Typelib]
@="{00062FFF-0000-0000-C000-000000000046}"
Добавление подписи Outlook через файлы профиля и реестр
 %APPDATA%\Microsoft\Signatures
Remove-ItemProperty -Path HKCU:\Software\Microsoft\Office\16.0\Outlook\Setup -Name First-Run -Force -ErrorAction SilentlyContinue -Verbose
New-ItemProperty HKCU:'\Software\Microsoft\Office\16.0\Common\MailSettings' -Name 'ReplySignature' -Value $my_manual_sign -PropertyType 'String' -Force
New-ItemProperty HKCU:'\Software\Microsoft\Office\16.0\Common\MailSettings' -Name 'NewSignature' -Value my_manual_sign -PropertyType 'String' –Force
Высокая загрузка CPU процессом System (Ntoskrnl.exe)
Ситуация, когда процесс System потребляет более половины процессорных ресурсов системы — это не нормально. Сам по себе файл Ntoskrnl.exe представляет собой исполняемый файл ядра ОС. Это базовый процесс системы. В рамках ядра ОС выполняется запуск системных драйверов устройств, которые скорее всего и являются источником проблемы (далеко не все драйверы соответствующим образом тестируются разработчиками оборудования).
Также, чтобы выявить драйвер, который вызывает высокую загрузку CPU, можно воспользоваться бесплатной утилитой Microsoft — kernrate.exe (Kernrate Viewer). Утилита входит в состав WDK (Windows Device Kit). После установки WDK, найти утилиту можно в каталоге …\Tools\Other\amd64.
Запустите утилиту kernrate.exe без аргументов и подождите некоторое время, пока идет сбор данных (10-15 минут), после чего прервите работу утилиты сочетанием клавиш Ctrl-C: Посмотрите на список модулей в секции Result for Kernel Mode.
Кроме того, проанализировать использование CPU при загрузки системы можно с помощью Windows Performance Toolkit (WPT). Нужно установить компонент и запустить сбор данных с помощью графической консоли Windows Perfomance Recorder (First level triangle + CPU usage -> Start)
Либо так:
xperf -on latency -stackwalk profile -buffersize 1024 -MaxFile 256 -FileMode Circular && timeout -1 && xperf -d cpuusage.etl
***
Управление NTFS разрешениями
$path = "c:\drivers"
$user = "WORKSTAT1\user1"
$Rights = "Read, ReadAndExecute, ListDirectory"
$InheritSettings = "Containerinherit, ObjectInherit"
$PropogationSettings = "None"
$RuleType = "Allow"
$acl = Get-Acl $path
$perm = $user, $Rights, $InheritSettings, $PropogationSettings, $RuleType
$rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $perm
$acl.SetAccessRule($rule)
$acl | Set-Acl -Path $path
Outlook не отображает картинки в теле письма
Outlook может не показывать изображения в письмах, если переполнена или повреждена папка Temporary Internet Files. В этом случае проще всего ее пересоздать.
Войдите на компьютер под другим аккаунтом с правами администратора, найдите и удалите каталог проблемного пользователя C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache (в Windows 10) 
Вы можете включить автоматическую загрузку картинок в Outlook (не безопасно!!!): Файл -> Параметры -> Центр управления безопасностью -> Параметры центра управления безопасностью -> Автоматическое скачивание -> снимите галку “Не скачивать автоматически рисунки в сообщениях HTML и элементах RSS” (File -> Options -> Trust Center -> Trust Center Settings -> Don’t download pictures automatically in HTML e-mail messages or RSS items”).
Команды DISM и SFC:
sfc /scannow , DISM /Online /Cleanup-Image /RestoreHealth
Перед тем, как восстанавливать образ Windows с помощью DISM, рекомендуется сначала попробовать проверить целостность системных файлов с помощью утилиты SFC (System File Checker). Команда sfc /scannow позволяет проверить целостность системных файлов Windows. Если какие-то системные файлы отсутствуют или повреждены, утилита SFC попробует восстановить их оригинальные копии из хранилища системных компонентов Windows (каталог C:\Windows\WinSxS).
Утилита SFC записывает все свои действия в лог-файл windir%\logs\cbs\cbs.log . Для всех записей, оставленных SFC в файле CBS.log проставлен тег [SR]. Чтобы выбрать из лога только записи, относящиеся к SFC, выполните команду:
findstr /c:"[SR]" %windir%\Logs\CBS\CBS.log >"%userprofile%\Desktop\sfc.txt"
Чтобы проверить наличие признака повреждения хранилища компонентов в образе Windows (флаг CBS),
DISM /Online /Cleanup-Image /CheckHealth
Ошибка загрузки Linux на Hyper-V: The image’s hash and certificate are not allowed
Чтобы начать установку Linux мне пришлось отключить режим безопасной загрузки в настройках виртуальной машины (Settings -> Security -> Enable Secure Boot).
Или можно оставить Secure Boot включенным, но использовать шаблон «Microsoft UEFI Certificate Authority» вместо “Microsoft Windows”. По информации Microsoft данный шаблон позволяет запускать большинство дистрибутовов Linux в режиме совместимости с Secure Boot.
Set-VMFirmware -VMName "centos7" -EnableSecureBoot On -SecureBootTemplate "MicrosoftUEFICertificateAuthority"
Управление ролями и компонентами Windows Server
Get-WindowsFeature
Не работает поиск в Windows 10
поиск из панели задач
SearchUI.exe
SearchApp.exe и SerchIndexer.exe
поиск в стартовом меню
1.	Удалите следующий ключ реестра HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{ef87b4cb-f2ce-4785-8658-4ca6c63e38c6}\TopView\{00000000-0000-0000-0000-000000000000} . В 64 битной версии Windows 10 нужно удалить ключ реестра HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\ Explorer\FolderTypes\ {ef87b4cb-f2ce-4785-8658-4ca6c63e38c6}\TopViews\{00000000-0000-0000-0000-000000000000};
Windows 10 Creator Update (1703) и более новых версиях есть еще одна частая проблема, из-за которой может не работать поиск. В разделе Параметры -> Конфиденциальность -> Фоновые приложения (Settings -> Privacy -> Background apps), включите опцию «Разрешить приложениям работать в фоновом режиме» (Let apps run in the background). При отключении данной опции может не работает поиск среди только что установленных приложений.
REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 0 /f
REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Search /v BackgroundAppGlobalToggle /t REG_DWORD /d 1 /f
WSearch
 
Get-AppXPackage -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
полностью удалить и переустановить универсальное приложение Microsoft.Windows.Search ( Microsoft.Windows.Search_cw5n1h2txyewy ).
1.	Запустите консоль PowerShell.exe с правами администратора;
2.	Остановите службу Windows Search. Сначала нужно изменить тип запуска на Disabled, а потом остановить ее: Get-Service WSearch| Set-Service –startuptype disabled –passthru| Stop-Service –Force
3.	Перезагрузите Windows;
4.	Удалите универсальное приложениеSearch:
Get-AppxPackage -Name *Search* | Remove-AppxPackage -Verbose -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
Get-AppxPackage -AllUsers  -Name *Search* | Remove-AppxPackage -Verbose -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
5.	Теперь нужно удалить папку приложения %LOCALAPPDATA%\Packages\Microsoft.Windows.Search_cw5n1h2txyewy. Но для этого нужно сначала назначить локальную группу Administrators владельцем папки. Это можно сделать вручную в проводнике Windows (вкладка Безопасность в свойствах папки) или с помощью такого PowerShell скрипта:
$searchapp_path ="$env:localappdata\Packages\Microsoft.Windows.Search_cw5n1h2txyewy"
$Account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList 'BUILTIN\Administrators';
$ItemList = Get-ChildItem -Path %searchapp_path -Recurse;
foreach ($Item in $ItemList) {
$Acl = $null;
$Acl = Get-Acl -Path $Item.FullName;
$Acl.SetOwner($Account);
Set-Acl -Path $Item.FullName -AclObject $Acl;
}
6.	Теперь можно удалить папку Windows.Search_cw5n1h2txyewy:
Remove-Item -Path $env:localappdata\Packages\Microsoft.Windows.Search_cw5n1h2txyewy –force
 
7.	Сейчас поиск в Windows полностью отключен;
8.	Переустановите приложение Search App:
Get-AppxPackage -AllUsers -Name *Search* | % {Add-AppxPackage -Path ($_.InstallLocation + "\Appxmanifest.xml") -Register -DisableDevelopmentMode -ForceApplicationShutdown -Verbose}
 
9.	Включите автозапуск для службы WSearch:
Set-Service WSearch –startuptype automatic
10.	Перезагрузите Windows, войдите под своей учетной записью и проверьте, что поиск теперь работает.
Bing
REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Search /v BingSearchEnabled /t REG_DWORD /d 0 /f
REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Search /v CortanaConsent /t REG_DWORD /d 0 /f
1.	Скачайте скрипт ResetWindowsSearchBox.ps1 по ссылке;

Боремся с ростом файла Windows.edb
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\.
net stop "Windows Search"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows Search" /v SetupCompletedSuccessfully /t REG_DWORD /d 0 /f
del %PROGRAMDATA%\Microsoft\Search\Data\Applications\Windows\Windows.edb
net start "Windows Search"
Не работает поиск в Outlook
ля этого, перейдите на вкладку Поиск и в разделе Средства поиска выберите элемент Состояния индексирования.
Проверьте PST файлы на наличие ошибок
Outlook и режим кэширования Exchange
аще всего проблема в том, что закончилось место на дисках (недостаточно места для увеличения размера поискового индекса), либо текущий индексный файл был поврежден и нужно его перестроить. Для сброса поискового индекса в Exchange можно использовать встроенный PowerShell скрипт %PROGRAMFILES%\Microsoft\Exchange Server\V14\Scripts\ResetSearchIndex.ps1
Не работает поиск Outlook в общих ящиках Exchange

New-ItemProperty -path "HKCU:\Software\Microsoft\Office\16.0\Outlook\Search" -Name DisableServerAssistedSearch -PropertyType "DWORD" -Value "1"
Как найти и закрыть открытые файлы в сетевой папке
Get-SmbOpenFile|select ClientUserName,ClientComputerName,Path,SessionID
Get-SmbOpenFile | Where-Object {$_.Path -Like "*защита*"}
Close-SmbOpenFile - SessionId 3489847304
Компьютер неожиданно перезагрузился, или возникла непредвиденная ошибка
1.	HKEY_LOCAL_MACHINE\SYSTEM\Setup\Status\ChildCompletion;
2.	В правой панели нужно найти параметр setup.exe. Скорее всего он равен 1. Измените его значение на 3 
chkdsk W: /F /R
***
Установка контроллера домена AD на Windows Server Core
Rename-Computer -NewName spb-dc03
Get-NetAdapter
$ip = "192.168.113.11"
$gw="192.168.113.1"
$dns = "192.168.13.11"
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress $ip -AddressFamily IPv4 -PrefixLength 24 –DefaultGateway $gw
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $dns
Install-WindowsFeature AD-Domain-Services –IncludeManagementTools -Verbose
Install-ADDSDomainController -DomainName test.com -InstallDns:$true -NoGlobalCatalog:$false -SiteName 'SPB' -NoRebootOnCompletion:$true -Force:$true -SafeModeAdministratorPassword (ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force) -Credential (get-credential TEST\Administrator) –verbose

Get-ADDomainController -Discover
Get-Service adws,kdc,netlogon,dns
get-smbshare
Get-ADReplicationFailure -Target DC03
Как узнать, кто сбросил пароль пользователя
(Get-ADComputer -SearchBase ‘OU=Domain Controllers,DC=winitpro,DC=loc’ -Filter *).Name | foreach {
Get-WinEvent -ComputerName $_ -FilterHashtable @{LogName="Security";ID=4724 }| Foreach {
$event = [xml]$_.ToXml()
if($event)
{
$Time = Get-Date $_.TimeCreated -UFormat "%Y-%m-%d %H:%M:%S"
$AdmUser = $event.Event.EventData.Data[4]."#text"
$User = $event.Event.EventData.Data[0]."#text"
$dc = $event.Event.System.computer
write-host “Admin ” $AdmUser “ reset password to ” $User “ on ” $dc “ “ $Time
}
}
}
Удаление зависших писем в папке Исходящие
Самый простой и быстрый способ избавиться от зависшего письма – попробовать закрыть и заново запустить клиент Outlook. После перезапуска, попробуйте выбрать зависшее письмо и попытайтесь удалить его (ПКМ – Удалить, или кнопкой Del) или переместить в папку Черновики.
Проверьте, не превышен ли максимальный допустимый размер письма (с учетом вложений), который может отправить ваш почтовый сервер (настройка максимального размера отправляемого сообщения в Exchange 2010) . В том случае, если этот лимит превышен, придется удалить письмо из очереди, либо изменить его размер, удалив или разбив вложения на части.
Попробуйте переключить Outlook в офлайн режим, нажав на вкладке Send/Receive кнопку Work Offline. Закройте Outlook и с помощью диспетчера задач убедитесь, что процесс outlook.exe в системе не запущен.
Запустите Outlook, найдите зависшее письмо и попробуйте его переместить/удалить. После этого отключите офлайн режим и нажмите кнопку Send/Receive для обновления папок.
Временный PST файл и пересоздание папки Исходящие
Существует возможность низкоуровневой работы с почтовым ящиком через MAPI. Для целей отладки MAPI почтовых ящиков можно использовать ряд утилит. На мой взгляд, самой удобной является MFCMAPI
Аудит удаления файлов в сетевой папке
$Path = "D:\Public"
$AuditChangesRules = New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone', 'Delete,DeleteSubdirectoriesAndFiles', 'none', 'none', 'Success')
$Acl = Get-Acl -Path $Path
$Acl.AddAuditRule($AuditChangesRules)
Set-Acl -Path $Path -AclObject $Acl

today = get-date -DisplayHint date -UFormat %Y-%m-%d
Get-WinEvent -FilterHashTable @{LogName="Security";starttime="$today";id=4663} | Foreach {
$event = [xml]$_.ToXml()
if($event)
{
$Time = Get-Date $_.TimeCreated -UFormat "%Y-%m-%d %H:%M:%S"
$File = $event.Event.EventData.Data[6]."#text"
$User = $event.Event.EventData.Data[1]."#text"
$Computer = $event.Event.System.computer
}
}
Управление отключенными ящиками в Exchange
Get-MailboxDatabase | Get-MailboxStatistics | Where { $_.DisconnectReason -eq "Disabled" } | ft DisplayName,Database,DisconnectDate,MailboxGUID
Get-MailboxDatabase | Get-MailboxStatistics | Where { $_.DisconnectReason -eq "SoftDeleted" } | ft DisplayName,Database,DisconnectDate,MailboxGUID
Connect-Mailbox -Identity "AAndreev" -Database Msk-DB1  -User AAndreev
Создание и управление заданиями планировщика
$TaskName = "NewPsTask"
$TaskDescription = "Запуск скрипта PowerShell из планировщика"
$TaskCommand = "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe"
$TaskScript = "C:\PS\StartupScript.ps1"
$TaskArg = "-WindowStyle Hidden -NonInteractive -Executionpolicy unrestricted -file $TaskScript"
$TaskStartTime = [datetime]::Now.AddMinutes(1)
$service = new-object -ComObject("Schedule.Service")
$service.Connect()
$rootFolder = $service.GetFolder("\")
$TaskDefinition = $service.NewTask(0)
$TaskDefinition.RegistrationInfo.Description = "$TaskDescription"
$TaskDefinition.Settings.Enabled = $true
$TaskDefinition.Settings.AllowDemandStart = $true
$triggers = $TaskDefinition.Triggers
#http://msdn.microsoft.com/en-us/library/windows/desktop/aa383915(v=vs.85).aspx
$trigger = $triggers.Create(8)

Register-ScheduledTask -Xml (Get-Content “\\Server1\public\NewPsTask.xml” | out-string) -TaskName "NewPsTask"
Outlook 2013/2016 зависает/не отвечает при запуске и получении писем
В том случае, если в безопасном режиме проблем не наблюдается – рекомендуется по-очереди отключить дополнительные модули (Параметры -> Надстройки ->Управление Надстройка COM -> Перейти).
В Office 2013 появился функционал аппаратного ускорения (Hardware graphics acceleration), который по идее должен улучшать визуальный вид, отзывчивость, плавность и реактивировать масштабирования приложений Office. По умолчанию в Office 2013 / 2016 режим аппаратного ускорения включен, но зачастую он вызывать обратный эффект – периодическое зависание приложений Office (в том числе Outlook) при отрисовке их окошек с содержимым. Как правило, такие проблемы наблюдаются на компьютерах со старыми или интегрированными видеокартами, когда на компьютере установлено 2 и более GPU, или используются устаревшие видеодрайверы.
Отключить аппаратное ускорение обработки изображений можно через реестре. Достаточно создать Dword параметр DisableHardwareAcceleration со значением 1 в ветке:
•	Для Office 2013 — HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Common\Graphics
•	Для Office 2016 — HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Common\Graphic
Проверьте размеры pst и ost файлов на компьютере. В том случае, если размеры этих файлов превышает 10-20 Гб, могут наблюдаться проблемы с производительностью Outlook. Не рекомендуется превышать эти значения.
Ищем причину медленной загрузки Windows с помощью Process Monitor
1.	Скачайте и распакуйте архив с Process Monitor (http://download.sysinternals.com/files/ProcessMonitor.zip);
2.	Запустите procmon.exeс правами администратора;
3.	В меню Options выберите пункт Enable Boot Logging;
Выберите опцию Generate thread profiling events -> Every second. В этом режиме драйвер procmon будет записывать состояние всех процессов каждую секунду.
Сохраните изменения. ProcMon скопирует драйвер procmon23.sys в каталог %SystemRoot%\System32\Drivers и создаст отдельную службу (в ветке HKLM\SYSTEM\CurrentControlSet\Services). Эта служба будет запускаться после запуска Winload.exe и будет записывать в лог активность всех процесс, которые выполняются при загрузке Windows и входе пользователя;
Чтобы отключить режим протоколирования загрузки, выполните команду: procmon.exe /noconnect
1.	Перезагрузите компьютер и дождитесь появления рабочего стола;
2.	Драйвер procmon23.sys будет писать лог событий до тех пор, пока пользователь вручную не запустит утилиту Process Monitor. После этого режим протоколирования загрузки отключается;
3.	В окне Process Monitor соглашаемся с предложение сохранить собранные данные в файл bootlog.pml.
Также для анализа процесса загрузки можно воспользоваться функцией в меню Tools -> Process Tree, позволяющей отобразить все процессы в виде графического дерева с информацией о начале, завершении и длительности процесса;
С помощью Network Summary можно отследить медленные сетевые обращения и процессы, которые загружают/отправляют по сети большие порции данных при загрузке Windows. Например, на скриншоте видно, что при запуске компьютеру пришлось получить около 0.5 Мб данных с контроллера домена.
Проверка статуса сообщений (прочитано\не прочитано) в Exchange
Get-OrganizationConfig | Select ReadTrackingEnabled
Get-MessageTrackingLog -Sender email_name@companyname -MessageSubject "тема письма" -Start (Get-Date).AddHours(-48) -EventId RECEIVE | Select MessageID
Сам скрипт Get-MessageReadStatusReport.ps1:
[CmdletBinding()]
param (
[Parameter( Mandatory=$true)]
[string]$Mailbox,
[Parameter( Mandatory=$true)]
[string]$MessageId
)
$output = @()
#Проверяем журналирование
if (!(Get-OrganizationConfig).ReadTrackingEnabled) {
throw "Трекинг статуса письма выключен"
}
#Берем ID письма
$msg = Search-MessageTrackingReport -Identity $Mailbox -BypassDelegateChecking -MessageId $MessageId
#Должно быть одно письмо
if ($msg.count -ne 1) {
throw "$($msg).count писем найдено по этому ID"
}
#Получаем отчет
$report = Get-MessageTrackingReport -Identity $msg.MessageTrackingReportId -BypassDelegateChecking
#Получаем события
$recipienttrackingevents = @($report | Select -ExpandProperty RecipientTrackingEvents)
#Генерируем список получателей$recipients = $recipienttrackingevents | select recipientaddress
#Получаем статус письма для каждого получателя
foreach ($recipient in $recipients) {
$events = Get-MessageTrackingReport -Identity $msg.MessageTrackingReportId -BypassDelegateChecking `
-RecipientPathFilter $recipient.RecipientAddress -ReportTemplate RecipientPath
$outputline = $events.RecipientTrackingEvents[-1] | Select RecipientAddress,Status,EventDescription
$output += $outputline
}
$output
$directory = "C:\log\RSR"
$filename = 'ReadStatusReport'
$file = "$filename.csv"
#Выводим отчет в csv
$output | Export-Csv -NoTypeInformation -Append -Path "$directory\$file"
Недостаточно памяти на компьютере с Windows 10
1.	Слишком большое количество запущенных программ или процессов
2.	Недостаточно оперативной памяти (RAM) на компьютере для нормальной работы
3.	Неправильная настройка файла подкачки (или полное его отключение)
4.	Закончилось место на системном диске, из-за чего динамический файл подкачки не может увеличиваться
5.	Утечка памяти в одной из программ
6.	Как вы, вероятно, знаете, файл подкачки является продолжением оперативной памяти компьютера и представляет собой скрытый файл pagefile.sys на системном диске, в который Windows сбрасывает данные неиспользуемых (но запущенных) программ из оперативной памяти.
7.	По-умолчанию размером файла подкачки в Windows 10 управляет система (и это нормально). Есть рекомендации MSFT (упрощенные), что в современных Windows рекомендует задавать начальный (минимальный) размер файла подкачки равный количеству физической памяти (RAM), установленной на компьютере. При этом максимальный размер файла подкачки ограничивается трехкратным объемом физической RAM. 
Перерегистрация компонентов VSS (Volume Shadow Copy Service) в Windows Server
VSS Writer	Имя службы 	Полное имя службы
ASR Writer	VSS	Volume Shadow Copy
BITS Writer	BITS	Background Intelligent Transfer Service
Certificate Authority	CertSvc	Active Directory Certificate Services
COM+ REGDB Writer	VSS	Volume Shadow Copy
DFS Replication service writer	DFSR	DFS Replication
DHCP Jet Writer	DHCPServer	DHCP Server
FRS Writer	NtFrs	File Replication
FSRM writer	srmsvc	File Server Resource Manager
IIS Config Writer	AppHostSvc	Application Host Helper Service
IIS Metabase Writer	IISADMIN	IIS Admin Service
Microsoft Exchange Replica Writer	MSExchangeRepl	Microsoft Exchange Replication Service
Microsoft Exchange Writer	MSExchangeIS	Microsoft Exchange Information Store
Microsoft Hyper-V VSS Writer	vmms	Hyper-V Virtual Machine Management
MSMQ Writer (MSMQ)	MSMQ	Message Queuing
MSSearch Service Writer	WSearch	Windows Search
NPS VSS Writer	EventSystem	COM+ Event System
NTDS	NTDS	Active Directory Domain Services
OSearch VSS Writer	OSearch	Office SharePoint Server Search
OSearch14 VSS Writer	OSearch14	SharePoint Server Search 14
Registry Writer	VSS	Volume Shadow Copy
Shadow Copy Optimization Writer	VSS	Volume Shadow Copy
SMS Writer	SMS_SITE_VSS_WRITER	SMS_SITE_VSS_WRITER
SPSearch VSS Writer	SPSearch	Windows SharePoint Services Search
SPSearch4 VSS Writer	SPSearch4	SharePoint Foundation Search V4
SqlServerWriter	SQLWriter	SQL Server VSS Writer
System Writer	CryptSvc	Cryptographic Services
TermServLicensing	TermServLicensing	Remote Desktop Licensing
WDS VSS Writer	WDSServer	Windows Deployment Services Server
WIDWriter	WIDWriter	Windows Internal Database VSS Writer
WINS Jet Writer	WINS	Windows Internet Name Service (WINS)
WMI Writer	Winmgmt	Windows Management Instrumentation
vssadmin list writers
Net Stop VSS
Net Stop SWPRV
regsvr32 /s ole32.dll
regsvr32 /s oleaut32.dll
regsvr32 /s vss_ps.dll
vssvc /register
regsvr32 /s /i swprv.dll
regsvr32 /s /i eventcls.dll
regsvr32 /s es.dll
regsvr32 /s stdprov.dll
regsvr32 /s vssui.dll
regsvr32 /s msxml.dll
regsvr32 /s msxml3.dll
regsvr32 /s msxml4.dll
vssvc /registerNet Start SWPRV
Net Start VSS
Определить на каком контроллере домена (Logon Server) вы аутентифицировались
systeminfo | find /i “logon server”
get-service netlogon
1.	При загрузке Windows служба NetLogon делает DNS запрос за списком контроллеров домена (SVR записи _ldap._tcp.dc._msdcs.domain_ ;
2.	DNS возвращает список DC в домене;
3.	Клиент делает LDAP запрос к DC для определения сайта AD по-своему IP адресу;
4.	DC возвращает сайт, которому соответствует IP клиента или наиболее близкий сайт (эта информация кэшируется в ветке реестра HKLM\System\CurrentControlSet\Services\Netlogon\Parameters и используется при следующем входе для более быстрого поиска);
5.	Windows пытается связаться со всеми DC в сайте и первый ответивший используется для выполнении аутентификации и в качестве LogonServer.
Аудит действий пользователей в почтовых ящиках Exchange
Set-Mailbox kbuldogov -AuditEnabled $false
В Exchange есть несколько уровней аудита в ящике:
•	AuditOwner – аудит действия владельца ящика
•	AuditAdmin – аудит действий администратора
•	AuditDelegate – аудит действия сторонних пользователей, которым предоставлен доступ к почтовому ящику
В журнал аудита можно записывать следующие события:
•	Copy
•	Create
•	FolderBind
•	HardDelete
•	MailboxLogin
•	MessageBind
•	Move
•	MoveToDeletedItems
•	SendAs
•	SendOnBehalf
•	SoftDelete
•	Update
•	UpdateCalendarDelegation
•	UpdateFolderPermissions
Search-MailboxAuditLog -Identity AlinaV@winitpro.onmicrosoft.com -StartDate 9/5/2021 -ShowDetails| ft MailboxOwnerUPN, LogonType, LogonUserDisplayName, Operation,OperationResult, SourceItemSubjectsList,FolderPathName, DestFolderPathName,LastAccessed|ft
Решение проблемы со службой CDPUserSvc
%WinDir%\System32\CDPSvc.dll
Официальной информации о данной службе от Microsoft мне найти не удалось. Если произвести анализ соединений службы CDPUserSvc, можно обнаружить, что данная служба периодически подключается к серверам Microsoft и OneDrive и отправляет какие-то данные по HTTPS. Посмотрим, как выглядит процессы, запускаемые в группе UnistackSvcGroup. Для этого в Process Explorer откроем свойства процесса svchost.exe и посмотрим его свойства.
В рамках этого процесса запущены пять служб (обратите внимание, что все они в имени содержат одинаковый с CDPUserSvc пятизначный идентификатор:
•	CDPUserSvc_6b511 – наш клиент
•	OneSyncSvc_6b511 — отвечает за синхронизацию почты, контактов, календаря и других данных пользователя
•	PimIndexMaintenanceSvc_6b511 – служба индексации контактов для быстрого поиска
•	UnistoreSvc_6b511 – хранит структурированные данные пользователя (контакты, календаря, почту)
•	UserDataSvc_6b511 – обеспечивает доступ к структурированным данным пользователя
•	Еще одним решением, которое должно исправить проблему постоянного падения службы CDPUserSvc_xxxxx, является ее запуск в изолированным режиме. Для этого в командной строке с правами администратора, выполните команду:
•	sc config cdpusersvc type= own
sc config CDPUserSvc start= disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc /v "Start" /t REG_DWORD /d "4" /f
