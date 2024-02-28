Замирает/отключается RDP сессия при использовании UDP
``` powershell
reg add "HKLM\software\policies\microsoft\windows nt\Terminal Services\Client" /v fClientDisableUDP /d 1 /t REG_DWORD
```
*************
Смена истекшего пароля через Remote Desktop Web Access

В Windows Server 2012 R2 и выше по умолчанию включен механизм аутентификации на уровне сети NLA (Network Level Authentication, подробнее о нем здесь). Особенность этого метода аутентификации в том, что при включенном NLA пользователи с истекшим сроком действия пароля (или у которых в атрибуте пользователя useraccountcontrolвключена опция смены пароля при первом входе) не смогут подключиться к RDP/RDS хосту.
 [Server Name] –> Sites –> Default Web Site –> RDWeb –> Pages и откройте настройки приложения (Application Settings).
параметр с именем PasswordChangeEnabled и измените его значение на true
IISRESET
Вы можете использовать этот способ смены пароля на Remote Desktop Web Access только если на RDWA сервере включена аутентификация Forms Authentication. При использовании метода Window Authentication, смена пароля через форму RD Web невозможна
C:\Windows\Web\RDWeb\Pages\en-US\login.aspx;
Перейдите на 429 строку (В Windows Server 2022 она находится после html блока 
``` html
<tr id="trPasswordExpiredNoChange" <%=strErrorMessageRowStyle%> > ……..… </tr> )
```
 и добавьте следующий код:
 ``` html
<!-- Start Add Link to Change Password -->
<tr>
<td align="right"> <a href="password.aspx" title="Change User Password">Click here </a>to change your password.
</td>
</tr>
<!-- End Add Link to Change Password -->
```
*************
Ошибка RDP подключения: CredSSP encryption oracle remediation
•	Вы подключаетесь к удаленному рабочему столу компьютера с недавно установленной старой (например, RTM) версией Windows (например, Windows 10 ниже билда 1803, Windows Server 2012 R2, Windows Server 2016), на котором не установлены последние обновления безопасности Windows;
•	Вы пытаетесь подключиться к RDP компьютеру, на который давно не устанавливали обновления Microsoft;
•	RDP подключение блокирует удаленный компьютер, т.к. нет нужных обновлений безопасности на вашем клиентском компьютере.
``` powershell
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters /v AllowEncryptionOracle /t REG_DWORD /d 2
```
*************
Пропадает языковая панель в RDP сеансе после завершения теневой сессии
$1 = New-WinUserLanguageList en-US
$1.Add("ru-RU")
Set-WinUserLanguageList $1 -force

Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layout]
"IgnoreRemoteKeyboardLayout"=dword:00000001
*************
Настройка лимитов (таймаутов) для активных/отключенных RDP/RDS сессий в Windows
$connectionBrocker = “MSK-RDSMAN.WINITPRO.RU"
Get-RDUserSession -ConnectionBroker $connectionBrocker |select-object -Property CollectionName, HostServer, DomainName, UserName, ServerIPAddress, CreateTime, DisconnectTime,  SessionState, IdleTime , SessionID , @{Name='SessionAge ([days.]hours:minutes)';Expression={ ((get-date ) - $_.CreateTime) } }
*************
Произошла внутренняя ошибка при RDP подключении
1.	Если у вас на удаленном сервере установлен КриптоПРО, он может быть источником проблем с rdp подключением. Попробуйте отключить проверку контрольных целостности файлов (проверки контрольных сумм) в КриптоПро через реестр. Перейдите в ветку реестра HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\CProIntegrity и измените значение параметра CheckMode на 0. Перезагрузите сервер.
2.	Если в журнале событий TerminalServices-RemoteConnectionManager вы встретите событие с EventID 1057 (The RD Session Host Server has failed to create a new self signed certificate to be used for RD Session Host Server authentication on SSL connections), перейдите в каталог C:\ProgramData\Microsoft\Crypto\RSA , переименуйте папку Machinekeys в Machinekeys_bak и перезапустите службу TermService.
3.	Также нашел информацию, что RDP проблема “Произошла внутренняя ошибка” встречалась в Windows 10 1809, если на удаленном компьютере включена политика Configure H.264/AVC hardware encoding for Remote Desktop connections (находится в секции GPO: Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Remote Session Environment). Для решения этой проблемы достаточно отключить UDP протокол для RDP, создав в ветке реестра HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client параметр fClientDisableUDP со значением 1.
4.	В комментариях Ivan оставил очень полезный фикс.
Проблема с ошибкой RDP может быть в наличии некоего счетчика учитывающего максимальное количество подключений в Windows.
В десктопных версиях Windows — 100, в Windows Server -3000. Для сброса счетчика достаточно перезагрузить компьютер, или просто увеличить лимит через реестр:
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v MaxOutstandingConnections /t REG_DWORD /d 65536
5.	Я очистил историю RDP подключений в ветке HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers и сбросил кэш RDP в каталоге C:\Users\%Username%\AppData\Local\Microsoft\Terminal Server Client\Cache (перед удалением закройте все запущенные сеансы mstsc.exe):
6.	del "C:\Users\%Username%\AppData\Local\Microsoft\Terminal Server Client\cache"
Ошибка RDP: службы удаленных рабочих столов сейчас заняты
Ошибка RDP подключения может возникать по разным причинам:
•	Ошибка в работе службы удаленных рабочих столов;
•	Баг с процессом csrss.exe;
•	Проблема с профилем пользователя или со службой profsvc;
•	Нехватка оперативной памяти или свободного места на диске RDSH сервера;
•	Некорректные настройки групповых политик.
Проверьте свободные ресурсы RDS сервера
Сброс RDS сессии пользователя и завершение зависших процессов
Возможно у пользователя, которые не может зайти на RDS сервер осталась активная сессия или процесс. Попробуйте принудительно сбросить сессию и процессы такого пользователя. Найдите нужного пользователя на вкладке Users в диспетчере задач, щелкните по нему правой кнопкой и выберите “Log off”. В большинстве случаев, этого достаточно. Но иногда в диспетчере задач отображается множество зависших сессий с именем “(4)” вместо имени пользователя. Как правило в такой зависшей RDS сессии будет присутствовать 4 процесса:
•	Client Server Runtime Process (csrss.exe)
•	Desktop Windows Manager (dwm.exe)
•	Windows Logon Application (winlogon.exe)
•	Windows Logon User Interface
•	Перезагрузите службу RDS. В командной строке с правами администратора наберите net stop termserviceи net start termservice . Либо перезапустите службу удаленно с помощью PowerShell: Get-Servicetermservice –ComputerName msk-rds1 | Restart-Service
•	Принудительно убейте процессы tstheme.exe;
•	Рекомендуется применить все последние обновления для вашей версии Windows, воспользуйтесь стандартными средствами обновления;
•	В Windows Server 2012 R2 в Event Viewer может появится событие Event ID 20499 “Remote Desktop Services has taken too long to load the user configuration from server..”. Для исправления проблемы добавьте в реестр параметр fQueryUserConfigFromLocalMachine:
REG ADD "HKLM\SYSTEM\CurrentControlSet\control\Terminal Server\Winstations\RDP-Tcp" /v fQueryUserConfigFromLocalMachine /t REG_DWORD /d 1 /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fQueryUserConfigFromLocalMachine /t REG_DWORD /d 1 /f  
•	Если на Windows хосте установлен Citrix и на Server VDA много сессий со статусом disconnected, попробуйте создать параметр реестра SeTokenDoesNotTrackSessionObject:
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v SeTokenDoesNotTrackSessionObject /t REG_DWORD /d 1 /f
•	Проверьте логи службы профилей пользователей ( profsvc ). Если вы используете профили User Profile Disksили FSLogix на Windows Server, проверьте что файловый сервер с профилями доступен и не имеет проблем с производительностью. Также при использовании UPD на Windows Server 2019/2016 нужно создать параметр реестра DeleteUserAppContainersOnLogoff, который исправить проблемы со множеством правил Windows Defender Firewall, которые генерируются для UWP приложений Windows Store при каждом входе пользователя.
*************
Черный экран вместо рабочего стола в RDP сессии
В RDP сессии нажмите сочетание клавиш CTRL+ALT+END (в том числе позволяет сменить пароль в RDP сеансе), а затем нажмите кнопку Отмена. Иногда это позволяет вернуться к рабочему столу RDP сессии. Если это не помогло, запустите из этого экрана диспетчер задач Task Manager и запустите процесс File Explorer (File -> Run new task ->explorer.exe -> Ok);
Проверьте, что в настройках RDP клиента ( mstsc.exe ) отключено кэширование (отключите опцию Persistent bitmap caching на вкладке Experience) и используется разрешение экрана, которое поддерживается удаленным хостом (на вкладке Display выставите меньшее разрешение экрана, или попробуйте режим Full Screen);
Убедитесь, что на вашем и на удаленном компьютере установлены последние версии видеодрайверов. Попробуйте воспользоваться автоматическим обновлением драйверов (если этот режим у вас не отключен), или скачайте и установите драйвер вручную).
В Windows Server 2016 с настроенными таймаутами для RDS сессий пару раз сталкивался с жалобами пользователей, что после подключения в отключенную (disconnected) сессию, она не активировалась корректно и они видели черный экран. Здесь поможет только завершение RDP сеанса пользователем самостоятельно (CTRL+ALT+End -> Sign out), либо принудительное завершение сессии администратором
Отключите использование протокола UDP 3389 для передачи RDP трафика в дополнение к стандартному RDP порту TCP 3389 (доступно, начиная с Windows Server 2012 R2/Windows 8.1) через параметр Turn off UDP on client на клиенте (Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Connection Client) или через реестр: reg add “HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client” /v “fClientDisableUDP” /t REG_DWORD /d 1 /f . 
Если проблема с черным экраном в RDP встречается на Windows Server 2019 и Windows 10 1809+. Откройте Event Viewer и проверьте журнал событий Application and Service Logs –> Microsoft –> Windows –> RemoteDesktopService-RdpCoreTS. Проверьте, есть ли там ошибки вида ‘ Failed GetConnectionProperty’ in CUMRDPConnection::QueryProperty at 2884 err=[0x80004001] ‘, ‘ Connection doesn’t support logon error redirector’ in CUMRDPConnection::GetLogonErrorRedirector at 4199 err=[0x80004001] . Если такие ошибки встречаются, нужно отключить использование протокола URCP (Universal Rate Control Protocol), который используется для передачи некоторых данных между RDP клиентом и сервером поверх UDP (MS-RDPEUDP2):
reg add “HKLM\SOFTWARE\Microsoft\Terminal Server Client” /v “UseURCP” /t REG_DWORD /d 0 /f
*************
Оценка трафика для RDP сессии пользователя на RDS сервере
 Performance Monitor (perfmon.exe) и добавьте счётчик RemoteFX Network/Total Sent Rate(*) 
*************
Плохая производительность (тормозит) RDS и RemoteAPP в Windows Server 2019/2016
New-ItemProperty -Path “HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy” -Type DWord -Path -Name DeleteUserAppContainersOnLogoff -Value 1
Многие пользователи стали жаловаться на проблемы с мышью в RDP сессии после миграции фермы RDS на Windows Server 2019. Мышь очень медленно реагирует на движения, курсор дрожит и зависает.
Если вы не можете уменьшить частоту опроса, попробуйте в настройках мыши в панели управления Windows ( main.cpl ) отключить тень курсора мыши (отключите опцию Enable pointer shadow) и выбрать схему None для указателя.
Также есть обходное решение, которое заключается в замене версии клиента RDP на более старую. Т.к. проблемы с производительностью Remoteapp встречались еще в Windows 10 1709, лучше всего использовать библиотеки RDP из 1607 или 1703.
Дело в том, что после апгрейда билда Windows 10 в системе устанавливается новая версия клиента RDP, которая на данный момент работает некорректно с опубликованными через RemoteApp приложениями.
Если заменить файлы mstsc.exe и mstscax.dll в каталоге C:\Windows\System32 на версии файлов из предыдущего билда Windows 10 (1703 или 1607), проблема с производительностью RemoteApp исчезает.
Как заменить файлы клиента RDP в Windows 10:
1.	Закройте все RDP подключения и запущенные RemoteApp (лучше даже перезагрузить компьютер);
2.	Скачайте архив с версиями файлов mstsc.exe и mstscax.dll из Windows 10 1607 (ссылка на скачивание с Я.Диска mstsc-w10-1607.zip);
3.	Скопируйте оригинальные файлы mstsc.exe и mstscax.dll из каталога C:\windows\system32\ в каталог C:\Backup с помощью команд:
md c:\backup\
copy C:\windows\system32\mstsc.exe c:\backup
copy C:\windows\system32\mstscax.dll c:\backup
4.	Затем нужно назначить свою учетную запись владельцем файлов mstsc.exe и mstscax.dll в каталоге C:\windows\system32\, отключите наследование и предоставьте себе права на изменение файлов: takeown /F C:\windows\system32\mstsc.exe
takeown /F C:\windows\system32\mstscax.dll
icacls C:\windows\system32\mstsc.exe /inheritance:d
icacls C:\windows\system32\mstscax.dll /inheritance:d
icacls C:\windows\system32\mstsc.exe /grant root:F
icacls C:\windows\system32\mstscax.dll /grant root:F
5.	Замените файлы в каталоге C:\windows\system32\ файлами из скачанного архива;
6.	Восстановите оригинальные разрешения на заменённых файлах. Включите наследование NTFS разрешений и установите владельцем файлов NT Service\TrustedInstaller:
icacls C:\windows\system32\mstsc.exe /inheritance:e
icacls C:\windows\system32\mstscax.dll /inheritance:e
icacls C:\windows\system32\mstsc.exe /setowner "NT Service\TrustedInstaller" /T /C
icacls C:\windows\system32\mstscax.dll /setowner "NT Service\TrustedInstaller" /T /C
7.	Осталось перерегистрировать библиотеку:
regsvr32 C:\Windows\System32\mstscax.dll
*************
Изменить номер RDP порта
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name PortNumber -Value 1350
New-NetFirewallRule -DisplayName "NewRDPPort-TCP-In" -Direction Inbound -LocalPort 1350 -Protocol TCP -Action allow 
New-NetFirewallRule -DisplayName "NewRDPPort-UDP-In" -Direction Inbound -LocalPort 1350 -Protocol UDP -Action allow
net stop termservice & net start termservice
*************
Easy Print
«TS Easy Print работает в качестве прокси для каждого действия печати, который просто перенаправляет все печатные задания на локальный компьютер пользователя без необходимости установки драйверов принтера на сервере терминалов. Эта система обеспечивает ряд преимуществ, таких как возможность перенаправить принтер на клиентскую машину пользователя без перенастройки сервера, а пользователь может прозрачно работать со своим принтером их терминальной сессии»
RDC/RDP client 6.1 и .NET Framework 3.0 SP1
*************
Не работает буфер обмена в RDP сессии
(Get-WmiObject -Query "select * from Win32_Process where name='RDPClip.exe'"|?{$_.GetOwner().User -eq $ENV:USERNAME}).Terminate()
rdpclip.exe
Права c:\windows\system32\rdpclip.exe
Коллекция Set-RDSessionCollectionConfiguration -CollectionName myCol1 -ClientDeviceRedirectionOptions “Clipboard,Drive”
Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' | Select fDisableClip,fDisableCdm
Запрет
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Terminal Server” /v “DisableClipboardRedirection" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Terminal Server” /v “DisableDriveRedirection" / t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableClip /t REG_DWORD /d 1 /f
ярлык 
redirectclipboard:i:1
redirectdrives:i:1
drivestoredirect:s:*
*************
Ошибка RDP: обнаружено различие во времени или текущей дате между этим компьютером и удаленным компьютером
net stop w32time & net start w32time & w32tm /resync
Test-ComputerSecureChannel -Repair -Credential corp\adminname
*************
Как включить и настроить удаленный рабочий стол
$compname = “WKMDK22SQ65”
(Get-WmiObject -Class Win32_TerminalServiceSetting -Namespace root\CIMV2\TerminalServices -Computer $compname -Authentication 6).SetAllowTSConnections(1,1)
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member 'a.petrov'
*************
RDS: Удаленный сеанс отключен, отсутствуют серверы лицензирования/клиентские лицензии
•	На хосте Remote Desktop Services не указан сервер RDS лицензирования, с которого нужно получить клиентские лицензии (RDS CAL);
•	На сервере RDS Licensing закончились доступные клиентские лицензии;
•	Клиент пытается подключиться с истекшей временной RDS лицензией;
RD Licensing Manager ( licmgr.exe 
$obj = gwmi -namespace "Root/CIMV2/TerminalServices" Win32_TerminalServiceSetting
$obj.GetSpecifiedLicenseServerList()
$obj = gwmi -namespace "Root/CIMV2/TerminalServices" Win32_TerminalServiceSetting
$obj.SetSpecifiedLicenseServerList("msk-rdslic.winitpro.ru")
**********
Удаление сервера из фермы Remote Desktop Services
Remove-RDSessionHost -SessionHost @("rdsh2.winitpro.ru") -ConnectionBroker rdcb.winitpro.ru –verbose

use RDCms;
delete from rds.RoleRdsh where ServerID = '3';
delete from rds.Server where Id = '3';

