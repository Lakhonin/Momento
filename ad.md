Re-using the account was blocked by security policy
В октябре была обновление kb5020276, которое запрещает повторное использование объекта computer в AD если вы не админ или не владелец объекта (Domain Join Hardening Changes CVE-2022-38042).
После установки патча пользователи не смогут добавить компьютер в домен с помощью существующего аккаунта компьютера.
На клиенте можно пока использовать обходное решение:
Reg add HKLM\System\CurrentControlSet\Control\Lsa /v NetJoinLegacyAccountReuse /t REG_DWORD /d 1 /f
*************
FSMO роли
1.	Хозяин схемы (Schema master) – отвечает за внесение изменение в схему Active Directory, например, при расширении с помощью команды adprep /forestprep (для управления ролью нужны права “Schema admins”);
2.	Хозяин именования домена (Domain naming master) – обеспечивает уникальность имен для всех создаваемых доменов и разделов приложений в лесу AD (для управления нужны права “Enterprise admins”);

1.	Эмулятор PDC (PDC emulator) – является основным обозревателем в сети Windows (Domain Master Browser – нужен для нормального отображения компьютеров в сетевом окружении); отслеживает блокировки пользователей при неправильно введенном пароле, является главным NTP сервером в домене, используется для совместимости с клиентами Windows 2000/NT, используется корневыми серверами DFS для обновления информации о пространстве имён;
2.	Хозяин инфраструктуры (Infrastructure Master) — отвечает за обновление в междоменных объектных ссылок, также на нем выполняется команда adprep /domainprep;.
3.	Хозяин RID (RID Master) —сервер раздает другим контроллерам домена идентификаторы RID (пачками по 500 штук) для создания уникальных идентификаторов объектов — SID.
Get-ADDomainController -Filter * | Select-Object Name, Domain, Forest, OperationMasterRoles |Where-Object {$_.OperationMasterRoles}
Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator
Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster
1.	Роли уровня леса (Schema master и Domain naming master) нужно расположить на контроллере корневого домена, который одновременно является сервером глобального каталога (Global Catalog);
2.	Все 3 доменные FSMO роли нужно разместить на одном DC с достаточной производительностью;
3.	Все DC в лесу должны быть серверами глобального каталога, т.к. это повышает надежность и производительность AD, при этом роль Infrastructure Master фактически не нужна. Если у вас в домене есть DC без роли Global Catalog, нужно поместить FSMO роль Infrastructure Master именно на него;
4.	Не размешайте другие задачи на DC, владельцах FSMO ролей.
Move-ADDirectoryServerOperationMasterRole -Identity dc02 -OperationMasterRole PDCEmulator, RIDMaster
PDCEmulator	0
RIDMaster	1
InfrastructureMaster	2
SchemaMaster	3
DomainNamingMaster	
*************
Корзина Active Directory в Windows Server 2012
1.	Как минимум один контроллер, сWindows Server 2012 и включенным Active Directory Administrative Center
2.	Все контролеры домена должны работать под управлением Windows Server 2008 R2 или выше
3.	Функциональный уровень леса должен быть не менее Windows Server 2008 R2
4.	Enable-ADOptionalFeature –Identity ‘CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=winitpro,DC=ru’ –Scope ForestOrConfigurationSet –Target ‘corp.winitpro.ru’
*****************
Восстановление доверительных отношений между рабочей станцией и доменом AD
The trust relationship between this workstation and the primary domain failed.
The security database on the server does not have a computer account for this workstation trust relationship.
HKLM\SECURITY\Policy\Secrets\$machine.ACC
1.	Самая частая проблема. Компьютер был восстановлен из старой точки восстановления или снапшота (если это виртуальная машина), созданной раньше, чем был изменен пароль компьютера в AD. Т.е. пароль в снапшоте отличается от пароля компьютера в AD. Если вы откатите такой компьютер на предыдущее состояние, это компьютер попытается аутентифицироваться на DC со старым паролем.
2.	В AD создан новый компьютер с тем же именем, или кто-то сбросил аккаунт компьютера в домене через консоль
3.	Учетная запись компьютера в домене заблокирована администраторам (например, во время регулярной процедуры отключения неактивных объектов AD);
4.	Довольно редкий случай, когда сбилось системное время на компьютере.
Test-ComputerSecureChannel –verbose
The Secure channel between the local computer and the domain winitpro.ru is broken
Test-ComputerSecureChannel –Repair –Credential (Get-Credential)
*****
Ищем источник блокировки учетной записи пользователя в Active Directory
Get-ADUser aaivanov -Properties Name, lastLogonTimestamp,lockoutTime,logonCount,pwdLastSet | Select-Object Name,@{n='LastLogon';e={[DateTime]::FromFileTime($_.lastLogonTimestamp)}},@{n='lockoutTime';e={[DateTime]::FromFileTime($_.lockoutTime)}},@{n='pwdLastSet';e={[DateTime]::FromFileTime($_.pwdLastSet)}},logonCount
Get-ADUser -Identity aaivanov | Unlock-ADAccount
События блокировки пользователей EventID 4740, 4625
Если пользователь ввел неверный пароль, то ближайший к пользователю контроллер домена перенаправляет запрос аутентификации на DC с FSMO ролью эмулятора PDC (именно он отвечает за обработку блокировок учетных записей). Если проверка подлинности не выполнилась и на PDC, он отвечает первому DC о невозможности аутентификации.
При этом в журнале обоих контроллеров домена фиксируются событие с EventID 4740 с указанием DNS имени (IP адреса) компьютера, с которого пришел первоначальный запрос на авторизацию пользователя.
•	0xc000006a – An invalid attempt to login has been made by the following user
•	0xc0000234 – The user account has been automatically locked because too many invalid logon attempts or password change attempts have been requested.
•	nltest /dbflag:2080ffffff
•	net stop netlogon && net start netlogon
type C:\Windows\debug\netlogon.log | findstr a.berg| findstr /i "0xC000006A"

$Username = 'username1'
$Pdce = (Get-AdDomain).PDCEmulator
$GweParams = @{
‘Computername’ = $Pdce
‘LogName’ = ‘Security’
‘FilterXPath’ = "*[System[EventID=4740] and EventData[Data[@Name='TargetUserName']='$Username']]"
}
$Events = Get-WinEvent @GweParams
$Events | foreach {$_.Properties[1].value + ' ' + $_.TimeCreated}
•	Сетевые диски, подключенные через net use (Map Drive);
•	Задания планировщика Windows Task Scheduler;
•	Ярлыки с настроенным режимом RunAs (используется для запуска от имени другого пользователя);
•	В службах Windows, которые настроены на запуск из-под доменной учетной записи;
•	Сохранённые пароли в менеджере паролей в панели управления (Credential Manager). Выполните команду rundll32.exe keymgr.dll, KRShowKeyMgr и удалите сохраненные пароли;
•	Программы, которые хранят и используют закэшировнный пароль пользователя;
•	Браузеры;
•	Мобильные устройства (например, использующееся для доступа к корпоративной почте);
•	Программы с автологином или настроенный автоматический вход в Windows;
•	Незавершенные сессии пользователя на других компьютерах или терминальных RDS фермах или RDP серверах (поэтому желательно настраивать лимиты для RDP сессий);
•	Сохраненные пароли для подключения к Wi-FI сетям (WPA2-Enterprise 802.1x аутентификацию в беспроводной сети);
•	Если пользователь недавно сменил пароль и забыл его, вы можете сбросить его.
********
Настройка размера токена Kerberos с помощью параметра MaxTokenSize
На днях столкнулся с довольно интересной проблемой у некоторых пользователей, заключающейся в невозможности аутентифицироваться на ряде доменных сервисов из-за превышения максимального размера билета (токена) Kerberos. В этой статье мы покажем, как определить размер билета Kerberos для конкретного пользователя и увеличить буфер для хранения токена с помощью параметра MaxTokenSize.
Microsoft-Windows-Security-Kerberos
Размер билета Kerberos зависит от следующих факторов:
•	Количества групп безопасности Active Directory (в том числе вложенных) в которых состоит пользователь (группы рассылок типа Mail-enabled universal distribution group в токен не включаются);
•	Используется ли SIDHistory;
•	Используемого механизма аутентификации (обычный парольный или мультифакторный, например, через смарт карты)
•	Доверена ли учетная запись для делегирования или нет.
•	В Windows 7 и Windows Server 2008R2 – 12 Кб.
•	В Windows 8 и Windows Server 2012 (вплоть до Windows Server 2022 и Windows 11) размер увеличен до 48 Кб.
В Active Directory есть жесткий лимит на количество групп, в которых может состоять пользователь. Лимит составляет 1015 групп (включая вложенные группы). При превышении количества групп пот входе пользователя в систему появляется ошибка:
(https://github.com/winadm/posh/blob/master/ActiveDirectory/CheckMaxTokenSize.ps1).
Вы можете уменьшить размер билета Kerberos пользователя за счет:
•	Уменьшения количества групп, в которых состоит пользователь;
•	Очистки атрибута SID History;
•	Отключения использования ограниченного делегирования Kerberos в атрибутах учетных записей (существенно сокращает размер токена).
•	Откройте редактор реестра и перейдите в раздел HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters;
•	Создайте новый параметр типа DWORD (32-bit) Value с именем MaxTokenSize;
•	Укажите желаемое значение для максимального размер буфера (мы указали 48000 в десятичном формате
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP\Parameters
•	MaxFieldLength – максимальный размер каждого заголовка (размер заголовка по-умолчани в IIS 16 Кб, максимальное значение 65536)
•	MaxRequestBytes – максимальный размер строки запроса и заголовков (максимальное значение 16777216)
**********
Группа защищенных пользователей Active Directory
1.	новая глобальная группа безопасности — Защищенные пользователи (Protected Users) 
Члены этой группы могут аутентифицироваться только по протоколу Kerberos. Аутентифицироваться с помощью NTLM, дайджест-проверки (Digest Authentication) или CredSSP не удастся.
1.	Для пользователей этой группы в протоколе Kerberos при предварительной проверке подлинности не могут использоваться слабые алгоритмы шифрования, такие как DES или RC4 (требуется поддержка как минимум AES) .
2.	Эти учетные записи не могут быть делегированы через ограниченную или неограниченную делегацию Kerberos
3.	Долгосрочные ключи Kerberos не сохраняются в памяти, а это значит, что при истечении TGT (по умолчанию 4 часа) пользователь должен повторно аутентифицироваться.
4.	Для пользователей данной группы не сохраняются данные для кэшированного входа в домен. Т.е. при недоступности контроллеров домена, эти пользователи не смогут аутентифицироваться на своих машинах через cached credential.
**********
Обновление членства в группах AD без перезагрузки
klist.exe -li 0x3e7
klist –li 0x3e7 purge
klist -li 0x3e7 tgt

klist purge
Get-WmiObject Win32_LogonSession | Where-Object {$_.AuthenticationPackage -ne 'NTLM'} | ForEach-Object {klist.exe purge -li ([Convert]::ToString($_.LogonId, 16))}
нужно перезапустить оболочку прводника Windows с новым токеном.
Для короткого имени ресурса ( NAME ) и полного имени ( FQDN ) используются разные cifs тикеты. Если вы ранее использовали FQDN, то после сброса тикетов на клиенте командой klist purge , вы сможете получить доступ по NAME (при первом обращении будет выдан новый тикет с новыми группами). Старый тикет для FQDN при этом все еще находится в процесс explorer и не будет сброшен до его перезапуска
****
Добавление фотографии пользователям Active Directory
•	Максимальный размер фото в атрибуте thumbnailPhoto пользователя — 100 Кб. Однако есть общая рекомендация использовать в качестве фото пользователя в AD графический JPEG/BMP файл размером до 10 Кб и размером 96×96 пикселей;
•	Для отображения фото в Outlook 2010 и выше требуется как минимум версия схемы Active Directory Windows Server 2008;
•	При большом количестве фотографий пользователей в AD увеличивается трафик репликации между контроллерами домена из-за роста базы NTDS.DIT;
•	У пользователей есть права на изменение собственного фото в AD. Если нужно делегировать возможность загрузки фото другим пользователям (к примеру, кадровой службе), нужно с помощью мастера делегирования AD предоставить группе право “Write thumbnailPhoto” на OU с учетными записями пользователей.
Set-ADUser vvkuzmin -Replace @{thumbnailPhoto=([byte[]](Get-Content "C:\ps\admin_photo.jpg" -Encoding byte))}

$photofile = ([Byte[]] $(Get-Content -Path "C:\ps\uer_photo.jpg" -Encoding Byte -ReadCount 0))
Set-UserPhoto -Identity vvkuzmin -PictureData $photofile -Confirm:$False
Set-UserPhoto -Identity vvkuzmin -Save -Confirm:$False

Remove-UserPhoto -Identity vvkuzmin
Временное членство в группах Active Directory
(Get-ADForest).ForestMode
Windows2016Forest
Enable-ADOptionalFeature 'Privileged Access Management Feature' -Scope ForestOrConfigurationSet -Target contoso.com
$ttl = New-TimeSpan -Minutes 15
Add-ADGroupMember -Identity "Domain Admins" -Members a.ivanov -MemberTimeToLive $ttl
Get-ADGroup “Domain Admins” -Property member –ShowMemberTimeToLive

$OU = [adsi]"LDAP://OU=Groups,OU=SPB,OU=RU,DC=resource,DC=loc"
$Group = $OU.Create("group","cn=FS01_Public_tmp")
$Group.PutEx(2,"objectClass",@("dynamicObject","group"))
$Group.Put("entryTTL","2592000")
$Group.SetInfo()
****
Как узнать, кто и когда создал пользователя в Active Directory
Get-ADUser a.novak –properties name,whencreated|select name,whencreated
$Report = @()
$time = (get-date) - (new-timespan -hour 24)
Get-WinEvent -FilterHashtable @{LogName="Security";ID=4720;StartTime=$Time}| Foreach {
$event = [xml]$_.ToXml()
if($event)
{
$Time = Get-Date $_.TimeCreated -UFormat "%Y-%m-%d %H:%M:%S"
$CreatorUser = $event.Event.EventData.Data[4]."#text"
$NewUser = $event.Event.EventData.Data[0]."#text"
$objReport = [PSCustomObject]@{
User = $NewUser
Creator = $CreatorUser
DC = $event.Event.System.computer
CreationDate = $Time
}
}
$Report += $objReport
}
$Report
***
Как изменить дату установки пароля пользователя в Active Directory
Set-ADUser admin1 -Replace @(pwdLastSet='0')
Set-ADUser admin1 -Replace @(pwdLastSet='-1')
****8
