принудительно завершить зависшую службу в Windows
sc queryex wuauserv
taskkill /PID 9168 /F

$Services = Get-WmiObject -Class win32_service -Filter "state = 'stop pending'"
if ($Services) {
foreach ($service in $Services) {
try {
Stop-Process -Id $service.processid -Force -PassThru -ErrorAction Stop
}
catch {
Write-Warning -Message " Error. Error details: $_.Exception.Message"
}
}
}
else {
Write-Output "No services with 'Stopping'.status"
}

( resmon.exe ).
1.	В окне Монитора ресурсов перейдите на вкладку ЦП (CPU) и найдите процесс зависшей службы;
2.	Выберите пункт Анализ цепочки ожидания (Analyze Wait Chain);
3.	Таймаут, в течении которого Service Control Manager ждет ожидания запуска или остановки службы можно изменить через параметр реестра ServicesPipeTimeout. Если служба не запускается в течении указанного таймаута, Windows записывает ошибку в Event Log (Event ID: 7000, 7009, 7011, A timeout was reached 30000 milliseconds). Вы можете увеличить этот таймаут, например до 60 секунд:
4.	reg add HKLM\SYSTEM\CurrentControlSet\Control /v ServicesPipeTimeout /t REG_SZ /d 600000 /f
*************
Как предоставить обычным пользователям права на запуск/остановку служб Window
sc.exe sdshow Spooler
S: — System Access Control List (SACL)
D: — Discretionary ACL (DACL)
CC — SERVICE_QUERY_CONFIG (запрос настроек служы)
LC — SERVICE_QUERY_STATUS (опрос состояния служы)
SW — SERVICE_ENUMERATE_DEPENDENTS (опрос зависимостей)
LO — SERVICE_INTERROGATE
CR — SERVICE_USER_DEFINED_CONTROL
RC — READ_CONTROL
RP — SERVICE_START (запуск службы)
WP — SERVICE_STOP (остановка службы)
DT — SERVICE_PAUSE_CONTINUE (приостановка, продолжение службы)
AU Authenticated Users
AO Account operators
RU Alias to allow previous Windows 2000
AN Anonymous logon
AU Authenticated users
BA Built-in administrators
BG Built-in guests
BO Backup operators
BU Built-in users
CA Certificate server administrators
CG Creator group
CO Creator owner
DA Domain administrators
DC Domain computers
DD Domain controllers
DG Domain guests
DU Domain users
EA Enterprise administrators
ED Enterprise domain controllers
WD Everyone
PA Group Policy administrators
IU Interactively logged-on user
LA Local administrator
LG Local guest
LS Local service account
SY Local system
NU Network logon user
NO Network configuration operators
NS Network service account
PO Printer operators
PS Personal self
PU Power users
RS RAS servers group
RD Terminal server users
RE Replicator
RC Restricted code
SA Schema administrators
SO Server operators
SU Service logon user
Get-ADUser -Identity 'iipeshkov' | select SID
A;;RPWPCR;;; S-1-5-21-2927053466-1818515551-2824591131-1110)
•	A – Allow
•	RPWPCR – RP (SERVICE_START) + WP (SERVICE_STOP) + CR ( SERVICE_USER_DEFINED_CONTROL)
•	SID – SID пользователя или группы

sc sdset Spooler "D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;RPWPCR;;;S-1-5-21-2927053466-1818515551-2824591131-1110)"

$SDDL = "D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;RPWPCR;;;S-1-5-21-2927053466-1818515551-2824591131-1110)"
Set-Service -Name Spooler -SecurityDescriptorSddl $SDDL
********
Предоставление прав на удаленное подключение к Service Control Manager
sc sdset scmanager “D:(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)(A;;CC;;;AC)(A;;CCLCRPRC;;;S-1-5-21-2470146451-3958456388-2988885117-23703978)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)“
 При назначении прав на SCManager, отличных от стандартных, они сохраняются в ветке HKLM\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security. И если при формировании SDDL строки была допущена ошибка, сбросить текущие разрешения на дефолтные можно простым удалением этой ветки и перезагрузкой.
********
