0xC004C4AEКоды ошибок активации Windows
0xC004C003 The activation server determined the specified product key is blocked (Сервер активации определил, что указанный ключ заблокирован)
0xC004B100 The activation server determined that the computer could not be activated. (Сервер активации определил, что компьютер не может быть активирован)
0xC004C008 The activation server determined that the specified product key could not be used. (Сервер активации определил, что указанный ключ не может быть использован)
0xC004C020 The activation server reported that the Multiple Activation Key has exceeded its limit. (Сервер активации сообщает о том, что для ключа Multiple Activation Key превышено количество возможных активаций) 0xC004C021 The activation server reported that the Multiple Activation Key extension limit has been exceeded. (Сервер активации сообщает о том, что расширение ключа Multiple Activation Key также превышено по числу активаций)
0xC004F009 The software Licensing Service reported that the grace period expired. (Сервер лицензий сообщает о том, что бесплатный период использования окончен)
0xC004F00F The Software Licensing Service reported that the hardware ID binding is beyond level of tolerance.
0xC004F014 The Software Licensing Service reported that the product key is not available (ключ продукта не доступен)
0xC004F02C The software Licensing Service reported that the format for the offline activation data is incorrect. (формат для офлайн активации неверен)
0xC004F035 The software Licensing Service reported that the computer could not be activated with a Volume license product key. Volume licensed systems require upgrading from a qualified operating system. Please contact your system administrator or use a different type of key. ( компьютер не может быть активирован при помощи данного ключа Volume license, необходимо обновить операционную систему)
0xC004F038 The software Licensing Service reported that the computer could not be activated. The count reported by your Key Management Service (KMS) is insufficient. Please contact your system administrator. (ошибка счетчика активаций на KMS, обратитесь к системному администратору )
0xC004F039 The software Licensing Service reported that the computer could not be activated. The Key Management Service (KMS) is not enabled. (KMS не включен)
0xC004F041 The software Licensing Service determined that the Key Management Server (KMS) is not activated. KMS needs to be activated. (Key Management Server не активирован, его необходимо активировать)
0xC004F042 The software Licensing Service determined that the specified Key Management Service (KMS) cannot be used. (указанный сервер KMS не может быть использован)
0xC004F050 The Software Licensing Service reported that the product key is invalid. (ключ неверен)
0xC004F051 The software Licensing Service reported that the product key is blocked. (ключ заблокирован)
0xC004F064 The software Licensing Service reported that the non-Genuine grace period expired (льготный период закончен).
0xC004F065 The software Licensing Service reported that the application is running within the valid non-genuine grace period .
0xC004F066 The Software Licensing Service reported that the product SKU is not found. (Software Licensing Service сообщил, что данный код продукта не найден)
0xC004F068 The software Licensing Service determined that it is running in a virtual machine. The Key Management Service (KMS) is not supported in this mode. (Licensing Service определил, что он запущен на виртуальной машине, KMS не поддерживает этот режим)
0xC004F069 The Software Licensing Service reported that the computer could not be activated. The Key Management Service (KMS) determined that the request timestamp is invalid. (KMS определила неправильную метку времени)
0xC004F06C The Software Licensing Service reported that the computer could not be activated. The Key Management Service (KMS) determined that the request timestamp is invalid. (KMS определила неправильную метку времени)
0×80070005 Access denied the requested action requires elevated privileges. (доступ запрещен, указанное действие требует административных прав)
0x8007232A DNS server failure. (ошибка DNS сервера)
0x8007232B DNS name does not exist. (DNS имя не существует)
0x800706BA The RPC server is unavailable.
0x8007251D No records found for DNS query (DNS запрос не вернул записей)
0×80092328 DNS name does not exist (DNS имя не существует)
******
Список ошибок активации Windows 10
0xC004C4AE
Данная ошибка может появляться при добавлении с помощью стороннего ПО нового языка интерфейса Windows, который в данный момент не поддерживается. Рекомендуется откатить состояние системы на момент, предшествующий изменению
0xC004F061
•	В ветке реестра HKEY_LOCAL_MACHINE/Software/Microsoft/Windows/CurrentVersion/Setup/OOBE измените значения параметра MediaBootInstall на 0.
•	Выполните команду: slmgr /rearm
•	Перезагрузитесь
•	Еще раз укажите ключ и попробуйте активировать систему
0xC004FC03
На компьютере отсутствует подключение к Интернету, или соединение с серверами активацией блокируется Брандмауэром Windows, другим межсетевым экраном или прокси
0xC004C008
Ошибка возникает, если данный ключ продукта уже использовался для активации системы на другом компьютере, или на большем числе компьютеров, чем предусмотрено лицензионным соглашением (например, при превышении количества активаций MAK ключом).
0xC004C003
Скорее всего указан некорректный или недействительный ключ продукта. Также ошибка может появится при попытке активировать чистую версию Windows 10 вместо выполнения апгрейда с предыдущей версии.
0xC004F034
высокая нагрузка на сервер активации Microsoft,
0xC004C020
Ошибка связана, с тем, что количество активаций ОС с помощью ключа многократной активации (MAK ключа) превысило количество, определенное в корпоративном соглашении с Microsoft.
0x8007232B
Ошибка может возникнуть при отсутствии подключения к сети, либо использованием некорректного/нефункционирующего DNS сервера.
0x8007007B
Причиной данной ошибки является попытка использования для активации системы ключа от другой редакции Windows 10. Измените ключ системы.
0x80072F8F
Windows не может подключится к серверу активации, или время системы существенно отличается от времени сервера. Проверьте настройки времени на клиенте, и если это не помогло, перезагрузите компьютер.
0xC004E003
Некоторые системный файлы системы отсутствуют или повреждены. Проверьте целостность системных файлов с помощью команды sfc /scannow или попробуйте откатить состояние системы на более раннее состояние.
0x80004005
Попробуйте перезагрузить компьютер и активировать Windows еще раз из панели управления. Если не помогло, придется выполнить сброс системы
0xC004F074
Причиной может быть отсутствие SRV записи _VLMCS._tcp в DNS. Эту запись можно создать вручную, либо на клиенте принудительно указать адрес KMS, например:
slmgr /skms kms-server.winitpro.ru:1688
Также проверьте, не отличается ли время на KMS сервере и клиенте
0xC004F014
Ошибка 0xC004F038 также связана с проблемой активации на KMS сервере и говорит о том, что в сети не набралось необходимого количества систем для активации
0x803F7001
•	Произошло изменение в конфигурации оборудования системы. Попробуйте связаться с оператором колл центра Microsoft и объяснить проблему (команда для получения номера телефона slui 4). Также телефон Microsoft в вашей стране можно получить из файла %windir%System32\SPPUI\Phone.inf
•	Для активации Windows 10 используется ключ от Windows 7 /8.1
•	В ключе активации содержимся ошибка
•	Проблема подключения к серверам активации (возможно временная)
0xC004F012
Попробуйте указать правильный ключ активации системы и проверьте, работает ли служба «Защита программного обеспечения» (Microsoft Software Protection Platform Service).
Попробуйте включить ее из консоли services.msc или через реестр:
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\sppsvc]
Значение «Start»=dword:00000002
После включения службы нужно перезагрузить компьютер.
***
FAQ по KMS активации продуктов Microsoft
•	Установка корпоративного ключа KMS (CSVLK ключа) на клиентах вместо общедоступного GVLK ключа;
•	Общий KMS ключ (CSVLK) не соответствует версии ОС на активируемом хосте;
•	Сервер KMS должен быть обновлён для поддержки активации последних версий продуктов Microsoft;
•	Если при попытке активации появляется ошибка 0xC004F074 – причиной может быть отсутствие SRV записи_VLMCS._tcp.winitpro.ru в DNS. Ее можно создать вручную или указать адрес KMS сервера вручную (команда указана ниже);
•	Ошибка 0xC004F038 говорит о том, что в вашей сети не набралось необходимого количества клиентов для активации (см. информацию о пороге активации выше). Как только на KMS сервер поступит достаточное количество запросов активации, она начнет выполнять активацию клиентов;
•	Проверьте доступность порта 1688 на KMS сервере с помощью командлета Test-NetConnection: TNC msk-mankms -Port 1688 -InformationLevel Quiet
Если порт недоступен, возможно доступ блокируется файерволом, или на KMS сервере не запущена служба Software Protection (sppsvc);
•	Для получения более подробной информации о конкретной ошибке активации Windows используете команду:slui.exe 0x2a ErrorCode
***
Как остановить зависшую виртуальную машину в Hyper-V
Get-Service vmms | Restart-Service
$VMGUID = (Get-VM "SVM-GUARDEDHOST1").ID
$VMWMProc = (Get-WmiObject Win32_Process | ? {$_.Name -match 'VMWP' -and $_.CommandLine -match $VMGUID})
Stop-Process ($VMWMProc.ProcessId) –Force
Удаляем ключ активации Windows из реестра
slmgr /cpky
Как узнать ключ активации установленного MS Office
function Get-MSOfficeProductKey { param( [string[]]$computerName = "." ) $product = @() $hklm = 2147483650 $path = "SOFTWARE\Microsoft\Office" 
 

foreach ($computer in $computerName) { $wmi = [WMIClass]"\\$computer\root\default:stdRegProv" $subkeys1 = $wmi.EnumKey($hklm,$path) foreach ($subkey1 in $subkeys1.snames) { $subkeys2 = $wmi.EnumKey($hklm,"$path\$subkey1") foreach ($subkey2 in $subkeys2.snames) { $subkeys3 = $wmi.EnumKey($hklm,"$path\$subkey1\$subkey2") foreach ($subkey3 in $subkeys3.snames) { $subkeys4 = $wmi.EnumValues($hklm,"$path\$subkey1\$subkey2\$subkey3") foreach ($subkey4 in $subkeys4.snames) { if ($subkey4 -eq "digitalproductid") { $temp = "" | select ComputerName,ProductName,ProductKey $temp.ComputerName = $computer $productName = $wmi.GetStringValue($hklm,"$path\$subkey1\$subkey2\$subkey3","productname") $temp.ProductName = $productName.sValue $data = $wmi.GetBinaryValue($hklm,"$path\$subkey1\$subkey2\$subkey3","digitalproductid") 
$valueData = ($data.uValue)[52..66] # decrypt base24 encoded binary data $productKey = "" $chars = "BCDFGHJKMPQRTVWXY2346789" for ($i = 24; $i -ge 0; $i--) { $r = 0 for ($j = 14; $j -ge 0; $j--) { $r = ($r * 256) -bxor $valueData[$j] $valueData[$j] = [math]::Truncate($r / 24) $r = $r % 24 } $productKey = $chars[$r] + $productKey if (($i % 5) -eq 0 -and $i -ne 0) { $productKey = "-" + $productKey } } $temp.ProductKey = $productKey $product += $temp } } } 
} } } $product } 
Очистка занятых COM портов
Get-WMIObject Win32_SerialPort | Select-Object Name,DeviceID,Description
get-pnpdevice -class Ports -ea 0| Select Name, PNPDeviceID, Status, Service
Проверка статуса активации и типа лицензии Office 2019/ 2016
Cd “C:\Program Files (x86)\Microsoft Office\Office16”
Следующей командой можно проверить статус активации Office:
cscript ospp.vbs /dstatus
Get-CimInstance SoftwareLicensingProduct| where {$_.name -like "*office*"}|select name,licensestatus

enum Licensestatus{
Unlicensed = 0
Licensed = 1
Out_Of_Box_Grace_Period = 2
Out_Of_Tolerance_Grace_Period = 3
Non_Genuine_Grace_Period = 4
Notification = 5
Extended_Grace = 6
}
Get-CimInstance -ClassName SoftwareLicensingProduct | where {$_.name -like "*office*"}| select Name, ApplicationId, @{N=’LicenseStatus’; E={[LicenseStatus]$_.LicenseStatus}}
***
Почему растет невыгружаемый пул памяти 
На компьютерах и серверах Windows могут возникать проблемы с исчерпанием свободной памяти, вызванной утечкой некого системного драйвера, хранящего свои данные в невыгружаемом пуле памяти системы. Невыгружаемый пул памяти (Non-paged memory) – это данные в оперативной памяти компьютера, используемые ядром и драйверами операционной системой, которая никогда не выгружается на диск (в своп/ файл подкачки), т.е. всегда находится в физической RAM памяти.
Анализ дампа памяти в Windows при BSOD с помощью WinDBG
В момент критического сбоя операционная система Windows прерывает работу и показывает синий экран смерти (BSOD). Содержимое оперативной памяти и вся информация о возникшей ошибке записывается в файл подкачки. При следующей загрузке Windows создается аварийный дамп c отладочной информацией на основе сохраненных данных. В системном журнале событий создается запись о критической ошибке.
•	Мини дамп памяти (Small memory dump) (256 КБ). Этот тип файла включает минимальный объем информации. Он содержит только сообщение об ошибке BSOD, информацию о драйверах, процессах, которые были активны в момент сбоя, а также какой процесс или поток ядра вызвал сбой.
•	Дамп памяти ядра (Kernel memory dump). Как правило, небольшой по размеру — одна треть объема физической памяти. Дамп памяти ядра является более подробным, чем мини дамп. Он содержит информацию о драйверах и программах в режиме ядра, включает память, выделенную ядру Windows и аппаратному уровню абстракции (HAL), а также память, выделенную драйверам и другим программам в режиме ядра.
•	Полный дамп памяти (Complete memory dump). Самый большой по объему и требует памяти, равной оперативной памяти вашей системы плюс 1MB, необходимый Windows для создания этого файла.
•	Автоматический дамп памяти (Automatic memory dump). Соответствует дампу памяти ядра с точки зрения информации. Отличается только тем, сколько места он использует для создания файла дампа. Этот тип файлов не существовал в Windows 7. Он был добавлен в Windows 8.
•	Активный дамп памяти (Active memory dump). Этот тип отсеивает элементы, которые не могут определить причину сбоя системы. Это было добавлено в Windows 10 и особенно полезно, если вы используете виртуальную машину, или если ваша система является хостом Hyper-V.

Утилита WinDBG входит в «Пакет SDK для Windows 10» (Windows 10 SDK). Скачать можно здесь.
Файл называется winsdksetup.exe, размер 1,3 МБ.
WinDBG для Windows7 и более ранних систем включен в состав пакета «Microsoft Windows SDK for Windows 7 and .NET Framework 4». Скачать можно здесь.
Можете установить весь пакет, но для установки только инструмента отладки выберите Debugging Tools for Windows.
Настройте WinDBG на использование Microsoft Symbol Server:
•	Откройте WinDBG;
•	Перейдите в меню File –> Symbol File Path;
•	Пропишите строку, содержащую URL для загрузки символов отладки с сайта Microsoft и папку для сохранения кэша: SRV*E:\Sym_WinDBG*http://msdl.microsoft.com/download/symbols В примере кэш загружается в папку E:\Sym_WinDBG, можете указать любую.
•	Не забывайте сохранить изменения в меню File –> Save WorkSpace;

Отладчик WinDBG открывает файл дампа и загружает необходимые символы для отладки из локальной папки или из интернета. Во время этого процесса вы не можете использовать WinDBG. Внизу окна (в командной строке отладчика) появляется надпись Debugee not connected. 
Команды вводятся в командную строку, расположенную внизу окна.

Самое главное, на что нужно обратить внимание – это код ошибки, который всегда указывается в шестнадцатеричном значении и имеет вид 0xXXXXXXXX (указываются в одном из вариантов — STOP: 0x0000007B, 02.07.2019 0008F, 0x8F). В нашем примере код ошибки 0х139.
Полный справочник ошибок можно посмотреть здесь.
•	Она выполняет предварительный анализ дампа памяти и предоставляет подробную информацию для начала анализа.
•	Эта команда отобразит STOP-код и символическое имя ошибки.
•	Она показывает стек вызовов команд, которые привели к аварийному завершению.
•	Кроме того, здесь отображаются неисправности IP-адреса, процессов и регистров.
•	Команда может предоставить готовые рекомендации по решению проблемы.
Основные моменты, на которые вы должны обратить внимание при анализе после выполнения команды !analyze –v (листинг неполный).
1: kd> !analyze -v
*****************************************************************************
* *
* Bugcheck Analysis *
* *
*****************************************************************************
Символическое имя STOP-ошибки (BugCheck)
KERNEL_SECURITY_CHECK_FAILURE (139)
Описание ошибки (Компонент ядра повредил критическую структуру данных. Это повреждение потенциально может позволить злоумышленнику получить контроль над этой машиной):
A kernel component has corrupted a critical data structure. The corruption could potentially allow a malicious user to gain control of this machine.
Аргументы ошибки:
Arguments:
Arg1: 0000000000000003, A LIST_ENTRY has been corrupted (i.e. double remove).
Arg2: ffffd0003a20d5d0, Address of the trap frame for the exception that caused the bugcheck
Arg3: ffffd0003a20d528, Address of the exception record for the exception that caused the bugcheck
Arg4: 0000000000000000, Reserved
Debugging Details:
------------------
Счетчик показывает сколько раз система упала с аналогичной ошибкой:
CUSTOMER_CRASH_COUNT: 1
Основная категория текущего сбоя:
DEFAULT_BUCKET_ID: FAIL_FAST_CORRUPT_LIST_ENTRY
Код STOP-ошибки в сокращенном формате:
BUGCHECK_STR: 0x139
Процесс, во время исполнения которого произошел сбой (не обязательно причина ошибки, просто в момент сбоя в памяти выполнялся этот процесс):
PROCESS_NAME: sqlservr.exe
CURRENT_IRQL: 2
Расшифровка кода ошибки: В этом приложении система обнаружила переполнение буфера стека, что может позволить злоумышленнику получить контроль над этим приложением.

ERROR_CODE: (NTSTATUS) 0xc0000409 - The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application.
EXCEPTION_CODE: (NTSTATUS) 0xc0000409 - The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application.
Последний вызов в стеке:
LAST_CONTROL_TRANSFER: from fffff8040117d6a9 to fffff8040116b0a0
Стек вызовов в момент сбоя:
STACK_TEXT:
ffffd000`3a20d2a8 fffff804`0117d6a9 : 00000000`00000139 00000000`00000003 ffffd000`3a20d5d0 ffffd000`3a20d528 : nt!KeBugCheckEx
ffffd000`3a20d2b0 fffff804`0117da50 : ffffe000`f3ab9080 ffffe000`fc37e001 ffffd000`3a20d5d0 fffff804`0116e2a2 : nt!KiBugCheckDispatch+0x69
ffffd000`3a20d3f0 fffff804`0117c150 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiFastFailDispatch+0xd0
ffffd000`3a20d5d0 fffff804`01199482 : ffffc000`701ba270 ffffc000`00000001 000000ea`73f68040 fffff804`000006f9 : nt!KiRaiseSecurityCheckFailure+0x3d0
ffffd000`3a20d760 fffff804`014a455d : 00000000`00000001 ffffd000`3a20d941 ffffe000`fcacb000 ffffd000`3a20d951 : nt! ?? ::FNODOBFM::`string'+0x17252
ffffd000`3a20d8c0 fffff804`013a34ac : 00000000`00000004 00000000`00000000 ffffd000`3a20d9d8 ffffe001`0a34c600 : nt!IopSynchronousServiceTail+0x379
ffffd000`3a20d990 fffff804`0117d313 : ffffffff`fffffffe 00000000`00000000 00000000`00000000 000000eb`a0cf1380 : nt!NtWriteFile+0x694
ffffd000`3a20da90 00007ffb`475307da : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiSystemServiceCopyEnd+0x13
000000ee`f25ed2b8 00000000`00000000 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : 0x00007ffb`475307da
Участок кода, где возникла ошибка:
FOLLOWUP_IP:
nt!KiFastFailDispatch+d0
fffff804`0117da50 c644242000 mov byte ptr [rsp+20h],0
FAULT_INSTR_CODE: 202444c6
SYMBOL_STACK_INDEX: 2
SYMBOL_NAME: nt!KiFastFailDispatch+d0
FOLLOWUP_NAME: MachineOwner
Имя модуля в таблице объектов ядра. Если анализатору удалось обнаружить проблемный драйвер, имя отображается в полях MODULE_NAME и IMAGE_NAME:
MODULE_NAME: nt
IMAGE_NAME: ntkrnlmp.exe
Если кликнете по ссылке модуля (nt), то увидите подробную информацию о пути и других свойствах модуля. Находите указанный файл, и изучаете его свойства.
1: kd> lmvm nt
Browse full module list
Loaded symbol image file: ntkrnlmp.exe
Mapped memory image file: C:\ProgramData\dbg\sym\ntoskrnl.exe\5A9A2147787000\ntoskrnl.exe
Image path: ntkrnlmp.exe
Image name: ntkrnlmp.exe
InternalName: ntkrnlmp.exe
OriginalFilename: ntkrnlmp.exe
ProductVersion: 6.3.9600.18946
FileVersion: 6.3.9600.18946 (winblue_ltsb_escrow.180302-1800)
 
В приведенном примере анализ указал на файл ядра ntkrnlmp.exe. Когда анализ дампа памяти указывает на системный драйвер (например, win32k.sys) или файл ядра (как в нашем примере ntkrnlmp.exe), вероятнее всего данный файл не является причиной проблемы. Очень часто оказывается, что проблема кроется в драйвере устройства, настройках BIOS или в неисправности оборудования.
Если вы увидели, что BSOD возник из-за стороннего драйвера, его имя будет указано в значениях MODULE_NAME и IMAGE_NAME.
Например:
Image path: \SystemRoot\system32\drivers\cmudaxp.sys
Image name: cmudaxp.sys
Откройте свойсва файла драйвера и проверьте его версию. В большинстве случаев проблема с драйверами решается их обнвовлением.
