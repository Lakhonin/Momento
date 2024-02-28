Восстановление удаленного загрузочного EFI раздела в Windows
•	Системный раздел EFI (Extensible Firmware Interface, или EFI System Partition — ESP) с загрузчиком – 100 Мб (тип раздела — EFI);
•	Резервный раздел Майкрософт (Microsoft Reserved) – 128 Мб (тип раздела — MSR);
•	Основной раздел Windows – раздел с Windows.
 
![alt text](https://winitpro.ru/wp-content/uploads/2015/06/default-uefi-disk-partitions.jpg)

На EFI разделе (по аналогии с разделом System Reserved на дисках с MBR разметкой) хранится хранилище конфигурации загрузки (BCD) и ряд файлов, необходимых для загрузки Windows. При загрузке компьютера среда UEFI загружает загрузчик (EFI\Microsoft\Boot\bootmgfw.efi) с раздела EFI (ESP) и передает управление ему. Исполняемый файл bootmgfw.efi выполняет запуск основного загрузчика Windows Boot Manager, который загружает данные конфигурации из BCD. После загрузки BCD начинается загрузка Windows через winload.efi.

Diskpart
list disk
 
Select disk 0
Select partition 1
Delete partition override
create partition efi size=100
select partition 1
format quick fs=fat32 label="System"
assign letter=G
bcdboot c:\windows /s G: /f UEFI
************
Восстановление удаленного MBR в Windows
Diskpart
list disk

Select disk 0
Select partition 1
Delete partition override
create partition size=100
select partition 1
format quick fs=fat32 
assign letter=G
bcdboot c:\windows /s G: /f ALL
*************
Резервное копирование и восстановление хранилища загрузки BCD
начиная с Windows Vista, отказалась от старого загрузчика ОС Windows NTLDR, заменив его новым диспетчером загрузки — BOOTMGR. Код нового диспетчера загрузки хранится в специальном файле bootmgr в корне активного раздела. Диспетчер загрузки выполняет процедуру загрузки в соответствии с существующей конфигурацией, которая содержится в специальном хранилище данных конфигурации BCD (Boot Configuratin Data). Данное хранилище представляет собой специальный бинарный файл с именем BCD, расположенный в каталоге BOOT активного раздела (это тот самый «скрытый» раздел с меткой System Reserved).
bcdedit /export e:\bcd_backup.bcd
•	 bootrec /FixMbr – перезапись master boot record на системном разделе
•	 bootrec /FixBoot – пересоздание загрузочного сектора на загрузочном разделе
•	 bootrec /ScanOS – сканирование всех дисков на предмет поиска на них установленных систем, совместимых с Windows
•	bootrec /RebuildBcd
•	bcdedit /import e:\bcd_backup.bcd
*************
Secure Boot
Функция Secure Boot в Windows 8 позволяет в процессе загрузки (до запуска операционной системы) организовать проверку всех запускаемых компонентов (драйвера, программы), гарантируя, что только доверенные (с цифровой подписью) программы могут выполняться в процессе загрузки Windows. Неподписанный код и код без надлежащих сертификатов безопасности (руткиты, буткиты) блокируется UEFI (однако и эту систему защиту можно обойти, вспомните червя Flame, подписанного фальшивым сертификатом Microsoft). В случае обнаружения компонента без цифровой подписи автоматически запустится служба Windows Recovery, которая попытается внести изменения в Windows, восстановив нужные системные файлы.
для использования технологии защищенной загрузки вместо BIOS на ПК должна использоваться система UEFI (что это такое описано в статье UEFI и Windows 8). Кроме того, прошивка материнской платы должна поддерживать спецификацию UEFI v2.3.1 и иметь в своей базе сигнатур UEFI сертификат центра сертификации Microsoft Windows (
•	Recovery – 300 Мб
•	System – 100 Мб – системный раздел EFI, содержащий NTLDR, HAL, Boot.txt, драйверы и другие файлы, необходимые для загрузки системы.
•	MSR (Reserved) – 128 Мб – раздел зарезервированный Microsoft (Microsoft Reserved -MSR) который создается на каждом диске для последующего использования операционной системой
•	Primary – все оставшееся место, это раздел, куда, собственно, и устанавливается Windows 8
*************
Запуск Windows 10 в безопасном режиме
bcdedit /set {current} safeboot minimal
bcdedit /deletevalue {default} safeboot
чтобы включить безопасный режим и прочие параметры восстановления в Windows 10, достаточно 3 раза подряд прервать загрузку системы кнопкой отключения питания.
Затем перейдите в раздел Update & security Перейдите в раздел Recovery и в секции Advanced Startup нажмите Restart now
В стартовом меню нажмите кнопку Power и, зажав Shift на клавиатуре, выберите пункт перезагрузки системы (Restart)
*************
включить поддержку AHCI
Режим AHCI (Advance Host Controller Interface) позволяет задействовать расширенные возможностей SATA, такие как горячее подключение (Hot-Plugging) и NCQ (native command queuing), позволяющая повысить производительность дисковых операций 
ких системах при включении в BIOS-е режима AHCI на SATA-контроллере, система перестает видеть sata диск (отсутствует необходимый ahci-драйвер) и падает в BSOD (INACCESSIBLE_BOOT_DEVICE) HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storahci\
ErrorControl=0
StartOverride 0=0

1.	Отключить режим AHCI в BIOS
2.	bcdedit /set {current} safeboot minimal
3.	Затем систему нужно перезагрузить, вновь зайти в BIOS, переключится в AHCI Mode и сохранить изменения.
4.	В результате Windows 8 должна загрузится в безопасном режиме и автоматически установить драйвер AHCI.
5.	Затем нужно отключить загрузку в SafeMode:
bcdedit /deletevalue {current} safeboot
*************
Исправляем ошибку 0x0000007B (INACCESSABLE_BOOT_DEVICE)

•	При восстановлении Windows из бэкапа на другой физический компьютер или виртуальную машину Hyper-V, VMware или VirtualBox (как частный случай восстановление из Bare Metal Recovery на другое железо);
•	После переносе (клонировании) Windows на новый диск или новый компьютер;
•	При миграции физической системы с помощью создании образа компьютера (например, с помощью disk2vhd) и разворачивании из этого vhd образа новой виртуальной машины;
•	При переключении режима работы SATA контроллера в BIOS с AHCI на IDE/RAID, или наоборот (в этом случае достаточно открыть настройки BIOS и вернуть исходный режим SATA);
•	При замене материнской платы и / или контроллера жесткого диска;
•	После обновления BIOS/UEFI или смене настроек.
\Windows\System32\config\SYSTEM
В загруженной ветке перейдите в раздел HKEY_LOCAL_MACHINE\local_hkey\ControlSet001\services\.
Найдите следующие ключи реестра:
•	Atapi
•	Intelide
•	LSI_SAS
В каждом из этих ключей найдите параметр типа REG_DWORD с именем Start и измените его значение на 0(0x00000000).
Примечание. Значение Start=0, означает что данная служба (и соответвующий драввер) будут загружаться при загрузке Windows. Start=3 – ручной запуск службы
msahci установить Start=0
dism /image:f:\ /add-driver /driver:vioscsi.inf
