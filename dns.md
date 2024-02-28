репликация зон DNS
Стандартные запросы DNS используют 53 порт UDP, а для передачи зон используется 53 порт протокола TCP. Протокол UDP более эффективен для пересылки запросов DNS, которые обычно состоят из двух составляющих: пакет с запросом, посылаемый на сервер DNS, и пакет с ответом, отправляемом серверов клиенту.
***
Аудит DNS запросов клиентов в Windows Server, логи DNS
1.	Запустите консоль DNS Manager ( dnsmgmt.msc ) и подключитесь к нужному DNS серверу;
2.	Откройте его свойства и перейдите на вкладку Debug Logging;
3.	Включите опцию Log packets for debugging;
4.	Далее можно настроить параметры логирования: выбрать направление DNS пакетов, протокол (UDP и/или TCP), типы пакетов (простые dns запросы, запросы на обновление записей, уведомления);
5.	С помощью опцию Filter packets by IP address можно указать IP адреса, для которых нужно логировать отправленные или полученные пакеты (поможет существенно уменьшить размер лога).
Get-DnsServerDiagnostics
Скрипт не мой, но к сожалению он сейчас не доступен в TechNet Scriptcenter из за очередных изменений Microsoft, поэтому я сохранил его в свой репозитории на GitHub https://github.com/winadm/posh/blob/master/DNS/Get-DNSDebugLog.ps1
Hyper-V: настройка автоматического запуска и порядка загрузки виртуальных машин
•	Nothing – при загрузке хоста виртуальная машина не запускается автоматически (не зависимо от ее состояния до перезагрузки сервера);
•	Automatically start if it was running when the service stopped – ВМ будет автоматически запущена только если она была включена до выключения хоста.
•	Always start this virtual machine automatically – всегда включать данную виртуальную машину при загрузке хоста Hyper-V.
Get-VM –VMname dc01| Set-VM –AutomaticStartDelay 0
Get-VM –VMname exchange, db01 | Set-VM –AutomaticStartDelay 90
Get-VM –VMname rds01,app01 | Set-VM –AutomaticStartDelay 180
