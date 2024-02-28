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
