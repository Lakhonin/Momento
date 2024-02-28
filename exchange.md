Отозвать отправленное письмо в Outlook и Exchange
•	Вы используете десктопный клиент Outlook. Функция отзыва письма в не доступна в веб клиенте Outlook (OWA, Outlook on the Web)
•	Ваш почтовый ящик и ящик получателя находится в одной организации Exchange;
•	Письмо не было прочитано получателем. Если письмо было просмотрено через панель быстрого просмотра (Preview Pane), считается что такое письмо прочитано (вы можете получить статус прочтения письма в ящике Exchange с помощью PowerShell)
•	Письмо находится в папке Входящие (Inbox) и не было перемещено в другую папку почтовыми правилами Exchange/Outlook или вручную пользователем;
•	Вы не используете для подключения к ящику протоколы POP, MAPI или IMAP;
•	Если вы используете Exchange Online, отзыв писем должен быть разрешен на уровне всего тенанта;
•	У пользователя не включен режим кэширования или автономный режим.
 
Найдите ваше письмо в папке Отправленные (Sent Items) и откройте его;
Выберите в меню File -> Info -> Resend or Recall -> Recall this message;
*********
Не обновляется офлайн адресная книга (OAB) в Outlook
В Windows для загрузки Offline Address Book (OAB) с сервера Exchange используется протокол BITS. Протокол BITS позволяет скачать файл адресной книги с сервера на компьютер пользователя (используется в том числе для получения файлов обновлений Windows). Если в очереди BITS более 50 заданий, задание загрузки адресной книги Outlook может завершаться с ошибкой 0x80200049 или 0x80070057.
bitsadmin /list
bitsadmin.exe /reset /allusers
Если проблема не решена, попробуйте закрыть Outlook и очистить каталог с текущей версией адресной книги. Достаточно просто переименовать папку C:\Users\%username%\AppData\Local\Microsoft\Outlook\Offline Address Books\ в профиле пользователя.
 
Get-AddressList | Update-AddressList
Get-GlobalAddressList | Update-GlobalAddressList
Get-OfflineAddressBook | Update-OfflineAddressBook
**********
Настройка переадресации почты в Exchange Server
Set-Mailbox a.petrov@winitpro.ru -ForwardingAddress kbuldogov@winitpro.ru -DeliverToMailboxAndForward $true
Опция DeliverToMailboxAndForward указывает, что нужно сохранить копию письма в исходном ящике
**********
Disable и Remove Mailbox
•	Disable – удаляет атрибуты Exchange у пользователя домена, и оставляет учетную запись пользователя в Active Directory. Отключенный почтовый ящик пользователя остается в базе почтовых ящиков Exchange до истечения срока хранения, после чего он автоматически удаляется.
•	Remove – удаляет ящик пользователя и его учетную запись из Active Directory
**********
Настройка максимального размера сообщения в Exchange
Get-TransportConfig | Set-TransportConfig -MaxSendSize 21MB - MaxReceiveSize 21MB
Get-SendConnector | Set-SendConnector -MaxmessageSize 21MB
Get-ReceiveConnector | Set-ReceiveConnector -MaxmessageSize 21MB
Set-MailBox < email пользователя> - MaxSendSize 21MB -MaxReceiveSize 21MB
c:\Program Files\Microsoft\Exchange Server\ClientAccess\Owa\
C:\Program Files\Microsoft\Exchange Server\V14\ClientAccess\Sync\web.config
maxRequestLength
 перезапустить Microsoft Exchange Information Store
*************
Импорт и экспорт почтовых ящиков в PST-файлы в Exchange
должна быть назначена RBAC роль “Mailbox Import Export” 
1.	Целевой ящик Exchange должен существовать;
2.	PST-файл нужно разместить в общей сетевой папке и знать полный UNC путь к нему (не забывайте, что к локальному файлу можно всегда обратится по сетевому пути в формате \\PCName111\C$\PST\tstmail.pst);
3.	У администратора, который выполняет операцию импорта писем в ящик Exchange, должны быть права доступа на сетевой каталог, в котором хранится PST-файл с почтовым архивом.
New-MailboxImportRequest -Mailbox mailtst -FilePath \\HQFS01\PST\usetest.pst -TargetRootFolder "Old_mail" -IncludeFolders "#Inbox#"
Совет. Полный список имен стандартных почтовых папок ящика Exchange:
•	Inbox
•	SentItems
•	DeletedItems
•	Calendar
•	Contacts
•	Drafts
•	Journal
•	Tasks
•	Notes
•	JunkEmail
•	CommunicationHistory
•	Voicemail
•	Fax
•	Conflicts
•	SyncIssues
•	LocalFailures
•	ServerFailures
New-MailboxExportRequest –Mailbox mailtst –FilePath \\HQFS01\ExportPST\mailtst.pst -IncludeFolders “#Inbox#”
************
Скрыть пользователя или группу в адресной книге Exchange
Чтобы скрыть пользователя в GAL, выполните:
Set-Mailbox -Identity AdeleV -HiddenFromAddressListsEnabled $true
•	Контакты: Set-MailContact someextcontact -HiddenFromAddressListsEnabled $true
•	Группы рассылки (Mail-enabled universal distribution groups и Mail-enabled universal security groups):Set-DistributionGroup global_server_admins -HiddenFromAddressListsEnabled $true
•	Динамические группы рассылки Exchange: Set-DynamicDistributionGroup all_msk_users -HiddenFromAddressListsEnabled $true
•	Следующая команда выведет все скрытые объекты в адресной книге:
•	Get-Recipient -ResultSize unlimited -Filter 'HiddenFromAddressListsEnabled -eq $true'
************
Скрыть пользователей в группе рассылки Exchange
Set-ADGroup –id global_admins -replace @{hideDLMembership=$true}
************
Восстановление ящиков и отдельных писем в Exchange
Get-MailboxStatistics -Database RDB
New-MailboxRestoreRequest –SourceDatabase RDB –SourceStoreMailbox “Petrov Ivan” –TargetMailbox ipetrov –AllowLegacyDNMismatch
По умолчанию командлет New-MailboxRestoreRequest ищет в почтовой базе совпадающие LegacyExchangeDN либо проверяет совпадение адреса X500
New-MailboxRestoreRequest –SourceDatabase RDB –SourceStoreMailbox “Petrov Ivan” –TargetMailbox ipetrov –TargetRootFolder “Restored Items” –AllowLegacyDNMismatch
New-MailboxRestoreRequest -SourceDatabase RDB -SourceStoreMailbox "Petrov Ivan" -TargetMailbox ipetrov -IncludeFolders "#Inbox#"
**************
Восстановление поврежденного PST файла
•	Лимиты на размер pst файлов Outlook 2010 и Outlook 2013 – файлы pst/ost имеют формат Unicode и ограничены максимальным размером 50 Гб
**************
Изменить максимальный размер вложений в Outlook
В почтовом клиенте Outlook (в т.ч. последних версиях Outlook в Office 365 и Office 2019/2016 и Office 365) существует ограничение на максимальный размер вложения к письму – 20 Мб.
•	REG ADD HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Preferences\ /v "MaximumAttachmentSize" /t REG_DWORD /d 51200 /f
REG ADD HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\Preferences\ /v "MaximumAttachmentSize" /t REG_DWORD /d 51200 /f
такого почтового отбойника:
•	The attachment size exceeds the allowable limit
•	552: Message size exceeds maximum permitted

•	552 5.3.4 Message size exceeds fixed maximum message size
•	System Undeliverable, message size exceeds outgoing message size limit
•	The message was not sent; reduce the message size and try again
•	Error (0x80040610): The message being sent exceeds the message size established for this user
•	Maximum size of appendable message has been exceeded
**************
Ограничения на размер вложений в Exchange
get-transportconfig | ft maxsendsize, maxreceivesize
get-receiveconnector | ft name, maxmessagesize
get-sendconnector | ft name, maxmessagesize
get-mailbox kbuldogov |ft Name, Maxsendsize, maxreceivesize
Get-Mailbox kbuldogov@winitpro.onmicrosoft.com| fl mailboxplan,maxsendsize
Set-Mailbox kbuldogov -MaxReceiveSize 50MB -MaxSendSize 50MB
**********
