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
Ошибка Exchange “452 4.3.1 Insufficient system resources”
Причина возникновения ошибки – окончание свободного места на диске, на котором находятся очереди службы Exchange Hub Transport. Дело в том, что в Exchange есть специальный компонент мониторинга доступных ресурсов Back Pressure, который в том числе отслеживает свободное место на диске, на котором хранятся очереди транспортной службы Exchange
•	порог Medium (90%) — перестать принимать по SMTP почту от внешних отправителей (почта от MAPI клиентов при этом обрабатывается)
•	порог High (99%) — обработка потока почты полностью прекращается
Управление почтовыми правилами в ящике Exchange
•	Серверные правила Outlook (Server-side rules) — выполняются на стороне сервера Exchange при получении письма. При этом не важно, запущен ли Outlook у пользователя или нет. На стороне сервера могут выполняться следующие виды правил: установка флага важности письма, перемещение письма в другую папку ящика, удаление сообщения, пересылка письма в другой ящик. Правила, которые создаются через Outlook Web App всегда выполняются на стороне сервера;
•	Клиентские правила (Client-side rules) выполняются только в запущенном клиенте Outlook. Пример таких правил: перемещение письма в PST файл, отметить письмо прочитанным (как проверить, прочитал ли пользователь Exchange письмо), вывести оповещение или воспроизвести звук. Этими правилами нельзя управлять из PowerShell. В интерфейсе Outlook у таких правил указан статус «только клиент».
Get-InboxRule -Mailbox abivanov -IncludeHidden
****
Управление группами рассылок в Exchange
•	Группы рассылки (Mail-enabled universal distribution groups) – используются только для рассылки писем. В обычных группах рассылки (не security) вы можете разрешить пользователям самим добавляться или удаляться из группы (membership approval);
•	Группы безопасности (Mail-enabled universal security groups) – используются как для рассылки электронных писем, так и для предоставления доступа к ресурсам в домене Active Directory;
•	Динамическая группа рассылки (Dynamic Distribution Group) – состав членов группы (получателей) формируется автоматически на основании LDAP-фильтра.

New-DistributionGroup -Name “HelpDesk” -SamAccountName “HelpDesk” -OrganizationalUnit “winitpro.ru/ru/groups” -DisplayName "HelpDesk team" -Alias helpdesk
New-DynamicDistributionGroup -Name 'IT dept' -RecipientContainer 'winitpro.ru/ru/user' -IncludedRecipients 'AllRecipients' -ConditionalDepartment 'Департамент ИТ' -OrganizationalUnit 'winitpro.ru/ru/groups/exchange' -Alias itdept
***
Язык, имена папок, часовой пояс и региональные параметры в Exchange
Get-Mailbox aaivanov| Set-MailboxRegionalConfiguration -LocalizeDefaultFolderName:$true -Language "en-US" -TimeZone "Russian Standard Time"
Get-Mailbox aaivanov| Set-MailboxRegionalConfiguration -LocalizeDefaultFolderName:$true -Language "ru-RU" –DateFormat “yyyy-MM-dd” –TimeFormat “HH:mm”
***
Get-MessageTrackingLog: отслеживание сообщений в журналах Exchange
%ExchangeInstallPath%TransportRoles\Logs\MessageTracking
•	Sender – поиск по отправителю;
•	Recipients — поиск по получателю;
•	Server – поиск на определенном транспортном сервере;
•	Start «02/30/2019 08:00:00» -End «02/31/2019 21:00:00” — поиск за определённый промежуток времени;
•	MessageSubject — поиск по теме сообщения;
•	EventID – поиск по коду события сервера (как правило используются коды RECEIVE, SEND, FAIL, DSN, DELIVER, BADMAIL, RESOLVE, EXPAND, REDIRECT, TRANSFER, SUBMIT, POISONMESSAGE, DEFER);
•	messageID – трекинг письма по его ID.
Get-MessageTrackingLog -Sender "dbpetrov@winitpro.ru" -Recipients "aksimonova@winitpro.ru" -ResultSize unlimited –server msk-hub-01| Select-Object Timestamp,Sender,{$_.recipients},MessageSubject | Export-Csv-Path "C:\ps\exchange\msg_tracking_out.csv" -Encoding Default -Delimiter ";"
***
Блокировка адресов и доменов отправителей в Exchange
	On-premises Exchange Server	Exchange Online (Microsoft 365)
Фильтры антиспам агента Sender Filter	+	
Блокировка отправителей с помощью транспортных правил (mailflow rules)	+	+
Индивидуальные списки заблокированных адресов в почтовых ящиках	+	+
Список разрешенных доменов и адресов (Tenant Allow/Block List)		+

Enable-TransportAgent "Recipient Filter Agent"
тобы активировать фильтр, выполните:
Set-SenderFilterConfig -Enabled $true
Если нужно фильтровать только внешних отправителей, выполните:
Set-SenderFilterConfig -ExternalMailEnabled $true
Теперь вы можете указать список e-mail адресов, которых нужно заблокировать.
Set-SenderFilterConfig -BlockedSenders info@spam.ru,admin@baddomain.ru
Чтобы заблокировать все письма с определенных доменов и всех поддоменов:
Set-SenderFilterConfig -BlockedDomainsAndSubdomains spammer.com,masssend.net
Чтобы получить список заблокированных адресов, выполните команду:
Get-SenderFilterConfig |fl BlockedSenders,BlockedDomains,BlockedDomainsAndSubdomains
Вывести список всех заблокированных адресов:
Get-SenderFilterConfig |fl BlockedSenders,BlockedDomains,BlockedDomainsAndSubdomains
Если нужно добавить в список заблокированных доменов/адресов новые записи, воспользуйтесь такой конструкцией:
Set-SenderFilterConfig -BlockedSenders @{Add=”new@mail.ru”}
Или
Set-SenderFilterConfig -BlockedDomainsAndSubdomains @{Add=”blokme.ru”,”spammers.com”,”fb.com”}
$list1 = @('contoso.com','contoso2.com',)
New-TransportRule -Name "block_sender_domain" -RecipientAddressMatchesPatterns $list1 RejectMessageEnhancedStatusCode '5.7.1' -RejectMessageReasonText "Blocked recipients"
Вывести информацию о транспортном правиле:
Get-TransportRule block_sender_domain | select name,State,SenderDomainIs,RejectMessageReasonText

Set-MailboxJunkEmailConfiguration -Identity avpetrov –BlockedSendersandDomains @{Add=”new@mail.ru”}
Настройка белого списка отправителей и доменов в Exchange
Get-ContentFilterConfig | Format-List Enabled, ExternalMailEnabled, InternalMailEnabled
Outlook 2016/2013 постоянно запускается в автономном режиме
Что еще мы проверяли при диагностике этой проблемы:
1.	Доступность ящика через веб-интерфейса OWA: ящик доступен;
2.	В Exchange 2010 нужно проверить доступность CAS сервера от пользователя по порту TCP/135 (RPC-локатор). Можно выполнить с помощью командлета Test-NetConnection: tnc msg-cas –port 135 – порт доступен. В Exchange 2013/2016 в качестве основного протокола подключения клиентов Outlook к CAS является HTTPS (MAPI over HTTP), поэтому достаточно проверить доступность порта 443.
3.	Запускали Outlook в безопасном режиме (команда outlook.exe /safe) и отключали все надстройки: проблема сохранялась;
4.	Пытались удалять, профиль Outlook и пересоздавать его заново. Выполняли переустановку и Repair Outlook – все это не помогало.
Решение проблемы оказалось неожиданным: у всех пользователей, у которых Outlook запускался в офлайн режиме был установлен мессенджер Skype for Business(Lync). Оказалось, что, если на компьютере одновременно запущены Lync и Outlook, то когда вы изменяете настройки Автономного режима, они не сохраняются после закрытия Outlook (Lync каким-то образом блокирует сохранение настройки автономной работы, видимо потому что также держит постоянное подключение с Exchange).
