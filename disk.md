Chkdsk: проверка жесткого диска на ошибки в Windows
chkdsk E: /F /R /x
Данная команда:
•	Выполнит проверку диска E:\
•	Исправит автоматически найденные ошиьки (/F)
•	Попытаться восстановить данные при обнаружении поврежденных секторов, она попытается восстановить информации (/R).
•	атрибут /X в команде chkdsk. В этом случае Windows принудительно закрое все открытые файловые дескрипторы
Get-WinEvent -FilterHashTable @{logname="Application"; id="1001"}| ?{$_.providername –match "wininit"} | fl timecreated, message
notepad.exe "c:\System Volume Information\Chkdsk\Chkdsk20231129072214.log"
**************
