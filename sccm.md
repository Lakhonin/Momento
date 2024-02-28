Порты, используемые SCCM Remote Tools
1.	TCP порт 135
2. TCP/UDP порт 2701
3. TCP/UDP порт 2702
*************
Remote Control 
Параметры удаленного подключения, определенные политикой SCCM находятся в разделе реестра HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control.
что для возможности удаленного подключения к компьютерам через Remote Control должны быть открыты следующие порты:
•	TCP – 135
•	TCP – 2701
•	TCP – 2702
•	UDP – 2701
•	UDP – 2702
Информация обо всех удаленных подключения сохраняется с специальных логах, которые хранятся как на стороне сервера, так и на клиенте:
•	SCCM Site сервер — [System Drive]\Users\[UserName]\Documents\Remote Application Logs
•	Клиент SCCM — [System Drive]\Users\[UserName]\Documents\Remote Application Logs
