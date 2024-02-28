Как работает DHCP
1) DHCPDISCOVER — клиент шлет широковещательный пакет DHCPDISCOVER, пытаясь найти сервер DHCP в сети, в случаях, когда сервер DHCP не нашелся в той же подсети, что и клиент, нужно настраивать на сетевых устройствах (маршрутизаторах) DHCP Relay Agent, в целях передачи пакета DHCPDISCOVER на сервер DHCP.
2) DHCPOFFER — сервер DHCP шлет широковещательный пакет DHCPOFFER для клиента, который включает предложение использовать уникальный IP адрес.
3) DHCPREQUEST — клиент шлет широковещательный пакет DHCPREQUEST на сервер DHCP с ответом, и «просит» у сервера выдать в аренду предложенный уникальный адрес.
4) DHCPACK — сервер DHCP шлет клиенту широковещательный пакет DHCPACK, в этот пакете сервером утверждается запрос клиента на использование IP-адреса, а также сообщаются и другие детали, такие, как сервера DNS, шлюз по умолчанию, и т.д. Если сервер не может предоставить запрашиваемый адрес или по каким-то причинам адрес недействителен, сервер посылает пакет DHCPNACK.
*****************
Миграция DHCP сервера на Windows Server
Add-WindowsFeature -IncludeManagementTools dhcp
Add-DhcpServerInDC -DnsName srv-dhcp2012.winitpro.ru -IPAddress 192.168.10.22
Export-DhcpServer -ComputerName srv-dhcp2008.winitpro.ru -File C:\DHCP\w2008dhcpconfig.xml -verbose
Import-Dhcpserver –ComputerName srv-dhcp2012.winitpro.ru  -File C:\DHCP\w2008dhcpconfig.xml -BackupPath C:\ DHCP\backup\ -verbose
*****************
