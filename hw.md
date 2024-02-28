Сброс пароля администратора в HP ILO
hponcfg.exe /w current_config.xml
<ribcl VERSION="2.0">
<login USER_LOGIN="Administrator" PASSWORD="password">
<user_INFO MODE="write">
<mod_USER USER_LOGIN="Administrator">
<password value="NewPassword"/>
</mod_USER>
</user_INFO>
</login>
</ribcl>
hponcfg.exe /f reset_admin_password.xml /l hplog.txt
