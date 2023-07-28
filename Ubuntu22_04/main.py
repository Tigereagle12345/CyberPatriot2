import os
import argparse
import sys
import platform
import subprocess
import psutil
from crontab import CronTab
import pexpect
import re

#----- Classes -----
# Logger
class Log():
    def __init__(self):
        self.HEADER = '\033[95m'
        self.NORMALWHITE = '\033[0m'
        self.OKBLUE = '\033[94m'
        self.OKCYAN = '\033[96m'
        self.OKGREEN = '\033[92m'
        self.WARNING = '\033[93m'
        self.FAIL = '\033[91m'
        self.ENDC = '\033[0m'
        self.BOLD = '\033[1m'
        self.UNDERLINE = '\033[4m'
        self.level = 0

    def done(self, text):
        if self.level < 1:
            print(f"{self.OKGREEN}{text}")
            print(f"{self.NORMALWHITE}", end="")

    def text(self, text):
        if self.level < 2:
            print(f"{self.OKCYAN}{text}")
            print(f"{self.NORMALWHITE}", end="")

    def head(self, text):
        if self.level < 3:
            print(f"{self.HEADER}{text}")
            print(f"{self.NORMALWHITE}", end="")
    
    def warn(self, text):
        if self.level < 4:
            print(f"{self.WARNING}{text}")
            print(f"{self.NORMALWHITE}", end="")
        
    def error(self, text):
        if self.level < 5:
            print(f"{self.FAIL}{text}")
            print(f"{self.NORMALWHITE}", end="")

    def updateLevel(self, level="debug"):
        if level == "debug":
            self.level = 0
        elif level == "normal":
            self.level = 1
        elif level == "head":
            self.level = 2
        elif level == "warn":
            self.level = 3
        elif level == "error":
            self.level = 4
        else:
            self.level == 0
            log.error("Please provide a logging level!\nOptions:\n-'done'\n-'text'\n-'head'\n-'warn'\n-'error'")

#----- End Of Classes -----

# ----- System Variables -----
# Create Argparse Parser
parser = argparse.ArgumentParser(description="Secure an OS for the CyberPatriot Competition.")

# Add Arguments

# Add Verbose Option
parser.add_argument("-v", "--verbose", action="store_true", help="Log all messages.")
parser.add_argument("-u", "--userfile", type=str, help="Sets the userfile. Default is users.txt.")
parser.add_argument("-a", "--adminfile", type=str, help="Sets the adminfile. Default is admins.txt.")

args = parser.parse_args()


# Create Logger
log = Log()
if args.verbose:
    log.updateLevel("debug")

CURR_DIR = sys.path[0]
SYSTEM = platform.platform()

print(SYSTEM)
    
WINDOWS = "windows" in SYSTEM.lower()
LINUX = "linux" in SYSTEM.lower()
OSTYPE = (WINDOWS, LINUX)

if args.userfile:
    if os.path.isfile(args.userfile):
        USERFILE = args.userfile
    else:
        USERFILE = os.path.join(CURR_DIR, "users.txt")
else:
    USERFILE = os.path.join(CURR_DIR, "users.txt")

if args.adminfile:
    if os.path.isfile(args.adminfile):
        ADMINFILE = args.adminfile
    else:
        ADMINFILE = os.path.join(CURR_DIR, "admins.txt")
else:
    ADMINFILE = os.path.join(CURR_DIR, "admins.txt")

try:
    USERS = psutil.users()
    USERNAMES = [user.name for user in USERS]
except:
    USERS, USERNAMES = False

MASTER_PASSWORD = "mT80F0!t07zCg@D#"

CURR_USER = os.getlogin()

# Print Script Password
log.error(f"IMPORTANT: Automatic password used by the script is: {MASTER_PASSWORD}")

#----- End Of System Variables -----

# Start Script
def answer(text, log):
    YES = ["Y", "y", "YES", "Yes", "yes"]
    NO = ["N", "n", "NO", "No", "no"]
    
    proceed = input(log.warn(f"{text} Y/N\n"))
    if proceed in YES:
        retbool = True
    elif proceed in NO:
        retbool = False
    else: 
        answer(text, log)
    return retbool

def pause(log):
    cont = input(log.warn("Press anything to continue: "))

def mainScript(log, CURR_DIR, USERS, USERNAMES, OSTYPE, USERFILE, ADMINFILE, MASTER_PASSWORD):
    WINDOWS = OSTYPE[0]
    LINUX = OSTYPE[1]
    print(WINDOWS)
    print(LINUX)
    if LINUX:
        log.head("Starting Ubuntu Script...")
        ubuntu2204(log, CURR_DIR, USERS, USERNAMES, USERFILE, ADMINFILE, OSTYPE, MASTER_PASSWORD)
    elif WINDOWS:
        sys.exit(log.error("Windows is not currently supported!"))
    else:
        if answer("OS Unknown, Continue with Ubuntu?", log):
            OSTYPE[1] = True
            if os.getuid() == 0:
                ubuntu2204(log, CURR_DIR, USERS, USERNAMES, USERFILE, ADMINFILE, OSTYPE, MASTER_PASSWORD)
            else:
                sys.exit(log.error("This Script Requires Root Priveledges!"))
        else:
            sys.exit(log.error("Ok then, exiting!"))

#----- UBUNTU 22.04 -----

# Start Script for Ubuntu
def ubuntu2204(log, CURR_DIR, USERS, USERNAMES, USERFILE, ADMINFILE, OSTYPE, MASTER_PASSWORD):
    # Configure dpkg
    os.system("dpkg --configure -a")

    # Add Google's DNS To Fix Potential DNS Server Issues (Disabled: Can be found in ./fix-apt.sh)
    #os.system("""echo "nameserver 8.8.8.8" | sudo tee /etc/resolvconf/resolv.conf.d/base > /dev/null""")

    # Refresh apt repositories
    log.text("Refreshing/Reinstalling default apt repositories...")

    log.text("Installing dependancies for add-apt-repository...")
    os.system("apt install software-properties-common -y")

    log.text("Installing 'main' repository...")
    os.system("add-apt-repository main -y")
    log.done("Done!")

    log.text("Installing 'universe' repository...")
    os.system("add-apt-repository universe -y")
    log.done("Done!")

    log.text("Installing 'restricted' repository...")
    os.system("add-apt-repository restricted -y")
    log.done("Done!")

    log.text("Installing 'multiverse' repository...")
    os.system("add-apt-repository multiverse -y")
    log.done("Done!")

    log.done("Apt repositories refreshed!")

    # Update Ubuntu 22.04
    update(log)

    # Install Dependancies
    installDep(log)

    # Authenticate users and user permissions
    authUsers(log, USERS, USERNAMES, USERFILE, OSTYPE)
    GROUPS = authAdmins(log, ADMINFILE, OSTYPE)

    # Enable and setup firewall
    ufw(log)

    # Disable booting unwanted filesystems
    disableModules(log)

    # Ensure /tmp is a seperate partition
    log.text("Ensuring /tmp is a seperate partition...")
    os.system("systemctl unmask tmp.mount")
    with open("/etc/fstab", "a") as file:
        file.write("\ntmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 00")
    log.done("/tmp is a seperate partition!")

    # Disable Automounting
    log.text("Disabling automounting...")
    os.system("apt purge autofs -y")
    log.done("Automounting disabled!")

    # Install and configure AIDE
    aide(log, CURR_DIR)

    # Set bootloader password
    bootloaderPass(log, MASTER_PASSWORD, CURR_DIR)

    # Disable root account
    log.text("Disabling root account...")
    os.system("passwd root -l")
    log.done("Root account disabled!")

    # Ensure address space layout randomization (ASLR) is enabled
    log.text("Ensuring ASLR is enabled")
    with open("/etc/sysctl.conf", "a") as file:
        file.write("\nkernel.randomize_va_space = 2")
    os.system("sysctl -w kernel.randomize_va_space=2")
    log.done("ASLR is enabled!")

    # Ensure prelink is not installed
    log.text("Ensuring prelink is not installed...")
    os.system("prelink -ua")
    os.system("apt purge prelink -y")
    log.done("Prelink uninstalled!")

    # Uninstall Automatic Error Reporting
    log.text("Uninstalling Automatic Error Reporting...")
    os.system("apt purge apport -y")
    log.done("Automatic Error Reporting uninstalled!")

    # Ensure coredumps are restricted
    restrictCoredumps(log)

    # AppArmour
    appArmour(log)

    # Remove MOTD
    log.text("Removing the MOTD...")
    os.remove("/etc/motd")
    log.done("Removed MOTD!")

    # Configure warning banners
    warningBanner(log)

    # Configure Gnome Display Manager
    gdm(log)

    # Ensure XDCMP is not enabled
    log.text("Ensuring XDCMP is not enabled...")
    with open("/etc/gdm3/custom.conf", "w") as file:
        file.write(file.read().replace("Enable=true", ""))
    log.done("Ensured XDCMP is not enabled!")

    # Install and configure chrony
    chrony(log)

    # Disable xserver
    delServices(log)

    # Remove rsync
    log.text("Uninstalling rsync...")
    os.system("apt purge rsync -y")
    log.done("Rsync uninstalled!")

    # Remove rsh
    log.text("Uninstalling rsh...")
    os.system("apt purge rsh-client -y")
    log.done("Rsh uninstalled!")

    # Disable uncommon network protocols
    uncommonNetProtocols(log)

    # Set IP rules
    ipRules(log)

    # Audit
    audit(log, CURR_DIR)

    # Cron
    cron(log)

    # SSH
    ssh(log)

    # Disable the su command
    # To re-enable it, either remove the line "auth required pam_wheel.so use_uid group=sugroup" from the /etc/pam.d/su file
    # or add users to the group "sugroup"
    log.text("Disabling the su command...")
    with open("/etc/pam.d/su", "a") as file:
        file.write("\nauth required pam_wheel.so use_uid group=sugroup")
    log.done("Su command disabled!")

    # Configure password settings
    passwd(log, CURR_DIR, USERS, USERNAMES, MASTER_PASSWORD)

    # Find unowned files
    log.text("Finding unowned files...")
    result = subprocess.run(["find", "/", "-nogroup", "-nouser"], stdout=subprocess.PIPE).split("\n")
    log.warn("These files are unowned:")
    with open(os.path.join(CURR_DIR, "/output/unownedFiles.txt"), "w") as output:
        for file in result:
            log.warn("\n"+file)
            output.write("\n"+file)
    log.warn(f"Files can be found in {os.path.join(CURR_DIR, '/output/unownedFiles.txt')}")
    pause(log)

    # Ensure all users have a home directory
    for user in USERS:
        if user.pid > 999:
            if not os.path.isdir(f"/home/{user.name}"):
                log.text(f"Creating a home directory for {user.name}...")
                os.mkdir(f"/home/{user.name}")
                log.done(f"Created a home directory for {user.name}!")

    # Set permissions on files
    permissions(log)

    # Remove unauthorized .netrc, .forward, .rhost files
    log.text("Removing unauthorized .netrc, .forward and .rhost files...")
    for user in USERNAMES:
        if os.path.isdir(f"/home/{user}"):
            # .netrc
            if os.path.exists(f"/home/{user}/.netrc"):
                if answer(f"Should /home/{user}/.netrc exist?"):
                    os.system(f"chmod 600 /home/{user}/.netrc")
                else:
                    os.remove(f"/home/{user}/.netrc")
            # .forward
            if os.path.exists(f"/home/{user}/.forward"):
                if answer(f"Should /home/{user}/.forward exist?"):
                    os.system(f"chmod 600 /home/{user}/.forward")
                else:
                    os.remove(f"/home/{user}/.forward")
            # .rhost
            if os.path.exists(f"/home/{user}/.rhost"):
                if answer(f"Should /home/{user}/.rhost exist?"):
                    os.system(f"chmod 600 /home/{user}/.rhost")
                else:
                    os.remove(f"/home/{user}/.rhost")
    log.done("Removed unauthorized .netrc, .forward and .rhost files!")
    
    # Manage users
    userMng(log, USERNAMES, USERS)
    
    # Manage groups
    groupMng(log, USERS)

    # Confgure Firefox settings
    if answer("Is firefox installed?", log):
        firefox(log, USERS, CURR_DIR)

# ----- Functions -----
# Confgure Firefox settings
def firefox(log, USERS, CURR_DIR):
    log.text("Updating firefox...")
    os.system("apt update -y")
    log.done("Done!")

    if answer("Should firefox be installed as a snap package?", log):
        os.system("snap install firefox")
        os.system("apt update -y")
        os.system("apt install firefox -y")
        log.done("Firefox is installed as a snap package!")

        loc = "/snap/firefox/1635/usr/lib/firefox/"
    else:
        log.text("Configuring files...")
        os.system("add-apt-repository ppa:mozillateam/ppa -y")
        with open("/etc/apt/preferences.d/mozilla-firefox", "w") as file:
            file.write("Package: *\nPin: release o=LP-PPA-mozillateam\nPin-Priority: 1001")
        with open("/etc/apt/apt.conf.d/51unattended-upgrades-firefox", "w") as file:
            file.write('Unattended-Upgrade::Allowed-Origins:: "LP-PPA-mozillateam:${distro_codename}";')
        log.done("Done!")

        log.text("Removing the firefox snap package...")
        os.system("snap remove firefox")
        log.done("Firefox snap package removed!")
        
        log.text("Installing firefox as a .deb package...")
        os.system("apt install firefox -y")
        log.done("Firefox installed!")

        loc = "/usr/lib/firefox/"
    
    profiles = []
    for user in USERS:
        if user.pid > 999:
            if os.path.isdir(f"/home/{user.name}"):
                if os.path.isfile(f"/home/{user.name}/snap/firefox/common/.mozilla/firefox/profiles.ini"):
                    for line in open(f"/home/{user.name}/snap/firefox/common/.mozilla/firefox/profiles.ini", "rb").read():
                        if "Path=" in line:
                            profiles.append(os.path.join(f"/home/{user.name}/snap/firefox/common/.mozilla/firefox/", line.replace("Path=", "", 1)))

    for profile in profiles:
        with open(os.path.join(CURR_DIR, "/config/user.js")) as source:
                if os.path.isfile(os.path.join(profile, "/user.js")):
                    with open(profile, "a") as file:
                        file.write(source.read())
                else:
                    with open(profile, "w") as file:
                        file.write(source.read())
        
    with open(os.path.join(CURR_DIR, "/config/local-settings.js"), "rb") as source:
        with open(os.path.join(loc, "/defaults/pref/local-settings.js"), "w") as file:
            file.write(source.read())

    with open(os.path.join(CURR_DIR, "/config/mozilla.cfg"), "rb") as source:
        with open(os.path.join(loc, "mozilla.cfg"), "w") as file:
            file.write(source.read())

# Manage users
def userMng(log, USERNAMES, USERS, MASTER_PASSWORD):
    addUser(log, USERNAMES, USERS, MASTER_PASSWORD)
    delUser(log, USERNAMES)

# Add Users
def addUser(log, USERNAMES, USERS, MASTER_PASSWORD):
    log.warn("Users: ")
    for user in USERS:
        if user.pid > 999:
            log.warn(user.name)
    if answer("Add a new user?", log):
        name = input(log.warn("Type new username: "))
        if name in USERNAMES:
            log.error("Username already taken!")
            addUser(log, USERNAMES, USERS, MASTER_PASSWORD)
        else:
            os.system(f"useradd -m {name}")
            process = pexpect.spawn(f"passwd {name}")
            process.expect("New password: ")
            process.sendline(MASTER_PASSWORD)
            process.expect("Retype new password: ")
            process.sendline(MASTER_PASSWORD)
            log.done(f"Added new user {name}!")
            addUser(log, USERNAMES, USERS, MASTER_PASSWORD)

def delUser(log, USERNAMES):
    log.warn("Users: ")
    for user in USERS:
        if user.pid > 999:
            log.warn(user.name)
    if answer("Delete a user?", log):
        name = input(log.warn("Type user to delete: "))
        if name in USERNAMES:
            os.system(f"deluser {name}")
            log.done(f"{user} deleted!")
            if answer("Delete home directory?", log):
                os.remove(f"/home/{name}")
                log.done("Home directory deleted!")
            delUser(log, USERNAMES)
        else:
            log.error("User does not exist!")
            addUser(log, USERNAMES)
        

# Manage groups
def groupMng(log, USERS):
    GROUPS = {}
    with open("/etc/group", "rb") as file:
        for line in file.read():
            GROUPS[line.split(":")[0]]
            GROUPS[line.split(":")[0]]["Users"] = line.split(":")[3]
    addGroup(log, GROUPS)
    delGroup(log, GROUPS)
    modGroupMem(log, GROUPS, USERS)


# Add groups
def addGroup(log, GROUPS):
    log.warn("Groups: ")
    for group in GROUPS.keys():
        log.warn(group)
    if answer("Add a new group?", log):
        group = input(log.warn("Type new groupname: "))
        if group in GROUPS.keys():
            log.error("Group already exists!")
            addGroup(log, GROUPS)
        else:
            os.system(f"groupadd {group}")
            log.done(f"Added group {group}!")
            addGroup(log, GROUPS)

# Delete groups
def delGroup(log, GROUPS):
    log.warn("Groups: ")
    for group in GROUPS.keys():
        log.warn(group)
    if answer("Delete a group?", log):
        group = input(log.warn("Type group to delete: "))
        if group in GROUPS.keys():
            os.system(f"groupdel {group}")
            log.done(f"Deleted group {group}!")
            addGroup(log, GROUPS)
        else:
            log.error("Group doesn't exist!")
            addGroup(log, GROUPS)

# Modify group membership
def modGroupMem(log, GROUPS, USERS):
    normUsers = []
    for user in USERS:
        if user.pid > 999:
            normUsers.append(user.name)

    log.warn("Groups: ")
    for group in GROUPS.keys():
        log.warn(f"{group}: {GROUPS[group]['Users']}")
    if answer("Modify members of a group?", log):
        run = True
        while run:
            if answer("Add users to a group?", log):
                run = False
                group = input(log.warn("Add a user to which group? "))
                if group in GROUPS.keys():
                    log.warn("Users: ")
                    for user in normUsers:
                        log.warn(user)
                    user = input(f"Add which user to {group}? ")
                    if user in normUsers:
                        os.system(f"usermod -a - {group} {user}")
                    else:
                        log.error("User doesn't exist!")
                else:
                    log.error(f"Group {group} doesn't exist!")
                    modGroupMem(log, GROUPS, USERS)
            elif answer("Remove users from a group?", log):
                run = False
                group = input(log.warn("Remove a user from which group? "))
                if group in GROUPS.keys():
                    log.warn("Users: ")
                    for user in normUsers:
                        log.warn(user)
                    user = input(f"Remove which user from {group}? ")
                    if user in normUsers:
                        os.system(f"deluser {user} {group}")
                    else:
                        log.error("User doesn't exist!")

# Set permissions on files
def permissions(log):
    # Set permissions on /etc/passwd, /etc/passwd-, /etc/group, /etc/group-
    files1 = ["/etc/passwd", "/etc/passwd-", "/etc/group", "/etc/group-"]
    for file in files1:
        log.text(f"Setting permissions on {file}...")
        os.system(f"chown root:root {file}")
        os.system(f"chmod u-x,go-wx {file}")
        log.done(f"Set permissions on {file}!")

    # Set permissions on /etc/shadow, /etc/shadow-, /etc/gshadow, /etc/gshadow-
    files2 = ["/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-"]
    for file in files2:
        log.text(f"Setting permissions on {file}...")
        os.system(f"chown root:root {file}")
        os.system(f"chmod u-x,g-wx,o-rwx {file}")
        log.done(f"Set permissions on {file}!")
    
    for user in USERS:
        if user.pid > 999:
            if os.path.isdir(f"/home/{user.name}"):
                os.system(f"chmod g-w,o-rwx /home/{user.name}")

# Configure password settings
def passwd(log, CURR_DIR, USERS, USERNAMES, MASTER_PASSWORD):
    # Installing PAM (Pluggable Authentication Module)
    log.text("Installing PAM...")
    os.system("apt install libpam-pwquality -y")
    log.done("Done!")

    # Setting password complexity requirements according to the CIS Benchmark for Ubuntu 22.04
    log.text("Setting password complexity requirements...")
    with open("/etc/security/pwquality.conf", "a") as file:
        file.write("\nminlen = 14")
    log.done("Password complexity requirements set!")

    # Enable lockout for failed password attempts
    log.text("Enabling lockout for failed password attempts...")
    with open("/etc/pam.d/common-auth", "w") as file:
        with open(os.path.join(CURR_DIR, "/config/common-auth"), "rb") as source:
            file.write(source.read())
    with open("/etc/pam.d/common-account", "a") as file:
        file.write("account required pam_faillock.so")
    log.done("Lockout for failed password attempts enabled!")
    
    # Disable password reuse to the last 5 passwords
    log.text("Disabling password reuse...")
    # Set in the /etc/pam.d/common-auth file above
    log.done("Users cannot reuse their last 5 passwords!")

    # Configure failock
    log.text("Configuring faillock...")
    with open("/etc/security/faillock.conf", "a") as file:
        # Disable the lockout with the command "/usr/sbin/faillock --user username --reset"
        file.write("\ndeny = 4\nfail_interval = 900\nunlock time = 600")
    log.done("Faillock configured!")

    # Ensure password hashing algorithm is set to yescrypt (Latest recommended standards as of writing at 27/7/23)
    log.text("Setting hashing algorithm to yescrypt...")
    with open("/etc/pam.d/common-password", "w") as file:
        with open(os.path.join(CURR_DIR, "/config/common-password"), "rb") as source:
            file.write(source.read())
    log.done("Hashing algorithm set to yescrypt")

    # Update user passwords
    try:
        USERNAMES.remove("root")
        USERNAMES.remove("syslog")
    except:
        pass
    for user in USERNAMES:
        if answer(f"Change password for {user} to the master password?", log):
            log.text(f"Changing {user}'s password...")
            process = pexpect.spawn(f"passwd {user}")
            process.expect("New password: ")
            process.sendline(MASTER_PASSWORD)
            process.expect("Retype new password: ")
            process.sendline(MASTER_PASSWORD)
            log.done(f"{user}'s password changed to the master password (mT80F0!t07zCg@D#)!")
        elif answer(f"Change password for {user} manually?", log):
            run = True
            while run:
                password = input(log.warn("Type new password (Master password is mT80F0!t07zCg@D#): "))
                if answer(f"Should {user}'s password be changed to {password}?", log):
                    run = False
                    log.text(f"Changing {user}'s password...")
                    process = pexpect.spawn(f"passwd {user}")
                    process.expect("New password: ")
                    process.sendline(password)
                    process.expect("Retype new password: ")
                    process.sendline(password)
                    log.done(f"{user}'s password changed to the your password ({password}])!")
                else:
                    log.text("Ok, trying again...")

    # Configure /etc/login.defs
    log.text("Configuring /etc/login.defs...")
    with open("/etc/login.defs", "w") as file:
        with open(os.path.join(CURR_DIR, "/config/login.defs")) as source:
            file.write(source.read())

    os.system("useradd -D -f 30")
    # Ensure default group for the root account is GID 0
    os.system("usermod -g 0 root")

    #Ensure default user umask is 027 or more restrictive
    with open("/etc/pam.d/common-session", "w") as file:
        with open(os.path.join(CURR_DIR, "/config/common-session"), "rb") as source:
            file.write(source.read())

    # Ensure system accounts are secured
    SYSUSERS = []
    for user in USERS:
        if user.pid < 1000:
            SYSUSERS.append(user.name)
    for user in ["root", "sync", "shutdown", "halt"]:
        SYSUSERS.remove(user)
    for user in SYSUSERS:
        os.system(f"usermod -s $(which nologin) {user}")
        os.system(f"usermod -L {user}")

    try:
        USERNAMES.remove("root")
        USERNAMES.remove("syslog")
    except:
        pass
    for user in USERNAMES:
        os.system(f"chage --mindays 1 {user}")
        os.system(f"chage --maxdays 365 {user}")
        os.system(f"chage --warndays 7 {user}")
        os.system(f"chage --inactive 30 {user}")
    log.done("Minimum days between changing passwords is set to 1!")
    log.done("Maximum password age is set to 365 days!")
    log.done("Password expiry warnings are set to 7 days!")
    log.done("Accounts that have been inactive for 30 days will be locked!")
    log.done("System accounts are secured!")
    log.done("Default group for the root acount is GID 0!")
    log.done("Default user umask is 027 or more restrictive!")
    log.done("/etc/login.defs is now configured!")

    # Remove all users from the shadow groups
    log.text("Removing users from the shadow group...")
    with open("/etc/group", "w") as file:
        textList = file.read()
        text = ""
        for group in textList:
            if "shadow:x:" in group:
                group = "shadow:x:42:"
            text = "\n"+group
        file.write(text)
    log.done("Removed all users from the shadow group!")

def ssh(log):
    # Check if SSH should be installed
    if answer("Should SSH be installed?", log):
        # Allow SSH through the firewall
        log.text("Allowing SSH through the firewall...")
        os.system("ufw allow ssh")
        log.done("Allowed SSH through the firewall!")

        # Set permissions on /etc/ssh/sshd_config
        log.text("Setting permissions on /etc/ssh/sshd_config...")
        os.system("chown root:root /etc/ssh/sshd_config")
        os.system("chmod og-rwx /etc/ssh/sshd_config")
        log.done("Set permissions on /etc/ssh/sshd_config")

        with open("/etc/ssh/sshd_config", "a") as file:
            # Set SSH log level to verbose
            log.text("Setting SSH log level to verbose...")
            file.write("\nLogLevel VERBOSE")
            log.done("Set SSH log level to verbose!")

            # Use PAM with SSH
            log.text("Using PAM with of SSH...")
            file.write("\nUsePAM yes")
            log.done("Now using PAM with SSH!")

            # Disable root login for SSH
            log.text("Disabling root login for SSH...")
            file.write("\nPermitRootLogin no")
            log.done("Disabled root login for SSH!")

            # Disable Host Based Authentication
            log.text("Disabling Host Based Authentication...")
            file.write("\nHostbasedAuthentication no")
            log.done("Disabled Host Based Authentication!")

            # Disable empty passwords
            log.text("Disabling empty passwords...")
            file.write("\nPermitEmptyPasswords no")
            log.done("Disabled empty passwords!")

            # Disable User Environment
            log.text("Disabling User Environment...")
            file.write("\nPermitUserEnvironment no")
            log.done("Disabled User Environment!")

            # Ignore Rhosts
            log.text("Ignoring Rhosts...")
            file.write("\nIgnoreRhosts yes")
            log.done("Rhosts will be ignored!")

            # Disable X11 Forwarding
            log.text("Disabling X11 Forwarding...")
            file.write("\nX11Forwarding no")
            log.done("Disable X11 Forwarding!")

            # Use only approved ciphers
            log.text("Adding list of approved ciphers...")
            file.write("\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr")
            log.done("Only approved ciphers will be used!")

            # Use only approved MACs
            log.text("Adding list of approved MACs...")
            file.write("\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256")
            log.done("Only approved MACs will be used!")

            # Use only strong Key Exchange algorithms
            log.text("Using only strong Key Exchange algorithms...")
            file.write("\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256")
            log.done("Will use only strong Key Exchange algorithms!")

            # Disable Tcp Forwarding
            log.text("Disabling Tcp Forwarding...")
            file.write("\nAllowTcpForwarding no")
            log.done("Disable Tcp Forwarding!")

            # Set SSH warning banner
            log.text("Setting SSH warning banner...")
            file.write("\nBanner /etc/issue.net")
            log.done("Set SSH warning banner!")

            # Set max authentication tried to 4
            log.text("Setting max authentication tried to 4...")
            file.write("\nMaxAuthTries 4")
            log.done("Set max authentication tried to 4!")

            # Set max startups to 10:30:60
            log.text("Setting max startups to 10:30:60...")
            file.write("\nMaxStartups 10:30:60")
            log.done("Set max startups to 10:30:60!")

            # Set max sessions to 10
            log.text("Setting max sessions to 10...")
            file.write("\nMaxSessions 10")
            log.done("Set max sessions to 10!")

            # Set login grace time to 1 minute
            log.text("Setting login grace time to 1 minute...")
            file.write("\nLoginGraceTime 60")
            log.done("Set login grace time to 1 minute!")

            # Configure idle timeout interval
            log.text("Configuring idle timeout interval...")
            file.write("\nClientAliveInterval 15\nClientAliveCountMax 3")
            log.done("Configure idle timeout interval!")

        # Reload SSH daemon
        log.text("Reloading the SSH daemon...")
        os.system("systemctl reload sshd")
        log.done("SSH daemon reloaded!")
    else:
        # Remove SSH
        log.text("Ok! Removing ssh...")
        os.system("apt purge openssh-server -y")
        os.system("apt purge openssh-client -y")
        log.done("SSH removed!")

# Cron
def cron(log):
    # Enable cron
    log.text("Enabling cron...")
    os.system("systemctl --now enable cron")
    log.done("Cron is enabled")

    # Set permissions on /etc/crontab
    log.text("Setting permissions on /etc/crontab...")
    os.system("chown root:root /etc/crontab")
    os.system("chmod og-rwx /etc/crontab")
    log.done("Permissions for /etc/crontab set!")

    # Set permissions on /etc/cron.hourly
    log.text("Setting permissions on /etc/cron.hourly...")
    os.system("chown root:root /etc/cron.hourly/")
    os.system("chmod og-rwx /etc/cron.hourly/")
    log.done("Permissions for /etc/cron.hourly set!")

    # Set permissions on /etc/cron.daily
    log.text("Setting permissions on /etc/cron.daily...")
    os.system("chown root:root /etc/cron.daily/")
    os.system("chmod og-rwx /etc/cron.daily/")
    log.done("Permissions for /etc/cron.daily set!")

    # Set permissions on /etc/cron.weekly
    log.text("Setting permissions on /etc/cron.weekly...")
    os.system("chown root:root /etc/cron.weekly/")
    os.system("chmod og-rwx /etc/cron.weekly/")
    log.done("Permissions for /etc/cron.weekly set!")

    # Set permissions on /etc/cron.monthly
    log.text("Setting permissions on /etc/cron.monthly...")
    os.system("chown root:root /etc/cron.monthly/")
    os.system("chmod og-rwx /etc/cron.monthly/")
    log.done("Permissions for /etc/cron.monthly set!")

    # Set permissions on /etc/cron.d
    log.text("Setting permissions on /etc/cron.d...")
    os.system("chown root:root /etc/cron.d/")
    os.system("chmod og-rwx /etc/cron.d/")
    log.done("Permissions for /etc/cron.d set!")

    # Delete the /etc/cron.deny file
    log.text("Deleting the /etc/cron.deny file...")
    os.remove("/etc/cron.deny")
    log.done("Deleted the /etc/cron.deny file!")

    # Create an /etc/cron.allow file and set permissions
    log.text("Creating an /etc/cron.allow file...")
    with open("/etc/cron.allow", "x") as file:
        file.write("")
    log.done("Created a /etc/cron.allow file!")

    log.text("Setting permissions on /etc/cron.allow...")
    os.system("chmod g-wx,o-rwx /etc/cron.allow")
    os.system("chown root:root /etc/cron.allow")
    log.done("Set permissions on /etc/cron.allow!")

    # Delete the /etc/at.deny file
    log.text("Deleting the /etc/at.deny file...")
    os.remove("/etc/at.deny")
    log.done("Deleted the /etc/at.deny file!")

    # Create an /etc/at.allow file and set permissions
    log.text("Creating an /etc/at.allow file...")
    with open("/etc/at.allow", "x") as file:
        file.write("")
    log.done("Created a /etc/at.allow file!")
    
    log.text("Setting permissions on /etc/at.allow...")
    os.system("chmod g-wx,o-rwx /etc/at.allow")
    os.system("chown root:root /etc/at.allow")
    log.done("Set permissions on /etc/at.allow!")

# Audit
def audit(log, CURR_DIR):
    log.warn("The log files are in /var/log/audit/audit.log and /var/log/sudo.log!")
    
    # Install auditd
    log.text("Installing auditd...")
    os.system("apt install auditd audispd-plugins -y")
    log.done("Done!")

    # Starting auditd
    log.text("Starting auditd...")
    os.system("systemctl --now enable auditd")
    log.done("Started auditd!")

    # Configure auditd
    log.text("Configuring auditd...")
    with open("/etc/audit/auditd.conf", "w") as file:
        fileText = file.read()

        # Set max size for log files
        log.text("Setting max size for log files...")
        if "max_log_file=" in fileText:
            re.sub(r"max_log_file=\d", "max_log_file=10")
        else:
            fileText = fileText + "\nmax_log_file=10"
        log.done("Max size for log files set to 10MB!")

        # Ensure logs are not automatically deleted
        log.text("Ensuring logs are not automatically deleted...")
        fileText = fileText + "\nmax_log_file_action = keep_logs"
        log.done("Logs will not be automatically deleted!")

        # Ensure auditd stops the system when log files are full
        log.text("Ensuring auditd stops the system when log files are full...")
        fileText = fileText + "\nspace_left_action = email\naction_mail_acct = root\nadmin_space_left_action = halt"
        log.done("Auditd will stop the system when log files are full!")

        file.write(fileText)

    # Set auditd rules
    log.text("Setting rules for auditd...")
    with open("/etc/audit/rules.d/50-scope.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-scope.rules")))
    
    with open("/etc/audit/rules.d/50-user_emulation.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-user_emulation.rules")))

    with open("/etc/audit/rules.d/50-sudo.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-sudo.rules")))
    
    with open("/etc/audit/rules.d/50-time-change.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-time-change.rules")))
    
    with open("/etc/audit/rules.d/50-system_local.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-system_local.rules")))
    
    with open("/etc/audit/rules.d/50-access.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-access.rules")))

    with open("/etc/audit/rules.d/50-identity.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-identity.rules")))
    
    with open("/etc/audit/rules.d/50-perm_mod.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-perm_mod.rules")))
    
    with open("/etc/audit/rules.d/50-mounts.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-mounts.rules")))

    with open("/etc/audit/rules.d/50-session.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-session.rules")))

    with open("/etc/audit/rules.d/50-login.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-login.rules")))
            
    with open("/etc/audit/rules.d/50-delete.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-delete.rules")))

    with open("/etc/audit/rules.d/50-MAC-policy.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-MAC-policy.rules")))

    with open("/etc/audit/rules.d/50-perm_chng.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-perm_chng.rules")))

    with open("/etc/audit/rules.d/50-priv_cmd.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-priv_cmd.rules")))

    with open("/etc/audit/rules.d/50-usermod.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-usermod.rules")))

    with open("/etc/audit/rules.d/50-kernel_modules.rules", "w") as file:
        file.write(open(os.path.join(CURR_DIR, "/config/50-kernel_modules.rules")))

    with open("/etc/audit/rules.d/99-finalize.rules", "w") as file:
        file.write("-e 2")

    os.system("augenrules --load")
    log.done("Rules for auditd set!")

    # Set permissions on log files to 640
    log.text("Setting permissions on log files to 640...")
    os.system("chmod 640 /var/log/audit/audit.log")
    os.system("chmod 640 /var/log/sudo.log")
    os.system("chgrp adm /var/log/audit/")
    os.system("chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules")
    os.system("chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules")
    os.system("chown root:root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules")
    os.system("systemctl restart auditd")
    log.done("Permissions on log files set to 640!")

def ipRules(log):
    with open("/etc/ufw/sysctl.conf", "w") as file:
        fileText = file.read()

        # Disable packet redirect sending
        log.text("Disabling packet redirect sending...")
        if "net.ipv4.conf.all.send_redirects=" in fileText:
            re.sub(r"net.ipv4.conf.all.send_redirects=\d", "net.ipv4.conf.all.send_redirects=0", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.conf.all.send_redirects=0"
        
        if "net.ipv4.conf.default.send_redirects=" in fileText:
            re.sub(r"net.ipv4.conf.default.send_redirects=\d", "net.ipv4.conf.default.send_redirects=0", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.conf.default.send_redirects=0"
        log.done("Packet redirect sending disabled!")

        # Diable IP forwarding
        log.text("Disabling IP forwarding...")
        if "net.ipv4.ip_forward=" in fileText:
            re.sub(r"net.ipv4.ip_forward=\d", "net.ipv4.ip_forward=0", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.ip_forward=0"
        
        if "net.ipv6.conf.all.forwarding=" in fileText:
            re.sub(r"net.ipv6.conf.all.forwarding=\d", "net.ipv6.conf.all.forwarding=0", fileText)
        else:
            fileText = fileText + "\nnet.ipv6.conf.all.forwarding=0"

        if "net.ipv4.conf.all.accept_source_route=" in fileText:
            re.sub(r"net.ipv4.conf.all.accept_source_route=\d", "net.ipv4.conf.all.accept_source_route=0", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.conf.all.accept_source_route=0"
        log.done("Disabled IP forwarding!")

        # Ensure source routed packets are not accepted
        log.text("Ensuring source routed packets are not accepted...")
        if "net.ipv4.conf.all.accept_source_route=" in fileText:
            re.sub(r"net.ipv4.conf.all.accept_source_route=\d", "net.ipv4.conf.all.accept_source_route=0", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.conf.all.accept_source_route=0"
        
        if "net.ipv4.conf.default.accept_source_route=" in fileText:
            re.sub(r"net.ipv4.conf.default.accept_source_route=\d", "net.ipv4.conf.default.accept_source_route=0", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.conf.default.accept_source_route=0"
        
        if "net.ipv6.conf.all.accept_source_route=" in fileText:
            re.sub(r"net.ipv6.conf.all.accept_source_route=\d", "net.ipv6.conf.all.accept_source_route=0", fileText)
        else:
            fileText = fileText + "\nnet.ipv6.conf.all.accept_source_route=0"

        if "net.ipv6.conf.default.accept_source_route=" in fileText:
            re.sub(r"net.ipv6.conf.default.accept_source_route=\d", "net.ipv6.conf.default.accept_source_route=0", fileText)
        else:
            fileText = fileText + "\nnet.ipv6.conf.default.accept_source_route=0"
        log.done("Ensured source routed packets are not accepted!")

        # Deny ICMP redirects
        log.text("Denying ICMP redirects...")
        if "net.ipv4.conf.default.secure_redirects=" in fileText:
            re.sub(r"net.ipv4.conf.default.secure_redirects=\d", "net.ipv4.conf.default.secure_redirects=0", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.conf.default.secure_redirects=0"

        if "net.ipv4.conf.all.secure_redirects=" in fileText:
            re.sub(r"net.ipv4.conf.all.secure_redirects=\d", "net.ipv4.conf.all.secure_redirects=0", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.conf.all.secure_redirects=0"
        log.done("ICMP redirects will be denied!")

        # Log suspicious packets
        log.text("Logging suspicious packets...")
        if "net.ipv4.conf.all.log_martians=" in fileText:
            re.sub(r"net.ipv4.conf.all.log_martians=\d", "net.ipv4.conf.all.log_martians=1", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.conf.all.log_martians=1"

        if "net.ipv4.conf.default.log_martians=" in fileText:
            re.sub(r"net.ipv4.conf.default.log_martians=\d", "net.ipv4.conf.default.log_martians=1", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.conf.default.log_martians=1"
        log.done("Suspicious packets will be logged!")

        # Ignore broadcast ICMP requests
        log.text("Ignoring broadcast ICMP requests...")
        if "net.ipv4.icmp_echo_ignore_broadcasts=" in fileText:
            re.sub(r"net.ipv4.icmp_echo_ignore_broadcasts=\d", "net.ipv4.icmp_echo_ignore_broadcasts=1", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.icmp_echo_ignore_broadcasts=1"
        log.done("Broadcast ICMP requests will be ignored!")

        # Ignore bogus ICMP responses
        log.text("Ignoring bogus ICMP responses...")
        if "icmp_ignore_bogus_error_responses=" in fileText:
            re.sub(r"icmp_ignore_bogus_error_responses=\d", "icmp_ignore_bogus_error_responses=1", fileText)
        else:
            fileText = fileText + "\nicmp_ignore_bogus_error_responses=1"
        log.done("Bogus ICMP responses will be ignored!")

        # Enabling Reverse Path Filtering
        log.text("Enabling Reverse Path Filtering...")
        if "net.ipv4.conf.all.rp_filter=" in fileText:
            re.sub(r"net.ipv4.conf.all.rp_filter=\d", "net.ipv4.conf.all.rp_filter=1", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.conf.all.rp_filter=1"

        if "net.ipv4.conf.default.rp_filter=" in fileText:
            re.sub(r"net.ipv4.conf.default.rp_filter=\d", "net.ipv4.conf.default.rp_filter=1", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.conf.default.rp_filter=1"
        log.done("Reverse Path Filtering enabled!")

        # Enable TCP SYN Cookies
        log.text("Enabling TCP SYN Cookies...")
        if "net.ipv4.tcp_syncookies=" in fileText:
            re.sub(r"net.ipv4.tcp_syncookies=\d", "net.ipv4.tcp_syncookies=1", fileText)
        else:
            fileText = fileText + "\nnet.ipv4.tcp_syncookies=1"
        log.done("Enabled TCP SYN Cookies!")

        # Don't accept IPv6 router advertisements
        log.text("Denying IPv6 router advertisements...")
        if "net.ipv6.conf.all.accept_ra=" in fileText:
            re.sub(r"net.ipv6.conf.all.accept_ra=\d", "net.ipv6.conf.all.accept_ra=1", fileText)
        else:
            fileText = fileText + "\nnet.ipv6.conf.all.accept_ra=1"

        if "net.ipv6.conf.default.accept_ra=" in fileText:
            re.sub(r"net.ipv6.conf.default.accept_ra=\d", "net.ipv6.conf.default.accept_ra=0", fileText)
        else:
            fileText = fileText + "\nnet.ipv6.conf.default.accept_ra=0"
        file.write(fileText)
        log.done("IPv6 router advertisements will be denied!")

# Disable uncommon network protocols
def uncommonNetProtocols(log):
    # Disable Datagram Congestion Control Protocol (DCCP)
    # Disable Stream Control Transmission Protocol (SCTP)
    # Disable Reliable Datagram Sockets (RDS)
    # Disable Transparent Inter-Process Communication (TIPC)
    protocols = ["dccp", "sctp", "rds", "tipc"]
    for protocol in protocols:
        if not os.path.exists(f"/etc/modprobe.d/{protocol}"):
            with open(f"/etc/modprobe.d/{protocol}", "x") as file:
                file.write(f"install {protocol} /bin/false")
        else:
            with open(f"/etc/modprobe.d/{protocol}", "a") as file:
                file.write(f"install {protocol} /bin/false")
            

# Delete services
def delServices(log):
    log.text("Deleting possibly dangerous services...")
    
    # Uninstall XServer
    if answer("Should XServer be installed?", log):
        log.text("Uninstalling XServer...")
        os.system("apt purge xserver-xorg* -y")
        log.text("XServer uninstalled!")

    # Uninstall Avahi Server
    if answer("Should Avahi Server be installed?", log):
        log.text("Uninstalling Avahi Server...")
        os.system("systemctl stop avahi-daaemon.service")
        os.system("systemctl stop avahi-daemon.socket")
        os.system("apt purge avahi-daemon -y")
        log.text("Avahi Server uninstalled!")

    # Uninstall CUPS
    if answer("Should CUPS (Printing driver) be installed?", log):
        log.text("Uninstalling CUPS...")
        os.system("apt purge cups -y")
        log.text("CUPS uninstalled!")

    # Uninstall DHCP Server
    if answer("Should DHCP Server be installed?", log):
        log.text("Uninstalling DHCP Server...")
        os.system("apt purge isc-dhcp-server -y")
        log.text("DHCP Server uninstalled!")

    # Uninstall LDAP Server
    if answer("Should LDAP Server be installed?", log):
        log.text("Uninstalling LDAP Server...")
        os.system("apt purge slapd -y")
        os.system("apt purge ldap-utils -y")
        log.text("LDAP Server uninstalled!")
    
    # Uninstall NFS
    if answer("Should NFS (Network File System) be installed?", log):
        log.text("Uninstalling NFS...")
        os.system("apt purge nfs-kernel-server -y")
        log.text("NFS uninstalled!")
    
    # Uninstall DNS Server
    if answer("Should DNS Server (bind9) be installed?", log):
        log.text("Uninstalling DNS Server...")
        os.system("apt purge bind9 -y")
        log.text("DNS Server uninstalled!")

    # Uninstall FTP Server
    if answer("Should FTP server be installed?", log):
        log.text("Uninstalling FPT server...")
        os.system("apt purge vsftpd -y")
        log.text("FTP server uninstalled!")
    
    # Uninstall HTTP servers
    if answer("Should HTTP server be installed?", log):
        log.text("Uninstalling HTTP server...")
        os.system("apt purge apache2 -y")
        os.system("apt purge nginx -y")
        log.text("HTTP server uninstalled!")

    # Uninstall IMAP and POP3 server
    if answer("Should IMAP and POP3 server be installed?", log):
        log.text("Uninstalling IMAP and POP3 server...")
        os.system("apt purge dovecot-imapd dovecot-pop3d -y")
        log.text("IMAP and POP3 server uninstalled!")

    # Uninstall SAMBA
    if answer("Should SAMBA be installed?", log):
        log.text("Uninstalling SAMBA...")
        os.system("apt purge samba -y")
        log.text("SAMBA uninstalled!")

    # Uninstall Squid HTTP Proxy Server
    if answer("Should Squid HTTP Proxy Server be installed?", log):
        log.text("Uninstalling Squid HTTP Proxy Server...")
        os.system("apt purge squid -y")
        log.text("Squid HTTP Proxy Server uninstalled!")

    # Uninstall SNMP Server
    if answer("Should SNMP Server be installed?", log):
        log.text("Uninstalling SNMP Server...")
        os.system("apt purge snmp -y")
        log.text("SNMP Server uninstalled!")

    # Uninstall NIS
    if answer("Should NIS be installed?", log):
        log.text("Uninstalling NIS...")
        os.system("apt purge nis -y")
        log.text("NIS uninstalled!")

    # Uninstall talk
    if answer("Should talk be installed?", log):
        log.text("Uninstalling talk...")
        os.system("apt purge talk -y")
        log.text("Talk uninstalled!")

    # Uninstall telnet
    if answer("Should telnet be installed?", log):
        log.text("Uninstalling telnet...")
        os.system("apt purge telnet -y")
        log.text("Telnet uninstalled!")

    # Uninstall RPC
    if answer("Should RPC be installed?", log):
        log.text("Uninstalling RPC...")
        os.system("apt purge rpcbind -y")
        log.text("RPC uninstalled!")

# Install and configure chrony
def chrony(log):
    log.text("Installing chrony...")
    os.system("apt install chrony -y")
    log.done("Done!")

    # Stop other time services
    log.text("Stop and remove other time services...")
    # Stop systemd-timesyncd
    log.text("Stopping systemd-timesyncd...")
    os.system("systemctl stop systemd-timesyncd.service")
    # Mask systemd-timesyncd
    os.system("systemctl --now mask systemd-timesyncd.service")
    log.done("Stopped systemd-timesyncd!")
    # Remove ntp
    log.text("Removing ntp...")
    os.system("apt purge ntp -y")
    log.done("Ntp removed!")

    # Ensure chrony is configured with authorized timeserver
    log.text("Configuring chrony with an authorized timeserver...")
    with open("/etc/chrony/chrony.conf", "a") as file:
        file.write("pool time.nist.gov iburst maxsources 4")
    os.system("systemctl restart chronyd")
    log.done("Configured chrony with an authorized timeserver!")

    # Ensure chrony is running as user_chrony
    log.text("Ensuring chrony is running as user_chrony...")
    with open("/etc/chrony/chrony.conf", "a") as file:
        file.write("user _chrony")
    log.done("Chrony is now running as user_chrony!")

    # Make sure chrony is running
    log.text("Starting chrony...")
    os.system("systemctl unmask chrony.service")
    os.system("systemctl --now enable chrony.service")
    log.done("Started chrony!")

# Configure Gnome Display Manager
def gdm(log):
    # Configure GDM login profile settings
    log.text("Configuring GDM login profile settings...")
    with open("/etc/dconf/profile/gdm", "w") as file:
        file.write("user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults")
    log.done("Configured GDM login profile settings!")

    # Setting GDM login banner message
    log.text("Configuring GDM login banner message...")
    with open("/etc/dconf/db/gdm.d/01-banner-message", "w") as file:
        file.write("[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='This system is monitered 24/7 and any intrusions will be prosecuted to the full extent of the law.'")
    log.done("Configured GDM login banner message!")

    # Disable user list on the login screen
    log.text("Disabling user list on the login screen...")
    with open("/etc/dconf/db/gdm.d/00-login-screen", "w") as file:
        file.write("[org/gnome/login-screen]\ndisable-user-list=true")
    log.done("Disabled user list on the login screen!")

    # Force the screen to lock when the user is idle
    log.text("Forcing the screen to lock when the user is idle..")
    with open("/etc/dconf/profile/user", "w") as file:
        file.write("user-db:user\nsystem-db:local")

    if not os.path.exists("/etc/dconf/db/local.d/"):
        os.mkdir("/etc/dconf/db/local.d/")
    
    with open(" /etc/dconf/db/local.d/00-screensaver", "w") as file:
        file.write("[org/gnome/desktop/session]\nidle-delay=uint32 120\n[org/gnome/desktop/screensaver]\nlock-delay=uint32 0")

    with open("/etc/dconf/db/local.d/locks/screensaver", "w") as file:
        file.write("/org/gnome/desktop/session/idle-delay\n/org/gnome/desktop/screensaver/lock-delay")
    log.done("Forced the screen to lock when the user is idle")

    # Disable USB automounting
    log.text("Disabling USB automounting...")
    with open("/etc/dconf/db/local.d/00-media-automount", "w") as file:
        file.write("cat /etc/dconf/db/local.d/00-media-automount\n[org/gnome/desktop/media-handling]\nautomount=false\nautomount-open=false")
    if not os.path.exists("/etc/dconf/db/local.d/locks"):
        os.mkdir("/etc/dconf/db/local.d/locks")
    with open("/etc/dconf/db/local.d/locks/00_automountCypat", "w") as file:
        file.write("/org/gnome/desktop/media-handling/automount\n/org/gnome/desktop/media-handling/automount-open")
    log.done("Disabled USB automounting!")

    # Ensure GDM autorun-never is enabled
    log.text("Ensuring GDM autorun-never is enabled...")
    with open("/etc/dconf/db/local.d/00-No-Automount", "w") as file:
        file.write("[org/gnome/desktop/media-handling]\nautomount=false\nautomount-open=false\nautorun-never=true")
    with open("/etc/dconf/db/local.d/locks/00-No-Automount", "w") as file:
        file.write("/org/gnome/desktop/media-handling/automount\n/org/gnome/desktop/media-handling/automount-open\n/org/gnome/desktop/media-handling/autorun-never")
    log.done("Ensured GDM autorun-never is enabled!")

    # Update GDM settings
    log.text("Updating GDM settings...")
    os.system("dconf update")
    log.done("Updated GDM settings!")

# Configure warning banners
def warningBanner(log):
    log.text("Configuring warning banner...")
    # Configure local warning banner
    log.text("Configuring local warning banner...")
    with open("/etc/issue", "w") as file:
        file.write("Authorized uses only. All activity may be monitored and reported.")
    log.done("Local warning banner configured!")
    
    # Configure remote warning banner
    log.text("Configuring remove warning banner...")
    with open("/etc/issue.net", "w") as file:
        file.write("Authorized uses only. All activity may be monitored and reported.")
    log.done("Remote warning banner configured!")

    # Configure permissions for the warning banners
    # Configure permissions for local warning banners
    log.text("Configuring permissions for local warning banners...")
    os.system("chown root:root $(readlink -e /etc/issue)")
    os.system("chmod u-x,go-wx $(readlink -e /etc/issue)")
    log.done("Configured permissions for local warning banners!")

    # Configure permissions for remote warning banners
    log.text("Configuring permissions for remote warning banners...")
    os.system("chown root:root $(readlink -e /etc/issue.net")
    os.system("chmod u-x,go-wx $(readlink -e /etc/issue.net)")
    log.done("Configured permissions for remote warning banners!")

# AppArmour
def appArmour(log):
    log.text("Installing and configuring AppArmour...")
    # Install AppArmour
    log.text("Installing AppArmour...")
    os.system("apt install apparmor -y")
    log.done("Done!")

    # Configure AppArmour
    log.text("Configuring AppArmour...")
    with open("/etc/default/grub", "w") as file:
        fileTextList = file.read().split("\n")
        if "GRUB_CMDLINE_LINUX" in fileTextList:
            for line in fileTextList:
                if "GRUB_CMDLINE_LINUX" in line:
                    line = line[:-1]
                    line = line + " audit_backlog_limit=8192 audit=1 ipv6.disable=1 apparmor=1 security=apparmor\""
        else:
            fileTextList.append("GRUB_CMDLINE_LINUX=\"apparmor=1 security=apparmor\"")
        
        fileText = ""
        for line in fileTextList:
            fileText = line+"\n"

        file.write(fileText)
    # Refresh AppArmour
    os.system("update-grub")
    log.done("AppArmour configured!")

    # Set AppArmour profiles to enforce
    log.text("Setting AppArmour profiles to enforce...")
    os.system("aa-enforce /etc/apparmor.d/*")
    log.done("AppArmour profiles set to enforce!")
    log.done("AppArmour installed and configured!")

# Ensure coredumps are restricted
def restrictCoredumps(log):
    log.text("Ensuring coredumps are restricted...")
    with open("/etc/security/limits.conf", "a") as file:
        file.write("\n* hard core 0")
    
    with open("/etc/security/limits.conf", "w") as file:
        fileText = file.read()

        if "fs.suid_dumpable = " in fileText:
            re.sub(r"fs.suid_dumpable = \d", "fs.suid_dumpable = 0", fileText)
        else:
            fileText = fileText + "\nfs.suid_dumpable = 0"

        file.write(fileText)
    os.system("sysctl -w fs.suid_dumpable=0")

    result = subprocess.run(["systemctl", "is-enabled coredump.service"], stdout=subprocess.PIPE)
    if result.stdout in ["enabled", "masked", "disabled"]:
        with open("/etc/systemd/coredump.conf", "a") as file:
            file.write("\nStorage=none\nProcessSizeMax=0")
    
    os.system("systemctl daemon-reload")
    log.done("Coredumps are now restricted!")

# Set bootloader password
def bootloaderPass(log, MASTER_PASSWORD, CURR_DIR):
    log.text("Setting bootloader password...")
    setup = pexpect.spawn("grub-mkpasswd-pbkdf2")
    setup.expect("Enter password:")
    setup.sendline(f"{MASTER_PASSWORD}")
    setup.expect("Reenter password:")
    setup.sendline(f"{MASTER_PASSWORD}")
    setup.expect(pexpect.EOF)
    output = setup.before

    output = output.split("PBKDF2 hash of your password is ")
    output = output[1]
    log.done("Bootloader password set!")

    # Writing config to custom grub file
    log.text("Writing config to custom grub file...")
    with open("/etc/grub.d/99_custom", "w") as grub:
        with open(os.path.join(CURR_DIR, "/config/99_custom", "rb")) as file:
            text = file.read()
            text = text.replace("<username>", str(CURR_USER))
            text = text.replace("<encrypted-password>", str(output))
            grub.write(text)
    log.done("Custom grub file written!")

    # Restarting grub
    log.text("Restarting grub...")
    os.system("update-grub")
    log.done("Grub has been restarted!")

    log.text("Setting permissions on /etc/grub/grub.cfg...")
    os.system("chown root:root /boot/grub/grub.cfg")
    os.system("chmod u-wx,go-rwx /boot/grub/grub.cfg")
    log.done("Permissions for /etc/grub/grub.cfg set!")

# Install and configure AIDE
def aide(log, CURR_DIR):
    # Install AIDE
    log.text("Installing AIDE...")
    os.system("apt install aide aide-common -y")
    log.done("Done!")

    # Copy basic configuration to /etc/aide/aide.conf
    log.text("Copying basic configuration to /etc/aide/aide.conf...")
    with open(os.path.join(CURR_DIR, "/config/aide.conf"), "rb") as file:
        with open("/etc/aide/aide.conf", "a") as conf:
            conf.write(file.read())
    log.done("Basic configuration copied!")

    # Start AIDE
    log.text("Initializing AIDE...")
    os.system("aideinit")
    os.system("mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db")
    log.done("AIDE started!")

    # Schedule a cron job to run AIDE
    log.text("Scheduling a cron job to run AIDE...")
    cron = CronTab(tab="0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check")
    cron.write()
    

# Disable booting unwanted filesystems according to the CIS Ubuntu 22.04 Document
def disableModules(log):
    # Disable unwanted filesystems and modules
    log.text("Disabling unwanted filesystems and modules...")
    with open("/etc/modprobe.d/blacklist.conf", "a") as file:
        # Disable cramf filesystem
        log.text("Disabling cramf...")
        file.write("\nblacklist cramf")
        log.done("Cramf disabled!")
        # Disable squashfs filesystem
        log.text("Disabling squashfs...")
        file.write("\nblacklist squashfs")
        log.done("Squashfs disabled!")
        # Disable udf filesystem
        log.text("Disabling udf...")
        file.write("\nblacklist udf")
        log.done("Udf disabled!")
        # Disable USBs
        log.text("Disabling USBs...")
        file.write("\nblacklist usb-storage")
        log.done("USBs disabled!")


# Update System
def update(log):
    log.text("Starting updates...")
    os.system("apt update -y")
    os.system("apt upgrade -y")
    os.system("apt dist-upgrade -y")
    os.system("apt --fix-missing update -y")
    os.system("apt install unattended-upgrades -y")
    log.done("Finished updating!")

# Install Dependancies
def installDep(log):
    # Install Nano
    log.text("Installing nano...")
    os.system("apt install nano -y")
    log.done("Done!")

    # Install Tree
    log.text("Installing tree...")
    os.system("apt install tree -y")
    log.done("Done!")

    # Install Netstat
    log.text("Installing netstat...")
    os.system("apt install net-tools -y")
    log.done("Done!")

    # Install Systemd
    log.text("Installing systemd...")
    os.system("apt install systemd -y")
    log.done("Done!")

    # Install Members
    log.text("Installing members...")
    os.system("apt install members -y")
    log.done("Done!")

# Enable Firewall
def ufw(log):
    log.text("Installing UFW...")
    os.system("apt install ufw -y")
    os.system("apt purge iptables-persistent -y")
    log.done("Done!")

    # Enable Firewall
    log.text("Enabling firewall...")
    os.system("systemctl unmask ufw.service")
    os.system("systemctl --now enable ufw.service")
    os.system("ufw enable")
    log.done("Firewall enabled!")

    # Configure Firewall Rules
    # Disable UFW Looping
    log.text("Disabling UFW looping...")
    os.system("ufw allow in on lo")
    os.system("ufw allow out on lo")
    os.system("ufw deny in from 127.0.0.0/8")
    os.system("ufw deny in from ::1")
    log.done("UFW looping disabled!")

    # Allow HTTP and HTTPS
    log.text("Enabling HTTP...")
    os.system("ufw allow in http")
    os.system("ufw allow out http")
    log.done("HTTP enabled!")
    log.text("Enabling HTTPS...")
    os.system("ufw allow in https")
    os.system("ufw allow out https")
    log.done("HTTPS enabled!")
    # Enable Git
    log.text("Enabling Git...")
    os.system("ufw allow out 53")
    os.system("ufw allow git")
    log.done("Git enabled!")

    # Configure miscellaneous rules
    # Configure outbound connections
    log.text("Configuring outbound connections...")
    os.system("ufw allow out on all")
    log.done("Configured outbound connections")
    # Implement a default deny policy
    log.text("Implementing a default deny policy...")
    os.system("ufw default deny incoming")
    os.system("ufw default deny outgoing")
    os.system("ufw default deny routed")
    log.done("Implemented a default deny policy!")

    # Configure UFW Status
    # Enable UFW Logging
    log.text("Enabling UFW logging...")
    os.system("ufw logging on")
    log.done("UFW logging enabled!")
    # Set UFW Logging to full
    log.text("Setting UFW logging level to full...")
    os.system("ufw logging full")
    log.done("UFW logging level set to full!")
    # UFW Status
    log.text("----- UFW STATUS -----")
    os.system("ufw status")
    os.system("ufw status verbose")
    log.text("---- End of Status -----")

# Find Unauthorizerd Users
def authUsers(log, USERNAMES, USERFILE, OSTYPE):
    goodUsers = [line for line in open(USERFILE, "rb").read()]
    goodUsers.append("root")
    for user in goodUsers:
        if user not in USERNAMES:
            if answer(f"Unauthorized user {user} detected: Remove?", log):
                try:
                    LINUX = OSTYPE[1]
                    if LINUX:
                        output = subprocess.run(["deluser", user])
                    if output.returncode == 0:
                        log.done(f"User {user} deleted!")
                except:
                    log.error(f"Failed to remove user {user}!")
            else:
                log.text(f"Proceeding without deleting user {user}.")

# Find Unauthorized Administrators
def authAdmins(log, ADMINFILE, OSTYPE):
    goodAdmins = [line for line in open(ADMINFILE, "rb")]
    goodAdmins.append("syslog")

    GROUPS = {}
    with open("/etc/group", "rb") as GROUPFILE:
        for group in GROUPFILE:
            if not group == "":
                groupInfo = group.split(":")

                groupName = groupInfo[0]
                groupGID = groupInfo[2]
                groupUsers = groupInfo[3].split(",")

                GROUPS[groupName] = {}
                GROUPS[groupName]["GID"] = groupGID
                GROUPS[groupName]["Users"] = groupUsers
    
    # Check members of the adm group
    if not GROUPS["adm"]["Users"][0] == "":
        for admin in GROUPS["adm"]["Users"]:
            if admin not in goodAdmins:
                if answer(f"Unauthorized user {admin} in the adm group: Remove?", log):
                    try:
                        LINUX = OSTYPE[1]
                        if LINUX:
                            output = subprocess.run(["deluser", admin, "adm"])
                        if output.returncode == 0:
                            log.done(f"User {admin} removed from adm group!")
                    except:
                        log.error(f"Failed to remove {admin} from adm group!")
                else:
                    log.text(f"Proceeding without removing {admin} from the adm group.")
    
    # Check members of the sudo group
    if not GROUPS["sudo"]["Users"][0] == "":
        for admin in GROUPS["sudo"]["Users"]:
            if admin not in goodAdmins:
                if answer(f"Unauthorized user {admin} in the sudo group: Remove?", log):
                    try:
                        LINUX = OSTYPE[1]
                        if LINUX:
                            output = subprocess.run(["deluser", admin, "sudo"])
                        if output.returncode == 0:
                            log.done(f"User {admin} removed from sudo group!")
                    except:
                        log.error(f"Failed to remove {admin} from sudo group!")
                else:
                    log.text(f"Proceeding without removing {admin} from the sudo group.")
    
    return GROUPS

# Run the main file
mainScript(log, CURR_DIR, USERS, USERNAMES, OSTYPE, USERFILE, ADMINFILE, MASTER_PASSWORD)