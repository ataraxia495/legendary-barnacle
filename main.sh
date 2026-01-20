#!/bin/bash

set -e

check_root() {
    if [[ $(id -u) -ne 0 ]]; then
        echo "Must execute with root"
        exit 1
    fi
}

check_version() {
    local version=
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "Distribution: $ID $DEBIAN_VERSION_FULL $VERSION_CODENAME"
    fi
}
ssh_hardening() {
    #local ssh_backup = /etc/ssh
    echo ""
    echo "Started SSH hardening.."
    #echo "Creating backup.. backup file
#    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
#
#    sed -i 's/^#\?Port.*/Port 2222/' /etc/ssh/sshd_config
#    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
#    sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
#    sed -i 's/^#\?MaxSessions.*/MaxSessions 2/' /etc/ssh/sshd_config
#    sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
#    sed -i 's/^#\?AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config
#    sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
#    sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
#    sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
#    sed -i 's/^#\?TCPKeepAlive.*/TCPKeepAlive no/' /etc/ssh/sshd_config
#    sed -i 's/^#\?LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
#
#    sshd -t
#
#    systemctl reload ssh
}

firewall_hardening() {
    apt install ufw -y
    sudo ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 2222/tcp
    ufw logging on
    ufw --force enable
    ufw status verbose
}

dns_hardening() {
    echo "wip"
}

grub_hardening() {
    local password="debian13"
    cat > /etc/grub.d/40_custom << EOF
#!/bin/sh
exec tail -n +3 \$0

set superusers="grubadmin"
password_pbkdf2 grubadmin $(echo -e "$password\n$password" | grub-mkpasswd-pbkdf2 | awk '/grub.pbkdf2/{print $NF}')
EOF

    chmod +x /etc/grub.d/40_custom
    update-grub
}

security_packages() {
    apt update && apt install fail2ban debsums apt-listbugs needrestart rkhunter auditd
}

kernel_hardening() {
    cat > /etc/sysctl.d/99-custom.conf << EOF
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
EOF

sysctl -p /etc/sysctl.d/99-custom.conf
}

fail2ban_hardening() {
    apt update && apt install fail2ban
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
}

lynis_suggestions() {
    apt update && apt install libpam-tmpdir
    grep tmpdir /etc/pam.d/common-session

}

show_menu() {
    clear
    echo -e "#=================================#"
    echo -e "       Test Hardening Script       "
    echo -e "#=================================#"
    echo ""
    check_version
    echo ""
    echo "1. ssh_hardening"
    echo "2. firewall_hardening"
    echo "3. dns_hardening"
    echo "4. grub_hardening"
    echo "5. security_packages"
    echo "6. kernel_hardening"
    echo "7. fail2ban_hardening"
    echo "8. lynis_suggestions"
    echo "0. Exit"

    echo ""
    read -p "Option: " option
}

main() {
    check_root

    while true; do
        show_menu
        case $option in
            1) ssh_hardening ;;
            2) firewall_hardening ;;
            3) dns_hardening ;;
            4) grub_hardening ;;
            5) security_hardening ;;
            6) kernel_hardening ;;
            7) fail2ban_hardening ;;
            8) lynis_suggestions ;;
            0)
                echo "Exiting. Please reboot"
                exit 0
                ;;
            *)
                echo "Invalid option"
                ;;
        esac

        echo ""
        read -p "Press enter to continue.."
    done
}

main