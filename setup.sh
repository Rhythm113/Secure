#!/bin/bash

# ==============================================================================
# setup.sh
# This script automates the installation of the IDS project with an
# interactive configuration guide.
# It creates the necessary directories, copies the script and configuration
# files, and sets the correct file permissions.
# This script must be run with root privileges.
# ==============================================================================

# --- Welcome Banner ---
echo "========================================"
echo "       Project Secure IDS 1.0           "
echo "         By @Rhythm113                  " 
echo "========================================"
echo ""

# uid chk
if [[ $(id -u) -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

# --- path ---
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
CONFIG_FILE_SOURCE="$SCRIPT_DIR/ids.conf"
CORE_SCRIPT_SOURCE="$SCRIPT_DIR/ids_core.sh"
WRAPPER_SCRIPT_SOURCE="$SCRIPT_DIR/secure"

# Destination paths
CONFIG_DIR="/etc/secure_ids"
CORE_SCRIPT_DEST="/usr/local/bin/ids_core.sh"
WRAPPER_SCRIPT_DEST="/bin/secure"
CONF_FILE_DEST="$CONFIG_DIR/ids.conf"

# --- conf ---
configure_interactive() {
    echo "--- Interactive Configuration ---"
    echo "Press Enter to accept the default value shown in brackets."
    echo ""

    local temp_conf=$(mktemp)
    
    # Save template as array (no pipe!)
    readarray -t conf_lines <<'EOF'
# IDS Configuration
# Log files and directories. Must be absolute paths.
# Description: Main log for security events.
LOGFILE=/var/tmp/Secure/secure.log
# Description: Working directory for temporary files.
WORKDIR=/var/tmp/Secure/Secure
# Description: Log for file integrity changes.
LOGFILE_MODIFY=/var/tmp/Secure/patch.log
# Description: List of trusted IP addresses.
KNOWN_IPS=/var/tmp/Secure/known_ips.txt
# Description: Main log for security alerts.
ALERT_LOG=/var/tmp/Secure/ids_alerts.log
# Description: List of phone numbers for SMS alerts.
ALERT_USERS_LIST=/var/tmp/Secure/numbers.txt
# Description: List of directories for file integrity monitoring.
WATCH_DIR_LIST=/var/tmp/Secure/watch_dir.txt
# Description: List of files/directories to ignore during monitoring.
WATCH_DIR_EXCEPTIONS=/var/tmp/Secure/watch_dir_ex.txt
# Description: List of users for SMS or Email alerts.
ALERT_USERS_LIST=/var/tmp/Secure/users_sms.txt

# Main Configuration Switches
# Description: Enable alerts via SMS or Email. (true/false)
ALERT_ENABLED=true
# Description: Alert method. (SMS/EMAIL)
ALERT_MODE=SMS
# Description: Enable File Integrity Monitoring. (true/false)
ENABLE_WATCHDIR=false
# Description: Immediately terminate detected reverse shells. (true/false)
KILL_REVERSE_SHELL=false

# API Configuration (For alerts)
# Description: Endpoint for the alert API.
API_URL=
# Description: Username for the alert API.
API_USERNAME=
# Description: Password for the alert API.
API_PASSWORD=

# Reverse Shell Detection Configuration
# Description: User to monitor for reverse shells. ("ALL" or specific username).
REV_DETECT_USER=ALL
EOF

    local description=""

    for line in "${conf_lines[@]}"; do
        if [[ "$line" =~ ^#\ Description:\  ]]; then
            description="${line#*Description: }"
            continue
        elif [[ "$line" =~ ^[[:space:]]*#.*$ || -z "$line" ]]; then
            echo "$line" >> "$temp_conf"
            continue
        fi

        local key=$(echo "$line" | cut -d'=' -f1)
        local default_value=$(echo "$line" | cut -d'=' -f2-)

        echo "$description"
        read -p "Enter value for $key [$default_value]: " new_value

        if [[ -z "$new_value" ]]; then
            echo "$key=$default_value" >> "$temp_conf"
        else
            echo "$key=$new_value" >> "$temp_conf"
        fi

        echo ""
    done

    # Confirm overwrite if config exists
    if [[ -f "$CONF_FILE_DEST" ]]; then
        read -p "Configuration already exists. Overwrite? (y/N): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Aborting configuration."
            rm "$temp_conf"
            return
        fi
    fi

    mv "$temp_conf" "$CONF_FILE_DEST"
    chmod 600 "$CONF_FILE_DEST"
    echo "Configuration saved to $CONF_FILE_DEST."
}



# --- Main script execution ---

# create
echo "Creating installation directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "/usr/local/bin"

# copy
echo "Copying scripts and configuration files..."
cp "$CORE_SCRIPT_SOURCE" "$CORE_SCRIPT_DEST" || { echo "Error: Failed to copy ids_core.sh. Aborting." >&2; exit 1; }
cp "$WRAPPER_SCRIPT_SOURCE" "$WRAPPER_SCRIPT_DEST" || { echo "Error: Failed to copy secure wrapper script. Aborting." >&2; exit 1; }

# perm
echo "Setting file permissions..."
chmod 755 "$CORE_SCRIPT_DEST"
chmod 755 "$WRAPPER_SCRIPT_DEST"


configure_interactive

# --- Final confirmation and instructions ---
echo ""
echo "========================================"
echo "IDS Setup Complete!"
echo "========================================"
echo "Next steps:"
echo ""
echo "1. The configuration is saved to '$CONF_FILE_DEST'."
echo "2. You can start the IDS by running:"
echo "   sudo secure --start <delay_in_seconds>"
echo "   For example, to run every minute: sudo secure --start 60"
echo ""
echo "To stop the IDS at any time, run: sudo secure --stop"
echo "To reconfigure your settings later, you can edit '$CONF_FILE_DEST' directly."
echo ""
