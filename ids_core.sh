#!/bin/bash

# IDS Configuration 
# configs are in /etc/secure_ids/ids.conf

# global variables for script logging and configuration
declare LOGFILE
declare LOGFILE_MODIFY
declare KNOWN_IPS
declare ALERT_LOG
declare WATCH_DIR_LIST
declare WATCH_DIR_EXCEPTIONS
declare ALERT_USERS_LIST
declare WORKDIR
declare ALERT_ENABLED
declare API_USERNAME
declare API_PASSWORD
declare ALERT_MODE
declare ENABLE_WATCHDIR
declare REV_DETECT_USER
declare KILL_REVERSE_SHELL
declare API_URL

function load_config() {
    local config_file="/etc/secure_ids/ids.conf"
    
    if [[ ! -f "$config_file" ]]; then
        echo "Error: Configuration file not found at $config_file." >&2
        exit 1
    fi

    # Read and parse the config file
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        key=$(echo "$key" | tr -d '[:space:]')
        value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/^"//;s/"$//')
        
        case "$key" in
            LOGFILE) LOGFILE="$value" ;;
            LOGFILE_MODIFY) LOGFILE_MODIFY="$value" ;;
            KNOWN_IPS) KNOWN_IPS="$value" ;;
            ALERT_LOG) ALERT_LOG="$value" ;;
            WATCH_DIR_LIST) WATCH_DIR_LIST="$value" ;;
            WATCH_DIR_EXCEPTIONS) WATCH_DIR_EXCEPTIONS="$value" ;;
            ALERT_USERS_LIST) ALERT_USERS_LIST="$value" ;;
            WORKDIR) WORKDIR="$value" ;;
            ALERT_ENABLED) ALERT_ENABLED="$value" ;;
            API_USERNAME) API_USERNAME="$value" ;;
            API_PASSWORD) API_PASSWORD="$value" ;;
            ALERT_MODE) ALERT_MODE="$value" ;;
            ENABLE_WATCHDIR) ENABLE_WATCHDIR="$value" ;;
            REV_DETECT_USER) REV_DETECT_USER="$value" ;;
            KILL_REVERSE_SHELL) KILL_REVERSE_SHELL="$value" ;;
            API_URL) API_URL="$value" ;;
        esac
    done < "$config_file"

    if [[ -z "$LOGFILE" || -z "$WORKDIR" || -z "$API_URL" ]]; then
        echo "Error: Required configurations (LOGFILE, WORKDIR, API_URL) are missing." >&2
        exit 1
    fi
}

function self_log() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$LOGFILE"
}

function send_alert() {
    local alert_message="$1"
    local recipients_file="$ALERT_USERS_LIST"

    if [[ "$ALERT_ENABLED" != "true" ]]; then
        self_log "Alerting is disabled. Not sending alert: $alert_message"
        return
    fi

    if [[ ! -f "$recipients_file" ]]; then
        self_log "Error: Recipients file not found: $recipients_file. Cannot send alert."
        return
    fi
    
    if [[ -z "$API_URL" ]]; then
        self_log "Error: API URL is not configured. Cannot send alert."
        return
    fi

    self_log "Sending alert: $alert_message"
    while IFS= read -r recipient || [[ -n "$recipient" ]]; do
        recipient=$(echo "$recipient" | tr -d '[:space:]')
        if [[ -n "$recipient" ]]; then
            local post_data=""
            if [[ "$ALERT_MODE" == "SMS" ]]; then
                post_data="key=$API_USERNAME&pass=$API_PASSWORD&to=$recipient&message=$alert_message"
            elif [[ "$ALERT_MODE" == "EMAIL" ]]; then
                post_data="key=$API_USERNAME&pass=$API_PASSWORD&to=$recipient&subject=IDS%20Alert&message=$alert_message"
            else
                self_log "Error: Invalid ALERT_MODE specified: $ALERT_MODE"
                continue
            fi
            
            # Use curl to send the POST request
            local curl_output=$(curl -s -X POST -d "$post_data" "$API_URL" 2>&1)
            self_log "Curl request sent to $recipient. Response: $curl_output"
        fi
    done < "$recipients_file"
}

function boot() {
    if [[ $(id -u) -ne 0 ]]; then
        echo "Error: This script must be run as root." >&2
        exit 1
    fi
    
    load_config
    self_log "Boot sequence initiated."

    if [[ ! -d "$WORKDIR" ]]; then
        mkdir -p "$WORKDIR"
        self_log "Created working directory: $WORKDIR"
    fi

    # Only create files if they are specified in the config
    [[ -n "$LOGFILE_MODIFY" && ! -f "$LOGFILE_MODIFY" ]] && touch "$LOGFILE_MODIFY" && self_log "Created config file: $LOGFILE_MODIFY"
    [[ -n "$KNOWN_IPS" && ! -f "$KNOWN_IPS" ]] && touch "$KNOWN_IPS" && self_log "Created config file: $KNOWN_IPS"
    [[ -n "$ALERT_LOG" && ! -f "$ALERT_LOG" ]] && touch "$ALERT_LOG" && self_log "Created config file: $ALERT_LOG"
    [[ -n "$WATCH_DIR_LIST" && ! -f "$WATCH_DIR_LIST" ]] && touch "$WATCH_DIR_LIST" && self_log "Created config file: $WATCH_DIR_LIST"
    [[ -n "$WATCH_DIR_EXCEPTIONS" && ! -f "$WATCH_DIR_EXCEPTIONS" ]] && touch "$WATCH_DIR_EXCEPTIONS" && self_log "Created config file: $WATCH_DIR_EXCEPTIONS"
    [[ -n "$ALERT_USERS_LIST" && ! -f "$ALERT_USERS_LIST" ]] && touch "$ALERT_USERS_LIST" && self_log "Created config file: $ALERT_USERS_LIST"
}

function dir_watcher() {
    self_log "Starting directory watcher."
    if [[ "$ENABLE_WATCHDIR" != "true" ]]; then
        self_log "Directory watcher is disabled. Skipping."
        return
    fi

    if [[ ! -s "$WATCH_DIR_LIST" ]]; then
        self_log "Watch directory list is empty. Skipping directory watcher."
        return
    fi
    
    local current_hashes="$WORKDIR/current_hashes.txt"
    local old_hashes="$WORKDIR/hashes.txt"
    local watch_dirs=()
    
    # Read directories to watch into an array
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | tr -d '[:space:]')
        [[ -n "$line" ]] && watch_dirs+=("$line")
    done < "$WATCH_DIR_LIST"

    # Find files and compute hashes
    find "${watch_dirs[@]}" -type f 2>/dev/null | while read -r file; do
        is_exception=false
        if [[ -f "$WATCH_DIR_EXCEPTIONS" ]]; then
            if grep -qF "$file" "$WATCH_DIR_EXCEPTIONS"; then
                is_exception=true
            fi
        fi
        
        if [[ "$is_exception" == false ]]; then
            md5sum "$file" 2>/dev/null
        fi
    done > "$current_hashes"
    
    local initial_run=false
    if [[ ! -f "$old_hashes" ]]; then
        initial_run=true
        mv "$current_hashes" "$old_hashes"
        self_log "Initial file list and hashes saved. Monitoring started."
        return
    fi

    local changed_files=0
    local message_body=""
    diff -u "$old_hashes" "$current_hashes" | grep -E '^\+' | grep -v '^\+\+\+' | while read -r line; do
        message_body+="[MODIFIED] $(date) - ${line:1}"$'\n'
        changed_files=$((changed_files+1))
    done

    diff -u "$old_hashes" "$current_hashes" | grep -E '^\-' | grep -v '^\-\-\-' | while read -r line; do
        message_body+="[DELETED] $(date) - ${line:1}"$'\n'
        changed_files=$((changed_files+1))
    done

    if [[ "$changed_files" -gt 0 ]]; then
        echo "$message_body" >> "$LOGFILE_MODIFY"
        self_log "Detected $changed_files file changes. Details logged to $LOGFILE_MODIFY."
        send_alert "Secure IDS: File changes detected on host: $HOSTNAME"
    fi

    mv "$current_hashes" "$old_hashes"
    self_log "Directory watcher finished."
}


function detect_conn() {
    self_log "Starting connection detection with netstat."


    netstat -tn | awk 'NR>2 {print $5}' | cut -d':' -f1 | grep -v '127.0.0.1' | sort -u > $WORKDIR/current_ips.tmp
    
    if [[ -s "$KNOWN_IPS" ]]; then
        comm -23 $WORKDIR/current_ips.tmp "$KNOWN_IPS" | while read -r remote_ip; do
            if [[ "$remote_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                local alert_message="[INFO] $(date) - New Outgoing Connection to Unknown IP: $remote_ip"
                echo "$alert_message" >> "$ALERT_LOG"
                self_log "$alert_message"
                #send_alert "Secure IDS: New Outgoing Connection to Unknown IP: $remote_ip"
            fi
        done
    else
        self_log "KNOWN_IPS file is missing or empty. All connections will be alerted."
        cat $WORKDIR/current_ips.tmp | while read -r remote_ip; do
            if [[ "$remote_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                local alert_message="[INFO] $(date) - New Outgoing Connection to Unknown IP: $remote_ip"
                echo "$alert_message" >> "$ALERT_LOG"
                self_log "$alert_message"
                #send_alert "Secure IDS: New Outgoing Connection to Unknown IP: $remote_ip"
            fi
        done
    fi

    rm $WORKDIR/current_ips.tmp

    self_log "Connection detection finished."
}


function ssh_detect() {
    self_log "Starting SSH detection."
    local log_file=""
    
    # won't give output 99% of the time. 
    local journal_output=$(journalctl --no-pager --since "5 minutes ago" -u ssh.service 2>/dev/null)

    if [[ -z "$journal_output" ]]; then
        self_log "journalctl -u ssh.service returned no logs. Checking traditional log files."
        if [[ -f "/var/log/auth.log" ]]; then
            log_file="/var/log/auth.log"
        elif [[ -f "/var/log/secure" ]]; then
            log_file="/var/log/secure"
        else
            self_log "Could not find a traditional SSH log file (/var/log/auth.log or /var/log/secure)."
            self_log "SSH detection finished. No logs to process."
            return 1
        fi
        
        local log_output=$(tail -n 200 "$log_file" | grep "sshd")
    else
        local log_output="$journal_output"
    fi

    if [[ -z "$log_output" ]]; then
        self_log "No new SSH events found in logs."
    else
        self_log "Processing SSH events from logs."
        
        # AI SLOP idk how tf it runs perfectly
        # This prevents multiple greps and loops on the same data
        echo "$log_output" | awk '
            /Accepted password|Failed password|session opened for user root/ {
                # Extract the IP address
                match($0, /from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, ip_match)
                if (ip_match[1] != "") {
                    event_type = ""
                    if ($0 ~ /Failed password/) {
                        event_type = "Failed SSH login"
                    } else if ($0 ~ /Accepted password/) {
                        event_type = "Accepted SSH login"
                    } else if ($0 ~ /session opened for user root/) {
                        event_type = "Root user SSH login"
                    }
                    print ip_match[1], event_type
                }
            }
        ' | while read -r ip_addr event_type; do
            if [[ -f "$KNOWN_IPS" ]] && ! grep -qF "$ip_addr" "$KNOWN_IPS"; then
                local alert_message="[ALERT] $(date) - $event_type from unknown IP: $ip_addr"
                echo "$alert_message" >> "$ALERT_LOG"
                self_log "$alert_message"
                send_alert "Secure IDS: $event_type from unknown IP: $ip_addr"
            fi
        done
    fi

    self_log "SSH detection finished."
}


function rev_detect() {
    self_log "Starting reverse shell detection."
    local ps_output

    if [[ "$REV_DETECT_USER" == "ALL" ]]; then
        ps_output=$(ps aux)
    else
        ps_output=$(ps -u "$REV_DETECT_USER" -o user,pid,cmd --no-headers)
    fi

    local patterns="(^|[^a-zA-Z0-9_-])(nc|bash -i|sh -i|perl .*socket|python.*socket|python -c|socat|0<&[0-9]+;exec [0-9]+<>/dev/tcp)([^a-zA-Z0-9_-]|$)"
    
    echo "$ps_output" | grep -E "$patterns" | grep -v "grep -E" | while read -r line; do
        local user=$(echo "$line" | awk '{print $1}')
        local pid=$(echo "$line" | awk '{print $2}')
        local command=$(echo "$line" | awk '{$1=$2=""; print $0}' | xargs)
        
        local alert_message="[ALERT] $(date) - Possible Reverse Shell Detected: User=$user, PID=$pid, Command=$command"
        echo "$alert_message" >> "$ALERT_LOG"
        self_log "$alert_message"
        send_alert "Secure IDS: Possible Reverse Shell Detected: User=$user, PID=$pid, Command=$command"

        if [[ "$KILL_REVERSE_SHELL" == "true" ]]; then
            if kill -9 "$pid" 2>/dev/null; then
                local action_message="[ACTION] $(date) - PID $pid (User=$user) has been terminated."
                echo "$action_message" >> "$ALERT_LOG"
                self_log "$action_message"
            else
                local error_message="[ERROR] $(date) - Failed to terminate PID $pid (User=$user)."
                echo "$error_message" >> "$ALERT_LOG"
                self_log "$error_message"
            fi
        fi
    done
    self_log "Reverse shell detection finished."
}



# --- Main script execution ---
boot
dir_watcher
detect_conn
ssh_detect
rev_detect
self_log "Script execution completed."