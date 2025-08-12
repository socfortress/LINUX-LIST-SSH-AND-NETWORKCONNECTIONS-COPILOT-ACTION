## List-SSH-Network-Connections.sh

This script lists all active TCP and UDP network connections on the system, providing a JSON-formatted output for integration with security tools like OSSEC/Wazuh.

### Overview

The `List-SSH-Network-Connections.sh` script uses `netstat` to enumerate all network connections, collecting protocol, local and remote addresses, state, and associated process information. Output is formatted as JSON for active response workflows.

### Script Details

#### Core Features

1. **Connection Enumeration**: Lists all active TCP and UDP connections.
2. **Process Metadata**: Collects protocol, local/remote addresses, state, and PID/program.
3. **JSON Output**: Generates a structured JSON report for integration with security tools.
4. **Logging Framework**: Provides detailed logs for script execution.
5. **Log Rotation**: Implements automatic log rotation to manage log file size.
6. **Auto-Install**: Attempts to install `netstat` if missing.

### How the Script Works

#### Command Line Execution
```bash
./List-SSH-Network-Connections.sh
```

#### Parameters

| Parameter | Type | Default Value | Description |
|-----------|------|---------------|-------------|
| `ARLog`   | string | `/var/ossec/active-response/active-responses.log` | Path for active response JSON output |
| `LogPath` | string | `/tmp/List-SSH-Network-Connections.sh-script.log` | Path for detailed execution logs |
| `LogMaxKB` | int | 100 | Maximum log file size in KB before rotation |
| `LogKeep` | int | 5 | Number of rotated log files to retain |

### Script Execution Flow

#### 1. Initialization Phase
- Rotates the detailed log file if it exceeds the size limit
- Clears the active response log file
- Logs the start of the script execution
- Attempts to install `netstat` if missing

#### 2. Connection Collection
- Uses `netstat` to enumerate all TCP and UDP connections
- Collects metadata for each connection

#### 3. JSON Output Generation
- Formats connection details into a JSON array
- Writes the JSON result to the active response log

#### 4. Completion Phase
- Logs the duration of the script execution
- Outputs the final JSON result

### JSON Output Format

#### Example Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "List-SSH-Network-Connections.sh",
  "data": {
    "connections": [
      {
        "proto": "tcp",
        "recvq": "0",
        "sendq": "0",
        "local": "127.0.0.1:22",
        "remote": "192.168.1.100:54321",
        "state": "ESTABLISHED",
        "pid_prog": "1234/sshd"
      },
      {
        "proto": "udp",
        "recvq": "0",
        "sendq": "0",
        "local": "0.0.0.0:68",
        "remote": "0.0.0.0:0",
        "state": "",
        "pid_prog": "-"
      }
    ]
  },
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to access network and process information
- Validate the JSON output for compatibility with your security tools
- Test the script in isolated environments

#### Security Considerations
- Ensure minimal required privileges
- Protect the output log files

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure the script has privileges to access network and process information
2. **Missing netstat**: Ensure `netstat` is installed or installable
3. **Log File Issues**: Check write permissions

#### Debugging
Enable verbose logging:
```bash
VERBOSE=1 ./List-SSH-Network-Connections.sh
```

### Contributing

When modifying this script:
1. Maintain the connection enumeration and JSON output structure
2. Follow Shell scripting best practices
3. Document any additional functionality
4. Test thoroughly in isolated environments
