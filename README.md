# kolinaloader
kolinaloader


1. **Remote download over TLS**: Downloads DLL from HTTPS server with proper TLS verification
2. **Retry logic**: Attempts download multiple times with exponential backoff
3. **File verification**: Checks if downloaded file is a valid PE (Portable Executable) file
4. **Sleep/evasion techniques**: Strategic delays to avoid detection
5. **Periodic beaconing**: Optional check-in with command & control server
6. **Enhanced error handling**: Better error messages and recovery
7. **Cleanup**: Removes downloaded DLL on failure
8. **Admin check**: Detects if running with elevated privileges
9. **Architecture awareness**: Different behavior based on 32/64-bit

![img](https://github.com/hacker1337itme/kolinaloader/blob/main/poc.png)
